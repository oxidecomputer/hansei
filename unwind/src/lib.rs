// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Stack unwinding for a target using DWARF `.eh_frame` CFI.
//!
//! Everything here reads through [`proc::Target`], so a backtrace comes
//! out of a core dump or a replayed snapshot alike. What it needs
//! from the target is the unwind information of whichever object the
//! program counter is in, which means every mapped object that carries
//! any — not just the executable and libc, since a thread parked in the
//! kernel has libc frames below it and the loader and libgcc turn up in
//! their own right.

use anyhow::{Context as _, Result};
use gimli::{
    BaseAddresses, CfaRule, EhFrame, EhFrameHdr, EndianSlice, EvaluationResult, LittleEndian,
    ParsedEhFrameHdr, RegisterRule, UnwindContext, UnwindSection, Value,
};
use goblin::container::Ctx;
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64};
use goblin::elf::program_header::{PT_LOAD, ProgramHeader};
use proc::{Mappings, Reg, Regs, SymbolBuf, Target, x86_64::*};

use std::collections::BTreeMap;
use std::ops::Range;

type Endian = LittleEndian;
type Slice<'a> = EndianSlice<'a, Endian>;

/// The segment holding `.eh_frame_hdr`, under each platform's name for
/// it. The two are different values, and an object carries one or the
/// other, so both are accepted rather than chosen between.
const PT_SUNW_UNWIND: u32 = 0x6464e550;
const PT_GNU_EH_FRAME: u32 = 0x6474e550;

// TODO - does this actually matter?
const _: () = assert!(usize::BITS == 64, "host system must be 64-bit");

#[derive(Clone, PartialEq, Default, Debug)]
pub struct Backtrace {
    pub frames: Vec<Frame>,
    /// Why the walk stopped before the CFI's own bottom, when it did:
    /// a pc no sourced CFI covers and the frame-pointer walk could not
    /// bridge, or an error popping a frame. `None` for a stack walked
    /// to its end.
    pub truncated: Option<String>,
}

impl Backtrace {
    pub fn new(frames: Vec<Frame>) -> Self {
        Self {
            frames,
            truncated: None,
        }
    }

    pub fn stack_trace(&self, max_frames: usize) -> Vec<String> {
        let mut lines: Vec<String> = self
            .frames
            .iter()
            .take(max_frames)
            .map(|frame| {
                let mangled = frame
                    .symbol
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or_default();
                let mark = if frame.heuristic {
                    "  (frame-pointer walk)"
                } else {
                    ""
                };
                format!(
                    "{:#018x} {:#}{mark}",
                    frame.regs.rip,
                    rustc_demangle::demangle(mangled)
                )
            })
            .collect();
        // The reason binds to the walk's end, so it prints only when
        // the end is in view — a listing cut short by `max_frames`
        // already says less than the walk found.
        if self.frames.len() <= max_frames
            && let Some(why) = &self.truncated
        {
            lines.push(format!("(walk ended: {why})"));
        }
        lines
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Frame {
    pub pc: u64,
    pub regs: Regs,
    pub symbol: Option<SymbolBuf>,
    /// Whether the frame-pointer walk produced this frame rather than
    /// CFI. Such a frame is a validated guess — the return address
    /// landed in mapped text — not a fact the unwind tables state, and
    /// a rendering may want to say so.
    pub heuristic: bool,
}

/// Every thread's backtrace, plus what the walk could not source: the
/// mapped objects whose CFI never loaded, whose pcs the walks bridge
/// by frame pointer or stop at.
pub struct Unwound {
    pub stacks: BTreeMap<u32, Backtrace>,
    pub missing: Vec<MissingCfi>,
}

/// A mapped object whose CFI could not be sourced, and why: its pages
/// are not in the core and the backing file is not on this machine, or
/// what is readable does not parse.
#[derive(Clone, PartialEq, Debug)]
pub struct MissingCfi {
    pub range: Range<u64>,
    pub path: String,
    pub why: String,
}

pub fn load_frames<T: Target>(target: &T) -> Result<Unwound> {
    let mappings = target
        .mappings()
        .context("failed to retrieve memory mappings from the target")?;
    let (images, mut missing) = load_images(target, &mappings);
    let mut objects: Vec<ObjectInfo<'_>> = Vec::new();
    for image in &images {
        match ObjectInfo::parse(&image.bytes, image.range.clone()) {
            Ok(object) => objects.push(object),
            Err(e) => missing.push(MissingCfi {
                range: image.range.clone(),
                path: image.path.clone(),
                why: format!("{e:#}"),
            }),
        }
    }
    // No CFI at all — a snapshot, whose capture records stacks but
    // not object images — still walks: frame 0 needs only registers
    // and the symbol table, and the frame-pointer fallback bridges
    // what it can validate. Each walk's truncation says what was
    // missing.
    let unwinder = Unwinder {
        target,
        objects: &objects,
        mappings: &mappings,
        missing: &missing,
    };

    let mut stacks = BTreeMap::new();
    for lwp in target.lwps()? {
        // One thread's ragged stack is that thread's news alone: the
        // walk records why it stopped rather than costing every other
        // thread its backtrace.
        let backtrace = unwinder.unwind_stack(&lwp.regs, &mut UnwindContext::new(), 64);
        stacks.insert(lwp.tid, backtrace);
    }
    Ok(Unwound { stacks, missing })
}

/// The mapped image of every file-backed object in the target, read
/// through the target so that it works the same whether the bytes are
/// in the core or on disk behind it.
///
/// An object's mappings are read one at a time and laid out at their
/// own offsets, leaving anything unreadable — an alignment gap between
/// two segments, say — zeroed rather than failing the whole object.
fn load_images<T: Target>(target: &T, mappings: &Mappings) -> (Vec<Image>, Vec<MissingCfi>) {
    let mut paths: Vec<&str> = mappings.iter().filter_map(|m| m.path.as_deref()).collect();
    paths.sort_unstable();
    paths.dedup();

    let mut images = Vec::new();
    let mut missing = Vec::new();
    for path in paths {
        let parts: Vec<_> = mappings
            .iter()
            .filter(|m| m.path.as_deref() == Some(path))
            .collect();
        let (Some(base), Some(end)) = (
            parts.iter().map(|m| m.vaddr).min(),
            parts.iter().map(|m| m.range().end).max(),
        ) else {
            continue;
        };
        let Ok(len) = usize::try_from(end - base) else {
            continue;
        };

        let mut bytes = vec![0u8; len];
        let mut any = false;
        for part in parts {
            // A part is rarely readable end to end: the dump filter keeps
            // a file-backed mapping's first page and leaves the rest to
            // the backing file, and no single read crosses that seam. So
            // the part is read in whatever runs the target can serve,
            // rather than skipped whole on the first seam — which would
            // zero the ELF header along with it.
            let runs = proc::readable_runs(part.vaddr, part.size, |addr, max| {
                target.readable_len(addr, max)
            });
            for (addr, run) in runs {
                if let Ok(chunk) = target.read_bytes(addr, run) {
                    let at = (addr - base) as usize;
                    bytes[at..at + chunk.len()].copy_from_slice(chunk);
                    any = true;
                }
            }
        }
        if any {
            images.push(Image {
                range: base..end,
                path: path.to_string(),
                bytes,
            });
        } else {
            missing.push(MissingCfi {
                range: base..end,
                path: path.to_string(),
                why: "none of its pages are in the core, and the backing file \
                      is not on this machine"
                    .to_string(),
            });
        }
    }
    (images, missing)
}

/// One object's mapped image, at the addresses it occupies.
struct Image {
    range: Range<u64>,
    path: String,
    bytes: Vec<u8>,
}

struct Unwinder<'a, T> {
    target: &'a T,
    objects: &'a [ObjectInfo<'a>],
    mappings: &'a Mappings,
    /// The objects whose CFI never loaded, for naming in a walk's
    /// truncation reason when it stops inside one.
    missing: &'a [MissingCfi],
}

/// What popping one frame produced. The frame rides boxed: `Regs`
/// makes it an order of magnitude larger than the other variants, and
/// every pop moves one through two returns.
enum Pop {
    Frame(Box<Frame>),
    /// The CFI marked the return address undefined: the stack's own
    /// bottom, ending the walk with nothing to explain.
    End,
    /// The walk is out of facts short of the bottom: a pc no sourced
    /// CFI covers, where the frame-pointer walk found nothing it could
    /// validate. The reason names the missing CFI when the pc is in an
    /// object known to lack it.
    Lost(String),
}

impl<T: Target> Unwinder<'_, T> {
    /// The object holding `pc`, if it is in one that carries unwind
    /// information.
    fn object_at(&self, pc: u64) -> Option<&ObjectInfo<'_>> {
        self.objects.iter().find(|o| o.range.contains(&pc))
    }
    fn unwind_stack(
        &self,
        initial_regs: &Regs,
        ctx: &mut UnwindContext<usize>,
        max_frames: usize,
    ) -> Backtrace {
        let mut frames = Vec::new();
        let mut truncated = None;
        let mut regs = initial_regs.clone();
        let mut pc = regs.rip;

        let initial_frame = Frame {
            pc: regs.rip,
            regs: regs.clone(),
            symbol: self.target.lookup_symbol_by_addr(regs.rip),
            heuristic: false,
        };
        frames.push(initial_frame);

        // A thread that called through a bad pointer faults with its pc
        // outside every mapping, where no CFI can describe it. But the
        // frame that made the call is one word down: the `call` pushed
        // the return address and nothing ran after it. Popping that word
        // by hand lands the walk back where CFI resumes.
        if !self.mappings.contains_addr(regs.rip)
            && let Ok(ret) = self.target.read_u64(regs.rsp)
            && self.is_text(ret)
        {
            regs.rip = ret;
            regs.rsp += size_of::<u64>() as u64;
            pc = ret;
            frames.push(Frame {
                pc: ret,
                symbol: self.symbol_at(ret),
                regs: regs.clone(),
                heuristic: false,
            });
        }

        for _ in 0..max_frames {
            // Out of the address space entirely: there is nothing below.
            if !self.mappings.contains_addr(regs.rip) {
                break;
            }
            if !self.mappings.contains_addr(pc) {
                pc -= size_of::<u64>() as u64;
                if !self.mappings.contains_addr(pc) {
                    break;
                }
            }

            // PC will point to directly after function generally, or outside the function
            // entirely for functions without an epilogue. Adjust it to point to the
            // function.
            pc -= 1;

            // No object with unwind information covers this pc — the
            // vDSO, or a mapping whose file has gone. The frame pointer
            // is all that is left to walk.
            let object = self.object_at(pc);

            // An error popping one frame — CFI the reader cannot
            // evaluate, a torn stack — ends this walk with what it has,
            // and says why; the frames above the failure are real
            // either way.
            let prev_frame = match self.unwind_frame_with_cfi(pc, &regs, object, ctx) {
                Ok(Pop::Frame(frame)) => *frame,
                Ok(Pop::End) => break,
                Ok(Pop::Lost(why)) => {
                    truncated = Some(why);
                    break;
                }
                Err(e) => {
                    truncated = Some(format!("{e:#}"));
                    break;
                }
            };

            regs = prev_frame.regs.clone();
            pc = regs.rip;

            frames.push(prev_frame);
        }

        Backtrace { frames, truncated }
    }

    /// Whether `addr` is in a mapping that holds code. This is what a
    /// guessed return address must satisfy to be believed: any mapped
    /// word can be read, but only text can have been called from.
    fn is_text(&self, addr: u64) -> bool {
        self.mappings.get(addr).is_some_and(|m| m.is_text())
    }

    /// Attempt to pop the frame to the previous function based on the frame pointer.
    /// RIP, RBP, and RSP will be updated, callee-saved registers will remain unchanged,
    /// and caller-saved registers will be zeroed.
    ///
    /// `None` when the chain ends or was never there: rbp not pointing
    /// at readable memory is how a walk off a function that keeps no
    /// frame pointer announces itself, and is the end of what can be
    /// known, not an error.
    fn pop_frame_with_frame_pointer(&self, initial_regs: &Regs) -> Option<Regs> {
        if initial_regs.rip == 0 {
            return None;
        }
        let mut regs = initial_regs.clone();
        for reg in REGS {
            // We can't assume anything about the state of caller-saved registers.
            if !reg.is_callee_saved() {
                regs[reg] = 0;
            }
        }

        regs.rip = self.target.read_u64(initial_regs.rbp + 8).ok()?;
        regs.rbp = self.target.read_u64(initial_regs.rbp).ok()?;
        regs.rsp = initial_regs.rbp + 16;

        Some(regs)
    }

    /// The frame below one no CFI describes, walked with the frame
    /// pointer — a validated guess, marked as such. [`Pop::Lost`] once
    /// there is nothing recognisable below: a popped return address
    /// that does not land in mapped text is a chain that was never
    /// real, and believing it would fabricate a frame.
    fn pop_frame_without_cfi(&self, pc: u64, regs: &Regs) -> Pop {
        let popped = self
            .pop_frame_with_frame_pointer(regs)
            .filter(|prev| self.is_text(prev.rip));
        match popped {
            Some(prev_regs) => Pop::Frame(Box::new(Frame {
                pc: prev_regs.rip,
                symbol: self.symbol_at(prev_regs.rip),
                regs: prev_regs,
                heuristic: true,
            })),
            None => Pop::Lost(self.lost_at(pc)),
        }
    }

    /// The truncation reason for a walk that ran out of facts at `pc`:
    /// name the object whose missing CFI is why, when it is known.
    fn lost_at(&self, pc: u64) -> String {
        match self.missing.iter().find(|m| m.range.contains(&pc)) {
            Some(m) => format!(
                "no CFI for {} ({}); the frame-pointer walk found nothing below {pc:#x}",
                m.path, m.why
            ),
            None => format!("no CFI covers {pc:#x}; the frame-pointer walk found nothing below it"),
        }
    }

    /// The symbol a return address belongs to. A return address points
    /// *after* the call, which for a call in tail position can be the
    /// first byte of the next function; stepping back one finds the
    /// function that actually made the call.
    fn symbol_at(&self, addr: u64) -> Option<SymbolBuf> {
        self.target
            .lookup_symbol_by_addr(addr)
            .or_else(|| self.target.lookup_symbol_by_addr(addr - 1))
    }

    /// Attempt to pop the frame to the previous function based on .eh_frame unwind info.
    /// RIP, RBP, and RSP and, callee-saved registers will be updated with the values
    /// returned by the CFI; caller-saved registers will be zeroed.
    pub fn unwind_frame_with_cfi(
        &self,
        pc: u64,
        regs: &Regs,
        object: Option<&ObjectInfo>,
        ctx: &mut UnwindContext<usize>,
    ) -> Result<Pop> {
        // Nothing carries unwind information for this pc; the frame
        // pointer is the only way down.
        let Some(object) = object else {
            return Ok(self.pop_frame_without_cfi(pc, regs));
        };

        // We confirmed in `parse` that the table is present.
        let table = object.eh_frame_hdr.table().unwrap();

        let fde = match table.fde_for_address(
            &object.eh_frame,
            &object.bases,
            pc,
            gimli::EhFrame::cie_from_offset,
        ) {
            Ok(fde) => fde,
            Err(gimli::Error::NoUnwindInfoForAddress) => {
                return Ok(self.pop_frame_without_cfi(pc, regs));
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        let row = fde.unwind_info_for_address(&object.eh_frame, &object.bases, ctx, pc)?;
        let encoding = fde.cie().encoding();

        // Compute the CFA (Canonical Frame Address) for the previous function.
        let cfa = self.compute_cfa(regs, row.cfa(), encoding, object)?;

        let mut modified_regs = Vec::new();
        let mut prev_regs = Regs::default();
        for reg in REGS {
            if let Some(value) = self.restore_register(reg, regs, cfa, row)? {
                prev_regs[reg] = value;
                modified_regs.push(reg);
            }
        }

        // An undefined return address is how the CFI says the stack ends
        // — it is what glibc's thread entry and the program's own
        // `_start` carry — so this is the bottom, not a failure.
        let Some(prev_pc) = self.restore_register(RIP, regs, cfa, row)? else {
            return Ok(Pop::End);
        };

        prev_regs.rsp = cfa;
        prev_regs.rip = prev_pc;

        let prev_frame = Frame {
            pc: prev_pc,
            symbol: self.symbol_at(prev_regs.rip),
            regs: prev_regs,
            heuristic: false,
        };

        Ok(Pop::Frame(Box::new(prev_frame)))
    }

    fn restore_register(
        &self,
        reg: Reg,
        regs: &Regs,
        cfa: u64,
        row: &gimli::UnwindTableRow<usize>,
    ) -> Result<Option<u64>> {
        match row.register(reg.into()) {
            RegisterRule::Undefined => {
                if reg.is_callee_saved() {
                    // Callee-saved register unmodified.
                    return Ok(Some(regs[reg]));
                }
                // Volatile register not preserved.
                Ok(None)
            }
            RegisterRule::SameValue => Ok(Some(regs[reg])),
            RegisterRule::Offset(offset) => {
                let addr = (cfa as i64 + offset) as u64;
                let val = self.target.read_u64(addr)?;
                Ok(Some(val))
            }
            RegisterRule::Register(other_reg) => Ok(Some(regs[other_reg.into()])),
            RegisterRule::ValOffset(offset) => {
                // Value is CFA + offset (not a pointer).
                Ok(Some((cfa as i64 + offset) as u64))
            }
            RegisterRule::Expression(_) | RegisterRule::ValExpression(_) => {
                Err(anyhow::anyhow!("Register expressions not supported"))
            }
            e => Err(anyhow::anyhow!("Unsupported register rule {e:?} for {reg}")),
        }
    }

    fn compute_cfa(
        &self,
        regs: &Regs,
        cfa_rule: &CfaRule<usize>,
        encoding: gimli::Encoding,
        object: &ObjectInfo,
    ) -> Result<u64> {
        match cfa_rule {
            CfaRule::RegisterAndOffset { register, offset } => {
                let reg = *register;
                let reg_val = regs[reg.into()];
                Ok((reg_val as i64 + offset) as u64)
            }
            CfaRule::Expression(expr) => {
                let expression = expr.get(&object.eh_frame)?;
                let mut eval = expression.evaluation(encoding);
                let mut result = eval.evaluate().context("initial CFA evaluation failed")?;

                loop {
                    match result {
                        EvaluationResult::Complete => break,

                        // CASE A: The expression needs a register value (e.g., DW_OP_breg7)
                        EvaluationResult::RequiresRegister { register, .. } => {
                            let val = regs[register.into()];
                            result = eval
                                .resume_with_register(Value::Generic(val))
                                .context("failed to resume with CFA register")?;
                        }

                        // CASE B: The expression needs to read memory (e.g., DW_OP_deref)
                        // This happens if the CFA is stored on the stack of the *previous* frame
                        EvaluationResult::RequiresMemory { address, size, .. } => {
                            let val = match size {
                                8 => self.target.read_u64(address)?,
                                4 => self.target.read_u32(address)? as u64,
                                2 => self.target.read_u16(address)? as u64,
                                1 => self.target.read_u8(address)? as u64,
                                _ => anyhow::bail!("CFA had unexpected read size of {size}"),
                            };
                            result = eval
                                .resume_with_memory(Value::Generic(val))
                                .context("failed to resume with CFA memory read")?;
                        }

                        EvaluationResult::RequiresRelocatedAddress(addr) => {
                            // Assume no relocations and just use address as-is. Is this a valid
                            // assumption? Not sure.
                            result = eval
                                .resume_with_relocated_address(addr)
                                .context("failed to resume with CFA relocated")?;
                        }

                        // ERROR CASES:
                        // A CFA expression calculating the CFA cannot ask for the Frame Base or CFA.
                        // That would be infinite recursion.
                        EvaluationResult::RequiresFrameBase => {
                            anyhow::bail!(
                                "CFA expression requires FrameBase (circular dependency)"
                            );
                        }
                        EvaluationResult::RequiresCallFrameCfa => {
                            anyhow::bail!("CFA expression requires CFA (circular dependency)");
                        }

                        r => anyhow::bail!("Unsupported DWARF Op in CFA expression: {r:?}"),
                    }
                }

                // The result of a CFA expression is the address of the CFA.
                let final_results = eval.result();

                match final_results.first() {
                    Some(gimli::Piece {
                        location: gimli::Location::Address { address },
                        ..
                    }) => {
                        // In some DWARF contexts, a "Location" result implies the value IS the address.
                        Ok(*address)
                    }
                    Some(gimli::Piece {
                        location: gimli::Location::Value { value },
                        ..
                    }) => {
                        // In others, it returns a Value literal.
                        match value {
                            Value::Generic(v) => Ok(*v),
                            _ => anyhow::bail!("CFA resolved to non-generic value"),
                        }
                    }
                    _ => anyhow::bail!(
                        "CFA expression {final_results:?} did not resolve to a single address/value"
                    ),
                }
            }
        }
    }
}

#[derive(Debug)]
struct ObjectInfo<'a> {
    /// The addresses this object occupies, which is how the object for
    /// a program counter is found.
    range: Range<u64>,
    eh_frame_hdr: ParsedEhFrameHdr<Slice<'a>>,
    eh_frame: EhFrame<Slice<'a>>,
    bases: BaseAddresses,
}

impl<'a> ObjectInfo<'a> {
    pub fn parse(bytes: &'a [u8], range: Range<u64>) -> Result<Self> {
        let map_addr = range.start;
        // Only the header's class and the program headers are read:
        // PT_LOAD for the load bias, the unwind segment for the CFI.
        // A full `Elf::parse` would also decode every symbol and
        // string table — on a production binary, hundreds of
        // megabytes of strtab UTF-8 validation for tables nothing
        // here looks at.
        let header = Elf::parse_header(bytes).context("failed to parse the ELF header")?;
        if header.e_ident[EI_CLASS] != ELFCLASS64 {
            anyhow::bail!("only ELF64 is supported");
        }
        let endianness = header
            .endianness()
            .context("failed to read the ELF endianness")?;
        if !endianness.is_little() {
            anyhow::bail!("only little-endian files are supported");
        }
        let ctx = Ctx::new(
            header.container().context("failed to read the ELF class")?,
            endianness,
        );
        let program_headers =
            ProgramHeader::parse(bytes, header.e_phoff as usize, header.e_phnum as usize, ctx)
                .context("failed to parse the program headers")?;

        let text_phdr = program_headers
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_offset == 0)
            .ok_or(anyhow::anyhow!("no PT_LOAD program header"))?;

        let vaddr = text_phdr.p_vaddr;

        // Calculate ASLR slide (Load Bias)
        // mapping_addr = Runtime Address
        // vaddr        = Link-time Address
        let load_bias = map_addr.wrapping_sub(vaddr);

        let eh_phdr = program_headers
            .iter()
            .find(|ph| ph.p_type == PT_SUNW_UNWIND || ph.p_type == PT_GNU_EH_FRAME)
            .ok_or(anyhow::anyhow!("no unwind-table program header"))?;

        let eh_frame_hdr_vaddr = eh_phdr.p_vaddr.wrapping_add(load_bias);
        let mut bases = BaseAddresses::default().set_eh_frame_hdr(eh_frame_hdr_vaddr);

        let eh_frame_hdr_offset = (eh_phdr.p_vaddr - vaddr) as usize;
        if eh_frame_hdr_offset + (eh_phdr.p_memsz as usize) > bytes.len() {
            anyhow::bail!(
                ".eh_frame_hdr at offset {:#x} and size {:#x} extends outside the mapping with size {:#x}",
                eh_phdr.p_vaddr,
                eh_phdr.p_memsz,
                bytes.len()
            );
        }
        let eh_frame_hdr_slice =
            &bytes[eh_frame_hdr_offset..(eh_frame_hdr_offset + eh_phdr.p_memsz as usize)];

        let partial_eh_frame_hdr = EhFrameHdr::new(eh_frame_hdr_slice, LittleEndian);
        let eh_frame_hdr = partial_eh_frame_hdr.parse(&bases, 8)?;

        if eh_frame_hdr.table().is_none() {
            anyhow::bail!("no CFI table in .eh_frame_hdr");
        }

        let eh_frame_addr = eh_frame_hdr.eh_frame_ptr().pointer();
        bases = bases.set_eh_frame(eh_frame_addr);
        let eh_frame_offset = (eh_frame_addr - map_addr) as usize;
        if eh_frame_offset >= bytes.len() {
            anyhow::bail!(
                ".eh_frame offset {eh_frame_offset:#x} outside the mapping with size {:#x}",
                bytes.len()
            );
        }

        let eh_frame_slice = &bytes[eh_frame_offset..];
        let eh_frame = EhFrame::new(eh_frame_slice, LittleEndian);

        Ok(Self {
            range,
            eh_frame_hdr,
            eh_frame,
            bases,
        })
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::{Backtrace, MissingCfi, Unwinder};
    use gimli::UnwindContext;
    use proc::{LoadedObjectWithPath, MapFlags, Mappings, Regs, SymbolBuf, Target};

    /// Memory regions and a mapping table, and nothing else: with no
    /// parsed objects, every pop goes through the frame-pointer
    /// fallback, which is what these tests pin.
    struct FakeTarget {
        mem: Vec<(u64, Vec<u8>)>,
        mappings: Mappings,
    }

    impl Target for FakeTarget {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            for (base, bytes) in &self.mem {
                if addr >= *base && addr + len <= base + bytes.len() as u64 {
                    let at = (addr - base) as usize;
                    return Ok(&bytes[at..at + len as usize]);
                }
            }
            Err(proc::Error::unmapped(addr, len))
        }
        fn lookup_symbol_by_addr(&self, _: u64) -> Option<SymbolBuf> {
            None
        }
        fn lookup_symbol_by_name(&self, _: &str) -> Option<SymbolBuf> {
            None
        }
        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            Ok(Vec::new())
        }
        fn mappings(&self) -> proc::Result<Mappings> {
            unreachable!("the tests hand the unwinder its mappings")
        }
        fn lwps(&self) -> proc::Result<Vec<proc::LwpInfo>> {
            Ok(Vec::new())
        }
        fn tls_var_addr(&self, _: &Regs, _: &SymbolBuf) -> proc::Result<Option<u64>> {
            Ok(None)
        }
    }

    const TEXT: u64 = 0x40_0000;
    const HEAP: u64 = 0x60_0000;
    const STACK: u64 = 0x7000_0000;

    fn mapping(vaddr: u64, size: u64, flags: u32) -> LoadedObjectWithPath {
        LoadedObjectWithPath {
            path: None,
            vaddr,
            size,
            flags: MapFlags(flags),
        }
    }

    /// A target whose stack memory holds the given words, with a text,
    /// a heap and a stack mapping. No CFI anywhere.
    fn target(stack_words: &[(u64, u64)]) -> FakeTarget {
        const READ: u32 = 0x04;
        const WRITE: u32 = 0x02;
        const EXEC: u32 = 0x01;
        let mem = stack_words
            .iter()
            .map(|&(addr, word)| (addr, word.to_le_bytes().to_vec()))
            .collect();
        let mappings = [
            mapping(TEXT, 0x1000, READ | EXEC),
            mapping(HEAP, 0x1000, READ | WRITE),
            mapping(STACK, 0x1_0000, READ | WRITE),
        ]
        .into_iter()
        .collect();
        FakeTarget { mem, mappings }
    }

    fn walk(target: &FakeTarget, regs: &Regs, missing: &[MissingCfi]) -> Backtrace {
        let unwinder = Unwinder {
            target,
            objects: &[],
            mappings: &target.mappings,
            missing,
        };
        unwinder.unwind_stack(regs, &mut UnwindContext::new(), 8)
    }

    /// A real rbp chain walks: each popped frame lands in text, is
    /// marked as the guess it is, and the chain's zeroed-rbp end
    /// truncates the walk with a reason instead of failing it.
    #[test]
    fn test_a_valid_rbp_chain_walks_and_its_end_truncates() {
        let regs = Regs {
            rip: TEXT + 0x10,
            rsp: STACK + 0xf0,
            rbp: STACK + 0x100,
            ..Regs::default()
        };
        let t = target(&[
            (STACK + 0x100, STACK + 0x200), // saved rbp
            (STACK + 0x108, TEXT + 0x20),   // return address, in text
            (STACK + 0x200, 0),             // chain terminator
            (STACK + 0x208, TEXT + 0x30),
        ]);
        let bt = walk(&t, &regs, &[]);
        let pcs: Vec<u64> = bt.frames.iter().map(|f| f.pc).collect();
        assert_eq!(pcs, [TEXT + 0x10, TEXT + 0x20, TEXT + 0x30]);
        assert!(!bt.frames[0].heuristic);
        assert!(bt.frames[1].heuristic && bt.frames[2].heuristic);
        // The pop restores the caller's registers, not just its pc: a
        // wrong rsp here skews every CFI frame below the hop.
        assert_eq!(bt.frames[1].regs.rbp, STACK + 0x200);
        assert_eq!(bt.frames[1].regs.rsp, STACK + 0x100 + 16);
        // The terminator: rbp 0, so the next pop reads address 8,
        // which is unreadable — the walk ends with the reason, it
        // does not error.
        let why = bt.truncated.expect("the chain's end is explained");
        assert!(why.contains("no CFI covers"), "{why}");
    }

    /// A popped word that lands outside text — a heap pointer where a
    /// return address should be — is a chain that was never real: no
    /// frame is fabricated from it.
    #[test]
    fn test_a_non_text_return_address_is_not_believed() {
        let regs = Regs {
            rip: TEXT + 0x10,
            rsp: STACK + 0xf0,
            rbp: STACK + 0x100,
            ..Regs::default()
        };
        let t = target(&[
            (STACK + 0x100, STACK + 0x200),
            (STACK + 0x108, HEAP + 0x40), // mapped, but nothing to call
        ]);
        let bt = walk(&t, &regs, &[]);
        assert_eq!(bt.frames.len(), 1, "{:?}", bt.frames);
        assert!(bt.truncated.is_some());
    }

    /// The truncation reason names the object whose CFI is missing
    /// when the pc falls in one, so the reader learns which file to
    /// supply rather than only that the walk stopped.
    #[test]
    fn test_the_reason_names_the_object_missing_its_cfi() {
        let regs = Regs {
            rip: TEXT + 0x10,
            rsp: STACK + 0xf0,
            rbp: 0,
            ..Regs::default()
        };
        let missing = [MissingCfi {
            range: TEXT..TEXT + 0x1000,
            path: "/usr/lib64/libc.so.6".to_string(),
            why: "none of its pages are in the core".to_string(),
        }];
        let bt = walk(&target(&[]), &regs, &missing);
        let why = bt.truncated.expect("the walk explains its end");
        assert!(why.contains("/usr/lib64/libc.so.6"), "{why}");
        assert!(why.contains("none of its pages are in the core"), "{why}");
    }

    /// The truncation reason prints only when the walk's end is in
    /// view: a listing cut short by max_frames says less than the walk
    /// found, and the guessed frames carry their mark.
    #[test]
    fn test_stack_trace_binds_the_reason_to_the_visible_end() {
        let frame = |pc, heuristic| super::Frame {
            pc,
            regs: Regs {
                rip: pc,
                ..Regs::default()
            },
            symbol: None,
            heuristic,
        };
        let bt = Backtrace {
            frames: vec![frame(0x10, false), frame(0x20, true)],
            truncated: Some("no CFI covers 0x20".to_string()),
        };
        let lines = bt.stack_trace(8);
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(!lines[0].contains("frame-pointer walk"), "{}", lines[0]);
        assert!(lines[1].ends_with("(frame-pointer walk)"), "{}", lines[1]);
        assert_eq!(lines[2], "(walk ended: no CFI covers 0x20)");
        let cut = bt.stack_trace(1);
        assert_eq!(cut.len(), 1, "{cut:?}");
    }
}

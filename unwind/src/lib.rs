// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Stack unwinding for core dumps using DWARF `.eh_frame` CFI.

use anyhow::{Context as _, Result};
use gimli::{
    BaseAddresses, CfaRule, EhFrame, EhFrameHdr, EndianSlice, EvaluationResult, LittleEndian,
    ParsedEhFrameHdr, RegisterRule, UnwindContext, UnwindSection, Value,
};
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64};
use goblin::elf::program_header::PT_LOAD;
use proc::{Proc, Reg, Regs, SymbolBuf, x86_64::*};

use std::collections::BTreeMap;
use std::ops::Range;

type Endian = LittleEndian;
type Slice<'a> = EndianSlice<'a, Endian>;

const PT_SUNW_UNWIND: u32 = 0x6464e550;

// TODO - does this actually matter?
const _: () = assert!(usize::BITS == 64, "host system must be 64-bit");

#[derive(Clone, PartialEq, Default, Debug)]
pub struct Backtrace {
    pub frames: Vec<Frame>,
}

impl Backtrace {
    pub fn new(frames: Vec<Frame>) -> Self {
        Self { frames }
    }

    pub fn stack_trace(&self, max_frames: usize) -> Vec<String> {
        self.frames
            .iter()
            .take(max_frames)
            .map(|frame| {
                let mangled = frame
                    .symbol
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or_default();
                format!(
                    "{:#018x} {:#}",
                    frame.regs.rip,
                    rustc_demangle::demangle(mangled)
                )
            })
            .collect()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Frame {
    pub pc: u64,
    pub regs: Regs,
    pub symbol: Option<SymbolBuf>,
}

pub fn load_frames(core: &Proc) -> Result<BTreeMap<u32, Backtrace>> {
    let addrs = AddrRanges::parse(&core).context("could not parse address mappings")?;

    let exec_bytes = load_object(&addrs.exec_text, &core).context("failed to load executable")?;
    let exec = ObjectInfo::parse(&exec_bytes, addrs.exec_text.start)
        .context("could not parse object info for executable")?;

    let libc_bytes = load_object(&addrs.libc_text, &core).context("failed to load libc")?;
    let libc = ObjectInfo::parse(&libc_bytes, addrs.libc_text.start)
        .context("could not parse object info for libc")?;

    let mut frame_map = BTreeMap::new();
    let lwps = core.lwps()?;
    for lwp in lwps {
        let initial_regs = core
            .regs(lwp.tid)
            .context("failed to get thread registers")?;

        let unwinder = Unwinder {
            core: &core,
            exec: &exec,
            libc: &libc,
        };
        let frames = unwinder
            .unwind_stack(&initial_regs, &mut UnwindContext::new(), 64)
            .with_context(|| format!("failed to unwind stack for tid {}", lwp.tid))?;
        frame_map.insert(lwp.tid, Backtrace::new(frames));
    }
    Ok(frame_map)
}

#[derive(Debug)]
struct Unwinder<'a> {
    core: &'a Proc,
    exec: &'a ObjectInfo<'a>,
    libc: &'a ObjectInfo<'a>,
}

impl<'a> Unwinder<'a> {
    fn unwind_stack(
        &self,
        initial_regs: &Regs,
        ctx: &mut UnwindContext<usize>,
        max_frames: usize,
    ) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let mut regs = initial_regs.clone();
        let mut pc = regs.rip;

        let initial_frame = Frame {
            pc: regs.rip,
            regs: regs.clone(),
            symbol: self.core.lookup_symbol_by_addr(regs.rip),
        };
        frames.push(initial_frame);

        for _ in 0..max_frames {
            // Below minimum range of binary in address space.
            if regs.rip < self.exec.map_addr {
                break;
            }

            let mapping = match self.core.addr_to_map(pc) {
                Some(l) => l,
                None => {
                    pc -= size_of::<u64>() as u64;
                    self.core
                        .addr_to_map(pc)
                        .with_context(|| format!("no mapping found for PC {pc:#x}"))?
                }
            };
            let object = if mapping.vaddr == self.exec.map_addr {
                &self.exec
            } else if mapping.vaddr == self.libc.map_addr {
                &self.libc
            } else {
                // We only expect the executable and libc, all other mappings are unhandled.
                //anyhow::bail!("unanticipated mapping at addr {pc:#x} - {mapping:?}")
                &self.exec //TODO
            };

            // PC will point to directly after function generally, or outside the function
            // entirely for functions without an epilogue. Adjust it to point to the
            // function.
            pc -= 1;

            let Some(prev_frame) = self.unwind_frame_with_cfi(pc, &regs, object, ctx)? else {
                break;
            };

            regs = prev_frame.regs.clone();
            pc = regs.rip;

            frames.push(prev_frame);
        }

        Ok(frames)
    }

    /// Attempt to pop the frame to the previous function based on the frame pointer.
    /// RIP, RBP, and RSP will be updated, callee-saved registers will remain unchanges,
    /// and caller-saved registers will be zeroed.
    fn pop_frame_with_frame_pointer(&self, initial_regs: &Regs) -> Result<Option<Regs>> {
        if initial_regs.rip == 0 {
            return Ok(None);
        }
        let mut regs = initial_regs.clone();
        for reg in REGS {
            // We can't assume anything about the state of caller-saved registers.
            if !Regs::is_callee_saved(reg) {
                regs[reg] = 0;
            }
        }

        let return_addr_addr = regs.rbp + 8;
        regs.rip = self
            .core
            .read_u64(return_addr_addr)
            .context("failed to read return address")?;

        regs.rbp = self
            .core
            .read_u64(regs.rbp)
            .context("failed to read saved RBP")?;

        regs.rsp = regs.rbp + 16;

        Ok(Some(regs))
    }

    /// Attempt to pop the frame to the previous function based on .eh_frame unwind info.
    /// RIP, RBP, and RSP and, callee-saved registers will be updated with the values
    /// returned by the CFI; caller-saved registers will be zeroed.
    pub fn unwind_frame_with_cfi(
        &self,
        pc: u64,
        regs: &Regs,
        object: &ObjectInfo,
        ctx: &mut UnwindContext<usize>,
    ) -> Result<Option<Frame>> {
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
                let Some(prev_regs) = self
                    .pop_frame_with_frame_pointer(regs)
                    .context("failed to pop stack of function without FDE")?
                else {
                    return Ok(None);
                };

                // Definitely unmapped, no frame to return.
                if prev_regs.rip < self.exec.map_addr {
                    return Ok(None);
                }

                let prev_symbol = self
                    .core
                    .lookup_symbol_by_addr(prev_regs.rip)
                    .or_else(|| self.core.lookup_symbol_by_addr(prev_regs.rip - 1));
                return Ok(Some(Frame {
                    pc: prev_regs.rip,
                    regs: prev_regs,
                    symbol: prev_symbol,
                }));
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
            if let Some(value) = self.restore_register(reg, regs, cfa, &row)? {
                prev_regs[reg] = value;
                modified_regs.push(reg);
            }
        }

        let prev_pc = self
            .restore_register(RIP, regs, cfa, &row)?
            .ok_or_else(|| anyhow::anyhow!("Cannot find return address"))?;

        prev_regs.rsp = cfa;
        prev_regs.rip = prev_pc;

        let prev_symbol = self
            .core
            .lookup_symbol_by_addr(prev_regs.rip)
            .or_else(|| self.core.lookup_symbol_by_addr(prev_regs.rip - 1));
        let prev_frame = Frame {
            pc: prev_pc,
            regs: prev_regs,
            symbol: prev_symbol,
        };

        Ok(Some(prev_frame))
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
                let val = self.core.read_u64(addr)?;
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
                                8 => self.core.read_u64(address)?,
                                4 => self.core.read_u32(address)? as u64,
                                2 => self.core.read_u16(address)? as u64,
                                1 => self.core.read_u8(address)? as u64,
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

                match final_results.get(0) {
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

fn load_object(object_range: &Range<u64>, core: &Proc) -> Result<Vec<u8>> {
    let object_len = object_range.end - object_range.start;
    let mut buf = vec![0u8; object_len as usize];
    core.pread_exact(&mut buf, object_range.start)
        .context("failed to read libc mapping from core")?;

    Ok(buf)
}

#[derive(Debug)]
struct ObjectInfo<'a> {
    map_addr: u64,
    eh_frame_hdr: ParsedEhFrameHdr<Slice<'a>>,
    eh_frame: EhFrame<Slice<'a>>,
    bases: BaseAddresses,
}

impl<'a> ObjectInfo<'a> {
    pub fn parse(bytes: &'a [u8], map_addr: u64) -> Result<Self> {
        let elf = Elf::parse_with_opts(&bytes, &goblin::options::ParseOptions::permissive())
            .context("failed to parse data as ELF")?;

        if elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
            anyhow::bail!("only ELF64 is supported");
        }
        if !elf.little_endian {
            anyhow::bail!("only little-endian files are supported");
        }

        let text_phdr = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_offset == 0)
            .ok_or(anyhow::anyhow!("no PT_LOAD program header"))?;

        let vaddr = text_phdr.p_vaddr;

        // Calculate ASLR slide (Load Bias)
        // mapping_addr = Runtime Address
        // vaddr        = Link-time Address
        let load_bias = map_addr.wrapping_sub(vaddr);

        let eh_phdr = elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == PT_SUNW_UNWIND)
            .ok_or(anyhow::anyhow!("no PT_SUNW_UNWIND program header"))?;

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
            map_addr,
            eh_frame_hdr,
            eh_frame,
            bases,
        })
    }
}

#[derive(Debug)]
struct AddrRanges {
    exec_text: Range<u64>,
    libc_text: Range<u64>,
}

impl AddrRanges {
    pub fn parse(core: &Proc) -> Result<Self> {
        let core_mappings = core
            .mappings()
            .context("failed to retrieve memory mappings from core")?;

        let Some(exec_text) = core_mappings.first() else {
            anyhow::bail!("no mappings in core");
        };
        if !exec_text.is_text() {
            anyhow::bail!("first mapping is not .text");
        }

        let Some(libc_mapping) = core_mappings.iter().find(|o| {
            o.path
                .as_ref()
                .map(|p| p.ends_with("libc.so.1"))
                .unwrap_or_default()
        }) else {
            anyhow::bail!("no .text mapping found for libc");
        };

        Ok(AddrRanges {
            exec_text: exec_text.range(),
            libc_text: libc_mapping.range(),
        })
    }
}

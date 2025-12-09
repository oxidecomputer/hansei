use anyhow::{Context as _, Result};
use clap::Parser;
use fallible_iterator::FallibleIterator;
use gimli::{
    AttributeValue, BaseAddresses, CfaRule, DW_AT_abstract_origin, DW_AT_byte_size, DW_AT_count,
    DW_AT_data_member_location, DW_AT_discr, DW_AT_discr_value, DW_AT_high_pc, DW_AT_location,
    DW_AT_low_pc, DW_AT_lower_bound, DW_AT_name, DW_AT_ranges, DW_AT_type, DW_AT_upper_bound,
    DW_TAG_formal_parameter, DW_TAG_lexical_block, DW_TAG_member, DW_TAG_subprogram,
    DW_TAG_subrange_type, DW_TAG_variable, DW_TAG_variant, DW_TAG_variant_part,
    DebuggingInformationEntry, Dwarf, EhFrame, EhFrameHdr, Encoding, EndianSlice, EvaluationResult,
    Expression, LittleEndian, Location, ParsedEhFrameHdr, Piece, RegisterRule, Unit, UnitOffset,
    UnitRef, UnwindContext, UnwindSection, Value,
};
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64};
use goblin::elf::program_header::PT_LOAD;
use memmap2::Mmap;
use proc::{Core, Reg, Regs, SymbolBuf, x86_64::*};
use rangemap::RangeMap;

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

type Endian = LittleEndian;
type Slice<'a> = EndianSlice<'a, Endian>;

const PT_SUNW_UNWIND: u32 = 0x6464e550;

const _: () = assert!(usize::BITS == 64, "host system must be 64-bit");

#[derive(clap::Parser)]
struct Args {
    /// The core dump to open.
    core: PathBuf,

    /// The corresponding ELF file with debug symbols.
    #[clap(long, short)]
    debug_elf: Option<PathBuf>,

    /// The lwp to analyze.
    #[clap(long, short)]
    lwp: Option<u32>,
}

fn main() {
    let args = Args::parse();
    let mut stdout = io::stdout().lock();

    if let Err(e) = exec(args, &mut stdout) {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "{e:#}");
        std::process::exit(1);
    }
}

fn exec(args: Args, out: &mut dyn io::Write) -> Result<()> {
    let debug_file = args
        .debug_elf
        .as_deref()
        .map(DebugFile::open)
        .transpose()
        .with_context(|| format!("failed to open {}", args.debug_elf.unwrap().display()))?;
    let debug_info = debug_file
        .as_ref()
        .map(|df| df.load_debug_info())
        .transpose()?;

    let core = Core::open(&args.core)
        .with_context(|| format!("failed to open {} as a core", args.core.display()))?;
    let addrs = AddrRanges::parse(&core).context("could not parse address mappings")?;

    let exec_bytes = load_object(&addrs.exec_text, &core).context("failed to load executable")?;
    let exec = ObjectInfo::parse(&exec_bytes, addrs.exec_text.start, debug_info)
        .context("could not parse object info for executable")?;

    let libc_bytes = load_object(&addrs.libc_text, &core).context("failed to load libc")?;
    let libc = ObjectInfo::parse(&libc_bytes, addrs.libc_text.start, None)
        .context("could not parse object info for libc")?;

    let lwp = args.lwp.unwrap_or_else(|| core.status().active_lwp);
    let initial_regs = core.regs(lwp).context("failed to get thread registers")?;

    writeln!(out, "LWP {lwp}")?;
    writeln!(out, "\nInitial registers:\n{initial_regs}")?;

    let unwinder = Unwinder {
        core: &core,
        exec: &exec,
        libc: &libc,
    };
    let frames = unwinder.unwind_stack(&initial_regs, &mut UnwindContext::new(), 16)?;

    let frame_entries = exec
        .debug_info
        .as_ref()
        .map(|di| FrameEntries::find(&frames, &di.dwarf))
        .transpose()?;

    for (i, frame) in frames.iter().enumerate() {
        eprintln!("FRAME_{i}: PC {:#x}", frame.pc);
    }

    for (i, frame) in frames.iter().enumerate() {
        frame.print_regs(out, i, &addrs, &core)?;

        let Some(mapping) = core.lookup_map(frame.pc) else {
            continue;
        };

        // We can only have debug info for the executable. Nothing to do if we're in any other
        // mapping.
        if mapping.vaddr != exec.map_addr {
            continue;
        }

        if let Some(debug_info) = &exec.debug_info
            && let Some(frame_units) = &frame_entries
            && let Some(entry_loc) = frame_units.0.get(&frame.regs.rip)
            && let Some(header) = debug_info.dwarf.units().nth(entry_loc.unit_index)?
        {
            let unit = debug_info.dwarf.unit(header)?;
            let unit_ref = UnitRef::new(&debug_info.dwarf, &unit);
            let variables =
                find_variables_in_scope(&unit_ref, entry_loc.offset, frame.pc, &frame.regs, &core)?;
            if !variables.is_empty() {
                writeln!(out, "\nVariables:")?;
            }
            for var in variables {
                writeln!(out, "  name: {}", var.name)?;
                writeln!(
                    out,
                    "    type: {}",
                    var.type_name.as_deref().unwrap_or("<unknown>")
                )?;
                writeln!(
                    out,
                    "    size: {}",
                    var.size.map(|s| s.to_string()).unwrap_or_default()
                )?;

                if let Some(pieces) = &var.parts {
                    if !pieces.is_empty() {
                        writeln!(out, "    parts:")?;
                    }
                    for piece in pieces {
                        if let Some((name, value)) = frame.eval_piece(piece)? {
                            print_stuff(out, 6, value, &name, &addrs, &core)?;
                        }
                    }
                }

                // Show dereferenced pointer info for top-level variable
                if let Some(deref_addr) = var.dereferenced_addr {
                    writeln!(out, "    -> @{deref_addr:#x}:")?;
                }

                // Print fields if this is a struct/union (or dereferenced pointer to one)
                if !var.fields.is_empty() {
                    writeln!(out, "    fields:")?;
                    for field in &var.fields {
                        write!(out, "      .{}: ", field.name)?;
                        if let Some(type_name) = &field.type_name {
                            write!(out, "({type_name}) ")?;
                        }
                        match &field.value {
                            Some(FieldValue::Unsigned(v)) => {
                                writeln!(out, "{v:#x} ({v})")?;
                            }
                            Some(FieldValue::Signed(v)) => {
                                writeln!(out, "{v:#x} ({v})")?;
                            }
                            Some(FieldValue::Bytes(bytes)) => {
                                let hex: String = bytes
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                writeln!(out, "[{hex}]")?;
                            }
                            None => {
                                writeln!(out, "<unavailable>")?;
                            }
                        }
                        // Show dereferenced pointer info
                        if let Some(deref_addr) = field.dereferenced_addr {
                            writeln!(out, "        -> @{deref_addr:#x}:")?;
                        }
                        // Recursively print nested fields
                        print_nested_fields(out, &field.nested_fields, 8)?;
                    }
                }
            }
        }

        // if let Some(fn_info) = debug_info.index.find_by_name_and_offset(&symbol.name, pc) {
        //     DwarfEval::print_arguments(
        //         pc,
        //         frame.regs.rsp, // TODO correct?
        //         &frame.regs,
        //         fn_info,
        //         &symbol.name,
        //         &debug_info.dwarf,
        //         &core,
        //     )?;
        // }

        // let callee_saved = [RBX, R12, R13, R14, R15];

        // for &reg in &callee_saved {
        //     let value = regs[reg];

        //     // What variables claim to live in this register at this PC?
        //     let candidates = debug_info.locations.find_in_register(reg, pc);

        //     if !candidates.is_empty() {
        //         eprintln!("  {reg} = {value:#x} might be:");
        //         for var in candidates {
        //             eprintln!(
        //                 "    - {} (from {:#x}..{:#x})",
        //                 var.name, var.range.start, var.range.end
        //             );
        //         }
        //     }
        // }
    }

    Ok(())
}

fn print_nested_fields(out: &mut dyn Write, fields: &[FieldInfo], indent: usize) -> Result<()> {
    for field in fields {
        write!(out, "{}.{}: ", " ".repeat(indent), field.name)?;
        if let Some(type_name) = &field.type_name {
            write!(out, "({type_name}) ")?;
        }
        match &field.value {
            Some(FieldValue::Unsigned(v)) => {
                writeln!(out, "{v:#x} ({v})")?;
            }
            Some(FieldValue::Signed(v)) => {
                writeln!(out, "{v:#x} ({v})")?;
            }
            Some(FieldValue::Bytes(bytes)) => {
                let hex: String = bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                writeln!(out, "[{hex}]")?;
            }
            None => {
                writeln!(out, "<unavailable>")?;
            }
        }
        // Show dereferenced pointer info
        if let Some(deref_addr) = field.dereferenced_addr {
            writeln!(out, "{} -> @{deref_addr:#x}:", " ".repeat(indent + 2))?;
        }
        print_nested_fields(out, &field.nested_fields, indent + 2)?;
    }
    Ok(())
}

#[derive(Debug)]
struct AddrRanges {
    exec_text: Range<u64>,
    exec_data: Range<u64>,
    exec_brk: Range<u64>,
    exec_stack: Range<u64>,
    exec_anon: Vec<Range<u64>>,
    exec_guard: Vec<Range<u64>>,
    lwp_stacks: RangeMap<u64, u32>,
    libc_text: Range<u64>,
}

impl AddrRanges {
    pub fn parse(core: &Core) -> Result<Self> {
        let core_mappings = core
            .mappings()
            .context("failed to retrieve memory mappings from core")?;

        let Some(exec_text) = core_mappings.first() else {
            anyhow::bail!("no mappings in core");
        };
        let Some(exec_path) = &exec_text.path else {
            anyhow::bail!("no path for first mapping");
        };
        if !exec_text.is_text() {
            anyhow::bail!("first mapping is not text");
        }
        let Some(exec_data) = core_mappings
            .iter()
            .filter(|m| m.path.as_ref().map(|p| p == exec_path).unwrap_or_default())
            .find(|m| m.is_data())
        else {
            anyhow::bail!("no data mapping for executable");
        };

        let Some(libc_mapping) = core_mappings.iter().find(|o| {
            o.path
                .as_ref()
                .map(|p| p.ends_with("libc.so.1"))
                .unwrap_or_default()
        }) else {
            anyhow::bail!("no .text mapping found for libc");
        };

        let anon_mappings: Vec<_> = core_mappings.iter().filter(|o| o.path.is_none()).collect();
        let (guard_mappings, anon_mappings): (Vec<_>, Vec<_>) =
            anon_mappings.into_iter().partition(|o| o.is_guard());

        let lwps = core.lwps()?;
        let lwp_stacks: RangeMap<_, _> = lwps
            .into_iter()
            .map(|lwp| (lwp.stack_range, lwp.tid))
            .collect();

        let status = core.status();

        Ok(AddrRanges {
            exec_text: exec_text.range(),
            exec_data: exec_data.range(),
            exec_brk: status.brk_range,
            exec_anon: anon_mappings.into_iter().map(|m| m.range()).collect(),
            exec_guard: guard_mappings.into_iter().map(|m| m.range()).collect(),
            exec_stack: status.stack_range,
            lwp_stacks,
            libc_text: libc_mapping.range(),
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
enum MappingType {
    /// .text and .rodata, the first mapping for the executable.
    ExecText,
    /// .data and .bss, the second mapping for the executable.
    ExecData,
    /// pr_brkbase from Pstatus.
    ExecBrk,
    /// pr_stkbase from Pstatus.
    ExecStk,
    /// Mappings with MA_ANON flag set.
    ExecAnon,
    /// Guard pages, mappings with no flags set.
    ExecGuard,
    /// A LWP's stack.
    LwpStack(u32),
    /// .text and .rodata for libc.
    LibcText,
}

impl fmt::Display for MappingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecText => write!(f, "text"),
            Self::ExecData => write!(f, "data"),
            Self::ExecBrk => write!(f, "heap"),
            Self::ExecStk => write!(f, "stack"),
            Self::ExecAnon => write!(f, "anon"),
            Self::ExecGuard => write!(f, "guard"),
            Self::LwpStack(tid) => write!(f, "stack[{tid}]"),
            Self::LibcText => write!(f, "libc"),
        }
    }
}

impl AddrRanges {
    pub fn mapping_type(&self, addr: u64) -> Option<MappingType> {
        if self.exec_text.contains(&addr) {
            Some(MappingType::ExecText)
        } else if self.exec_data.contains(&addr) {
            Some(MappingType::ExecData)
        } else if self.exec_brk.contains(&addr) {
            Some(MappingType::ExecBrk)
        } else if self.exec_stack.contains(&addr) {
            Some(MappingType::ExecStk)
        } else if let Some(&tid) = self.lwp_stacks.get(&addr) {
            Some(MappingType::LwpStack(tid))
        } else if self.libc_text.contains(&addr) {
            Some(MappingType::LibcText)
        } else if self.exec_anon.iter().any(|r| r.contains(&addr)) {
            Some(MappingType::ExecAnon)
        } else if self.exec_guard.iter().any(|r| r.contains(&addr)) {
            Some(MappingType::ExecGuard)
        } else {
            None
        }
    }
}

struct DebugFile {
    _file: File,
    mmap: Mmap,
}

impl DebugFile {
    fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        let mmap = unsafe {
            Mmap::map(&file).with_context(|| format!("failed to mmap {}", path.display()))?
        };
        Ok(Self { _file: file, mmap })
    }

    fn load_debug_info<'a>(&'a self) -> Result<DebugInfo<'a>> {
        let elf = Elf::parse(&self.mmap)?;

        let loader = |section_id: gimli::SectionId| -> Result<EndianSlice<LittleEndian>> {
            let name = section_id.name();
            for sh in &elf.section_headers {
                if let Some(section_name) = elf.shdr_strtab.get_at(sh.sh_name)
                    && section_name == name
                {
                    let start = sh.sh_offset as usize;
                    let end = start + sh.sh_size as usize;
                    return Ok(EndianSlice::new(&self.mmap[start..end], LittleEndian));
                }
            }
            Ok(EndianSlice::new(&[], LittleEndian))
        };

        let dwarf = Dwarf::load(&loader).with_context(|| format!("failed to load DWARF"))?;

        Ok(DebugInfo { dwarf })
    }
}

#[derive(Debug)]
struct DebugInfo<'a> {
    dwarf: Dwarf<Slice<'a>>,
}

fn load_object(object_range: &Range<u64>, core: &Core) -> Result<Vec<u8>> {
    let object_len = object_range.end - object_range.start;
    let mut buf = vec![0u8; object_len as usize];
    let read_len = core
        .pread(&mut buf, object_range.start)
        .context("failed to read libc mapping from core")?;
    if read_len != object_len {
        anyhow::bail!("unexpected pread len {read_len:x} reading object, expected {object_len:x}");
    }

    Ok(buf)
}

#[derive(Debug)]
struct Frame {
    pc: u64,
    regs: Regs,
    symbol: Option<SymbolBuf>,
    modified_regs: Vec<Reg>,
    has_cfi: bool,
}

impl Frame {
    pub fn print_regs(
        &self,
        out: &mut dyn io::Write,
        i: usize,
        addrs: &AddrRanges,
        core: &Core,
    ) -> Result<()> {
        writeln!(out, "\n{}\n", "-".repeat(20))?;

        let pc = self.regs.rip;
        if let Some(sym) = &self.symbol {
            let function_offset = pc - sym.st_value;
            writeln!(out, "#{i} {pc:#018x} {}+{function_offset:#x}", sym.name)?;
        } else {
            writeln!(out, "#{i} {pc:#018x}")?;
        }

        writeln!(out, "")?;
        if !self.modified_regs.is_empty() {
            writeln!(out, "Register state:")?;
        }
        for &reg in &self.modified_regs {
            if reg == RBP {
                continue;
            }

            let mut current_ptr = self.regs[reg];
            let map_ty = addrs.mapping_type(current_ptr);
            let desc = map_ty.map(|m| m.to_string()).unwrap_or_else(String::new);
            write!(
                out,
                "  %{reg}: {current_ptr:#018x} {desc:>9} {}",
                format_value(current_ptr)
            )?;

            match map_ty {
                Some(MappingType::ExecText) => {
                    if let Some(sym) = core.lookup_symbol(current_ptr) {
                        write!(out, " {}", sym.name)?;
                    }
                    // Don't deref into .text
                    continue;
                }
                Some(MappingType::ExecData) => {
                    if let Some(sym) = core.lookup_symbol(current_ptr) {
                        print!(" {}", sym.name);
                    }
                }
                None => {
                    writeln!(out, "")?;
                    continue;
                }
                _ => {}
            }

            current_ptr = core.read_u64(current_ptr)?;

            loop {
                let map_ty = addrs.mapping_type(current_ptr);
                let desc = map_ty.map(|m| m.to_string()).unwrap_or_else(String::new);
                write!(
                    out,
                    "\n     -> {current_ptr:#018x} {desc:>9} {}",
                    format_value(current_ptr)
                )?;

                match map_ty {
                    Some(MappingType::ExecText) | Some(MappingType::LibcText) => {
                        if let Some(sym) = core.lookup_symbol(current_ptr) {
                            write!(out, " {}", sym.name)?;
                        }
                        break;
                    }
                    Some(MappingType::ExecData) => {
                        if let Some(sym) = core.lookup_symbol(current_ptr) {
                            write!(out, " {}", sym.name)?;
                        }
                    }
                    None => break,
                    _ => {}
                }

                let next_ptr = core.read_u64(current_ptr)?;
                if current_ptr == next_ptr {
                    break;
                }
                current_ptr = next_ptr;
            }
            writeln!(out, "")?;
        }

        if !self.has_cfi {
            writeln!(out, "No control flow information")?;
        }

        Ok(())
    }

    fn eval_piece<'a>(&self, piece: &Piece<Slice<'a>>) -> Result<Option<(String, u64)>> {
        // let offset = match piece.bit_offset {
        //     Some(off) if off % 8 == 0 => off,
        //     Some(off) => {
        //         anyhow::bail!("bit offset {off} is not on a byte boundary")
        //     }
        //     None => 0,
        // };
        match piece.location {
            Location::Empty => Ok(None),
            Location::Register { register } => {
                let reg = Reg::from(register);
                if !reg.is_callee_saved() {
                    return Ok(None);
                }
                Ok(Some((format!("%{reg}"), self.regs[reg])))
            }
            Location::Value { value } => Ok(Some(("<immediate>".to_string(), value.to_u64(0)?))),
            Location::Bytes { value } => {
                eprintln!("CONST BYTES {value:?}");
                Ok(Some(("<const>".to_string(), 0)))
            }
            Location::Address { address } => Ok(Some(("   ".to_string(), address))),
            Location::ImplicitPointer { value, byte_offset } => {
                todo!();
            }
        }
    }
}

fn eval_piece<'a>(
    piece: &Piece<Slice<'a>>,
    regs: &Regs,
    core: &Core,
) -> Result<Option<(String, u64)>> {
    let &Piece {
        size_in_bits,
        bit_offset,
        location,
    } = piece;
    if size_in_bits.is_some() || bit_offset.is_some() {
        todo!("complicated expression piece {piece:?}");
    }
    // let offset = match piece.bit_offset {
    //     Some(off) if off % 8 == 0 => off,
    //     Some(off) => {
    //         anyhow::bail!("bit offset {off} is not on a byte boundary")
    //     }
    //     None => 0,
    // };
    match location {
        Location::Empty => Ok(None),
        Location::Register { register } => {
            let reg = Reg::from(register);
            if !reg.is_callee_saved() {
                return Ok(None);
            }
            Ok(Some((format!("%{reg}"), regs[reg])))
        }
        Location::Value { value } => Ok(Some(("<immediate>".to_string(), value.to_u64(0)?))),
        Location::Bytes { value } => {
            eprintln!("CONST BYTES {value:?}");
            Ok(Some(("<const>".to_string(), 0)))
        }
        Location::Address { address } => {
            let size = piece.size_in_bits.unwrap_or(64) / 8;
            let value = match size {
                8 => core.read_u64(address)?,
                4 => core.read_u32(address)? as u64,
                2 => core.read_u16(address)? as u64,
                1 => core.read_u8(address)? as u64,
                _ => anyhow::bail!("expression piece had unexpected read size of {size}"),
            };
            Ok(Some(("   ".to_string(), value)))
        }
        Location::ImplicitPointer { value, byte_offset } => {
            todo!();
        }
    }
}

/// Indicates how the variable's location was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocationKind {
    /// The value is stored at a memory address (need to read from it)
    Memory,
    /// The value is directly available (e.g., in a register)
    Direct,
}

/// Extract the base address from location pieces, if available.
/// Returns the address and whether it's a memory location or direct value.
fn get_base_address_from_pieces<'a>(
    pieces: &[Piece<Slice<'a>>],
    regs: &Regs,
) -> Option<(u64, LocationKind)> {
    if pieces.len() != 1 {
        return None;
    }
    match pieces[0].location {
        Location::Address { address } => Some((address, LocationKind::Memory)),
        Location::Register { register } => {
            let reg = Reg::from(register);
            Some((regs[reg], LocationKind::Direct))
        }
        _ => None,
    }
}

fn print_stuff(
    out: &mut dyn Write,
    indent: usize,
    current_ptr: u64,
    name: &str,
    addrs: &AddrRanges,
    core: &Core,
) -> Result<()> {
    let mut current_ptr = current_ptr;
    let map_ty = addrs.mapping_type(current_ptr);
    let desc = map_ty.map(|m| m.to_string()).unwrap_or_else(String::new);
    write!(
        out,
        "{}{name}: {current_ptr:#018x} {desc:>9} {}",
        " ".repeat(indent),
        format_value(current_ptr)
    )?;

    match map_ty {
        Some(MappingType::ExecText) => {
            if let Some(sym) = core.lookup_symbol(current_ptr) {
                write!(out, " {}", sym.name)?;
            }
            // Don't deref into .text
            return Ok(());
        }
        Some(MappingType::ExecData) => {
            if let Some(sym) = core.lookup_symbol(current_ptr) {
                print!(" {}", sym.name);
            }
        }
        None => {
            writeln!(out, "")?;
            return Ok(());
        }
        _ => {}
    }

    current_ptr = core.read_u64(current_ptr)?;

    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_ptr) {
            //write!(out, "\n     [cycle detected at {current_ptr:#018x}]")?;
            break;
        }
        let map_ty = addrs.mapping_type(current_ptr);
        let desc = map_ty.map(|m| m.to_string()).unwrap_or_else(String::new);
        write!(
            out,
            "\n{}-> {current_ptr:#018x} {desc:>9} {}",
            " ".repeat(indent + 2),
            format_value(current_ptr)
        )?;

        match map_ty {
            Some(MappingType::ExecText) | Some(MappingType::LibcText) => {
                if let Some(sym) = core.lookup_symbol(current_ptr) {
                    write!(out, " {}", sym.name)?;
                }
                break;
            }
            Some(MappingType::ExecData) => {
                if let Some(sym) = core.lookup_symbol(current_ptr) {
                    write!(out, " {}", sym.name)?;
                }
            }
            None => break,
            _ => {}
        }
    }
    writeln!(out, "")?;

    Ok(())
}

fn format_value(data: u64) -> String {
    let chunk = data.to_ne_bytes();

    let hex_dump: String = chunk
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    // 'is_ascii_graphic' excludes spaces, so we check range 0x20..=0x7e
    let ascii_dump: String = chunk
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    format!("{hex_dump:<23}  |{ascii_dump}|")
}

struct Unwinder<'a> {
    core: &'a Core,
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
            symbol: self.core.lookup_symbol(regs.rip),
            modified_regs: Vec::new(),
            has_cfi: false,
        };
        frames.push(initial_frame);

        for _ in 0..max_frames {
            // TODO EXPLAIN
            if regs.rip < 0x1000 {
                break;
            }

            let mapping = self
                .core
                .lookup_map(pc)
                .with_context(|| format!("no mapping found for PC {pc:#x}"))?;
            let object = if mapping.vaddr == self.exec.map_addr {
                &self.exec
            } else if mapping.vaddr == self.libc.map_addr {
                &self.libc
            } else {
                // We only expect the executable and libc, all other mappings are unhandled.
                anyhow::bail!("unanticipated mapping at addr {pc:#x} - {mapping:?}")
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

                let prev_symbol = self
                    .core
                    .lookup_symbol(prev_regs.rip)
                    .or_else(|| self.core.lookup_symbol(prev_regs.rip - 1));
                return Ok(Some(Frame {
                    pc: prev_regs.rip,
                    regs: prev_regs,
                    symbol: prev_symbol,
                    modified_regs: Vec::new(),
                    has_cfi: false,
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
            .lookup_symbol(prev_regs.rip)
            .or_else(|| self.core.lookup_symbol(prev_regs.rip - 1));
        let prev_frame = Frame {
            pc: prev_pc,
            regs: prev_regs,
            symbol: prev_symbol,
            modified_regs,
            has_cfi: true,
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
            RegisterRule::SameValue => {
                // Register unchanged from caller
                Ok(Some(regs[reg]))
            }
            RegisterRule::Offset(offset) => {
                // Register saved at CFA + offset
                let addr = (cfa as i64 + offset) as u64;
                let val = self.core.read_u64(addr)?;
                // eprintln!("reading {reg} at offset {offset} from CFA -> {val:#x}",);
                Ok(Some(val))
            }
            RegisterRule::Register(other_reg) => {
                // eprintln!(
                //     "reading {reg} from reg {}: {:#x}",
                //     Reg::from(other_reg),
                //     regs[other_reg.into()]
                // );
                // Value is in another register
                Ok(Some(regs[other_reg.into()]))
            }
            RegisterRule::ValOffset(offset) => {
                // eprintln!("{reg} is offset value {:#x} from CFA", cfa as i64 + offset);
                // Value is CFA + offset (not a pointer)
                Ok(Some((cfa as i64 + offset) as u64))
            }
            RegisterRule::Expression(_) | RegisterRule::ValExpression(_) => {
                Err(anyhow::anyhow!("Register expressions not yet supported"))
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

                // 2. Extract the final result
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

#[derive(Debug)]
struct ObjectInfo<'a> {
    map_addr: u64,
    eh_frame_hdr: ParsedEhFrameHdr<Slice<'a>>,
    eh_frame: EhFrame<Slice<'a>>,
    bases: BaseAddresses,
    debug_info: Option<DebugInfo<'a>>,
}

impl<'a> ObjectInfo<'a> {
    pub fn parse(
        bytes: &'a [u8],
        map_addr: u64,
        debug_info: Option<DebugInfo<'a>>,
    ) -> Result<Self> {
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
            debug_info,
        })
    }
}

struct DwarfEval<'a> {
    cfa: u64,
    regs: &'a Regs,
    symbol_name: &'a str,
    unit_index: usize,
    entry_offset: UnitOffset,
    dwarf: &'a Dwarf<Slice<'a>>,
    core: &'a Core,
}

impl<'a> DwarfEval<'a> {
    pub fn print_arguments(
        pc: u64,
        cfa: u64,
        regs: &'a Regs,
        symbol_name: &'a str,
        unit_index: usize,
        entry_offset: UnitOffset,
        dwarf: &'a Dwarf<Slice<'a>>,
        core: &'a Core,
    ) -> Result<()> {
        let eval = DwarfEval {
            cfa,
            regs,
            symbol_name,
            unit_index,
            entry_offset,
            dwarf,
            core,
        };
        eval.exec(pc)
    }

    pub fn exec(&self, pc: u64) -> Result<()> {
        let header = self.dwarf.units().nth(self.unit_index)?.ok_or_else(|| {
            anyhow::anyhow!(
                "failed to find DWARF unit {} for {}",
                self.unit_index,
                self.symbol_name
            )
        })?;

        let unit = self.dwarf.unit(header)?;
        let concrete = unit.entry(self.entry_offset).with_context(|| {
            anyhow::anyhow!(
                "failed to get DIE at offset {:?} for {}",
                self.entry_offset,
                self.symbol_name
            )
        })?;

        // let name = self
        //     .get_die_name(&unit, &concrete)?
        //     .unwrap_or_else(|| "<unknown>".to_string());
        // println!("{name}");

        self.print_params(&unit, &concrete, pc)
    }

    fn get_die_name(
        &self,
        unit: &Unit<Slice<'a>>,
        entry: &DebuggingInformationEntry<Slice<'a>>,
    ) -> Result<Option<String>> {
        // Try direct name first
        if let Ok(Some(attr)) = entry.attr(DW_AT_name) {
            let name = self.dwarf.attr_string(unit, attr.value())?;
            return Ok(Some(name.to_string_lossy().to_string()));
        }

        // Try abstract_origin
        if let Some(AttributeValue::UnitRef(origin)) = entry.attr_value(DW_AT_abstract_origin)? {
            let abs = unit.entry(origin)?;
            if let Ok(Some(attr)) = abs.attr(DW_AT_name) {
                let name = self.dwarf.attr_string(unit, attr.value())?;
                return Ok(Some(name.to_string_lossy().to_string()));
            }
        }

        Ok(None)
    }

    fn print_params(
        &self,
        unit: &Unit<Slice<'a>>,
        concrete: &DebuggingInformationEntry<Slice<'a>>,
        pc: u64,
    ) -> Result<()> {
        let mut tree = unit.entries_tree(Some(concrete.offset()))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            if child.entry().tag() == DW_TAG_formal_parameter {
                self.evaluate_param(pc, unit, child.entry())?;
            }
        }
        Ok(())
    }

    fn evaluate_param(
        &self,
        pc: u64,
        unit: &Unit<Slice<'a>>,
        entry: &DebuggingInformationEntry<Slice<'a>>,
    ) -> Result<()> {
        // Name might be here or via abstract_origin
        let name = if let Ok(Some(attr)) = entry.attr(DW_AT_name) {
            self.dwarf
                .attr_string(unit, attr.value())?
                .to_string_lossy()
                .to_string()
        } else if let Some(AttributeValue::UnitRef(origin)) =
            entry.attr_value(DW_AT_abstract_origin)?
        {
            let abs = unit.entry(origin)?;
            if let Ok(Some(attr)) = abs.attr(DW_AT_name) {
                self.dwarf
                    .attr_string(unit, attr.value())?
                    .to_string_lossy()
                    .to_string()
            } else {
                "<anon>".to_string()
            }
        } else {
            "<anon>".to_string()
        };

        let location = match entry.attr(DW_AT_location)? {
            Some(attr) => attr,
            None => {
                println!("  Arg '{name}': <optimized out>");
                return Ok(());
            }
        };

        // This effectively runs a tiny VM to calculate where the data lives
        let expression = match location.value() {
            AttributeValue::Exprloc(expr) => expr,
            AttributeValue::LocationListsRef(offset) => {
                let mut locations = self.dwarf.locations(unit, offset)?;
                let mut valid_expr = None;

                // 1. Use PC - 1 for lookup (Call Site) vs PC (Return Address)
                // If this is the top-most frame (the crash site), use `pc`. (Never the case, no
                // DWARF for libc).
                // If this is a frame further down the stack, use `pc - 1`.
                // (Assuming you can pass a flag or infer this, typically `pc - 1` is safer for lookups)
                // NOTE: Done above in unwind_stack

                while let Some(loc) = locations.next()? {
                    let range = loc.range.begin..loc.range.end;
                    if range.contains(&pc) {
                        valid_expr = Some(loc.data);
                        break;
                    }
                }

                let Some(expr) = valid_expr else {
                    println!("  Arg '{name}': <optimized out / not live at PC {pc:#x}>",);
                    return Ok(());
                };
                expr
            }
            e => {
                eprintln!("Unhandled attribute {e:?}, ignoring");
                return Ok(());
            }
        };

        let mut eval = expression.evaluation(unit.encoding());
        let mut result = eval.evaluate()?;

        while !matches!(result, gimli::EvaluationResult::Complete) {
            match result {
                gimli::EvaluationResult::RequiresRegister { register, .. } => {
                    // TODO check if register is valid?
                    let val = self.regs[register.into()];
                    result = eval.resume_with_register(gimli::Value::Generic(val))?;
                }
                gimli::EvaluationResult::RequiresFrameBase => {
                    // IMPORTANT: Some variables are at RBP + offset.
                    // You need to calculate the CFA for this frame and return it here.
                    // For simplicity, assuming RBP is valid FrameBase for now,
                    // but ideally you read DW_AT_frame_base from the subprogram entry.
                    let rbp = self.regs[RBP];
                    result = eval.resume_with_frame_base(rbp)?;
                }
                // Handle memory reads if necessary (e.g. dereferencing pointers)
                gimli::EvaluationResult::RequiresMemory { address, size, .. } => {
                    let val = match size {
                        8 => self.core.read_u64(address)?,
                        4 => self.core.read_u32(address)? as u64,
                        2 => self.core.read_u16(address)? as u64,
                        1 => self.core.read_u8(address)? as u64,
                        _ => anyhow::bail!("CFA had unexpected read size of {size}"),
                    };
                    result = eval.resume_with_memory(Value::Generic(val))?;
                }
                gimli::EvaluationResult::RequiresCallFrameCfa => {
                    result = eval.resume_with_call_frame_cfa(self.cfa)?;
                }
                gimli::EvaluationResult::RequiresEntryValue(expr) => {
                    // 1. The 'expr' describes where the value lived at function entry.
                    //    (Usually just DW_OP_regN). We must evaluate this nested expression.
                    let mut nested_eval = expr.evaluation(unit.encoding());
                    let mut nested_result = nested_eval.evaluate()?;

                    // 2. Drive the nested evaluation loop
                    loop {
                        match nested_result {
                            gimli::EvaluationResult::Complete => break,
                            gimli::EvaluationResult::RequiresRegister { register, .. } => {
                                let val = self.regs[register.into()];
                                nested_result =
                                    nested_eval.resume_with_register(gimli::Value::Generic(val))?;
                            }
                            // Nested entry values (recursion) are technically possible but rare.
                            // For simplicity, we break if we hit complex requirements here.
                            _ => {
                                println!("  Arg '{name}': <recursive entry_value>");
                                return Ok(());
                            }
                        }
                    }

                    // 3. Extract the location result from the nested evaluation
                    let entry_val = match nested_eval.result()[..] {
                        [
                            gimli::Piece {
                                location: gimli::Location::Register { register },
                                ..
                            },
                        ] => {
                            let val = self.regs[register.into()];
                            gimli::Value::Generic(val)
                        }
                        // Sometimes entry_value can refer to stack locations
                        [
                            gimli::Piece {
                                location: gimli::Location::Address { address },
                                ..
                            },
                        ] => {
                            let val = self.core.read_u64(address)?; // Assuming 64-bit for simplicity
                            gimli::Value::Generic(val)
                        }
                        _ => {
                            println!("  Arg '{name}': <unknown entry_value location>");
                            return Ok(());
                        }
                    };

                    // 4. Resume the MAIN evaluation with the found value
                    result = eval.resume_with_entry_value(entry_val)?;
                }
                r => {
                    eprintln!("Unhandled EvaluationResult {r:?}, ignoring");
                    break;
                }
            }
        }

        // 4. Interpret Result
        match eval.result()[..] {
            [
                gimli::Piece {
                    location: gimli::Location::Register { register },
                    ..
                },
            ] => {
                let reg = register.into();
                let val = self.regs[reg];
                println!("  Arg '{name}': {reg} = {val:#x}");
            }
            [
                gimli::Piece {
                    location: gimli::Location::Address { address },
                    ..
                },
            ] => {
                let value = self
                    .core
                    .read_u64(address)
                    .context("failed to read stack value")?;
                println!("  Arg '{name}': Stack({address:#x}) {value:#x}");
            }
            [
                gimli::Piece {
                    location: gimli::Location::Value { value },
                    ..
                },
            ] => {
                println!("  Arg '{name}': = {value:?}");
            }
            _ => println!("  Arg '{name}': <complex location>"),
        }

        Ok(())
    }
}

struct EntryLoc {
    unit_index: usize,
    offset: UnitOffset,
}

impl EntryLoc {
    pub fn new(unit_index: usize, offset: UnitOffset) -> Self {
        Self { unit_index, offset }
    }
}

struct FrameEntries(pub HashMap<u64, EntryLoc>);

impl FrameEntries {
    pub fn find<'a>(frames: &[Frame], dwarf: &Dwarf<Slice<'a>>) -> Result<Self> {
        let mut map = HashMap::new();
        let mut units = dwarf.units();
        let mut unit_index = 0;

        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let unit_ref = UnitRef::new(dwarf, &unit);
            let mut entry = unit.entries();

            while let Some((_, entry)) = entry.next_dfs()? {
                if entry.tag() == DW_TAG_subprogram
                    && let Some(ranges) = get_die_ranges(&unit_ref, entry)?
                {
                    for frame in frames.iter().filter(|f| {
                        ranges
                            .iter()
                            .any(|r| (r.begin..r.end).contains(&f.regs.rip))
                    }) {
                        map.insert(frame.regs.rip, EntryLoc::new(unit_index, entry.offset()));
                    }
                }
            }
            unit_index += 1;
        }

        Ok(Self(map))
    }
}

pub fn get_die_ranges<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<Vec<gimli::Range>>> {
    // First, try DW_AT_ranges for non-contiguous ranges
    if let Some(ranges) = get_ranges_from_attr(unit, entry)? {
        return Ok(Some(ranges));
    }

    // Fall back to DW_AT_low_pc / DW_AT_high_pc
    get_low_high_pc(unit, entry)
}

fn get_ranges_from_attr<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<Vec<gimli::Range>>> {
    let ranges_attr = entry.attr_value(DW_AT_ranges)?;

    let offset = match ranges_attr {
        Some(AttributeValue::RangeListsRef(offset)) => offset.0,
        Some(AttributeValue::DebugRngListsIndex(index)) => {
            // DWARF 5 uses indices into .debug_rnglists
            let offset = unit.ranges_offset(index)?;
            offset.0 // TODO: is this actually equivalent to the DWARF 4 value?
        }
        _ => return Ok(None),
    };

    let mut ranges_iter = unit.ranges(gimli::RangeListsOffset(offset))?;
    let mut ranges = Vec::new();

    while let Some(range) = ranges_iter.next()? {
        // Skip empty ranges
        if range.begin < range.end {
            ranges.push(range);
        }
    }

    if ranges.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ranges))
    }
}

fn get_low_high_pc<'a>(
    unit: &UnitRef<Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<Vec<gimli::Range>>> {
    let Some(low_pc_attr) = entry.attr_value(DW_AT_low_pc)? else {
        return Ok(None);
    };

    let low_pc = match low_pc_attr {
        AttributeValue::Addr(addr) => addr,
        AttributeValue::DebugAddrIndex(index) => {
            // DWARF 5 uses indices into .debug_addr
            unit.address(index)?
        }
        _ => return Ok(None),
    };

    // DW_AT_high_pc can be an address or a length
    let Some(high_pc_attr) = entry.attr_value(DW_AT_high_pc)? else {
        return Ok(None);
    };

    let high_pc = match high_pc_attr {
        AttributeValue::Addr(addr) => addr,
        AttributeValue::DebugAddrIndex(index) => unit.address(index)?,
        // If it's a constant, it's a length relative to low_pc
        AttributeValue::Udata(len) => low_pc + len,
        AttributeValue::Data1(len) => low_pc + len as u64,
        AttributeValue::Data2(len) => low_pc + len as u64,
        AttributeValue::Data4(len) => low_pc + len as u64,
        AttributeValue::Data8(len) => low_pc + len,
        AttributeValue::Sdata(len) => {
            if len >= 0 {
                low_pc + len as u64
            } else {
                return Ok(None);
            }
        }
        _ => return Ok(None),
    };

    if low_pc < high_pc {
        Ok(Some(vec![gimli::Range {
            begin: low_pc,
            end: high_pc,
        }]))
    } else {
        Ok(None)
    }
}

fn find_variables_in_scope<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    func_offset: gimli::UnitOffset,
    pc: u64,
    regs: &Regs,
    core: &Core,
) -> Result<Vec<VariableLocation<'a>>> {
    let mut variables = Vec::new();
    let mut tree = unit.entries_tree(Some(func_offset)).unwrap();
    let root = tree.root().unwrap();

    collect_variables_recursive(unit, root, pc, regs.rsp, regs, core, &mut variables)?;
    Ok(variables)
}

fn collect_variables_recursive<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    node: gimli::EntriesTreeNode<Slice<'a>>,
    pc: u64,
    frame_base: u64,
    regs: &Regs,
    core: &Core,
    variables: &mut Vec<VariableLocation<'a>>,
) -> Result<()> {
    let entry = node.entry();
    //let frame_base = get_base_address(unit, entry);

    // For lexical blocks, check if PC is in range before descending
    if entry.tag() == DW_TAG_lexical_block {
        if let Some(ranges) = get_die_ranges(unit, entry)? {
            if !ranges.iter().any(|r| pc >= r.begin && pc < r.end) {
                return Ok(()); // PC not in this scope
            }
        }
    }

    // Collect variables and parameters
    if entry.tag() == DW_TAG_variable || entry.tag() == DW_TAG_formal_parameter {
        if let Some(info) = read_variable_info(unit, entry, pc, frame_base, regs, core)? {
            variables.push(info);
        }
        // if let Some(var) = extract_variable_info(dwarf, unit, entry, pc) {
        //     dbg!(var);
        //     variables.push(var);
        // }
    }

    // Recurse into children
    let mut children = node.children();
    while let Some(child) = children.next()? {
        collect_variables_recursive(unit, child, pc, frame_base, regs, core, variables)?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct FieldInfo {
    pub name: String,
    pub type_name: Option<String>,
    pub offset: u64,
    pub size: Option<u64>,
    pub value: Option<FieldValue>,
    pub nested_fields: Vec<FieldInfo>,
    /// If this field is a pointer/ref that was dereferenced, this holds the pointee address
    pub dereferenced_addr: Option<u64>,
}

#[derive(Debug)]
pub enum FieldValue {
    Unsigned(u64),
    Signed(i64),
    Bytes(Vec<u8>),
}

#[derive(Debug)]
pub struct VariableLocation<'a> {
    pub name: String,
    pub type_name: Option<String>,
    pub parts: Option<Vec<Piece<Slice<'a>>>>,
    pub size: Option<u64>,
    pub fields: Vec<FieldInfo>,
    /// If this variable is a pointer/ref that was dereferenced, this holds the pointee address
    pub dereferenced_addr: Option<u64>,
}

pub fn read_variable_info<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
    pc: u64,
    frame_base: u64,
    regs: &Regs,
    core: &Core,
) -> Result<Option<VariableLocation<'a>>> {
    let Some(name) = get_name(unit, entry)? else {
        return Ok(None);
    };
    let (type_name, size) = get_type_name_and_size(unit, entry)?;
    let address = evaluate_location(unit, entry, pc, frame_base, regs, core)?;

    // Calculate base address and location kind for reading fields
    let (base_addr, loc_kind) = address
        .as_ref()
        .and_then(|pieces| get_base_address_from_pieces(pieces, regs))
        .map(|(addr, kind)| (Some(addr), kind))
        .unwrap_or((None, LocationKind::Memory));

    // Get the type offset to check for pointer dereferencing
    let type_offset = entry.attr_value(DW_AT_type)?;

    // Get fields and track if we dereferenced a pointer
    let (fields, dereferenced_addr) = if let Some(AttributeValue::UnitRef(type_off)) = type_offset {
        // Check if this is a pointer type
        let (_, deref_addr) = resolve_type_with_deref(unit, type_off, base_addr, loc_kind, core)?;
        let fields = get_struct_fields(unit, entry, base_addr, loc_kind, core, 0)?;
        (fields, deref_addr)
    } else {
        (Vec::new(), None)
    };

    Ok(Some(VariableLocation {
        name,
        type_name,
        parts: address,
        size,
        fields,
        dereferenced_addr,
    }))
}

/// Maximum recursion depth for nested structs
const MAX_FIELD_DEPTH: usize = 5;

/// Get struct/union/class fields from a variable's type.
/// Also handles pointer/reference types by dereferencing them.
fn get_struct_fields<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
    base_addr: Option<u64>,
    loc_kind: LocationKind,
    core: &Core,
    depth: usize,
) -> Result<Vec<FieldInfo>> {
    if depth >= MAX_FIELD_DEPTH {
        return Ok(Vec::new());
    }

    // Get the type DIE
    let type_offset = match entry.attr_value(DW_AT_type)? {
        Some(AttributeValue::UnitRef(offset)) => offset,
        _ => return Ok(Vec::new()),
    };

    // Resolve through type modifiers (const, volatile, typedef, etc.) to get the concrete type
    let (concrete_offset, deref_addr) =
        resolve_type_with_deref(unit, type_offset, base_addr, loc_kind, core)?;

    let mut entries = unit.entries_at_offset(concrete_offset)?;
    entries.next_entry()?;
    let Some(type_entry) = entries.current() else {
        return Ok(Vec::new());
    };

    let tag = type_entry.tag();
    if tag != gimli::DW_TAG_structure_type
        && tag != gimli::DW_TAG_class_type
        && tag != gimli::DW_TAG_union_type
    {
        // Base types, enumerations, pointers without struct target, etc. don't have fields
        return Ok(Vec::new());
    }

    // Check if this is just a declaration (forward declaration without definition)
    if let Some(AttributeValue::Flag(true)) = type_entry.attr_value(gimli::DW_AT_declaration)? {
        return Ok(Vec::new());
    }

    // Use dereferenced address if we went through a pointer, otherwise use base_addr
    let effective_base = deref_addr.or(base_addr);

    // Enumerate members
    let mut fields = Vec::new();

    // We need to use entries_tree to iterate children, but we need to be careful
    // about borrowing. Get the offset and create a new tree.
    let type_offset = type_entry.offset();
    let mut tree = unit.entries_tree(Some(type_offset))?;
    let root = tree.root()?;
    let mut children = root.children();

    while let Some(child) = children.next()? {
        let child_tag = child.entry().tag();
        if child_tag == DW_TAG_member {
            if let Some(field) = read_member_info(unit, child.entry(), effective_base, core, depth)?
            {
                fields.push(field);
            }
        } else if child_tag == DW_TAG_variant_part {
            // This is a Rust enum - traverse into the variant_part
            let variant_fields =
                read_enum_variant_fields(unit, child.entry(), effective_base, core, depth)?;
            fields.extend(variant_fields);
        }
    }

    Ok(fields)
}

/// Get fields from a type, given its offset directly (used for nested field traversal).
/// For nested fields, we always use LocationKind::Memory since struct members are at memory addresses.
fn get_struct_fields_from_type_offset<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    type_offset: UnitOffset,
    base_addr: Option<u64>,
    core: &Core,
    depth: usize,
) -> Result<Vec<FieldInfo>> {
    if depth >= MAX_FIELD_DEPTH {
        return Ok(Vec::new());
    }

    // For nested fields, the base_addr is always a memory address
    let (concrete_offset, deref_addr) =
        resolve_type_with_deref(unit, type_offset, base_addr, LocationKind::Memory, core)?;

    let mut entries = unit.entries_at_offset(concrete_offset)?;
    entries.next_entry()?;
    let Some(type_entry) = entries.current() else {
        return Ok(Vec::new());
    };

    let tag = type_entry.tag();
    if tag != gimli::DW_TAG_structure_type
        && tag != gimli::DW_TAG_class_type
        && tag != gimli::DW_TAG_union_type
    {
        return Ok(Vec::new());
    }

    // Use dereferenced address if we went through a pointer
    let effective_base = deref_addr.or(base_addr);

    let mut fields = Vec::new();
    let entry_offset = type_entry.offset();
    let mut tree = unit.entries_tree(Some(entry_offset))?;
    let root = tree.root()?;
    let mut children = root.children();

    while let Some(child) = children.next()? {
        let child_tag = child.entry().tag();
        if child_tag == DW_TAG_member {
            if let Some(field) = read_member_info(unit, child.entry(), effective_base, core, depth)?
            {
                fields.push(field);
            }
        } else if child_tag == DW_TAG_variant_part {
            // This is a Rust enum - traverse into the variant_part
            let variant_fields =
                read_enum_variant_fields(unit, child.entry(), effective_base, core, depth)?;
            fields.extend(variant_fields);
        }
    }

    Ok(fields)
}

/// Read fields from a Rust enum's variant_part.
/// This handles the DWARF representation of Rust enums:
/// - DW_TAG_variant_part contains a discriminant (DW_AT_discr) and variants (DW_TAG_variant)
/// - Each DW_TAG_variant has a DW_AT_discr_value and contains DW_TAG_member entries
fn read_enum_variant_fields<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    variant_part: &DebuggingInformationEntry<Slice<'a>>,
    base_addr: Option<u64>,
    core: &Core,
    depth: usize,
) -> Result<Vec<FieldInfo>> {
    let mut fields = Vec::new();

    // Get the discriminant member to read the tag value
    let discr_value = read_discriminant_value(unit, variant_part, base_addr, core)?;

    // Now iterate through variants to find the active one
    let mut tree = unit.entries_tree(Some(variant_part.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();

    while let Some(child) = children.next()? {
        if child.entry().tag() == DW_TAG_variant {
            // Check if this variant matches the discriminant
            let variant_discr = child
                .entry()
                .attr_value(DW_AT_discr_value)?
                .and_then(|v| v.udata_value());

            // If we couldn't read the discriminant or it matches, show this variant's fields
            let is_match = match (discr_value, variant_discr) {
                (Some(actual), Some(expected)) => actual == expected,
                // If no discriminant (like unit variant or couldn't read), we can't determine
                // For now, just show the first variant or all variants
                (None, _) => true,
                (Some(_), None) => {
                    // This variant has no discr_value, might be the "default" variant
                    // In Rust DWARF, the default variant often has no DW_AT_discr_value
                    true
                }
            };

            if is_match {
                // Read the variant name if available
                let variant_name = get_name(unit, child.entry())?.unwrap_or_default();

                // Get member fields from this variant
                let mut variant_children = child.children();
                while let Some(member) = variant_children.next()? {
                    if member.entry().tag() == DW_TAG_member {
                        if let Some(mut field) =
                            read_member_info(unit, member.entry(), base_addr, core, depth)?
                        {
                            // Prefix field name with variant name if not empty
                            if !variant_name.is_empty() {
                                field.name = format!("{}::{}", variant_name, field.name);
                            }
                            fields.push(field);
                        }
                    }
                }

                // If we matched a specific discriminant, don't look at other variants
                if discr_value.is_some() && variant_discr.is_some() {
                    break;
                }
            }
        }
    }

    Ok(fields)
}

/// Read the discriminant value for an enum.
fn read_discriminant_value<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    variant_part: &DebuggingInformationEntry<Slice<'a>>,
    base_addr: Option<u64>,
    core: &Core,
) -> Result<Option<u64>> {
    // DW_AT_discr points to the discriminant member
    let discr_ref = match variant_part.attr_value(DW_AT_discr)? {
        Some(AttributeValue::UnitRef(offset)) => offset,
        _ => return Ok(None), // No discriminant (might be a single-variant enum)
    };

    // Get the discriminant member
    let mut entries = unit.entries_at_offset(discr_ref)?;
    entries.next_entry()?;
    let Some(discr_entry) = entries.current() else {
        return Ok(None);
    };

    // Get the offset of the discriminant within the struct
    let discr_offset = get_member_offset(unit, discr_entry)?;

    // Get the size of the discriminant
    let (_, discr_size) = get_type_name_and_size(unit, discr_entry)?;
    let discr_size = discr_size.unwrap_or(1) as usize;

    // Read the discriminant value from memory
    let Some(base) = base_addr else {
        return Ok(None);
    };
    let discr_addr = base + discr_offset.unwrap_or(0);

    let value = match discr_size {
        1 => core.read_u8(discr_addr)? as u64,
        2 => core.read_u16(discr_addr)? as u64,
        4 => core.read_u32(discr_addr)? as u64,
        8 => core.read_u64(discr_addr)?,
        _ => return Ok(None),
    };

    Ok(Some(value))
}

/// Chase through typedefs, const, volatile, pointers, references etc. to get the underlying
/// concrete type offset. If we go through a pointer/reference, dereference it and return
/// the new base address.
///
/// `loc_kind` indicates whether `base_addr` is a memory address containing the variable,
/// or the variable's value directly (e.g., from a register).
///
/// Returns (concrete_type_offset, Option<dereferenced_address>)
fn resolve_type_with_deref<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    mut type_offset: UnitOffset,
    base_addr: Option<u64>,
    loc_kind: LocationKind,
    core: &Core,
) -> Result<(UnitOffset, Option<u64>)> {
    let mut deref_addr: Option<u64> = None;
    let mut current_addr = base_addr;
    let mut current_kind = loc_kind;

    loop {
        let mut entries = unit.entries_at_offset(type_offset)?;
        entries.next_entry()?;
        let Some(entry) = entries.current() else {
            break;
        };

        let tag = entry.tag();

        // Handle pointer and reference types - dereference them
        if tag == gimli::DW_TAG_pointer_type || tag == gimli::DW_TAG_reference_type {
            if let Some(addr) = current_addr {
                // If the location is Direct (e.g., register), the value IS the pointer.
                // If the location is Memory, we need to read from that address to get the pointer.
                let pointee_addr = if current_kind == LocationKind::Direct {
                    // The value itself is the pointer
                    addr
                } else {
                    // Read the pointer value from memory
                    core.read_u64(addr)?
                };

                // Check if it's a valid pointer (not null, not obviously invalid)
                if pointee_addr != 0 && pointee_addr > 0x1000 {
                    deref_addr = Some(pointee_addr);
                    current_addr = Some(pointee_addr);
                    // After dereferencing, we now have a memory address
                    current_kind = LocationKind::Memory;
                } else {
                    // Null or invalid pointer, stop here
                    return Ok((type_offset, None));
                }
            }

            // Get the underlying type
            match entry.attr_value(DW_AT_type)? {
                Some(AttributeValue::UnitRef(offset)) => {
                    type_offset = offset;
                    continue;
                }
                _ => break, // void pointer or no type info
            }
        }

        // These are modifier tags that we should chase through (without dereferencing)
        let is_modifier = matches!(
            tag,
            gimli::DW_TAG_typedef
                | gimli::DW_TAG_const_type
                | gimli::DW_TAG_volatile_type
                | gimli::DW_TAG_restrict_type
                | gimli::DW_TAG_atomic_type
        );

        if !is_modifier {
            break;
        }

        // Get the underlying type
        match entry.attr_value(DW_AT_type)? {
            Some(AttributeValue::UnitRef(offset)) => {
                type_offset = offset;
            }
            _ => break,
        }
    }
    Ok((type_offset, deref_addr))
}

/// Chase through typedefs, const, volatile, etc. to get the underlying concrete type offset.
/// Does NOT dereference pointers - use resolve_type_with_deref for that.
fn resolve_to_concrete_type<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    mut type_offset: UnitOffset,
) -> Result<UnitOffset> {
    loop {
        let mut entries = unit.entries_at_offset(type_offset)?;
        entries.next_entry()?;
        let Some(entry) = entries.current() else {
            break;
        };

        let tag = entry.tag();
        // These are modifier tags that we should chase through
        let is_modifier = matches!(
            tag,
            gimli::DW_TAG_typedef
                | gimli::DW_TAG_const_type
                | gimli::DW_TAG_volatile_type
                | gimli::DW_TAG_restrict_type
                | gimli::DW_TAG_atomic_type
        );

        if !is_modifier {
            break;
        }

        // Get the underlying type
        match entry.attr_value(DW_AT_type)? {
            Some(AttributeValue::UnitRef(offset)) => {
                type_offset = offset;
            }
            _ => break,
        }
    }
    Ok(type_offset)
}

/// Read information about a struct member (DW_TAG_member).
fn read_member_info<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
    base_addr: Option<u64>,
    core: &Core,
    depth: usize,
) -> Result<Option<FieldInfo>> {
    // Get field name
    let name = match get_name(unit, entry)? {
        Some(n) => n,
        None => return Ok(None), // Anonymous field, skip for now
    };

    // Get field type info
    let (type_name, size) = get_type_name_and_size(unit, entry)?;

    // Get field offset within struct
    let offset = get_member_offset(unit, entry)?;

    // Calculate the field's address
    let field_addr = match (base_addr, offset) {
        (Some(base), Some(off)) => Some(base + off),
        _ => None,
    };

    // Read the field value if we have an address and size
    let value = match (field_addr, size) {
        (Some(addr), Some(sz)) => read_field_value(core, addr, sz),
        (Some(_addr), None) => {
            eprintln!("DEBUG read_member_info: field '{name}' has no size, type={type_name:?}");
            None
        }
        (None, _) => None,
    };

    // Get the type offset for this member to check if it's a pointer/struct
    let type_offset = entry.attr_value(DW_AT_type)?;

    // Try to get nested fields - this will dereference pointers if needed
    // Struct members are always at memory locations, so we use LocationKind::Memory
    let (nested_fields, dereferenced_addr) =
        if let Some(AttributeValue::UnitRef(type_off)) = type_offset {
            // Check if this is a pointer type and get dereferenced info
            let (_concrete_offset, deref_addr) =
                resolve_type_with_deref(unit, type_off, field_addr, LocationKind::Memory, core)?;

            // Get fields from the (possibly dereferenced) type
            let fields =
                get_struct_fields_from_type_offset(unit, type_off, field_addr, core, depth + 1)?;

            (fields, deref_addr)
        } else {
            (Vec::new(), None)
        };

    Ok(Some(FieldInfo {
        name,
        type_name,
        offset: offset.unwrap_or(0),
        size,
        value,
        nested_fields,
        dereferenced_addr,
    }))
}

/// Get the offset of a member within its containing struct.
fn get_member_offset<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<u64>> {
    let Some(attr) = entry.attr_value(DW_AT_data_member_location)? else {
        return Ok(Some(0)); // No offset means offset 0 (e.g., first member or union)
    };

    match attr {
        // Simple constant offset (most common case)
        AttributeValue::Udata(offset) => Ok(Some(offset)),
        AttributeValue::Sdata(offset) => Ok(Some(offset as u64)),
        AttributeValue::Data1(offset) => Ok(Some(offset as u64)),
        AttributeValue::Data2(offset) => Ok(Some(offset as u64)),
        AttributeValue::Data4(offset) => Ok(Some(offset as u64)),
        AttributeValue::Data8(offset) => Ok(Some(offset)),

        // DWARF expression (rare, but can happen for virtual base classes, etc.)
        AttributeValue::Exprloc(expr) => {
            // For now, try to evaluate simple expressions
            let mut eval = expr.evaluation(unit.encoding());
            let result = eval.evaluate()?;
            match result {
                EvaluationResult::Complete => {
                    let pieces = eval.result();
                    if let Some(piece) = pieces.first() {
                        match piece.location {
                            Location::Address { address } => Ok(Some(address)),
                            Location::Value { value } => Ok(Some(value.to_u64(0)?)),
                            _ => Ok(None),
                        }
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None), // Complex expression requiring more context
            }
        }
        _ => Ok(None),
    }
}

/// Read a field value from memory.
fn read_field_value(core: &Core, addr: u64, size: u64) -> Option<FieldValue> {
    match size {
        1 => core
            .read_u8(addr)
            .ok()
            .map(|v| FieldValue::Unsigned(v as u64)),
        2 => core
            .read_u16(addr)
            .ok()
            .map(|v| FieldValue::Unsigned(v as u64)),
        4 => core
            .read_u32(addr)
            .ok()
            .map(|v| FieldValue::Unsigned(v as u64)),
        8 => core.read_u64(addr).ok().map(FieldValue::Unsigned),
        _ if size <= 64 => {
            // For other sizes, read as bytes
            let mut buf = vec![0u8; size as usize];
            let mut offset = 0;
            while offset < size {
                let remaining = size - offset;
                let chunk_size = remaining.min(8);
                let chunk_addr = addr + offset;
                match chunk_size {
                    8 => {
                        if let Ok(v) = core.read_u64(chunk_addr) {
                            buf[offset as usize..offset as usize + 8]
                                .copy_from_slice(&v.to_ne_bytes());
                        } else {
                            return None;
                        }
                    }
                    4 => {
                        if let Ok(v) = core.read_u32(chunk_addr) {
                            buf[offset as usize..offset as usize + 4]
                                .copy_from_slice(&v.to_ne_bytes());
                        } else {
                            return None;
                        }
                    }
                    2 => {
                        if let Ok(v) = core.read_u16(chunk_addr) {
                            buf[offset as usize..offset as usize + 2]
                                .copy_from_slice(&v.to_ne_bytes());
                        } else {
                            return None;
                        }
                    }
                    1 => {
                        if let Ok(v) = core.read_u8(chunk_addr) {
                            buf[offset as usize] = v;
                        } else {
                            return None;
                        }
                    }
                    _ => {
                        // Read byte by byte for odd sizes
                        for i in 0..chunk_size {
                            if let Ok(v) = core.read_u8(chunk_addr + i) {
                                buf[(offset + i) as usize] = v;
                            } else {
                                return None;
                            }
                        }
                    }
                }
                offset += chunk_size;
            }
            Some(FieldValue::Bytes(buf))
        }
        _ => None, // Too large
    }
}

fn get_name<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<String>> {
    let attr = match entry.attr_value(DW_AT_name)? {
        Some(a) => a,
        None => return Ok(None),
    };

    match attr {
        AttributeValue::String(s) => Ok(Some(s.to_string_lossy().into_owned())),
        AttributeValue::DebugStrRef(offset) => {
            let s = unit.string(offset)?;
            Ok(Some(s.to_string_lossy().into_owned()))
        }
        _ => Ok(None),
    }
}

fn get_type_name_and_size<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<(Option<String>, Option<u64>)> {
    let type_offset = match entry.attr_value(DW_AT_type)? {
        Some(AttributeValue::UnitRef(offset)) => offset,
        _ => return Ok((None, None)),
    };

    // Navigate to the type DIE
    let mut entries = unit.entries_at_offset(type_offset)?;
    entries.next_entry()?;
    let type_entry = match entries.current() {
        Some(e) => e,
        None => return Ok((None, None)),
    };

    // Chase through typedefs, const, volatile, etc. to get the underlying type name
    let (name, size) = resolve_type_name(unit, type_entry)?;

    Ok((name, size))
}

fn resolve_type_name<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<(Option<String>, Option<u64>)> {
    let tag = entry.tag();

    // Get size from this DIE if present
    let size = entry
        .attr_value(DW_AT_byte_size)?
        .and_then(|v| v.udata_value());

    // Try to get name directly
    if let Some(name) = get_name(unit, entry)? {
        // For pointer and reference types without explicit size, default to 8 bytes (64-bit)
        let effective_size = match tag {
            gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => size.or(Some(8)),
            _ => size,
        };
        return Ok((Some(format_type_name(tag, &name)), effective_size));
    }

    // For modifiers, chase the DW_AT_type reference
    match tag {
        gimli::DW_TAG_pointer_type => {
            let (inner, _) = get_referenced_type_name(unit, entry)?;
            let name = match inner {
                Some(n) => format!("*{}", n),
                None => "*void".to_string(),
            };
            // Pointers are always 8 bytes on 64-bit platforms
            Ok((Some(name), size.or(Some(8))))
        }
        gimli::DW_TAG_reference_type => {
            let (inner, _) = get_referenced_type_name(unit, entry)?;
            let name = match inner {
                Some(n) => format!("&{}", n),
                None => "&?".to_string(),
            };
            // References are always 8 bytes on 64-bit platforms
            Ok((Some(name), size.or(Some(8))))
        }
        gimli::DW_TAG_const_type => {
            let (inner, inner_size) = get_referenced_type_name(unit, entry)?;
            let name = match inner {
                Some(n) => format!("const {}", n),
                None => "const ?".to_string(),
            };
            Ok((Some(name), size.or(inner_size)))
        }
        gimli::DW_TAG_volatile_type => {
            let (inner, inner_size) = get_referenced_type_name(unit, entry)?;
            let name = match inner {
                Some(n) => format!("volatile {}", n),
                None => "volatile ?".to_string(),
            };
            Ok((Some(name), size.or(inner_size)))
        }
        gimli::DW_TAG_restrict_type => {
            let (inner, inner_size) = get_referenced_type_name(unit, entry)?;
            Ok((inner, size.or(inner_size)))
        }
        gimli::DW_TAG_typedef => {
            // For typedef, we already tried the name above
            // Chase to underlying type
            get_referenced_type_name(unit, entry)
        }
        gimli::DW_TAG_array_type => {
            let (inner, _) = get_referenced_type_name(unit, entry)?;
            let count = get_array_count(&unit.unit, entry)?;
            let name = match (inner, count) {
                (Some(n), Some(c)) => format!("[{}; {}]", n, c),
                (Some(n), None) => format!("[{}]", n),
                (None, Some(c)) => format!("[?; {}]", c),
                (None, None) => "[?]".to_string(),
            };
            Ok((Some(name), size))
        }
        gimli::DW_TAG_subroutine_type => {
            // Function pointers are 8 bytes on 64-bit platforms
            Ok((Some("fn(...)".to_string()), size.or(Some(8))))
        }
        _ => Ok((None, size)),
    }
}

fn format_type_name(tag: gimli::DwTag, name: &str) -> String {
    match tag {
        gimli::DW_TAG_structure_type => format!("struct {}", name),
        gimli::DW_TAG_union_type => format!("union {}", name),
        gimli::DW_TAG_enumeration_type => format!("enum {}", name),
        gimli::DW_TAG_class_type => format!("class {}", name),
        gimli::DW_TAG_pointer_type => format!("pointer {}", name),
        gimli::DW_TAG_base_type => name.to_string(),
        t => {
            dbg!(t);
            name.to_string()
        }
    }
}

fn get_referenced_type_name<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<(Option<String>, Option<u64>)> {
    let type_offset = match entry.attr_value(DW_AT_type)? {
        Some(AttributeValue::UnitRef(offset)) => offset,
        _ => return Ok((None, None)),
    };

    let mut entries = unit.entries_at_offset(type_offset)?;
    entries.next_entry()?;
    match entries.current() {
        Some(type_entry) => resolve_type_name(unit, type_entry),
        None => Ok((None, None)),
    }
}

fn get_array_count<'a>(
    unit: &Unit<Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<u64>, gimli::Error> {
    let mut tree = unit.entries_tree(Some(entry.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();

    while let Some(child) = children.next()? {
        if child.entry().tag() == DW_TAG_subrange_type {
            // The count is stored directly.
            if let Some(count) = child
                .entry()
                .attr_value(DW_AT_count)?
                .and_then(|v| v.udata_value())
            {
                return Ok(Some(count));
            }
            // Calculate the count by subtracting offsets).
            if let Some(upper) = child
                .entry()
                .attr_value(DW_AT_upper_bound)?
                .and_then(|v| v.udata_value())
            {
                let lower = child
                    .entry()
                    .attr_value(DW_AT_lower_bound)?
                    .and_then(|v| v.udata_value())
                    .unwrap_or(0);
                return Ok(Some(upper - lower + 1));
            }
        }
    }
    Ok(None)
}

fn evaluate_location<'a>(
    unit: &UnitRef<'a, Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
    pc: u64,
    frame_base: u64,
    regs: &Regs,
    core: &Core,
) -> Result<Option<Vec<Piece<Slice<'a>>>>> {
    let Some(loc_attr) = entry.attr_value(DW_AT_location)? else {
        return Ok(None);
    };

    let expression = match loc_attr {
        AttributeValue::Exprloc(expr) => expr,
        AttributeValue::LocationListsRef(offset) => {
            // Find the location list entry for our PC.
            let mut locs = unit.locations(offset)?;
            let mut found = None;
            while let Some(entry) = locs.next()? {
                if (entry.range.begin..entry.range.end).contains(&pc) {
                    found = Some(entry.data);
                    break;
                }
            }
            let Some(x) = found else {
                eprintln!("NO LOC LIST FOUND for pc {pc:#x} and frame base {frame_base:#x}");
                return Ok(None);
            };
            x
        }
        e => {
            eprintln!("UNHANDLED expression type {e:?}");
            return Ok(None);
        }
    };

    // Evaluate the expression
    let pieces = evaluate_expression(expression, unit.encoding(), frame_base, regs, core)?;
    Ok(Some(pieces))
}

fn evaluate_expression<'a>(
    expr: Expression<Slice<'a>>,
    encoding: Encoding,
    frame_base: u64,
    regs: &Regs,
    core: &Core,
) -> Result<Vec<Piece<Slice<'a>>>> {
    let mut eval = expr.evaluation(encoding);
    let mut result = eval.evaluate()?;

    loop {
        match result {
            EvaluationResult::Complete => break,
            EvaluationResult::RequiresFrameBase => {
                result = eval.resume_with_frame_base(frame_base)?;
            }
            EvaluationResult::RequiresRegister { register, .. } => {
                let val = regs[register.into()];
                result = eval.resume_with_register(Value::Generic(val))?;
            }
            EvaluationResult::RequiresMemory { address, .. } => {
                let val = core.read_u64(address)?;
                result = eval.resume_with_memory(Value::Generic(val))?;
            }
            EvaluationResult::RequiresRelocatedAddress(address) => {
                result = eval.resume_with_relocated_address(address)?;
            }
            EvaluationResult::RequiresCallFrameCfa => {
                result = eval.resume_with_call_frame_cfa(regs.rsp)?;
            }
            EvaluationResult::RequiresEntryValue(entry_expr) => {
                let pieces = evaluate_expression(entry_expr, encoding, frame_base, regs, core)?;
                let mut values = Vec::new();
                for piece in pieces {
                    if let Some((_, out)) = eval_piece(&piece, regs, core)? {
                        values.push(out);
                    }
                }
                if values.len() > 1 {
                    todo!("subexpression piece ct > 1: {values:?}");
                }
                let Some(value) = values.first() else {
                    return Ok(Vec::new());
                };
                result = eval.resume_with_entry_value(Value::Generic(*value))?;
            }
            e => {
                panic!("unhandled EvaluationResult {e:?}");
            }
        }
    }
    Ok(eval.result())
}

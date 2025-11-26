use anyhow::{Context as _, Result};
use clap::Parser;
use fallible_iterator::FallibleIterator;
use gimli::{
    AttributeValue, BaseAddresses, CfaRule, DW_AT_location, DW_TAG_formal_parameter,
    DW_TAG_variable, DebuggingInformationEntry, Dwarf, EhFrame, EhFrameHdr, EndianSlice,
    EvaluationResult, LittleEndian, ParsedEhFrameHdr, Reader, RegisterRule, Unit, UnitOffset,
    UnwindContext, UnwindSection, Value,
};
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64};
use goblin::elf::program_header::PT_LOAD;
use memmap2::Mmap;
use proc::{Core, LoadedObjectWithPath, Reg, Regs, x86_64::*};

use std::collections::HashMap;
use std::fs::File;
use std::ops::Range;
use std::path::{Path, PathBuf};

type Endian = LittleEndian;
type Slice<'a> = EndianSlice<'a, Endian>;

const PT_SUNW_UNWIND: u32 = 0x6464e550;

const _: () = assert!(usize::BITS >= 64, "host system must be at least 64-bit");

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

fn main() -> Result<()> {
    let args = Args::parse();

    let debug_file = args.debug_elf.as_deref().map(DebugFile::open).transpose()?;
    let debug_info = debug_file
        .as_ref()
        .map(|df| df.load_debug_info())
        .transpose()?;

    let core = Core::open(&args.core)
        .with_context(|| format!("failed to open {} as a core", args.core.display()))?;
    let core_mappings = core
        .mappings()
        .context("failed to retrieve memory mappings from core")?;

    let exec_mapping = core_mappings
        .first()
        .ok_or(anyhow::anyhow!("no mappings found in core"))?;
    let exec_bytes = load_object(exec_mapping, &core)?;
    let executable = ObjectInfo::parse(&exec_bytes, exec_mapping.vaddr, debug_info)
        .context("could not create unwinder for executable")?;

    let libc_mapping = core_mappings
        .iter()
        .find(|o| o.path.ends_with("libc.so.1"))
        .ok_or(anyhow::anyhow!("no mappings found for libc"))?;
    let libc_bytes = load_object(libc_mapping, &core)?;
    let libc = ObjectInfo::parse(&libc_bytes, libc_mapping.vaddr, None)
        .context("could not create unwinder for libc")?;

    let lwp = args.lwp.unwrap_or_else(|| core.status().active_lwp);
    let regs = core.regs(lwp)?;

    println!("LWP {lwp}");
    let unwinder = Unwinder {
        core,
        exec_vaddr: exec_mapping.vaddr,
        exec: executable,
        libc_vaddr: libc_mapping.vaddr,
        libc,
    };
    unwinder.unwind_stack(&regs, &mut UnwindContext::new(), 16)?;

    Ok(())
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
        eprintln!("building debug index");
        let debug_index = DebugIndex::build(&dwarf)?;
        eprintln!("building location index");
        let locations = LocationIndex::build(&dwarf)?;

        Ok(DebugInfo {
            dwarf,
            index: debug_index,
            locations,
        })
    }
}

#[derive(Debug)]
struct DebugInfo<'a> {
    dwarf: Dwarf<Slice<'a>>,
    index: DebugIndex,
    locations: LocationIndex,
}

fn load_object(object_mapping: &LoadedObjectWithPath, core: &Core) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; object_mapping.size as usize];
    let read_len = core
        .pread(&mut buf, object_mapping.vaddr)
        .context("failed to read libc mapping from core")?;
    if read_len != object_mapping.size {
        anyhow::bail!(
            "unexpected pread len {read_len:x} reading object, expected {:x}",
            object_mapping.size
        );
    }

    Ok(buf)
}

struct Unwinder<'a> {
    core: Core,
    exec_vaddr: u64,
    exec: ObjectInfo<'a>,
    libc_vaddr: u64,
    libc: ObjectInfo<'a>,
}

impl<'a> Unwinder<'a> {
    fn unwind_stack(
        &self,
        initial_regs: &Regs,
        ctx: &mut UnwindContext<usize>,
        max_frames: usize,
    ) -> Result<Vec<(u64, Regs)>> {
        let mut frames = vec![(initial_regs.rip, initial_regs.clone())];
        let mut regs = initial_regs.clone();

        let mut frm_nr = 0;
        let mut pc = regs.rip;
        for _ in 0..max_frames {
            let mapping = self
                .core
                .lookup_map(pc)
                .with_context(|| format!("no mapping found for addr {pc:#x}"))?;
            let object = if mapping.vaddr == self.exec_vaddr {
                &self.exec
            } else if mapping.vaddr == self.libc_vaddr {
                &self.libc
            } else {
                // We just handle the executable and libc, all other mappings are unhandled.
                anyhow::bail!("unanticipated mapping at addr {pc:#x} - {mapping:?}")
            };

            if !frm_nr == 0 {
                // PC will point to directly after function generally, or outside the function
                // entirely for functions without an epilogue. Adjust PC to handle this.
                pc -= 1;
            }

            match self.unwind_frame(frm_nr, pc, &regs, object, ctx) {
                Ok(Some(prev_regs)) => {
                    frames.push((pc, regs.clone()));
                    let prev_pc = prev_regs.rip;

                    if prev_pc == 0 || prev_pc < 0x1000 {
                        eprintln!("Stopping unwinding with PC value {prev_pc:#x}");
                        break;
                    }

                    pc = prev_pc;
                    regs = prev_regs.clone();
                }
                Ok(None) => {
                    println!("Unwinding complete");
                    break;
                }
                Err(e) => {
                    eprintln!("Unwinding failed: {}", e);
                    break;
                }
            }
            frm_nr += 1;
        }

        Ok(frames)
    }

    /// Attempt to pop the frame to the previous function based on the frame pointer.
    /// This does not modify register state other than RIP, RBP, and RSP.
    fn pop_frame(&self, initial_regs: &Regs) -> Result<Option<Regs>> {
        if initial_regs.rip == 0 {
            return Ok(None);
        }
        let mut regs = initial_regs.clone();
        for reg in REGS {
            // We probably can't assume anything about the state of caller-saved
            // registers.
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
    pub fn unwind_frame(
        &self,
        frm_nr: usize,
        pc: u64,
        regs: &Regs,
        object: &ObjectInfo,
        ctx: &mut UnwindContext<usize>,
    ) -> Result<Option<Regs>> {
        // We confirmed in `parse` that the table is present.
        let table = object.eh_frame_hdr.table().unwrap();

        println!("\n{}\n", "-".repeat(20));
        let symbol = self.core.lookup_symbol(pc);
        if let Some(sym) = &symbol {
            let function_offset = pc - sym.st_value;
            println!("#{frm_nr} {:#018x} {}+{function_offset:#x}", pc, sym.name);
        }

        let fde = match table.fde_for_address(
            &object.eh_frame,
            &object.bases,
            pc,
            gimli::EhFrame::cie_from_offset,
        ) {
            Ok(fde) => fde,
            Err(gimli::Error::NoUnwindInfoForAddress) => {
                let Some(prev_regs) = self
                    .pop_frame(regs)
                    .context("failed to pop stack of function without FDE")?
                else {
                    return Ok(None);
                };
                println!("\n{regs}");
                eprintln!("manually popped frame for function with no unwind information");

                return Ok(Some(prev_regs));
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        let row = fde.unwind_info_for_address(&object.eh_frame, &object.bases, ctx, pc)?;
        let encoding = fde.cie().encoding();

        // Compute the CFA (Canonical Frame Address)
        let cfa = self.compute_cfa(regs, row.cfa(), encoding, object)?;
        if let Some(debug_info) = &object.debug_info
            && let Some(symbol) = &symbol
        {
            // If we generated the DWARF separately from the original binary, then the PC for
            // the function in the debug info will be different. We can correct this by finding
            // the function by name and then giving DWARF our relative offset from its expected
            // PC. Is the unwind info valid? Maaaaaaybe?
            let function_offset = pc - symbol.st_value;
            if let Some(fn_info) = debug_info.index.find_by_name_and_offset(&symbol.name, pc) {
                DwarfEval::print_arguments(
                    pc,
                    cfa,
                    regs,
                    function_offset,
                    fn_info,
                    &symbol.name,
                    &debug_info.dwarf,
                    &self.core,
                )?;
            }
        }
        println!("\n{regs}");

        let mut prev_regs = Regs::default();
        for reg in REGS {
            if let Some(value) = self.restore_register(reg, regs, cfa, &row)? {
                prev_regs[reg] = value;
            }
        }

        let prev_pc = self
            .restore_register(RIP, regs, cfa, &row)?
            .ok_or_else(|| anyhow::anyhow!("Cannot find return address"))?;

        prev_regs.rsp = cfa;
        prev_regs.rip = prev_pc;

        if let Some(debug_info) = &object.debug_info {
            let callee_saved = [RBX, R12, R13, R14, R15];

            for &reg in &callee_saved {
                let value = regs[reg];

                // What variables claim to live in this register at this PC?
                let candidates = debug_info.locations.find_in_register(reg, pc);

                if !candidates.is_empty() {
                    eprintln!("  {reg} = {value:#x} might be:");
                    for var in candidates {
                        eprintln!(
                            "    - {} (from {:#x}..{:#x})",
                            var.name, var.range.0, var.range.1
                        );
                    }
                }
            }
        }

        Ok(Some(prev_regs))
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
                if Regs::is_callee_saved(reg) {
                    // Callee-saved register unmodified
                    return Ok(Some(regs[reg]));
                }
                // Register not preserved
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
                eprintln!("reading {reg} at offset {offset} from CFA -> {val:#x}",);
                Ok(Some(val))
            }
            RegisterRule::Register(other_reg) => {
                eprintln!(
                    "reading {reg} from reg {}: {:#x}",
                    Reg::from(other_reg),
                    regs[other_reg.into()]
                );
                // Value is in another register
                Ok(Some(regs[other_reg.into()]))
            }
            RegisterRule::ValOffset(offset) => {
                // Value is CFA + offset (not a pointer)
                eprintln!("{reg} is offset value {:#x} from CFA", cfa as i64 + offset);
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

                        // CASE C: Relocations (usually just return the address as-is)
                        EvaluationResult::RequiresRelocatedAddress(addr) => {
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
    eh_frame_hdr: ParsedEhFrameHdr<Slice<'a>>,
    eh_frame: EhFrame<Slice<'a>>,
    bases: BaseAddresses,
    debug_info: Option<DebugInfo<'a>>,
}

impl<'a> ObjectInfo<'a> {
    pub fn parse(
        bytes: &'a [u8],
        mapping_addr: u64,
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
        let load_bias = mapping_addr.wrapping_sub(vaddr);

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
        let eh_frame_offset = (eh_frame_addr - mapping_addr) as usize;
        if eh_frame_offset >= bytes.len() {
            anyhow::bail!(
                ".eh_frame offset {eh_frame_offset:#x} outside the mapping with size {:#x}",
                bytes.len()
            );
        }

        let eh_frame_slice = &bytes[eh_frame_offset..];
        let eh_frame = EhFrame::new(eh_frame_slice, LittleEndian);

        Ok(Self {
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
    function_offset: u64,
    function_info: &'a FunctionInstance,
    symbol_name: &'a str,
    dwarf: &'a Dwarf<Slice<'a>>,
    core: &'a Core,
}

impl<'a> DwarfEval<'a> {
    pub fn print_arguments(
        pc: u64,
        cfa: u64,
        regs: &'a Regs,
        function_offset: u64,
        function_info: &'a FunctionInstance,
        symbol_name: &'a str,
        dwarf: &'a Dwarf<Slice<'a>>,
        core: &'a Core,
    ) -> Result<()> {
        let eval = DwarfEval {
            cfa,
            regs,
            function_offset,
            function_info,
            symbol_name,
            dwarf,
            core,
        };
        eval.exec(pc)
    }

    pub fn exec(&self, pc: u64) -> Result<()> {
        let header = self
            .dwarf
            .units()
            .nth(self.function_info.unit_index)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "failed to find DWARF unit {} for {}",
                    self.function_info.unit_index,
                    self.symbol_name
                )
            })?;

        let unit = self.dwarf.unit(header)?;
        let concrete = unit
            .entry(self.function_info.entry_offset)
            .with_context(|| {
                anyhow::anyhow!(
                    "failed to get DIE at offset {:?} for {}",
                    self.function_info.entry_offset,
                    self.symbol_name
                )
            })?;

        let name = self
            .get_die_name(&unit, &concrete)?
            .unwrap_or_else(|| "<unknown>".to_string());
        println!("{name}");

        self.print_params(&unit, &concrete, pc)
    }

    fn get_die_name(
        &self,
        unit: &Unit<Slice<'a>>,
        entry: &DebuggingInformationEntry<Slice<'a>>,
    ) -> Result<Option<String>> {
        // Try direct name first
        if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name) {
            let name = self.dwarf.attr_string(unit, attr.value())?;
            return Ok(Some(name.to_string_lossy().to_string()));
        }

        // Try abstract_origin
        if let Some(AttributeValue::UnitRef(origin)) =
            entry.attr_value(gimli::DW_AT_abstract_origin)?
        {
            let abs = unit.entry(origin)?;
            if let Ok(Some(attr)) = abs.attr(gimli::DW_AT_name) {
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
            if child.entry().tag() == gimli::DW_TAG_formal_parameter {
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
        let name = if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name) {
            self.dwarf
                .attr_string(unit, attr.value())?
                .to_string_lossy()
                .to_string()
        } else if let Some(AttributeValue::UnitRef(origin)) =
            entry.attr_value(gimli::DW_AT_abstract_origin)?
        {
            let abs = unit.entry(origin)?;
            if let Ok(Some(attr)) = abs.attr(gimli::DW_AT_name) {
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

        let location = match entry.attr(gimli::DW_AT_location)? {
            Some(attr) => attr,
            None => {
                println!("  Arg '{}': <optimized out>", name);
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
                let lookup_pc = if pc > 0 { pc - 1 } else { pc };

                while let Some(loc) = locations.next()? {
                    if lookup_pc >= loc.range.begin && lookup_pc < loc.range.end {
                        valid_expr = Some(loc.data);
                        break;
                    }
                }

                let Some(expr) = valid_expr else {
                    println!(
                        "  Arg '{}': <optimized out / not live at PC {:#x}>",
                        name, lookup_pc
                    );
                    return Ok(());
                };
                expr
            }
            e => {
                eprintln!("Unhandled attribute {e:?}, ignoring");
                todo!();
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

    fn print_params_for_subprogram(
        &self,
        pc: u64,
        unit: &Unit<Slice<'a>>,
        subprogram: &DebuggingInformationEntry<Slice<'a>>,
    ) -> Result<()> {
        let mut tree = unit.entries_tree(Some(subprogram.offset()))?;
        let root = tree.root()?;
        let mut children = root.children();

        let name = if let Ok(Some(attr)) = subprogram.attr(gimli::DW_AT_name) {
            self.dwarf
                .attr_string(unit, attr.value())?
                .to_string_lossy()
                .to_string()
        } else {
            "<unknown>".to_string()
        };
        println!("{name}");

        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_formal_parameter {
                self.evaluate_variable(pc, unit, child.entry())?;
            }
        }
        Ok(())
    }

    fn evaluate_variable(
        &self,
        pc: u64,
        unit: &Unit<Slice<'a>>,
        entry: &DebuggingInformationEntry<Slice<'a>>,
    ) -> Result<()> {
        // 1. Get Variable Name
        let name = if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name) {
            self.dwarf
                .attr_string(unit, attr.value())?
                .to_string_lossy()
                .to_string()
        } else {
            "<anon>".to_string()
        };

        let location = match entry.attr(gimli::DW_AT_location)? {
            Some(attr) => attr,
            None => {
                println!("  Arg '{}': <optimized out>", name);
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
                let lookup_pc = if pc > 0 { pc - 1 } else { pc };

                while let Some(loc) = locations.next()? {
                    if lookup_pc >= loc.range.begin && lookup_pc < loc.range.end {
                        valid_expr = Some(loc.data);
                        break;
                    }
                }

                let Some(expr) = valid_expr else {
                    println!(
                        "  Arg '{}': <optimized out / not live at PC {:#x}>",
                        name, lookup_pc
                    );
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

// We kept 'register' because it allows instant CFI checks without touching DWARF.
#[derive(Debug)]
pub struct VariableRecord {
    pub range: Range<u64>,
    pub name: String,
    pub register: Option<u16>,    // Fast path: Cached register ID
    pub unit_index: usize,        // Pointer to the Compilation Unit
    pub entry_offset: UnitOffset, // Pointer to the Variable DIE
}

pub struct VarIndex {
    records: Vec<VariableRecord>,
}

impl VarIndex {
    pub fn build<'a>(dwarf: &Dwarf<Slice<'a>>) -> Result<Self> {
        let mut records = Vec::new();
        let mut units = dwarf.units();
        let mut unit_idx = 0;

        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();

            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_variable
                    || entry.tag() == gimli::DW_TAG_formal_parameter
                {
                    // 1. Get Name (reusing your recursive helper)
                    let name = get_name_recursive(dwarf, &unit, &entry).unwrap_or_default();
                    if name.is_empty() {
                        continue;
                    }

                    // 2. Extract ranges, but store POINTERS to the DIE, not the data
                    extract_locations(
                        dwarf,
                        &unit,
                        &entry,
                        &name,
                        unit_idx, // Pass the index so we can store it
                        &mut records,
                    )?;
                }
            }
            unit_idx += 1;
        }

        records.sort_by(|a, b| a.range.start.cmp(&b.range.start));
        Ok(Self { records })
    }

    /// Primary Use Case: Fast Register Check
    pub fn find_var_in_reg(&self, pc: u64, reg: u16) -> Option<&str> {
        let candidates = self.query_at_pc(pc);
        for record in candidates {
            if record.register == Some(reg) {
                return Some(&record.name);
            }
        }
        None
    }

    /// Helper to find candidates by PC
    fn query_at_pc(&self, pc: u64) -> Vec<&VariableRecord> {
        let start_idx = self.records.partition_point(|r| r.range.end <= pc);
        let mut results = Vec::new();

        for record in &self.records[start_idx..] {
            if record.range.start > pc {
                break;
            }
            if record.range.contains(&pc) {
                results.push(record);
            }
        }
        results
    }

    /// Slow Path: Fully resolve a variable's location from the DWARF
    /// Only needed if 'register' is None (e.g., stack offsets or complex expressions)
    pub fn resolve_location<'a>(
        &self,
        dwarf: &'a Dwarf<Slice<'a>>,
        record: &VariableRecord,
    ) -> Result<gimli::Location<Slice<'a>>> {
        // 1. Fetch the Unit
        let header = dwarf
            .units()
            .nth(record.unit_index)
            .context("Invalid unit index")?
            .unwrap();
        let unit = dwarf.unit(header)?;

        // 2. Fetch the DIE
        let entry = unit.entry(record.entry_offset)?;

        // 3. Re-parse the location attribute
        let attr = entry
            .attr_value(gimli::DW_AT_location)?
            .context("Variable has no location attribute")?;

        // 4. Find the specific expression for the PC (since DIEs can have lists)
        // We use the record's range start to uniquely identify which list entry matched.
        match attr {
            AttributeValue::Exprloc(expr) => {
                // It was a single expression, just return it
                evaluate_expr(&expr, unit.encoding())
            }
            AttributeValue::LocationListsRef(offset) => {
                let mut locations = dwarf.locations(&unit, offset)?;
                while let Some(loc) = locations.next()? {
                    // Match the specific range we stored in the record
                    if loc.range.begin == record.range.start {
                        return evaluate_expr(&loc.data, unit.encoding());
                    }
                }
                anyhow::bail!("Could not re-find location list entry");
            }
            _ => anyhow::bail!("Unsupported location format"),
        }
    }
}

// --- Updated Extractor ---

fn extract_locations<'a>(
    dwarf: &Dwarf<Slice<'a>>,
    unit: &Unit<Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
    name: &str,
    unit_index: usize,
    out: &mut Vec<VariableRecord>,
) -> Result<()> {
    let attr = match entry.attr_value(gimli::DW_AT_location)? {
        Some(a) => a,
        None => return Ok(()),
    };

    // Helper closure to push a record
    let mut push_record = |range: Range<u64>, expr: &gimli::Expression<Slice<'a>>| {
        // We eagerly evaluate ONLY simple registers for the cache.
        // Complex expressions are left as None in the 'register' field.
        let reg = parse_if_simple_register(expr, unit.encoding());

        out.push(VariableRecord {
            range,
            name: name.to_string(),
            register: reg,
            unit_index,
            entry_offset: entry.offset(),
        });
    };

    match attr {
        AttributeValue::Exprloc(expr) => {
            // For single expressions, valid range is technically the parent function's range.
            // You can pass u64::MAX or the actual function range if you have it.
            push_record(0..u64::MAX, &expr);
        }
        AttributeValue::LocationListsRef(offset) => {
            let mut locations = dwarf.locations(unit, offset)?;
            while let Some(loc) = locations.next()? {
                push_record(loc.range.begin..loc.range.end, &loc.data);
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_if_simple_register<'a>(
    expr: &gimli::Expression<Slice<'a>>,
    enc: gimli::Encoding,
) -> Option<u16> {
    let mut eval = expr.evaluation(enc);
    if let Ok(EvaluationResult::Complete) = eval.evaluate() {
        if let [
            gimli::Piece {
                location: gimli::Location::Register { register },
                ..
            },
        ] = eval.result().as_slice()
        {
            return Some(register.0);
        }
    }
    None
}

// Dummy helper for compilation context
fn evaluate_expr<'a>(
    expr: &gimli::Expression<Slice<'a>>,
    enc: gimli::Encoding,
) -> Result<gimli::Location<Slice<'a>>> {
    todo!();
    // In real code this runs the state machine.
    // For this example we just return a placeholder Result.
    Ok(gimli::Location::Register {
        register: gimli::Register(0),
    })
}

fn get_name_recursive<R: Reader>(
    _: &Dwarf<R>,
    _: &Unit<R>,
    _: &DebuggingInformationEntry<R>,
) -> Option<String> {
    todo!();
    Some("foo".to_string())
}

/// A single concrete instance of a function (either a real subprogram or an inlined copy)
#[derive(Clone, Debug)]
pub struct FunctionInstance {
    pub unit_index: usize,
    pub entry_offset: UnitOffset,

    /// If Some, this is an inlined instance - look here for name/params
    pub abstract_origin: Option<UnitOffset>,

    /// Address ranges where this code lives (start, end)
    pub ranges: Vec<Range<u64>>,
}

impl FunctionInstance {
    pub fn contains_pc(&self, pc: u64) -> bool {
        self.ranges.iter().any(|r| r.contains(&pc))
    }

    pub fn start_address(&self) -> u64 {
        self.ranges.first().map(|r| r.start).unwrap_or(0)
    }
}

/// Index entry: name -> all instances of that function
#[derive(Debug, Default)]
struct NameEntry {
    /// The abstract/declaration DIE (if any) - has param names/types
    abstract_die: Option<(usize, UnitOffset)>, // (unit_index, offset)

    /// All concrete instances, sorted by start address
    instances: Vec<FunctionInstance>,
}

#[derive(Debug)]
pub struct DebugIndex {
    /// Map: "stripped name" -> entry
    by_name: HashMap<String, NameEntry>,

    /// All instances sorted by start address for PC lookup
    by_address: Vec<FunctionInstance>,
}

impl DebugIndex {
    pub fn build<'a>(dwarf: &Dwarf<Slice<'a>>) -> Result<Self> {
        let mut by_name: HashMap<String, NameEntry> = HashMap::new();
        let mut all_instances: Vec<FunctionInstance> = Vec::new();

        // First pass: collect abstract origins (declarations) and their names
        // We need this because inlined_subroutine only has abstract_origin ref
        let mut abstract_origins: HashMap<(usize, UnitOffset), String> = HashMap::new();

        let mut units = dwarf.units();
        let mut unit_idx = 0;

        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();

            while let Some((_, entry)) = entries.next_dfs()? {
                match entry.tag() {
                    gimli::DW_TAG_subprogram => {
                        let name = get_entry_name(dwarf, &unit, entry)?;
                        let Some(name) = name else { continue };

                        let is_abstract = matches!(
                            entry.attr_value(gimli::DW_AT_inline)?,
                            Some(AttributeValue::Inline(
                                gimli::DW_INL_inlined | gimli::DW_INL_declared_inlined
                            ))
                        );

                        let offset = entry.offset();

                        // Store for abstract_origin lookups
                        abstract_origins.insert((unit_idx, offset), name.clone());

                        let name_entry = by_name.entry(name).or_default();

                        if is_abstract {
                            // Just a declaration - no code here
                            name_entry.abstract_die = Some((unit_idx, offset));
                        } else {
                            // Concrete subprogram with actual code
                            let ranges = get_entry_ranges(dwarf, &unit, entry)?;
                            if !ranges.is_empty() {
                                let instance = FunctionInstance {
                                    unit_index: unit_idx,
                                    entry_offset: offset,
                                    abstract_origin: None,
                                    ranges,
                                };
                                name_entry.instances.push(instance.clone());
                                all_instances.push(instance);
                            }
                        }
                    }

                    gimli::DW_TAG_inlined_subroutine => {
                        // Get the abstract origin to find the name
                        let origin = match entry.attr_value(gimli::DW_AT_abstract_origin)? {
                            Some(AttributeValue::UnitRef(o)) => o,
                            _ => continue,
                        };

                        let ranges = get_entry_ranges(dwarf, &unit, entry)?;
                        if ranges.is_empty() {
                            continue;
                        }

                        let instance = FunctionInstance {
                            unit_index: unit_idx,
                            entry_offset: entry.offset(),
                            abstract_origin: Some(origin),
                            ranges,
                        };

                        // We'll resolve the name after the pass
                        // For now, store with a placeholder key
                        all_instances.push(instance.clone());

                        // Try to find the name from abstract_origins we've seen
                        if let Some(name) = abstract_origins.get(&(unit_idx, origin)) {
                            by_name
                                .entry(name.clone())
                                .or_default()
                                .instances
                                .push(instance);
                        }
                        // If not found, the abstract might be in a different unit
                        // or we haven't seen it yet - we'd need a second pass
                        // or store and resolve later
                    }

                    _ => {}
                }
            }
            unit_idx += 1;
        }

        // Sort instances by address for efficient PC lookup
        all_instances.sort_by_key(|i| i.start_address());

        // Sort each name's instances by address
        for entry in by_name.values_mut() {
            entry.instances.sort_by_key(|i| i.start_address());
        }

        Ok(Self {
            by_name,
            by_address: all_instances,
        })
    }

    /// Find all function instances containing a PC (handles nested inlines)
    pub fn find_at_pc(&self, pc: u64) -> Vec<&FunctionInstance> {
        // Binary search to find starting point
        let start = self.by_address.partition_point(|i| i.start_address() <= pc);

        // Check instances that could contain this PC
        // Need to look backwards since we want instances that START before pc
        let mut results = Vec::new();

        for instance in &self.by_address[..start] {
            if instance.contains_pc(pc) {
                results.push(instance);
            }
        }

        // Also check a few after in case of edge cases with ranges
        for instance in self.by_address.get(start..).unwrap_or(&[]).iter().take(10) {
            if instance.start_address() > pc {
                break;
            }
            if instance.contains_pc(pc) {
                results.push(instance);
            }
        }

        results
    }
    pub fn find_by_name_and_offset(&self, name: &str, offset: u64) -> Option<&FunctionInstance> {
        let entry = self.by_name.get(name)?;

        // If only one instance, use it
        if entry.instances.len() == 1 {
            return entry.instances.first();
        }

        // Otherwise find one where offset fits within its size
        entry
            .instances
            .iter()
            .find(|inst| inst.ranges.iter().any(|r| r.contains(&offset)))
    }

    /// Get the abstract DIE for a function (for param names/types)
    pub fn get_abstract_die(&self, name: &str) -> Option<(usize, UnitOffset)> {
        self.by_name.get(name)?.abstract_die
    }
}

fn get_entry_name<'a>(
    dwarf: &Dwarf<Slice<'a>>,
    unit: &Unit<Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Option<String>> {
    let attr = if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_linkage_name) {
        attr
    } else if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name) {
        attr
    } else {
        return Ok(None);
    };

    let name = dwarf.attr_string(unit, attr.value())?;
    Ok(Some(name.to_string_lossy().to_string()))
}

fn get_entry_ranges<'a>(
    dwarf: &Dwarf<Slice<'a>>,
    unit: &Unit<Slice<'a>>,
    entry: &DebuggingInformationEntry<Slice<'a>>,
) -> Result<Vec<Range<u64>>> {
    let mut ranges = Vec::new();

    // Try low_pc/high_pc first
    if let Some(AttributeValue::Addr(low)) = entry.attr_value(gimli::DW_AT_low_pc)? {
        let high = match entry.attr_value(gimli::DW_AT_high_pc)? {
            Some(AttributeValue::Addr(h)) => h,
            Some(AttributeValue::Udata(offset)) => low + offset,
            _ => return Ok(ranges),
        };
        ranges.push(low..high);
        return Ok(ranges);
    }

    // Try DW_AT_ranges
    if let Some(attr) = entry.attr_value(gimli::DW_AT_ranges)? {
        let offset = match attr {
            AttributeValue::RangeListsRef(o) => dwarf.ranges_offset_from_raw(unit, o),
            AttributeValue::SecOffset(o) => {
                dwarf.ranges_offset_from_raw(unit, gimli::RawRangeListsOffset(o))
            }
            _ => return Ok(ranges),
        };

        let mut range_iter = dwarf.ranges(unit, offset)?;
        while let Some(range) = range_iter.next()? {
            ranges.push(range.begin..range.end);
        }
    }

    Ok(ranges)
}

/// A variable/parameter that's live at some address range
#[derive(Clone, Debug)]
pub struct LiveVariable {
    pub name: String,
    pub unit_index: usize,
    pub die_offset: UnitOffset,
    /// Where is this variable located? Register number or stack offset
    pub location: VariableLocation,
    /// PC range where this location is valid
    pub range: (u64, u64),
}

#[derive(Clone, Debug)]
pub enum VariableLocation {
    Register(u16),
    FrameOffset(i64), // CFA + offset
    Address(u64),
    EntryValue(u16), // Register at function entry
    Complex,
}

/// Index: register -> variables located in that register, sorted by start address
#[derive(Debug, Default)]
pub struct LocationIndex {
    by_register: HashMap<Reg, Vec<LiveVariable>>,
    by_address: Vec<LiveVariable>,
}

impl LocationIndex {
    pub fn build<'a>(dwarf: &Dwarf<Slice<'a>>) -> Result<Self> {
        let mut index = LocationIndex::default();

        let mut units = dwarf.units();
        let mut unit_idx = 0;

        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();

            while let Some((_, entry)) = entries.next_dfs()? {
                let tag = entry.tag();
                if tag != DW_TAG_formal_parameter && tag != DW_TAG_variable {
                    continue;
                }

                // Get name (direct or via abstract_origin)
                let name = Self::get_var_name(dwarf, &unit, entry)?
                    .unwrap_or_else(|| "<anon>".to_string());

                let Some(location_attr) = entry.attr(DW_AT_location)? else {
                    continue;
                };

                let die_offset = entry.offset();

                // Parse location - could be single expression or location list
                Self::parse_location(
                    dwarf,
                    &unit,
                    &location_attr,
                    &name,
                    unit_idx,
                    die_offset,
                    &mut index,
                )?;
            }
            unit_idx += 1;
        }

        // Sort for efficient lookup
        for vars in index.by_register.values_mut() {
            vars.sort_by_key(|v| v.range.0);
        }
        index.by_address.sort_by_key(|v| v.range.0);

        Ok(index)
    }

    fn parse_location<'a>(
        dwarf: &Dwarf<Slice<'a>>,
        unit: &Unit<Slice<'a>>,
        attr: &gimli::Attribute<Slice<'a>>,
        name: &str,
        unit_idx: usize,
        die_offset: UnitOffset,
        index: &mut LocationIndex,
    ) -> Result<()> {
        // Handle exprloc directly for simple single-location case
        // if let AttributeValue::Exprloc(expr) = attr.value() {
        //     if let Some(loc) = Self::parse_expression(expr.clone(), unit.encoding())? {
        //         let var = LiveVariable {
        //             name: name.to_string(),
        //             unit_index: unit_idx,
        //             die_offset,
        //             location: loc.clone(),
        //             range: (0, 1), // TODO FIXME
        //         };
        //         dbg!(&var);
        //         Self::add_to_index(index, loc, var);
        //     }
        //     return Ok(());
        // }

        // For location lists, use attr_locations
        let Some(mut locations) = dwarf.attr_locations(unit, attr.value())? else {
            return Ok(());
        };

        while let Some(entry) = locations.next()? {
            if let Some(loc) = Self::parse_expression(entry.data.clone(), unit.encoding())? {
                let var = LiveVariable {
                    name: name.to_string(),
                    unit_index: unit_idx,
                    die_offset,
                    location: loc.clone(),
                    range: (entry.range.begin, entry.range.end),
                };
                Self::add_to_index(index, loc, var);
            }
        }

        Ok(())
    }

    fn parse_expression<'a>(
        expr: gimli::Expression<Slice<'a>>,
        encoding: gimli::Encoding,
    ) -> Result<Option<VariableLocation>> {
        // We can't fully evaluate without runtime info, but we can
        // peek at simple cases
        let mut ops = expr.operations(encoding);

        // Look at first operation for simple cases
        let Some(op) = ops.next()? else {
            return Ok(None);
        };

        use gimli::Operation::*;
        let loc = match op {
            Register { register } => VariableLocation::Register(register.0),
            RegisterOffset {
                register, offset, ..
            } if register.0 == 6 => {
                // RBP-relative, common for frame base
                VariableLocation::FrameOffset(offset)
            }
            FrameOffset { offset } => VariableLocation::FrameOffset(offset),
            Address { address } => VariableLocation::Address(address),
            EntryValue { expression } => {
                // Recursively parse the entry value expression
                if let Some(VariableLocation::Register(r)) =
                    Self::parse_expression(gimli::Expression(expression), encoding)?
                {
                    VariableLocation::EntryValue(r)
                } else {
                    VariableLocation::Complex
                }
            }
            _ => VariableLocation::Complex,
        };

        Ok(Some(loc))
    }

    fn add_to_index(index: &mut LocationIndex, loc: VariableLocation, var: LiveVariable) {
        match &loc {
            VariableLocation::Register(r) => {
                index
                    .by_register
                    .entry(Reg(*r))
                    .or_default()
                    .push(var.clone());
            }
            VariableLocation::EntryValue(r) => {
                // Index by the entry register too
                index
                    .by_register
                    .entry(Reg(*r))
                    .or_default()
                    .push(var.clone());
            }
            _ => {}
        }
        index.by_address.push(var);
    }

    fn get_var_name<'a>(
        dwarf: &Dwarf<Slice<'a>>,
        unit: &Unit<Slice<'a>>,
        entry: &DebuggingInformationEntry<Slice<'a>>,
    ) -> Result<Option<String>> {
        if let Ok(Some(attr)) = entry.attr(gimli::DW_AT_name) {
            let s = dwarf.attr_string(unit, attr.value())?;
            return Ok(Some(s.to_string_lossy().to_string()));
        }

        if let Some(AttributeValue::UnitRef(origin)) =
            entry.attr_value(gimli::DW_AT_abstract_origin)?
        {
            let abs = unit.entry(origin)?;
            if let Ok(Some(attr)) = abs.attr(gimli::DW_AT_name) {
                let s = dwarf.attr_string(unit, attr.value())?;
                return Ok(Some(s.to_string_lossy().to_string()));
            }
        }

        Ok(None)
    }

    /// Find all variables in a given register at a given PC
    pub fn find_in_register(&self, reg: Reg, pc: u64) -> Vec<&LiveVariable> {
        let Some(vars) = self.by_register.get(&reg) else {
            return vec![];
        };

        vars.iter()
            .filter(|v| pc >= v.range.0 && pc < v.range.1)
            .collect()
    }

    /// Find all variables live at a PC
    pub fn find_at_pc(&self, pc: u64) -> Vec<&LiveVariable> {
        self.by_address
            .iter()
            .filter(|v| pc >= v.range.0 && pc < v.range.1)
            .collect()
    }
}

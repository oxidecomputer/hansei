use anyhow::{Context, Result};
use clap::Parser;
use gimli::{
    Attribute, AttributeValue, DW_AT_location, DW_AT_name, DW_TAG_formal_parameter,
    DW_TAG_subprogram, DebuggingInformationEntry, Dwarf, EndianSlice, Reader, RunTimeEndian, Unit,
    UnitHeader, UnitOffset,
};
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64, Header};
use goblin::elf::section_header::{
    SHN_UNDEF, SHT_DYNSYM, SHT_NOBITS, SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SectionHeader,
};
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use memmap2::Mmap;

use std::fs::File;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

#[derive(clap::Parser)]
struct Args {
    /// The corresponding ELF file with debug symbols.
    #[clap(long, short)]
    debug_elf: PathBuf,

    /// Address to find argument locs for.
    #[clap(long, short)]
    addr: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let addr = u64::from_str_radix(&args.addr, 16)?;

    let debug_file = File::open(&args.debug_elf)
        .with_context(|| format!("failed to open {}", args.debug_elf.display()))?;
    let debug_bytes = unsafe {
        Mmap::map(&debug_file)
            .with_context(|| format!("failed to mmap {}", args.debug_elf.display()))?
    };
    let debug_elf = Elf::parse(&debug_bytes)
        .with_context(|| format!("failed to parse {} as ELF", args.debug_elf.display()))?;

    if debug_elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
        anyhow::bail!("Only ELF64 is supported");
    }
    if !debug_elf.little_endian {
        anyhow::bail!("Only little-endian files are supported");
    }

    let endian = RunTimeEndian::Little;

    let loader = |section_id: gimli::SectionId| -> Result<EndianSlice<RunTimeEndian>> {
        let name = section_id.name();

        for sh in &debug_elf.section_headers {
            if let Some(section_name) = debug_elf.shdr_strtab.get_at(sh.sh_name)
                && section_name == name
            {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                return Ok(EndianSlice::new(&debug_bytes[start..end], endian));
            }
        }

        // Section not found.
        Ok(EndianSlice::new(&[], endian))
    };
    let dwarf = Dwarf::load(&loader)
        .with_context(|| format!("failed to load DWARF from {}", args.debug_elf.display()))?;

    find_function_args(&dwarf, addr)?;

    Ok(())
}

fn find_function_args<R: Reader>(dwarf: &Dwarf<R>, target_addr: u64) -> Result<()> {
    // Iterate through compilation units
    let mut units = dwarf.units();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;

        // Iterate through DIEs in this unit
        let mut entries = unit.entries();

        while let Some((_, entry)) = entries.next_dfs()? {
            // Look for subprograms (functions)
            if entry.tag() != DW_TAG_subprogram {
                continue;
            }

            // Check if this function contains our address
            let mut ranges = dwarf.die_ranges(&unit, entry)?;
            let mut contains_addr = false;

            while let Some(range) = ranges.next()? {
                if target_addr >= range.begin && target_addr < range.end {
                    contains_addr = true;
                    break;
                }
            }

            if !contains_addr {
                continue;
            }

            let func_name = if let Ok(Some(attr)) = entry.attr(DW_AT_name) {
                get_attr_string(dwarf, &attr)?
            } else {
                "<unknown>".to_string()
            };

            println!("Found function: {}", func_name);
            println!("  Address range contains: 0x{:x}", target_addr);

            // Now find formal parameters (arguments)
            let mut tree = unit.entries_tree(Some(entry.offset()))?;
            let node = tree.root()?;

            let mut children = node.children();
            while let Some(child) = children.next()? {
                let child_entry = child.entry();

                if child_entry.tag() == DW_TAG_formal_parameter {
                    process_parameter(dwarf, &unit, child_entry, target_addr)?;
                }
            }

            return Ok(());
        }
    }

    println!("Function not found at address 0x{:x}", target_addr);
    Ok(())
}

fn process_parameter<R: Reader>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
    pc: u64,
) -> Result<()> {
    let name = if let Ok(Some(attr)) = entry.attr(DW_AT_name) {
        get_attr_string(dwarf, &attr)?
    } else {
        "<unknown>".to_string()
    };

    println!("\n  Parameter: {}", name);

    // Get location
    if let Some(attr) = entry.attr(DW_AT_location)? {
        match attr.value() {
            AttributeValue::Exprloc(expr) => {
                // Simple location expression
                println!("    Location expression: {:?}", expr);
                decode_location_expr(expr, unit.encoding())?;
            }
            AttributeValue::LocationListsRef(offset) => {
                // Location list (changes during function execution)
                let mut loclists = dwarf.locations(unit, offset)?;

                println!("    Location varies by PC:");
                while let Some(loclist) = loclists.next()? {
                    println!(
                        "      Range: 0x{:x}..0x{:x}",
                        loclist.range.begin, loclist.range.end
                    );

                    // Check if our PC is in this range
                    if pc >= loclist.range.begin && pc < loclist.range.end {
                        println!("      ^^^ PC 0x{:x} is HERE", pc);
                        decode_location_expr(loclist.data, unit.encoding())?;
                    } else {
                        decode_location_expr(loclist.data, unit.encoding())?;
                    }
                }
            }
            _ => {
                println!("    Unexpected location attribute type");
            }
        }
    } else {
        println!("    No location information (optimized away?)");
    }

    Ok(())
}

fn decode_location_expr<R: Reader>(
    expr: gimli::Expression<R>,
    encoding: gimli::Encoding,
) -> Result<()> {
    let mut evaluation = expr.evaluation(encoding);
    let result = evaluation.evaluate()?;

    match result {
        gimli::EvaluationResult::Complete => {
            // Get the pieces
            let pieces = evaluation.result();
            for piece in pieces {
                match piece.location {
                    gimli::Location::Empty => {
                        println!("        -> Optimized away");
                    }
                    gimli::Location::Register { register } => {
                        println!("        -> Register: {}", register.0);
                    }
                    gimli::Location::Address { address } => {
                        println!("        -> Memory address: 0x{:x}", address);
                    }
                    gimli::Location::Value { value } => {
                        println!("        -> Constant value: {:?}", value);
                    }
                    _ => {
                        println!("        -> {:?}", piece.location);
                    }
                }
            }
        }
        _ => {
            println!("        Location expression needs runtime context");
        }
    }

    Ok(())
}

fn get_attr_string<R: Reader>(dwarf: &Dwarf<R>, attr: &Attribute<R>) -> Result<String> {
    match attr.value() {
        AttributeValue::DebugStrRef(offset) => {
            let s = dwarf.string(offset)?;
            Ok(s.to_string()?.into_owned())
        }
        AttributeValue::String(s) => Ok(s.to_string()?.into_owned()),
        _ => Ok(String::new()),
    }
}

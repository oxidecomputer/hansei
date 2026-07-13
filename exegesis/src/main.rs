use exegesis::DwReader;

use clap::{Parser, Subcommand};
#[cfg(not(target_os = "illumos"))]
use mimalloc::MiMalloc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use std::path::{Path, PathBuf};

#[cfg(not(target_os = "illumos"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(name = "exegesis", about = "async debug bundle extractor and inspector")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Parse a binary's DWARF and summarize its types and statics.
    DumpDwarf {
        /// ELF binary (or object file) with DWARF debug info.
        binary: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    match Cli::parse().cmd {
        Cmd::DumpDwarf { binary } => dump_dwarf(&binary),
    }
}

fn dump_dwarf(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let f = std::fs::File::open(path)?;
    let obj_bytes = unsafe { memmap2::Mmap::map(&f) }?;

    let obj = object::File::parse(&*obj_bytes)?;
    let endian = if object::Object::is_little_endian(&obj) {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<std::borrow::Cow<[u8]>, Box<dyn std::error::Error>> {
        use object::{Object, ObjectSection};
        Ok(match obj.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => std::borrow::Cow::Borrowed(&[]),
        })
    };
    let borrow_section = |section| gimli::EndianSlice::new(std::borrow::Cow::as_ref(section), endian);

    let dwarf_sections = gimli::DwarfSections::load(&load_section)?;
    let dwarf = dwarf_sections.borrow(borrow_section);

    let dw = DwReader::read_types(&dwarf, Default::default())?;
    println!("{} total types", dw.types.len());
    println!("{} total statics", dw.variables.len());
    println!("{} dup strings", dw.strings.dups_found());
    println!("{} total strings", dw.strings.len());
    Ok(())
}

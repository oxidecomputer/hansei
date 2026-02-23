use crate::parser::DwarfParser;

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use durin::write::CtfWriterBuilder;
use gimli::{DebugInfoOffset, Dwarf, EndianSlice, RunTimeEndian};
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64, Header};
use goblin::elf::section_header::{
    SHT_DYNSYM, SHT_NOBITS, SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SectionHeader,
};
use memmap2::Mmap;
use scroll::{LE, Pwrite};

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::mem::size_of;
use std::path::PathBuf;

mod parser;

/// Absolute offset of type in .debug_info.
type GlobalTypeOffset = DebugInfoOffset<usize>;

#[derive(clap::Parser)]
#[clap(group(ArgGroup::new("input").required(true).multiple(true)))]
#[clap(group(ArgGroup::new("output").required(true).multiple(true)))]
struct Args {
    /// An ELF file containing DWARF debug information.
    elf: PathBuf,

    /// The functions to generate CTF for parameter and return types.
    #[clap(long = "fn", short, value_name = "FN", group = "input")]
    func: Vec<String>,

    /// The types to generate CTF for.
    #[clap(long = "type", short, value_name = "TYPE", group = "input")]
    ty: Vec<String>,

    /// Path to write CTF to.
    #[clap(long, short, group = "output")]
    ctf_out: Option<PathBuf>,

    /// Path to write updated ELF with CTF to.
    #[clap(long, short, group = "output")]
    bin_out: Option<PathBuf>,
}

/// Copy the source Elf and insert the CTF data into it.
pub fn add_sunw_ctf(src: &[u8], elf: &Elf, ctf_data: &[u8]) -> Result<Vec<u8>> {
    if elf
        .section_headers
        .iter()
        .any(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".SUNW_ctf"))
    {
        anyhow::bail!("source binary already has a .SUNW_ctf section");
    }

    let ehdr = elf.header;
    let phdrs = elf.program_headers.to_vec();

    // --- Prepare shstrtab: copy RAW bytes and append ".SUNW_ctf\0" ---
    let shstr_src_i = ehdr.e_shstrndx as usize;
    let shstr_sh = elf
        .section_headers
        .get(shstr_src_i)
        .ok_or_else(|| anyhow::anyhow!("bad e_shstrndx {}", shstr_src_i))?;

    let shstr_off = shstr_sh.sh_offset as usize;
    let shstr_len = shstr_sh.sh_size as usize;
    if shstr_off
        .checked_add(shstr_len)
        .is_none_or(|end| end > src.len())
    {
        anyhow::bail!(
            "original .shstrtab out of bounds: off={} len={} file={}",
            shstr_off,
            shstr_len,
            src.len()
        );
    }

    let mut shstr_bytes = src[shstr_off..shstr_off + shstr_len].to_vec();
    let ctf_name_off = shstr_bytes.len();
    shstr_bytes.extend_from_slice(b".SUNW_ctf\0");

    // --- Choose link target for .SUNW_ctf: prefer .symtab else .dynsym ---
    let symtab_idx = elf
        .section_headers
        .iter()
        .position(|sh| sh.sh_type == SHT_SYMTAB);
    let dynsym_idx = elf
        .section_headers
        .iter()
        .position(|sh| sh.sh_type == SHT_DYNSYM);

    let link_target = symtab_idx
        .or(dynsym_idx)
        .ok_or_else(|| anyhow::anyhow!("no SHT_SYMTAB or SHT_DYNSYM present to link .SUNW_ctf"))?
        as u32;

    // --- Lay out the new file ---
    // [Ehdr][Phdrs][all original sections (with updated .shstrtab)][.SUNW_ctf][padding][Shdrs]
    let mut out = vec![0; ehdr.e_ehsize as usize]; // reserve Ehdr

    if ehdr.e_phnum > 0 {
        let phdr_bytes = (ehdr.e_phentsize as usize) * (ehdr.e_phnum as usize);
        out.resize(out.len() + phdr_bytes, 0);
    }
    let cur_off = &mut out.len();

    // Build new section headers: index 0 = NULL, then every original section in the same order
    let mut new_shdrs = Vec::with_capacity(elf.section_headers.len() + 2);
    new_shdrs.push(SectionHeader {
        sh_name: 0,
        sh_type: SHT_NULL,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 0,
        sh_entsize: 0,
    });

    // Copy each original section's data (except .shstrtab, which we replace with new bytes)
    for (i, sh) in elf.section_headers.iter().enumerate().skip(1) {
        let mut nsh = sh.clone();
        let addralign = nsh.sh_addralign.max(1);
        align_up(addralign, cur_off, &mut out);
        nsh.sh_offset = *cur_off as u64;

        if nsh.sh_type != SHT_NOBITS {
            if i == shstr_src_i {
                // write our updated shstrtab
                nsh.sh_size = shstr_bytes.len() as u64;
                out.resize(out.len() + shstr_bytes.len(), 0);
                out.gwrite(&*shstr_bytes, cur_off)
                    .context("write new shstrtab")?;
            } else if nsh.sh_size != 0 {
                // copy original payload
                let start = sh.sh_offset as usize;
                let end = start
                    .checked_add(sh.sh_size as usize)
                    .ok_or_else(|| anyhow::anyhow!("section size overflow (index {i})"))?;
                if end > src.len() {
                    anyhow::bail!("section {i} out of bounds: {start}..{end} > {}", src.len());
                }
                out.resize(out.len() + sh.sh_size as usize, 0);
                out.gwrite_with(&src[start..end], cur_off, ())
                    .context("write section header")?;
            }
        }
        // Keep sh_name as-is for existing sections (strings still valid; we only appended)
        new_shdrs.push(nsh);
    }

    // Append new .SUNW_ctf section (after all originals)
    let mut ctf_sh = SectionHeader {
        sh_name: ctf_name_off, // offset in *new* shstrtab
        sh_type: SHT_PROGBITS,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0, // set after alignment
        sh_size: ctf_data.len() as u64,
        sh_link: link_target, // point to symtab/dynsym (same index)
        sh_info: 0,
        sh_addralign: 4,
        sh_entsize: 0,
    };
    align_up(ctf_sh.sh_addralign, cur_off, &mut out);
    ctf_sh.sh_offset = *cur_off as u64;

    out.resize(out.len() + ctf_data.len(), 0);
    out.gwrite(ctf_data, cur_off)
        .context("failed to write CTF data")?;

    new_shdrs.push(ctf_sh);

    // Emit section header table at the end (aligned)
    let align = size_of::<u64>() as u64;
    align_up(align, cur_off, &mut out);
    let e_shoff = *cur_off;

    let shdr_size = size_of::<SectionHeader>();
    let shdr_len = new_shdrs.len() * shdr_size;
    let start = out.len();
    out.resize(start + shdr_len, 0);

    // Write section headers
    let woff = &mut start.clone();
    for sh in &new_shdrs {
        out.gwrite_with(sh.clone(), woff, LE.into())
            .context("write section header")?;
    }
    *cur_off = start + shdr_len;

    // Patch ELF header & PHDRs
    {
        let mut new_ehdr = ehdr;
        new_ehdr.e_phoff = if phdrs.is_empty() {
            0
        } else {
            size_of::<Header>() as u64
        };
        new_ehdr.e_shoff = e_shoff as u64;
        new_ehdr.e_shnum = new_shdrs.len() as u16;
        // e_shstrndx stays the SAME index (its content changed, not its position)
        new_ehdr.e_shstrndx = ehdr.e_shstrndx;

        out.pwrite_with(new_ehdr, 0, LE)
            .context("write ELF header")?;
    }

    if !phdrs.is_empty() {
        let off = &mut size_of::<Header>();
        for ph in &phdrs {
            out.gwrite_with(ph.clone(), off, LE.into())
                .context("write program header")?;
        }
    }

    Ok(out)
}

fn align_up(align: u64, cur_off: &mut usize, out: &mut Vec<u8>) {
    if align > 0 {
        let r = *cur_off as u64 % align;
        if r != 0 {
            let pad = (align - r) as usize;
            out.extend(std::iter::repeat_n(0u8, pad));
            *cur_off += pad;
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let debug_file =
        File::open(&args.elf).with_context(|| format!("failed to open {}", args.elf.display()))?;
    let debug_bytes = unsafe {
        Mmap::map(&debug_file).with_context(|| format!("failed to mmap {}", args.elf.display()))?
    };
    let debug_elf = Elf::parse(&debug_bytes)
        .with_context(|| format!("failed to parse {} as ELF", args.elf.display()))?;

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
        .with_context(|| format!("failed to load DWARF from {}", args.elf.display()))?;
    let mut parser = DwarfParser::build(&dwarf)?;
    let label = args
        .elf
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| args.elf.display().to_string());

    let mut builder = CtfWriterBuilder::new()
        .with_labels(vec![label])
        .with_truncate_str_len(1024)
        .with_replace_spaces("_");
    if args.bin_out.is_some() {
        builder = builder.with_elf(&debug_elf);
    }
    let mut writer = builder.build();

    let source_symbols: HashSet<_> = debug_elf
        .syms
        .iter()
        .filter_map(|sym| debug_elf.strtab.get_at(sym.st_name))
        .collect();

    let missing_fns: Vec<_> = args
        .func
        .iter()
        .filter(|f| !source_symbols.contains(f.as_str()))
        .collect();

    for missing in &missing_fns {
        eprintln!("'{missing}' was not found in {}", args.elf.display());
    }

    let mut symbols: HashMap<_, _> = args.func.into_iter().map(|name| (name, false)).collect();
    let mut type_names: HashMap<_, _> = args.ty.into_iter().map(|name| (name, false)).collect();

    // Find functions and collect their type dependencies in one pass
    let (function_info, mut type_deps) = parser
        .find_functions_and_collect_types(&mut symbols)
        .context("error finding functions and collecting types from DWARF")?;

    // Find explicitly requested types and merge their dependencies
    let explicit_type_deps = parser
        .find_types_by_name(&mut type_names)
        .context("error finding types from DWARF")?;

    // Merge type dependencies
    type_deps.all_types.extend(explicit_type_deps.all_types);
    type_deps.stubs.extend(explicit_type_deps.stubs);
    type_deps.deps.extend(explicit_type_deps.deps);
    type_deps
        .type_locations
        .extend(explicit_type_deps.type_locations);

    let missing_symbols: Vec<_> = symbols.iter().filter(|&(_name, found)| !found).collect();
    for (name, _) in &missing_symbols {
        eprintln!("\nFunction '{name}' not found in any compilation unit");
    }

    let missing_types: Vec<_> = type_names.iter().filter(|&(_name, found)| !found).collect();
    for (name, _) in &missing_types {
        eprintln!("\nType '{name}' not found in any compilation unit");
    }

    // Build CTF types from the collected dependencies
    let parsed_function_info = parser
        .build_fn_info_from_deps(&function_info, &type_deps, &mut writer)
        .context("failed to build types from DWARF debug data")?;
    for (name, func) in parsed_function_info {
        writer.add_func(name, func);
    }

    // Extract and add crate version markers
    let crate_versions = parser
        .extract_crate_versions()
        .context("failed to extract crate versions")?;
    writer.add_crate_versions(&crate_versions)?;

    let ctf_buffer = writer.generate_ctf().context("failed to generate CTF")?;

    if let Some(ctf_path) = &args.ctf_out {
        fs::write(ctf_path, &ctf_buffer)?;
    }

    if let Some(bin_out) = &args.bin_out {
        let updated_elf = add_sunw_ctf(&debug_bytes, &debug_elf, &ctf_buffer)
            .context("failed to generate updated ELF")?;

        fs::write(bin_out, &updated_elf)
            .with_context(|| format!("failed to write updated ELF to {}", bin_out.display()))?;

        let metadata = debug_file
            .metadata()
            .with_context(|| format!("failed to stat {}", args.elf.display()))?;
        fs::set_permissions(bin_out, metadata.permissions()).with_context(|| {
            format!(
                "failed to set permissions on updated ELF {}",
                bin_out.display()
            )
        })?;
    }

    Ok(())
}

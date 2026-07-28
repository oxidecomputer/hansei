use exegesis::DwReader;
use exegesis::bundle::{Bundle, StaticRole, TypeDef};

use clap::{Parser, Subcommand};
#[cfg(not(target_os = "illumos"))]
use mimalloc::MiMalloc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use std::path::{Path, PathBuf};

#[cfg(not(target_os = "illumos"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(
    name = "exegesis",
    about = "async debug bundle extractor and inspector"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Extract an async debug bundle from a debug binary's DWARF.
    Extract {
        /// Debug binary (or any DWARF-bearing object).
        binary: PathBuf,
        /// Output bundle path.
        #[arg(short, long)]
        output: PathBuf,
        /// Print extraction statistics.
        #[arg(long)]
        stats: bool,
        /// Extra root types to include, by fully-qualified name.
        #[arg(long = "include-type")]
        include_types: Vec<String>,
        /// Extract even when tokio infrastructure types or statics are
        /// missing (placeholders are emitted instead).
        #[arg(long)]
        allow_missing_infra: bool,
    },
    /// Parse a binary's DWARF and summarize its types and statics.
    DumpDwarf {
        /// ELF binary (or object file) with DWARF debug info.
        binary: PathBuf,
    },
    /// Print summary statistics for a bundle file.
    Stats {
        /// Bundle file produced by `exegesis extract`.
        bundle: PathBuf,
    },
    /// Dump a bundle's tables as text.
    Dump {
        /// Bundle file produced by `exegesis extract`.
        bundle: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    match Cli::parse().cmd {
        Cmd::Extract {
            binary,
            output,
            stats,
            include_types,
            allow_missing_infra,
        } => extract(&binary, &output, stats, include_types, allow_missing_infra),
        Cmd::DumpDwarf { binary } => dump_dwarf(&binary),
        Cmd::Stats { bundle } => stats(&bundle),
        Cmd::Dump { bundle } => dump(&bundle),
    }
}

fn extract(
    binary: &Path,
    output: &Path,
    print_stats: bool,
    include_types: Vec<String>,
    allow_missing_infra: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let opts = exegesis::extract::ExtractOptions {
        include_types,
        allow_missing_infra,
        extract_args: std::env::args().skip(1).collect::<Vec<_>>().join(" "),
    };
    let (bundle, stats) = exegesis::extract::extract_file(binary, &opts)?;
    bundle.save(output)?;
    println!(
        "wrote {} ({} types, {} task entries, {} dyn futures)",
        output.display(),
        bundle.types.types.len(),
        bundle.tasks.entries.len(),
        bundle.dyn_futures.by_symbol.len(),
    );
    if print_stats {
        print!("{stats}");
    }
    Ok(())
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

    let load_section =
        |id: gimli::SectionId| -> Result<std::borrow::Cow<[u8]>, Box<dyn std::error::Error>> {
            use object::{Object, ObjectSection};
            Ok(match obj.section_by_name(id.name()) {
                Some(section) => section.uncompressed_data()?,
                None => std::borrow::Cow::Borrowed(&[]),
            })
        };
    let borrow_section =
        |section| gimli::EndianSlice::new(std::borrow::Cow::as_ref(section), endian);

    let dwarf_sections = gimli::DwarfSections::load(&load_section)?;
    let dwarf = dwarf_sections.borrow(borrow_section);

    let dw = DwReader::read_types(&dwarf, Default::default())?;
    println!("{} total types", dw.types.len());
    println!("{} total statics", dw.variables.len());
    println!("{} dup strings", dw.strings.dups_found());
    println!("{} total strings", dw.strings.len());
    Ok(())
}

fn stats(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = Bundle::load(path)?;
    let m = &bundle.meta;
    println!("bundle: {}", path.display());
    println!("  format version:  {}", m.format_version);
    println!("  rustc:           {}", m.rustc_version);
    match &m.tokio_version {
        Some(v) => println!("  tokio:           {v}"),
        None => println!("  tokio:           (unknown)"),
    }
    println!("  debug binary:    {}", m.debug_binary.basename);
    println!("  extract args:    {}", m.extract_args);
    println!("  fingerprint:     {} symbols", m.symbol_fingerprint.len());

    let mut kinds = [
        ("base", 0usize),
        ("pointer", 0),
        ("array", 0),
        ("struct", 0),
        ("union", 0),
        ("enum", 0),
        ("c-enum", 0),
        ("opaque", 0),
    ];
    for def in &bundle.types.types {
        let slot = match def {
            TypeDef::Base { .. } => 0,
            TypeDef::Pointer { .. } => 1,
            TypeDef::Array { .. } => 2,
            TypeDef::Struct { .. } => 3,
            TypeDef::Union { .. } => 4,
            TypeDef::Enum { .. } => 5,
            TypeDef::CEnum { .. } => 6,
            TypeDef::Opaque { .. } => 7,
        };
        kinds[slot].1 += 1;
    }
    println!("  types:           {}", bundle.types.types.len());
    for (name, count) in kinds {
        if count > 0 {
            println!("    {name:<10} {count}");
        }
    }
    println!("  strings:         {}", bundle.strings.len());
    println!(
        "  task entries:    {} ({} symbol keys)",
        bundle.tasks.entries.len(),
        bundle.tasks.by_symbol.len()
    );
    println!(
        "    normalized     {} keys ({} ambiguous)",
        bundle.tasks.by_normalized_symbol.len(),
        bundle
            .tasks
            .by_normalized_symbol
            .values()
            .filter(|ids| ids.len() > 1)
            .count()
    );
    println!("  dyn futures:     {}", bundle.dyn_futures.by_symbol.len());
    println!(
        "    normalized     {} keys ({} ambiguous)",
        bundle.dyn_futures.by_normalized_symbol.len(),
        bundle
            .dyn_futures
            .by_normalized_symbol
            .values()
            .filter(|ids| ids.len() > 1)
            .count()
    );
    println!("  statics:         {}", bundle.statics.entries.len());
    let with_decl = bundle
        .provenance
        .entries
        .iter()
        .filter(|p| p.decl.is_some())
        .count();
    println!(
        "  provenance:      {}/{} with source location",
        with_decl,
        bundle.provenance.entries.len()
    );
    Ok(())
}

fn dump(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = Bundle::load(path)?;
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");

    println!("== types ({}) ==", bundle.types.types.len());
    for (i, def) in bundle.types.types.iter().enumerate() {
        match def {
            TypeDef::Base {
                name,
                size,
                encoding,
            } => {
                println!("[{i}] base {} size={size} {encoding:?}", s(*name));
            }
            TypeDef::Pointer { name, target } => {
                let name = name.map(s).unwrap_or("<anon>");
                println!("[{i}] pointer {name} -> [{}]", target.0);
            }
            TypeDef::Array { elem, count } => println!("[{i}] array [{}; {count}]", elem.0),
            TypeDef::Struct {
                name,
                size,
                members,
            } => {
                println!("[{i}] struct {} size={size}", s(*name));
                for m in members {
                    println!("      +{:<5} {} : [{}]", m.offset, s(m.name), m.ty.0);
                }
            }
            TypeDef::Union {
                name,
                size,
                members,
            } => {
                println!("[{i}] union {} size={size}", s(*name));
                for m in members {
                    println!("      +{:<5} {} : [{}]", m.offset, s(m.name), m.ty.0);
                }
            }
            TypeDef::Enum { name, size, shape } => {
                println!("[{i}] enum {} size={size}", s(*name));
                if let Some(d) = &shape.discr {
                    println!("      discr +{} : [{}]", d.offset, d.ty.0);
                }
                for v in &shape.variants {
                    let vals = match &v.discr_values {
                        None => "default".to_string(),
                        Some(dv) => format!("{:?}", dv.0),
                    };
                    let decl = v
                        .decl
                        .map(|l| format!(" @ {}:{}", s(l.file), l.line))
                        .unwrap_or_default();
                    // Only when it says something `decl` does not: an await
                    // whose two descriptions agree needs no second line.
                    let await_site = v
                        .await_site
                        .filter(|l| v.decl != Some(*l))
                        .map(|l| format!(" (awaited at {}:{})", s(l.file), l.line))
                        .unwrap_or_default();
                    println!(
                        "      {} ({vals}) +{} : [{}]{decl}{await_site}",
                        s(v.name),
                        v.payload.offset,
                        v.payload.ty.0
                    );
                }
            }
            TypeDef::CEnum {
                name,
                size,
                repr,
                enumerators,
            } => {
                println!("[{i}] c-enum {} size={size} repr=[{}]", s(*name), repr.0);
                for (ename, val) in enumerators {
                    println!("      {} = {val}", s(*ename));
                }
            }
            TypeDef::Opaque { name, size } => {
                println!("[{i}] opaque {} size={size:?}", s(*name));
            }
        }
        if let Some(format) = bundle
            .types
            .debug_formats
            .get(&exegesis::bundle::BundleTypeId(i as u32))
        {
            println!("      debug: {format:?}");
        }
    }

    println!("== tasks ({}) ==", bundle.tasks.entries.len());
    for (i, e) in bundle.tasks.entries.iter().enumerate() {
        println!(
            "[{i}] {} future=[{}] cell=[{}] stage=[{}] scheduler=[{}]",
            s(e.display_name),
            e.future.0,
            e.cell.0,
            e.stage.0,
            e.scheduler.0
        );
        if let Some(p) = bundle.provenance.entries.get(i) {
            let loc = p
                .decl
                .map(|l| format!("{}:{}", s(l.file), l.line))
                .unwrap_or_else(|| "<no decl>".into());
            println!("      {:?} {loc}", p.kind);
        }
    }
    println!("== task symbol keys ({}) ==", bundle.tasks.by_symbol.len());
    for (sym, id) in &bundle.tasks.by_symbol {
        println!("{sym} -> [{}]", id.0);
    }

    println!("== dyn futures ({}) ==", bundle.dyn_futures.by_symbol.len());
    for (sym, id) in &bundle.dyn_futures.by_symbol {
        println!("{sym} -> [{}]", id.0);
    }

    println!("== statics ({}) ==", bundle.statics.entries.len());
    for (role, def) in &bundle.statics.entries {
        let role = match role {
            StaticRole::TlsContextKey => "tls-context-key",
            StaticRole::TaskWakerVtable => "task-waker-vtable",
        };
        println!("{role}: {} ({})", def.symbol, def.display);
    }
    Ok(())
}

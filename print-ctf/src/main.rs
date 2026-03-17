use anyhow::{Context, Result};
use clap::Parser;
use durin::read::{CtfMemberIter, CtfReader, CtfType};

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(clap::Parser)]
struct Cli {
    /// The CTF file to read.
    ctf: PathBuf,

    /// The names of the types to print.
    #[clap(long = "type", short, value_name = "TYPE")]
    types: Vec<String>,

    /// The maximum depth for expanding nested types. A depth of 0 prints the
    /// top-level type without expanding members.
    #[clap(short = 'd', long, default_value_t = 3)]
    max_depth: usize,
}

fn main() {
    let args = Cli::parse();

    if let Err(e) = exec(&args) {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "Error: {e:?}");
        std::process::exit(1);
    }
}

fn exec(args: &Cli) -> Result<()> {
    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let reader = CtfReader::load(&ctf_bytes).context("failed to load CTF")?;
    let ctf = reader.view();

    let mut out = io::stdout().lock();

    let depth = 0;

    for name in &args.types {
        let iter = ctf.find_all(name);

        if iter.len() == 0 {
            writeln!(out, "Type {name} not found in CTF")?;
            continue;
        };

        for ctf_ty in iter {
            writeln!(out, "{}", format_type(&ctf_ty, depth, args.max_depth, 0))?;
        }
    }

    Ok(())
}

fn format_type(ty: &CtfType, depth: usize, max_depth: usize, abs_offset: u64) -> String {
    if depth > max_depth {
        return String::new();
    }

    let mut desc = ty_title(ty);

    match ty {
        CtfType::Unknown(_u) => {
            // No further formatting.
        }
        CtfType::Integer(i) => {
            desc.push_str(&format!(", size {}, encoding {:?}", i.size(), i.encoding()));
        }
        CtfType::Float(f) => {
            desc.push_str(&format!(", size {}, encoding {:?}", f.size(), f.encoding()));
        }
        CtfType::Pointer(p) => {
            desc.push_str(&format!(", target {}", ty_title(&p.target())));
        }
        CtfType::Array(a) => {
            desc.push_str(&format!(
                ", element type {}, len {}",
                a.element_type().name(),
                a.len()
            ));
        }
        CtfType::Function(f) => {
            desc.push_str(&format!(
                ", return type {}, is_varargs: {}",
                ty_title(&f.return_type()),
                f.is_varargs(),
            ));
            if f.arg_count() > 0 {
                desc.push_str(", args:");
            }
            for arg in f.args() {
                desc.push_str(&format!(
                    "\n <{}> {} {}",
                    arg.id().get(),
                    arg.kind(),
                    arg.name(),
                ));
            }
            todo!()
        }
        CtfType::Struct(s) => {
            desc.push_str(&format!(", size: {}", s.size()));
            if depth < max_depth {
                if s.members().len() > 0 {
                    desc.push_str(", members:");
                }
                desc.push_str(&format_members(
                    s.members(),
                    depth + 1,
                    max_depth,
                    abs_offset,
                ));
            }
        }
        CtfType::Union(u) => {
            desc.push_str(&format!(", size: {}", u.size()));

            if depth < max_depth {
                if u.members().len() > 0 {
                    desc.push_str(", members:");
                }
                desc.push_str(&format_members(
                    u.members(),
                    depth + 1,
                    max_depth,
                    abs_offset,
                ));
            }
        }
        CtfType::Enum(e) => {
            let iter = e.enumerators();
            if iter.len() > 0 {
                desc.push_str(", enumerators:");
            }
            for enumerator in e.enumerators() {
                desc.push_str(&format!(
                    "\n{}{}={}",
                    "  ".repeat(depth + 1),
                    enumerator.name(),
                    enumerator.value()
                ));
            }
        }
        CtfType::Forward(_f) => {
            // No further formatting.
        }
        CtfType::Typedef(t) => {
            desc.push_str(&format!(", target {}", ty_title(&t.target())));
        }
        CtfType::Volatile(v) => {
            desc.push_str(&format!(", target {}", ty_title(&v.target())));
        }
        CtfType::Const(c) => {
            desc.push_str(&format!(", target {}", ty_title(&c.target())));
        }
        CtfType::Restrict(r) => {
            desc.push_str(&format!(", target {}", ty_title(&r.target())));
        }
    }

    desc
}

fn format_members(
    members: CtfMemberIter,
    depth: usize,
    max_depth: usize,
    abs_offset: u64,
) -> String {
    let mut desc = String::new();
    if depth > max_depth {
        return desc;
    }

    for member in members {
        let mem_abs_off = abs_offset + member.offset();
        let member_desc = format_type(&member.ty(), depth, max_depth, mem_abs_off);
        if member_desc.is_empty() {
            desc.push_str(&format!(
                "\n{}{}, offset {}, abs_offset: {}, {}",
                "  ".repeat(depth),
                member.name(),
                member.offset(),
                mem_abs_off,
                ty_title(&member.ty())
            ));
        } else {
            desc.push_str(&format!(
                "\n{}{}, offset {}, abs_offset {}, {}",
                "  ".repeat(depth),
                member.name(),
                member.offset(),
                mem_abs_off,
                member_desc,
            ));
        }
    }

    desc
}

fn ty_title(ty: &CtfType) -> String {
    format!("<{}> {} {}", ty.id().get(), ty.kind(), ty.name())
}

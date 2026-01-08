use anyhow::{Context as _, Result};
use clap::Parser;
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64};
use goblin::elf::program_header::PT_LOAD;
use memmap2::Mmap;
use proc::{Core, SymbolBuf, x86_64::*};

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

#[derive(clap::Parser)]
struct Args {
    /// The core dump to open.
    core: PathBuf,

    /// The CTF to use.
    #[clap(long, short)]
    ctf: Option<PathBuf>,
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
    let core = Core::open(&args.core)
        .with_context(|| format!("failed to open {} as a core", args.core.display()))?;
    let addrs = AddrRanges::parse(&core).context("could not parse address mappings")?;

    let exec_bytes = load_object(&addrs.exec_text, &core).context("failed to load executable")?;
    let exec = ObjectInfo::parse(&exec_bytes, addrs.exec_text.start, debug_info)
        .context("could not parse object info for executable")?;

    Ok(())
}

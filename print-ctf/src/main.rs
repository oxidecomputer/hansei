use anyhow::{Context, Result};
use clap::Parser;
use durin::read::CtfReader;

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

    for name in &args.types {
        let iter = ctf.find_all(name);

        if iter.len() == 0 {
            writeln!(out, "Type {name} not found in CTF")?;
            continue;
        };

        for ctf_ty in iter {
            writeln!(out, "{ctf_ty:#?}")?;
        }
    }

    Ok(())
}

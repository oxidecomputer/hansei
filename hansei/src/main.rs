use anyhow::{Context as _, Result};
use clap::Parser;
use durin::read::CtfReader;
use proc::Core;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

pub mod tokio;
pub mod unwind;

#[derive(clap::Parser)]
struct Args {
    /// The core dump to open.
    core: PathBuf,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,
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

        let _ = writeln!(io::stderr(), "Error: {e:?}");
        std::process::exit(1);
    }
}

fn exec(args: Args, _out: &mut dyn io::Write) -> Result<()> {
    let core = Core::open(&args.core)
        .with_context(|| format!("failed to open {} as a core", args.core.display()))?;
    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes)?;

    let runtime = tokio::TokioRuntime::parse(&ctf, &core).context("failed to parse tokio state")?;

    for active in runtime.active_workers() {
        eprintln!("{:#?}", active.thd_ctx);
        for frame in active.backtrace.stack_trace(32) {
            eprintln!("{frame}");
        }
        eprintln!("");
    }
    eprintln!("{:#?}", runtime.scheduler);

    Ok(())
}

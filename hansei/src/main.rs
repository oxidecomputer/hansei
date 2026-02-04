use anyhow::{Context as _, Result};
use clap::{Args, Parser};
use durin::read::CtfReader;
use proc::Proc;

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

pub mod tokio;
pub mod unwind;

#[derive(clap::Parser)]
struct Cli {
    #[command(flatten)]
    source: Source,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Source {
    /// The pid of the process to inspect.
    #[arg(long)]
    pid: Option<i32>,

    /// The core dump to open.
    #[arg(long)]
    core: Option<PathBuf>,
}

fn main() {
    let args = Cli::parse();
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

fn exec(args: Cli, out: &mut dyn io::Write) -> Result<()> {
    let proc = match (args.source.pid, args.source.core) {
        (Some(pid), None) => Proc::open_pid(pid).with_context(|| "failed to open pid {pid}")?,
        (None, Some(ref core)) => {
            Proc::open_core(core).with_context(|| format!("failed to open {}", core.display()))?
        }
        _ => unreachable!(),
    };

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes)?;

    let runtime = tokio::TokioRuntime::parse(&ctf, &proc).context("failed to parse tokio state")?;

    let run_dur = runtime.now - runtime.scheduler.driver.time.time_source;
    writeln!(out, "Now: {:?}, Running for {:?}", runtime.now, run_dur)?;
    for active in runtime.active_workers() {
        writeln!(out, "{:#?}", active.thd_ctx)?;
        for frame in active.backtrace.stack_trace(32) {
            writeln!(out, "{frame}")?;
        }
        writeln!(out, "")?;
    }
    writeln!(out, "{:#?}", runtime.scheduler)?;

    Ok(())
}

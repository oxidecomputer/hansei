use anyhow::{Context as _, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use durin::read::CtfReader;
use jiff::{Unit, Zoned};
use proc::Proc;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub mod tokio;
pub mod unwind;

#[cfg(not(target_os = "illumos"))]
compile_error!("this crate only supports illumos");

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    Dump(Dump),
    Poll(Poll),
}

#[derive(Args)]
struct Poll {
    /// The pid of the process to inspect.
    #[arg(long)]
    pid: u32,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,

    /// How frequently tokio state should be polled, in milliseconds.
    #[arg(long, short)]
    freq: Option<u64>,
}

#[derive(Args)]
struct Dump {
    #[command(flatten)]
    source: Source,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,

    /// Include thread backtraces.
    #[arg(long, default_value_t = true, action = ArgAction::SetTrue, overrides_with="no_backtrace")]
    backtrace: bool,

    /// Don't include thread backtraces.
    #[arg(long, action = ArgAction::SetTrue, overrides_with="backtrace")]
    no_backtrace: bool,
}

impl Dump {
    fn capture_backtraces(&self) -> bool {
        if self.no_backtrace {
            false
        } else {
            self.backtrace
        }
    }
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Source {
    /// The pid of the process to inspect.
    #[arg(long)]
    pid: Option<u32>,

    /// The core dump to open.
    #[arg(long)]
    core: Option<PathBuf>,
}

fn main() {
    let args = Cli::parse();
    let mut stdout = io::stdout().lock();

    let res = match args.action {
        Action::Poll(poll) => exec_poll(poll, &mut stdout),
        Action::Dump(dump) => exec_dump(dump, &mut stdout),
    };
    if let Err(e) = res {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "Error: {e:?}");
        std::process::exit(1);
    }
}

fn exec_dump(args: Dump, out: &mut dyn io::Write) -> Result<()> {
    let proc = match (args.source.pid, &args.source.core) {
        (Some(pid), None) => Proc::grab_pid(pid).with_context(|| "failed to open pid {pid}")?,
        (None, Some(core)) => {
            Proc::open_core(core).with_context(|| format!("failed to open {}", core.display()))?
        }
        _ => unreachable!(),
    };
    let main_lwp = proc.lwp_handle(1)?;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes)?;

    let mut symbols = HashMap::new();
    let runtime = tokio::TokioRuntime::parse(
        &ctf,
        &proc,
        &main_lwp,
        &mut symbols,
        args.capture_backtraces(),
    )
    .context("failed to parse tokio state")?;

    let run_dur =
        Instant::from(runtime.now) - Instant::from(runtime.scheduler.driver.time.time_source);

    writeln!(out, "Now: {:?}, Running for {:?}", runtime.now, run_dur)?;
    for active in runtime.active_workers() {
        writeln!(out, "{:#?}", active.thd_ctx)?;
        if let Some(bt) = &active.backtrace {
            for frame in bt.stack_trace(32) {
                writeln!(out, "{frame}")?;
            }
        }
        writeln!(out, "")?;
    }
    writeln!(out, "{:#?}", runtime.scheduler)?;

    Ok(())
}

fn exec_poll(args: Poll, out: &mut dyn io::Write) -> Result<()> {
    const DEFAULT_FREQ: Duration = Duration::from_millis(2000);

    let proc = Proc::grab_pid_no_stop(args.pid).with_context(|| "failed to open pid {pid}")?;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes).context("failed to load CTF")?;

    let symbols = HashMap::new();

    let freq = args
        .freq
        .map(|f| Duration::from_millis(f))
        .unwrap_or(DEFAULT_FREQ);

    let main_lwp = proc.lwp_handle(1)?;

    // This assumes that process mappings remain stable over time, which isn't
    // the case. If we're polling for a few seconds its probably fine.
    // TODO fix this
    let ctx = tokio::Context::new(&proc, &main_lwp, &ctf, &symbols)
        .context("failed to create Context")?;

    let start_pause = Instant::now();
    // We need to read the worker's thread-local contexts.
    // We must stop the process in order to access register state.
    proc.stop(0).context("failed to stop process")?;

    let lwps = proc.lwps().context("failed to read lwps")?;

    proc.run().context("failed to set process to run")?;
    let end_pause = Instant::now();
    writeln!(out, "paused process for {:?}", end_pause - start_pause)?;

    // We assume that the address of the scheduler handle will remain constant
    // over time. It's not `Pin`, but it is an `Arc` and I don't think the
    // underlying heap pointer will be moved.
    let sched_info = tokio::MinTokioState::find_type_info(&ctx, &lwps)?;

    loop {
        let start = Instant::now();

        // We will get torn reads doing this without pausing the process,
        // particularly when reading the remotes to find the io driver. Each of
        // those is a separate allocation we need to `Pread`. Given that we're
        // mostly interested in whether the driver is stuck, getting an
        // inconsistent value on the io driver is a sacrifice worth making.
        let runtime = tokio::MinTokioState::parse(&ctx, &sched_info)
            .context("failed to parse tokio state")?;
        let now = Zoned::now().round(Unit::Second)?;
        writeln!(
            out,
            "\n{now}\n{} active workers\n{} total workers\n{} tasks",
            runtime.active.len(),
            runtime.worker_ct,
            runtime.task_ct,
        )?;
        if let Some(i) = runtime.io_driver {
            writeln!(out, "worker {i} is the io_driver")?;
        }

        let end = Instant::now();
        writeln!(out, "read took {:?}", end - start)?;

        std::thread::sleep(freq);
    }
}

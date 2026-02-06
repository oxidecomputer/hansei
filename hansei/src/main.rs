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

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes)?;

    let mut symbols = HashMap::new();
    let runtime = tokio::TokioRuntime::parse(&ctf, &proc, &mut symbols, args.capture_backtraces())
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

    let mut symbols = HashMap::new();

    // Pre-cache known symbol names, lookup is expensive.
    let sym_names = [
        "tokio::runtime::park::wake",
        "tokio::runtime::park::wake_by_ref",
        "tokio::runtime::park::clone",
        "tokio::runtime::park::drop_waker",
        "tokio::runtime::task::waker::wake_by_val",
        "tokio::runtime::task::waker::wake_by_ref",
        "tokio::runtime::task::waker::clone_waker",
        "tokio::runtime::task::waker::drop_waker",
        "tokio::util::wake::wake_arc_raw",
        "tokio::util::wake::wake_by_ref_arc_raw",
        "tokio::util::wake::clone_arc_raw",
        "tokio::util::wake::drop_arc_raw",
        "futures_util::stream::futures_unordered::task::waker_ref::wake_arc_raw",
        "futures_util::stream::futures_unordered::task::waker_ref::wake_by_ref_arc_raw",
        "futures_util::stream::futures_unordered::task::waker_ref::clone_arc_raw",
        "futures_util::stream::futures_unordered::task::waker_ref::drop_arc_raw",
    ];

    // There may be multiple addresses for a given method, most frequently due
    // to generics, but also inlining in some cases. Scan all symbols for
    for symbol in proc.symbols()? {
        let demangled = format!("{:#}", rustc_demangle::demangle(&symbol.name));
        if let Some(&sym_name) = sym_names.iter().find(|&&n| demangled == n) {
            symbols.insert(symbol.st_value, sym_name);
        }
    }

    let freq = args
        .freq
        .map(|f| Duration::from_millis(f))
        .unwrap_or(DEFAULT_FREQ);

    loop {
        let start = Instant::now();
        proc.stop(0).context("failed to stop process")?;

        let runtime = tokio::TokioRuntime::parse(&ctf, &proc, &mut symbols, false)
            .context("failed to parse tokio state")?;
        let active = runtime.active_workers();
        let now = Zoned::now().round(Unit::Second)?;
        writeln!(
            out,
            "\n{now}\n{} active workers\n{} total workers\n{} tasks",
            active.len(),
            runtime.scheduler.shared.idle.num_workers,
            runtime.scheduler.shared.owned.count
        )?;
        if let Some((i, _)) = runtime
            .scheduler
            .shared
            .remotes
            .iter()
            .enumerate()
            .find(|(_, r)| r.unpark.is_parked_driving_io())
        {
            writeln!(out, "worker {i} is the io_driver")?;
        }
        for worker in active {
            writeln!(
                out,
                "Worker: {:?}, Task ID: {:?}",
                worker.thd_ctx.worker_index, worker.thd_ctx.current_task_id
            )?;
            if let Some(task_id) = worker.thd_ctx.current_task_id {
                if let Some(task) = runtime
                    .scheduler
                    .shared
                    .owned
                    .tasks
                    .values()
                    .find(|t| t.id == task_id)
                {
                    writeln!(out, "{task:?}")?;
                }
            }
        }

        proc.run().context("failed to set process to run")?;

        let end = Instant::now();
        writeln!(out, "process stopped for {:?}", end - start)?;

        std::thread::sleep(freq);
    }
}

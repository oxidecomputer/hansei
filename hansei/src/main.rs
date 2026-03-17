use crate::tokio::{Context, MinTokioState, TokioRuntime};

use anyhow::{Context as _, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use console::{StyledObject, Term};
use durin::read::CtfReader;
use proc::Proc;

use std::collections::HashMap;
use std::fmt::Display;
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
    #[command(visible_alias = "dump")]
    SchedulerDump(Dump),
    Poll(Poll),
    #[command(visible_alias = "trace")]
    TaskTrace(TaskTrace),
}

#[derive(Args)]
struct TaskTrace {
    #[command(flatten)]
    source: Source,

    /// The address of the task in hexadecimal, e.g., 0x1234.
    #[clap(long, short)]
    addr: String,

    /// The type of the task.
    #[clap(long = "type", short)]
    ty: String,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,

    /// Pausing a live process is potentially destructive.
    /// Required if --pid is passed.
    #[arg(long, short = 'w')]
    destructive: bool,

    /// Show the variables present at each await point.
    #[clap(long, short)]
    verbose: bool,
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

    /// Dumping a live process is potentially destructive.
    /// Required if --pid is passed.
    #[arg(long, short = 'w')]
    destructive: bool,
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

impl Source {
    fn open_proc(&self, destructive: bool) -> Result<Proc> {
        match (self.pid, &self.core) {
            (Some(pid), None) => {
                anyhow::ensure!(
                    destructive,
                    "This command is potentially destructive when run against live \
                processes. Pass the `-w` / `--destructive` flag to allow it."
                );

                Proc::grab_pid(pid).with_context(|| "failed to grab pid {pid}")
            }
            (None, Some(core)) => {
                Proc::open_core(core).with_context(|| format!("failed to open {}", core.display()))
            }
            _ => unreachable!(),
        }
    }
}

fn main() {
    let args = Cli::parse();

    let res = match args.action {
        Action::Poll(poll) => exec_poll(poll, Term::stdout()),
        Action::SchedulerDump(dump) => exec_dump(dump, &mut io::stdout().lock()),
        Action::TaskTrace(dump) => exec_trace(dump, &mut io::stdout().lock()),
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
    let proc = args.source.open_proc(args.destructive)?;
    let main_lwp = proc.lwp_handle(1)?;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes).context("failed to load CTF")?;
    let view = ctf.view();

    let mut symbols = HashMap::new();
    let runtime = TokioRuntime::parse(
        view,
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

fn exec_poll(args: Poll, term: Term) -> Result<()> {
    const DEFAULT_FREQ: Duration = Duration::from_millis(200);

    let proc = Proc::grab_pid_no_stop(args.pid).with_context(|| "failed to open pid {pid}")?;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes).context("failed to load CTF")?;
    let view = ctf.view();

    let symbols = HashMap::new();

    let freq = args
        .freq
        .map(|f| Duration::from_millis(f))
        .unwrap_or(DEFAULT_FREQ);

    let main_lwp = proc.lwp_handle(1)?;

    // Process mappings may change at any time, so for arbitrary addresses
    // reusing an old copy in the Context is invalid. However, the scheduler
    // addresses we're looking at here remain stable, so as long as they are
    // valid now we can assume they will remain valid for the remainder of the
    // process's lifetime.
    let ctx = Context::new(&proc, &main_lwp, view, &symbols).context("failed to create Context")?;

    let start_pause = Instant::now();
    // We need to read the worker's thread-local contexts.
    // We must stop the process in order to access register state, which we use
    // to locate the address of the LWP's thread-local storage.
    proc.stop(0).context("failed to stop process")?;

    let lwps = proc.lwps().context("failed to read lwps")?;

    proc.run().context("failed to set process to run")?;
    let end_pause = Instant::now();
    term.write_line(&format!(
        "Paused process to read LWP registers for {:?}\n",
        end_pause - start_pause
    ))?;

    // We assume that the address of the scheduler handle will remain constant
    // over time. It's not `Pin`, but it is an `Arc` and I don't think the
    // underlying heap pointer will be moved.
    let mut sched_info = MinTokioState::find_type_info(&ctx, &lwps)?;

    let mut last = ChangeTimes::default();

    loop {
        let start = Instant::now();

        // Re-read scheduler bytes from process memory.
        sched_info
            .refresh(&ctx)
            .context("failed to re-read scheduler")?;

        // We will get torn reads doing this without pausing the process,
        // particularly when reading the remotes to find the io driver. Each of
        // those is a separate allocation we need to `Pread`. Given that we're
        // mostly interested in whether the driver is stuck, getting an
        // inconsistent value on the io driver is a sacrifice worth making.
        let runtime =
            MinTokioState::parse(&ctx, &sched_info).context("failed to parse tokio state")?;
        let now = Instant::now();

        // Update timestamps for any values that changed since the last
        // iteration.
        if let Some(ref prev) = last.runtime {
            if runtime.active.len() != prev.active.len() {
                last.active_workers = Some(now);
            }
            if runtime.worker_ct != prev.worker_ct {
                last.total_workers = Some(now);
            }
            if runtime.task_ct != prev.task_ct {
                last.tasks = Some(now);
            }
            if runtime.io_driver != prev.io_driver {
                last.io_driver = Some(now);
            }
        }

        let active = maybe_style(runtime.active.len(), now, last.active_workers);
        let total = maybe_style(runtime.worker_ct, now, last.total_workers);
        let tasks = maybe_style(runtime.task_ct, now, last.tasks);
        let io_driver = runtime
            .io_driver
            .map(|i| maybe_style(i, now, last.io_driver).to_string())
            .unwrap_or_default();

        if last.runtime.is_some() {
            term.clear_last_lines(5)?;
        }
        term.write_line(&format!("Active Workers:    {active}"))?;
        term.write_line(&format!("Worker Count:      {total}"))?;
        term.write_line(&format!("Task Count:        {tasks}"))?;
        term.write_line(&format!("I/O Driver Worker: {io_driver}"))?;
        term.write_line(&format!("Scan duration:     {:?}", now - start))?;

        last.runtime = Some(runtime);

        std::thread::sleep(freq);
    }
}

#[derive(Default, Debug)]
struct ChangeTimes {
    runtime: Option<MinTokioState>,
    active_workers: Option<Instant>,
    total_workers: Option<Instant>,
    tasks: Option<Instant>,
    io_driver: Option<Instant>,
}

/// Highlight `value` in green+bold if it changed within the last 2 seconds.
fn maybe_style<T: Display>(
    value: T,
    now: Instant,
    last_changed: Option<Instant>,
) -> StyledObject<T> {
    const HIGHLIGHT_DUR: Duration = Duration::from_secs(2);

    match last_changed {
        Some(last) if now - last < HIGHLIGHT_DUR => console::style(value).green().bold(),
        _ => console::style(value),
    }
}

struct TraceContext<'ctf> {
    pub proc: &'ctf Proc,
    pub ctf: durin::read::CtfView<'ctf>,
    pub mappings: proc::Mappings,
}

impl<'ctf> reify::ParseCtx<'ctf> for TraceContext<'ctf> {
    fn proc(&self) -> &'ctf Proc {
        self.proc
    }

    fn ctf(&self) -> &durin::read::CtfView<'ctf> {
        &self.ctf
    }

    fn mappings(&self) -> &proc::Mappings {
        &self.mappings
    }
}

fn exec_trace(args: TaskTrace, out: &mut dyn io::Write) -> Result<()> {
    let addr_str = args.addr.strip_prefix("0x").unwrap_or(args.addr.as_str());
    let addr =
        u64::from_str_radix(addr_str, 16).context("failed to parse address as hexadecimal")?;

    let proc = args.source.open_proc(args.destructive)?;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes).context("failed to load CTF")?;
    let view = ctf.view();

    let ctx = TraceContext {
        proc: &proc,
        ctf: view,
        mappings: proc.mappings()?,
    };
    let Some(task_ty) = ctx.ctf.find(&args.ty, durin::TypeKind::Struct) else {
        anyhow::bail!("failed to find task CTF type");
    };

    let info = reify::TypeInfo::from_addr(&ctx, task_ty, addr)
        .with_context(|| format!("failed to parse {:#x} as {}", addr, args.ty))?;

    let Ok(stage) = info.member("core").and_then(|c| c.member("stage")) else {
        anyhow::bail!("failed to find the future");
    };

    let (state, active) = stage.active_variant()?;
    if state != "Running" {
        anyhow::bail!("task is in {state} state, no trace available");
    }

    writeln!(out, "{}", stage.ty.name())?;
    let mut active = active.to_owned();

    while let Ok((await_point, var)) = active.as_ref().active_variant() {
        writeln!(out, "    suspended at await point {}", await_point)?;

        // TODO: this is hilariously overbroad.
        if let Some(lock) = var.try_member("lock")? {
            let addr: u64 = lock.parse(&ctx)?;
            writeln!(out, "    blocked on mutex at {addr:#x}")?;
        }

        if args.verbose && !var.is_enum() {
            writeln!(out, "    Arguments:")?;
            for m in var.ty.members().filter(|m| m.name() != "__awaitee") {
                let mm = var.member(m.name())?;
                writeln!(out, "      {}: {}", m.name(), mm.display_with_depth(1))?;
            }
        }

        writeln!(out, "waiting on: {}", var.ty.name())?;

        // We have an explicit awaitee.
        if let Some(aw) = var.try_member("__awaitee")? {
            active = aw.to_owned();
        } else {
            // Move down to the next nested type.
            active = var.to_owned();
        }
    }

    Ok(())
}

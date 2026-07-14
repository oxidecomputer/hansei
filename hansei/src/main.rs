use crate::tokio::{Context, Lifecycle, MinTokioState, bundle, find_thd_context, parse_runtime};

use anyhow::{Context as _, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use console::{StyledObject, Term};
use durin::read::CtfReader;
use exegesis::bundle::{Bundle, BundleView};
use proc::Proc;
use proc::snapshot::Recorder;

use std::collections::HashMap;
use std::fmt::Display;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub mod tokio;

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
    Tasks(Tasks),
    Snapshot(SnapshotCmd),
}

/// Capture a replayable snapshot of everything the bundle-backed
/// analysis reads from the target: task enumeration and every task's
/// await chain are driven once with a recording wrapper in place, and
/// the memory, symbol, and LWP state they touched is written out.
/// Together with a bundle extracted from a *separate* build of the
/// same source, the snapshot feeds the offline two-binary tests.
#[derive(Args)]
struct SnapshotCmd {
    #[command(flatten)]
    source: Source,

    /// The debug bundle to read (produced by `exegesis extract`).
    #[clap(long, short)]
    bundle: PathBuf,

    /// Where to write the snapshot.
    #[clap(long, short)]
    output: PathBuf,

    /// Proceed even if the bundle's symbols don't all resolve in the target.
    #[arg(long)]
    force: bool,

    /// Pausing a live process is potentially destructive.
    /// Required if --pid is passed.
    #[arg(long, short = 'w')]
    destructive: bool,
}

/// List every task owned by the runtime: id, lifecycle state, concrete
/// future type, spawn location, and where the future is defined.
#[derive(Args)]
struct Tasks {
    #[command(flatten)]
    source: Source,

    /// The debug bundle to read (produced by `exegesis extract`).
    #[clap(long, short)]
    bundle: PathBuf,

    /// Proceed even if the bundle's symbols don't all resolve in the target.
    #[arg(long)]
    force: bool,

    /// Find worker threads with the legacy TSD byte-pattern heuristic
    /// instead of the TLS key named by the bundle.
    #[arg(long)]
    heuristic_discovery: bool,

    /// Pausing a live process is potentially destructive.
    /// Required if --pid is passed.
    #[arg(long, short = 'w')]
    destructive: bool,
}

/// Print a task's await chain. With `--bundle`, tasks are selected by id
/// (see `hansei tasks`) and the future type is resolved automatically via
/// the symbol join; with `--ctf`, the task address and concrete future
/// type must be supplied by hand.
#[derive(Args)]
#[command(group = clap::ArgGroup::new("debug_info").required(true).args(["ctf", "bundle"]))]
struct TaskTrace {
    #[command(flatten)]
    source: Source,

    /// The id of the task to trace, from `hansei tasks` (bundle mode).
    #[clap(long, requires = "bundle")]
    task_id: Option<u64>,

    /// The address of the task in hexadecimal, e.g., 0x1234 (CTF mode).
    #[clap(long, short, requires = "ctf")]
    addr: Option<String>,

    /// The type of the task (CTF mode).
    #[clap(long = "type", short, requires = "ctf")]
    ty: Option<String>,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: Option<PathBuf>,

    /// The debug bundle to read (produced by `exegesis extract`).
    #[clap(long, short)]
    bundle: Option<PathBuf>,

    /// Proceed even if the bundle's symbols don't all resolve in the target.
    #[arg(long)]
    force: bool,

    /// Find worker threads with the legacy TSD byte-pattern heuristic
    /// instead of the TLS key named by the bundle.
    #[arg(long)]
    heuristic_discovery: bool,

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
        Action::Tasks(tasks) => exec_tasks(tasks, &mut io::stdout().lock()),
        Action::Snapshot(snap) => exec_snapshot(snap, &mut io::stdout().lock()),
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
    let runtime = parse_runtime(
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

struct TraceContext<'a> {
    pub proc: &'a Proc,
    pub ctf: durin::read::CtfView<'a>,
    pub mappings: proc::Mappings,
}

impl reify::ParseCtx for TraceContext<'_> {
    type Target = Proc;

    fn proc(&self) -> &Proc {
        self.proc
    }

    fn mappings(&self) -> &proc::Mappings {
        &self.mappings
    }
}

fn exec_trace(args: TaskTrace, out: &mut dyn io::Write) -> Result<()> {
    if args.bundle.is_some() {
        exec_trace_bundle(args, out)
    } else {
        exec_trace_ctf(args, out)
    }
}

fn exec_trace_ctf(args: TaskTrace, out: &mut dyn io::Write) -> Result<()> {
    let (Some(addr), Some(ty), Some(ctf_path)) = (&args.addr, &args.ty, &args.ctf) else {
        anyhow::bail!("CTF tracing requires --addr and --type");
    };
    let addr_str = addr.strip_prefix("0x").unwrap_or(addr.as_str());
    let addr =
        u64::from_str_radix(addr_str, 16).context("failed to parse address as hexadecimal")?;

    let proc = args.source.open_proc(args.destructive)?;

    let ctf_bytes =
        fs::read(ctf_path).with_context(|| format!("failed to read {}", ctf_path.display()))?;
    let ctf = CtfReader::load(&ctf_bytes).context("failed to load CTF")?;
    let view = ctf.view();

    let ctx = TraceContext {
        proc: &proc,
        ctf: view,
        mappings: proc.mappings()?,
    };
    let Some(task_ty) = ctx.ctf.find(ty, durin::TypeKind::Struct) else {
        anyhow::bail!("failed to find task CTF type");
    };

    let info = reify::TypeInfo::from_addr(&ctx, task_ty, addr)
        .with_context(|| format!("failed to parse {addr:#x} as {ty}"))?;

    let Ok(stage) = info.member("core").and_then(|c| c.member("stage")) else {
        anyhow::bail!("failed to find the future");
    };

    let (state, active) = stage.active_variant()?;
    if state != "Running" {
        anyhow::bail!("task is in {state} state, no trace available");
    }

    let task_id: u64 = info.member("core")?.member("task_id")?.parse(&ctx)?;

    writeln!(out, "Task {task_id}:")?;
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

fn exec_trace_bundle(args: TaskTrace, out: &mut dyn io::Write) -> Result<()> {
    let Some(task_id) = args.task_id else {
        anyhow::bail!("bundle tracing requires --task-id (list tasks with `hansei tasks`)");
    };
    let bundle_path = args
        .bundle
        .as_ref()
        .expect("clap group guarantees --bundle");

    let proc = args.source.open_proc(args.destructive)?;
    let bundle = Bundle::load(bundle_path)
        .with_context(|| format!("failed to load bundle {}", bundle_path.display()))?;
    let view = BundleView::new(&bundle);
    let ctx = bundle::Context::new(&proc, view)?;
    check_fingerprint(&ctx, args.force)?;

    let workers = discover_workers(&proc, &ctx, args.heuristic_discovery)?;
    let shared = ctx.find_shared(&workers)?;
    let list = ctx.enumerate_tasks(&shared)?;
    for err in &list.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }

    let Some(task) = list.tasks.iter().find(|t| t.task_id == Some(task_id)) else {
        let ids: Vec<u64> = list.tasks.iter().filter_map(|t| t.task_id).collect();
        anyhow::bail!(
            "the runtime owns no task with id {task_id}; it owns {} task(s): {ids:?}",
            list.tasks.len()
        );
    };

    let name = match &task.future {
        bundle::FutureInfo::Known(known) => known.display_name.clone(),
        bundle::FutureInfo::Unknown {
            poll_symbol: Some(sym),
        } => format!("<unknown: {:#}>", rustc_demangle::demangle(sym)),
        bundle::FutureInfo::Unknown { poll_symbol: None } => "<unknown>".to_string(),
    };
    writeln!(out, "Task {task_id}: {name} ({})", task.state.lifecycle())?;
    if let Some(loc) = &task.spawn_location {
        writeln!(out, "Spawned at: {loc}")?;
    }
    if let bundle::FutureInfo::Known(known) = &task.future
        && let Some((file, line)) = &known.decl
    {
        writeln!(out, "Defined at: {file}:{line}")?;
    }

    // A mid-poll task is being mutated while we read it; anything below
    // may be torn.
    if task.state.lifecycle() == Lifecycle::Running {
        let lwp = workers
            .iter()
            .find(|w| w.current_task_id == Some(task_id))
            .map(|w| format!(" on LWP {}", w.tid))
            .unwrap_or_default();
        writeln!(
            io::stderr(),
            "warning: task {task_id} is running{lwp}; its state may be torn"
        )?;
    }

    writeln!(out)?;
    match ctx.task_stage(task)? {
        bundle::TaskStage::Running(future) => {
            let chain = ctx.await_chain(future);
            print_await_chain(&chain, args.verbose, out)?;
            // The leaf-future knowledge base (§3.6): name what the task
            // is actually waiting on when the leaf is a known primitive.
            match ctx.wait_target(&chain) {
                Some(Ok(target)) => writeln!(out, "     waiting on {target}")?,
                Some(Err(e)) => writeln!(
                    io::stderr(),
                    "warning: failed to read what the leaf future waits on: {e:#}"
                )?,
                None => {}
            }
        }
        bundle::TaskStage::Finished(result) => {
            // Result<T::Output, JoinError>: Ok is a normal return, Err a
            // panic or cancellation.
            writeln!(
                out,
                "The task has finished; its output has not been consumed:"
            )?;
            writeln!(out, "  {:#}", result.as_ref().display_with_depth(4))?;
        }
        bundle::TaskStage::Consumed => {
            writeln!(out, "The task has finished and its output was consumed.")?;
        }
    }
    Ok(())
}

/// Render an await chain, one line per future, with the coroutine state
/// and awaited expression where known, and the live locals when verbose.
fn print_await_chain(
    chain: &bundle::AwaitChain<'_>,
    verbose: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    for (i, frame) in chain.frames.iter().enumerate() {
        let dyn_marker = if frame.dyn_symbol.is_some() {
            " [dyn]"
        } else {
            ""
        };
        writeln!(out, "{i:>3}: {}{dyn_marker}", frame.future.ty.name())?;

        let Some(state) = &frame.state else { continue };
        let loc = state
            .await_loc
            .map(|(file, line)| format!(" — {file}:{line}"))
            .unwrap_or_default();
        writeln!(out, "     state {}{loc}", state.name)?;

        if verbose {
            let payload = state.payload.as_ref();
            // `__…` members are compiler-generated (the awaitee itself
            // and liveness slots), not source-level locals. A coroutine
            // state may hold the same name twice (a captured upvar and a
            // saved local), so members are sliced positionally, never
            // looked up by name.
            let mut seen = std::collections::HashSet::new();
            let locals: Vec<_> = payload
                .ty
                .members()
                .filter(|m| {
                    m.ty().size() > 0
                        && !m.name().starts_with("__")
                        && seen.insert((m.name(), m.offset()))
                })
                .collect();
            if !locals.is_empty() {
                writeln!(out, "     locals:")?;
            }
            for m in locals {
                let start = m.offset() as usize;
                let end = start + m.ty().size() as usize;
                match payload.bytes.get(start..end) {
                    Some(bytes) => {
                        let v = reify::TypeInfoRef::new(m.ty(), payload.addr + m.offset(), bytes)
                            .peel();
                        writeln!(out, "       {}: {}", m.name(), v.display_with_depth(2))?;
                    }
                    None => writeln!(out, "       {}: <unreadable>", m.name())?,
                }
            }
        }
    }

    match &chain.end {
        bundle::ChainEnd::Leaf => {}
        bundle::ChainEnd::UnknownDyn {
            pointee,
            poll_symbol,
        } => {
            writeln!(
                out,
                "the chain continues into a {pointee} whose concrete type is not in the bundle"
            )?;
            if let Some(sym) = poll_symbol {
                writeln!(
                    out,
                    "     its poll fn is {:#} ({sym})",
                    rustc_demangle::demangle(sym)
                )?;
            }
        }
        bundle::ChainEnd::DepthLimit => {
            writeln!(
                out,
                "await chain truncated after {} futures (depth bound); corrupt memory?",
                chain.frames.len()
            )?;
        }
        bundle::ChainEnd::Cycle { addr } => {
            writeln!(
                out,
                "await chain truncated: it loops back to {addr:#x}; corrupt memory?"
            )?;
        }
        bundle::ChainEnd::Error(e) => {
            writeln!(out, "await chain truncated: {e:#}")?;
        }
    }
    Ok(())
}

/// Attach-time bundle validation (§5.1), shared by all bundle-mode
/// subcommands: a bundle from a different commit/toolchain must never
/// silently misinterpret memory. `force` downgrades refusal to a warning.
fn check_fingerprint<T: proc::Target>(ctx: &bundle::Context<'_, T>, force: bool) -> Result<()> {
    let fp = ctx.validate_fingerprint();
    if fp.is_complete() {
        return Ok(());
    }
    let mut sample = fp
        .missing
        .iter()
        .take(5)
        .map(|s| format!("  {:#}", rustc_demangle::demangle(s)))
        .collect::<Vec<_>>()
        .join("\n");
    if fp.missing.len() > 5 {
        sample.push_str(&format!("\n  ... and {} more", fp.missing.len() - 5));
    }
    anyhow::ensure!(
        force,
        "only {}/{} bundle symbols resolve in the target — the bundle does \
         not match this binary. Missing, for example:\n{}\n\
         Pass --force to proceed anyway.",
        fp.matched,
        fp.total,
        sample
    );
    writeln!(
        io::stderr(),
        "warning: only {}/{} bundle symbols resolve in the target; \
         output may be wrong",
        fp.matched,
        fp.total
    )?;
    Ok(())
}

/// Find the LWPs holding a tokio `Context`: the pthread-key flow (§3.0),
/// or the legacy byte-pattern heuristic on request.
fn discover_workers(
    proc: &Proc,
    ctx: &bundle::Context<'_, Proc>,
    heuristic: bool,
) -> Result<Vec<bundle::Worker>> {
    let lwps = proc.lwps().context("failed to read lwps")?;
    let workers = if heuristic {
        let brk_range = proc.status().brk_range;
        let mut workers = Vec::new();
        for lwp in &lwps {
            if let Some(addr) = find_thd_context(&lwp.regs, &brk_range, proc)? {
                workers.push(ctx.worker_at(lwp.tid, addr)?);
            }
        }
        workers
    } else {
        ctx.find_workers(&lwps)?
    };
    anyhow::ensure!(
        !workers.is_empty(),
        "no LWP has a tokio Context in thread-local storage; is this a tokio program?"
    );
    Ok(workers)
}

/// Drive the full bundle-backed analysis with a recording Target in
/// place, then persist what it read (plan §11.3). Every task's stage
/// and await chain is walked so the snapshot can answer the offline
/// tests' whole question set; walk problems are warnings, not errors,
/// since a partially-traceable target is still worth capturing.
fn exec_snapshot(args: SnapshotCmd, out: &mut dyn io::Write) -> Result<()> {
    let proc = args.source.open_proc(args.destructive)?;
    let bundle = Bundle::load(&args.bundle)
        .with_context(|| format!("failed to load bundle {}", args.bundle.display()))?;
    let view = BundleView::new(&bundle);

    let recorder = Recorder::new(&proc);
    let ctx = bundle::Context::new(&recorder, view)?;
    check_fingerprint(&ctx, args.force)?;

    let lwps = proc.lwps().context("failed to read lwps")?;
    let workers = ctx.find_workers(&lwps)?;
    anyhow::ensure!(
        !workers.is_empty(),
        "no LWP has a tokio Context in thread-local storage; is this a tokio program?"
    );
    let shared = ctx.find_shared(&workers)?;
    let list = ctx.enumerate_tasks(&shared)?;
    for err in &list.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }

    let mut chains = 0usize;
    for task in &list.tasks {
        if let bundle::FutureInfo::Unknown { .. } = task.future {
            continue;
        }
        match ctx.task_stage(task) {
            Ok(bundle::TaskStage::Running(future)) => {
                let chain = ctx.await_chain(future);
                if let bundle::ChainEnd::Error(e) = &chain.end {
                    writeln!(
                        io::stderr(),
                        "warning: await chain of task {:?} is incomplete: {e:#}",
                        task.addr
                    )?;
                }
                // Drive the leaf-future interpretation too, so its reads
                // are in the snapshot for the offline tests.
                if let Some(Err(e)) = ctx.wait_target(&chain) {
                    writeln!(
                        io::stderr(),
                        "warning: failed to read what task {:?} waits on: {e:#}",
                        task.addr
                    )?;
                }
                chains += 1;
            }
            Ok(_) => {}
            Err(e) => {
                writeln!(
                    io::stderr(),
                    "warning: failed to read the stage of task {:?}: {e:#}",
                    task.addr
                )?;
            }
        }
    }

    let snapshot = recorder.snapshot().context("failed to assemble snapshot")?;
    snapshot
        .save(&args.output)
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    writeln!(
        out,
        "captured {} tasks ({chains} await chains) to {}",
        list.tasks.len(),
        args.output.display()
    )?;
    Ok(())
}

fn exec_tasks(args: Tasks, out: &mut dyn io::Write) -> Result<()> {
    let proc = args.source.open_proc(args.destructive)?;

    let bundle = Bundle::load(&args.bundle)
        .with_context(|| format!("failed to load bundle {}", args.bundle.display()))?;
    let view = BundleView::new(&bundle);
    let ctx = bundle::Context::new(&proc, view)?;
    check_fingerprint(&ctx, args.force)?;

    let workers = discover_workers(&proc, &ctx, args.heuristic_discovery)?;
    let shared = ctx.find_shared(&workers)?;
    let list = ctx.enumerate_tasks(&shared)?;

    // Which LWP is polling which task right now (§3.2).
    let polling: HashMap<u64, u32> = workers
        .iter()
        .filter_map(|w| w.current_task_id.map(|id| (id, w.tid)))
        .collect();

    let mut rows = vec![[
        "TASK".to_string(),
        "STATE".to_string(),
        "FUTURE".to_string(),
        "SPAWNED AT".to_string(),
        "DEFINED AT".to_string(),
    ]];
    for task in &list.tasks {
        let id = match task.task_id {
            Some(id) => id.to_string(),
            None => format!("{:?}", task.addr),
        };
        let state = match (task.state.lifecycle(), task.task_id) {
            (Lifecycle::Running, Some(id)) if polling.contains_key(&id) => {
                format!("running (lwp {})", polling[&id])
            }
            (lifecycle, _) => lifecycle.to_string(),
        };
        let (future, defined) = match &task.future {
            bundle::FutureInfo::Known(known) => (
                known.display_name.clone(),
                known
                    .decl
                    .as_ref()
                    .map(|(file, line)| format!("{file}:{line}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            bundle::FutureInfo::Unknown {
                poll_symbol: Some(sym),
            } => (
                format!("<unknown: {:#}>", rustc_demangle::demangle(sym)),
                "-".to_string(),
            ),
            bundle::FutureInfo::Unknown { poll_symbol: None } => {
                ("<unknown>".to_string(), "-".to_string())
            }
        };
        let spawned = task
            .spawn_location
            .as_ref()
            .map(|loc| loc.to_string())
            .unwrap_or_else(|| "-".to_string());
        rows.push([id, state, future, spawned, defined]);
    }

    let mut widths = [0usize; 5];
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.len());
        }
    }
    for row in &rows {
        let [id, state, future, spawned, defined] = row;
        writeln!(
            out,
            "{id:<w0$}  {state:<w1$}  {future:<w2$}  {spawned:<w3$}  {defined}",
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
        )?;
    }
    writeln!(out, "\n{} tasks", list.tasks.len())?;

    for err in &list.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }

    Ok(())
}

use crate::tokio::{Lifecycle, bundle, graph};

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use exegesis::bundle::{Bundle, BundleType, BundleView};
use proc::Proc;
use proc::snapshot::Recorder;
use reify::{TypeInfo, TypeInfoRef};

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub mod repl;
pub mod tokio;
pub mod types;

/// The command line names a target and nothing else; what to ask of it
/// is read from stdin, at a prompt or from a pipe.
#[derive(Parser)]
#[command(
    about = "Inspect a tokio runtime in a core dump",
    long_about = "Inspect a tokio runtime in a core dump.\n\n\
                  The command line names a target and nothing else. What to \
                  ask of it is read from stdin: at a prompt when stdin is a \
                  terminal, otherwise one command per line, stopping at the \
                  first failure.",
    after_help = "Examples:\n  \
                  hansei --core core.app --bundle app.bundle\n  \
                  echo 'trace 42 -v' | hansei --core core.app --bundle app.bundle\n\n\
                  Type `help` for the commands a session accepts."
)]
struct Cli {
    #[command(flatten)]
    session: SessionArgs,
}

/// What it takes to attach: the pair of files, and how strictly they
/// have to agree.
#[derive(Args)]
struct SessionArgs {
    /// The core dump to open.
    #[arg(long, short)]
    core: PathBuf,

    /// The debug bundle to read (produced by `exegesis extract`).
    #[arg(long, short)]
    bundle: PathBuf,

    /// Proceed even if the bundle's symbols don't all resolve in the target.
    #[arg(long, short)]
    force: bool,
}

/// Everything a session can be asked. These are read from stdin, never
/// from the command line, so a `Subcommand` derive here defines the
/// grammar of a typed line rather than of an argv.
#[derive(Subcommand)]
pub enum Command {
    /// Show the target, the bundle, and how far its symbols resolve.
    Info,

    /// List every task owned by the runtime: id, lifecycle state,
    /// concrete future type, spawn location, and where the future is
    /// defined.
    Tasks,

    /// Print a task's await chain. Tasks are selected by id (see
    /// `tasks`) and the future type is resolved automatically via the
    /// symbol join.
    Trace {
        /// The id of the task to trace, from `tasks`.
        task_id: u64,

        /// Show the variables present at each await point.
        #[arg(long, short)]
        verbose: bool,

        /// Maximum depth to recurse when formatting variable values.
        #[arg(long, short, default_value_t = 2, requires = "verbose")]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

    /// Print the waker-based task dependency graph: what every task is
    /// waiting on, and any futurelock — a lock future granted or queued
    /// on a contended semaphore that its task stopped polling and so can
    /// never complete or release (RFD 609).
    Graph,

    /// Show every thread running the runtime: the task it is polling,
    /// the worker core it holds, and its stack.
    Threads {
        /// Maximum stack frames to print per thread.
        #[arg(long, short, default_value_t = 50)]
        frames: usize,

        /// Maximum depth to recurse when formatting the worker core.
        #[arg(long, short, default_value_t = 3)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

    /// Show the scheduler state the workers share: the owned-task set,
    /// the injection queue, the idle set and the per-worker remotes.
    SharedState {
        /// Maximum depth to recurse when formatting values.
        #[arg(long, short, default_value_t = 3)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

    /// Show the runtime's drivers: io, signal, time and the clock.
    Drivers {
        /// Maximum depth to recurse when formatting values.
        #[arg(long, short, default_value_t = 3)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

    /// Print the layout the bundle records for a type, by its exact
    /// fully-qualified name: members and their offsets, or an enum's
    /// variants and the discriminant that selects them.
    Type {
        /// The fully-qualified name, as `find-types` lists it.
        name: String,
    },

    /// List the types whose name contains a substring.
    FindTypes {
        /// The substring to look for.
        needle: String,
    },

    /// Capture a replayable snapshot of everything the bundle-backed
    /// analysis reads from the target: task enumeration and every task's
    /// await chain are driven once with a recording wrapper in place,
    /// and the memory, symbol, and LWP state they touched is written
    /// out. Together with a bundle extracted from a *separate* build of
    /// the same source, the snapshot feeds the offline two-binary tests.
    #[command(hide = true)]
    Snapshot {
        /// Where to write the snapshot.
        output: PathBuf,
    },

    /// Leave the session.
    Quit,

    #[command(hide = true)]
    Exit,
}

/// Whether the session carries on after a command.
pub enum Flow {
    Continue,
    Quit,
}

/// One target, opened once. A core does not change while we read it, so
/// the attach-time walks — worker discovery and task enumeration — are
/// done here and reused by every command, rather than repeated per
/// command as they were when each invocation opened its own target.
pub struct Session<'b> {
    ctx: bundle::Context<'b, Proc>,
    proc: &'b Proc,
    bundle: &'b Bundle,
    core: &'b Path,
    bundle_path: &'b Path,
    workers: Vec<bundle::Worker>,
    /// The multi_thread scheduler's `Handle`: the scheduler state and
    /// the drivers both hang off it.
    handle: TypeInfo<'b, BundleType<'b>>,
    tasks: bundle::TaskList,
}

impl<'b> Session<'b> {
    fn attach(proc: &'b Proc, bundle: &'b Bundle, args: &'b SessionArgs) -> Result<Self> {
        let ctx = bundle::Context::new(proc, BundleView::new(bundle))?;
        check_fingerprint(&ctx, args.force)?;

        let workers = discover_workers(proc, &ctx)?;
        let handle = ctx.find_handle(&workers)?;
        let shared = handle.member("shared")?.to_owned();
        let tasks = ctx.enumerate_tasks(&shared)?;
        for err in &tasks.errors {
            writeln!(io::stderr(), "warning: {err:#}")?;
        }

        Ok(Session {
            ctx,
            proc,
            bundle,
            core: &args.core,
            bundle_path: &args.bundle,
            workers,
            handle,
            tasks,
        })
    }
}

/// Run one command against an attached session.
pub fn dispatch(session: &Session<'_>, command: Command, out: &mut dyn io::Write) -> Result<Flow> {
    match command {
        Command::Quit | Command::Exit => return Ok(Flow::Quit),
        Command::Info => exec_info(session, out)?,
        Command::Tasks => exec_tasks(session, out)?,
        Command::Graph => exec_graph(session, out)?,
        Command::Threads {
            frames,
            depth,
            ugly,
        } => exec_threads(session, frames, depth, ugly, out)?,
        Command::SharedState { depth, ugly } => {
            exec_runtime_field(session, "shared", depth, ugly, out)?
        }
        Command::Drivers { depth, ugly } => {
            exec_runtime_field(session, "driver", depth, ugly, out)?
        }
        Command::Type { name } => types::describe(&session.ctx.view, &name, out)?,
        Command::FindTypes { needle } => types::find(&session.ctx.view, &needle, out)?,
        Command::Trace {
            task_id,
            verbose,
            depth,
            ugly,
        } => exec_trace(session, task_id, verbose, depth, ugly, out)?,
        Command::Snapshot { output } => exec_snapshot(session, &output, out)?,
    }
    Ok(Flow::Continue)
}

fn main() {
    let args = Cli::parse();

    let res = run(&args.session);
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

/// Open the target and hand the session to the command reader.
///
/// The proc and the bundle are owned here rather than by [`Session`]:
/// the context borrows both, so keeping all three in one frame is what
/// lets a session be held across many commands without a
/// self-referential struct.
fn run(args: &SessionArgs) -> Result<()> {
    let proc = Proc::open_core(&args.core)
        .with_context(|| format!("failed to open {}", args.core.display()))?;
    let bundle = Bundle::load(&args.bundle)
        .with_context(|| format!("failed to load bundle {}", args.bundle.display()))?;
    let session = Session::attach(&proc, &bundle, args)?;

    repl::run(&session)
}

/// The attach summary: what is being read, and how well the two files
/// agree. A partial fingerprint is what `--force` waves through, so it
/// is worth being able to ask after the fact.
fn exec_info(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let fp = session.ctx.validate_fingerprint();
    writeln!(out, "core:   {}", session.core.display())?;
    writeln!(out, "bundle: {}", session.bundle_path.display())?;
    writeln!(
        out,
        "symbols resolved: {}/{}{}",
        fp.matched,
        fp.total,
        if fp.is_complete() { "" } else { " (forced)" }
    )?;
    writeln!(
        out,
        "{} worker thread(s), {} task(s)",
        session.workers.len(),
        session.tasks.tasks.len()
    )?;
    Ok(())
}

fn exec_trace(
    session: &Session<'_>,
    task_id: u64,
    verbose: bool,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    let list = &session.tasks;

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
        bundle::FutureInfo::Ambiguous { candidates, .. } => {
            format!("<ambiguous: {}>", candidates.join(" | "))
        }
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
        let lwp = session
            .workers
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
            print_await_chain(ctx, &chain, verbose, depth, ugly, out)?;
            // The leaf-future knowledge base (§3.6): name what the task
            // is actually waiting on when the leaf is a known primitive.
            match ctx.wait_target(&chain) {
                Some(Ok(target)) => {
                    let indent = frame_detail_indent(chain.frames.len().saturating_sub(1));
                    writeln!(out, "{indent}waiting on {target}")?;
                }
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
            let output = result.as_ref();
            let mut value = output.display_with_depth(4);
            if ugly {
                value = value.ugly();
            }
            writeln!(out, "  {:#}", value)?;
        }
        bundle::TaskStage::Consumed => {
            writeln!(out, "The task has finished and its output was consumed.")?;
        }
    }
    Ok(())
}

/// Render an await chain, one line per future, with the coroutine state
/// and awaited expression where known, and the live locals when verbose.
fn print_await_chain<'b, T: proc::Target>(
    ctx: &bundle::Context<'b, T>,
    chain: &bundle::AwaitChain<'b>,
    verbose: bool,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let active_frame = chain.frames.len().checked_sub(1);
    for (i, frame) in chain.frames.iter().enumerate() {
        let active = Some(i) == active_frame;
        let marker = if active { '*' } else { ' ' };
        let kind = async_kind(
            frame.future.ty.name(),
            frame.state.as_ref().map(|state| state.name),
        );
        let dyn_marker = if frame.dyn_symbol.is_some() {
            " [dyn]"
        } else {
            ""
        };
        if i == 0 {
            writeln!(
                out,
                "  {i}  {kind:<13} {}{dyn_marker}",
                frame.future.ty.name()
            )?;
        } else {
            let indent = frame_node_indent(i);
            writeln!(
                out,
                "{indent}└─{marker} {i}  {kind:<13} {}{dyn_marker}",
                frame.future.ty.name()
            )?;
        }

        let detail_indent = frame_detail_indent(i);

        if let Some(state) = &frame.state {
            let loc = state
                .await_loc
                .map(|(file, line)| format!(" — {file}:{line}"))
                .unwrap_or_default();
            // Align the state value with the type name above it. Child
            // nodes have a frame-number column between the tree branch
            // and the kind label; the state line must account for it.
            let label_width = state_label_width(i);
            writeln!(
                out,
                "{detail_indent}{:<label_width$} {}{loc}",
                "state", state.name
            )?;
        }

        if verbose && (frame.state.is_some() || active) {
            let payload = match &frame.state {
                Some(state) => state.payload.as_ref(),
                None => frame.future.as_ref(),
            };
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
                let heading = if frame.state.is_some() {
                    "locals:"
                } else {
                    "fields:"
                };
                writeln!(out, "{detail_indent}{heading}")?;
            }
            let value_indent = format!("{detail_indent}  ");
            for m in locals {
                let start = m.offset() as usize;
                let end = start + m.ty().size() as usize;
                match payload.bytes.get(start..end) {
                    Some(bytes) => {
                        let v = reify::TypeInfoRef::new(m.ty(), payload.addr + m.offset(), bytes)
                            .peel();
                        let mut disp = v.display_from_target(ctx.proc, depth);
                        if ugly {
                            disp = disp.ugly();
                        }
                        let value = format!("{:#}", disp);
                        print_variable(out, &value_indent, m.name(), &value)?;
                    }
                    None => writeln!(out, "{value_indent}{}: <unreadable>", m.name())?,
                }
            }
        }

        if !active {
            writeln!(out, "{detail_indent}awaits:")?;
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
        bundle::ChainEnd::AmbiguousDyn {
            pointee,
            symbol,
            candidates,
        } => {
            writeln!(
                out,
                "the chain continues into a {pointee}, but its normalized poll symbol is ambiguous"
            )?;
            writeln!(out, "     poll fn: {symbol}")?;
            for candidate in candidates {
                writeln!(out, "     candidate: {candidate}")?;
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

fn frame_node_indent(depth: usize) -> String {
    format!("{} ", "    ".repeat(depth))
}

fn frame_detail_indent(depth: usize) -> String {
    format!("{} ", "    ".repeat(depth + 1))
}

fn state_label_width(frame: usize) -> usize {
    if frame == 0 {
        13
    } else {
        frame.to_string().len() + 15
    }
}

/// Classify the outer future type from rustc's generated DWARF basename.
/// The names are an implementation detail, so an unrecognized state
/// machine deliberately receives the neutral `async` label.
fn async_kind(name: &str, state: Option<&str>) -> &'static str {
    // Ignore generic arguments: an ordinary wrapper such as
    // `PollFn<foo::{async_fn_env#0}>` is not itself an async fn.
    let mut outer = String::with_capacity(name.len());
    let mut generic_depth = 0usize;
    for c in name.chars() {
        match c {
            '<' => generic_depth += 1,
            '>' => generic_depth = generic_depth.saturating_sub(1),
            _ if generic_depth == 0 => outer.push(c),
            _ => {}
        }
    }
    if outer.rsplit("::").next().is_some_and(|component| {
        component.starts_with("{async_fn_env#") && component.ends_with('}')
    }) {
        "async fn"
    } else if outer.rsplit("::").next().is_some_and(|component| {
        component.starts_with("{async_block_env#") && component.ends_with('}')
    }) {
        "async block"
    } else if outer.rsplit("::").next().is_some_and(|component| {
        component.starts_with("{async_closure_env#") && component.ends_with('}')
    }) {
        "async closure"
    } else if state.is_some_and(|state| {
        state.starts_with("Suspend") || matches!(state, "Unresumed" | "Returned" | "Panicked")
    }) {
        "async"
    } else {
        "future"
    }
}

/// Print a named variable compactly when it fits on one line, or as an
/// indented block when the value formatter expands an aggregate.
fn print_variable(out: &mut dyn io::Write, indent: &str, name: &str, value: &str) -> Result<()> {
    if value.contains('\n') {
        writeln!(out, "{indent}{name}:")?;
        for line in value.lines() {
            writeln!(out, "{indent}  {line}")?;
        }
    } else {
        writeln!(out, "{indent}{name}: {value}")?;
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

/// Find the LWPs holding a tokio `Context`, through the thread-local
/// the bundle names (§3.0).
fn discover_workers(proc: &Proc, ctx: &bundle::Context<'_, Proc>) -> Result<Vec<bundle::Worker>> {
    let lwps = proc.lwps().context("failed to read lwps")?;
    let workers = ctx.find_workers(&lwps)?;
    anyhow::ensure!(
        !workers.is_empty(),
        "no LWP has a tokio Context in thread-local storage; is this a tokio program?"
    );
    Ok(workers)
}

/// Render every running frame's source-level locals through reify,
/// discarding the output. The renderer follows the pointers inside
/// formatted values (mpsc channels, `Notify`, `Semaphore`, `watch`, …)
/// that the task/await analysis never touches; driving it through the
/// recording target is what puts those pages into the snapshot, so the
/// offline render tests replay the same reads. The depth is generous so
/// the recorded reads are a superset of any the tests perform.
///
/// Each local is rendered twice: peeled (how `trace` displays it)
/// and unpeeled (which dispatches the local's own top-level formatter —
/// e.g. `bounded::Receiver`'s compact `MpscRx` form, which peeling would
/// strip away). The two read slightly different page sets, so warming
/// both keeps the snapshot faithful to either rendering path.
fn warm_frame_values<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    chain: &bundle::AwaitChain<'_>,
) {
    const WARM_DEPTH: usize = 200;
    for frame in &chain.frames {
        let payload = match &frame.state {
            Some(state) => state.payload.as_ref(),
            None => frame.future.as_ref(),
        };
        for m in payload.ty.members() {
            if m.ty().size() == 0 {
                continue;
            }
            let start = m.offset() as usize;
            let end = start + m.ty().size() as usize;
            let Some(bytes) = payload.bytes.get(start..end) else {
                continue;
            };
            let v = reify::TypeInfoRef::new(m.ty(), payload.addr + m.offset(), bytes);
            let _ = format!("{:#}", v.display_from_target(ctx.proc, WARM_DEPTH));
            let _ = format!("{:#}", v.peel().display_from_target(ctx.proc, WARM_DEPTH));
        }
    }
}

/// Drive the full bundle-backed analysis with a recording Target in
/// place, then persist what it read (plan §11.3). Every task's stage
/// and await chain is walked so the snapshot can answer the offline
/// tests' whole question set; walk problems are warnings, not errors,
/// since a partially-traceable target is still worth capturing.
fn exec_snapshot(session: &Session<'_>, output: &Path, out: &mut dyn io::Write) -> Result<()> {
    // The recording wrapper has to sit under its own context: what makes
    // a snapshot is the reads going through `Recorder`, so the session's
    // context — which reads the target directly — cannot serve here. The
    // whole analysis is therefore driven a second time.
    let proc = session.proc;
    let recorder = Recorder::new(proc);
    let ctx = bundle::Context::new(&recorder, BundleView::new(session.bundle))?;
    // Not a policy check — the session already made it, and refused if it
    // failed. This is for the reads it makes, which belong in the
    // snapshot like any other.
    let _ = ctx.validate_fingerprint();

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
        if !matches!(task.future, bundle::FutureInfo::Known(_)) {
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
                // Drive reify's value renderer over the frame locals too,
                // so the pages behind formatted values are recorded for
                // the offline render tests.
                warm_frame_values(&ctx, &chain);
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

    // Drive the dependency analysis too — wake queues and the
    // off-path acquire scan — so its reads are in the snapshot. Its
    // failures duplicate the per-task warnings above.
    let analysis = graph::analyze(&ctx, &list);

    let snapshot = recorder.snapshot().context("failed to assemble snapshot")?;
    snapshot
        .save(output)
        .with_context(|| format!("failed to write {}", output.display()))?;
    writeln!(
        out,
        "captured {} tasks ({chains} await chains, {} futurelocks) to {}",
        list.tasks.len(),
        analysis.futurelocks.len(),
        output.display()
    )?;
    Ok(())
}

fn exec_tasks(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let list = &session.tasks;

    // Which LWP is polling which task right now (§3.2).
    let polling: HashMap<u64, u32> = session
        .workers
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
            bundle::FutureInfo::Ambiguous { candidates, .. } => (
                format!("<ambiguous: {}>", candidates.join(" | ")),
                "-".to_string(),
            ),
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

fn exec_graph(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let list = &session.tasks;
    let analysis = graph::analyze(&session.ctx, list);
    for err in &analysis.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }

    // One wait edge per task ([`graph::Analysis::waits`] parallels the
    // task list).
    let mut rows = vec![[
        "TASK".to_string(),
        "STATE".to_string(),
        "WAITING ON".to_string(),
    ]];
    for (task, wait) in list.tasks.iter().zip(&analysis.waits) {
        let id = match task.task_id {
            Some(id) => id.to_string(),
            None => format!("{:?}", task.addr),
        };
        let target = wait
            .target
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "-".to_string());
        rows.push([id, task.state.lifecycle().to_string(), target]);
    }
    let mut widths = [0usize; 2];
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.len());
        }
    }
    for row in &rows {
        let [id, state, target] = row;
        writeln!(
            out,
            "{id:<w0$}  {state:<w1$}  {target}",
            w0 = widths[0],
            w1 = widths[1],
        )?;
    }

    for fl in &analysis.futurelocks {
        writeln!(out)?;
        print_futurelock(fl, out)?;
    }
    if analysis.futurelocks.is_empty() {
        writeln!(out, "\nno futurelock detected")?;
    }
    Ok(())
}

/// Every thread the runtime is running on, as the runtime sees it and
/// as the stack sees it: the task it is polling, the worker core it
/// holds while it runs, and the frames it is parked in.
fn exec_threads(
    session: &Session<'_>,
    frames: usize,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Unwinding reads the CFI of every mapped object, so it is done once
    // for the whole target and only when a command asks for it. A target
    // it cannot walk still has runtime state worth printing, so a failure
    // costs the stacks and nothing else.
    let stacks = match unwind::load_frames(session.proc) {
        Ok(stacks) => stacks,
        Err(e) => {
            writeln!(
                io::stderr(),
                "warning: cannot unwind the target's threads: {e:#}"
            )?;
            BTreeMap::new()
        }
    };

    for (i, worker) in session.workers.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        writeln!(out, "LWP {}  {}", worker.tid, polling(session, worker))?;

        if let Err(e) = print_thread_context(session, worker, depth, ugly, out) {
            writeln!(out, "  thread context unreadable: {e:#}")?;
        }

        match session.ctx.worker_context(worker) {
            Ok(Some(worker_ctx)) => print_worker_state(session, &worker_ctx, depth, ugly, out)?,
            // A thread inside the runtime without a scheduler context is
            // ordinary: `block_on` enters the runtime from a thread that
            // never runs the worker loop.
            Ok(None) => writeln!(out, "  not in the scheduler's run loop")?,
            Err(e) => writeln!(out, "  scheduler context unreadable: {e:#}")?,
        }

        match stacks.get(&worker.tid) {
            Some(backtrace) => {
                writeln!(out, "  stack:")?;
                for line in backtrace.stack_trace(frames) {
                    writeln!(out, "    {line}")?;
                }
            }
            None => writeln!(out, "  stack: unavailable")?,
        }
    }
    Ok(())
}

/// What a thread is doing with the task it last entered. tokio restores
/// the thread-local task id after a poll returns, but a thread that was
/// interrupted mid-poll — and any thread whose id belongs to a task that
/// has since finished — leaves a stale one behind, so the claim is only
/// made for a task the runtime still owns and still calls running.
fn polling(session: &Session<'_>, worker: &bundle::Worker) -> String {
    let Some(id) = worker.current_task_id else {
        return "polling no task".to_string();
    };
    let running = session
        .tasks
        .tasks
        .iter()
        .any(|t| t.task_id == Some(id) && t.state.lifecycle() == Lifecycle::Running);
    if running {
        format!("polling task {id}")
    } else {
        format!("last polled task {id}")
    }
}

/// The tokio state a thread carries in its own thread-local `Context`:
/// which thread the runtime takes it for, whether it has entered a
/// runtime, and what is left of the task's cooperative budget.
fn print_thread_context(
    session: &Session<'_>,
    worker: &bundle::Worker,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let info = session.ctx.context_info(worker.context_addr)?;
    for field in ["thread_id", "runtime", "budget"] {
        let value = info.member(field)?;
        print_variable(out, "  ", field, &render(session, &value, depth, ugly))?;
    }
    Ok(())
}

/// A worker thread's own state: which worker it is, the `Core` it holds
/// while it runs — the run queue, the LIFO slot, the park state and the
/// counters the scheduler keeps per worker — and the wakers it has
/// deferred until the current poll returns.
fn print_worker_state<'b>(
    session: &Session<'_>,
    worker_ctx: &TypeInfo<'b, BundleType<'b>>,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    let worker = worker_ctx.member("worker")?.deref_ptr(ctx)?;
    let index: u64 = worker.member("data")?.member("index")?.parse(ctx)?;
    writeln!(out, "  worker {index}")?;

    let defer = worker_ctx.member("defer")?;
    print_variable(out, "  ", "defer", &render(session, &defer, depth, ugly))?;

    // The core is moved out of the thread's context while the scheduler
    // parks or hands it to another thread, so its absence is a state
    // worth naming rather than an error.
    let core = worker_ctx.member("core")?.member("value")?;
    let Some(boxed) = core.try_select_variant("Some")? else {
        writeln!(out, "  core: not held by this thread")?;
        return Ok(());
    };
    let core = boxed.deref_ptr(ctx)?;
    print_variable(
        out,
        "  ",
        "core",
        &render(session, &core.as_ref(), depth, ugly),
    )?;
    Ok(())
}

/// Render one of the runtime handle's fields out of the target: the
/// scheduler state the workers share, or the drivers they park on.
///
/// Both are read straight through the bundle's layouts rather than into
/// a hand-written mirror of tokio's structs, so a field tokio adds shows
/// up without hansei being taught about it.
fn exec_runtime_field(
    session: &Session<'_>,
    field: &str,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let value = session.handle.member(field)?;
    writeln!(out, "{}", render(session, &value, depth, ugly))?;
    Ok(())
}

/// Format a value read from the target, honouring the custom formatters
/// unless asked for the raw structural view.
fn render<'b>(
    session: &Session<'_>,
    value: &TypeInfoRef<'_, 'b, BundleType<'b>>,
    depth: usize,
    ugly: bool,
) -> String {
    let display = value.display_from_target(session.ctx.proc, depth);
    if ugly {
        format!("{:#}", display.ugly())
    } else {
        format!("{display:#}")
    }
}

/// Render one futurelock diagnosis: who holds what, where the
/// abandoned future is parked, and who is stuck behind it.
fn print_futurelock(fl: &graph::Futurelock, out: &mut dyn io::Write) -> Result<()> {
    let acq = &fl.acquire;
    let semaphore = match acq.owner {
        Some(owner) => format!("a {owner} (semaphore {:#x})", acq.semaphore),
        None => format!("the semaphore at {:#x}", acq.semaphore),
    };
    let held = if acq.granted() {
        let plural = if acq.num_permits == 1 { "" } else { "s" };
        format!("{} granted permit{plural}", acq.num_permits)
    } else {
        "a place in the wake queue".to_string()
    };
    writeln!(
        out,
        "futurelock: {} holds {held} of {semaphore} in a future it stopped polling:",
        fl.holder
    )?;
    let loc = acq
        .await_loc
        .as_ref()
        .map(|(file, line)| format!(" — {file}:{line}"))
        .unwrap_or_default();
    writeln!(out, "  `{}` ({})", acq.local, acq.future)?;
    writeln!(out, "  held across {} state {}{loc}", acq.frame, acq.state)?;
    if fl.blocked.is_empty() {
        writeln!(out, "  nothing is blocked behind it yet")?;
    } else {
        let blocked = fl
            .blocked
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "  blocked behind it: {blocked}")?;
    }
    Ok(())
}

#[cfg(test)]
mod variable_format_tests {
    use super::{async_kind, print_variable, state_label_width};

    #[test]
    fn scalar_stays_on_the_name_line() {
        let mut out = Vec::new();
        print_variable(&mut out, "  ", "count", "42").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "  count: 42\n");
    }

    #[test]
    fn aggregate_is_indented_below_the_name() {
        let mut out = Vec::new();
        print_variable(&mut out, "  ", "point", "Point {\n    x: 1,\n    y: 2,\n}").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "  point:\n    Point {\n        x: 1,\n        y: 2,\n    }\n"
        );
    }

    #[test]
    fn classifies_rustc_async_environment_names() {
        assert_eq!(
            async_kind("crate::work::{async_fn_env#0}<T>", Some("Suspend0")),
            "async fn"
        );
        assert_eq!(
            async_kind("crate::work::{async_block_env#2}", Some("Suspend0")),
            "async block"
        );
        assert_eq!(
            async_kind("crate::work::{async_closure_env#1}", Some("Suspend0")),
            "async closure"
        );
        assert_eq!(async_kind("crate::unknown", Some("Suspend3")), "async");
        assert_eq!(async_kind("crate::MaybeDone", Some("Done")), "future");
    }

    #[test]
    fn classifies_the_outer_future_not_its_type_arguments() {
        assert_eq!(
            async_kind("core::future::PollFn<crate::work::{async_fn_env#0}>", None),
            "future"
        );
        assert_eq!(
            async_kind(
                "crate::Wrapper<T>::work::{async_fn_env#0}<U>",
                Some("Suspend0")
            ),
            "async fn"
        );
    }

    #[test]
    fn state_alignment_accounts_for_frame_number_width() {
        assert_eq!(state_label_width(0), 13);
        assert_eq!(state_label_width(1), 16);
        assert_eq!(state_label_width(10), 17);
    }
}

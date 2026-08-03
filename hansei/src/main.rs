use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use exegesis::bundle::{Bundle, BundleMember, BundleType, BundleView};
use hansei_types::tokio::{Lifecycle, bundle, census, graph};
use proc::Proc;
#[cfg(feature = "snapshot")]
use proc::snapshot::Recorder;
use reify::{TypeInfo, TypeInfoRef};

use std::cell::OnceCell;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub mod repl;
pub mod types;

/// The command line names a target; what to ask of it comes from
/// `--exec`, or failing that from stdin, at a prompt or from a pipe.
#[derive(Parser)]
#[command(
    about = "Inspect a tokio runtime in a core dump",
    long_about = "Inspect a tokio runtime in a core dump.\n\n\
                  The command line names a target. What to ask of it is read \
                  from stdin — at a prompt when stdin is a terminal, otherwise \
                  one command per line, stopping at the first failure — or \
                  given with --exec, which asks and exits.",
    after_help = "Examples:\n  \
                  hansei --core core.app --bundle app.bundle\n  \
                  hansei --core core.app --bundle app.bundle -e 'tasks; graph'\n  \
                  echo 'trace 42 -v' | hansei --core core.app --bundle app.bundle\n\n\
                  Type `help` for the commands a session accepts."
)]
struct Cli {
    #[command(flatten)]
    session: SessionArgs,

    /// Commands to run instead of reading stdin, `;` between them.
    /// Repeat the flag to add more; the session exits when they are
    /// answered, or at the first one that fails.
    #[arg(long, short, value_name = "COMMANDS")]
    exec: Vec<String>,
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
    /// Show the runtime's drivers: io, signal, time and the clock.
    Drivers {
        /// Maximum depth to recurse when formatting values.
        #[arg(long, short, default_value_t = 4)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

    /// List the types whose name contains a substring.
    FindTypes {
        /// The substring to look for.
        needle: String,
    },

    /// List the futures no task listing shows, grouped by the task
    /// that owns them: futures *held* in frames off the poll spine
    /// (select!/join! arms in flight, a future stored across an await,
    /// a futurelock's abandoned lock), and every FuturesUnordered with
    /// its children. Found by value in each task's frames: coroutine
    /// environments, future trait objects (resolved through the vtable
    /// join), and the recognized leaf futures.
    Futures,

    /// Print the waker-based task dependency graph: what every task is
    /// waiting on, and any futurelock — a lock future granted or queued
    /// on a contended semaphore that its task stopped polling and so can
    /// never complete or release (RFD 609).
    Graph,

    /// Show the target, the bundle, and how far its symbols resolve.
    Info,

    /// Show the scheduler state the workers share: the owned-task set,
    /// the injection queue, the idle set and the per-worker remotes.
    SharedState {
        /// Maximum depth to recurse when formatting values.
        #[arg(long, short, default_value_t = 4)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

    /// Capture a replayable snapshot of everything the bundle-backed
    /// analysis reads from the target: task enumeration and every task's
    /// await chain are driven once with a recording wrapper in place,
    /// and the memory, symbol, and LWP state they touched is written
    /// out. Together with a bundle extracted from a *separate* build of
    /// the same source, the snapshot feeds the offline two-binary tests.
    #[cfg(feature = "snapshot")]
    #[command(hide = true)]
    Snapshot {
        /// Where to write the snapshot.
        output: PathBuf,
    },

    /// Find the task whose allocation contains an address. Any pointer
    /// into a task — its Header, its future's state machine, its
    /// Trailer — resolves to the owning task.
    TaskAt {
        /// The address to look up, written in hex with a required
        /// leading `0x` (e.g. `0x7fffb1c26100`).
        #[arg(value_parser = parse_hex_addr)]
        addr: u64,
    },

    /// List every task owned by the runtime: id, lifecycle state,
    /// concrete future type, spawn location, and where the future is
    /// defined.
    Tasks,

    /// Show every thread running the runtime: the task it is polling,
    /// the worker core it holds, and its stack.
    Threads {
        /// Maximum stack frames to print per thread.
        #[arg(long, short, default_value_t = 50)]
        frames: usize,

        /// Maximum depth to recurse when formatting the worker core.
        #[arg(long, short, default_value_t = 4)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
    },

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
        #[arg(long, short, default_value_t = 4, requires = "verbose")]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,

        /// Show the values the bundle renders as `<elided>` (runtime
        /// handles, loggers) instead of hiding them.
        #[arg(long, short = 'n')]
        no_elide: bool,

        /// Render matching types as `<elided>`; repeat the flag to add
        /// more. `*` matches any run of characters (quote the pattern
        /// from the shell), a name without a `*` covers every
        /// instantiation, and a matched type stays elided under
        /// --no-elide.
        #[arg(long, short = 'e', value_name = "TYPE")]
        elide: Vec<String>,
    },

    /// Print the layout the bundle records for a type, by its exact
    /// fully-qualified name: members and their offsets, or an enum's
    /// variants and the discriminant that selects them.
    Type {
        /// The fully-qualified name, as `find-types` lists it.
        name: String,

        /// Follow what the layout names: open every type it reaches —
        /// through members, pointees, array elements and enum payloads
        /// — under the line that names it.
        #[arg(long, short)]
        recursive: bool,

        /// How many types deep to follow. A line with more below it
        /// than this shows is marked with a `…`.
        #[arg(long, short, default_value_t = 4, requires = "recursive")]
        depth: usize,
    },

    // Last rather than alphabetical: it is not a question to ask of a
    // target, and a listing read to find one should not open with the
    // way out.
    /// Leave the session.
    Quit,

    // `quit` under the name a gdb habit reaches for.
    #[command(hide = true)]
    Exit,
}

/// Parse a target address: hex digits behind a required `0x`. The
/// prefix is demanded rather than inferred so an address can never be
/// mistaken for the decimal task ids the other commands select by.
fn parse_hex_addr(s: &str) -> std::result::Result<u64, String> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| {
            format!(
                "an address is written in hex with a leading 0x (e.g. 0x7fffb1c26100), got {s:?}"
            )
        })?;
    u64::from_str_radix(digits, 16).map_err(|e| format!("invalid hex address {s:?}: {e}"))
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
    /// Read again under a recording target when a snapshot is captured.
    #[cfg(feature = "snapshot")]
    bundle: &'b Bundle,
    core: &'b Path,
    bundle_path: &'b Path,
    workers: Vec<bundle::Worker>,
    /// The multi_thread scheduler's `Handle`: the scheduler state and
    /// the drivers both hang off it.
    handle: TypeInfo<'b, BundleType<'b>>,
    tasks: bundle::TaskList,
    /// Task extents and the sub-executor census, built on first use: a
    /// core does not change, so the address→task answers never do
    /// either, and the census walks every chain — worth paying once.
    extents: OnceCell<bundle::TaskExtents>,
    census: OnceCell<census::FutureCensus>,
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
            #[cfg(feature = "snapshot")]
            bundle,
            core: &args.core,
            bundle_path: &args.bundle,
            workers,
            handle,
            tasks,
            extents: OnceCell::new(),
            census: OnceCell::new(),
        })
    }

    fn extents(&self) -> &bundle::TaskExtents {
        self.extents
            .get_or_init(|| self.ctx.task_extents(&self.tasks))
    }

    fn census(&self) -> &census::FutureCensus {
        self.census
            .get_or_init(|| census::census(&self.ctx, &self.tasks))
    }
}

/// Run one command against an attached session.
pub fn dispatch(session: &Session<'_>, command: Command, out: &mut dyn io::Write) -> Result<Flow> {
    match command {
        Command::Drivers { depth, ugly } => {
            exec_runtime_field(session, "driver", depth, ugly, out)?
        }
        Command::FindTypes { needle } => types::find(&session.ctx.view, &needle, out)?,
        Command::Futures => exec_futures(session, out)?,
        Command::Graph => exec_graph(session, out)?,
        Command::Info => exec_info(session, out)?,
        Command::SharedState { depth, ugly } => {
            exec_runtime_field(session, "shared", depth, ugly, out)?
        }
        #[cfg(feature = "snapshot")]
        Command::Snapshot { output } => exec_snapshot(session, &output, out)?,
        Command::TaskAt { addr } => exec_task_at(session, addr, out)?,
        Command::Tasks => exec_tasks(session, out)?,
        Command::Threads {
            frames,
            depth,
            ugly,
        } => exec_threads(session, frames, depth, ugly, out)?,
        Command::Trace {
            task_id,
            verbose,
            depth,
            ugly,
            no_elide,
            elide,
        } => {
            let elide = reify::ElideOverride {
                no_elide,
                types: elide,
            };
            exec_trace(session, task_id, verbose, depth, ugly, &elide, out)?
        }
        Command::Type {
            name,
            recursive,
            depth,
        } => types::describe(&session.ctx.view, &name, recursive, depth, out)?,
        Command::Quit | Command::Exit => return Ok(Flow::Quit),
    }
    Ok(Flow::Continue)
}

fn main() {
    let args = Cli::parse();

    // Cap the worker pool rendering fans out on: value rendering is
    // memory-bound and stops scaling well before the 128-256 logical
    // CPUs of a rack sled, and a debugging session should not
    // commandeer a sled's worth of threads either.
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
    if let Err(e) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("reify-render-{i}"))
        .build_global()
    {
        let _ = writeln!(io::stderr(), "Error: {e:?}");
        std::process::exit(1);
    }

    let res = run(&args.session, &args.exec);
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
fn run(args: &SessionArgs, exec: &[String]) -> Result<()> {
    // The two files are independent and each costs real time to read
    // (the core indexes its symbol tables, the bundle decompresses and
    // decodes), so one is opened on a second thread.
    let (proc, bundle) = std::thread::scope(|scope| {
        let bundle = scope.spawn(|| {
            Bundle::load(&args.bundle)
                .with_context(|| format!("failed to load bundle {}", args.bundle.display()))
        });
        let proc = Proc::open_core(&args.core)
            .with_context(|| format!("failed to open {}", args.core.display()));
        (proc, bundle.join().expect("bundle loader panicked"))
    });
    let (proc, bundle) = (proc?, bundle?);
    let session = Session::attach(&proc, &bundle, args)?;

    repl::run(&session, exec)
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
    elide: &reify::ElideOverride,
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

    let name = future_name(&task.future);
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

    // Values shown under --verbose may hold raw pointers into task
    // allocations (wakers, JoinHandles); name those with the task id so
    // the reader knows what to trace next. The traced task itself is
    // named like any other: a wake-queue entry resolving back to it is a
    // finding (the futurelock shape), not noise. A pointer into a
    // sub-executor's child node instead names the task that polls the
    // set — the task a wake there would ultimately run.
    let lookups = verbose.then(|| (session.extents(), session.census()));
    let annotate = lookups.map(|(extents, census)| {
        move |ptr: u64| {
            if let Some((index, _)) = extents.locate(ptr) {
                return Some(task_label(list, index));
            }
            let (set, _, _) = census.locate(ptr)?;
            Some(format!(
                "{} via FuturesUnordered",
                task_label(list, census.sets[set].owner)
            ))
        }
    });

    writeln!(out)?;
    match ctx.task_stage(task)? {
        bundle::TaskStage::Running(future) => {
            let chain = ctx.await_chain(future);
            let annotate = annotate.as_ref().map(|a| a as &reify::AddrAnnotator<'_>);
            print_await_chain(ctx, &chain, verbose, depth, ugly, elide, annotate, out)?;
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

/// Render an await chain, one line per future, each coroutine frame
/// followed by every place it can park with the one it is parked at
/// marked, and the live locals of that state when verbose.
///
/// A frame's child hangs from its active suspend row, so how far each
/// frame indents follows from its predecessors' inventories rather than
/// from its depth alone, and a state listed after the active one is
/// printed once the subtree that grew out of the active one is closed.
#[allow(clippy::too_many_arguments)]
fn print_await_chain<'b, T: proc::Target + Sync>(
    ctx: &bundle::Context<'b, T>,
    chain: &bundle::AwaitChain<'b>,
    verbose: bool,
    depth: usize,
    ugly: bool,
    elide: &reify::ElideOverride,
    annotate: Option<&reify::AddrAnnotator<'_>>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let active_frame = chain.frames.len().checked_sub(1);
    let mut node_indent = FRAME_ROOT_INDENT;
    let mut detail_indent = frame_detail_indent(node_indent);
    // One per frame, kept so the states listed after each active row can
    // be printed — in the columns their whole inventory was laid out
    // in — once the chain below them is done.
    let mut tables: Vec<SuspendTable<'b>> = Vec::new();
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
            let indent = " ".repeat(node_indent);
            writeln!(
                out,
                "{indent}└─{marker} {i}  {kind:<13} {}{dyn_marker}",
                frame.future.ty.name()
            )?;
        }

        detail_indent = frame_detail_indent(node_indent);
        let table = SuspendTable::new(suspend_rows(frame), verbose, detail_indent.clone());
        let rows_empty = table.is_empty();
        tables.push(table);

        if rows_empty {
            // Not a coroutine: a leaf future has no states at all, and an
            // ordinary enum's variants are not suspend points, so the one
            // it decoded to is reported on its own.
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
        } else {
            writeln!(out, "{detail_indent}suspends:")?;
            tables.last().expect("just pushed").print_to_active(out)?;
        }

        if verbose && (frame.state.is_some() || active) {
            let payload = match &frame.state {
                Some(state) => state.payload.as_ref(),
                None => frame.future.as_ref(),
            };
            let locals = state_locals(payload.ty);
            // The locals belong to the marked row, so they hang from it
            // rather than from the frame; a frame with no inventory keeps
            // them against its own detail column.
            let heading_indent = if rows_empty {
                detail_indent.clone()
            } else {
                format!("{detail_indent}  ")
            };
            if !locals.is_empty() {
                let heading = if frame.state.is_some() {
                    "locals:"
                } else {
                    "fields:"
                };
                writeln!(out, "{heading_indent}{heading}")?;
            }
            let value_indent = format!("{heading_indent}  ");
            // print_variable's contract: the value's lines after the
            // first open with the variable's indent plus two spaces.
            let value_prefix = format!("{value_indent}  ");
            for m in locals {
                let start = m.offset() as usize;
                let end = start + m.ty().size() as usize;
                match payload.bytes.get(start..end) {
                    Some(bytes) => {
                        let v = reify::TypeInfoRef::new(m.ty(), payload.addr + m.offset(), bytes)
                            .peel();
                        let mut disp = v
                            .display_from_target(ctx.proc, depth)
                            .elide_override(elide)
                            .line_prefix(&value_prefix);
                        if let Some(annotate) = annotate {
                            disp = disp.annotate_addrs(annotate);
                        }
                        if ugly {
                            disp = disp.ugly();
                        }
                        print_variable(out, &value_indent, m.name(), &format_args!("{disp:#}"))?;
                    }
                    None => writeln!(out, "{value_indent}{}: <unreadable>", m.name())?,
                }
            }
        }

        // An inventory introduces the child itself: the marked row *is*
        // the await that produced it, and the branch descends from there.
        if rows_empty {
            if !active {
                writeln!(out, "{detail_indent}awaits:")?;
            }
            node_indent += FRAME_DETAIL_STEP;
        } else {
            node_indent += FRAME_DETAIL_STEP + SUSPEND_ROW_STEP;
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

    // Name what the task is actually waiting on when the leaf is a
    // known primitive. It belongs to the deepest frame, so it goes out
    // before any inventory closes back over it.
    match ctx.wait_target(chain) {
        Some(Ok(target)) => writeln!(out, "{detail_indent}waiting on {target}")?,
        Some(Err(e)) => writeln!(
            io::stderr(),
            "warning: failed to read what the leaf future waits on: {e:#}"
        )?,
        None => {}
    }

    // The states each frame lists after the one it is parked in. They
    // are printed here, innermost frame first, because the subtree that
    // grew out of the active row sits between them and their own block.
    for table in tables.iter().rev() {
        table.print_after_active(out)?;
    }
    Ok(())
}

/// The column the outermost future's node line starts at.
const FRAME_ROOT_INDENT: usize = 2;

/// How far a frame's detail sits inside its node line.
const FRAME_DETAIL_STEP: usize = 3;

/// How far a suspend row's text sits inside the detail column, leaving
/// room for the marker in front of it.
const SUSPEND_ROW_STEP: usize = 2;

/// Marks the state a coroutine is parked in. Distinct from the `*` the
/// tree puts on the leaf frame, which says where the chain ends rather
/// than which of a frame's suspend points is live.
const SUSPEND_MARKER: char = '▸';

fn frame_detail_indent(node_indent: usize) -> String {
    " ".repeat(node_indent + FRAME_DETAIL_STEP)
}

fn state_label_width(frame: usize) -> usize {
    if frame == 0 {
        13
    } else {
        frame.to_string().len() + 16
    }
}

/// One row of a coroutine frame's suspend-point inventory: somewhere the
/// future can park, read from its type rather than from the target.
struct SuspendRow<'b> {
    /// `Suspend0`, `Suspend1`, …, or a terminal state (`Unresumed`,
    /// `Returned`, `Panicked`) when that is the one the frame is in.
    name: &'b str,
    /// The awaited expression's source coordinates.
    loc: Option<(&'b str, u32)>,
    /// How many source-level locals the state holds live. Every variant
    /// of a coroutine shares the same storage, so only the active
    /// state's *values* can be read; for the rest a count is the most
    /// the type alone can say.
    locals: usize,
    /// What the state awaits, from its `__awaitee` member.
    awaitee: Option<&'b str>,
    /// Whether this is the state the frame is parked in.
    active: bool,
}

/// A coroutine frame's suspend points, in the order the debug info lists
/// its variants.
///
/// Empty for a frame that is not a coroutine — a plain leaf future, or
/// an ordinary enum whose variants are alternatives rather than parking
/// spots — and for one whose state did not decode: with nothing to mark,
/// an inventory would say where the future *could* be without saying
/// where it is.
fn suspend_rows<'b>(frame: &bundle::AwaitFrame<'b>) -> Vec<SuspendRow<'b>> {
    let Some(state) = &frame.state else {
        return Vec::new();
    };
    if !frame.future.ty.is_coroutine() {
        return Vec::new();
    }
    frame
        .future
        .ty
        .variants()
        .filter_map(|variant| {
            let name = variant.state_name();
            let active = name == state.name;
            // A terminal state is not a suspend point; it earns a row
            // only by being the one the frame is actually in, which it
            // is for a task parked before its first poll or holding an
            // unconsumed result.
            if !active && !name.starts_with("Suspend") {
                return None;
            }
            Some(SuspendRow {
                name,
                loc: variant.await_loc(),
                locals: state_locals(variant.ty).len(),
                awaitee: variant.ty.member("__awaitee").map(|m| m.ty().name()),
                active,
            })
        })
        .collect()
}

/// The source-level locals a coroutine state holds live.
///
/// `__…` members are compiler-generated (the awaitee itself and
/// liveness slots), not source-level locals. A coroutine state may hold
/// the same name twice (a captured upvar and a saved local), so members
/// are sliced positionally, never looked up by name.
fn state_locals(ty: BundleType<'_>) -> Vec<BundleMember<'_>> {
    let mut seen = std::collections::HashSet::new();
    ty.members()
        .filter(|m| {
            m.ty().size() > 0 && !m.name().starts_with("__") && seen.insert((m.name(), m.offset()))
        })
        .collect()
}

/// A frame's suspend rows laid out in columns, printable in two pieces.
///
/// The child frame is printed between them — it hangs from the marked
/// row — so the widths are settled once, over the whole inventory, and
/// both pieces are written against them. An empty column is omitted
/// rather than padded, so a frame whose states hold nothing does not
/// carry a blank gutter down the trace.
struct SuspendTable<'b> {
    rows: Vec<SuspendRow<'b>>,
    /// `(location, locals, awaitee)`, already reduced to what each row
    /// shows: the marked row drops its awaitee, which the child frame
    /// beneath it names anyway, and under `verbose` drops its locals
    /// count, since those values are about to be listed in full.
    cells: Vec<(String, String, &'b str)>,
    detail_indent: String,
    name_width: usize,
    loc_width: usize,
    locals_width: usize,
}

impl<'b> SuspendTable<'b> {
    fn new(rows: Vec<SuspendRow<'b>>, verbose: bool, detail_indent: String) -> Self {
        let cells: Vec<(String, String, &'b str)> = rows
            .iter()
            .map(|row| {
                let loc = row
                    .loc
                    .map(|(file, line)| format!("{file}:{line}"))
                    .unwrap_or_default();
                let locals = match row.locals {
                    0 => String::new(),
                    _ if row.active && verbose => String::new(),
                    1 => "1 local".to_string(),
                    n => format!("{n} locals"),
                };
                let awaitee = if row.active {
                    ""
                } else {
                    row.awaitee.unwrap_or_default()
                };
                (loc, locals, awaitee)
            })
            .collect();
        let width =
            |f: fn(&(String, String, &str)) -> usize| cells.iter().map(f).max().unwrap_or(0);
        Self {
            name_width: rows.iter().map(|row| row.name.len()).max().unwrap_or(0),
            loc_width: width(|c| c.0.len()),
            locals_width: width(|c| c.1.len()),
            rows,
            cells,
            detail_indent,
        }
    }

    fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Where the marked row sits, or the end of the table when no row is
    /// marked — a state that matched no variant, which leaves nothing to
    /// hang a child from.
    fn active(&self) -> usize {
        self.rows
            .iter()
            .position(|row| row.active)
            .unwrap_or(self.rows.len().saturating_sub(1))
    }

    /// The states up to and including the one the frame is parked in.
    fn print_to_active(&self, out: &mut dyn io::Write) -> Result<()> {
        self.print_range(0, self.active() + 1, out)
    }

    /// The states the frame lists after the one it is parked in.
    fn print_after_active(&self, out: &mut dyn io::Write) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        self.print_range(self.active() + 1, self.rows.len(), out)
    }

    fn print_range(&self, from: usize, to: usize, out: &mut dyn io::Write) -> Result<()> {
        let (name_width, loc_width, locals_width) =
            (self.name_width, self.loc_width, self.locals_width);
        for (row, (loc, locals, awaitee)) in self.rows[from..to].iter().zip(&self.cells[from..to]) {
            let marker = if row.active { SUSPEND_MARKER } else { ' ' };
            let mut line = format!("{}{marker} {:<name_width$}", self.detail_indent, row.name);
            if loc_width > 0 {
                line.push_str(&format!("  {loc:<loc_width$}"));
            }
            if locals_width > 0 {
                line.push_str(&format!("  {locals:<locals_width$}"));
            }
            if !awaitee.is_empty() {
                line.push_str(&format!("  {awaitee}"));
            }
            writeln!(out, "{}", line.trim_end())?;
        }
        Ok(())
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

/// Print a named variable compactly when it fits on one line, or as a
/// `name:` heading with the value's lines beneath it when the value is
/// multi-line.
///
/// The value's own lines arrive final-form: a multi-line value must be
/// rendered with a reify line prefix of this `indent` plus two spaces
/// (see [`reify::DisplayTargetValue::line_prefix`]), so this function
/// lays out only the heading and the first line, and everything after
/// the first newline passes through to the sink untouched — no per-line
/// scan or re-copy, on values that run to gigabytes.
fn print_variable(
    out: &mut dyn io::Write,
    indent: &str,
    name: &str,
    value: &dyn fmt::Display,
) -> Result<()> {
    /// Small pieces batch up to this much before a sink write. The
    /// renderer writes a few bytes at a time — a member name, a brace —
    /// so accepting one must cost what a `String` append does.
    const CHUNK: usize = 64 << 10;
    /// A piece at least this big skips the batch and goes to the sink
    /// whole: the parallel renderer hands over entire chunk buffers,
    /// and staging those would only re-copy them.
    const BIG: usize = 4 << 10;

    struct Stream<'w> {
        sink: &'w mut dyn io::Write,
        /// Small pieces batched between sink writes.
        staged: String,
        indent: &'w str,
        name: &'w str,
        /// The first line so far; `None` once a newline committed the
        /// heading layout.
        first: Option<String>,
        /// The io error behind a `fmt::Error`, which cannot carry it.
        error: Option<io::Error>,
    }

    impl Stream<'_> {
        fn put(&mut self, mut text: &str) -> io::Result<()> {
            if self.first.is_some() {
                match text.split_once('\n') {
                    None => {
                        self.first.as_mut().unwrap().push_str(text);
                        return Ok(());
                    }
                    // The first newline commits the heading layout. The
                    // lines after it open with the renderer's prefix, so
                    // only this one needs its margin laid in here.
                    Some((head, rest)) => {
                        let first = self.first.take().unwrap();
                        self.staged.push_str(self.indent);
                        self.staged.push_str(self.name);
                        self.staged.push_str(":\n");
                        self.staged.push_str(self.indent);
                        self.staged.push_str("  ");
                        self.staged.push_str(&first);
                        self.staged.push_str(head);
                        self.staged.push('\n');
                        text = rest;
                    }
                }
            }
            if text.len() >= BIG {
                self.flush()?;
                return self.sink.write_all(text.as_bytes());
            }
            self.staged.push_str(text);
            if self.staged.len() >= CHUNK {
                self.flush()?;
            }
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.sink.write_all(self.staged.as_bytes())?;
            self.staged.clear();
            Ok(())
        }

        fn finish(&mut self) -> io::Result<()> {
            // No newline ever came: the single-line layout.
            if let Some(value) = self.first.take() {
                self.staged.push_str(self.indent);
                self.staged.push_str(self.name);
                self.staged.push_str(": ");
                self.staged.push_str(&value);
            }
            self.staged.push('\n');
            self.flush()
        }
    }

    impl fmt::Write for Stream<'_> {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            self.put(text).map_err(|e| {
                self.error = Some(e);
                fmt::Error
            })
        }
    }

    let mut stream = Stream {
        sink: out,
        staged: String::new(),
        indent,
        name,
        first: Some(String::new()),
        error: None,
    };
    use fmt::Write as _;
    let outcome = write!(stream, "{value}");
    match stream.error.take() {
        Some(error) => Err(error.into()),
        None => {
            outcome.map_err(|_| anyhow::anyhow!("failed to render {name}"))?;
            stream.finish()?;
            Ok(())
        }
    }
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
#[cfg(feature = "snapshot")]
fn warm_frame_values<T: proc::Target + Sync>(
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
#[cfg(feature = "snapshot")]
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

    // And the sub-executor census, so the set node chains and child
    // futures it reads replay offline as well.
    let _ = census::census(&ctx, &list);

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

/// How a task is referred to in passing: by id, or by Header address
/// when it has none.
fn task_label(list: &bundle::TaskList, index: usize) -> String {
    match list.tasks[index].task_id {
        Some(id) => format!("task {id}"),
        None => format!("task at {:?}", list.tasks[index].addr),
    }
}

/// List every future the census found, grouped by the task that owns
/// it: the futures held in frames off the poll spine, and each
/// sub-executor with its children.
fn exec_futures(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let list = &session.tasks;
    let census = session.census();
    for err in &census.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }

    // Group by owning task, keeping each group's entries in the order
    // the census found them.
    let mut by_owner: BTreeMap<usize, (Vec<&census::FutureSet>, Vec<&census::HeldFuture>)> =
        BTreeMap::new();
    for set in &census.sets {
        by_owner.entry(set.owner).or_default().0.push(set);
    }
    for held in &census.held {
        by_owner.entry(held.owner).or_default().1.push(held);
    }

    for (i, (&owner, (sets, held))) in by_owner.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        // How many futures the task has in flight beyond its spine:
        // the held ones plus every resident set child (an empty slot
        // is a future already gone, not one outstanding).
        let futures: usize = held.len()
            + sets
                .iter()
                .map(|s| s.children.iter().filter(|c| c.future.is_some()).count())
                .sum::<usize>();
        let plural = if futures == 1 { "" } else { "s" };
        writeln!(
            out,
            "{}: {} — {futures} future{plural}",
            task_label(list, owner),
            future_name(&list.tasks[owner].future)
        )?;
        for h in held {
            let via = h
                .via
                .as_ref()
                .map(|v| format!(", via {v}"))
                .unwrap_or_default();
            let state = h
                .state
                .as_ref()
                .map(|s| format!("  {s}"))
                .unwrap_or_default();
            writeln!(
                out,
                "  held (frame {}, `{}`{via}): {:#x}  {}{state}",
                h.frame, h.local, h.addr, h.future
            )?;
            if let Some(waiting) = &h.waiting_on {
                writeln!(out, "    waiting on {waiting}")?;
            }
        }
        for set in sets {
            let via = set
                .via
                .as_ref()
                .map(|v| format!(", via {v}"))
                .unwrap_or_default();
            writeln!(
                out,
                "  {} at {:#x} (frame {}, `{}`{via}): {} child(ren)",
                set.ty,
                set.addr,
                set.frame,
                set.local,
                set.children.len()
            )?;
            for child in &set.children {
                let Some(future) = &child.future else {
                    writeln!(out, "    {:#x}  <completed, not yet reaped>", child.node)?;
                    continue;
                };
                let state = child
                    .state
                    .as_ref()
                    .map(|s| format!("  {s}"))
                    .unwrap_or_default();
                writeln!(out, "    {:#x}  {future}{state}", child.node)?;
                if let Some(waiting) = &child.waiting_on {
                    writeln!(out, "      waiting on {waiting}")?;
                }
            }
        }
    }

    if by_owner.is_empty() {
        writeln!(out, "no futures found outside the task list")?;
    } else {
        let children: usize = census.sets.iter().map(|s| s.children.len()).sum();
        writeln!(
            out,
            "\n{} held future(s); {} set(s) holding {} child future(s)",
            census.held.len(),
            census.sets.len(),
            children
        )?;
    }
    Ok(())
}

/// The display name of a task's future, however well the symbol join
/// resolved it.
fn future_name(future: &bundle::FutureInfo) -> String {
    match future {
        bundle::FutureInfo::Known(known) => known.display_name.clone(),
        bundle::FutureInfo::Unknown {
            poll_symbol: Some(sym),
        } => format!("<unknown: {:#}>", rustc_demangle::demangle(sym)),
        bundle::FutureInfo::Unknown { poll_symbol: None } => "<unknown>".to_string(),
        bundle::FutureInfo::Ambiguous { candidates, .. } => {
            format!("<ambiguous: {}>", candidates.join(" | "))
        }
    }
}

fn exec_task_at(session: &Session<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    report_task_at(
        &session.tasks,
        session.extents(),
        session.census(),
        addr,
        out,
    )
}

/// The `task-at` answer, apart from the session so the offline
/// fixture tests can drive it.
fn report_task_at(
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some((index, offset)) = extents.locate(addr) else {
        // Not a task's memory — but a sub-executor's child node still
        // names the task that polls it.
        let Some((set_index, child, offset)) = census.locate(addr) else {
            writeln!(out, "no task's allocation contains {addr:#x}")?;
            return Ok(());
        };
        let set = &census.sets[set_index];
        let owner = &list.tasks[set.owner];
        writeln!(
            out,
            "{addr:#x} is at offset {offset:#x} in a FuturesUnordered child node \
             (set at {:#x}), polled by {}",
            set.addr,
            task_label(list, set.owner)
        )?;
        if let Some(future) = &set.children[child].future {
            let state = set.children[child]
                .state
                .as_ref()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            writeln!(out, "child future: {future}{state}")?;
        } else {
            writeln!(out, "child future: <completed, not yet reaped>")?;
        }
        writeln!(
            out,
            "Task {}: {} ({})",
            match owner.task_id {
                Some(id) => id.to_string(),
                None => format!("{:?}", owner.addr),
            },
            future_name(&owner.future),
            owner.state.lifecycle()
        )?;
        return Ok(());
    };
    let task = &list.tasks[index];
    let id = match task.task_id {
        Some(id) => id.to_string(),
        None => format!("{:?}", task.addr),
    };
    writeln!(
        out,
        "{addr:#x} is in task {id} at offset {offset:#x} (header {:?})",
        task.addr
    )?;
    writeln!(
        out,
        "Task {id}: {} ({})",
        future_name(&task.future),
        task.state.lifecycle()
    )?;
    if let Some(loc) = &task.spawn_location {
        writeln!(out, "Spawned at: {loc}")?;
    }
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
        print_variable(
            out,
            "  ",
            field,
            &format_args!("{:#}", render(session, &value, depth, ugly).line_prefix("    ")),
        )?;
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
    print_variable(
        out,
        "  ",
        "defer",
        &format_args!("{:#}", render(session, &defer, depth, ugly).line_prefix("    ")),
    )?;

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
        &format_args!("{:#}", render(session, &core.as_ref(), depth, ugly).line_prefix("    ")),
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
    writeln!(out, "{:#}", render(session, &value, depth, ugly))?;
    Ok(())
}

/// Display a value read from the target, honouring the custom formatters
/// unless asked for the raw structural view. Nothing is rendered until the
/// caller formats the result (with `{:#}` for the usual pretty layout), so
/// the text can stream to its destination instead of through a `String`.
fn render<'r, 'buf, 'b: 'buf>(
    session: &'r Session<'b>,
    value: &'r TypeInfoRef<'buf, 'b, BundleType<'b>>,
    depth: usize,
    ugly: bool,
) -> reify::DisplayTargetValue<'r, 'buf, 'b, BundleType<'b>, Proc> {
    let display = value.display_from_target(session.ctx.proc, depth);
    if ugly { display.ugly() } else { display }
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
        print_variable(&mut out, "  ", "count", &"42").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "  count: 42\n");
    }

    /// A multi-line value arrives with its lines after the first already
    /// prefixed (the renderer's `line_prefix` is the indent plus two
    /// spaces), so the heading and first line get their margin laid in
    /// here and the rest passes through byte for byte.
    #[test]
    fn aggregate_is_indented_below_the_name() {
        let mut out = Vec::new();
        print_variable(
            &mut out,
            "  ",
            "point",
            &"Point {\n        x: 1,\n        y: 2,\n    }",
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "  point:\n    Point {\n        x: 1,\n        y: 2,\n    }\n"
        );
    }

    /// Streaming decides the layout at the first newline however the text
    /// is chunked, so a value whose `Display` writes a piece at a time
    /// must land exactly where a single-write one does — including a
    /// piece big enough to take the direct-to-sink path.
    #[test]
    fn chunked_writes_land_like_whole_ones() {
        struct Chunked<'a>(&'a [&'a str]);
        impl std::fmt::Display for Chunked<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.iter().try_for_each(|piece| f.write_str(piece))
            }
        }
        let big = format!("    x: {},", "9".repeat(8 << 10));
        let pieces = ["Point {", "\n    x", ": 1,", "\n", &big, "\n", "}"];
        let mut chunked = Vec::new();
        print_variable(&mut chunked, "  ", "v", &Chunked(&pieces)).unwrap();
        let mut whole = Vec::new();
        print_variable(&mut whole, "  ", "v", &pieces.concat().as_str()).unwrap();
        assert_eq!(chunked, whole);
        assert_eq!(
            String::from_utf8(whole).unwrap(),
            format!("  v:\n    Point {{\n    x: 1,\n{big}\n}}\n")
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
        assert_eq!(state_label_width(1), 17);
        assert_eq!(state_label_width(10), 18);
    }
}

/// Offline `task-at` tests: address→task resolution over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod task_at_tests {
    use super::{parse_hex_addr, report_task_at};
    use exegesis::bundle::{Bundle, BundleView};
    use hansei_types::tokio::bundle::{Context, TaskExtents, TaskList};
    use hansei_types::tokio::census::{self, FutureCensus};
    use proc::Target;
    use proc::snapshot::Snapshot;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("hansei-types/tests/fixtures")
            .join(name)
    }

    fn with_tasks(program: &str, check: impl FnOnce(&TaskList, &TaskExtents, &FutureCensus)) {
        let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
            .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
        let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
            .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
        let ctx = Context::new(&snapshot, BundleView::new(&bundle)).expect("snapshot has mappings");

        let lwps = snapshot.lwps().unwrap();
        let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
        let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
        let list = ctx.enumerate_tasks(&shared).expect("the owned-task walk");
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&list, &extents, &census);
    }

    fn report(list: &TaskList, extents: &TaskExtents, census: &FutureCensus, addr: u64) -> String {
        let mut out = Vec::new();
        report_task_at(list, extents, census, addr, &mut out).expect("the report renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// An address inside a task's allocation — its header, or any
    /// offset short of the trailer's end — names that task; one
    /// outside every allocation reports the miss.
    #[test]
    fn test_addresses_resolve_to_the_containing_task() {
        with_tasks("sleep-join", |list, extents, census| {
            let sleeper = list
                .tasks
                .iter()
                .find(|t| t.task_id == Some(3))
                .expect("the sleeper is task 3");
            let header = sleeper.addr.0;

            let shown = report(list, extents, census, header);
            assert!(
                shown.contains(&format!(
                    "{header:#x} is in task 3 at offset 0x0 (header {header:#x})"
                )),
                "{shown}"
            );
            assert!(
                shown.contains("Task 3: sleep_join::sleeper::{async_fn_env#0} (idle)"),
                "{shown}"
            );

            let inside = report(list, extents, census, header + 0x10);
            assert!(inside.contains("is in task 3 at offset 0x10"), "{inside}");

            let miss = report(list, extents, census, 0x10);
            assert_eq!(miss, "no task's allocation contains 0x10\n");
        });
    }

    /// Every task claims its own header and nothing claims the word
    /// before it: the extents tile the tasks without bleeding.
    #[test]
    fn test_extents_cover_each_task_exactly() {
        with_tasks("dyn-future", |list, extents, _census| {
            for (index, task) in list.tasks.iter().enumerate() {
                assert_eq!(
                    extents.locate(task.addr.0),
                    Some((index, 0)),
                    "task {:?} does not claim its own header",
                    task.addr
                );
                let before = extents.locate(task.addr.0 - 1);
                assert_ne!(
                    before.map(|(i, _)| i),
                    Some(index),
                    "task {:?} claims the byte before its header",
                    task.addr
                );
            }
        });
    }

    /// The `0x` prefix is required, and the digits behind it parse as
    /// hex — the contract the command's help text states.
    #[test]
    fn test_addresses_parse_only_with_a_0x_prefix() {
        assert_eq!(parse_hex_addr("0x7fffb1c26100"), Ok(0x7fffb1c26100));
        assert_eq!(parse_hex_addr("0XFF"), Ok(0xff));
        assert!(parse_hex_addr("7fffb1c26100").is_err());
        assert!(parse_hex_addr("42").is_err());
        assert!(parse_hex_addr("0x").is_err());
        assert!(parse_hex_addr("0xzz").is_err());
    }
}

/// Offline trace-rendering tests: the await tree as `trace` prints it,
/// driven from a real extracted bundle joined against a real captured
/// snapshot.
///
/// The acceptance suite covers the same rendering end to end, but only
/// where a process can be cored; these run in plain `cargo test` on any
/// platform, which is what keeps the tree's shape — the suspend
/// inventories and the indent that accumulates through them — under test
/// while it is being changed.
#[cfg(test)]
mod trace_render_tests {
    use super::print_await_chain;
    use exegesis::bundle::{Bundle, BundleView};
    use hansei_types::tokio::bundle::{Context, TaskStage};
    use proc::Target;
    use proc::snapshot::Snapshot;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("hansei-types/tests/fixtures")
            .join(name)
    }

    /// Render task `task_id`'s await chain from the named fixture pair,
    /// with heap addresses masked so the expectation compares exactly.
    fn trace(program: &str, future: &str, verbose: bool) -> String {
        let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
            .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
        let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
            .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
        let ctx = Context::new(&snapshot, BundleView::new(&bundle)).expect("snapshot has mappings");

        let lwps = snapshot.lwps().unwrap();
        let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
        let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
        let list = ctx.enumerate_tasks(&shared).expect("the owned-task walk");

        let task = list
            .tasks
            .iter()
            .find(|t| match &t.future {
                hansei_types::tokio::bundle::FutureInfo::Known(known) => {
                    known.display_name == future
                }
                _ => false,
            })
            .unwrap_or_else(|| panic!("no task running {future}"));
        let TaskStage::Running(root) = ctx.task_stage(task).expect("the task's stage decodes")
        else {
            panic!("{future} is not running");
        };

        let chain = ctx.await_chain(root);
        let mut out = Vec::new();
        print_await_chain(
            &ctx,
            &chain,
            verbose,
            4,
            false,
            &Default::default(),
            None,
            &mut out,
        )
        .expect("the chain renders");
        let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
        regex::Regex::new(r"0x[0-9a-f]+")
            .unwrap()
            .replace_all(&rendered, "0xADDR")
            .into_owned()
    }

    /// Two suspend points, parked at the second: the row order is the
    /// enum's, the marked row drops the awaitee its child already names,
    /// and the child hangs from it.
    #[test]
    fn test_inventory_marks_the_active_state() {
        assert_eq!(
            trace(
                "simple-await",
                "simple_await::work::{async_fn_env#0}",
                false
            ),
            "  0  async fn      simple_await::work::{async_fn_env#0}
     suspends:
       Suspend0  simple-await.rs:32  11 locals  simple_await::ready_value::{async_fn_env#0}
     ▸ Suspend1  simple-await.rs:34  10 locals
       └─* 1  future        tokio::sync::oneshot::Receiver<u32>
"
        );
    }

    /// A frame whose states hold nothing carries no locals column, and
    /// the indent accumulates through each frame's inventory rather than
    /// by a fixed step per level.
    #[test]
    fn test_deep_chain_indents_through_its_inventories() {
        let rendered = trace(
            "futurelock",
            "futurelock::main::{async_block#0}::{async_block_env#0}",
            false,
        );
        assert_eq!(
            rendered,
            "  0  async block   futurelock::main::{async_block#0}::{async_block_env#0}
     suspends:
       Suspend0  futurelock.rs:22  1 local  futurelock::start_background_task::{async_fn_env#0}
     ▸ Suspend1  futurelock.rs:25  1 local
       └─  1  async fn      futurelock::do_stuff::{async_fn_env#0}
          suspends:
            Suspend0  futurelock.rs:59  4 locals  core::future::poll_fn::PollFn<futurelock::do_stuff::{async_fn#0}::{closure_env#0}>
          ▸ Suspend1  futurelock.rs:64  3 locals
            └─  2  async fn      futurelock::do_async_thing::{async_fn_env#0}
               suspends:
               ▸ Suspend0  futurelock.rs:72  2 locals
                 └─  3  async fn      tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>
                    suspends:
                    ▸ Suspend0  src/sync/mutex.rs:455
                      └─  4  async block   tokio::sync::mutex::{impl#10}::lock::{async_fn#0}::{async_block_env#0}<()>
                         suspends:
                         ▸ Suspend0  src/sync/mutex.rs:436
                           └─  5  async fn      tokio::sync::mutex::{impl#10}::acquire::{async_fn_env#0}<()>
                              suspends:
                                Suspend0  src/sync/mutex.rs:656  1 local  tokio::trace::async_trace_leaf::{async_fn_env#0}
                              ▸ Suspend1  src/sync/mutex.rs:658
                                └─* 6  future        tokio::sync::batch_semaphore::Acquire
                                   waiting on a tokio::sync::Mutex (semaphore 0xADDR): 1 permit requested, 0 available; wake queue: task 5
"
        );
    }

    /// A frame parked at a state its inventory lists others after: the
    /// rows keep the enum's order, so the one below the active row is
    /// printed once the subtree hanging off the active row is closed.
    #[test]
    fn test_states_after_the_active_one_close_over_the_subtree() {
        assert_eq!(
            trace("dyn-future", "dyn_future::driver::{async_fn_env#0}", false),
            "  0  async fn      dyn_future::driver::{async_fn_env#0}
     suspends:
     ▸ Suspend0  dyn-future.rs:29  1 local
       └─  1  async fn      dyn_future::boxed_leaf::{async_fn_env#0} [dyn]
          suspends:
          ▸ Suspend0  dyn-future.rs:11
            └─* 2  future        tokio::sync::oneshot::Receiver<u32>
       Suspend1  dyn-future.rs:30  2 locals  tokio::task::join_set::{impl#1}::join_next::{async_fn_env#0}<u32>
"
        );
    }

    /// Under `--verbose` a pointer into another task's allocation is
    /// labelled with that task's id, the way `exec_trace` wires it up:
    /// the joiner's `JoinHandle` holds the sleeper's `Header` pointer,
    /// which must name the task a reader would trace next.
    #[test]
    fn test_verbose_labels_pointers_into_other_tasks() {
        let bundle = Bundle::load(&fixture("sleep-join.bundle"))
            .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
        let snapshot = Snapshot::load(&fixture("sleep-join.snapshot"))
            .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
        let ctx = Context::new(&snapshot, BundleView::new(&bundle)).expect("snapshot has mappings");

        let lwps = snapshot.lwps().unwrap();
        let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
        let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
        let list = ctx.enumerate_tasks(&shared).expect("the owned-task walk");

        let joiner = list
            .tasks
            .iter()
            .find(|t| t.task_id == Some(4))
            .expect("the joiner is task 4");
        let TaskStage::Running(root) = ctx.task_stage(joiner).expect("the joiner's stage decodes")
        else {
            panic!("the joiner is not running");
        };

        let extents = ctx.task_extents(&list);
        let annotate = |ptr: u64| {
            let (index, _) = extents.locate(ptr)?;
            list.tasks[index].task_id.map(|id| format!("task {id}"))
        };

        let chain = ctx.await_chain(root);
        let mut out = Vec::new();
        print_await_chain(
            &ctx,
            &chain,
            true,
            4,
            false,
            &Default::default(),
            Some(&annotate),
            &mut out,
        )
        .expect("the chain renders");
        let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
        assert!(rendered.contains("(task 3)"), "{rendered}");
    }

    /// Under `--verbose` the marked row drops its count — the values it
    /// counted are listed right below it — and the listing hangs from
    /// the row rather than from the frame.
    #[test]
    fn test_verbose_lists_the_active_states_locals_under_its_row() {
        let rendered = trace("simple-await", "simple_await::work::{async_fn_env#0}", true);
        assert!(
            rendered.contains("     ▸ Suspend1  simple-await.rs:34\n       locals:\n"),
            "{rendered}"
        );
        // The inactive row keeps its count: every variant shares the
        // enum's storage, so its locals cannot be read at all.
        assert!(
            rendered.contains("       Suspend0  simple-await.rs:32  11 locals  "),
            "{rendered}"
        );
        assert!(rendered.contains("\n         count: 3\n"), "{rendered}");
    }
}

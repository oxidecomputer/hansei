use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::tokio::graph::{self as rt_graph, Analysis};
use hansei_runtime::tokio::{bundle, census, contract};
use proc::{Proc, Target};

use std::cell::OnceCell;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod graph;
pub mod repl;
#[cfg(feature = "snapshot")]
mod snapshot_cmd;
pub mod summary;
mod tasks;
mod threads;
mod trace;
pub mod types;
mod whatis;

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

    /// Attach even if non-essential walk paths are broken against this
    /// tokio's layouts, degrading whatever reads them. By default any
    /// broken path refuses the attach with a report of what moved.
    #[arg(long)]
    best_effort: bool,

    /// Read only one of the target's runtimes, by its index in the
    /// discovered list (`info` names them). By default every runtime is
    /// read, merged with a tag where there is more than one.
    #[arg(long, value_name = "INDEX")]
    runtime: Option<usize>,
}

/// Everything a session can be asked. These are read from stdin, never
/// from the command line, so a `Subcommand` derive here defines the
/// grammar of a typed line rather than of an argv.
#[derive(Subcommand)]
pub enum Command {
    /// Count what the target holds: its threads, its tasks and its
    /// futures, with what most of each is doing.
    ///
    /// This is the listing to read first. Every other command answers a
    /// question about one thing — this task, that address, those
    /// threads — and each number here is one a named command expands:
    /// `threads` for a thread, `tasks` for the task blocks behind a
    /// tally, `tasks --futures` for the futures counted off the await
    /// chains, `graph` for what waits on what.
    ///
    /// The thread section splits the target's lwps three ways: the
    /// workers running the scheduler's loop, the threads that have
    /// merely entered the runtime, and everything else. Each split is a
    /// share of the line above it and never a second count of the same
    /// threads — which takes one correction, because the runtime
    /// launches every worker with `spawn_blocking` and its pool
    /// therefore counts the workers among its own threads. They are
    /// netted out, so the pool's row is the threads doing blocking work
    /// and nothing else.
    ///
    /// The workers are broken down by what their parkers say, and the
    /// one parked *in* the driver is named — that is the thread blocked
    /// in the system's readiness call on the whole runtime's behalf.
    /// There is no io thread as such in a multi_thread runtime: the
    /// driver rotates between workers, so what is reported is whichever
    /// held it when the target stopped.
    ///
    /// The task section counts every task the runtime owns by
    /// lifecycle, by what it is waiting on, and by the future types and
    /// spawn sites most of them share. A wait is named by the primitive
    /// it is where hansei decodes one — a timer, a `JoinHandle`, the
    /// semaphore behind a `Mutex` — and by the type its await chain
    /// bottoms out in otherwise, which is most of them on any real
    /// target: the io readiness a socket is parked on, the channel a
    /// loop is receiving from, the `poll_fn` a hand-written future
    /// sits in. A task that is mid-poll, finished, or whose chain
    /// stopped before reaching any leaf has its own row saying so,
    /// rather than being counted as waiting on something.
    ///
    /// Only what is out of the ordinary is called out beside those.
    /// That nearly every task is detached is true of every target and
    /// says nothing about this one; that some are cancelled and not yet
    /// complete, or that the bundle cannot name what some are running,
    /// is worth knowing.
    ///
    /// The future section counts three populations that do not overlap:
    /// the futures on the tasks' own await chains, the ones their
    /// frames hold beside those chains, and the ones their
    /// `FuturesUnordered` hold. A `JoinSet`'s members are counted with
    /// the tasks instead, because that is what they are.
    ///
    /// Taking a census walks every task's await chain twice over — once
    /// for what each waits on, once for the futures off those chains —
    /// so on a large target it is the slowest command here. Both walks
    /// are kept, though, so a `tasks --futures`, `graph` or `whatis`
    /// after it costs nothing. A census narrowed to sections walks only
    /// what those sections need, which is nothing at all for the
    /// threads.
    Census {
        /// Print the thread section. Naming no section prints them all.
        #[arg(long, short = 'T')]
        threads: bool,

        /// Print the task section.
        #[arg(long, short)]
        tasks: bool,

        /// Print the future section.
        #[arg(long, short)]
        futures: bool,

        /// How many entries each "most of them are this" listing shows
        /// before the rest are summed into a final row.
        #[arg(long, short = 'n', default_value_t = 5)]
        top: usize,
    },

    /// List the types whose name contains a substring.
    FindTypes {
        /// The substring to look for.
        needle: String,
    },

    /// Print the waker-based task dependency graph: what every task is
    /// waiting on, and any futurelock — a lock future granted or queued
    /// on a contended semaphore that its task stopped polling and so can
    /// never complete or release (RFD 609).
    ///
    /// A task waiting for another is drawn above it, so reading down a
    /// tree is reading further into what blocks the task at its top:
    /// each row says what that task waits on, and the rows under it are
    /// the tasks that have to move first.
    ///
    /// Four things name a task to nest. Two are the task's own wait: a
    /// `JoinHandle` names the task being joined, and a contended
    /// semaphore names whoever the futurelock analysis found holding an
    /// acquire on it — the only case where a holder is knowable at all,
    /// since a tokio `Mutex` records no owner. The other two are what
    /// the census found in the task's frames: the members of a
    /// `JoinSet` it drives, marked `[in the JoinSet above]`, and the
    /// tasks it holds a `JoinHandle` to without awaiting, marked `[its
    /// handle held above]`. Both marks name the row they hang under,
    /// since that is the task doing the holding. Those two carry most
    /// of a real target's structure —
    /// `join_next` on a set is not a `JoinHandle` await, so nothing
    /// about the driving task's own wait mentions the tasks it exists
    /// to collect.
    ///
    /// A row's `WAITING ON` names the primitive where hansei decodes
    /// one and the type the task's await chain bottoms out in
    /// otherwise, which is most rows on a real target. `-` is for a
    /// task with no chain to have reached a leaf at all: mid-poll,
    /// finished, or one whose walk stopped short.
    ///
    /// Only the tasks in a graph are listed. A task that names none and
    /// is named by none is in no graph at all and is left out, since
    /// printing the twenty thousand unrelated tasks of a real runtime
    /// is what makes its thirty related ones impossible to find.
    /// `tasks` still lists them and `census` counts what they wait
    /// on.
    ///
    /// Each of the rest gets exactly one row, under whatever waits for
    /// it or at the left margin. A task reached twice — two of them
    /// blocked on the lock one acquire holds — is spelled out the first
    /// time and marked `(above)` after that, and a wait that closes back
    /// on the tasks above it is marked `← cycle` rather than followed:
    /// a task blocked on a lock its own abandoned future holds is that
    /// mark on its own row.
    Graph,

    /// Show the target, the bundle, and how far its symbols resolve.
    Info,

    /// Show the runtime's own state, read straight through the bundle's
    /// layouts: its drivers, or the scheduler state the workers share.
    /// The bundle's elisions (which hide runtime internals inside user
    /// values) never apply to this view.
    Runtime {
        /// Which state to show.
        #[arg(value_enum)]
        field: RuntimeField,

        #[command(flatten)]
        render: RenderOpts,
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

    /// List every task owned by the runtime: id, lifecycle state,
    /// concrete future type, spawn location, where the future is
    /// defined, how many futures it holds in its own frames beside its
    /// await chain, and how many sets it drives from them.
    ///
    /// Those two are of what no task listing otherwise shows — a
    /// `select!` arm held in a frame, a FuturesUnordered's children, a
    /// JoinSet's tasks. `--futures` lists each under its own count. They
    /// are counted apart because a set is a container rather than a
    /// future in flight: what it holds is the count beside it, and the
    /// numbers add up rather than overlapping.
    ///
    /// The `Join sets` row counts what its sets hold in two parts where
    /// it drives both kinds, because they are two populations: a JoinSet
    /// holds *tasks*, which this listing already carries blocks for, and
    /// a FuturesUnordered holds futures, which nothing else shows at
    /// all. A kind it drives none of goes unmentioned rather than
    /// counted at zero.
    ///
    /// A task's own await chain is what `trace` prints: the future it is
    /// suspended in, the one that is awaiting, and so on down to the leaf
    /// it is parked on. That chain is the only thing the task polls when
    /// it wakes. `--futures` lists what a program has in flight *beside*
    /// it.
    ///
    /// A row under `Held futures` is a future sitting in a frame's
    /// local, off the await chain: a `select!`/`join!` arm mid-flight,
    /// one stored across an await, or a futurelock's abandoned lock.
    /// Whether it will ever be polled again is not knowable here — a
    /// select arm is polled at every wakeup, a futurelock's never.
    /// `graph` is what decides that. The same find in a set child's
    /// frames is printed under that child and marked `held`, since no
    /// heading over it says so.
    ///
    /// A FuturesUnordered is listed under `Join sets` with the children
    /// it polls. A child lives in a heap node rather than in a frame, so
    /// neither a task listing nor a trace reaches it. An empty slot is a
    /// completed child the set has not reaped yet — not a future
    /// outstanding, and counted apart from the ones in flight.
    ///
    /// A JoinSet — and so anything built on one, such as omicron's
    /// `ParallelTaskSet` — is listed there too, with the tasks it holds,
    /// by the ids `trace` takes. Those are spawned tasks: each has a
    /// block of its own here, runs on whatever worker picks it up, and
    /// keeps running whether or not the task holding the set ever wakes. So the set says *what this task is waiting to join*, not
    /// what it is polling. A member the listing has no block for is one
    /// the runtime no longer owns: complete and waiting to be joined, or
    /// running where this session cannot enumerate it.
    ///
    /// The scan recurses through what it finds, so a future held inside a
    /// set child is listed indented under that child rather than beside
    /// the ones its task holds itself. Read the indentation as
    /// containment: a future under a set child is *inside* it, so the
    /// rows nested under a find are not a population beside it. A joined
    /// task's own frames are not scanned from here at all — they are
    /// scanned under its own block, where they belong.
    ///
    /// Every count is of the finds at the top of its listing, for the
    /// same reason: a future the census reached through a set child is
    /// already inside something counted, and counting it again would
    /// make a task driving 3075 children of which each holds one future
    /// report both numbers as if they were populations to add up.
    ///
    /// Every address printed — a held future's, a set child's node — is
    /// what `trace <0xaddr>` accepts to follow that one future's own
    /// chain, and what `whatis <0xaddr>` says the whereabouts of.
    ///
    /// What is listed is found *by value* in a frame's bytes: coroutine
    /// environments, future trait objects (resolved through the vtable
    /// join), and the recognized leaf futures. Ordinary pointers are
    /// never followed, so a future reachable only behind an unrecognized
    /// Box or Arc is not here, and DWARF cannot say whether a
    /// hand-written combinator implements Future, so one is not listed
    /// itself — though the scan descends through it and any coroutine
    /// inside it is. Treat the listing as a lower bound.
    Tasks {
        /// List each task's futures and task sets under their counts,
        /// rather than only counting them.
        #[arg(long, short)]
        futures: bool,

        /// Show only these tasks, each selected by its decimal id. The
        /// whole list is printed when none is named.
        #[arg(value_name = "TASK")]
        task: Vec<u64>,
    },

    /// Show every thread running the runtime: the task it is polling,
    /// the worker core it holds, and its stack.
    Threads {
        /// Maximum stack frames to print per thread.
        #[arg(long, short, default_value_t = 50)]
        frames: usize,

        #[command(flatten)]
        render: RenderOpts,
    },

    /// Print an await chain: a task's, selected by its decimal id
    /// (see `tasks`), or a lone future's, selected by the hex address
    /// `tasks --futures` prints — a held future's address or a
    /// set child's node address; any pointer into either resolves.
    /// Either way the future type is resolved automatically, via the
    /// symbol join for a task and via the census for an address.
    Trace {
        /// What to trace: a decimal task id from `tasks`, or a future
        /// address from `tasks --futures`, in hex with a required
        /// leading `0x`.
        #[arg(value_parser = parse_trace_target)]
        target: TraceTarget,

        /// Show the variables present at each await point.
        #[arg(long, short)]
        verbose: bool,

        #[command(flatten)]
        render: RenderOpts,

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

    /// Say what an address is: the task whose allocation contains it,
    /// and every future the census found that claims it.
    ///
    /// More than one answer is the normal case rather than an
    /// ambiguity, since the things an address can belong to nest: a
    /// future a frame holds lives inside its task's allocation, one
    /// awaited by value lives inside the future awaiting it, and a
    /// `FuturesUnordered` lives inside whichever of those drives it.
    /// The report names each claim outermost first, so reading down it
    /// is reading inward.
    ///
    /// Any pointer into a thing resolves to it, not just its first
    /// byte: a task's Header, its future's state machine and its
    /// Trailer all name the task, and every address `tasks --futures`
    /// prints — a held future's, a set's, a set child's node — names
    /// what it was printed for.
    Whatis {
        /// The address to look up, written in hex with a required
        /// leading `0x` (e.g. `0x7fffb1c26100`).
        #[arg(value_parser = parse_hex_addr)]
        addr: u64,
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

/// How values read from the target are rendered. Shared by every
/// command that formats target memory, so the flags spell the same and
/// thread through the render path as one value.
#[derive(clap::Args, Copy, Clone)]
pub struct RenderOpts {
    /// Maximum depth to recurse when formatting values.
    #[arg(long, short, default_value_t = 4)]
    depth: usize,

    /// Disable every type's custom formatter and show the raw
    /// structural view of values instead.
    #[arg(long, short)]
    ugly: bool,
}

/// What `runtime` shows: each choice is one member of the runtime
/// handle, read out of the target.
#[derive(clap::ValueEnum, Copy, Clone)]
pub enum RuntimeField {
    /// The io, signal and time drivers, and the clock.
    Drivers,
    /// The scheduler state the workers share: the owned-task set, the
    /// injection queue, the idle set and the per-worker remotes.
    Shared,
}

/// Everything `trace` was told about rendering a chain: the shared
/// render options plus the flags only tracing takes.
struct TraceOpts<'a> {
    verbose: bool,
    render: RenderOpts,
    elide: &'a reify::ElideOverride,
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

/// What `trace` was pointed at: a task, by decimal id, or a future, by
/// the hex address `tasks --futures` prints.
#[derive(Clone, Copy)]
pub enum TraceTarget {
    Task(u64),
    Future(u64),
}

/// Parse a trace target. The split follows the spelling the listings
/// print — task ids in decimal, future addresses always `0x`-prefixed
/// hex — so either identifier pastes back in unchanged and neither can
/// be mistaken for the other.
fn parse_trace_target(s: &str) -> std::result::Result<TraceTarget, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        parse_hex_addr(s).map(TraceTarget::Future)
    } else {
        s.parse().map(TraceTarget::Task).map_err(|_| {
            format!(
                "a trace target is a decimal task id (see `tasks`) or a future \
                 address in hex with a leading 0x (see `tasks --futures`), \
                 got {s:?}"
            )
        })
    }
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
    #[cfg_attr(not(feature = "snapshot"), allow(dead_code))]
    bundle: &'b Bundle,
    /// How the session attached, so the capture attaches the same way.
    #[cfg_attr(not(feature = "snapshot"), allow(dead_code))]
    policy: contract::WalkPolicy,
    core: &'b Path,
    bundle_path: &'b Path,
    workers: Vec<bundle::Worker>,
    /// How many lwps the target has, whatever they are doing. The
    /// workers above are the ones holding a tokio `Context`; the
    /// difference is what the runtime is *not* running.
    lwps: usize,
    /// Every runtime discovered in the target, of either scheduler
    /// flavor. One on nearly every real target; current_thread makes
    /// more ordinary, and the task list below merges them all.
    runtimes: Vec<bundle::RuntimeRef<'b>>,
    tasks: bundle::TaskList,
    /// Task extents, the sub-executor census and the wait analysis,
    /// built on first use: a core does not change, so the address→task
    /// answers never do either, and the two walks cover every chain —
    /// worth paying once.
    extents: OnceCell<bundle::TaskExtents>,
    census: OnceCell<census::FutureCensus>,
    analysis: OnceCell<Analysis>,
}

impl<'b> Session<'b> {
    fn attach(proc: &'b Proc, bundle: &'b Bundle, args: &'b SessionArgs) -> Result<Self> {
        let policy = if args.best_effort {
            contract::WalkPolicy::BestEffort
        } else {
            contract::WalkPolicy::Strict
        };
        let ctx = match bundle::Context::with_policy(proc, BundleView::new(bundle), policy) {
            Ok(ctx) => ctx,
            // The hint is only true when a laxer policy would in fact
            // have attached: required breakage refuses either way.
            Err(e)
                if !args.best_effort
                    && bundle::Context::with_policy(
                        proc,
                        BundleView::new(bundle),
                        contract::WalkPolicy::BestEffort,
                    )
                    .is_ok() =>
            {
                return Err(e.context(
                    "only non-essential walk paths are broken; --best-effort \
                     attaches anyway, degrading whatever reads them",
                ));
            }
            Err(e) => return Err(e),
        };
        for line in ctx.contract_report().degraded(policy) {
            writeln!(io::stderr(), "warning: degraded: {line}")?;
        }
        check_fingerprint(&ctx, args.force)?;

        let lwps = proc.lwps().context("failed to read lwps")?;
        let workers = discover_workers(&lwps, &ctx)?;
        let mut runtimes = ctx.find_runtimes(&workers)?;
        if let Some(index) = args.runtime {
            if index >= runtimes.len() {
                let listed: Vec<String> = runtimes
                    .iter()
                    .enumerate()
                    .map(|(i, r)| format!("{i}: {}", r.flavor))
                    .collect();
                anyhow::bail!(
                    "--runtime {index}: the target has {} runtime(s): {}",
                    runtimes.len(),
                    listed.join(", ")
                );
            }
            runtimes = vec![runtimes.swap_remove(index)];
        }
        let tasks = ctx.enumerate_all_tasks(&runtimes)?;
        print_warnings(&tasks.errors)?;

        Ok(Session {
            ctx,
            proc,
            bundle,
            policy,
            core: &args.core,
            bundle_path: &args.bundle,
            workers,
            lwps: lwps.len(),
            runtimes,
            tasks,
            extents: OnceCell::new(),
            census: OnceCell::new(),
            analysis: OnceCell::new(),
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

    fn analysis(&self) -> &Analysis {
        self.analysis
            .get_or_init(|| rt_graph::analyze(&self.ctx, &self.tasks))
    }

    /// The runtime a worker thread belongs to, by the discovery
    /// grouping, with its index in the session's list.
    fn runtime_of(&self, tid: u32) -> Option<(usize, &bundle::RuntimeRef<'b>)> {
        self.runtimes
            .iter()
            .enumerate()
            .find(|(_, r)| r.worker_tids.contains(&tid))
    }

    /// The per-runtime tags the listings mark tasks with: one label per
    /// discovered runtime when there is more than one, empty — no tags —
    /// for the single-runtime targets that are nearly all of them.
    fn runtime_tags(&self) -> Vec<String> {
        if self.runtimes.len() <= 1 {
            return Vec::new();
        }
        self.runtimes
            .iter()
            .enumerate()
            .map(|(i, r)| format!("{i} ({})", r.flavor))
            .collect()
    }
}

/// Run one command against an attached session.
pub fn dispatch(session: &Session<'_>, command: Command, out: &mut dyn io::Write) -> Result<Flow> {
    match command {
        Command::Census {
            threads,
            tasks,
            futures,
            top,
        } => {
            let sections = summary::Sections::select(threads, tasks, futures);
            tasks::exec_census(session, sections, top, out)?
        }
        Command::FindTypes { needle } => types::find(&session.ctx.view, &needle, out)?,
        Command::Graph => graph::exec_graph(session, out)?,
        Command::Info => exec_info(session, out)?,
        Command::Runtime { field, render } => {
            threads::exec_runtime_field(session, field, render, out)?
        }
        #[cfg(feature = "snapshot")]
        Command::Snapshot { output } => snapshot_cmd::exec_snapshot(session, &output, out)?,
        Command::Tasks { futures, task } => tasks::exec_tasks(session, futures, &task, out)?,
        Command::Threads { frames, render } => threads::exec_threads(session, frames, render, out)?,
        Command::Trace {
            target,
            verbose,
            render,
            no_elide,
            elide,
        } => {
            let elide = reify::ElideOverride {
                no_elide,
                types: elide,
            };
            let opts = TraceOpts {
                verbose,
                render,
                elide: &elide,
            };
            trace::exec_trace(session, target, &opts, out)?
        }
        Command::Type {
            name,
            recursive,
            depth,
        } => types::describe(&session.ctx.view, &name, recursive, depth, out)?,
        Command::Whatis { addr } => whatis::exec_whatis(session, addr, out)?,
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
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(16);
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
    for (i, rt) in session.runtimes.iter().enumerate() {
        let tids: Vec<String> = rt.worker_tids.iter().map(|t| t.to_string()).collect();
        writeln!(
            out,
            "runtime {i}: {}, on lwp {}",
            rt.flavor,
            tids.join(", ")
        )?;
    }
    Ok(())
}

/// Attach-time bundle validation, shared by all bundle-mode
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
/// the bundle names.
fn discover_workers<T: proc::Target>(
    lwps: &[proc::LwpInfo],
    ctx: &bundle::Context<'_, T>,
) -> Result<Vec<bundle::Worker>> {
    let workers = ctx.find_workers(lwps)?;
    anyhow::ensure!(
        !workers.is_empty(),
        "no LWP has a tokio Context in thread-local storage; is this a tokio program?"
    );
    Ok(workers)
}

/// Report a walk's non-fatal errors the way every command does: one
/// warning line per error, on stderr.
fn print_warnings<'a>(errors: impl IntoIterator<Item = &'a anyhow::Error>) -> io::Result<()> {
    for err in errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }
    Ok(())
}

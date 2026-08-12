use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use hansei_bundle::{Bundle, BundleMember, BundleType, BundleView, WalkRole};
use hansei_runtime::tokio::{Lifecycle, bundle, census, contract, graph};
use proc::Proc;
use proc::snapshot::Recorder;
use reify::Value;

use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub mod repl;
pub mod summary;
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

    /// Attach even if non-essential walk paths are broken against this
    /// tokio's layouts, degrading whatever reads them. By default any
    /// broken path refuses the attach with a report of what moved.
    #[arg(long)]
    best_effort: bool,
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
    /// after it costs nothing.
    Census {
        /// How many entries each "most of them are this" listing shows
        /// before the rest are summed into a final row.
        #[arg(long, short, default_value_t = 5)]
        top: usize,
    },

    /// Show the runtime's drivers: io, signal, time and the clock.
    /// The bundle's elisions (which hide runtime internals inside user
    /// values) never apply to this view.
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

    /// Show the scheduler state the workers share: the owned-task set,
    /// the injection queue, the idle set and the per-worker remotes.
    /// The bundle's elisions (which hide runtime internals inside user
    /// values) never apply to this view.
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

        /// Maximum depth to recurse when formatting the worker core.
        #[arg(long, short, default_value_t = 4)]
        depth: usize,

        /// Disable every type's custom formatter and show the raw
        /// structural view of values instead.
        #[arg(long, short)]
        ugly: bool,
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
    bundle: &'b Bundle,
    /// How the session attached, so the capture attaches the same way.
    policy: contract::WalkPolicy,
    core: &'b Path,
    bundle_path: &'b Path,
    workers: Vec<bundle::Worker>,
    /// How many lwps the target has, whatever they are doing. The
    /// workers above are the ones holding a tokio `Context`; the
    /// difference is what the runtime is *not* running.
    lwps: usize,
    /// The multi_thread scheduler's `Handle`: the scheduler state and
    /// the drivers both hang off it.
    handle: Value<'b>,
    tasks: bundle::TaskList,
    /// Task extents, the sub-executor census and the wait analysis,
    /// built on first use: a core does not change, so the address→task
    /// answers never do either, and the two walks cover every chain —
    /// worth paying once.
    extents: OnceCell<bundle::TaskExtents>,
    census: OnceCell<census::FutureCensus>,
    analysis: OnceCell<graph::Analysis>,
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
        let handle = ctx.find_handle(&workers)?;
        let shared = ctx.walk(WalkRole::HandleShared).walk_at(handle)?;
        let tasks = ctx.enumerate_tasks(shared)?;
        for err in &tasks.errors {
            writeln!(io::stderr(), "warning: {err:#}")?;
        }

        Ok(Session {
            ctx,
            proc,
            bundle,
            policy,
            core: &args.core,
            bundle_path: &args.bundle,
            workers,
            lwps: lwps.len(),
            handle,
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

    fn analysis(&self) -> &graph::Analysis {
        self.analysis
            .get_or_init(|| graph::analyze(&self.ctx, &self.tasks))
    }
}

/// Run one command against an attached session.
pub fn dispatch(session: &Session<'_>, command: Command, out: &mut dyn io::Write) -> Result<Flow> {
    match command {
        Command::Census { top } => exec_census(session, top, out)?,
        Command::Drivers { depth, ugly } => {
            exec_runtime_field(session, "driver", depth, ugly, out)?
        }
        Command::FindTypes { needle } => types::find(&session.ctx.view, &needle, out)?,
        Command::Graph => exec_graph(session, out)?,
        Command::Info => exec_info(session, out)?,
        Command::SharedState { depth, ugly } => {
            exec_runtime_field(session, "shared", depth, ugly, out)?
        }
        #[cfg(feature = "snapshot")]
        Command::Snapshot { output } => exec_snapshot(session, &output, out)?,
        Command::Tasks { futures, task } => exec_tasks(session, futures, &task, out)?,
        Command::Threads {
            frames,
            depth,
            ugly,
        } => exec_threads(session, frames, depth, ugly, out)?,
        Command::Trace {
            target,
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
            exec_trace(session, target, verbose, depth, ugly, &elide, out)?
        }
        Command::Type {
            name,
            recursive,
            depth,
        } => types::describe(&session.ctx.view, &name, recursive, depth, out)?,
        Command::Whatis { addr } => exec_whatis(session, addr, out)?,
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
    Ok(())
}

fn exec_trace(
    session: &Session<'_>,
    target: TraceTarget,
    verbose: bool,
    depth: usize,
    ugly: bool,
    elide: &reify::ElideOverride,
    out: &mut dyn io::Write,
) -> Result<()> {
    match target {
        TraceTarget::Task(id) => exec_trace_task(session, id, verbose, depth, ugly, elide, out),
        TraceTarget::Future(addr) => {
            exec_trace_future(session, addr, verbose, depth, ugly, elide, out)
        }
    }
}

fn exec_trace_task(
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

    writeln!(out)?;
    match ctx.task_stage(task)? {
        bundle::TaskStage::Running(future) => {
            let chain = ctx.await_chain(future);
            print_trace_chain(session, &chain, verbose, depth, ugly, elide, out)?;
        }
        bundle::TaskStage::Finished(result) => {
            // Result<T::Output, JoinError>: Ok is a normal return, Err a
            // panic or cancellation.
            writeln!(
                out,
                "The task has finished; its output has not been consumed:"
            )?;
            let mut value = result.display_from_target(ctx.proc, 4);
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

/// Trace one future by address: resolve the address against the census
/// (`tasks --futures` prints the addresses this accepts), say where the
/// future lives, and render its await chain the way a task's is rendered.
fn exec_trace_future(
    session: &Session<'_>,
    addr: u64,
    verbose: bool,
    depth: usize,
    ugly: bool,
    elide: &reify::ElideOverride,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    let list = &session.tasks;
    let census = session.census();

    let found = future_at(&ctx.view, list, session.extents(), census, addr)?;
    let (root, owner) = match found {
        FutureAt::Held(h) => {
            let via = via_suffix(census, h.via);
            writeln!(out, "Future {:#x}: {}", h.addr, h.future)?;
            writeln!(
                out,
                "Held by: {} — {} (frame {}, `{}`{via})",
                task_label(list, h.owner),
                future_name(&list.tasks[h.owner].future),
                h.frame,
                h.local
            )?;
            (
                census::FutureRoot {
                    addr: h.addr,
                    ty: h.ty,
                },
                h.owner,
            )
        }
        FutureAt::Child { set, child, root } => {
            let via = via_suffix(census, set.via);
            let future = child.future.as_deref().unwrap_or("<undecoded>");
            writeln!(out, "Future {:#x}: {future}", child.node)?;
            writeln!(
                out,
                "Child of: {} at {:#x} (frame {}, `{}`{via}), polled by {} — {}",
                set.ty,
                set.addr,
                set.frame,
                set.local,
                task_label(list, set.owner),
                future_name(&list.tasks[set.owner].future)
            )?;
            (root, set.owner)
        }
    };

    // The owning task mid-poll is mutating its frames — and this future
    // with them — while we read; anything below may be torn.
    let task = &list.tasks[owner];
    if task.state.lifecycle() == Lifecycle::Running {
        let lwp = task
            .task_id
            .and_then(|id| {
                session
                    .workers
                    .iter()
                    .find(|w| w.current_task_id == Some(id))
            })
            .map(|w| format!(" on LWP {}", w.tid))
            .unwrap_or_default();
        writeln!(
            io::stderr(),
            "warning: {} is running{lwp}; the future's state may be torn",
            task_label(list, owner)
        )?;
    }

    let ty = ctx
        .view
        .ty(root.ty)
        .context("the census recorded a type the bundle does not carry")?;
    let value = Value::read(ctx.proc, ty, root.addr)
        .with_context(|| format!("failed to read the future at {:#x}", root.addr))?;

    writeln!(out)?;
    let chain = ctx.await_chain(value);
    print_trace_chain(session, &chain, verbose, depth, ugly, elide, out)
}

/// What a future address resolved to: the census row that names it,
/// and — for a set child — the chain root to trace it from.
#[derive(Debug)]
enum FutureAt<'c> {
    Held(&'c census::HeldFuture),
    Child {
        set: &'c census::FutureSet,
        child: &'c census::SetChild,
        root: census::FutureRoot,
    },
}

/// Resolve `addr` to the census future it names: a held future's
/// address, a set child's node address, or any pointer into either —
/// an interior pointer picks the tightest containing future, since a
/// by-value awaitee sits inside the future holding it. A miss says
/// what the address *is* whenever that can be said: a set itself, a
/// completed child, a task's own allocation.
fn future_at<'c>(
    view: &BundleView<'_>,
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &'c census::FutureCensus,
    addr: u64,
) -> Result<FutureAt<'c>> {
    if let Some(h) = census.held.iter().find(|h| h.addr == addr) {
        return Ok(FutureAt::Held(h));
    }
    if let Some((set_index, child_index, _)) = census.locate(addr) {
        let set = &census.sets[set_index];
        let child = &set.children[child_index];
        let Some(root) = child.root else {
            anyhow::bail!(
                "the child at {:#x} of the {} at {:#x} has completed; \
                 there is no future left to trace",
                child.node,
                set.ty,
                set.addr
            );
        };
        return Ok(FutureAt::Child { set, child, root });
    }
    if let Some(set) = census.sets.iter().find(|s| s.addr == addr) {
        anyhow::bail!(
            "{addr:#x} is the {} polled by {}, not one future; \
             trace one of its {} child node(s) (`tasks --futures` lists them)",
            set.ty,
            task_label(list, set.owner),
            set.children.len()
        );
    }
    let containing = census
        .held
        .iter()
        .filter_map(|h| {
            let size = view.ty(h.ty)?.size();
            (h.addr <= addr && addr < h.addr + size).then_some((size, h))
        })
        .min_by_key(|&(size, _)| size);
    if let Some((_, h)) = containing {
        return Ok(FutureAt::Held(h));
    }
    if let Some((index, offset)) = extents.locate(addr) {
        anyhow::bail!(
            "no census future contains {addr:#x}; it is in {} at offset {offset:#x} \
             — `trace <id>` prints a task's own chain",
            task_label(list, index)
        );
    }
    anyhow::bail!(
        "nothing the census found contains {addr:#x}; \
         `tasks --futures` lists what can be traced"
    )
}

/// Render an await chain the way `trace` prints one. Values shown
/// under --verbose may hold raw pointers into task allocations
/// (wakers, JoinHandles); name those with the task id so the reader
/// knows what to trace next. The traced task itself is named like any
/// other: a wake-queue entry resolving back to it is a finding (the
/// futurelock shape), not noise. A pointer into a sub-executor's child
/// node instead names the task that polls the set — the task a wake
/// there would ultimately run.
fn print_trace_chain<'b>(
    session: &Session<'b>,
    chain: &bundle::AwaitChain<'b>,
    verbose: bool,
    depth: usize,
    ugly: bool,
    elide: &reify::ElideOverride,
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = &session.tasks;
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
    let annotate = annotate.as_ref().map(|a| a as &reify::AddrAnnotator<'_>);
    print_await_chain(
        &session.ctx,
        list,
        chain,
        verbose,
        depth,
        ugly,
        elide,
        annotate,
        out,
    )
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
fn print_await_chain<'b, T: proc::Target>(
    ctx: &bundle::Context<'b, T>,
    list: &bundle::TaskList,
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
                Some(state) => state.payload,
                None => frame.future,
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
                        let v = reify::Value::new(m.ty(), payload.addr + m.offset(), bytes).peel();
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
    match ctx.wait_target(chain, list) {
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
/// (see [`reify::DisplayValue::line_prefix`]), so this function
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
fn discover_workers(
    lwps: &[proc::LwpInfo],
    ctx: &bundle::Context<'_, Proc>,
) -> Result<Vec<bundle::Worker>> {
    let workers = ctx.find_workers(lwps)?;
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
#[cfg_attr(not(feature = "snapshot"), allow(dead_code))]
fn warm_frame_values<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    chain: &bundle::AwaitChain<'_>,
) {
    const WARM_DEPTH: usize = 200;
    for frame in &chain.frames {
        let payload = match &frame.state {
            Some(state) => state.payload,
            None => frame.future,
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
            let v = reify::Value::new(m.ty(), payload.addr + m.offset(), bytes);
            let _ = format!("{:#}", v.display_from_target(ctx.proc, WARM_DEPTH));
            let _ = format!("{:#}", v.peel().display_from_target(ctx.proc, WARM_DEPTH));
        }
    }
}

/// Drive the full bundle-backed analysis with a recording Target in
/// place, then persist what it read. Every task's stage
/// and await chain is walked so the snapshot can answer the offline
/// tests' whole question set; walk problems are warnings, not errors,
/// since a partially-traceable target is still worth capturing.
#[cfg_attr(not(feature = "snapshot"), allow(dead_code))]
fn exec_snapshot(session: &Session<'_>, output: &Path, out: &mut dyn io::Write) -> Result<()> {
    // The recording wrapper has to sit under its own context: what makes
    // a snapshot is the reads going through `Recorder`, so the session's
    // context — which reads the target directly — cannot serve here. The
    // whole analysis is therefore driven a second time.
    let proc = session.proc;
    let recorder = Recorder::new(proc);
    let ctx =
        bundle::Context::with_policy(&recorder, BundleView::new(session.bundle), session.policy)?;
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
    let list = ctx.enumerate_tasks(shared)?;
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
                if let Some(Err(e)) = ctx.wait_target(&chain, &list) {
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

/// The census as a tree, which is what a listing shows: two flat lists
/// naming their parent leave the reader matching addresses across them.
struct CensusTree<'a> {
    /// Each task's finds that named no parent, keyed by its index in
    /// the task list.
    roots: BTreeMap<usize, Vec<Entry<'a>>>,
    /// Everything else, keyed by the find it was reached through: a set
    /// can sit in a held future's frames, a future be held in a set
    /// child's.
    nested: HashMap<census::Via, Vec<Entry<'a>>>,
    /// What each task owns, tallied.
    counts: BTreeMap<usize, Counts>,
}

/// Rebuild that tree from what the census found, which is all it reads:
/// the census is a walk of a target, but rendering it is not. It takes
/// the find lists rather than the census itself so a test can lay out a
/// shape no fixture happens to hold.
fn census_tree<'a>(
    census_held: &'a [census::HeldFuture],
    census_sets: &'a [census::FutureSet],
    census_join_sets: &'a [census::JoinSet],
) -> CensusTree<'a> {
    let mut roots: BTreeMap<usize, Vec<Entry<'a>>> = BTreeMap::new();
    let mut nested: HashMap<census::Via, Vec<Entry<'a>>> = HashMap::new();
    for entry in census_entries(census_held, census_sets, census_join_sets) {
        match entry.via() {
            Some(via) => nested.entry(via).or_default().push(entry),
            None => roots.entry(entry.owner()).or_default().push(entry),
        }
    }
    CensusTree {
        roots,
        nested,
        counts: census_counts(census_held, census_sets, census_join_sets),
    }
}

/// Every census find as an [`Entry`]. Held first, then sets, then join
/// sets, so each level lists what a frame holds ahead of what it drives.
fn census_entries<'a>(
    census_held: &'a [census::HeldFuture],
    census_sets: &'a [census::FutureSet],
    census_join_sets: &'a [census::JoinSet],
) -> impl Iterator<Item = Entry<'a>> {
    let held = census_held
        .iter()
        .enumerate()
        .map(|(i, h)| Entry::Held(i, h));
    let sets = census_sets
        .iter()
        .enumerate()
        .map(|(i, s)| Entry::Set(i, s));
    let join_sets = census_join_sets.iter().map(Entry::JoinSet);
    held.chain(sets).chain(join_sets)
}

/// What the census found for each task, keyed by its index in the task
/// list. Every count a block carries is this, so no two of them can
/// disagree.
///
/// Only a find at the top of a listing is counted — one the census
/// reached through another is inside it, and the listing says so by
/// indenting it. Counting those too made a task driving a set of 3075
/// children, each holding the future it was spawned with, say it held
/// 3075 futures *and* drove sets of 3075: two rows for one population,
/// which is what the caller asked apart in the first place.
fn census_counts(
    census_held: &[census::HeldFuture],
    census_sets: &[census::FutureSet],
    census_join_sets: &[census::JoinSet],
) -> BTreeMap<usize, Counts> {
    let mut counts: BTreeMap<usize, Counts> = BTreeMap::new();
    for entry in
        census_entries(census_held, census_sets, census_join_sets).filter(|e| e.via().is_none())
    {
        counts.entry(entry.owner()).or_default().add(entry);
    }
    counts
}

/// One find in the nested listing, with the census index that anything
/// found inside it names as its parent. A join set carries no index:
/// its members are tasks, scanned as the tasks they are, so nothing is
/// ever reached *through* one.
#[derive(Clone, Copy)]
enum Entry<'a> {
    Held(usize, &'a census::HeldFuture),
    Set(usize, &'a census::FutureSet),
    JoinSet(&'a census::JoinSet),
}

impl Entry<'_> {
    fn owner(&self) -> usize {
        match self {
            Entry::Held(_, h) => h.owner,
            Entry::Set(_, s) => s.owner,
            Entry::JoinSet(j) => j.owner,
        }
    }

    fn via(&self) -> Option<census::Via> {
        match self {
            Entry::Held(_, h) => h.via,
            Entry::Set(_, s) => s.via,
            Entry::JoinSet(j) => j.via,
        }
    }

    /// Which of a block's two listings this find belongs under: the
    /// futures the task holds itself, or the sets it drives, of either
    /// kind. Only a root is sorted this way — a find inside another is
    /// printed under what holds it, wherever that is.
    fn is_set(&self) -> bool {
        matches!(self, Entry::Set(_, _) | Entry::JoinSet(_))
    }
}

/// A count and the noun it counts, pluralized.
fn counted(n: usize, noun: &str) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {noun}{plural}")
}

/// One task's share of the census.
#[derive(Clone, Copy, Default)]
struct Counts {
    /// Futures held in one of the task's own frames.
    held: usize,
    /// Sets of futures it drives from one of those frames. A set is a
    /// container rather than a future outstanding in its own right, so
    /// it is counted apart from both.
    sets: usize,
    /// Children of those sets still holding a future: an empty slot is a
    /// completed child the set has not reaped, not a future outstanding.
    children_live: usize,
    /// Join sets it drives from those frames, and the tasks they hold.
    /// A joined task is not a future off anyone's await chain — it is a
    /// task with a chain of its own, and a block in this same listing —
    /// so it is counted here and nowhere else.
    join_sets: usize,
    joined: usize,
}

impl Counts {
    fn add(&mut self, entry: Entry<'_>) {
        match entry {
            Entry::Held(_, _) => self.held += 1,
            Entry::Set(_, s) => {
                self.sets += 1;
                self.children_live += s.children.iter().filter(|c| c.future.is_some()).count();
            }
            Entry::JoinSet(j) => {
                self.join_sets += 1;
                self.joined += j.children.len();
            }
        }
    }

    /// The `Join sets` row's value: how many sets the task drives, of
    /// either kind, and what they hold between them.
    ///
    /// The two populations are named apart because they are not the
    /// same thing — a JoinSet holds tasks and a FuturesUnordered holds
    /// futures — but only where a set of that kind is listed. `2 (0
    /// tasks and 7126 futures)` over two sets of futures reads as a
    /// zero about the sets themselves, when it is really about the kind
    /// of set that is not there.
    ///
    /// Neither number is a second count of `Held futures`: what a set
    /// holds is inside it.
    fn sets_summary(&self) -> String {
        let sets = self.sets + self.join_sets;
        if sets == 0 {
            return "0".to_string();
        }
        let mut holds = Vec::new();
        if self.join_sets > 0 {
            holds.push(counted(self.joined, "task"));
        }
        if self.sets > 0 {
            holds.push(counted(self.children_live, "future"));
        }
        format!("{sets} ({})", holds.join(" and "))
    }
}

/// What printing a find needs beyond the find itself: the tree it sits
/// in, and the task listing a joined task is named from — a join set
/// holds tasks the listing already carries, so its rows say what those
/// blocks say rather than something of their own.
struct Listing<'a> {
    nested: &'a HashMap<census::Via, Vec<Entry<'a>>>,
    list: &'a bundle::TaskList,
    polling: &'a HashMap<u64, u32>,
}

/// Print one find and, indented under it, everything the census reached
/// by scanning its frames.
///
/// A set's row opens with a `-`, and everything it holds is indented one
/// four-space step under it — the same step the block's own rows take
/// from their heading. A listing running to thousands of children is
/// otherwise a wall with nothing marking where one set ends and the next
/// begins.
///
/// `mark_held` prefixes a held future's row with `held`. A row under
/// `Held futures` needs no such word — the heading is it — but one
/// found in a set child's frames sits under a listing of children, so
/// there it says what it is. Descending into a child turns the mark on;
/// nothing turns it off.
fn print_future_entry<'a>(
    entry: Entry<'a>,
    listing: &Listing<'a>,
    indent: usize,
    mark_held: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let pad = " ".repeat(indent);
    let nested = listing.nested;
    match entry {
        Entry::Held(index, h) => {
            let state = h
                .state
                .as_ref()
                .map(|s| format!("  {s}"))
                .unwrap_or_default();
            let mark = if mark_held { "held " } else { "" };
            writeln!(
                out,
                "{pad}{mark}(frame {}, `{}`): {:#x}  {}{state}",
                h.frame, h.local, h.addr, h.future
            )?;
            if let Some(waiting) = &h.waiting_on {
                writeln!(out, "{pad}  waiting on {waiting}")?;
            }
            for inner in nested.get(&census::Via::Held(index)).into_iter().flatten() {
                print_future_entry(*inner, listing, indent + 4, mark_held, out)?;
            }
        }
        Entry::Set(index, set) => {
            let live = set.children.iter().filter(|c| c.future.is_some()).count();
            let plural = if live == 1 { "" } else { "ren" };
            let reaped = match set.children.len() - live {
                0 => String::new(),
                n => format!(", {n} completed and not yet reaped"),
            };
            writeln!(
                out,
                "{pad}- {} at {:#x} (frame {}, `{}`): {live} child{plural} in flight{reaped}",
                set.ty, set.addr, set.frame, set.local
            )?;
            for (child_index, child) in set.children.iter().enumerate() {
                let Some(future) = &child.future else {
                    writeln!(
                        out,
                        "{pad}    {:#x}  <completed, not yet reaped>",
                        child.node
                    )?;
                    continue;
                };
                let state = child
                    .state
                    .as_ref()
                    .map(|s| format!("  {s}"))
                    .unwrap_or_default();
                writeln!(out, "{pad}    {:#x}  {future}{state}", child.node)?;
                if let Some(waiting) = &child.waiting_on {
                    writeln!(out, "{pad}      waiting on {waiting}")?;
                }
                let via = census::Via::SetChild {
                    set: index,
                    child: child_index,
                };
                for inner in nested.get(&via).into_iter().flatten() {
                    print_future_entry(*inner, listing, indent + 8, true, out)?;
                }
            }
        }
        Entry::JoinSet(set) => {
            let held = set.children.len();
            let plural = if held == 1 { "" } else { "s" };
            // The set keeps its own count; a walk that reached fewer
            // entries than that says so here, since the error saying
            // why is on stderr and this is the row it belongs to.
            let short = match set.length {
                len if len != held as u64 => format!(" (the set records {len})"),
                _ => String::new(),
            };
            writeln!(
                out,
                "{pad}- {} at {:#x} (frame {}, `{}`): {held} task{plural}{short}",
                set.ty, set.addr, set.frame, set.local
            )?;
            for child in &set.children {
                writeln!(out, "{pad}    {}", joined_task(child, listing))?;
            }
        }
    }
    Ok(())
}

/// A task's lifecycle as a listing spells it: the worker holding it
/// where the runtime says one is, since `running` alone leaves a reader
/// asking where.
fn task_state(task: &bundle::Task, polling: &HashMap<u64, u32>) -> String {
    match (task.state.lifecycle(), task.task_id) {
        (Lifecycle::Running, Some(id)) if polling.contains_key(&id) => {
            format!("running (lwp {})", polling[&id])
        }
        (lifecycle, _) => lifecycle.to_string(),
    }
}

/// One joined task's row: how the task listing names it, or — for a
/// task no listing can show — why it is not there to name.
fn joined_task(child: &census::JoinedTask, listing: &Listing<'_>) -> String {
    let who = match child.id {
        Some(id) => format!("task {id}"),
        None => format!("the task at {:#x}", child.task),
    };
    if let Some(task) = listing.list.tasks.iter().find(|t| t.addr.0 == child.task) {
        let state = task_state(task, listing.polling);
        return format!("{who}  {}  {state}", future_name(&task.future));
    }
    // Complete means off the runtime's owned list, alive only through
    // the set's entry until its output is taken; alive but unlisted
    // means it runs where this session does not enumerate tasks.
    if child.state.lifecycle() == Lifecycle::Complete {
        format!("{who}  <complete, awaiting join>")
    } else {
        format!(
            "{who}  <{}, not in the scheduler's owned tasks>",
            child.state.lifecycle()
        )
    }
}

/// The display name of a task's future, however well the symbol join
/// resolved it.
pub fn future_name(future: &bundle::FutureInfo) -> String {
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

fn exec_whatis(session: &Session<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    report_whatis(
        &session.ctx.view,
        &session.tasks,
        session.extents(),
        session.census(),
        addr,
        out,
    )
}

/// The `whatis` answer, apart from the session so the offline fixture
/// tests can drive it.
///
/// An address belongs to whatever contains it, and those things nest:
/// a held future lives in a frame of its task's allocation, a set in a
/// frame of whatever drives it, a set child in a heap node of its own.
/// So this reports every claim rather than the first one it finds, in
/// containment order — the task's allocation, then a set child's node,
/// then the held futures from widest to narrowest, then a set — which
/// makes reading down the report reading inward.
fn report_whatis(
    view: &BundleView<'_>,
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut blocks = 0;

    if let Some((index, offset)) = extents.locate(addr) {
        let task = &list.tasks[index];
        let id = match task.task_id {
            Some(id) => id.to_string(),
            None => format!("{:?}", task.addr),
        };
        separate(&mut blocks, out)?;
        writeln!(out, "Task {id}: {}", future_name(&task.future))?;
        writeln!(
            out,
            "    At: offset {offset:#x} in the task's allocation (header {:?})",
            task.addr
        )?;
        writeln!(out, "    State: {}", task.state.lifecycle())?;
        if let Some(loc) = &task.spawn_location {
            writeln!(out, "    Spawned at: {loc}")?;
        }
    }

    // A set child's node is its own heap allocation, outside every
    // task's — but the task that polls the set is what a wake there
    // ultimately runs, so the block names it.
    if let Some((set_index, child_index, offset)) = census.locate(addr) {
        let set = &census.sets[set_index];
        let child = &set.children[child_index];
        separate(&mut blocks, out)?;
        let future = child
            .future
            .as_deref()
            .unwrap_or("<completed, not yet reaped>");
        writeln!(out, "Future {:#x}: {future}", child.node)?;
        writeln!(
            out,
            "    At: offset {offset:#x} in a FuturesUnordered child node"
        )?;
        if let Some(state) = &child.state {
            writeln!(out, "    State: {state}")?;
        }
        if let Some(waiting) = &child.waiting_on {
            writeln!(out, "    Waiting on: {waiting}")?;
        }
        writeln!(
            out,
            "    Child of: {} at {:#x} (frame {}, `{}`{})",
            set.ty,
            set.addr,
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
        writeln!(
            out,
            "    Polled by: {} — {}",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future)
        )?;
    }

    // Widest first: a future awaited by value sits inside the one
    // awaiting it, so an interior address is claimed by each of them
    // and the narrowest is the future the address is really in.
    let mut held: Vec<(u64, &census::HeldFuture)> = census
        .held
        .iter()
        .filter_map(|h| {
            // A size the bundle does not carry leaves the future's own
            // address, which is what a reader pastes in anyway.
            let size = view.ty(h.ty).map_or(0, |ty| ty.size());
            let extent = h.addr..h.addr.saturating_add(size);
            (h.addr == addr || extent.contains(&addr)).then_some((size, h))
        })
        .collect();
    held.sort_by_key(|&(size, h)| (std::cmp::Reverse(size), h.addr));
    for (_, h) in held {
        separate(&mut blocks, out)?;
        writeln!(out, "Future {:#x}: {}", h.addr, h.future)?;
        writeln!(out, "    At: offset {:#x} in the future", addr - h.addr)?;
        if let Some(state) = &h.state {
            writeln!(out, "    State: {state}")?;
        }
        if let Some(waiting) = &h.waiting_on {
            writeln!(out, "    Waiting on: {waiting}")?;
        }
        writeln!(
            out,
            "    Held by: {} — {} (frame {}, `{}`{})",
            task_label(list, h.owner),
            future_name(&list.tasks[h.owner].future),
            h.frame,
            h.local,
            via_suffix(census, h.via)
        )?;
    }

    // A set is claimed by its own address alone: the census records
    // where one starts but not how long it is, so an address inside one
    // is reported as whatever frame holds it instead.
    for set in census.sets.iter().filter(|s| s.addr == addr) {
        separate(&mut blocks, out)?;
        let live = set.children.iter().filter(|c| c.future.is_some()).count();
        let reaped = match set.children.len() - live {
            0 => String::new(),
            n => format!(", {n} completed and not yet reaped"),
        };
        writeln!(out, "Set {addr:#x}: {}", set.ty)?;
        writeln!(out, "    Children: {live} in flight{reaped}")?;
        writeln!(
            out,
            "    Driven by: {} — {} (frame {}, `{}`{})",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future),
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
    }

    if blocks == 0 {
        writeln!(
            out,
            "no task's allocation and no future the census found contains {addr:#x}"
        )?;
    }
    Ok(())
}

/// Open a block, with a blank line between it and the one before.
fn separate(blocks: &mut usize, out: &mut dyn io::Write) -> Result<()> {
    if *blocks > 0 {
        writeln!(out)?;
    }
    *blocks += 1;
    Ok(())
}

/// How the census reached a find, for the line that says where it
/// lives: empty when it was found in a task's own frames, and naming
/// the future or set child whose frames it was found in otherwise.
fn via_suffix(census: &census::FutureCensus, via: Option<census::Via>) -> String {
    via.map(|v| format!(", via {}", census.describe(v)))
        .unwrap_or_default()
}

fn exec_tasks(
    session: &Session<'_>,
    futures: bool,
    tasks: &[u64],
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = &session.tasks;

    // Which LWP is polling which task right now.
    let polling: HashMap<u64, u32> = session
        .workers
        .iter()
        .filter_map(|w| w.current_task_id.map(|id| (id, w.tid)))
        .collect();

    // What each task has in flight beside its own await chain: the
    // count every block carries, and — under `--futures` — the finds
    // listed beneath it.
    let census = session.census();
    if futures {
        for err in &census.errors {
            writeln!(io::stderr(), "warning: {err:#}")?;
        }
        // A walk that failed says so above; one that hit a limit says so
        // here, because it looks like completeness otherwise. The listing
        // is a lower bound either way (`help tasks`), but this is the part
        // of it that varies by target rather than being inherent.
        if census.capped > 0 {
            writeln!(
                io::stderr(),
                "warning: the scan stopped at a depth limit in {} place(s); \
                 anything held deeper is not listed",
                census.capped
            )?;
        }
    }

    print_tasks(
        list,
        &polling,
        &census.held,
        &census.sets,
        &census.join_sets,
        futures,
        tasks,
        out,
    )?;

    for err in &list.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }

    Ok(())
}

/// Print the task listing: a block per task, and — under `futures` —
/// the census's finds for it, listed beneath the count each belongs
/// under.
/// `tasks` narrows the listing to the named tasks, and is empty for the
/// whole list.
///
/// It takes what it prints rather than a session so the offline tests
/// can drive it, the census as its flat lists so a test can lay out a
/// shape no fixture happens to hold.
#[allow(clippy::too_many_arguments)]
fn print_tasks(
    list: &bundle::TaskList,
    polling: &HashMap<u64, u32>,
    census_held: &[census::HeldFuture],
    census_sets: &[census::FutureSet],
    census_join_sets: &[census::JoinSet],
    futures: bool,
    tasks: &[u64],
    out: &mut dyn io::Write,
) -> Result<()> {
    // Resolve every selected id up front, so an id the runtime does not
    // own says so rather than printing a listing short of a block. A set
    // rather than the ids as given: repeating one asks for it once, and
    // the blocks come out in the listing's own order either way.
    let mut only = BTreeSet::new();
    for &id in tasks {
        let Some(index) = list.tasks.iter().position(|t| t.task_id == Some(id)) else {
            let ids: Vec<u64> = list.tasks.iter().filter_map(|t| t.task_id).collect();
            anyhow::bail!(
                "the runtime owns no task with id {id}; it owns {} task(s): {ids:?}",
                list.tasks.len()
            );
        };
        only.insert(index);
    }
    let selected = |index: usize| tasks.is_empty() || only.contains(&index);
    let census = census_tree(census_held, census_sets, census_join_sets);
    let listing = Listing {
        nested: &census.nested,
        list,
        polling,
    };

    // A block per task rather than a row: a future type is long enough
    // that column-aligning it pushes the two source locations off the
    // right of any terminal.
    let mut shown = 0;
    for (index, task) in list.tasks.iter().enumerate() {
        if !selected(index) {
            continue;
        }
        shown += 1;
        let id = match task.task_id {
            Some(id) => id.to_string(),
            None => format!("{:?}", task.addr),
        };
        writeln!(out, "Task {id}: {}", future_name(&task.future))?;
        writeln!(out, "    State: {}", task_state(task, polling))?;
        // Every block carries every row, so the two source locations sit
        // at the same place in each and a missing one reads as a gap in
        // what the target recorded rather than as a shorter block.
        let spawned = match &task.spawn_location {
            Some(loc) => loc.to_string(),
            None => "-".to_string(),
        };
        writeln!(out, "    Spawned at: {spawned}")?;
        let defined = match &task.future {
            bundle::FutureInfo::Known(known) => match &known.decl {
                Some((file, line)) => format!("{file}:{line}"),
                None => "-".to_string(),
            },
            _ => "-".to_string(),
        };
        writeln!(out, "    Defined at: {defined}")?;
        // What the task has off its spine, in two rows rather than one:
        // the futures held in its own frames, and the sets it drives
        // from them. A set is a container, so counting it among the
        // futures made a row saying `Futures: 2` list three finds;
        // keeping the two apart lets each number say what the listing
        // under it shows. The sets are one row whichever kind they are —
        // a listing of what this task drives is one thing to read — with
        // the tasks and the futures they hold counted apart, since those
        // are not the same population. Last in the block, since what
        // `--futures` lists under them is as long as the census found it
        // to be.
        let count = census.counts.get(&index).copied().unwrap_or_default();
        let roots = || census.roots.get(&index).into_iter().flatten();
        for (label, value, sets) in [
            ("Held futures", count.held.to_string(), false),
            ("Join sets", count.sets_summary(), true),
        ] {
            writeln!(out, "    {label}: {value}")?;
            if futures {
                for entry in roots().filter(|e| e.is_set() == sets) {
                    print_future_entry(*entry, &listing, 8, false, out)?;
                }
            }
        }
        writeln!(out)?;
    }
    // How many tasks the runtime owns is the listing's own answer; a
    // listing narrowed to ids the caller named already knows how many
    // it asked for, so the count would only restate the command line.
    if tasks.is_empty() {
        let plural = if shown == 1 { "" } else { "s" };
        writeln!(out, "{shown} task{plural}")?;
    }
    Ok(())
}

/// Gather what a census counts and print it.
///
/// The two analyses it rests on — what every task waits on, and the
/// futures off those tasks' chains — are the session's cached ones, so
/// a census pays for both walks and every later command that wants
/// either pays for neither.
fn exec_census(session: &Session<'_>, top: usize, out: &mut dyn io::Write) -> Result<()> {
    let analysis = session.analysis();
    let census = session.census();
    for err in analysis.errors.iter().chain(&census.errors) {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }
    // As `tasks --futures`: a walk that hit a depth limit looks like
    // completeness in a count, so it says so.
    if census.capped > 0 {
        writeln!(
            io::stderr(),
            "warning: the scan stopped at a depth limit in {} place(s); \
             anything held deeper is not counted",
            census.capped
        )?;
    }

    // The two reads a census makes of its own: which worker each thread
    // is running, and what every worker's parker says. Neither is worth
    // failing the command over — a census without them still counts
    // everything else — so a failure costs its own line and warns.
    let mut runtime = Vec::new();
    for worker in &session.workers {
        let index = match session.ctx.worker_context(worker) {
            Ok(Some(ctx)) => match session.ctx.worker_index(ctx) {
                Ok(index) => Some(index),
                Err(e) => {
                    writeln!(
                        io::stderr(),
                        "warning: cannot read which worker lwp {} runs: {e:#}",
                        worker.tid
                    )?;
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                writeln!(
                    io::stderr(),
                    "warning: cannot read the scheduler context of lwp {}: {e:#}",
                    worker.tid
                )?;
                None
            }
        };
        runtime.push(summary::Thread {
            tid: worker.tid,
            worker: index,
            polling: worker.current_task_id.filter(|id| {
                session
                    .tasks
                    .tasks
                    .iter()
                    .any(|t| t.task_id == Some(*id) && t.state.lifecycle() == Lifecycle::Running)
            }),
        });
    }
    let parks = optional(session.ctx.park_states(session.handle), "park state")?;
    let pool = optional(session.ctx.blocking_pool(session.handle), "blocking pool")?;

    let facts = summary::Facts {
        lwps: session.lwps,
        runtime,
        parks,
        pool,
        tasks: &session.tasks,
        waits: &analysis.waits,
        held: &census.held,
        sets: &census.sets,
    };
    summary::print(&facts, top, out)
}

/// A census section that is worth having and not worth failing over:
/// the value if it read, and a warning naming what is missing from the
/// listing if it did not.
fn optional<T>(read: Result<T>, what: &str) -> Result<Option<T>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            writeln!(io::stderr(), "warning: cannot read the {what}: {e:#}")?;
            Ok(None)
        }
    }
}

fn exec_graph(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let analysis = session.analysis();
    for err in &analysis.errors {
        writeln!(io::stderr(), "warning: {err:#}")?;
    }
    let census = session.census();
    print_graph(
        &session.tasks,
        analysis,
        &census.held,
        &census.join_sets,
        out,
    )?;

    // A diagnosis is printed when there is one to print, and nothing is
    // said when there is not: the analysis reads only the edges it
    // knows how to read, so an empty result is "none found here",
    // which is not the same as the "no futurelock detected" it used to
    // claim.
    for fl in &analysis.futurelocks {
        writeln!(out)?;
        print_futurelock(fl, out)?;
    }
    Ok(())
}

/// Why one task's row hangs under another's.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EdgeKind {
    /// The task is awaiting it right now — the row's own `WAITING ON`
    /// says how, so the edge needs no mark of its own.
    Waiting,
    /// It is a member of a `JoinSet` the task holds. The task will join
    /// it, though its own wait says whether it is doing so yet.
    JoinSet,
    /// The task holds a `JoinHandle` to it in one of its frames, off
    /// its await chain: it can join or abort it, and may be doing
    /// neither.
    Handle,
    // Both marks say "above" rather than "its": the mark is printed on
    // the row of the task being waited *for*, so a possessive there
    // reads as that task's own set or handle — the opposite of what it
    // means, and in opposite directions for the two of them.
}

impl EdgeKind {
    fn mark(self) -> &'static str {
        match self {
            Self::Waiting => "",
            Self::JoinSet => " [in the JoinSet above]",
            Self::Handle => " [its handle held above]",
        }
    }
}

/// One task's row, and why it hangs where it does.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    to: usize,
    kind: EdgeKind,
}

/// Which tasks each task is waiting for, by index into the task list.
///
/// Three things name a task. Two are the task's own wait: a
/// `JoinHandle` names the task being joined outright, and a contended
/// semaphore names whoever the futurelock analysis found holding an
/// acquire on it — the only case where a holder is knowable at all,
/// since a tokio `Mutex` records no owner. A timer names nobody, and
/// neither does a leaf hansei does not decode.
///
/// The third is what the census found in the task's frames: the members
/// of a `JoinSet` it drives, and the tasks it holds a `JoinHandle` to
/// without awaiting. Those are the edges a real target mostly has —
/// `join_next` on a set is not a `JoinHandle` await, so nothing about
/// the task's own wait mentions the tasks it is there to collect — and
/// leaving them out made the graph of a runtime running dozens of
/// parallel task sets look like a runtime with no structure at all.
fn wait_edges(
    list: &bundle::TaskList,
    analysis: &graph::Analysis,
    held: &[census::HeldFuture],
    join_sets: &[census::JoinSet],
) -> Vec<Vec<Edge>> {
    let index: HashMap<u64, usize> = list
        .tasks
        .iter()
        .enumerate()
        .map(|(i, t)| (t.addr.0, i))
        .collect();
    let mut edges: Vec<Vec<Edge>> = vec![Vec::new(); list.tasks.len()];
    let mut add = |from: usize, addr: u64, kind: EdgeKind| {
        // A task the runtime no longer owns has no row to point at; the
        // wait's own text says as much where it came from a wait.
        if let Some(&to) = index.get(&addr) {
            edges[from].push(Edge { to, kind });
        }
    };
    for (from, wait) in analysis.waits.iter().enumerate() {
        match &wait.target {
            Some(bundle::WaitTarget::Task { addr, .. }) => add(from, *addr, EdgeKind::Waiting),
            Some(bundle::WaitTarget::Semaphore { addr, .. }) => {
                for fl in analysis
                    .futurelocks
                    .iter()
                    .filter(|fl| fl.acquire.semaphore == *addr)
                {
                    add(from, fl.holder.addr.0, EdgeKind::Waiting);
                }
            }
            _ => {}
        }
    }
    for set in join_sets {
        for child in &set.children {
            add(set.owner, child.task, EdgeKind::JoinSet);
        }
    }
    for future in held {
        if let Some(bundle::WaitKind::Task { addr }) = future.wait {
            add(future.owner, addr, EdgeKind::Handle);
        }
    }
    for from in &mut edges {
        // By task, then by kind, so a task named twice keeps the most
        // direct claim: an await it is actually in, over a set it is
        // merely a member of, over a handle someone merely holds.
        from.sort_unstable();
        from.dedup_by_key(|edge| edge.to);
    }
    edges
}

/// Print the wait graph: one row per task, nested under whatever is
/// waiting for it.
///
/// Reading down a tree is reading further into what blocks its root: a
/// task's own row says what it waits on, and its children are the rows
/// of the tasks that answer for it. Every task in the graph appears
/// exactly once, under the task waiting for it where one is and at the
/// left margin otherwise. A task in no graph at all — naming none and
/// named by none — is left out: it has a row in `tasks` and a wait in
/// `census`, and on a target where thirty tasks are related and twenty
/// thousand are not, printing the twenty thousand is what makes the
/// thirty impossible to find.
///
/// It takes what it prints rather than a session so the offline tests
/// can drive it.
fn print_graph(
    list: &bundle::TaskList,
    analysis: &graph::Analysis,
    held: &[census::HeldFuture],
    join_sets: &[census::JoinSet],
    out: &mut dyn io::Write,
) -> Result<()> {
    let edges = wait_edges(list, analysis, held, join_sets);
    let mut waited_for = vec![false; list.tasks.len()];
    for edge in edges.iter().flatten() {
        waited_for[edge.to] = true;
    }
    // A task that names none and is named by none is not part of any
    // graph. It has a row in `tasks` and a wait in `census`; here it
    // would be one line of a page of them, and on a target where a few
    // dozen tasks are related and twenty thousand are not, those lines
    // are the whole reason the related ones cannot be found.
    let alone = |i: usize| edges[i].is_empty() && !waited_for[i];

    let mut rows = vec![[
        "TASK".to_string(),
        "STATE".to_string(),
        "WAITING ON".to_string(),
    ]];
    let mut walk = GraphWalk {
        list,
        analysis,
        edges: &edges,
        printed: vec![false; list.tasks.len()],
        path: Vec::new(),
        rows: &mut rows,
    };
    // The tasks nothing waits for are the tops of the trees. What is
    // left over after them is in a cycle — a task joining itself, or two
    // waiting on each other — which has no such top; those are walked
    // from wherever they are reached, and the row that closes the loop
    // says so.
    for (root, waited) in waited_for.iter().enumerate() {
        if !waited && !alone(root) {
            walk.visit(root, "", None, EdgeKind::Waiting);
        }
    }
    for root in 0..list.tasks.len() {
        if !walk.printed[root] && !alone(root) {
            walk.visit(root, "", None, EdgeKind::Waiting);
        }
    }

    // Counted in characters rather than bytes: a nested row's branch is
    // drawn with box-drawing characters, which are three bytes each,
    // and padding a column to a byte count would indent every tree
    // deeper than the one beside it.
    let mut widths = [0usize; 2];
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    // A heading over nothing reads as a graph that failed to print
    // rather than a target with no edges to draw.
    if rows.len() > 1 {
        for row in &rows {
            let [id, state, target] = row;
            writeln!(
                out,
                "{id:<w0$}  {state:<w1$}  {target}",
                w0 = widths[0],
                w1 = widths[1],
            )?;
        }
    }
    Ok(())
}

/// The walk behind [`print_graph`], carrying what one recursive step
/// needs.
struct GraphWalk<'a> {
    list: &'a bundle::TaskList,
    analysis: &'a graph::Analysis,
    edges: &'a [Vec<Edge>],
    /// Every task already given a row, so one reached twice — two tasks
    /// blocked on the semaphore one acquire holds — is spelled out once
    /// and referred back to after that.
    printed: Vec<bool>,
    /// The tasks between the root and here, for spotting a wait that
    /// closes back on one of them.
    path: Vec<usize>,
    rows: &'a mut Vec<[String; 3]>,
}

impl GraphWalk<'_> {
    /// Give `task` a row and walk what it waits for. `last` says
    /// whether it is the final child of the task above it, which is
    /// what decides its branch glyph and whether the rows under it
    /// carry a rule down to their own; `None` is a task at the margin,
    /// which has neither.
    fn visit(&mut self, task: usize, prefix: &str, last: Option<bool>, kind: EdgeKind) {
        let glyph = match last {
            None => "",
            Some(true) => "└─ ",
            Some(false) => "├─ ",
        };
        let name = format!("{prefix}{glyph}{}{}", task_id(self.list, task), kind.mark());
        let state = self.list.tasks[task].state.lifecycle().to_string();

        // A wait that closes back on the path is a cycle: the task is
        // blocked on something that is blocked on it. A task joining
        // itself is the one-node case of it.
        if self.path.contains(&task) {
            self.rows
                .push([format!("{name} ← cycle"), state, String::new()]);
            return;
        }
        // Reached a second time by another route — two tasks blocked on
        // the semaphore one acquire holds. Its own subtree is wherever
        // it was first printed; repeating it would double every task
        // under it.
        if self.printed[task] {
            self.rows
                .push([format!("{name} (above)"), state, String::new()]);
            return;
        }

        // The primitive where hansei decodes one, and the type the
        // chain bottoms out in otherwise — which is most rows on a real
        // target. A `-` is for a task with no chain to have reached a
        // leaf at all: one mid-poll, finished, or whose walk stopped
        // short.
        let wait = &self.analysis.waits[task];
        let target = match (&wait.target, &wait.leaf) {
            (Some(target), _) => target.to_string(),
            (None, Some(leaf)) => leaf.clone(),
            (None, None) => "-".to_string(),
        };
        self.rows.push([name, state, target]);
        self.printed[task] = true;

        let below = match last {
            None => prefix.to_string(),
            Some(true) => format!("{prefix}   "),
            Some(false) => format!("{prefix}│  "),
        };
        self.path.push(task);
        let children = &self.edges[task];
        for (i, child) in children.iter().enumerate() {
            self.visit(child.to, &below, Some(i + 1 == children.len()), child.kind);
        }
        self.path.pop();
    }
}

/// How the graph names a task: its id, or its Header where the target
/// records none.
fn task_id(list: &bundle::TaskList, task: usize) -> String {
    match list.tasks[task].task_id {
        Some(id) => id.to_string(),
        None => format!("{:?}", list.tasks[task].addr),
    }
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
            Ok(Some(worker_ctx)) => print_worker_state(session, worker_ctx, depth, ugly, out)?,
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
            &format_args!(
                "{:#}",
                render(session, &value, depth, ugly).line_prefix("    ")
            ),
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
    worker_ctx: Value<'b>,
    depth: usize,
    ugly: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    writeln!(out, "  worker {}", ctx.worker_index(worker_ctx)?)?;

    let defer = worker_ctx.member("defer")?;
    print_variable(
        out,
        "  ",
        "defer",
        &format_args!(
            "{:#}",
            render(session, &defer, depth, ugly).line_prefix("    ")
        ),
    )?;

    // The core is moved out of the thread's context while the scheduler
    // parks or hands it to another thread, so its absence is a state
    // worth naming rather than an error.
    let core = worker_ctx.member("core")?.member("value")?;
    let Some(boxed) = core.try_select_variant("Some")? else {
        writeln!(out, "  core: not held by this thread")?;
        return Ok(());
    };
    let core = boxed.deref_ptr(ctx.proc)?;
    print_variable(
        out,
        "  ",
        "core",
        &format_args!(
            "{:#}",
            render(session, &core, depth, ugly).line_prefix("    ")
        ),
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
    // The bundle's `Elided` formats hide the runtime graph from *user*
    // values; these commands exist to show the runtime's own insides, so
    // they must never apply here — a new elided row must not be able to
    // blank part of this output.
    let no_elide = reify::ElideOverride {
        no_elide: true,
        types: Vec::new(),
    };
    writeln!(
        out,
        "{:#}",
        render(session, &value, depth, ugly).elide_override(&no_elide)
    )?;
    Ok(())
}

/// Display a value read from the target, honouring the custom formatters
/// unless asked for the raw structural view. Nothing is rendered until the
/// caller formats the result (with `{:#}` for the usual pretty layout), so
/// the text can stream to its destination instead of through a `String`.
fn render<'r, 'b>(
    session: &'r Session<'b>,
    value: &'r Value<'b>,
    depth: usize,
    ugly: bool,
) -> reify::DisplayValue<'r, 'b, Proc> {
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

/// Offline `whatis` tests: what an address resolves to over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod whatis_tests {
    use super::{parse_hex_addr, report_whatis};
    use hansei_bundle::{Bundle, BundleView};
    use hansei_runtime::tokio::bundle::{Context, TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};
    use proc::Target;
    use proc::snapshot::Snapshot;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("hansei-runtime/tests/fixtures")
            .join(name)
    }

    fn with_tasks(
        program: &str,
        check: impl FnOnce(&BundleView<'_>, &TaskList, &TaskExtents, &FutureCensus),
    ) {
        let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
            .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
        let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
            .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
        let ctx = Context::new(&snapshot, BundleView::new(&bundle)).expect("snapshot has mappings");

        let lwps = snapshot.lwps().unwrap();
        let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
        let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
        let list = ctx.enumerate_tasks(shared).expect("the owned-task walk");
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&ctx.view, &list, &extents, &census);
    }

    fn report(
        view: &BundleView<'_>,
        list: &TaskList,
        extents: &TaskExtents,
        census: &FutureCensus,
        addr: u64,
    ) -> String {
        let mut out = Vec::new();
        report_whatis(view, list, extents, census, addr, &mut out).expect("the report renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// An address inside a task's allocation — its header, or any
    /// offset short of the trailer's end — names that task; one
    /// outside every allocation reports the miss.
    #[test]
    fn test_addresses_resolve_to_the_containing_task() {
        with_tasks("sleep-join", |view, list, extents, census| {
            let sleeper = list
                .tasks
                .iter()
                .find(|t| t.task_id == Some(3))
                .expect("the sleeper is task 3");
            let header = sleeper.addr.0;

            let shown = report(view, list, extents, census, header);
            assert!(
                shown.contains("Task 3: sleep_join::sleeper::{async_fn_env#0}\n"),
                "{shown}"
            );
            assert!(
                shown.contains(&format!(
                    "    At: offset 0x0 in the task's allocation (header {header:#x})"
                )),
                "{shown}"
            );
            assert!(shown.contains("    State: idle"), "{shown}");

            let inside = report(view, list, extents, census, header + 0x10);
            assert!(inside.contains("Task 3: "), "{inside}");
            assert!(
                inside.contains("    At: offset 0x10 in the task's allocation"),
                "{inside}"
            );

            let miss = report(view, list, extents, census, 0x10);
            assert_eq!(
                miss,
                "no task's allocation and no future the census found contains 0x10\n"
            );
        });
    }

    /// An address is reported against the futures the census found as
    /// well as against the tasks, and a pointer *into* a future
    /// resolves to it the way one into a task's allocation does. This
    /// future is `.boxed()`, so it is a heap allocation of its own and
    /// no task's allocation claims it — the block naming what holds it
    /// is the only thing that says whose it is.
    #[test]
    fn test_addresses_resolve_to_the_containing_future() {
        with_tasks("futurelock", |view, list, extents, census| {
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));
            let owner = list.tasks[future1.owner]
                .task_id
                .expect("the holder is an owned task");
            let size = view
                .ty(future1.ty)
                .expect("the bundle carries the held future's type")
                .size();
            assert!(
                size > 0x10,
                "the fixture's future is too small to point into"
            );

            for offset in [0, 0x10] {
                let shown = report(view, list, extents, census, future1.addr + offset);
                assert!(
                    shown.contains(&format!("Future {:#x}: {}", future1.addr, future1.future)),
                    "{shown}"
                );
                assert!(
                    shown.contains(&format!("    At: offset {offset:#x} in the future")),
                    "{shown}"
                );
                assert!(
                    shown.contains(&format!("    Held by: task {owner} — ")),
                    "{shown}"
                );
                assert!(shown.contains("(frame 1, `future1`)"), "{shown}");
            }

            // Past its end it is somebody else's memory, and this
            // heap allocation is nobody's as far as hansei can say.
            let past = report(view, list, extents, census, future1.addr + size);
            assert!(
                past.starts_with("no task's allocation and no future"),
                "{past}"
            );
        });
    }

    /// Every task claims its own header and nothing claims the word
    /// before it: the extents tile the tasks without bleeding.
    #[test]
    fn test_extents_cover_each_task_exactly() {
        with_tasks("dyn-future", |_view, list, extents, _census| {
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

/// Offline future-trace tests: what `trace <0x-address>` resolves an
/// address to, and the chain it renders from there, over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod future_trace_tests {
    use super::{
        FutureAt, TraceTarget, future_at, future_name, parse_trace_target, print_await_chain,
        print_tasks,
    };
    use hansei_bundle::{Bundle, BundleView};
    use hansei_runtime::tokio::TaskState;
    use hansei_runtime::tokio::bundle::{self, Context, TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};
    use proc::Target;
    use proc::snapshot::Snapshot;
    use reify::Value;

    use std::collections::HashMap;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("hansei-runtime/tests/fixtures")
            .join(name)
    }

    fn with_target(
        program: &str,
        check: impl FnOnce(&Context<'_, Snapshot>, &TaskList, &TaskExtents, &FutureCensus),
    ) {
        let bundle = Bundle::load(&fixture(&format!("{program}.bundle")))
            .expect("fixture bundle loads; regenerate with capture-snapshots.sh");
        let snapshot = Snapshot::load(&fixture(&format!("{program}.snapshot")))
            .expect("fixture snapshot loads; regenerate with capture-snapshots.sh");
        let ctx = Context::new(&snapshot, BundleView::new(&bundle)).expect("snapshot has mappings");

        let lwps = snapshot.lwps().unwrap();
        let workers = ctx.find_workers(&lwps).expect("TLS-key discovery works");
        let shared = ctx.find_shared(&workers).expect("a MultiThread runtime");
        let list = ctx.enumerate_tasks(shared).expect("the owned-task walk");
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&ctx, &list, &extents, &census);
    }

    /// The two spellings split on the `0x` prefix and nothing else —
    /// the contract the command's help text states.
    #[test]
    fn test_trace_targets_parse_by_prefix() {
        assert!(matches!(
            parse_trace_target("42"),
            Ok(TraceTarget::Task(42))
        ));
        assert!(matches!(
            parse_trace_target("0x7fffb1c26100"),
            Ok(TraceTarget::Future(0x7fffb1c26100))
        ));
        assert!(matches!(
            parse_trace_target("0XFF"),
            Ok(TraceTarget::Future(0xff))
        ));
        // Hex digits without the prefix are not silently a huge id.
        assert!(parse_trace_target("7fffb1c26100").is_err());
        assert!(parse_trace_target("0x").is_err());
        assert!(parse_trace_target("-3").is_err());
    }

    /// A held future's printed address resolves to that future, and an
    /// interior pointer resolves to a future containing it.
    #[test]
    fn test_future_addresses_resolve_to_the_held_future() {
        with_target("futurelock", |ctx, list, extents, census| {
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));

            let found = future_at(&ctx.view, list, extents, census, future1.addr)
                .expect("the printed address resolves");
            let FutureAt::Held(h) = found else {
                panic!("future1 did not resolve as a held future");
            };
            assert_eq!(h.addr, future1.addr);

            let found = future_at(&ctx.view, list, extents, census, future1.addr + 1)
                .expect("an interior pointer resolves");
            let FutureAt::Held(h) = found else {
                panic!("the interior pointer did not resolve as a held future");
            };
            let size = ctx.view.ty(h.ty).expect("the root type resolves").size();
            assert!(
                h.addr <= future1.addr + 1 && future1.addr + 1 < h.addr + size,
                "resolved to {:#x} (size {size:#x}), which does not contain {:#x}",
                h.addr,
                future1.addr + 1
            );
        });
    }

    /// A miss says what the address is when that can be said: a task's
    /// own allocation points back at `trace <id>`, and an address
    /// nothing contains points at `tasks --futures`.
    #[test]
    fn test_future_misses_explain_the_address() {
        with_target("futurelock", |ctx, list, extents, census| {
            let header = list.tasks[0].addr.0;
            let err = future_at(&ctx.view, list, extents, census, header)
                .expect_err("a task header is not a census future")
                .to_string();
            assert!(err.contains("trace <id>"), "{err}");
            assert!(err.contains("task"), "{err}");

            let err = future_at(&ctx.view, list, extents, census, 0x10)
                .expect_err("nothing contains 0x10")
                .to_string();
            assert!(err.contains("`tasks --futures`"), "{err}");
        });
    }

    /// The chain rendered from a held future's recorded root: the
    /// futurelock fixture's abandoned `future1`, traced on its own,
    /// shows the lock acquisition it is parked in — the very chain the
    /// task listing hides.
    #[test]
    fn test_held_future_renders_its_own_chain() {
        with_target("futurelock", |ctx, list, _extents, census| {
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));

            let ty = ctx
                .view
                .ty(future1.ty)
                .expect("the root type is in the bundle");
            let root =
                Value::read(ctx.proc, ty, future1.addr).expect("the recorded root reads back");
            let chain = ctx.await_chain(root);

            let mut out = Vec::new();
            print_await_chain(
                ctx,
                list,
                &chain,
                false,
                4,
                false,
                &Default::default(),
                None,
                &mut out,
            )
            .expect("the chain renders");
            let rendered = String::from_utf8(out).expect("rendered output is UTF-8");
            assert!(
                rendered.contains("futurelock::do_async_thing::{async_fn_env#0}"),
                "{rendered}"
            );
            assert!(
                rendered.contains("tokio::sync::batch_semaphore::Acquire"),
                "{rendered}"
            );
        });
    }

    /// Render the task listing the way `tasks` does, with no worker
    /// polling anything: what LWP holds a task is the session's to say,
    /// and no listing test turns on it.
    fn render(
        list: &TaskList,
        held: &[census::HeldFuture],
        sets: &[census::FutureSet],
        futures: bool,
        tasks: &[u64],
    ) -> String {
        render_joining(list, held, sets, &[], futures, tasks)
    }

    /// The same, for the tests that lay out join sets: no fixture
    /// spawns onto one, so they are built by hand.
    fn render_joining(
        list: &TaskList,
        held: &[census::HeldFuture],
        sets: &[census::FutureSet],
        join_sets: &[census::JoinSet],
        futures: bool,
        tasks: &[u64],
    ) -> String {
        let mut out: Vec<u8> = Vec::new();
        print_tasks(
            list,
            &HashMap::new(),
            held,
            sets,
            join_sets,
            futures,
            tasks,
            &mut out,
        )
        .expect("the listing renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// `tasks --futures` narrowed to the task that owns the fixture's
    /// one held future prints that future under it.
    #[test]
    fn test_futures_narrowed_to_the_owner_prints_its_futures() {
        with_target("futurelock", |_ctx, list, _extents, census| {
            let owner = census
                .held
                .first()
                .unwrap_or_else(|| panic!("the fixture holds a future"))
                .owner;
            let id = list.tasks[owner].task_id.expect("the owner has an id");

            let narrowed = render(list, &census.held, &census.sets, true, &[id]);
            assert!(narrowed.contains(&format!("Task {id}:")), "{narrowed}");
            // The row names the local it was found in and nothing more:
            // under `Held futures`, `held` would only repeat the
            // heading.
            assert!(narrowed.contains(", `future1`): 0x"), "{narrowed}");
            assert!(!narrowed.contains("held (frame"), "{narrowed}");
            // Narrowing narrows the listing itself, not just its
            // futures — and the block it leaves is the whole answer, so
            // there is no count under it restating the ids asked for.
            assert_eq!(narrowed.matches("\nTask ").count() + 1, 1, "{narrowed}");
            assert!(!narrowed.contains("\n1 task\n"), "{narrowed}");
            assert!(narrowed.contains("    Held futures: 1\n"), "{narrowed}");

            // The whole listing carries every task, and the same find
            // under the same block: what the census found is all this
            // task's.
            let all = render(list, &census.held, &census.sets, true, &[]);
            for task in &list.tasks {
                let id = task.task_id.expect("every fixture task has an id");
                assert!(all.contains(&format!("Task {id}: ")), "{all}");
            }
            assert!(all.contains(", `future1`): 0x"), "{all}");
        });
    }

    /// Several ids print several blocks, in the listing's order rather
    /// than the order asked for, and an id asked for twice prints once.
    #[test]
    fn test_tasks_narrowed_to_several_ids() {
        with_target("channels", |_ctx, list, _extents, census| {
            let ids: Vec<u64> = list
                .tasks
                .iter()
                .map(|t| t.task_id.expect("every fixture task has an id"))
                .collect();
            assert!(ids.len() >= 2, "the fixture owns several tasks: {ids:?}");
            let (first, second) = (ids[0], ids[1]);

            let rendered = render(
                list,
                &census.held,
                &census.sets,
                false,
                &[second, first, second],
            );
            assert!(
                rendered.starts_with(&format!("Task {first}: ")),
                "{rendered}"
            );
            assert_eq!(rendered.matches("\nTask ").count() + 1, 2, "{rendered}");
            assert!(
                rendered.contains(&format!("\nTask {second}: ")),
                "{rendered}"
            );
            // Two blocks are still not a listing, so nothing counts them.
            assert!(!rendered.contains("\n2 tasks\n"), "{rendered}");
        });
    }

    /// A future the census reached through a set child is printed under
    /// that child, and counted as being inside it — the distinction the
    /// summary exists to draw, since a flat listing of the two
    /// populations reads as twice as many futures as there are. No
    /// fixture nests this way, so the shape is laid out by hand.
    #[test]
    fn test_futures_prints_a_nested_find_under_what_holds_it() {
        with_target("futurelock", |_ctx, list, _extents, census| {
            let owner = census.held[0].owner;
            let ty = census.held[0].ty;
            let sets = vec![census::FutureSet {
                owner,
                frame: 0,
                local: "pending".to_string(),
                via: None,
                addr: 0x1000,
                ty: "FuturesUnordered<step::{async_fn_env#0}>".to_string(),
                children: vec![
                    census::SetChild {
                        depth: 1,
                        node: 0x2000,
                        future: Some("step::{async_fn_env#0}".to_string()),
                        root: None,
                        state: Some("Suspend0 — step.rs:9".to_string()),
                        waiting_on: None,
                        wait: None,
                        leaf: None,
                    },
                    census::SetChild {
                        depth: 1,
                        node: 0x2100,
                        future: None,
                        root: None,
                        state: None,
                        waiting_on: None,
                        wait: None,
                        leaf: None,
                    },
                ],
            }];
            let held = vec![census::HeldFuture {
                depth: 1,
                owner,
                frame: 1,
                local: "lock".to_string(),
                via: Some(census::Via::SetChild { set: 0, child: 0 }),
                addr: 0x3000,
                ty,
                future: "Mutex::lock::{async_fn_env#0}".to_string(),
                state: None,
                waiting_on: None,
                wait: None,
                leaf: None,
            }];

            let rendered = render(list, &held, &sets, true, &[]);

            // The set sits under the owning task's `Join sets` row, the
            // held row two columns right of the child it was found in,
            // which is itself two right of the set. The task holds
            // nothing in its own frames, so `Held futures` is zero and
            // its listing empty: the one held future is inside the
            // child, which the child's own row counts.
            assert!(
                rendered.contains(
                    "    Held futures: 0\n    Join sets: 1 (1 future)\n        \
                     - FuturesUnordered<step::{async_fn_env#0}> at 0x1000 (frame 0, `pending`): \
                     1 child in flight, 1 completed and not yet reaped\n            \
                     0x2000  step::{async_fn_env#0}  Suspend0 — step.rs:9\n                \
                     held (frame 1, `lock`): 0x3000  Mutex::lock::{async_fn_env#0}\n"
                ),
                "{rendered}"
            );
            // The reaped slot is not a future in flight, so the rows say
            // one child, not two — and they say it with or without the
            // listing under them.
            let counted = render(list, &held, &sets, false, &[]);
            assert!(counted.contains("    Held futures: 0\n"), "{counted}");
            assert!(
                counted.contains("    Join sets: 1 (1 future)\n"),
                "{counted}"
            );
            assert!(!counted.contains("FuturesUnordered"), "{counted}");
        });
    }

    /// A join set lists the tasks it holds by the ids `trace` takes,
    /// under a count of its own — its members are tasks the listing
    /// already carries. No fixture spawns onto a join set, so the shape
    /// is laid out by hand.
    #[test]
    fn test_futures_lists_a_join_set_by_task() {
        with_target("channels", |_ctx, list, _extents, _census| {
            // The set holds two of the fixture's own tasks and one the
            // runtime no longer owns, which is what a complete-but-not
            // yet-joined member looks like.
            let joined: Vec<&bundle::Task> = list.tasks.iter().take(2).collect();
            let owner = list.tasks.len() - 1;
            let mut children: Vec<census::JoinedTask> = joined
                .iter()
                .map(|task| census::JoinedTask {
                    entry: task.addr.0 + 0x40,
                    task: task.addr.0,
                    id: task.task_id,
                    state: task.state,
                    listed: true,
                })
                .collect();
            children.push(census::JoinedTask {
                entry: 0x5040,
                task: 0x5000,
                id: Some(99),
                state: TaskState(0b0010),
                listed: false,
            });
            let join_sets = vec![census::JoinSet {
                owner,
                frame: 0,
                local: "set".to_string(),
                via: None,
                addr: 0x4000,
                ty: "JoinSet<()>".to_string(),
                length: 3,
                children,
            }];

            let rendered = render_joining(list, &[], &[], &join_sets, true, &[]);
            let expected = format!(
                "    Held futures: 0\n    Join sets: 1 (3 tasks)\n        \
                 - JoinSet<()> at 0x4000 (frame 0, `set`): 3 tasks\n            \
                 task {}  {}  {}\n            task {}  {}  {}\n            \
                 task 99  <complete, awaiting join>\n",
                joined[0].task_id.expect("the fixture's tasks have ids"),
                future_name(&joined[0].future),
                joined[0].state.lifecycle(),
                joined[1].task_id.expect("the fixture's tasks have ids"),
                future_name(&joined[1].future),
                joined[1].state.lifecycle(),
            );
            assert!(rendered.contains(&expected), "{rendered}");
        });
    }

    /// A task the census found nothing for still prints its block, with
    /// every count zero — silence would read as a listing that failed.
    #[test]
    fn test_futures_narrowed_to_a_task_holding_none() {
        with_target("channels", |_ctx, list, _extents, census| {
            let id = list.tasks[0].task_id.expect("the first task has an id");
            let rendered = render(list, &census.held, &census.sets, true, &[id]);
            assert!(rendered.starts_with(&format!("Task {id}: ")), "{rendered}");
            assert!(rendered.contains("    Held futures: 0\n"), "{rendered}");
            // A task that drives no set says so with a bare zero: what
            // the sets it does not have would hold is noise.
            assert!(rendered.contains("    Join sets: 0\n"), "{rendered}");
        });
    }

    /// An id the runtime does not own is an error naming the ids it
    /// does, not an empty listing.
    #[test]
    fn test_futures_rejects_an_unknown_task_id() {
        with_target("futurelock", |_ctx, list, _extents, census| {
            let unknown = list
                .tasks
                .iter()
                .filter_map(|t| t.task_id)
                .max()
                .expect("some task has an id")
                + 1;
            let mut out = Vec::new();
            let err = print_tasks(
                list,
                &HashMap::new(),
                &census.held,
                &census.sets,
                &census.join_sets,
                true,
                &[unknown],
                &mut out,
            )
            .expect_err("no task owns that id")
            .to_string();
            assert!(err.contains(&format!("id {unknown}")), "{err}");
            assert!(out.is_empty(), "printed {out:?} before failing");
        });
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
    use hansei_bundle::{Bundle, BundleView};
    use hansei_runtime::tokio::bundle::{Context, TaskStage};
    use proc::Target;
    use proc::snapshot::Snapshot;

    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("hansei-runtime/tests/fixtures")
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
        let list = ctx.enumerate_tasks(shared).expect("the owned-task walk");

        let task = list
            .tasks
            .iter()
            .find(|t| match &t.future {
                hansei_runtime::tokio::bundle::FutureInfo::Known(known) => {
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
            &list,
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
       Suspend0  src/bin/simple-await.rs:32  11 locals  simple_await::ready_value::{async_fn_env#0}
     ▸ Suspend1  src/bin/simple-await.rs:34  10 locals
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
       Suspend0  src/bin/futurelock.rs:22  1 local  futurelock::start_background_task::{async_fn_env#0}
     ▸ Suspend1  src/bin/futurelock.rs:25  1 local
       └─  1  async fn      futurelock::do_stuff::{async_fn_env#0}
          suspends:
            Suspend0  src/bin/futurelock.rs:59  4 locals  core::future::poll_fn::PollFn<futurelock::do_stuff::{async_fn#0}::{closure_env#0}>
          ▸ Suspend1  src/bin/futurelock.rs:64  3 locals
            └─  2  async fn      futurelock::do_async_thing::{async_fn_env#0}
               suspends:
               ▸ Suspend0  src/bin/futurelock.rs:72  2 locals
                 └─  3  async fn      tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>
                    suspends:
                    ▸ Suspend0  tokio-1.52.4/src/sync/mutex.rs:455
                      └─  4  async block   tokio::sync::mutex::{impl#10}::lock::{async_fn#0}::{async_block_env#0}<()>
                         suspends:
                         ▸ Suspend0  tokio-1.52.4/src/sync/mutex.rs:436
                           └─  5  async fn      tokio::sync::mutex::{impl#10}::acquire::{async_fn_env#0}<()>
                              suspends:
                                Suspend0  tokio-1.52.4/src/sync/mutex.rs:656  1 local  tokio::trace::async_trace_leaf::{async_fn_env#0}
                              ▸ Suspend1  tokio-1.52.4/src/sync/mutex.rs:658
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
     ▸ Suspend0  src/bin/dyn-future.rs:29  1 local
       └─  1  async fn      dyn_future::boxed_leaf::{async_fn_env#0} [dyn]
          suspends:
          ▸ Suspend0  src/bin/dyn-future.rs:11
            └─* 2  future        tokio::sync::oneshot::Receiver<u32>
       Suspend1  src/bin/dyn-future.rs:30  2 locals  tokio::task::join_set::{impl#1}::join_next::{async_fn_env#0}<u32>
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
        let list = ctx.enumerate_tasks(shared).expect("the owned-task walk");

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
            &list,
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
            rendered.contains("     ▸ Suspend1  src/bin/simple-await.rs:34\n       locals:\n"),
            "{rendered}"
        );
        // The inactive row keeps its count: every variant shares the
        // enum's storage, so its locals cannot be read at all.
        assert!(
            rendered.contains("       Suspend0  src/bin/simple-await.rs:32  11 locals  "),
            "{rendered}"
        );
        assert!(rendered.contains("\n         count: 3\n"), "{rendered}");
    }
}

#[cfg(test)]
mod graph_tests {
    use super::print_graph;

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::bundle::{
        AbandonedAcquire, FutureInfo, Task, TaskList, WaitKind, WaitTarget,
    };
    use hansei_runtime::tokio::census;
    use hansei_runtime::tokio::graph::{Analysis, Futurelock, TaskRef, TaskWait};
    use hansei_runtime::tokio::{RawInstant, TaskAddr, TaskState};

    const REF_ONE: u64 = 1 << 6;
    const SEMAPHORE: u64 = 0x9000;

    fn addr(id: u64) -> TaskAddr {
        TaskAddr(0x1000 + id * 0x100)
    }

    fn task(id: u64) -> Task {
        Task {
            addr: addr(id),
            state: TaskState(REF_ONE),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
        }
    }

    fn wait(id: u64, target: Option<WaitTarget>) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: addr(id),
                task_id: Some(id),
            },
            target,
            depth: 1,
            leaf: None,
        }
    }

    /// A task parked on an ordinary future rather than on one of the
    /// primitives hansei decodes into a wait target.
    fn leaf_wait(id: u64, leaf: &str) -> TaskWait {
        TaskWait {
            leaf: Some(leaf.to_string()),
            ..wait(id, None)
        }
    }

    /// Waiting to join the task with this id.
    fn joining(id: u64) -> WaitTarget {
        WaitTarget::Task {
            addr: addr(id).0,
            task_id: Some(id),
            state: TaskState(REF_ONE),
            listed: true,
        }
    }

    fn semaphore() -> WaitTarget {
        WaitTarget::Semaphore {
            addr: SEMAPHORE,
            owner: Some("tokio::sync::Mutex"),
            num_permits: 1,
            available: 0,
            closed: false,
            waiters: Vec::new(),
        }
    }

    fn timer() -> WaitTarget {
        WaitTarget::Timer {
            deadline: RawInstant {
                tv_sec: 12,
                tv_nsec: 0,
            },
            stopped: Some(RawInstant {
                tv_sec: 2,
                tv_nsec: 0,
            }),
        }
    }

    /// The task holding an acquire on the semaphore in a future it
    /// stopped polling — the edge that says who a lock's waiters are
    /// really waiting for.
    fn futurelock(holder: u64) -> Futurelock {
        Futurelock {
            holder: TaskRef {
                addr: addr(holder),
                task_id: Some(holder),
            },
            acquire: AbandonedAcquire {
                frame: "worker::{async_fn_env#0}".to_string(),
                state: "Suspend0".to_string(),
                await_loc: None,
                local: "lock".to_string(),
                future: "Mutex::lock::{async_fn_env#0}".to_string(),
                owner: Some("tokio::sync::Mutex"),
                semaphore: SEMAPHORE,
                node: 0xa000,
                num_permits: 1,
                needed: 0,
            },
            blocked: Vec::new(),
        }
    }

    fn graph(tasks: Vec<Task>, waits: Vec<TaskWait>, futurelocks: Vec<Futurelock>) -> String {
        graph_with(tasks, waits, futurelocks, &[], &[])
    }

    /// A graph over what the census found in the tasks' frames as well:
    /// the sets they drive and the handles they hold.
    fn graph_with(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        futurelocks: Vec<Futurelock>,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
    ) -> String {
        let list = TaskList {
            tasks,
            errors: Vec::new(),
        };
        let analysis = Analysis {
            waits,
            futurelocks,
            errors: Vec::new(),
        };
        let mut out = Vec::new();
        print_graph(&list, &analysis, held, join_sets, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// A `JoinSet` in `owner`'s frames holding the tasks with these ids.
    fn join_set(owner: usize, ids: &[u64]) -> census::JoinSet {
        census::JoinSet {
            owner,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: 0xb000,
            ty: "tokio::task::join_set::JoinSet<()>".to_string(),
            length: ids.len() as u64,
            children: ids
                .iter()
                .map(|id| census::JoinedTask {
                    entry: 0xc000,
                    task: addr(*id).0,
                    id: Some(*id),
                    state: TaskState(REF_ONE),
                    listed: true,
                })
                .collect(),
        }
    }

    /// A `JoinHandle` to `id` sitting in `owner`'s frames, off its
    /// await chain.
    fn held_handle(owner: usize, id: u64) -> census::HeldFuture {
        census::HeldFuture {
            depth: 1,
            owner,
            frame: 0,
            local: "cancel_task".to_string(),
            via: None,
            addr: 0xd000,
            ty: BundleTypeId(0),
            future: "tokio::runtime::task::join::JoinHandle<()>".to_string(),
            state: None,
            waiting_on: None,
            wait: Some(WaitKind::Task { addr: addr(id).0 }),
            leaf: None,
        }
    }

    /// A chain of waits reads as one tree: the joiner at the margin, the
    /// task it joins under it, and — since the futurelock analysis names
    /// who holds the lock that task is blocked on — the holder under
    /// that. Every task keeps its one row.
    #[test]
    fn test_a_wait_chain_nests_to_its_depth() {
        let page = graph(
            vec![task(12), task(40), task(51)],
            vec![
                wait(12, Some(joining(40))),
                wait(40, Some(semaphore())),
                wait(51, Some(timer())),
            ],
            vec![futurelock(51)],
        );
        assert_eq!(
            page,
            "\
TASK      STATE  WAITING ON
12        idle   task 40 (JoinHandle)
└─ 40     idle   a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available
   └─ 51  idle   the timer: deadline 10.000s
"
        );
    }

    /// A task waiting on something that is waiting on it has no top to
    /// hang from. It is walked anyway, and the row that closes the loop
    /// says so rather than recurring forever.
    #[test]
    fn test_a_cycle_is_walked_once_and_marked() {
        let page = graph(
            vec![task(88)],
            vec![wait(88, Some(joining(88)))],
            Vec::new(),
        );
        assert_eq!(
            page,
            "\
TASK           STATE  WAITING ON
88             idle   task 88 (JoinHandle)
└─ 88 ← cycle  idle   
"
        );
    }

    /// Two tasks blocked on the same lock both point at its holder. It
    /// is spelled out under the first and referred back to under the
    /// second, so its subtree is not printed twice.
    #[test]
    fn test_a_task_reached_twice_is_printed_once() {
        let page = graph(
            vec![task(40), task(41), task(51)],
            vec![
                wait(40, Some(semaphore())),
                wait(41, Some(semaphore())),
                wait(51, Some(timer())),
            ],
            vec![futurelock(51)],
        );
        assert_eq!(
            page,
            "\
TASK           STATE  WAITING ON
40             idle   a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available
└─ 51          idle   the timer: deadline 10.000s
41             idle   a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available
└─ 51 (above)  idle   
"
        );
    }

    /// A `JoinSet`'s members hang under the task driving it. Nothing
    /// about that task's own wait names them — `join_next` is not a
    /// `JoinHandle` await — so without this edge a runtime built out of
    /// parallel task sets graphs as a runtime with no structure.
    #[test]
    fn test_join_set_members_hang_under_their_owner() {
        let page = graph_with(
            vec![task(7), task(8), task(9)],
            vec![wait(7, None), wait(8, None), wait(9, None)],
            Vec::new(),
            &[],
            &[join_set(0, &[8, 9])],
        );
        assert_eq!(
            page,
            "\
TASK                         STATE  WAITING ON
7                            idle   -
├─ 8 [in the JoinSet above]  idle   -
└─ 9 [in the JoinSet above]  idle   -
"
        );
    }

    /// A handle a frame merely holds is an edge too, and marked as one:
    /// the task can join or abort what it points at, and may be doing
    /// neither.
    #[test]
    fn test_a_held_handle_is_marked_as_held() {
        let page = graph_with(
            vec![task(7), task(8)],
            vec![wait(7, None), wait(8, Some(timer()))],
            Vec::new(),
            &[held_handle(0, 8)],
            &[],
        );
        assert_eq!(
            page,
            "\
TASK                          STATE  WAITING ON
7                             idle   -
└─ 8 [its handle held above]  idle   the timer: deadline 10.000s
"
        );
    }

    /// A task in no graph is left out of it: `tasks` is where it is
    /// listed, and `census` where its wait is counted.
    #[test]
    fn test_tasks_in_no_graph_are_left_out() {
        let page = graph_with(
            vec![task(7), task(8), task(1), task(2)],
            vec![
                wait(7, None),
                wait(8, Some(timer())),
                leaf_wait(1, "tokio::runtime::io::scheduled_io::Readiness"),
                wait(2, None),
            ],
            Vec::new(),
            &[held_handle(0, 8)],
            &[],
        );
        assert_eq!(
            page,
            "\
TASK                          STATE  WAITING ON
7                             idle   -
└─ 8 [its handle held above]  idle   the timer: deadline 10.000s
"
        );
    }

    /// With nothing related at all there is nothing to print: a heading
    /// over no rows reads as a graph that failed rather than a target
    /// with no edges to draw.
    #[test]
    fn test_a_target_with_no_edges_prints_no_table() {
        let page = graph(
            vec![task(1)],
            vec![leaf_wait(1, "tokio::runtime::io::scheduled_io::Readiness")],
            Vec::new(),
        );
        assert_eq!(page, "");
    }
}

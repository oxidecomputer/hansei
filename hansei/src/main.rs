use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::tokio::graph::{self as rt_graph, Analysis};
use hansei_runtime::tokio::{bundle, census, contract};
use proc::{Proc, Target};

use std::cell::{Cell, OnceCell};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod graph;
mod output;
mod print;
pub mod repl;
mod runtimes;
#[cfg(feature = "snapshot")]
mod snapshot_cmd;
pub mod summary;
mod sync;
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

    /// The executable the core was taken from.
    ///
    /// Required for a Linux core, which carries no symbol table of its
    /// own and names a path that is rarely still right on the machine
    /// reading the core. This is the binary that *ran*, not the debug
    /// build behind `--bundle`: the two share no addresses. An illumos
    /// core carries its own symbols and ignores this.
    #[arg(long, short, value_name = "PATH")]
    program: Option<PathBuf>,

    /// Proceed even if the bundle's symbols don't all resolve in the
    /// target, or `--program` is not the binary the core was taken from.
    #[arg(long, short)]
    force: bool,

    /// Attach even if non-essential walk paths are broken against this
    /// tokio's layouts, degrading whatever reads them. By default any
    /// broken path refuses the attach with a report of what moved.
    #[arg(long)]
    best_effort: bool,

    /// Read only one of the target's runtimes, by its index in the
    /// discovered list (`runtimes` names them). By default every
    /// runtime is read, merged with a tag where there is more than one.
    #[arg(long, value_name = "INDEX")]
    runtime: Option<usize>,

    /// How deep the future census descends into one frame local
    /// looking for futures held inside it: a future in a tuple in a
    /// struct in an `Option` is four levels down.
    ///
    /// The census says when it stopped at this limit, which is when
    /// raising it is worth it — a target that nests futures deeply
    /// enough to be cut off holds more than the listing showed.
    /// Lowering it below what a target needs is how to see what the
    /// descent is finding.
    #[arg(long, value_name = "LEVELS", default_value_t = census::Bounds::default().scan_depth)]
    search_depth: usize,

    /// Check the census against its own construction rules whenever
    /// one is taken, reporting any violation on stderr. The total
    /// class holds over any core whatsoever; the healthy-only class is
    /// the operator's judgment that this core is sound. Hidden: a
    /// violation is a hansei bug to report, not a fact about the
    /// target.
    #[arg(long, hide = true)]
    audit: bool,
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
    /// workers running a scheduler's loop, the threads that have merely
    /// entered a runtime, and everything else. Each split is a
    /// share of the line above it and never a second count of the same
    /// threads — which takes one correction, because a runtime launches
    /// every worker with `spawn_blocking` and its pool therefore counts
    /// the workers among its own threads. They are netted out, so the
    /// pool's row is the threads doing blocking work and nothing else.
    ///
    /// Every number that is one runtime's says which: the section names
    /// the runtime the way `runtimes` lists it — `runtime 0 @0x7f11c0`
    /// — where the target holds one, and counts them where it holds
    /// several, each row that belongs to one of them naming it.
    ///
    /// The workers are broken down by what their parkers say, and the
    /// one parked *in* the driver is named — that is the thread blocked
    /// in the system's readiness call on the whole runtime's behalf.
    /// There is no io thread as such in a multi_thread runtime: the
    /// driver rotates between workers, so what is reported is whichever
    /// held it when the target stopped.
    ///
    /// The task section counts every task the target's executors own,
    /// by lifecycle, by what it is waiting on, and by the future types and
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

    /// Render the memory at an address as a value of a named type: the
    /// inverse of `whatis`, for reading a structure the listings only
    /// point at. The address says where and the type says how, and
    /// nothing checks one against the other — printing the wrong type
    /// at an address renders that memory as the type asked for.
    Print {
        /// The address to read, written in hex with a required leading
        /// `0x` (e.g. `0x7fffb1c26100`).
        #[arg(value_parser = parse_hex_addr)]
        addr: u64,

        /// The type to render the memory as: the exact fully-qualified
        /// name as `find-types` lists it (several words are joined back
        /// into one name, so generics holding spaces paste in whole),
        /// or a bundle type id — the `type 4821` a listing prints where
        /// a name alone is not a handle. The kind-joined spelling the
        /// listings display (`async fn app::work`) names a function
        /// rather than the type its memory holds, so it is refused with
        /// the recorded name to use instead; a name with several
        /// recorded definitions is refused with the ids that pick one.
        #[arg(value_name = "TYPE", required = true, num_args = 1..)]
        ty: Vec<String>,

        #[command(flatten)]
        render: RenderOpts,
    },

    /// Show a runtime's own state, read straight through the bundle's
    /// layouts: its drivers, and the scheduler state its workers share.
    /// Naming no section shows both.
    ///
    /// The bundle's elisions (which hide runtime internals inside user
    /// values) never apply to this view.
    ///
    /// Every discovered runtime is shown, each under a heading, unless
    /// one is named — by its index in the `runtimes` listing, or by the
    /// handle address that listing prints beside it.
    Runtime {
        /// Which runtime to show: an index from `runtimes`, or a handle
        /// address in hex with a leading 0x. Every one of them by
        /// default.
        #[arg(value_parser = parse_runtime_scope)]
        scope: Option<RuntimeScope>,

        /// Print the drivers: io, signal, time, and the clock.
        #[arg(long, short = 'D')]
        drivers: bool,

        /// Print the scheduler state the workers share: the owned-task
        /// set, the injection queue, the idle set and the per-worker
        /// remotes.
        #[arg(long, short)]
        shared: bool,

        #[command(flatten)]
        render: RenderOpts,
    },

    /// List every executor the target holds: each discovered runtime,
    /// then each discovered `LocalSet`, with the tasks and futures the
    /// merged population attributes to it.
    ///
    /// The index each row carries is the one the task listing tags its
    /// blocks with, the one `--runtime` selects by, and the one the
    /// `runtime` command takes; the handle address beside it names the
    /// same thing and can be given anywhere the index can.
    ///
    /// A row says where its group runs — the lwps inside it — or, when
    /// nothing is inside it, the route discovery reached it by. That
    /// distinction is worth reading, because the list is a lower bound
    /// by construction: a runtime no thread is inside is only found
    /// when something already discovered points at it, so one whose
    /// `block_on` has returned and whose tasks nothing outside it
    /// names cannot be found at all.
    ///
    /// The future counts are the census's, so the first `runtimes`
    /// walks every task's await chain — the slowest thing a session
    /// does on a large target. The walk is kept, so a later `census`,
    /// `tasks --futures`, `graph` or `whatis` costs nothing.
    Runtimes,

    /// Capture a replayable snapshot of everything the bundle-backed
    /// analysis reads from the target: task enumeration and every task's
    /// await chain are driven once with a recording wrapper in place,
    /// and the memory, symbol, and lwp state they touched is written
    /// out. Together with a bundle extracted from a *separate* build of
    /// the same source, the snapshot feeds the offline two-binary tests.
    #[cfg(feature = "snapshot")]
    #[command(hide = true)]
    Snapshot {
        /// Where to write the snapshot.
        output: PathBuf,
    },

    /// List the contended synchronization primitives: one block per
    /// semaphore — the primitive backing tokio's Mutex, RwLock, and
    /// Semaphore — with its available permits, any holder the
    /// futurelock analysis can name, the tasks blocked on it, and its
    /// wake queue in wake order.
    ///
    /// This is `graph` turned resource-centric: the graph nests tasks
    /// under the tasks blocking them, and this lists the resources
    /// they contend on, each with everything known about it in one
    /// block. A tokio semaphore records no owner, so `Held by:`
    /// appears only where the futurelock analysis found an abandoned
    /// acquire holding permits (RFD 609) — the one case a holder is
    /// knowable at all.
    ///
    /// The address heading each block is the one `trace` prints in its
    /// `waiting on … (semaphore 0x…)` line, and the one this command
    /// takes to narrow to a single block. Discovery runs through the
    /// tasks' await chains and the futurelock scan, not a sweep of
    /// memory: a semaphore nothing waits on is not listed, and nothing
    /// at all prints on a target with no contention.
    Sync {
        /// One semaphore to show, by the address the listings print,
        /// in hex with a required leading `0x`. Every one by default.
        #[arg(value_parser = parse_hex_addr)]
        addr: Option<u64>,
    },

    /// List every task the target's executors own: id, lifecycle state,
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
    /// no runtime owns any longer: complete and waiting to be joined, or
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
    ///
    /// The descent into one local stops at `--search-depth` levels,
    /// and says so where it stopped; raise it on the command line for
    /// a target that nests futures deeper than that.
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

    /// Show every thread running a runtime: the task it is polling,
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
        /// instantiation, a matched type stays elided under --no-elide,
        /// and a name may be spelled the way the listings display it
        /// (folded, kind word and all), the way the debug info records
        /// it, or as a bundle type id — the `type 4821` a listing
        /// prints where a name alone is not a handle — which elides
        /// that exact instantiation.
        #[arg(long, short = 'e', value_name = "TYPE")]
        elide: Vec<String>,
    },

    /// Print the layout the bundle records for a type, by its exact
    /// fully-qualified name: members and their offsets, or an enum's
    /// variants and the discriminant that selects them.
    Type {
        /// The fully-qualified name, as `find-types` lists it — or as
        /// another listing displays it, folded and with the kind word —
        /// or a bundle type id, the `type 4821` a listing prints where
        /// the name alone is not a handle (an ambiguous site, one
        /// definition of several).
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

/// Which runtime a command was pointed at.
#[derive(Clone, Copy)]
pub enum RuntimeScope {
    /// Its position in the `runtimes` listing — the index every listing
    /// tags a task's group with.
    Index(usize),
    /// The address of its handle, which that listing prints beside the
    /// index so either identifier pastes back in.
    Handle(u64),
}

/// Parse a runtime scope. The split is the one `parse_trace_target`
/// makes for the same reason: the listing prints indices in decimal and
/// addresses in `0x` hex, so neither spelling can be mistaken for the
/// other. The listing prints the handle as `@0x…`, so that exact
/// spelling pastes back in; the `@` is its dress, not its identity,
/// and a bare address means the same handle.
fn parse_runtime_scope(s: &str) -> std::result::Result<RuntimeScope, String> {
    let addr = s.strip_prefix('@').unwrap_or(s);
    if addr.starts_with("0x") || addr.starts_with("0X") {
        parse_hex_addr(addr).map(RuntimeScope::Handle)
    } else {
        s.parse().map(RuntimeScope::Index).map_err(|_| {
            format!(
                "a runtime is named by its index in the `runtimes` listing, or \
                 by the handle address printed beside it there (with or \
                 without its leading @), got {s:?}"
            )
        })
    }
}

/// Everything `trace` was told about rendering a chain: the shared
/// render options plus the flags only tracing takes.
struct TraceOpts<'a> {
    verbose: bool,
    render: RenderOpts,
    elide: &'a reify::ElideOverride,
    theme: output::Theme,
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
    /// flavor: those a thread's context reaches first, then those
    /// discovery found because a task pointed at them. One on nearly
    /// every real target; current_thread makes more ordinary, and the
    /// task list below merges them all.
    runtimes: Vec<bundle::RuntimeRef<'b>>,
    /// The handles of the runtimes `--runtime` left out, so a filtered
    /// session can say it is one rather than reading as a target with
    /// fewer runtimes than it has.
    excluded: Vec<u64>,
    /// Every `LocalSet` discovery reached, in the group order their
    /// tasks are stamped with (after the runtimes). Empty on targets
    /// whose bundle shows no local-set machinery linked.
    local_sets: Vec<bundle::LocalSetRef<'b>>,
    tasks: bundle::TaskList,
    /// The bundle's impl-path substitutions, threaded into every
    /// display fold ([`hansei_bundle::names::fold_type_name`]).
    impl_fold: hansei_bundle::names::ImplFold,
    /// Task extents, the sub-executor census and the wait analysis,
    /// built on first use: a core does not change, so the address→task
    /// answers never do either, and the two walks cover every chain —
    /// worth paying once.
    extents: OnceCell<bundle::TaskExtents>,
    census: OnceCell<census::FutureCensus>,
    /// Where the census walk stops, `--search-depth` having moved the
    /// one bound a session can set.
    bounds: census::Bounds,
    /// Whether `--audit` asked for the census's self-check.
    audit: bool,
    /// Whether the version-ceiling drift notice has printed, so the
    /// walk commands raise it once per session, not once per line.
    ceiling_noticed: Cell<bool>,
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
        // The runtimes a selection leaves out: discovery must not hand
        // them back, or `--runtime` would stop being a filter.
        let mut excluded = Vec::new();
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
            let selected = runtimes.swap_remove(index);
            excluded = runtimes.iter().map(|r| r.handle.addr).collect();
            runtimes = vec![selected];
        }
        let mut tasks = ctx.enumerate_all_tasks(&runtimes)?;
        // Runtimes nothing is currently inside, and local sets, merge
        // into the same population: the runtimes join the list above,
        // the sets are tagged as groups after every runtime.
        let local_sets =
            ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &excluded, &mut tasks);
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
            excluded,
            local_sets,
            tasks,
            impl_fold: hansei_bundle::names::ImplFold::for_bundle(bundle),
            extents: OnceCell::new(),
            census: OnceCell::new(),
            bounds: census::Bounds {
                scan_depth: args.search_depth,
                ..census::Bounds::default()
            },
            audit: args.audit,
            ceiling_noticed: Cell::new(false),
            analysis: OnceCell::new(),
        })
    }

    /// Print the drift notice for a target newer than the bundle's
    /// version ceiling — once, before the first walk command's output.
    /// The walk commands (census/tasks/trace) call this rather than the
    /// attach, so drift surfaces where its layouts are actually read.
    fn note_version_ceiling(&self) {
        if let Some(line) = version_ceiling_line(&self.bundle.meta, &self.ceiling_noticed) {
            let _ = writeln!(io::stderr(), "{line}");
        }
    }

    fn extents(&self) -> &bundle::TaskExtents {
        self.extents
            .get_or_init(|| self.ctx.task_extents(&self.tasks))
    }

    fn census(&self) -> &census::FutureCensus {
        self.census.get_or_init(|| {
            let census = census::census_bounded(&self.ctx, &self.tasks, self.bounds);
            if self.audit {
                let violations = census.audit(&self.tasks);
                if violations.is_empty() {
                    let _ = writeln!(io::stderr(), "census audit: clean");
                }
                for violation in violations {
                    let _ = writeln!(io::stderr(), "warning: census audit: {violation}");
                }
            }
            census
        })
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

    /// The per-group tags the listings mark tasks with: one label per
    /// discovered runtime, then one per discovered local set, in the
    /// group order tasks are stamped with — empty (no tags) when the
    /// whole population is one runtime's, which is nearly every target.
    ///
    /// Each names its group the way `runtimes` lists it, so a tag can be
    /// looked up there and handed straight back to `--runtime` or the
    /// `runtime` command.
    fn group_tags(&self) -> Vec<String> {
        if self.runtimes.len() + self.local_sets.len() <= 1 {
            return Vec::new();
        }
        let mut tags: Vec<String> = self
            .runtimes
            .iter()
            .enumerate()
            .map(|(i, r)| match r.worker_tids.is_empty() {
                true => format!(
                    "{} ({}, no thread inside it)",
                    runtimes::runtime_label(i, r),
                    r.flavor
                ),
                false => format!("{} ({})", runtimes::runtime_label(i, r), r.flavor),
            })
            .collect();
        tags.extend(
            self.local_sets
                .iter()
                .enumerate()
                .map(|(i, set)| match set.owner_tid {
                    Some(tid) => format!("{} (lwp {tid})", runtimes::local_set_label(i, set)),
                    None => runtimes::local_set_label(i, set),
                }),
        );
        tags
    }
}

/// Run one command against an attached session.
pub fn dispatch(
    session: &Session<'_>,
    command: Command,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<Flow> {
    match command {
        Command::Census {
            threads,
            tasks,
            futures,
            top,
        } => {
            session.note_version_ceiling();
            let sections = summary::Sections::select(threads, tasks, futures);
            tasks::exec_census(session, sections, top, out)?
        }
        Command::FindTypes { needle } => types::find(&session.ctx.view, &needle, out)?,
        Command::Graph => graph::exec_graph(session, out)?,
        Command::Info => exec_info(session, out)?,
        Command::Print { addr, ty, render } => {
            print::exec_print(session, addr, &ty.join(" "), render, out)?
        }
        Command::Runtime {
            scope,
            drivers,
            shared,
            render,
        } => {
            let fields = runtimes::Fields::select(drivers, shared);
            runtimes::exec_runtime(session, scope, fields, render, out)?
        }
        Command::Runtimes => runtimes::exec_runtimes(session, out)?,
        #[cfg(feature = "snapshot")]
        Command::Snapshot { output } => snapshot_cmd::exec_snapshot(session, &output, out)?,
        Command::Sync { addr } => sync::exec_sync(session, addr, out)?,
        Command::Tasks { futures, task } => {
            session.note_version_ceiling();
            tasks::exec_tasks(session, futures, &task, out)?
        }
        Command::Threads { frames, render } => threads::exec_threads(session, frames, render, out)?,
        Command::Trace {
            target,
            verbose,
            render,
            no_elide,
            elide,
        } => {
            session.note_version_ceiling();
            let elide = reify::ElideOverride {
                no_elide,
                types: elide
                    .into_iter()
                    .map(|spec| types::resolve_elide_spec(&session.ctx.view, spec))
                    .collect::<Result<_>>()?,
                impls: session.impl_fold.clone(),
            };
            let opts = TraceOpts {
                verbose,
                render,
                elide: &elide,
                theme,
            };
            trace::exec_trace(session, target, &opts, out)?
        }
        Command::Type {
            name,
            recursive,
            depth,
        } => types::describe(
            &session.ctx.view,
            &name,
            &session.impl_fold,
            recursive,
            depth,
            out,
        )?,
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
        if exits_quietly(&e) {
            return;
        }

        let _ = writeln!(io::stderr(), "Error: {e:?}");
        std::process::exit(1);
    }
}

/// A broken pipe is the reader hanging up — `hansei … | head` — not a
/// failure: the answer ends, quietly and successfully.
fn exits_quietly(e: &anyhow::Error) -> bool {
    e.downcast_ref::<io::Error>()
        .is_some_and(|io_err| io_err.kind() == io::ErrorKind::BrokenPipe)
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
        // Named for the attach rather than for the core: either file
        // can be the one that failed, and the cause says which.
        let proc = Proc::open_core_with_program(&args.core, args.program.as_deref())
            .with_context(|| format!("failed to attach to {}", args.core.display()));
        (proc, bundle.join().expect("bundle loader panicked"))
    });
    let (proc, bundle) = (proc?, bundle?);
    check_program(&proc, args)?;
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
    // What ended the process, or that nothing did: a core with no
    // fatal signal is a live capture, which is worth saying outright —
    // "why does hansei show no crash?" is the question this preempts.
    match session.proc.fatal_signal() {
        Some(sig) => {
            let lwp = sig
                .lwp
                .map(|tid| format!(", taken on lwp {tid}"))
                .unwrap_or_default();
            writeln!(out, "signal: {}{lwp}", summary::fatal_signal_line(&sig))?;
        }
        None => writeln!(out, "signal: none recorded (a live capture, not a crash)")?,
    }
    writeln!(
        out,
        "{} worker thread(s), {} task(s)",
        session.workers.len(),
        session.tasks.tasks.len()
    )?;
    // What the target's executors are is `runtimes`' question: an
    // attach summary says how many there are to go and look at, and
    // leaves naming them to the listing that can afford the room.
    let sets = match session.local_sets.is_empty() {
        true => String::new(),
        false => format!(
            ", {}",
            summary::counted(session.local_sets.len(), "local set")
        ),
    };
    writeln!(
        out,
        "{}{sets} (see `runtimes`)",
        summary::counted(session.runtimes.len(), "runtime")
    )?;
    Ok(())
}

/// Hold `--program` to what the core says the executable was.
///
/// A Linux core carries no symbol table — `.symtab` is not `SHF_ALLOC`,
/// so it is never in the address space there is to dump — and the path
/// the core records for the executable is rarely still right on the
/// machine reading it. That makes the binary a third required input
/// rather than a convenience: without it not one symbol resolves, and
/// the attach dies at the thread-local the runtime lives behind.
///
/// *Which* binary is just as load-bearing. The debug build that
/// produced the bundle resolves every symbol *name* and shares none of
/// the addresses, so the fingerprint passes in full and every task
/// comes out named after whatever now sits at its address. The build
/// id is what separates the two, and it is the only exact check there
/// is between a core and a file.
fn check_program(proc: &Proc, args: &SessionArgs) -> Result<()> {
    if !proc.needs_program() {
        if let Some(path) = &args.program {
            writeln!(
                io::stderr(),
                "warning: ignoring --program {}; this core carries its own \
                 symbol tables",
                path.display()
            )?;
        }
        return Ok(());
    }

    let Some(path) = &args.program else {
        let named = proc
            .exec_name()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "the executable".to_owned());
        anyhow::bail!(
            "--program is required for a Linux core: the core carries no \
             symbol table, so {named} has to be read alongside it. Pass the \
             binary that ran — not the debug build behind --bundle, which \
             shares none of its addresses."
        );
    };

    let Some(ids) = proc.build_ids() else {
        return Ok(());
    };
    if !ids.disagree() {
        if unverifiable(&ids) {
            writeln!(
                io::stderr(),
                "warning: no build id to check {} against the core with",
                path.display()
            )?;
        }
        return Ok(());
    }

    let hex = |id: &Option<Vec<u8>>| match id {
        Some(id) => id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        None => "none".to_owned(),
    };
    let complaint = format!(
        "{} is not the binary this core was taken from: the core's \
         executable has build id {}, this file has {}",
        path.display(),
        hex(&ids.core),
        hex(&ids.program),
    );
    anyhow::ensure!(args.force, "{complaint}\nPass --force to proceed anyway.");
    writeln!(io::stderr(), "warning: {complaint}; output may be wrong")?;
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
    let sample = missing_sample(&fp.missing);
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

/// Whether the id pair leaves the match unverified rather than agreed:
/// nothing to check against is not evidence of a mismatch — a binary
/// can be linked without a build id, and a core can dump too little of
/// the executable to carry one — but it is worth a warning.
fn unverifiable(ids: &proc::BuildIds) -> bool {
    ids.core.is_none() || ids.program.is_none()
}

/// The first few missing symbols, demangled, and a count of the rest:
/// enough to recognize the mismatch without pages of names.
fn missing_sample(missing: &[String]) -> String {
    let mut sample = missing
        .iter()
        .take(5)
        .map(|s| format!("  {:#}", rustc_demangle::demangle(s)))
        .collect::<Vec<_>>()
        .join("\n");
    if missing.len() > 5 {
        sample.push_str(&format!("\n  ... and {} more", missing.len() - 5));
    }
    sample
}

/// Find the lwps holding a tokio `Context`, through the thread-local
/// the bundle names.
fn discover_workers<T: proc::Target>(
    lwps: &[proc::LwpInfo],
    ctx: &bundle::Context<'_, T>,
) -> Result<Vec<bundle::Worker>> {
    let workers = ctx.find_workers(lwps)?;
    anyhow::ensure!(
        !workers.is_empty(),
        "no lwp has a tokio Context in thread-local storage; is this a tokio program?"
    );
    Ok(workers)
}

/// Report a walk's non-fatal errors the way every command does: one
/// warning line per error, on stderr.
fn print_warnings<'a>(errors: impl IntoIterator<Item = &'a anyhow::Error>) -> io::Result<()> {
    for line in warning_lines(errors) {
        writeln!(io::stderr(), "{line}")?;
    }
    Ok(())
}

/// The warning spelling itself, apart from the stream it goes to: the
/// `warning:` prefix and the error with its whole context chain.
fn warning_lines<'a>(errors: impl IntoIterator<Item = &'a anyhow::Error>) -> Vec<String> {
    errors
        .into_iter()
        .map(|err| format!("warning: {err:#}"))
        .collect()
}

/// The version-ceiling warning a walk command should print now: the
/// notice, stated once — the first walk command of a session takes it,
/// later ones (and every command on an undrifted target) get `None`.
fn version_ceiling_line(meta: &hansei_bundle::Meta, noticed: &Cell<bool>) -> Option<String> {
    if noticed.replace(true) {
        return None;
    }
    contract::version_ceiling_notice(meta).map(|notice| format!("warning: {notice}"))
}

#[cfg(test)]
mod ceiling_notice_tests {
    use super::version_ceiling_line;

    use hansei_bundle::{FamilyCeiling, Meta};

    use std::cell::Cell;

    fn drifted() -> Meta {
        Meta {
            tokio_version: Some(semver::Version::new(1, 60, 0)),
            newest_family: Some(FamilyCeiling {
                name: "v1_53".into(),
                major: 1,
                minor: 53,
            }),
            ..Meta::default()
        }
    }

    /// A session states the drift once: the first walk command prints
    /// the warning, the rest stay quiet — a REPL over one target is
    /// not told the same fact per line.
    #[test]
    fn test_a_drifted_target_is_noticed_once() {
        let noticed = Cell::new(false);
        let line = version_ceiling_line(&drifted(), &noticed)
            .expect("the first walk command states the drift");
        assert!(line.starts_with("warning: "), "{line}");
        assert!(line.contains("tokio 1.60.0"), "{line}");
        assert_eq!(version_ceiling_line(&drifted(), &noticed), None);
    }

    /// An undrifted target prints nothing, and still consumes the
    /// session's one statement — there is nothing left unsaid.
    #[test]
    fn test_an_undrifted_target_stays_quiet() {
        let noticed = Cell::new(false);
        assert_eq!(version_ceiling_line(&Meta::default(), &noticed), None);
        assert!(noticed.get());
    }
}

#[cfg(test)]
mod glue_tests {
    use super::{exits_quietly, unverifiable, warning_lines};
    use std::io;

    /// Only a broken pipe ends the answer quietly: any other error —
    /// io or not — is a failure worth reporting and a nonzero exit.
    #[test]
    fn test_only_a_broken_pipe_exits_quietly() {
        let broken = anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe));
        assert!(exits_quietly(&broken));
        let other_io = anyhow::Error::from(io::Error::from(io::ErrorKind::NotFound));
        assert!(!exits_quietly(&other_io));
        assert!(!exits_quietly(&anyhow::anyhow!("not io at all")));
    }

    /// Either id missing leaves the match unverified; both present is
    /// checked, whichever way the comparison then goes.
    #[test]
    fn test_either_missing_id_is_unverifiable() {
        let ids = |core: bool, program: bool| proc::BuildIds {
            core: core.then(|| vec![1, 2]),
            program: program.then(|| vec![1, 2]),
        };
        assert!(unverifiable(&ids(false, false)));
        assert!(unverifiable(&ids(true, false)));
        assert!(unverifiable(&ids(false, true)));
        assert!(!unverifiable(&ids(true, true)));
    }

    /// One warning line per error, prefix and context chain included.
    #[test]
    fn test_warnings_spell_the_whole_context_chain() {
        use anyhow::Context;
        let errors = [
            anyhow::anyhow!("plain"),
            Err::<(), _>(anyhow::anyhow!("inner"))
                .context("outer")
                .unwrap_err(),
        ];
        assert_eq!(
            warning_lines(&errors),
            ["warning: plain", "warning: outer: inner"]
        );
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::missing_sample;

    /// Five missing symbols print whole; the tail count starts at the
    /// sixth, and counts only what the sample left out.
    #[test]
    fn test_the_sample_counts_only_past_five() {
        let missing: Vec<String> = (0..5).map(|i| format!("sym{i}")).collect();
        let sample = missing_sample(&missing);
        assert_eq!(sample.lines().count(), 5, "{sample}");
        assert!(!sample.contains("more"), "{sample}");

        let missing: Vec<String> = (0..6).map(|i| format!("sym{i}")).collect();
        let sample = missing_sample(&missing);
        assert!(sample.ends_with("  ... and 1 more"), "{sample}");
        assert!(sample.contains("sym4"), "{sample}");
        assert!(!sample.contains("sym5"), "{sample}");
    }
}

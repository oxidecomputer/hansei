// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context as _, Result};
use clap::{ArgGroup, Args, Parser, Subcommand};
use hansei_bundle::{Bundle, BundleView};
use hansei_runtime::heap::umem::UmemHeap;
use hansei_runtime::heap::view::{GateCounts, HeapView};
use hansei_runtime::tokio::graph::{self as rt_graph, Analysis};
use hansei_runtime::tokio::{bundle, census, contract};
use proc::{Proc, Target};

#[cfg(not(target_os = "illumos"))]
use mimalloc::MiMalloc;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod bundle_cmd;
mod cursor;
mod futures;
mod graph;
mod info;
#[cfg(test)]
mod offline;
mod output;
mod pattern;
mod print;
mod registers;
mod relations;
pub mod repl;
mod runtimes;
mod settings;
#[cfg(feature = "snapshot")]
mod snapshot_cmd;
pub mod summary;
mod sync;
mod tasks;
mod threads;
mod trace;
pub mod types;
mod umem;
mod whatis;

// mimalloc's vendored C sources fail to assemble with the illumos
// gcc/gas toolchain. Everywhere else it is what extraction's
// allocation-heavy interning was tuned against.
#[cfg(not(target_os = "illumos"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// The command line names a target; what to ask of it comes from
/// `--exec`, or failing that from stdin, at a prompt or from a pipe.
///
/// A subcommand instead of a target says to work on tokio-info *files*
/// — producing one, or reporting what is in one — and opens no session.
#[derive(Parser)]
#[command(
    about = "Inspect a tokio runtime in a core dump",
    long_about = "Inspect a tokio runtime in a core dump.\n\n\
                  The command line names a target. What to ask of it is read \
                  from stdin — at a prompt when stdin is a terminal, otherwise \
                  one command per line, stopping at the first failure — or \
                  given with --exec, which asks and exits.\n\n\
                  Naming no target but the `tokio-info` subcommand instead \
                  works on tokio-info files rather than on a running target's \
                  remains.",
    after_help = "Examples:\n  \
                  hansei --core core.app --tokio-info app.tinfo\n  \
                  hansei --core core.app --debug-info app.debug\n  \
                  hansei --core core.app --tokio-info app.tinfo -e 'tasks; graph'\n  \
                  echo 'trace 42 -v' | hansei --core core.app --tokio-info app.tinfo\n  \
                  hansei tokio-info extract app.debug -o app.tinfo\n  \
                  hansei tokio-info extract app --debug-info app.dbg -o app.tinfo\n\n\
                  Type `help` for the commands a session accepts.",
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[command(flatten)]
    session: Option<SessionArgs>,

    /// Commands to run instead of reading stdin, `;` between them — a
    /// `;` inside double quotes, as an array type's name needs, does
    /// not separate. Repeat the flag to add more; the session exits
    /// when they are answered, or at the first one that fails.
    #[arg(long, short, value_name = "COMMANDS")]
    exec: Vec<String>,
}

/// What argv can ask for other than a session on a target.
#[derive(Subcommand)]
enum Cmd {
    /// Produce a tokio-info file, or report what one holds.
    ///
    /// Distinct from the session's `--tokio-info` flag, which names a
    /// file to read: this side writes and inspects the files that
    /// flag consumes.
    TokioInfo {
        #[command(subcommand)]
        cmd: bundle_cmd::BundleCmd,
    },
}

/// What it takes to attach: the pair of files, and how strictly they
/// have to agree.
#[derive(Args)]
#[command(group = ArgGroup::new("types").required(true).args(["tokio_info", "debug_info"]))]
struct SessionArgs {
    /// The core dump to open.
    #[arg(long, short)]
    core: PathBuf,

    /// Tokio runtime debug info extracted from the debug build
    /// (produced by `hansei tokio-info extract`).
    #[arg(long, short)]
    tokio_info: Option<PathBuf>,

    /// Debug info to extract from now, instead of naming a file with
    /// --tokio-info: a build of the target carrying DWARF — the full
    /// binary, or split debug info (a companion file, a dSYM, a dwp)
    /// with --binary naming the binary it was split from.
    ///
    /// Extraction is the slower way in — a large binary's DWARF costs
    /// seconds — so it is the answer for a one-off look, and `hansei
    /// tokio-info extract` is the answer when the same target will be
    /// opened again.
    #[arg(long, short, value_name = "PATH")]
    debug_info: Option<PathBuf>,

    /// The executable the core was taken from — the binary that ran.
    ///
    /// Required for a Linux core, which carries no symbol table of its
    /// own and names a path that is rarely still right on the machine
    /// reading the core; an illumos core carries its own symbols. A
    /// separate debug build of the same source is not this binary: it
    /// shares none of the addresses, and the build id tells the two
    /// apart.
    #[arg(long, short, value_name = "PATH")]
    binary: Option<PathBuf>,

    /// Proceed even if the tokio info's symbols don't all resolve in
    /// the target, or `--binary` is not the binary the core was taken
    /// from.
    #[arg(long, short)]
    force: bool,

    /// Attach even if non-essential walk paths are broken against this
    /// tokio's layouts, degrading whatever reads them. By default any
    /// broken path refuses the attach with a report of what moved.
    #[arg(long)]
    best_effort: bool,

    /// Read only one of the target's runtimes, by its index in the
    /// discovered list (`runtimes --list` names them). By default every
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

impl SessionArgs {
    /// Where this session's types come from, as the attach summary
    /// should say it. clap's required group leaves exactly one of the
    /// two named.
    fn bundle_source(&self) -> BundleSource<'_> {
        match (&self.tokio_info, &self.debug_info) {
            (Some(path), _) => BundleSource::File(path),
            (None, Some(path)) => BundleSource::Extracted(path),
            (None, None) => unreachable!("clap requires --tokio-info or --debug-info"),
        }
    }
}

/// A session's bundle: the tokio-info file it read, or the debug info
/// it extracted one from at launch.
enum BundleSource<'a> {
    File(&'a Path),
    Extracted(&'a Path),
}

impl std::fmt::Display for BundleSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Extracted(path) => write!(f, "extracted from {}", path.display()),
        }
    }
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
    /// `threads` for a thread, `tasks` for the task rows behind a
    /// tally, `futures` for the futures counted off the await chains,
    /// `graph` for what waits on what.
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
    /// the runtime the way `runtimes` lists it — `runtime 0 @ 0x7f11c0`
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
    /// by state, by what it is waiting on, and by the future types
    /// most of them share. A wait is named by the primitive
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
    /// complete, or that the tokio info cannot name what some are
    /// running, is worth knowing.
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
    /// are kept, though, so a `futures`, `graph` or `whatis`
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

        /// Show at most this many entries in each "most of them are
        /// this" listing; the rest are summed into a final row. The
        /// census keeps its own default rather than reading `config
        /// limit`, whose "everything" would make every tally a page.
        #[arg(long, short = 'l', value_name = "N", default_value_t = 5)]
        limit: usize,
    },

    /// Move the cursor one await frame inward — toward #0, the most
    /// recently polled frame — and print the frame line it lands on.
    /// Any words after it are a command to run at the new frame
    /// (`down locals`); a refused move runs nothing.
    Down {
        /// The command to run after a successful move.
        #[arg(
            value_name = "COMMAND",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        then: Vec<String>,
    },

    /// List the types whose name matches a pattern.
    // Hidden from `help` and completion while the type-inspection
    // surface is reconsidered — not removed: it still parses and runs.
    #[command(hide = true)]
    FindTypes {
        /// The pattern to look for: a case-insensitive regex, so a
        /// plain substring types as itself and regex metacharacters
        /// in a type name are escaped with a backslash.
        needle: String,
    },

    /// Move the cursor within the selected chain — the await frames
    /// `trace` numbers, #0 the most recently polled — and print the
    /// frame line it lands on; with
    /// no index, the current frame's. Words after the index are a
    /// command to run at that frame (`frame 7 locals`, `frame 7
    /// print .self`); a refused move runs nothing. Only the await
    /// chain is addressable: a running task's native continuation
    /// belongs to `threads`.
    Frame {
        /// The frame number to move to, as `trace` numbers them.
        /// Naming none prints the current frame.
        index: Option<usize>,

        /// The command to run after a successful move.
        #[arg(
            value_name = "COMMAND",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        then: Vec<String>,
    },

    /// Select a lone future as the cursor, by the hex address the
    /// listings print — for the chains no task contains, such as a
    /// FuturesUnordered child in its heap node. An address some task
    /// holds selects that task instead, positioned at the holding
    /// frame — one cursor, never two. Either way it prints the future
    /// as one labelled line per field: its type, where it sits (the
    /// holding frame and local, or the set whose child node it is,
    /// and the task either belongs to), its owner where the target
    /// holds more than one group, its suspend state and depth, what
    /// it waits on, and the census's finds inside it under their
    /// counts — the same finds `task --futures` lists. Bare `future`
    /// prints the cursor's lone future; `-v` prints its await chain
    /// under the block.
    Future {
        /// The future's address, in hex with a required leading `0x`
        /// (see `futures`). Naming none prints the cursor's
        /// lone future.
        #[arg(value_parser = parse_hex_addr)]
        addr: Option<u64>,

        /// Print the future's await chain under its fields.
        #[arg(long, short)]
        verbose: bool,
    },

    /// List every future the census found in flight beside the tasks'
    /// own await chains — one table row per find: its address, the
    /// task whose frames it was found in, where it sits (the holding
    /// frame and local, or the set whose child node it is), its own
    /// suspend state, what it waits on, and its concrete type, never
    /// truncated. `--limit` is the only cut, and cutting earns a
    /// footer counting what was left out.
    ///
    /// This is the population `task --futures` lists under each task,
    /// as one listing: every future sitting in a frame's local off the
    /// await chain — a `select!`/`join!` arm mid-flight, one stored
    /// across an await, a futurelock's abandoned lock — and every
    /// child a FuturesUnordered polls, in its heap node. A JoinSet's
    /// members are tasks, with rows in `tasks`, so they are not here.
    /// Each address is what `trace <0xaddr>` follows, `whatis
    /// <0xaddr>` locates, and `future <0xaddr>` selects. The listing
    /// is a lower bound for the reasons `help tasks` gives: a future
    /// behind an unrecognized pointer is not found, and a stopped scan
    /// says so on stderr.
    ///
    /// Filters are the selection: repeatable `--with FIELD ARG` /
    /// `--without FIELD ARG` clauses AND together, and `--group FIELD`
    /// tallies the survivors. The string fields — type, state,
    /// waiting-on, local — are case-insensitive regexes over the
    /// spelled value; kind (`held` or `child`), task (the id as
    /// `tasks` prints it), rt (an index or `0x` handle), frame and
    /// addr are exact; depth, holds and sets compare counts, spelled
    /// '>N', '<N' or '=N' (quote them from a shell). `--group type` is
    /// the overview of a target with thirty thousand of these.
    ///
    /// `--exec COMMAND` takes the rest of the line as one session
    /// command and runs it once per surviving future, the command's
    /// omitted target filled with that future — `futures --with type
    /// acquire --exec trace -v` traces every match, each run under a
    /// `future 0x…` heading. The target is the future itself, even one a
    /// task holds: `trace` follows its own chain, `print` and `locals`
    /// its own frames, where `future 0x…` would have selected the
    /// holding task. One future's failure never stops the loop, the
    /// listing closes with `[Executed against N futures, M failed]`, and
    /// the command itself fails after the loop when M is not zero.
    /// One future's every field — who holds it and where, its state
    /// and depth, what it waits on, and what the census found inside
    /// it — is `future 0x…`, so `futures --with type acquire --exec
    /// future` prints each match in full.
    Futures {
        /// Show at most this many futures — or, under --group, this
        /// many buckets; a footer counts what the cut left out.
        /// Everything is listed when the flag is absent and no
        /// `config limit` stands.
        #[arg(long, short = 'l', value_name = "N")]
        limit: Option<usize>,

        /// Keep only the futures whose FIELD matches ARG; repeat for
        /// more clauses, which AND. Fields: type, state, waiting-on,
        /// local (case-insensitive regexes); kind, task, rt, frame,
        /// addr (exact); depth, holds, sets ('>N', '<N', '=N'). ARG
        /// may list alternatives, `held,child`, of which any matches;
        /// a literal comma is `\,`.
        #[arg(long, short = 'w', num_args = 2, value_names = ["FIELD", "ARG"])]
        with: Vec<String>,

        /// Drop the futures whose FIELD matches ARG; the same fields
        /// as --with.
        #[arg(long, short = 'W', num_args = 2, value_names = ["FIELD", "ARG"])]
        without: Vec<String>,

        /// Bucket the surviving futures by FIELD's spelled value: one
        /// `COUNT VALUE` row per bucket, most numerous first, each
        /// with a few member addresses; a future with nothing in the
        /// field lands in `<empty>`.
        #[arg(long, short = 'g', value_name = "FIELD")]
        group: Option<String>,

        /// Run a session command once per surviving future, under
        /// that future as its omitted target. Takes the rest of the
        /// line, the command's own flags included, so it must be the
        /// last flag: `futures --with kind set --exec trace -l 3`.
        /// Runs after --limit.
        #[arg(
            long,
            short = 'e',
            num_args = 1..,
            allow_hyphen_values = true,
            value_name = "COMMAND",
            conflicts_with = "group"
        )]
        exec: Vec<String>,

        // Addresses are the singular selector's; kept so the refusal
        // can name the way forward rather than clap's bare
        // "unexpected argument".
        #[arg(value_name = "ADDR", hide = true)]
        addr: Vec<String>,
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
    Graph {
        /// Show at most this many trees, counted by their roots — in
        /// task-id order, as always — with a footer counting what the
        /// cut left out.
        #[arg(long, short = 'l', value_name = "N")]
        limit: Option<usize>,
    },

    /// Print the command history: every line typed at a prompt, in
    /// this session and the ones before it, oldest first and numbered.
    /// A scripted session (a pipe, `--exec`) keeps none and says so.
    History {
        /// Print only the last N entries.
        #[arg(value_name = "N")]
        last: Option<usize>,
    },

    /// Show what the target records about its process: the core and
    /// tokio info attached and how far the symbols resolve; the process
    /// identity (ids, model, start time, argv, environment — what gdb's
    /// `info proc` and mdb's `::status`, `::pargs` and `::penv`
    /// answer); and what ended it and where.
    Info,

    /// List the variables the cursor's current frame holds live — the
    /// locals a verbose `trace` or `frame` nests under the frame line,
    /// flat and without the rest of the frame. The cursor must stand
    /// on a frame: `task`, `future` or `frame` selects one.
    Locals,

    /// Dump what libumem knows about the target's heap: every cache the
    /// walk believed, with its slabs and its live and freed chunk
    /// counts, the self-consistency check over the finished index, and
    /// a verdict for each address given.
    ///
    /// A target whose allocator is not libumem — umem is per-process
    /// opt-in — has nothing here and says so.
    #[command(hide = true)]
    UmemAudit {
        /// Addresses to locate in the heap, written in hex with a
        /// required leading `0x`.
        #[arg(value_parser = parse_hex_addr)]
        addrs: Vec<u64>,

        /// Print every chunk of one liveness instead, one address per
        /// line: `live` is the set mdb's `::walk umem` enumerates, for
        /// a differential against it, and `freed` the chunks this walk
        /// found on a slab freelist.
        #[arg(long, value_name = "SET")]
        dump: Option<umem::Dump>,
    },

    /// Render a local of the cursor frame, or memory at an address as
    /// a named type, and navigate into it: every `...` the renderer
    /// elides is reachable by a path.
    ///
    /// The first word names a local — one of the names `locals`
    /// lists, a member of the frame's future — and bare `print` is
    /// the frame itself: the active variant of that future, whose
    /// locals are its members. An address instead (`print 0x7f10
    /// "Vec<(u64, u64)>"`) reads that memory as the type the next
    /// word names, spelled as `find-types` lists it — double-quoted
    /// when it holds a space or a `;` — or as a type id. Nothing
    /// checks the type against the address: the memory renders as
    /// whatever was asked for. `whatis` says what actually stands
    /// there.
    ///
    /// Everything after the root is a path, in the same word or the
    /// next ones: `.member` navigates the way Rust's dot does (through
    /// references, `Box`, `Arc`/`Rc`, `Pin`, `NonNull`, and into an
    /// enum's active variant — an inactive one refuses with the
    /// active variant's name), `[3]` indexes a sequence (on a map, the
    /// Nth entry in display order, a pair `.0`/`.1` take apart),
    /// `[a..b]`/`[a..=b]`/`[..b]`/`[a..]` select a run of elements,
    /// and `*` dereferences explicitly — the only way through a raw
    /// pointer. A range fans out: every later step applies per
    /// element, each printed under its `[i]` heading and exempt from
    /// the max-array-values cap, since a range is the reader saying
    /// how many. Depth counts from the end of the path.
    Print {
        /// The local's name, with any path steps behind it
        /// (`values[..10]`, `foo.bar`), or nothing for the frame, or
        /// an address followed by the type to read it as; later words
        /// are further steps, each starting with `.`, `[` or `*`.
        #[arg(value_name = "LOCAL[PATH] | ADDR TYPE")]
        args: Vec<String>,
    },

    /// Print the cursor lwp's registers, annotated with what each
    /// value points into: a thread cursor, or a task cursor whose
    /// task is running on a thread — selecting a running task selects
    /// the lwp polling it. A task off every thread has no trap state
    /// to show.
    Regs,

    /// Show each runtime's own state, read straight through the tokio
    /// info's layouts: its drivers, and the scheduler state its workers
    /// share. Naming no section shows both, and naming no runtime shows
    /// every one of them, each under a heading.
    ///
    /// `--list` asks the other question instead: not what one runtime
    /// holds, but which executors there are at all — one row per
    /// discovered runtime, then one per discovered `LocalSet`, with the
    /// tasks and futures the merged population attributes to it.
    ///
    /// The index each row carries is the one the task listing tags its
    /// blocks with, the one `--runtime` selects by, and the one this
    /// command takes; the handle address beside it names the same thing
    /// and can be given anywhere the index can.
    ///
    /// A listed row says where its group runs — the lwps inside it — or,
    /// when nothing is inside it, the route discovery reached it by. That
    /// distinction is worth reading, because the list is a lower bound
    /// by construction: a runtime no thread is inside is only found
    /// when something already discovered points at it, so one whose
    /// `block_on` has returned and whose tasks nothing outside it
    /// names cannot be found at all.
    ///
    /// The future counts are the census's, so the first `runtimes
    /// --list` walks every task's await chain — the slowest thing a
    /// session does on a large target. The walk is kept, so a later
    /// `census`, `futures`, `graph` or `whatis` costs nothing.
    Runtimes {
        /// List the executors instead of showing their state: one row
        /// per runtime and per `LocalSet`, with what each holds.
        #[arg(long, short, conflicts_with_all = ["drivers", "shared", "scope"])]
        list: bool,

        /// Print the drivers: io, signal, time, and the clock.
        #[arg(long, short = 'D')]
        drivers: bool,

        /// Print the scheduler state the workers share: the owned-task
        /// set, the injection queue, the idle set and the per-worker
        /// remotes.
        #[arg(long, short)]
        shared: bool,

        /// Show only these runtimes, each named by its index in the
        /// listing or by the handle address printed beside it there in
        /// hex with a leading 0x. All of them are shown when none is
        /// named.
        #[arg(value_name = "RUNTIME", value_parser = parse_runtime_scope)]
        scope: Vec<RuntimeScope>,
    },

    /// Write this session's tokio info to a file `--tokio-info` can
    /// take next time, saving the launch-time extraction. Only a
    /// session that extracted at launch (`--debug-info`) has anything
    /// to save; one that read a tokio-info file refuses — that file
    /// already exists.
    #[command(name = "save-tokio-info")]
    SaveTokioInfo {
        /// Where to write it (`.tinfo` by convention).
        output: PathBuf,
    },

    /// Show or change the session's settings. The render keys —
    /// depth, max-string-len, max-array-values, ugly — govern
    /// `trace -v` locals and every other render outright; `limit`
    /// also backs the listings' `--limit` flags, which override the
    /// session value for that command only (`census --limit` has a
    /// default of its own and never reads it); `truncate-names` cuts the
    /// listings' name columns, the names `census` tallies, and the
    /// names ending `trace`'s frame lines, to the terminal's width,
    /// an ellipsis marking each cut — a `!` pipeline's output included, since its
    /// last command writes to the same terminal — and never touches
    /// output that is not headed for one. The values live for the
    /// session only. Bare `config` prints every key at its current
    /// value; `config KEY` prints one; `config KEY VALUE` changes it.
    Config {
        /// The key to show or change. Naming none prints them all.
        key: Option<String>,

        /// The new value. Naming none prints the key's current value.
        /// `ugly` and `truncate-names` take on or off; `limit` takes
        /// a count, or `off` for no limit.
        value: Option<String>,
    },

    /// Capture a replayable snapshot of everything the analysis reads
    /// from the target: task enumeration and every task's
    /// await chain are driven once with a recording wrapper in place,
    /// and the memory, symbol, and lwp state they touched is written
    /// out. Together with tokio info extracted from a *separate* build
    /// of the same source, the snapshot feeds the offline two-binary
    /// tests.
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
    /// Beside the semaphores, a *joined* task is a resource too — its
    /// block lists who waits to join it, who holds its `JoinHandle`
    /// unawaited, and the `JoinSet` that will collect it — and so is a
    /// driven task set, whose block lists its members by state. Only a
    /// task some other task waits on, holds, or drives earns a join
    /// block in the bare listing; `--kind semaphore|join|set` narrows
    /// to one family.
    ///
    /// The address heading each block is the one `trace` prints in its
    /// `waiting on … (semaphore 0x…)` line, and the one this command
    /// takes to narrow to a single block: a semaphore, a set, or a
    /// task's allocation. An address none of those own falls through
    /// to the tasks whose frames hold it by value (`--kind address`
    /// asks for that reading outright). With a task cursor standing
    /// (`task 129`, or the `task 129 sync` prefix) and no address, the
    /// listing narrows to every relation that task is party to.
    /// Discovery runs through the tasks' await chains, the census and
    /// the futurelock scan, not a sweep of memory: a resource nothing
    /// touches is not listed, and nothing at all prints on a target
    /// with no contention.
    // Hidden from `help` while its usefulness is reconsidered — not
    // yet removed: it still parses and runs.
    #[command(hide = true)]
    Sync {
        /// One resource to show, by the address the listings print,
        /// in hex with a required leading `0x`. Every one by default.
        #[arg(value_parser = parse_hex_addr)]
        addr: Option<u64>,

        /// Show one block family only: semaphore, join, set — or
        /// address, the by-value fallback, which needs the address.
        #[arg(long, value_enum)]
        kind: Option<sync::Kind>,
    },

    /// Select a task as the cursor: the position `trace`, `whatis` and
    /// `frame` answer about when given no target. A decimal id selects
    /// that task at frame #0; a 0x address selects the task whose
    /// allocation contains it, positioned at the await frame that
    /// claims the address (`whatis` semantics), and refuses when no
    /// task contains it. Selecting a running task also selects the lwp
    /// polling it; selecting an idle one clears any thread cursor.
    /// Either way it prints the task as one labelled line per field:
    /// state, owner, type, the leaf await site, what it waits on,
    /// every slot holding its waker (and where each sits — the wheel
    /// entry, the io slot, the wake-queue node), the spawn site,
    /// where the future is defined, and the census's counts — how
    /// many futures it holds in its own frames beside its await
    /// chain, and how many sets it drives from them. `--futures`
    /// lists each find under its count.
    ///
    /// Those counts are of what no task listing otherwise shows — a
    /// `select!` arm held in a frame, a FuturesUnordered's children, a
    /// JoinSet's tasks. They are counted apart because a set is a
    /// container rather than a future in flight: what it holds is the
    /// count beside it, and the numbers add up rather than
    /// overlapping.
    ///
    /// The `join sets` row counts what its sets hold in two parts
    /// where it drives both kinds, because they are two populations:
    /// a JoinSet holds *tasks*, which `tasks` already lists, and a
    /// FuturesUnordered holds futures, which nothing else shows at
    /// all. A kind it drives none of goes unmentioned rather than
    /// counted at zero.
    ///
    /// A task's own await chain is what `trace` prints: the future it
    /// is suspended in, the one that is awaiting, and so on down to
    /// the leaf it is parked on. That chain is the only thing the task
    /// polls when it wakes. `--futures` lists what it has in flight
    /// *beside* it.
    ///
    /// A row under `held futures` is a future sitting in a frame's
    /// local, off the await chain: a `select!`/`join!` arm mid-flight,
    /// one stored across an await, or a futurelock's abandoned lock.
    /// Whether it will ever be polled again is not knowable here — a
    /// select arm is polled at every wakeup, a futurelock's never.
    /// `graph` is what decides that. The same find in a set child's
    /// frames is printed under that child and marked `held`, since no
    /// heading over it says so.
    ///
    /// A FuturesUnordered is listed under `join sets` with the
    /// children it polls. A child lives in a heap node rather than in
    /// a frame, so neither a task listing nor a trace reaches it. An
    /// empty slot is a completed child the set has not reaped yet —
    /// not a future outstanding, and counted apart from the ones in
    /// flight.
    ///
    /// A JoinSet — and so anything built on one, such as omicron's
    /// `ParallelTaskSet` — is listed there too, with the tasks it
    /// holds, by the ids `trace` takes. Those are spawned tasks: each
    /// is a `tasks` row of its own, runs on whatever worker picks it
    /// up, and keeps running whether or not the task holding the set
    /// ever wakes. So the set says *what this task is waiting to
    /// join*, not what it is polling. A member the listing has no row
    /// for is one no runtime owns any longer: complete and waiting to
    /// be joined, or running where this session cannot enumerate it.
    ///
    /// The scan recurses through what it finds, so a future held
    /// inside a set child is listed indented under that child rather
    /// than beside the ones its task holds itself. Read the
    /// indentation as containment: a future under a set child is
    /// *inside* it, so the rows nested under a find are not a
    /// population beside it. A joined task's own frames are not
    /// scanned from here at all — they are scanned under its own
    /// `task`, where they belong.
    ///
    /// Every count is of the finds at the top of its listing, for the
    /// same reason: a future the census reached through a set child
    /// is already inside something counted, and counting it again
    /// would make a task driving 3075 children of which each holds
    /// one future report both numbers as if they were populations to
    /// add up.
    ///
    /// Every address printed — a held future's, a set child's node —
    /// is what `trace <0xaddr>` accepts to follow that one future's
    /// own chain, and what `whatis <0xaddr>` says the whereabouts of.
    ///
    /// What is listed is found *by value* in a frame's bytes:
    /// coroutine environments, future trait objects (resolved through
    /// the vtable join), and the recognized leaf futures. Ordinary
    /// pointers are never followed, so a future reachable only behind
    /// an unrecognized Box or Arc is not here, and DWARF cannot say
    /// whether a hand-written combinator implements Future, so one is
    /// not listed itself — though the scan descends through it and
    /// any coroutine inside it is. Treat the listing as a lower bound.
    ///
    /// The descent into one local stops at `--search-depth` levels,
    /// and says so where it stopped; raise it on the command line for
    /// a target that nests futures deeper than that.
    Task {
        /// A decimal task id (see `tasks`), or a 0x address inside
        /// the task's allocation. Naming none prints the cursor's
        /// task.
        #[arg(value_parser = parse_trace_target, value_name = "ID|0xADDR")]
        target: Option<TraceTarget>,

        /// List the task's futures and task sets under their counts,
        /// rather than only counting them.
        #[arg(long, short)]
        futures: bool,
    },

    /// List every task the target's executors own — one table row per
    /// task: id, lifecycle state (with the cancel bit where set), the
    /// owning runtime or local set on targets holding more than one,
    /// the leaf await site the task is parked behind, what it waits
    /// on, and its concrete future type, never truncated. `--limit`
    /// is the only cut, and cutting earns a footer counting what was
    /// left out.
    ///
    /// Filters are the selection: repeatable `--with FIELD ARG` /
    /// `--without FIELD ARG` clauses AND together and `--group FIELD`
    /// tallies the survivors; one task's every field is `task 129`.
    /// The string fields — type, awaiting, waiting-on, waker,
    /// spawned, defined, state — are case-insensitive regexes over
    /// the spelled value; rt (an index or `0x` handle), lwp and id
    /// are exact; holds and sets compare the census's counts, spelled
    /// '>N', '<N' or '=N' (quote them from a shell).
    ///
    /// The waker field is the wakeup answer: every slot hansei
    /// decodes holding this task's waker — `timer 0x…`, `io 0x…
    /// read`, `semaphore 0x…`, `join task N` — sorted and
    /// comma-joined. `--group waker` is the overview, bucketing the
    /// same slots at the kind level — `io read`, `timer`, with
    /// identity kept where it groups usefully (`semaphore 0x…`,
    /// `join task N`) — a `select!` over several buckets by the
    /// combination; a task with no armed slot lands in `<empty>`,
    /// which is the "nothing can wake it" answer. `task` places each
    /// slot (the wake-queue node, the trailer) under its `waker:`
    /// line.
    ///
    /// `--exec COMMAND` takes the rest of the line as one session
    /// command and runs it once per surviving task, the command's
    /// omitted target filled with that task — `tasks --with type
    /// qorb --exec trace -v` traces every match, each run under a
    /// `task N` heading, and `tasks --with state running --exec task
    /// --futures` prints every running task's fields and finds. One
    /// task's failure never stops the loop: the failed run shows its
    /// error in place, the listing closes with `[Executed against N
    /// tasks, M failed]`, and the command itself fails after the loop
    /// when M is not zero — a script sees one failure, with nothing
    /// skipped.
    ///
    /// What each task has in flight beside its own await chain — the
    /// futures held in its frames, the sets it drives — is the
    /// census's to count and `task` (or `futures`) to show; the table
    /// reads the wait analysis and nothing else, so it never pays for
    /// that walk unless a holds/sets clause asks.
    Tasks {
        /// Show at most this many tasks — or, under --group, this
        /// many buckets; a footer counts what the cut left out.
        /// Everything is listed when the flag is absent and no
        /// `config limit` stands.
        #[arg(long, short = 'l', value_name = "N")]
        limit: Option<usize>,

        /// Keep only the tasks whose FIELD matches ARG; repeat for
        /// more clauses, which AND. Fields: type, awaiting,
        /// waiting-on, waker, spawned, defined, state
        /// (case-insensitive regexes); rt, lwp, id (exact); holds,
        /// sets ('>N', '<N', '=N'). ARG may list alternatives,
        /// `1,2,3`, of which any matches; a literal comma is `\,`.
        #[arg(long, short = 'w', num_args = 2, value_names = ["FIELD", "ARG"])]
        with: Vec<String>,

        /// Drop the tasks whose FIELD matches ARG; the same fields as
        /// --with.
        #[arg(long, short = 'W', num_args = 2, value_names = ["FIELD", "ARG"])]
        without: Vec<String>,

        /// Bucket the surviving tasks by FIELD's spelled value: one
        /// `COUNT VALUE` row per bucket, most numerous first, each
        /// with a few member ids; a task with nothing in the field
        /// lands in `<empty>`.
        #[arg(long, short = 'g', value_name = "FIELD")]
        group: Option<String>,

        /// Run a session command once per surviving task, under that
        /// task as its omitted target. Takes the rest of the line,
        /// the command's own flags included, so it must be the last
        /// flag: `tasks --with state running --exec trace -l 3`.
        /// Runs after --limit.
        #[arg(
            long,
            short = 'e',
            num_args = 1..,
            allow_hyphen_values = true,
            value_name = "COMMAND",
            conflicts_with = "group"
        )]
        exec: Vec<String>,

        // The ids the old grammar took, kept so the refusal can name
        // the way forward rather than clap's bare "unexpected
        // argument".
        #[arg(value_name = "TASK", hide = true)]
        task: Vec<String>,
    },

    /// Select a thread as the cursor, by its lwp id. No task root
    /// comes with it — the task-taking commands answer `no task
    /// selected` until `task` moves on — and a bare `trace` walks the
    /// thread's native stack; the hybrid trace is the task cursor's.
    /// Either way it prints the thread in full: its heading — the
    /// lwp, what it is polling, and the fatal signal where it took
    /// one — then its tokio context, the worker core it holds, and
    /// its stack, fifty frames deep at most. The lwp that took the
    /// fatal signal also shows its registers, annotated with what
    /// each value points into. The stack at any depth is `trace -l N`
    /// under the cursor, and the registers are `regs`.
    Thread {
        /// The lwp id (see `threads`). Naming none prints the
        /// cursor's thread.
        lwp: Option<u32>,
    },

    /// List every thread in the target — one table row per lwp: its
    /// name where the core records one, its place in a runtime (which
    /// worker and what its parker says, the block_on caller, a
    /// blocking-pool thread read from its stack, or no runtime at
    /// all), the task it is polling, and the top of its stack. One
    /// thread in full — its tokio context, the worker core it holds,
    /// its whole stack — is `thread N`, so `threads --with role
    /// worker --exec thread` prints every worker that way.
    ///
    /// Filters are the selection: repeatable `--with FIELD ARG` /
    /// `--without FIELD ARG` clauses AND together, and `--group FIELD`
    /// tallies the survivors. The string fields — name, role,
    /// function — are case-insensitive regexes over the spelled
    /// value; task and lwp are exact ids; has-task is yes or no.
    /// `--group role` buckets by kind — worker, blocking, block_on
    /// caller, entered runtime, no runtime — not by worker index or
    /// park state. `--exec COMMAND` runs a command once per surviving
    /// thread under a cursor on it: `threads --with has-task yes
    /// --exec trace` walks every polling thread's stack.
    Threads {
        // The lwp ids the old grammar took, kept so the refusal can
        // name the way forward rather than clap's bare "unexpected
        // argument".
        #[arg(value_name = "LWP", hide = true)]
        lwp: Vec<String>,

        /// Keep the threads whose FIELD matches ARG. Repeatable; every
        /// clause must hold. The fields are name, role, task,
        /// has-task, function and lwp. ARG may list alternatives,
        /// `2,3`, of which any matches; a literal comma is `\,`.
        #[arg(long, short = 'w', num_args = 2, value_names = ["FIELD", "ARG"])]
        with: Vec<String>,

        /// Drop the threads whose FIELD matches ARG. Repeatable, and
        /// ANDed with every other clause; the fields are the same as
        /// --with.
        #[arg(long, short = 'W', num_args = 2, value_names = ["FIELD", "ARG"])]
        without: Vec<String>,

        /// Tally the surviving threads by FIELD: one row per distinct
        /// value, most numerous first, with a few member lwps.
        #[arg(long, short = 'g', value_name = "FIELD")]
        group: Option<String>,

        /// Run COMMAND once per surviving thread, under a cursor on
        /// that thread, each run's output under a `thread N` heading.
        /// Takes the rest of the line, the command's own flags
        /// included, so it must be the last flag:
        /// `threads --with has-task yes --exec trace -l 3`.
        #[arg(
            long,
            short = 'e',
            num_args = 1..,
            allow_hyphen_values = true,
            value_name = "COMMAND",
            conflicts_with = "group"
        )]
        exec: Vec<String>,
    },

    /// Print an await chain: a task's, selected by its decimal id
    /// (see `tasks`), or a lone future's, selected by the hex address
    /// `futures` prints — a held future's address or a
    /// set child's node address; any pointer into either resolves.
    /// Either way the future type is resolved automatically, via the
    /// symbol join for a task and via the census for an address.
    ///
    /// Frames print most recent first: #0 is the most recently
    /// polled future, and the root sits at the bottom. A task that
    /// is mid-poll shows, under -n/--native, the polling thread's
    /// native stack above the chain — the frames below the task's
    /// own poll fn, most recent first and unnumbered, with panic
    /// plumbing folded and the fatal signal attributed when this
    /// thread took it. Without the flag nothing native prints.
    /// `threads` shows the same stack raw, and `regs` the thread's
    /// registers.
    ///
    /// Under a thread cursor whose lwp polls no task, a bare `trace`
    /// prints that lwp's native backtrace instead.
    Trace {
        /// What to trace: a decimal task id from `tasks`, or a future
        /// address from `futures`, in hex with a required
        /// leading `0x`. May be omitted where something fills it in —
        /// the cursor (`task`, `future`, `thread` select one), or
        /// `tasks --exec trace`, which runs it under each surviving
        /// task.
        #[arg(value_parser = parse_trace_target)]
        target: Option<TraceTarget>,

        /// Show the variables present at each await point, and print
        /// a folded panic-plumbing run frame by frame.
        #[arg(long, short)]
        verbose: bool,

        /// Show a mid-poll task's native continuation above the
        /// chain: the polling thread's frames below the task's own
        /// poll fn, most recent first, unnumbered. Without the flag
        /// the native section is elided whole.
        #[arg(long, short = 'n')]
        native: bool,

        /// Show at most this many frames of each printed stack — the
        /// most recent N of the await chain and, separately, of the
        /// native continuation under -n. A cut section ends with a
        /// footer counting what it left out. Falls back to
        /// `config limit`.
        #[arg(long, short = 'l', value_name = "N")]
        limit: Option<usize>,
    },

    /// Print the layout the tokio info records for a type, by its
    /// exact fully-qualified name: members and their offsets, or an
    /// enum's variants and the discriminant that selects them.
    // Hidden from `help` and completion while the type-inspection
    // surface is reconsidered — not removed: it still parses and runs.
    #[command(hide = true)]
    Type {
        /// The fully-qualified name, as `find-types` lists it (several
        /// words are joined back into one name, so generics holding
        /// spaces paste in whole) — or as another listing displays it,
        /// folded and with the kind word — or a type id, the
        /// `type 4821` a listing prints where the name alone is not a
        /// handle (an ambiguous site, one definition of several).
        #[arg(value_name = "NAME", required = true, num_args = 1..)]
        name: Vec<String>,

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

    /// Move the cursor one await frame outward — toward the chain's
    /// root, the bottom of the listing — and print the frame line it
    /// lands on. Any words after it are a command to run at the new
    /// frame (`up locals`); a refused move runs nothing.
    Up {
        /// The command to run after a successful move.
        #[arg(
            value_name = "COMMAND",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        then: Vec<String>,
    },

    /// Say what an address is: the task whose allocation contains it,
    /// every future the census found that claims it — and, for the
    /// second word of a trait object, the vtable it points at, named
    /// by the concrete type it erases.
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
    /// Trailer all name the task, and every address `futures`
    /// prints — a held future's, a set's, a set child's node — names
    /// what it was printed for.
    Whatis {
        /// The address to look up, written in hex with a required
        /// leading `0x` (e.g. `0x7fffb1c26100`). Naming none asks
        /// after `$_`, the cursor's current frame.
        #[arg(value_parser = parse_hex_addr)]
        addr: Option<u64>,
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

/// How values read from the target are rendered: the session's render
/// defaults (`config`), resolved once into the value the render path
/// threads through.
#[derive(Copy, Clone)]
pub struct RenderOpts {
    depth: usize,
    ugly: bool,
    max_string_len: u64,
    max_array_values: u64,
}

impl RenderOpts {
    /// The values a command renders with — the session's, wholesale.
    fn from_settings(s: &settings::Settings) -> Self {
        RenderOpts {
            depth: s.depth,
            ugly: s.ugly,
            max_string_len: s.max_string_len,
            max_array_values: s.max_array_values,
        }
    }
}

/// Which runtime a command was pointed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeScope {
    /// Its position in the `runtimes --list` listing — the index every
    /// listing tags a task's group with.
    Index(usize),
    /// The address of its handle, which that listing prints beside the
    /// index so either identifier pastes back in.
    Handle(u64),
}

/// Parse a runtime scope. The split is the one `parse_trace_target`
/// makes for the same reason: the listing prints indices in decimal and
/// addresses in `0x` hex, so neither spelling can be mistaken for the
/// other. The listing prints the handle bare, and a label spells it
/// `@ 0x…`; either address pastes back in, with or without the `@`,
/// since the `@` is its dress, not its identity.
fn parse_runtime_scope(s: &str) -> std::result::Result<RuntimeScope, String> {
    let addr = s.strip_prefix('@').unwrap_or(s);
    if addr.starts_with("0x") || addr.starts_with("0X") {
        parse_hex_addr(addr).map(RuntimeScope::Handle)
    } else {
        s.parse().map(RuntimeScope::Index).map_err(|_| {
            format!(
                "a runtime is named by its index in the `runtimes --list` \
                 listing, or by the handle address printed beside it there \
                 (with or without its leading @), got {s:?}"
            )
        })
    }
}

/// Everything `trace` was told about rendering a chain: the shared
/// render options plus the flags only tracing takes.
struct TraceOpts<'a> {
    verbose: bool,
    /// Join a mid-poll task's native continuation onto the chain
    /// (`-n`); without it the trace ends at the last committed await.
    native: bool,
    /// Show at most this many frames of each printed stack (`-l`),
    /// the chain and the native continuation counted separately.
    limit: Option<usize>,
    render: RenderOpts,
    theme: output::Theme,
    /// The width to fit a frame line within by cutting the name that
    /// ends it — the future's, or a native frame's symbol — from
    /// [`Session::fit_width`]; `None` leaves every name whole.
    fit: Option<usize>,
    /// The allocator to corroborate every printed value against, where
    /// the target keeps one; see [`Session::heap_view`]. Carried here
    /// because the render happens deep inside the chain walk, which
    /// takes the walk context rather than the session.
    heap: Option<&'a dyn reify::Heap>,
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
/// the hex address `futures` prints.
#[derive(Clone, Copy, Debug)]
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
                 address in hex with a leading 0x (see `futures`), \
                 got {s:?}"
            )
        })
    }
}

/// Whether the session carries on after a command.
#[derive(Debug)]
pub enum Flow {
    Continue,
    Quit,
}

/// Run the command a frame move carried after it (`up locals`,
/// `frame 7 locals`). This is reached only after the move succeeded —
/// a refused move errors out of dispatch first, so its trailing
/// command never runs.
fn after_move<T: Target>(
    session: &Session<'_, T>,
    then: &[String],
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<Flow> {
    if then.is_empty() {
        return Ok(Flow::Continue);
    }
    match repl::parse_trailing(then)? {
        // `history` belongs to the repl loop, which answers it before
        // dispatch ever sees it; refuse it rather than panic in the
        // unreachable dispatch arm.
        Some(Command::History { .. }) => {
            anyhow::bail!("history is a repl command; run it on its own")
        }
        Some(command) => dispatch(session, command, theme, out),
        // Already answered in print (`help`).
        None => Ok(Flow::Continue),
    }
}

/// One target, opened once. A core does not change while we read it, so
/// the attach-time walks — worker discovery and task enumeration — are
/// done here and reused by every command, rather than repeated per
/// command as they were when each invocation opened its own target.
pub struct Session<'b, T: Target> {
    ctx: bundle::Context<'b, T>,
    proc: &'b T,
    /// Read again under a recording target when a snapshot is captured.
    bundle: &'b Bundle,
    /// How the session attached: the capture attaches the same way,
    /// and the launch-time worker's own context walks under it.
    policy: contract::WalkPolicy,
    core: &'b Path,
    bundle_source: BundleSource<'b>,
    workers: Vec<bundle::Worker>,
    /// Every lwp the target has, whatever it is doing, with its
    /// registers and recorded stack range. The workers above are the
    /// ones holding a tokio `Context`; the difference is what the
    /// runtime is *not* running.
    lwps: Vec<proc::LwpInfo>,
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
    /// What the registry harvests retained at attach: every wheel
    /// entry and io waiter, joined to rows by task address.
    registries: bundle::Registries,
    /// Which lwp runs each claimed blocking task, by Header address —
    /// an unwind of every stack, paid only when a blocking row is
    /// running and cached for the listings that spell it.
    blocking_lwps: OnceCell<HashMap<u64, u32>>,
    /// The bundle's impl-path substitutions, threaded into every
    /// display fold ([`hansei_bundle::names::fold_type_name`]).
    impl_fold: hansei_bundle::names::ImplFold,
    /// Task extents, the sub-executor census and the wait analysis:
    /// a core does not change, so the address→task answers never do
    /// either, and the two walks cover every chain — worth paying
    /// once. Built at launch, before the first prompt (see
    /// [`warm_listings`]); the `get_or_init` fallbacks compute in
    /// place for a session nothing warmed, or whose worker died.
    extents: OnceCell<bundle::TaskExtents>,
    census: OnceCell<census::FutureCensus>,
    /// The census as the tree the listings show — built once beside
    /// it, so `tasks --exec task` reads it per task rather than
    /// rebuilding it.
    census_tree: OnceCell<tasks::CensusTree>,
    /// Every lwp's unwound stack, keyed by tid — the one unwind the
    /// thread rows, the blocking rows and `thread` all read, so
    /// `threads --exec thread` walks the CFI once rather than once
    /// per thread. Empty when the target cannot be walked; the
    /// warning saying so prints once, when the unwind is first
    /// asked for.
    stacks: OnceCell<BTreeMap<u32, unwind::Backtrace>>,
    /// What the target's allocator says is live, where its allocator is
    /// libumem and says anything at all. `None` inside the cell is a
    /// target without umem, which is most of them.
    umem: OnceCell<Option<UmemHeap>>,
    /// How often each render gate has refused something the bytes alone
    /// would have allowed, over the whole session. A gate that fires
    /// prints nothing, so this is the only account of what it did.
    gates: GateCounts,
    /// Whether `--audit` has run against the census, wherever the
    /// census itself was built.
    audited: Cell<bool>,
    /// Where the census walk stops, `--search-depth` having moved the
    /// one bound a session can set.
    bounds: census::Bounds,
    /// Whether `--audit` asked for the census's self-check.
    audit: bool,
    /// Whether the version-ceiling drift notice has printed, so the
    /// walk commands raise it once per session, not once per line.
    ceiling_noticed: Cell<bool>,
    analysis: OnceCell<Analysis>,
    /// The relation index over the analysis and the census — forward
    /// for `graph`, reversed for `sync` and the waker slots — built on
    /// first use beside them.
    relations: OnceCell<relations::Relations>,
    /// The `tasks` table's rows, built from the analysis at launch
    /// and shared with the filters and the JSON printer.
    task_rows: OnceCell<Vec<tasks::TaskRow>>,
    /// The `futures` table's rows, likewise; building them reads the
    /// census and nothing more.
    future_rows: OnceCell<Vec<futures::FutureRow>>,
    /// The `threads` table's rows, likewise; building them pays for
    /// the one unwind of every stack.
    thread_rows: OnceCell<Vec<threads::ThreadRow>>,
    /// The session's standing defaults (`config`): what the per-command
    /// flags resolve against.
    settings: RefCell<settings::Settings>,
    /// The cursor (`task`/`future`/`thread`/`frame`): what the
    /// single-target commands fall back to when given no target.
    /// Listings never read it.
    cursor: RefCell<cursor::Cursor>,
}

impl<'b, T: Target> Session<'b, T> {
    fn attach(proc: &'b T, bundle: &'b Bundle, args: &'b SessionArgs) -> Result<Self> {
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
        // A bundle whose vtable scan had nothing to read (extracted
        // from a companion alone) still attaches — every symbol-keyed
        // table is whole — but realized trait objects were never
        // discovered, so anything rendered through a dyn pointer may
        // come up short. Say so once, at attach, rather than letting
        // it read as the target's own poverty.
        if matches!(
            bundle.meta.vtable_data,
            hansei_bundle::VtableDataSource::None
        ) {
            writeln!(
                io::stderr(),
                "warning: this tokio info's vtable scan had no program \
                 contents to read; dyn trait-object coverage is incomplete"
            )?;
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
        let (local_sets, registries) =
            ctx.discover_hidden_tasks(&lwps, &workers, &mut runtimes, &excluded, &mut tasks);
        print_warnings(&tasks.errors)?;

        Ok(Session {
            ctx,
            proc,
            bundle,
            policy,
            core: &args.core,
            bundle_source: args.bundle_source(),
            workers,
            lwps,
            runtimes,
            excluded,
            local_sets,
            tasks,
            registries,
            blocking_lwps: OnceCell::new(),
            impl_fold: hansei_bundle::names::ImplFold::for_bundle(bundle),
            extents: OnceCell::new(),
            census: OnceCell::new(),
            census_tree: OnceCell::new(),
            stacks: OnceCell::new(),
            umem: OnceCell::new(),
            gates: GateCounts::default(),
            audited: Cell::new(false),
            bounds: census::Bounds {
                scan_depth: args.search_depth,
                ..census::Bounds::default()
            },
            audit: args.audit,
            ceiling_noticed: Cell::new(false),
            analysis: OnceCell::new(),
            relations: OnceCell::new(),
            task_rows: OnceCell::new(),
            future_rows: OnceCell::new(),
            thread_rows: OnceCell::new(),
            settings: RefCell::new(settings::Settings::default()),
            cursor: RefCell::new(cursor::Cursor::default()),
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

    /// Adopt what the launch-time worker built. Nothing has asked for
    /// any of it yet — the worker is joined before the first command
    /// runs — so the cells are empty and the sets land.
    fn adopt(&self, warmed: Warmed) {
        let _ = self.extents.set(warmed.extents);
        let _ = self.census.set(warmed.census);
        let _ = self.umem.set(warmed.umem);
    }

    fn extents(&self) -> &bundle::TaskExtents {
        self.extents
            .get_or_init(|| self.ctx.task_extents(&self.tasks))
    }

    /// Every lwp's stack, unwound once per session on first use. A
    /// target that cannot be walked still has runtime state worth
    /// listing, so a failure costs the stacks and one warning, nothing
    /// else.
    pub(crate) fn stacks(&self) -> &BTreeMap<u32, unwind::Backtrace> {
        self.stacks
            .get_or_init(|| match unwind::load_frames(self.proc) {
                Ok(unwound) => unwound.stacks,
                Err(e) => {
                    let _ = writeln!(
                        io::stderr(),
                        "warning: cannot unwind the target's threads: {e:#}"
                    );
                    BTreeMap::new()
                }
            })
    }

    /// The census as a tree, built once per session on first use.
    fn census_tree(&self) -> &tasks::CensusTree {
        self.census_tree
            .get_or_init(|| tasks::census_tree(self.census().into()))
    }

    fn census(&self) -> &census::FutureCensus {
        let census = self.census.get_or_init(|| {
            census::census_bounded(&self.ctx, &self.tasks, self.bounds, self.umem())
        });
        if first_audit(self.audit, &self.audited) {
            let violations = census.audit(&self.tasks);
            if violations.is_empty() {
                let _ = writeln!(io::stderr(), "census audit: clean");
            }
            for violation in violations {
                let _ = writeln!(io::stderr(), "warning: census audit: {violation}");
            }
        }
        census
    }

    /// The allocator's own account of what is live, joined to the
    /// target and the gate tally — the form a render takes it in, and
    /// the one accessor every consumer goes through, so there is a
    /// single place a target without umem answers `None`.
    ///
    /// Handed out by value: a render holds the borrow only as long as
    /// it is being written, while the tally it counts into is the
    /// session's and outlives every one of them.
    pub fn heap_view(&self) -> Option<HeapView<'_, T>> {
        let umem = self
            .umem
            .get_or_init(|| UmemHeap::build(self.proc))
            .as_ref()?;
        Some(HeapView::new(umem, self.proc, &self.gates))
    }

    /// The index alone, for the answers that are about the allocator
    /// rather than about a value: `whatis`, `umem-audit`.
    pub fn umem(&self) -> Option<&UmemHeap> {
        self.heap_view().map(|view| view.heap())
    }

    /// What the render gates have refused this session.
    pub fn gates(&self) -> &GateCounts {
        &self.gates
    }

    /// The width a listing fits its name columns — and a trace its
    /// frame lines — within: the terminal's, when the output is one
    /// and `config truncate-names` is on; `None` leaves every name
    /// whole.
    pub(crate) fn fit_width(&self, theme: output::Theme) -> Option<usize> {
        match self.settings.borrow().truncate_names {
            true => theme.width(),
            false => None,
        }
    }

    /// The target itself, for the reads that go straight to it rather
    /// than through a bundle type.
    pub fn proc(&self) -> &T {
        self.proc
    }

    fn analysis(&self) -> &Analysis {
        self.analysis
            .get_or_init(|| rt_graph::analyze(&self.ctx, &self.tasks, &self.registries))
    }

    /// The relation index, built from the analysis and the census on
    /// first use — so the first `graph` or `sync` pays the census walk
    /// and every later one pays nothing.
    fn relations(&self) -> &relations::Relations {
        self.relations.get_or_init(|| {
            let census = self.census();
            relations::Relations::build(
                &self.tasks,
                self.analysis(),
                &census.held,
                &census.join_sets,
            )
        })
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
    /// Each names its group the way `runtimes --list` lists it, so a tag
    /// can be looked up there and handed straight back to `--runtime` or
    /// to `runtimes`.
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
pub fn dispatch<T: Target>(
    session: &Session<'_, T>,
    command: Command,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<Flow> {
    match command {
        Command::Census {
            threads,
            tasks,
            futures,
            limit,
        } => {
            session.note_version_ceiling();
            let sections = summary::Sections::select(threads, tasks, futures);
            tasks::exec_census(session, sections, limit, theme, out)?
        }
        Command::Down { then } => {
            cursor::exec_down(session, theme, out)?;
            return after_move(session, &then, theme, out);
        }
        Command::FindTypes { needle } => {
            let pattern = pattern::Pattern::new(&needle).context("find-types")?;
            types::find(&session.ctx.view, &pattern, out)?
        }
        Command::Frame { index, then } => {
            cursor::exec_frame(session, index, theme, out)?;
            return after_move(session, &then, theme, out);
        }
        Command::Future { addr, verbose } => {
            cursor::exec_future(session, addr, verbose, theme, out)?
        }
        Command::Futures {
            limit,
            with,
            without,
            group,
            exec,
            addr,
        } => {
            session.note_version_ceiling();
            let cmd = futures::FuturesCmd {
                limit: limit.or(session.settings.borrow().limit),
                with,
                without,
                group,
                exec,
                addr,
            };
            futures::exec_futures(session, cmd, theme, out)?
        }
        Command::Graph { limit } => {
            let limit = limit.or(session.settings.borrow().limit);
            graph::exec_graph(session, limit, out)?
        }
        // Answered in `repl`, which knows whether there is a prompt to
        // have a history; it never reaches here.
        Command::History { .. } => unreachable!("history is answered by the repl"),
        Command::Info => info::exec_info(session, out)?,
        Command::Locals => cursor::exec_locals(session, theme, out)?,
        Command::Print { args } => {
            let render = RenderOpts::from_settings(&session.settings.borrow());
            print::exec_print(session, &args, render, out)?
        }
        Command::Regs => registers::exec_regs(session, out)?,
        Command::Runtimes {
            list,
            drivers,
            shared,
            scope,
        } => {
            if list {
                runtimes::exec_list(session, out)?
            } else {
                let fields = runtimes::Fields::select(drivers, shared);
                let render = RenderOpts::from_settings(&session.settings.borrow());
                runtimes::exec_runtimes(session, &scope, fields, render, out)?
            }
        }
        Command::SaveTokioInfo { output } => exec_save_tokio_info(session, &output, out)?,
        Command::Config { key, value } => {
            settings::exec_config(&session.settings, key.as_deref(), value.as_deref(), out)?
        }
        #[cfg(feature = "snapshot")]
        Command::Snapshot { output } => snapshot_cmd::exec_snapshot(session, &output, out)?,
        Command::Sync { addr, kind } => sync::exec_sync(session, addr, kind, out)?,
        Command::Task { target, futures } => {
            cursor::exec_task(session, target, futures, session.fit_width(theme), out)?
        }
        Command::Tasks {
            limit,
            with,
            without,
            group,
            exec,
            task,
        } => {
            session.note_version_ceiling();
            let cmd = tasks::TasksCmd {
                limit: limit.or(session.settings.borrow().limit),
                with,
                without,
                group,
                exec,
                task,
            };
            tasks::exec_tasks(session, cmd, theme, out)?
        }
        Command::Thread { lwp } => {
            let render = RenderOpts::from_settings(&session.settings.borrow());
            cursor::exec_thread(session, lwp, render, out)?
        }
        Command::Threads {
            lwp,
            with,
            without,
            group,
            exec,
        } => {
            let cmd = threads::ThreadsCmd {
                lwp,
                with,
                without,
                group,
                exec,
            };
            threads::exec_threads(session, cmd, theme, out)?
        }
        Command::Trace {
            target,
            verbose,
            native,
            limit,
        } => {
            session.note_version_ceiling();
            let render = RenderOpts::from_settings(&session.settings.borrow());
            let limit = limit.or(session.settings.borrow().limit);
            let Some(target) = target.or(session.cursor.borrow().root) else {
                // A thread cursor has a stack worth walking: trace
                // answers with the native backtrace rather than
                // refusing. The hybrid trace is the task cursor's.
                if let Some(tid) = session.cursor.borrow().lwp {
                    trace::exec_trace_lwp(session, tid, limit, out)?;
                    return Ok(Flow::Continue);
                }
                anyhow::bail!(
                    "no task selected; trace takes a decimal task id or a 0x future address"
                );
            };
            let heap = session.heap_view();
            let opts = TraceOpts {
                verbose,
                native,
                limit,
                render,
                theme,
                fit: session.fit_width(theme),
                heap: heap.as_ref().map(|view| view as &dyn reify::Heap),
            };
            trace::exec_trace(session, target, &opts, out)?
        }
        Command::Type {
            name,
            recursive,
            depth,
        } => types::describe(
            &session.ctx.view,
            &name.join(" "),
            &session.impl_fold,
            recursive,
            depth,
            out,
        )?,
        Command::UmemAudit { addrs, dump } => umem::exec_umem_audit(session, &addrs, dump, out)?,
        Command::Up { then } => {
            cursor::exec_up(session, theme, out)?;
            return after_move(session, &then, theme, out);
        }
        Command::Whatis { addr } => {
            let Some(addr) = addr.or(session.cursor.borrow().last_addr) else {
                anyhow::bail!("no task selected; whatis takes a 0x address");
            };
            whatis::exec_whatis(session, addr, out)?
        }
        Command::Quit | Command::Exit => return Ok(Flow::Quit),
    }
    Ok(Flow::Continue)
}

fn main() {
    let args = Cli::parse();

    // Extraction reports what it declined — an unhandled location, a
    // layout that did not match, a unit skipped — as tracing events,
    // and a session's own diagnostics go the same way. Without a
    // subscriber `RUST_LOG` selects nothing and they all vanish.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let res = match args.cmd {
        Some(Cmd::TokioInfo { cmd }) => {
            // Extraction's heavy phases build their own scoped pools;
            // what is left for the global one is the vtable scan, with
            // no interactive session to stay out of the way of.
            build_pool(None, "tokio-info");
            bundle_cmd::exec(cmd)
        }
        None => {
            build_pool(Some(16), "reify-render");
            // clap requires --core and --tokio-info of every invocation
            // that names no subcommand.
            let session = args.session.expect("session args without a subcommand");
            run(&session, &args.exec)
        }
    };
    if let Err(e) = res {
        if exits_quietly(&e) {
            return;
        }

        let _ = writeln!(io::stderr(), "Error: {e:?}");
        std::process::exit(1);
    }
}

/// Build the global rayon pool this invocation fans out on.
///
/// A session passes a cap, because value rendering is memory-bound and
/// stops scaling well before the 128-256 logical CPUs of a rack sled,
/// and a debugging session should not commandeer a sled's worth of
/// threads either. A one-shot command wants the machine.
fn build_pool(cap: Option<usize>, name: &'static str) {
    let mut builder = rayon::ThreadPoolBuilder::new().thread_name(move |i| format!("{name}-{i}"));
    if let Some(cap) = cap {
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(cap);
        builder = builder.num_threads(threads);
    }
    if let Err(e) = builder.build_global() {
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
    // decodes — or, from a debug binary, is extracted outright), so one
    // is opened on a second thread. Named for the attach rather than
    // for the core: either file can be the one that failed, and the
    // cause says which.
    let open_core = || {
        Proc::open_core_with_binary(&args.core, args.binary.as_deref())
            .with_context(|| format!("failed to attach to {}", args.core.display()))
    };
    match args.bundle_source() {
        BundleSource::File(path) => {
            let (proc, bundle) = std::thread::scope(|scope| {
                let bundle = scope.spawn(|| {
                    Bundle::load(path)
                        .with_context(|| format!("failed to load tokio info {}", path.display()))
                });
                (open_core(), bundle.join().expect("bundle loader panicked"))
            });
            session(proc?, bundle?, Vec::new(), false, args, exec)
        }
        // Extraction leaves the parsed DWARF to free, which takes
        // seconds; the session runs inside its continuation so that
        // freeing overlaps the attach and everything after it.
        BundleSource::Extracted(path) => std::thread::scope(|scope| {
            let proc = scope.spawn(open_core);
            bundle_cmd::extract_for_session_with(
                path,
                args.binary.as_deref(),
                |bundle, warnings, binary_extracted_from| {
                    let proc = proc.join().expect("core opener panicked")?;
                    session(proc, bundle, warnings, binary_extracted_from, args, exec)
                },
            )?
        }),
    }
}

/// Attach to an opened target with its bundle, warm the listings, and
/// run the REPL over them.
fn session(
    proc: Proc,
    bundle: Bundle,
    warnings: Vec<String>,
    binary_extracted_from: bool,
    args: &SessionArgs,
    exec: &[String],
) -> Result<()> {
    // Held back until here rather than printed by the worker, whose
    // stderr the attach's own warnings are interleaved with.
    for warning in &warnings {
        writeln!(io::stderr(), "{warning}")?;
    }
    check_binary(&proc, args, binary_extracted_from)?;
    let session = Session::attach(&proc, &bundle, args)?;
    warm_listings(&session, &proc, &bundle);
    repl::run(&session, exec)
}

/// Build what the listings read before the first command runs, so
/// `tasks`, `futures` and `threads` — where a session starts — answer
/// at once rather than the first of each paying for its walk at the
/// prompt. Two threads share the wait: the joint state every deep
/// command reads (the allocator index, the task extents and the
/// census) builds on a worker, while this thread — the only one the
/// session's own context can run on — builds the wait analysis and
/// the rows that need only it. The future rows, which read the
/// census, come last, once the worker is joined.
fn warm_listings(session: &Session<'_, Proc>, proc: &Proc, bundle: &Bundle) {
    std::thread::scope(|scope| {
        let tasks = &session.tasks;
        let (policy, bounds) = (session.policy, session.bounds);
        let worker = scope.spawn(move || warm_worker(proc, bundle, policy, tasks, bounds));
        tasks::rows(session);
        threads::rows(session);
        // A worker that panicked has left the cells empty, and the
        // accessors' fallbacks compute in place.
        if let Ok(Some(warmed)) = worker.join() {
            session.adopt(*warmed);
        }
    });
    futures::rows(session);
}

/// Whether this `census()` call is the one that runs `--audit`'s
/// self-check: the first, and only when the flag asked for it — a REPL
/// asking for the census per command is not audited per line.
fn first_audit(audit: bool, audited: &Cell<bool>) -> bool {
    audit && !audited.replace(true)
}

/// What the launch-time worker hands the session, both built over the
/// worker's own [`bundle::Context`] (the session's holds interior
/// caches and stays on its thread) and the session's shared task list.
/// Boxed for the join: the census is large, and cannot be cloned
/// piecemeal (it carries its walk errors).
struct Warmed {
    extents: bundle::TaskExtents,
    census: census::FutureCensus,
    umem: Option<UmemHeap>,
}

fn warm_worker(
    proc: &Proc,
    bundle: &Bundle,
    policy: contract::WalkPolicy,
    tasks: &bundle::TaskList,
    bounds: census::Bounds,
) -> Option<Box<Warmed>> {
    // The attach already proved this constructor over the same inputs;
    // a failure here means the session is degraded in a way its own
    // accessors will report, so the worker just stands down.
    let ctx = bundle::Context::with_policy(proc, BundleView::new(bundle), policy).ok()?;
    // The allocator index first: it is the only one of the three that
    // reads nothing the bundle describes — so a target whose layouts
    // have drifted still gets it — and what the census below
    // corroborates its finds against.
    let umem = UmemHeap::build(proc);
    let extents = ctx.task_extents(tasks);
    let census = census::census_bounded(&ctx, tasks, bounds, umem.as_ref());
    Some(Box::new(Warmed {
        extents,
        census,
        umem,
    }))
}

/// The attach summary: what is being read, and how well the two files
/// agree. A partial fingerprint is what `--force` waves through, so it
/// is worth being able to ask after the fact.
/// Persist the tokio info this session extracted at launch, so the
/// next session on this target can take the file with `--tokio-info`
/// instead of paying for extraction again.
fn exec_save_tokio_info<T: Target>(
    session: &Session<'_, T>,
    output: &Path,
    out: &mut dyn io::Write,
) -> Result<()> {
    let BundleSource::Extracted(_) = session.bundle_source else {
        anyhow::bail!(
            "this session read its tokio info from {}; that file already \
             exists — there is nothing to save",
            session.bundle_source
        );
    };
    session
        .bundle
        .save(output)
        .with_context(|| format!("failed to write {}", output.display()))?;
    writeln!(out, "wrote {}", output.display())?;
    Ok(())
}

/// Hold `--binary` to what the core says the executable was.
///
/// A Linux core carries no symbol table — `.symtab` is not `SHF_ALLOC`,
/// so it is never in the address space there is to dump — and the path
/// the core records for the executable is rarely still right on the
/// machine reading it. That makes the binary a third required input
/// rather than a convenience: without it not one symbol resolves, and
/// the attach dies at the thread-local the runtime lives behind.
///
/// *Which* binary is just as load-bearing. A separate debug build of
/// the same source resolves every symbol *name* while sharing none of
/// the addresses, so the fingerprint passes in full and every task
/// comes out named after whatever now sits at its address. The build
/// id is the check that catches the substitution — and what tells that
/// mistake from a split-debug companion, which does share the
/// deployed binary's addresses.
fn check_binary(proc: &Proc, args: &SessionArgs, binary_extracted_from: bool) -> Result<()> {
    if !proc.needs_binary() {
        // Surplus only when nothing used it: extraction from split
        // debug info consumed `--binary` as the sibling the DWARF was
        // split from, and warning then would tell the operator to drop
        // a flag the next run refuses to start without.
        if let Some(path) = &args.binary
            && !binary_extracted_from
        {
            writeln!(
                io::stderr(),
                "warning: ignoring --binary {}; this core carries its own \
                 symbol tables",
                path.display()
            )?;
        }
        return Ok(());
    }

    let Some(path) = &args.binary else {
        let named = proc
            .exec_name()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "the executable".to_owned());
        anyhow::bail!(
            "--binary is required for a Linux core: the core carries no \
             symbol table, so {named} has to be read alongside it. Pass the \
             binary that ran — not a separate debug build, which shares \
             none of its addresses."
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
        hex(&ids.binary),
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
        "only {}/{} tokio-info symbols resolve in the target — the tokio \
         info does not match this binary. Missing, for example:\n{}\n\
         Pass --force to proceed anyway.",
        fp.matched,
        fp.total,
        sample
    );
    writeln!(
        io::stderr(),
        "warning: only {}/{} tokio-info symbols resolve in the target; \
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
    ids.core.is_none() || ids.binary.is_none()
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
mod render_flag_tests {
    use super::RenderOpts;
    use crate::settings::Settings;

    /// The render values are the session's, wholesale.
    #[test]
    fn test_render_opts_come_from_the_session() {
        let session = Settings {
            depth: 6,
            ugly: true,
            max_string_len: 10,
            max_array_values: 3,
            limit: None,
            truncate_names: true,
        };
        let resolved = RenderOpts::from_settings(&session);
        assert_eq!(resolved.depth, 6);
        assert!(resolved.ugly);
        assert_eq!(resolved.max_string_len, 10);
        assert_eq!(resolved.max_array_values, 3);
        assert!(!RenderOpts::from_settings(&Settings::default()).ugly);
    }
}

#[cfg(test)]
mod session_gate_tests {
    use super::first_audit;
    use std::cell::Cell;

    /// The audit runs once, and only when asked: never without the
    /// flag, on the first census with it, and not again after.
    #[test]
    fn test_the_audit_runs_once_when_asked() {
        let off = Cell::new(false);
        assert!(!first_audit(false, &off));
        assert!(!off.get(), "an unasked audit must not consume the gate");

        let on = Cell::new(false);
        assert!(first_audit(true, &on));
        assert!(!first_audit(true, &on));
    }
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
        let ids = |core: bool, binary: bool| proc::BuildIds {
            core: core.then(|| vec![1, 2]),
            binary: binary.then(|| vec![1, 2]),
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

#[cfg(test)]
mod cli_tests {
    use super::{Cli, Cmd};
    use crate::bundle_cmd::BundleCmd;

    use clap::Parser;

    use std::path::Path;

    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv).expect("should parse")
    }

    /// Naming a target opens a session, exactly as before the argv
    /// grammar grew a subcommand.
    #[test]
    fn test_bare_invocation_is_a_session() {
        let cli = parse(&["hansei", "-c", "core.app", "-t", "app.tinfo", "-e", "tasks"]);
        assert!(cli.cmd.is_none());
        let session = cli.session.expect("session args");
        assert_eq!(session.core.to_str(), Some("core.app"));
        assert_eq!(session.tokio_info.as_deref(), Some(Path::new("app.tinfo")));
        assert_eq!(session.debug_info, None);
        assert_eq!(cli.exec, ["tasks"]);
    }

    /// A debug build stands in for a tokio-info file, and the summary
    /// says which of the two the session's types came from.
    #[test]
    fn test_debug_info_stands_in_for_a_tokio_info_file() {
        let cli = parse(&["hansei", "-c", "core.app", "-d", "app.debug"]);
        let session = cli.session.expect("session args");
        assert_eq!(session.tokio_info, None);
        assert_eq!(session.debug_info.as_deref(), Some(Path::new("app.debug")));
        assert_eq!(
            session.bundle_source().to_string(),
            "extracted from app.debug"
        );
    }

    /// The two ways in are alternatives: one is required, and naming
    /// both would leave it ambiguous which the types came from.
    #[test]
    fn test_the_two_ways_in_are_exclusive() {
        assert!(
            Cli::try_parse_from([
                "hansei",
                "-c",
                "core.app",
                "-t",
                "app.tinfo",
                "--debug-info",
                "app.debug",
            ])
            .is_err()
        );
    }

    /// The subcommand takes the whole invocation: no target is named,
    /// and the flags a session requires are not asked for.
    #[test]
    fn test_tokio_info_extract_takes_the_extraction_flags() {
        let cli = parse(&[
            "hansei",
            "tokio-info",
            "extract",
            "app",
            "--debug-info",
            "app.dbg",
            "-o",
            "app.tinfo",
            "--stats",
            "--include-type",
            "core::net::IpAddr",
            "--explain-format",
            "Notify",
        ]);
        assert!(cli.session.is_none());
        let Some(Cmd::TokioInfo {
            cmd:
                BundleCmd::Extract {
                    binary,
                    debug_info,
                    output,
                    stats,
                    include_types,
                    allow_missing_infra,
                    explain_format,
                    explain_walk,
                },
        }) = cli.cmd
        else {
            panic!("expected `tokio-info extract`");
        };
        assert_eq!(binary.to_str(), Some("app"));
        assert_eq!(
            debug_info.as_deref().and_then(|p| p.to_str()),
            Some("app.dbg")
        );
        assert_eq!(output.to_str(), Some("app.tinfo"));
        assert!(stats);
        assert_eq!(include_types, ["core::net::IpAddr"]);
        assert!(!allow_missing_infra);
        assert_eq!(explain_format.as_deref(), Some("Notify"));
        assert_eq!(explain_walk, None);
    }

    /// The two sides are alternatives, not layers: a session's flags
    /// alongside a subcommand is a mistake worth naming, and naming
    /// neither leaves the session flags required.
    #[test]
    fn test_the_two_sides_do_not_mix() {
        assert!(
            Cli::try_parse_from([
                "hansei",
                "-c",
                "core.app",
                "tokio-info",
                "extract",
                "app.debug"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["hansei"]).is_err());
        assert!(Cli::try_parse_from(["hansei", "-c", "core.app"]).is_err());
    }
}

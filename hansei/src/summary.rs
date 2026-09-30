// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `census` command: how much of everything the target holds.
//!
//! Every other listing answers a question about one thing — this task,
//! that address, those threads. A census answers the question a reader
//! has *before* those: how big is what I am looking at, and what is it
//! mostly doing. So it counts rather than lists, and every number it
//! prints is one the other commands can be pointed at to expand.
//!
//! Each section is a heading and one or two tables, in the shape the
//! listings' `--group` prints: a `COUNT` column, the value it counts,
//! and the `[N things]` footer. The spellings are the listings' too —
//! a thread's role and state as `threads` spells them, a task's state
//! as `tasks` does, a wait as the `WAITING ON` column does — so a row
//! here is a `--with` clause away from its members.
//!
//! Nothing here reads the target. It is handed [`Facts`] — the thread
//! classification, the task list, the wait analysis and the future
//! census — and reduces them to a page, which is what lets the tallies
//! be tested from values laid out by hand rather than from a core that
//! happens to hold the shape under test.

use crate::output::{self, Theme};
use crate::tasks::{future_name, listing_footer, row_state};
use crate::typenames::{self, TypeNames};

use anyhow::Result;
use hansei_runtime::tokio::Lifecycle;
use hansei_runtime::tokio::assess::{
    ContinuationStatus, NotWaitingReason, RunnableReason, WaitAssessment,
};
use hansei_runtime::tokio::bundle::{
    BlockingPool, CtActivity, CtParkState, FutureInfo, OwnerResolution, ParkState, ParkStates,
    Task, TaskList, WaitKind,
};
use hansei_runtime::tokio::census::{FutureSet, HeldFuture};
use hansei_runtime::tokio::graph::TaskWait;

use std::collections::{BTreeMap, BTreeSet};
use std::io;

/// One thread of the target that holds a tokio `Context`.
pub struct Thread {
    pub tid: u32,
    /// Which runtime it is inside, as an index into [`Facts::runtimes`];
    /// `None` when the thread's context reaches no discovered runtime.
    /// A worker's park state is read from *that* runtime's parkers and
    /// no other, since a worker index means nothing outside the
    /// scheduler it belongs to.
    pub runtime: Option<usize>,
    /// The place the thread holds in a scheduler's run loop; `None` for
    /// a thread that has merely entered the runtime (a plain `block_on`
    /// caller on a multi_thread target, a blocking-pool thread).
    pub role: Option<ThreadRole>,
    /// The task it is polling, where the runtime still calls that task
    /// running — the same claim `tasks` makes in its `STATE` column.
    pub polling: Option<u64>,
}

/// How a thread runs a scheduler: as one of a multi_thread scheduler's
/// numbered workers, or as the `block_on` thread that *is* a
/// current_thread scheduler's one worker.
pub enum ThreadRole {
    Worker(u64),
    /// What the block_on thread's checked-in core said, when it was
    /// readable — the CT analog of the parker states.
    BlockOn(Option<CtParkState>),
}

/// One discovered runtime, with the readings that are its alone.
pub struct Runtime {
    /// How every listing names it: `runtime 0 @ 0x7f11c0`.
    pub label: String,
    /// What its workers' parkers say. `None` for a current_thread
    /// runtime, which has no parker array, and for one whose parkers
    /// could not be read — which costs the census the park breakdown of
    /// that runtime's threads and nothing else.
    pub parks: Option<ParkStates>,
    /// Its own blocking pool's counters, likewise optional.
    pub pool: Option<BlockingPool>,
}

/// Everything a census counts, as the session read it.
pub struct Facts<'a> {
    /// Every lwp the target has, whatever it is doing.
    pub lwps: Vec<u32>,
    /// Those of them holding a tokio `Context`.
    pub runtime: Vec<Thread>,
    /// The runtimes those threads are inside, in the order `runtimes`
    /// lists them.
    pub runtimes: Vec<Runtime>,
    /// How many local sets share the task population with them. They
    /// run no threads of their own — a set is polled by a task of the
    /// runtime it was created on — so they are a count here rather than
    /// a list.
    pub local_sets: usize,
    pub tasks: &'a TaskList,
    /// One wait per task, in task-list order.
    pub waits: &'a [TaskWait],
    /// The census as flat lists rather than as itself, so a test can
    /// lay out a shape no fixture happens to hold — the same reason
    /// `print_tasks` takes them that way. Its join sets are not among
    /// them: their members are tasks the section above counts, so a
    /// census of futures has nothing to say about them.
    pub held: &'a [HeldFuture],
    pub sets: &'a [FutureSet],
    /// How the census finds' types are named.
    pub(crate) names: &'a TypeNames<'a>,
}

/// The one-line spelling of a fatal signal every surface shares:
/// `SIGSEGV (SEGV_MAPERR), fault address 0x0`. The code appears by name
/// when it is a fault code, by number when it is some other refinement,
/// and not at all for a plain user-sent signal; the address only when
/// the code says the siginfo carried one.
pub fn fatal_signal_line(sig: &proc::FatalSignal) -> String {
    let mut line = signal_name(sig);
    if let Some(addr) = sig.fault_addr {
        line.push_str(&format!(", fault address {addr:#x}"));
    }
    line
}

/// The signal and its code alone — `SIGSEGV (SEGV_MAPERR)` — for the
/// lines that follow it with their own attribution, where the fault
/// address would only repeat what the attribution says.
pub fn signal_name(sig: &proc::FatalSignal) -> String {
    let mut line = sig.name.to_string();
    match (sig.code_name, sig.code) {
        (Some(code), _) => line.push_str(&format!(" ({code})")),
        (None, 0) => {}
        (None, code) => line.push_str(&format!(" (code {code})")),
    }
    line
}

impl Facts<'_> {
    /// How the target's executors are named where a whole section's
    /// numbers are theirs: by name when there is one of them, since a
    /// name is what the other commands take, and by count when there
    /// are several and no one name is true of the lot.
    fn whole(&self) -> String {
        match (self.runtimes.len(), self.local_sets) {
            (1, 0) => self.runtimes[0].label.clone(),
            (runtimes, 0) => counted(runtimes, "runtime"),
            (runtimes, sets) => format!(
                "{} and {}",
                counted(runtimes, "runtime"),
                counted(sets, "local set")
            ),
        }
    }
}

/// The `Tasks` heading's count: every task is the executors' where
/// every task's owner is one of them, and where some task's owner is
/// nobody's — no list, queue or scheduler established one — or in
/// conflict, those are counted apart, so the number beside the
/// executors is the number they own.
fn owned_heading(facts: &Facts<'_>) -> String {
    let tasks = &facts.tasks.tasks;
    let unknown = tasks
        .iter()
        .filter(|t| matches!(t.owner, OwnerResolution::Unknown))
        .count();
    let conflict = tasks
        .iter()
        .filter(|t| matches!(t.owner, OwnerResolution::Conflict(_)))
        .count();
    if unknown == 0 && conflict == 0 {
        return format!("{} owned by {}", tasks.len(), facts.whole());
    }
    let mut parts = vec![format!(
        "{} owned by {}",
        tasks.len() - unknown - conflict,
        facts.whole()
    )];
    if unknown > 0 {
        parts.push(format!("{unknown} with no established owner"));
    }
    if conflict > 0 {
        parts.push(format!("{conflict} with conflicting owners"));
    }
    format!("{}: {}", tasks.len(), parts.join(", "))
}

/// Which of the three sections to print.
#[derive(Clone, Copy)]
pub struct Sections {
    pub threads: bool,
    pub tasks: bool,
    pub futures: bool,
}

impl Sections {
    /// The sections the flags name. Naming none is not asking for an
    /// empty census: it is asking for the whole one, which is what the
    /// command printed before there were flags to narrow it.
    pub fn select(threads: bool, tasks: bool, futures: bool) -> Self {
        let all = !(threads || tasks || futures);
        Self {
            threads: threads || all,
            tasks: tasks || all,
            futures: futures || all,
        }
    }
}

/// Print the census.
///
/// `top` bounds every type tally; the rows past it are counted rather
/// than dropped silently. `fit` is the width the tables keep their
/// lines within by cutting the names in them, as
/// [`Session::fit_width`](crate::Session::fit_width) gives it; `None`
/// leaves every name whole. `theme` styles the section headings when
/// the page is bound for a terminal.
pub fn print(
    facts: &Facts<'_>,
    sections: Sections,
    top: usize,
    fit: Option<usize>,
    theme: Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The blank line goes *between* sections rather than after each, so
    // that a census narrowed to one section is a page in its own right
    // and not the whole page with the other two cut out of it.
    let mut printed = false;
    let mut separate = |out: &mut dyn io::Write| -> Result<()> {
        if std::mem::replace(&mut printed, true) {
            writeln!(out)?;
        }
        Ok(())
    };
    if sections.threads {
        separate(out)?;
        threads(facts, theme, out)?;
    }
    if sections.tasks {
        separate(out)?;
        tasks(facts, top, fit, theme, out)?;
    }
    if sections.futures {
        separate(out)?;
        futures(facts, top, fit, theme, out)?;
    }
    Ok(())
}

/// A section's heading: the section's name and its colon, bold where
/// the theme allows, then the one-line summary the tables below break
/// down — and a blank line, so the first table's header stands apart
/// from it.
fn heading(theme: Theme, name: &str, summary: &str, out: &mut dyn io::Write) -> Result<()> {
    writeln!(out, "{} {summary}", theme.bold(&format!("{name}:")))?;
    writeln!(out)?;
    Ok(())
}

// ---------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------

/// What one run-loop thread is doing, in the order rows of one count
/// list: the driver holder first, since a worker parked there is
/// parked on the whole runtime's behalf and is the one thread a reader
/// came looking for.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ThreadKind {
    Driver,
    Polling,
    BlockOnPoll,
    Awake,
    Notified,
    Parked,
    Unread,
}

impl ThreadKind {
    /// The `STATE` cell, spelled as the `threads` listing spells the
    /// state half of a worker's role.
    fn state(self) -> &'static str {
        match self {
            Self::Driver => "in driver",
            Self::Polling => "polling",
            Self::BlockOnPoll => "polling block_on",
            Self::Awake => "awake",
            Self::Notified => "notified",
            Self::Parked => "parked",
            Self::Unread => "park state unread",
        }
    }
}

/// Where a row of the thread table sorts: by the runtime it is inside,
/// then — within one runtime — by count, as `--group` ranks its
/// buckets, with ties in the order the kinds are declared, then the
/// two rows of threads that entered the runtime without running its
/// loop; the threads outside every runtime come last of all.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ThreadKey {
    /// The runtime's index; `usize::MAX` for a thread inside none it
    /// could be joined to, so those rows follow every runtime's.
    rt: usize,
    order: u8,
    role: &'static str,
    state: String,
}

const ORDER_POOL: u8 = 10;
const ORDER_ENTERED: u8 = 11;
const ORDER_NO_RUNTIME: u8 = 20;

/// One row of the thread table.
struct ThreadRow {
    key: ThreadKey,
    count: usize,
    /// The lwps in the row, where the census can say which they are;
    /// `None` where it can only count them.
    lwps: Option<Vec<String>>,
}

fn threads(facts: &Facts<'_>, theme: Theme, out: &mut dyn io::Write) -> Result<()> {
    // The threads are in runtimes, never in a local set: a set is
    // polled by a task of whatever runtime it was created on.
    let inside = match facts.runtimes.len() {
        1 => facts.runtimes[0].label.clone(),
        n => counted(n, "runtime"),
    };
    heading(
        theme,
        "Threads",
        &format!(
            "{}, {} in {inside}",
            counted(facts.lwps.len(), "lwp"),
            facts.runtime.len()
        ),
        out,
    )?;

    // The run-loop threads, bucketed by runtime, role and state.
    let mut in_loop: BTreeMap<ThreadKey, Vec<String>> = BTreeMap::new();
    for thread in &facts.runtime {
        let Some(role) = &thread.role else {
            continue;
        };
        let kind = kind(facts, thread);
        let role = match role {
            ThreadRole::Worker(_) => "worker",
            ThreadRole::BlockOn(_) => "block_on thread",
        };
        let key = ThreadKey {
            rt: thread.runtime.unwrap_or(usize::MAX),
            order: kind as u8,
            role,
            state: kind.state().to_string(),
        };
        let lwp = match thread.polling {
            Some(id) => format!("{} (task {id})", thread.tid),
            None => thread.tid.to_string(),
        };
        in_loop.entry(key).or_default().push(lwp);
    }
    let mut rows: Vec<ThreadRow> = in_loop
        .into_iter()
        .map(|(key, lwps)| ThreadRow {
            count: lwps.len(),
            key,
            lwps: Some(lwps),
        })
        .collect();

    // The threads that entered a runtime without running its loop:
    // its blocking pool's, and the rest.
    let indices = (0..facts.runtimes.len()).map(Some).chain([None]);
    for index in indices {
        let entered: Vec<String> = facts
            .runtime
            .iter()
            .filter(|t| t.runtime == index && t.role.is_none())
            .map(|t| t.tid.to_string())
            .collect();
        let rt = index.unwrap_or(usize::MAX);
        match index.and_then(|index| facts.runtimes[index].pool.as_ref()) {
            Some(pool) => rows.extend(blocking_pool(facts, rt, pool, entered)),
            None if entered.is_empty() => {}
            None => rows.push(ThreadRow {
                key: ThreadKey {
                    rt,
                    order: ORDER_ENTERED,
                    role: "entered runtime",
                    state: "—".to_string(),
                },
                count: entered.len(),
                lwps: Some(entered),
            }),
        }
    }

    // The lwps holding no runtime context at all.
    let in_runtime: BTreeSet<u32> = facts.runtime.iter().map(|t| t.tid).collect();
    let outside: Vec<String> = facts
        .lwps
        .iter()
        .filter(|tid| !in_runtime.contains(tid))
        .map(|tid| tid.to_string())
        .collect();
    if !outside.is_empty() {
        rows.push(ThreadRow {
            key: ThreadKey {
                rt: usize::MAX,
                order: ORDER_NO_RUNTIME,
                role: "no runtime",
                state: "—".to_string(),
            },
            count: outside.len(),
            lwps: Some(outside),
        });
    }
    rows.sort_by(|a, b| {
        a.key
            .rt
            .cmp(&b.key.rt)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.key.cmp(&b.key))
    });

    let mut table = output::Table::new(5)
        .header(["COUNT", "RT", "ROLE", "STATE", "LWPS"])
        .align_right(0)
        .theme(theme);
    for row in &rows {
        let rt = match row.key.rt {
            usize::MAX => "—".to_string(),
            rt => rt.to_string(),
        };
        let lwps = match row.lwps.as_deref() {
            Some([]) | None => "—".to_string(),
            Some(lwps) => sample(lwps),
        };
        table.row([
            row.count.to_string(),
            rt,
            row.key.role.to_string(),
            row.key.state.clone(),
            lwps,
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(
        out,
        "{}",
        listing_footer(facts.lwps.len(), facts.lwps.len(), "lwp")
    )?;
    Ok(())
}

/// Up to three of a row's lwps and `…` — the sample a bucket row
/// carries, as `--group` samples its members.
fn sample(lwps: &[String]) -> String {
    let shown: Vec<&str> = lwps.iter().take(3).map(String::as_str).collect();
    match lwps.len() > shown.len() {
        true => format!("{}, …", shown.join(", ")),
        false => shown.join(", "),
    }
}

/// Split the threads that entered one runtime without running its loop
/// into its blocking pool's and the rest, as rows.
///
/// The runtime launches each worker with `spawn_blocking`, so the pool
/// counts the workers among its threads — its `num_threads` is larger
/// than the pool proper by exactly the scheduler's worker count, and
/// netting them out is what makes this row a share of the threads that
/// entered rather than a second count of threads already listed. The
/// pool's idle count needs no such correction: a worker's blocking task
/// is its run loop and never returns, so a worker is never idle *to the
/// pool*.
///
/// The census reads no stacks, so it cannot say which of the threads
/// that entered are the pool's: a row lists its lwps only when every
/// thread that entered is in it, and counts them otherwise.
///
/// Where the two do not reconcile — a worker thread that has left the
/// pool's tally, a runtime hansei is reading mid-startup — nothing is
/// invented: the pool's own counters are reported as its own, said to
/// include the workers.
fn blocking_pool(
    facts: &Facts<'_>,
    rt: usize,
    pool: &BlockingPool,
    entered: Vec<String>,
) -> Vec<ThreadRow> {
    let runtime = facts.runtimes.get(rt);
    let mine = || facts.runtime.iter().filter(|t| t.runtime == Some(rt));
    // The scheduler's own count of workers where it was read, since
    // that is what `launch` spawned; the threads seen running its loop
    // otherwise. Only a multi_thread scheduler's workers are launched
    // through spawn_blocking and so counted among the pool's threads; a
    // block_on thread is the caller's own.
    let launched = runtime.and_then(|rt| rt.parks.as_ref()).map_or_else(
        || {
            mine()
                .filter(|t| matches!(t.role, Some(ThreadRole::Worker(_))))
                .count()
        },
        |parks| parks.workers.len(),
    );
    let threads = pool.threads as usize;
    let queued = match pool.queued {
        0 => String::new(),
        n => format!(", {n} queued"),
    };
    let Some(blocking) = threads
        .checked_sub(launched)
        .filter(|blocking| *blocking <= entered.len())
    else {
        return vec![ThreadRow {
            key: ThreadKey {
                rt,
                order: ORDER_ENTERED,
                role: "entered runtime",
                state: format!(
                    "pool counts {} (workers among them), {} idle{queued}",
                    counted(threads, "thread"),
                    pool.idle
                ),
            },
            count: entered.len(),
            lwps: Some(entered),
        }];
    };
    let other = entered.len() - blocking;
    let busy = blocking.saturating_sub(pool.idle as usize);
    let mut rows = vec![ThreadRow {
        key: ThreadKey {
            rt,
            order: ORDER_POOL,
            role: "blocking pool",
            state: format!("{} idle, {busy} busy{queued}", pool.idle),
        },
        count: blocking,
        lwps: (other == 0).then(|| entered.clone()),
    }];
    if other > 0 {
        rows.push(ThreadRow {
            key: ThreadKey {
                rt,
                order: ORDER_ENTERED,
                role: "entered runtime",
                state: "block_on caller".to_string(),
            },
            count: other,
            lwps: (blocking == 0).then_some(entered),
        });
    }
    rows
}

/// The parker states of the runtime a thread is inside, where that
/// runtime has them: a current_thread scheduler parks its one thread on
/// its driver rather than through a parker array.
fn parks_of<'a>(facts: &'a Facts<'_>, thread: &Thread) -> Option<&'a ParkStates> {
    facts.runtimes.get(thread.runtime?)?.parks.as_ref()
}

/// What one run-loop thread is doing. Holding the driver comes ahead of
/// everything: a worker parked there is parked on the whole runtime's
/// behalf, and it is the one thread a reader came looking for.
fn kind(facts: &Facts<'_>, thread: &Thread) -> ThreadKind {
    // A block_on thread's state comes from its own checked-in core and
    // thread-local task id rather than a parker word: parked in the
    // driver, polling the root future, or polling a task — the last
    // counted as polling only when the listing believes the id, as a
    // worker's is, and awake otherwise, like the bookkeeping between
    // polls and a shutdown's drops.
    if let Some(ThreadRole::BlockOn(state)) = &thread.role {
        return match state.map(|s| s.activity) {
            Some(CtActivity::Parked) => ThreadKind::Driver,
            Some(CtActivity::PollingBlockOn) => ThreadKind::BlockOnPoll,
            Some(CtActivity::PollingTask(_)) if thread.polling.is_some() => ThreadKind::Polling,
            Some(
                CtActivity::PollingTask(_) | CtActivity::BetweenPolls | CtActivity::DroppingTask(_),
            ) => ThreadKind::Awake,
            None => ThreadKind::Unread,
        };
    }
    let worker = match thread.role {
        Some(ThreadRole::Worker(index)) => Some(index),
        _ => None,
    };
    // A worker index is an index into *its own* scheduler's parker
    // array and means nothing in another's, so a thread is classified by
    // the runtime it is inside or not at all.
    let park = parks_of(facts, thread)
        .zip(worker)
        .and_then(|(parks, index)| parks.workers.get(index as usize).copied());
    match park {
        Some(ParkState::Driver) => ThreadKind::Driver,
        _ if thread.polling.is_some() => ThreadKind::Polling,
        Some(ParkState::Condvar) => ThreadKind::Parked,
        Some(ParkState::Notified) => ThreadKind::Notified,
        Some(ParkState::Awake) => ThreadKind::Awake,
        Some(ParkState::Unknown(_)) | None => ThreadKind::Unread,
    }
}

// ---------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------

fn tasks(
    facts: &Facts<'_>,
    top: usize,
    fit: Option<usize>,
    theme: Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = facts.tasks;
    heading(theme, "Tasks", &owned_heading(facts), out)?;

    // State first: every task is in exactly one of these, so it is
    // the one table that adds up to the total above it. The spelling
    // is the `STATE` cell's, so a row here is a `tasks --group state`
    // bucket — a blocking task's pool spelling, the cancel bit
    // appended — spelled as if no thread were named, so a running
    // blocking task is `blocking (running)` here whether or not the
    // listing knows its lwp.
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    for task in &list.tasks {
        *states.entry(row_state(task, None)).or_default() += 1;
    }
    counts("STATE", rank(tally(states)), theme, out)?;
    writeln!(
        out,
        "{}",
        listing_footer(list.tasks.len(), list.tasks.len(), "task")
    )?;
    writeln!(out)?;

    // What the runtime is full of, by the future a task runs. What the
    // tasks of a type are blocked on hangs off the type rather than
    // being tallied beside it: a thousand tasks on one semaphore is a
    // different target from a thousand types with one waiter each, and
    // only the breakdown under the type tells them apart. Where they
    // are parked and where they were spawned are `tasks --group
    // awaiting` and `tasks --group spawned`, which rank the same sites
    // with the tasks behind each.
    // Tallied by the type itself ([`typenames::tally`]), so two impls
    // of one generic that print alike are two rows, not one.
    let types = typenames::tally(
        list.tasks.iter().enumerate().map(|(index, task)| {
            let ty = match &task.future {
                FutureInfo::Known(known) => Some(known.future),
                _ => None,
            };
            let name = future_name(&task.future, facts.names);
            (
                facts.names.bucket(ty, &name),
                (task, facts.waits.get(index)),
            )
        }),
        |(count, waits): &mut (usize, Waits), (task, wait)| {
            *count += 1;
            if let Some(wait) = wait {
                waits.add_task(task, wait);
            }
        },
    );
    let futures = types
        .into_iter()
        .map(|(name, (count, waits))| chained(name, count, &waits, top));
    tree(ranked(futures, top, more_types), fit, theme, out)
}

/// The wait tally: one bucket per thing a task or a future can be
/// parked on, plus the reasons there is nothing to report.
#[derive(Default)]
struct Waits {
    timer: usize,
    timer_past_due: usize,
    task: usize,
    io: usize,
    /// A bounded mpsc receiver parked on its channel.
    channel: usize,
    /// Queued on a `Notify`.
    notify: usize,
    /// A oneshot receiver parked on its channel.
    oneshot: usize,
    /// A watch receiver parked on a change.
    watch: usize,
    /// Keyed by the primitive wrapping the semaphore, which is `None`
    /// where the awaiting frame did not name one (a channel's, say).
    semaphores: BTreeMap<Option<&'static str>, usize>,
    /// An HTTP connection parked between or inside exchanges, keyed by
    /// the cell word its role and version give (`http1 client`).
    http: BTreeMap<&'static str, usize>,
    /// Parked on several things at once — a `select!`, a hand-written
    /// state machine — with its waker in at least one: any one wakes
    /// it, and no one of them is its dependency.
    one_of: usize,
    /// Parked on a resource that has already given what was asked of
    /// it: the next poll takes it.
    ready: usize,
    /// Mid-poll on a worker: it is running, not waiting.
    running: usize,
    /// In a run queue: runnable, not waiting.
    queued: usize,
    /// Finished, waiting to be joined rather than on anything.
    complete: usize,
    /// Never polled: its storage holds arguments and awaits nothing.
    unresumed: usize,
    /// Its root has run to a terminal state.
    returned: usize,
    /// Its chain ends in a future no poll of which returns `Ready`:
    /// waiting, forever, on nothing that exists.
    never_ready: usize,
    /// No definite answer: the continuation is not established at some
    /// future no reviewed rule covers, the chain was cut short, or the
    /// resource's state is not one its protocol vouches for. On any
    /// real target this is most of them.
    unknown: usize,
}

impl Waits {
    /// Bucket one task by what the analysis assessed it to be waiting
    /// on: a verified wait by the resource's kind, and everything else
    /// by what there is instead — ready, runnable, finished, never
    /// polled, returned, or unknown. A mid-poll task counts as running
    /// whatever its assessment, the way its row spells it.
    fn add_task(&mut self, task: &Task, wait: &TaskWait) {
        if task.state.lifecycle() == Lifecycle::Running {
            self.running += 1;
            return;
        }
        match &wait.assessment {
            WaitAssessment::Waiting(verified) => self.add(verified.target().kind()),
            WaitAssessment::Set(_) => self.one_of += 1,
            WaitAssessment::ResourceReady(_) => self.ready += 1,
            WaitAssessment::Runnable(RunnableReason::ActivePoll) => self.running += 1,
            WaitAssessment::Runnable(RunnableReason::Scheduled) => self.queued += 1,
            WaitAssessment::NotWaiting(NotWaitingReason::Complete) => self.complete += 1,
            WaitAssessment::NotWaiting(_) => self.returned += 1,
            WaitAssessment::Unresumed => self.unresumed += 1,
            WaitAssessment::NeverReady { .. } => self.never_ready += 1,
            WaitAssessment::Unknown(_) => self.unknown += 1,
        }
    }

    /// Bucket one future the census named — held in a frame, or a set's
    /// child — by what it is parked on. It has no lifecycle of its own
    /// to be mid-poll or finished by, so those buckets cannot arise:
    /// what is left is the resource its chain ends in, a terminal
    /// state, or a continuation nothing establishes.
    fn add_future(&mut self, wait: Option<WaitKind>, continuation: &ContinuationStatus) {
        match (wait, continuation) {
            (Some(wait), _) => self.add(wait),
            (None, ContinuationStatus::Unresumed) => self.unresumed += 1,
            (None, ContinuationStatus::Returned | ContinuationStatus::Panicked) => {
                self.returned += 1
            }
            (None, ContinuationStatus::NeverReady) => self.never_ready += 1,
            (None, ContinuationStatus::ActivePoll) => self.running += 1,
            (
                None,
                ContinuationStatus::Primitive
                | ContinuationStatus::Unknown { .. }
                | ContinuationStatus::Incomplete { .. },
            ) => self.unknown += 1,
        }
    }

    fn add(&mut self, kind: WaitKind) {
        match kind {
            WaitKind::Timer { past_due } => {
                self.timer += 1;
                self.timer_past_due += usize::from(past_due.unwrap_or(false));
            }
            WaitKind::Task { .. } => self.task += 1,
            WaitKind::Io { .. } => self.io += 1,
            WaitKind::Semaphore { owner } => *self.semaphores.entry(owner).or_default() += 1,
            WaitKind::Channel { .. } => self.channel += 1,
            WaitKind::Notify { .. } => self.notify += 1,
            WaitKind::Oneshot { .. } => self.oneshot += 1,
            WaitKind::Watch { .. } => self.watch += 1,
            WaitKind::HttpConn { .. } => *self.http.entry(kind.word()).or_default() += 1,
        }
    }

    /// The tally as printable rows, commonest first, each spelled as
    /// the `WAITING ON` column spells the wait at kind level — `io`,
    /// `timer`, `task`, the semaphore by the primitive wrapping it,
    /// `one of several` for a wait set, `ready`, `never ready`, `unknown`
    /// — and a task waiting on nothing by why: `—
    /// (mid-poll)`, `— (queued)`, `— (complete)`, `— (unresumed)`, `—
    /// (returned)`. A closed set, so every nonzero row prints and
    /// `top` cuts nothing.
    fn rows(&self, _top: usize) -> Vec<Row> {
        // A deadline already passed at the moment the target stopped is
        // a wakeup that was owed and had not been delivered, which is
        // worth saying wherever the timer count is said.
        let timer = match self.timer_past_due {
            0 => "timer".to_string(),
            n => format!("timer ({n} past due)"),
        };
        let mut rows = vec![
            Row::new(self.timer, timer),
            Row::new(self.task, "task"),
            Row::new(self.io, "io"),
            Row::new(self.channel, "mpsc rx"),
            Row::new(self.oneshot, "oneshot rx"),
            Row::new(self.watch, "watch rx"),
            Row::new(self.notify, "notify rx"),
            Row::new(self.one_of, "one of several"),
            Row::new(self.ready, "ready"),
            Row::new(self.never_ready, "never ready"),
            Row::new(self.unknown, "unknown"),
            Row::new(self.running, "— (mid-poll)"),
            Row::new(self.queued, "— (queued)"),
            Row::new(self.complete, "— (complete)"),
            Row::new(self.unresumed, "— (unresumed)"),
            Row::new(self.returned, "— (returned)"),
        ];
        for (owner, count) in &self.semaphores {
            let what = match owner {
                Some(owner) => format!("a {owner} (semaphore)"),
                None => "a semaphore".to_string(),
            };
            rows.push(Row::new(*count, what));
        }
        for (word, count) in &self.http {
            rows.push(Row::new(*count, *word));
        }
        rank(rows)
    }
}

// ---------------------------------------------------------------------
// Futures
// ---------------------------------------------------------------------

fn futures(
    facts: &Facts<'_>,
    top: usize,
    fit: Option<usize>,
    theme: Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Every count here is of *chains*, not of the frames they stand on:
    // a chain is one future making progress on its own, and the frames
    // under it are that one future's stack. Counting frames instead
    // would make a task whose wrappers run eight deep read as eight
    // things in flight, and would answer "how many futures are running
    // here" with a number that grows when a library adds a combinator.
    // The depth is not lost — it is the second number on the heading,
    // where it reads as the size of what is in flight rather than as
    // more of it.
    let tasks = facts.tasks.tasks.len();
    let held = facts.held.len();
    let mut slots = 0;
    let mut live = 0;
    for set in facts.sets {
        slots += set.children.len();
        live += set.children.iter().filter(|c| c.future.is_some()).count();
    }

    let depths = || {
        facts
            .waits
            .iter()
            .map(|w| w.depth)
            .chain(facts.held.iter().map(|h| h.depth))
            .chain(facts.sets.iter().flat_map(|s| &s.children).map(|c| c.depth))
    };
    let frames: usize = depths().sum();
    let deepest = depths().max().unwrap_or(0);

    // The three populations are disjoint by construction — a task's own
    // spine, what its frames hold beside it, and what its sets hold —
    // so this total is a sum and not a re-count.
    let in_flight = tasks + held + live;
    heading(
        theme,
        "Futures",
        &format!(
            "{in_flight} in flight, on {}, up to {deepest} deep",
            counted(frames, "await-chain frame"),
        ),
        out,
    )?;

    // Where each is, in the `HELD IN` column's terms: a task's own
    // chain, a frame, a set. Every row prints, a zero included, since
    // the three are a closed set and a zero here says "none" rather
    // than nothing. A reaped slot is a future no longer: it is said on
    // the set row rather than counted, so the table still sums to the
    // footer.
    let reaped = match slots - live {
        0 => String::new(),
        n => format!(", {n} completed and not yet reaped"),
    };
    // `FuturesUnordered` names one set however many there are, so it
    // is spelled as tokio spells it rather than pluralized.
    let places = [
        Row::new(tasks, "task (its own await chain)"),
        Row::new(held, "frame (off any await chain)"),
        Row::new(
            live,
            format!("set ({} FuturesUnordered{reaped})", facts.sets.len()),
        ),
    ];
    counts("HELD IN", places.into_iter().collect(), theme, out)?;
    writeln!(out, "{}", listing_footer(in_flight, in_flight, "future"))?;
    writeln!(out)?;

    // The same tally as the tasks', over the futures no task listing
    // shows: they park on the same things and are as worth naming, and
    // a set of ten thousand children all of one type all waiting on one
    // semaphore is the shape this row exists to make visible — which is
    // why what they wait on hangs off the type here too. It runs over
    // what the census *names* — a chain frame is not among them, since
    // this section counts its depth and nothing else, and the future its
    // task runs is already a row of the tasks' own type tally. A reaped
    // slot is a future no longer, said above rather than counted here.
    let children = facts
        .sets
        .iter()
        .flat_map(|s| &s.children)
        .filter_map(|c| Some((c.future?, c.wait, &c.continuation)));
    let finds = facts
        .held
        .iter()
        .map(|h| (h.future, h.wait, &h.continuation))
        .chain(children);
    let types = typenames::tally(
        finds.map(|(future, wait, continuation)| {
            let name = facts.names.future(future);
            (
                facts.names.bucket(Some(future), &name),
                (wait, continuation),
            )
        }),
        |(count, waits): &mut (usize, Waits), (wait, continuation)| {
            *count += 1;
            waits.add_future(wait, continuation);
        },
    );
    let futures = types
        .into_iter()
        .map(|(name, (count, waits))| chained(name, count, &waits, top));
    tree(ranked(futures, top, more_types), fit, theme, out)
}

// ---------------------------------------------------------------------
// Shared shaping
// ---------------------------------------------------------------------

/// The header of both type tallies. It names the two levels the way
/// perf's `--hierarchy` heads its own: the column holds a type, and
/// under each type, what the futures of that type are waiting on —
/// each branch a whole chain collapsed to its far end rather than the
/// next frame down, which is `trace`'s listing. The second word is the
/// column `tasks` and `futures` print, since a branch here is that
/// column's value, tallied.
const TYPE_HEADER: &str = "TYPE / WAITING ON";

/// The tail row of a type tally: what the rows past `top` add up to.
fn more_types(n: usize) -> String {
    format!("({n} more types)")
}

/// One future type as a row, with what the chains rooted at it are
/// assessed to wait on hanging off it.
fn chained(name: String, count: usize, waits: &Waits, top: usize) -> Row {
    Row::new(count, name).under(waits.rows(top))
}

/// A count and the noun it counts, pluralized.
pub(crate) fn counted(n: usize, noun: &str) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {noun}{plural}")
}

/// One row of a tally: how many, of what, and — where the census has
/// more to say about that row than a number — the tally that breaks it
/// down, drawn as branches beneath it.
struct Row {
    count: usize,
    what: String,
    under: Vec<Row>,
}

impl Row {
    fn new(count: usize, what: impl Into<String>) -> Self {
        Self {
            count,
            what: what.into(),
            under: Vec::new(),
        }
    }

    fn under(mut self, under: Vec<Row>) -> Self {
        self.under = under;
        self
    }
}

/// A name-keyed tally as rows.
fn tally(tally: BTreeMap<String, usize>) -> Vec<Row> {
    tally
        .into_iter()
        .map(|(what, count)| Row::new(count, what))
        .collect()
}

/// Order a tally commonest first, dropping the empty buckets — a zero
/// says nothing a reader needs, and a page of them buries what does.
/// Ties keep their label order, so two runs of the same target print
/// the same page.
fn rank(mut rows: Vec<Row>) -> Vec<Row> {
    rows.retain(|row| row.count > 0);
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.what.cmp(&b.what)));
    rows
}

/// A tally cut to its `top` commonest rows: the rows, with whatever
/// the cut left out summed into a tail row, and the two numbers the
/// footer says — how many there were, how many are shown.
struct Ranked {
    rows: Vec<Row>,
    total: usize,
    shown: usize,
}

/// The `top` commonest entries of a tally, with whatever it leaves out
/// counted rather than dropped in silence: `tail` spells the row that
/// sums them, from how many rows it stands for.
fn ranked(
    tally: impl IntoIterator<Item = Row>,
    top: usize,
    tail: impl Fn(usize) -> String,
) -> Ranked {
    let mut rows = rank(tally.into_iter().collect());
    let total = rows.len();
    let shown = total.min(top);
    if total > top {
        let rest: usize = rows[top..].iter().map(|row| row.count).sum();
        rows.truncate(top);
        rows.push(Row::new(rest, tail(total - top)));
    }
    Ranked { rows, total, shown }
}

/// Print a two-column table of counted rows under `COUNT` and `label`,
/// or nothing for no rows: the caller's footer says what there was.
fn counts(label: &str, rows: Vec<Row>, theme: Theme, out: &mut dyn io::Write) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut table = output::Table::new(2)
        .header(["COUNT", label])
        .align_right(0)
        .theme(theme);
    for row in &rows {
        table.row([row.count.to_string(), row.what.clone()]);
    }
    table.write(out)?;
    Ok(())
}

/// Print a type tally: the `COUNT` / [`TYPE_HEADER`] table, each row's
/// breakdown drawn as branches beneath it, and the `[N types, M
/// shown]` footer.
fn tree(ranked: Ranked, fit: Option<usize>, theme: Theme, out: &mut dyn io::Write) -> Result<()> {
    let Ranked { rows, total, shown } = ranked;
    if !rows.is_empty() {
        let mut table = output::Table::new(2)
            .header(["COUNT", TYPE_HEADER])
            .align_right(0)
            .truncatable(1)
            .fit(fit)
            .theme(theme);
        for row in &rows {
            table.row([row.count.to_string(), row.what.clone()]);
        }
        // The branches hang from where the type starts, so a breakdown
        // reads as the type's and not the count's.
        let indent = " ".repeat(table.width(0) + 2);
        let mut lines = table.render().into_iter();
        writeln!(out, "{}", lines.next().expect("the header line"))?;
        for (row, line) in rows.iter().zip(lines) {
            writeln!(out, "{line}")?;
            if !row.under.is_empty() {
                branches(&row.under, &indent, fit, out)?;
            }
        }
    }
    writeln!(out, "{}", listing_footer(total, shown, "type"))?;
    Ok(())
}

/// Print one row's breakdown as branches under it, the counts
/// right-aligned within the level so the magnitudes line up, as perf's
/// hierarchy indents each level's share with its label.
///
/// `fit` is the width of the whole line, so the indent and the stem
/// come off it before the table fits what is left: a cut name leaves
/// the line within the edge, not just the table's part of it.
fn branches(rows: &[Row], indent: &str, fit: Option<usize>, out: &mut dyn io::Write) -> Result<()> {
    let taken = indent.chars().count() + "├─ ".chars().count();
    let mut table = output::Table::new(2)
        .align_right(0)
        .truncatable(1)
        .fit(fit.map(|fit| fit.saturating_sub(taken)));
    for row in rows {
        table.row([row.count.to_string(), row.what.clone()]);
    }
    let width = table.width(0);
    for ((i, row), line) in rows.iter().enumerate().zip(table.render()) {
        let (stem, run) = match i + 1 == rows.len() {
            true => ("└─ ", "   "),
            false => ("├─ ", "│  "),
        };
        writeln!(out, "{indent}{stem}{line}")?;
        if !row.under.is_empty() {
            let under = format!("{indent}{run}{}", " ".repeat(width + 2));
            branches(&row.under, &under, fit, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use hansei_bundle::{BundleTypeId, FutureKind, TaskEntryId};
    use hansei_runtime::tokio::assess::{
        IncompleteReason, NotWaitingReason, VerifiedWait, WaitAssessment, WaitUnknownReason,
    };
    use hansei_runtime::tokio::bundle::{
        FutureInfo, KnownFuture, OwnerKey, OwnerResolution, RuntimeFlavor, Task, TaskKind,
        WaitTarget,
    };
    use hansei_runtime::tokio::census::SetChild;
    use hansei_runtime::tokio::graph::TaskRef;
    use hansei_runtime::tokio::{Location, RawInstant, TaskAddr, TaskState};

    use crate::typenames::testing::{named, type_names};

    const RUNNING: u64 = 0b1;
    const COMPLETE: u64 = 0b10;
    const NOTIFIED: u64 = 0b100;
    const JOIN_INTEREST: u64 = 0b1_000;
    const CANCELLED: u64 = 0b100_000;
    const REF_ONE: u64 = 1 << 6;

    /// One task, named by id and spelled by the two things the tallies
    /// group on: the future it runs and the line that spawned it.
    fn task(id: u64, bits: u64, future: &str, site: &str) -> Task {
        Task {
            addr: TaskAddr(0x1000 + id * 0x100),
            state: TaskState(REF_ONE | bits),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: Some(Location {
                filename: site.to_string(),
                line: 7,
                col: 1,
            }),
            future: FutureInfo::Known(KnownFuture {
                entry: TaskEntryId(0),
                future: named(future),
                kind: FutureKind::AsyncFn,
                decl: None,
                symbol: "_ZN1x".to_string(),
            }),
            kind: TaskKind::Async,
            owner: OwnerResolution::Known(RUNTIME),
        }
    }

    /// The one runtime the test facts hold, as the tasks' owner key.
    const RUNTIME: OwnerKey = OwnerKey::Runtime {
        flavor: RuntimeFlavor::MultiThread,
        handle: 0x1000,
    };

    /// The heading counts the tasks the executors own; the ones no
    /// owner was established for, and the ones several claimed, are
    /// counted apart rather than filed under the runtime.
    #[test]
    fn test_the_tasks_heading_counts_unowned_tasks_apart() {
        let mut unknown = task(2, 0, "x", "x.rs");
        unknown.owner = OwnerResolution::Unknown;
        let mut conflict = task(3, 0, "x", "x.rs");
        conflict.owner =
            OwnerResolution::Conflict(vec![RUNTIME, OwnerKey::LocalSet { shared: 0x2000 }]);
        let list = TaskList::new(vec![task(1, 0, "x", "x.rs"), unknown, conflict]);
        assert_eq!(
            owned_heading(&facts(&list, &[])),
            "3: 1 owned by runtime 0 @ 0x1000, 1 with no established owner, \
             1 with conflicting owners"
        );
        let owned = TaskList::new(vec![task(1, 0, "x", "x.rs")]);
        assert_eq!(
            owned_heading(&facts(&owned, &[])),
            "1 owned by runtime 0 @ 0x1000"
        );
        // Each apart count prints only when it is nonzero.
        let mut unknown = task(2, 0, "x", "x.rs");
        unknown.owner = OwnerResolution::Unknown;
        let unknown_only = TaskList::new(vec![task(1, 0, "x", "x.rs"), unknown]);
        assert_eq!(
            owned_heading(&facts(&unknown_only, &[])),
            "2: 1 owned by runtime 0 @ 0x1000, 1 with no established owner"
        );
        let mut conflict = task(3, 0, "x", "x.rs");
        conflict.owner =
            OwnerResolution::Conflict(vec![RUNTIME, OwnerKey::LocalSet { shared: 0x2000 }]);
        let conflict_only = TaskList::new(vec![conflict]);
        assert_eq!(
            owned_heading(&facts(&conflict_only, &[])),
            "1: 0 owned by runtime 0 @ 0x1000, 1 with conflicting owners"
        );
    }

    /// A task assessed as verified-waiting on `target`, or — with no
    /// target — with its continuation unknown: parked on a future no
    /// reviewed rule covers.
    fn wait(id: u64, target: Option<WaitTarget>, depth: usize) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000 + id * 0x100),
                task_id: Some(id),
            },
            assessment: match target {
                Some(target) => WaitAssessment::Waiting(VerifiedWait::testkit(target, None)),
                None => WaitAssessment::Unknown(WaitUnknownReason::Continuation),
            },
            continuation: ContinuationStatus::Incomplete {
                reason: IncompleteReason::NoRoot,
                detail: None,
            },
            depth,
            site: None,
            observation: None,
            notes: Vec::new(),
            held: Vec::new(),
            held_capped: 0,
            frames: Vec::new(),
            frame_sites: Vec::new(),
        }
    }

    fn timer(deadline: u64, stopped: u64) -> WaitTarget {
        let at = |tv_sec| RawInstant { tv_sec, tv_nsec: 0 };
        WaitTarget::Timer {
            deadline: at(deadline),
            stopped: Some(at(stopped)),
        }
    }

    fn mutex() -> WaitTarget {
        WaitTarget::Semaphore {
            addr: 0x9000,
            owner: Some("tokio::sync::Mutex"),
            num_permits: 1,
            available: 0,
            closed: false,
            waiters: Vec::new(),
        }
    }

    fn held(future: &str, wait: Option<WaitKind>) -> HeldFuture {
        held_deep(future, wait, 1)
    }

    /// A held future whose own chain ran `depth` frames, for the counts
    /// that must not confuse a future with the frames under it.
    fn held_deep(future: &str, wait: Option<WaitKind>, depth: usize) -> HeldFuture {
        HeldFuture {
            depth,
            frames: Vec::new(),
            owner: 0,
            frame: 0,
            local: "arm".to_string(),
            via: None,
            slot: 0x4000,
            addr: 0x4000,
            ty: BundleTypeId(0),
            future: named(future),
            state: None,
            waiting_on: wait.map(|_| "something".to_string()),
            wait,
            observation: None,
            continuation: match wait {
                Some(_) => ContinuationStatus::Primitive,
                None => ContinuationStatus::Unresumed,
            },
            request: None,
        }
    }

    fn child(future: Option<&str>, wait: Option<WaitKind>) -> SetChild {
        child_deep(future, wait, if future.is_some() { 1 } else { 0 })
    }

    fn child_deep(future: Option<&str>, wait: Option<WaitKind>, depth: usize) -> SetChild {
        SetChild {
            node: 0x2000,
            depth,
            future: future.map(named),
            root: None,
            state: None,
            waiting_on: wait.map(|_| "something".to_string()),
            wait,
            observation: None,
            continuation: match wait {
                Some(_) => ContinuationStatus::Primitive,
                None => ContinuationStatus::Unresumed,
            },
            request: None,
        }
    }

    /// A run-loop thread of runtime 0, polling nothing.
    fn worker(tid: u32, index: u64) -> Thread {
        Thread {
            tid,
            runtime: Some(0),
            role: Some(ThreadRole::Worker(index)),
            polling: None,
        }
    }

    /// A thread that entered runtime 0 without running its loop.
    fn entered(tid: u32) -> Thread {
        Thread {
            tid,
            runtime: Some(0),
            role: None,
            polling: None,
        }
    }

    /// A current_thread runtime's block_on thread, in runtime 0.
    fn block_on(tid: u32, state: Option<CtParkState>, polling: Option<u64>) -> Thread {
        Thread {
            tid,
            runtime: Some(0),
            role: Some(ThreadRole::BlockOn(state)),
            polling,
        }
    }

    /// Print a whole census over facts a test laid out, and hand back
    /// the page.
    fn census(facts: &Facts<'_>, top: usize) -> String {
        sections(facts, Sections::select(false, false, false), top)
    }

    /// The same, narrowed to the sections named.
    fn sections(facts: &Facts<'_>, sections: Sections, top: usize) -> String {
        fitted(facts, sections, top, None)
    }

    /// The same, its lines fit within `fit` columns.
    fn fitted(facts: &Facts<'_>, sections: Sections, top: usize, fit: Option<usize>) -> String {
        let mut out = Vec::new();
        print(facts, sections, top, fit, Theme::plain(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// The thread section alone — the page up to its first blank line
    /// past the heading's own.
    fn thread_section(facts: &Facts<'_>) -> String {
        sections(facts, Sections::select(true, false, false), 5)
    }

    /// The one runtime the thread fixtures below are inside, holding
    /// the readings a test gives it.
    fn runtime(parks: Option<ParkStates>, pool: Option<BlockingPool>) -> Runtime {
        Runtime {
            label: "runtime 0 @ 0x1000".to_string(),
            parks,
            pool,
        }
    }

    /// The facts of an empty runtime, for a test to fill in the part it
    /// is about.
    fn facts<'a>(tasks: &'a TaskList, waits: &'a [TaskWait]) -> Facts<'a> {
        Facts {
            lwps: Vec::new(),
            runtime: Vec::new(),
            runtimes: vec![runtime(None, None)],
            local_sets: 0,
            tasks,
            waits,
            held: &[],
            sets: &[],
            names: type_names(),
        }
    }

    fn empty() -> TaskList {
        TaskList::new(Vec::new())
    }

    /// A code the fault table does not name is still evidence — it is
    /// printed as a number rather than dropped, with no address, since
    /// an undecoded code does not say the siginfo carried one.
    #[test]
    fn test_an_unnamed_code_prints_as_a_number() {
        let sig = proc::FatalSignal {
            name: "SIGSEGV",
            signo: 11,
            code: 128,
            code_name: None,
            fault_addr: None,
            lwp: None,
            sender: None,
        };
        assert_eq!(fatal_signal_line(&sig), "SIGSEGV (code 128)");
    }

    /// The heading's name and colon are bold on a terminal and bare
    /// bytes everywhere else, as is each table's header line; nothing
    /// else on the page is styled.
    #[test]
    fn test_headings_are_bold_only_on_a_terminal() {
        let list = empty();
        let facts = facts(&list, &[]);
        let plain = census(&facts, 5);
        assert!(
            plain.starts_with("Threads: 0 lwps, 0 in runtime 0 @ 0x1000\n\n"),
            "{plain}"
        );
        assert!(!plain.contains('\x1b'), "{plain}");

        let mut out = Vec::new();
        let all = Sections::select(false, false, false);
        print(&facts, all, 5, None, Theme::forced(), &mut out).unwrap();
        let styled = String::from_utf8(out).unwrap();
        assert!(
            styled.starts_with("\x1b[1mThreads:\x1b[0m 0 lwps, 0 in runtime 0 @ 0x1000\n\n"),
            "{styled}"
        );
        assert!(
            styled.contains("\n\x1b[1mTasks:\x1b[0m 0 owned by"),
            "{styled}"
        );
        assert!(
            styled.contains("\n\x1b[1mFutures:\x1b[0m 0 in flight"),
            "{styled}"
        );
        assert!(
            styled.contains("\n\x1b[1mCOUNT  HELD IN\x1b[0m\n    0  task"),
            "{styled}"
        );
        assert_eq!(styled.matches('\x1b').count(), 8, "{styled}");
    }

    /// Every run-loop thread is a row by what it is doing, the rows of
    /// one runtime ranked by count as `--group` ranks its buckets and,
    /// among equals, the driver holder first; a polling row names the
    /// task beside each lwp; the pool is a share of the threads that
    /// entered, netted of the workers it launched; and the lwps outside
    /// every runtime close the table.
    #[test]
    fn test_threads_are_rows_by_role_and_state() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12, 13, 14, 15, 16];
        let mut polling = worker(12, 1);
        polling.polling = Some(42);
        facts.runtime = vec![worker(11, 0), polling, worker(13, 2), entered(14)];
        // The pool counts the three workers among its four threads,
        // since the runtime launched each of them with spawn_blocking.
        facts.runtimes = vec![runtime(
            Some(ParkStates {
                workers: vec![ParkState::Driver, ParkState::Awake, ParkState::Condvar],
                driver_held: true,
            }),
            Some(BlockingPool {
                threads: 4,
                idle: 1,
                queued: 1,
            }),
        )];

        assert_eq!(
            thread_section(&facts),
            "Threads: 6 lwps, 4 in runtime 0 @ 0x1000\n\
             \n\
             COUNT  RT  ROLE           STATE                     LWPS\n\
             \x20   1  0   worker         in driver                 11\n\
             \x20   1  0   worker         polling                   12 (task 42)\n\
             \x20   1  0   worker         parked                    13\n\
             \x20   1  0   blocking pool  1 idle, 0 busy, 1 queued  14\n\
             \x20   2  —   no runtime     —                         15, 16\n\
             [6 lwps]\n"
        );
    }

    /// A row samples three of its lwps and says there are more, as a
    /// `--group` bucket samples its members.
    #[test]
    fn test_a_row_samples_three_lwps() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![1, 2, 3, 4, 5];
        facts.runtime = (1..=5).map(|tid| worker(tid, u64::from(tid) - 1)).collect();
        facts.runtimes = vec![runtime(
            Some(ParkStates {
                workers: vec![ParkState::Condvar; 5],
                driver_held: false,
            }),
            None,
        )];
        let page = thread_section(&facts);
        assert!(
            page.contains("    5  0   worker  parked  1, 2, 3, …\n"),
            "{page}"
        );
        assert!(!page.contains("entered runtime"), "{page}");
    }

    /// Where the pool's threads and the block_on callers both have
    /// members, neither row can say which lwps are its — the census
    /// reads no stacks — so both count and neither lists.
    #[test]
    fn test_a_split_pool_lists_no_lwps() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12, 13, 14];
        facts.runtime = vec![worker(11, 0), entered(12), entered(13), entered(14)];
        facts.runtimes = vec![runtime(
            Some(ParkStates {
                workers: vec![ParkState::Condvar],
                driver_held: false,
            }),
            Some(BlockingPool {
                threads: 3,
                idle: 2,
                queued: 0,
            }),
        )];
        assert_eq!(
            thread_section(&facts),
            "Threads: 4 lwps, 4 in runtime 0 @ 0x1000\n\
             \n\
             COUNT  RT  ROLE             STATE            LWPS\n\
             \x20   2  0   blocking pool    2 idle, 0 busy   —\n\
             \x20   1  0   worker           parked           11\n\
             \x20   1  0   entered runtime  block_on caller  —\n\
             [4 lwps]\n"
        );
    }

    /// A pool whose count does not reconcile with the workers it
    /// launched is reported as its own count rather than netted into a
    /// share of a row it would not add up to.
    #[test]
    fn test_an_unreconciled_pool_count_is_reported_as_the_pools_own() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12];
        facts.runtime = vec![worker(11, 0), entered(12)];
        facts.runtimes = vec![runtime(
            Some(ParkStates {
                workers: vec![ParkState::Condvar],
                driver_held: false,
            }),
            Some(BlockingPool {
                threads: 9,
                idle: 4,
                queued: 0,
            }),
        )];
        let page = thread_section(&facts);
        assert!(
            page.contains(
                "    1  0   entered runtime  pool counts 9 threads (workers among them), 4 idle  12\n"
            ),
            "{page}"
        );
    }

    /// A current_thread runtime's block_on thread is classified from
    /// its own core rather than a parker word: parked in the driver
    /// here, in the row the driver-holding worker would take. The pool
    /// needs no netting: no worker of this flavor was launched through
    /// spawn_blocking.
    #[test]
    fn test_a_block_on_thread_is_classified_from_its_core() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12, 13];
        facts.runtime = vec![
            block_on(
                11,
                Some(CtParkState {
                    woken: true,
                    activity: CtActivity::Parked,
                }),
                None,
            ),
            entered(12),
        ];
        facts.runtimes = vec![runtime(
            None,
            Some(BlockingPool {
                threads: 1,
                idle: 1,
                queued: 0,
            }),
        )];

        assert_eq!(
            thread_section(&facts),
            "Threads: 3 lwps, 2 in runtime 0 @ 0x1000\n\
             \n\
             COUNT  RT  ROLE             STATE           LWPS\n\
             \x20   1  0   block_on thread  in driver       11\n\
             \x20   1  0   blocking pool    1 idle, 0 busy  12\n\
             \x20   1  —   no runtime       —               13\n\
             [3 lwps]\n"
        );
    }

    /// The two polling states a block_on thread can be in, told apart
    /// by the thread-local task id: the root future when none is set,
    /// a spawned task — the row a worker mid-poll takes — when the
    /// listing believes the id.
    #[test]
    fn test_block_on_activities_have_their_own_rows() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12];
        facts.runtime = vec![
            block_on(
                11,
                Some(CtParkState {
                    woken: false,
                    activity: CtActivity::PollingBlockOn,
                }),
                None,
            ),
            block_on(
                12,
                Some(CtParkState {
                    woken: false,
                    activity: CtActivity::PollingTask(7),
                }),
                Some(7),
            ),
        ];

        let page = thread_section(&facts);
        assert!(
            page.contains(
                "    1  0   block_on thread  polling           12 (task 7)\n    \
                 1  0   block_on thread  polling block_on  11\n"
            ),
            "{page}"
        );
    }

    /// The states that are neither parked nor a believed poll are
    /// awake, not polling: a task id the listing does not back (a
    /// completed task's output being taken, a task it does not carry),
    /// the bookkeeping between polls, and a shutdown's drops. The
    /// polling claim is only made when a believed task id backs it.
    #[test]
    fn test_unbelieved_and_between_poll_states_are_awake() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12, 13];
        facts.runtime = vec![
            block_on(
                11,
                Some(CtParkState {
                    woken: false,
                    activity: CtActivity::PollingTask(7),
                }),
                None,
            ),
            block_on(
                12,
                Some(CtParkState {
                    woken: false,
                    activity: CtActivity::BetweenPolls,
                }),
                None,
            ),
            block_on(
                13,
                Some(CtParkState {
                    woken: false,
                    activity: CtActivity::DroppingTask(7),
                }),
                None,
            ),
        ];

        let page = thread_section(&facts);
        assert!(
            page.contains("    3  0   block_on thread  awake  11, 12, 13\n"),
            "{page}"
        );
        assert!(!page.contains("polling"), "{page}");
    }

    /// A pool with nothing in it but the workers still prints its row:
    /// the threads idle in it and the tasks queued on it are the two
    /// numbers a reader came for, and a pool of none with a task queued
    /// on it is a state worth seeing. The thread that entered is then
    /// wholly the caller's, and the row says which lwp it is.
    #[test]
    fn test_a_pool_of_workers_alone_still_reports_its_counters() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12];
        facts.runtime = vec![worker(11, 0), entered(12)];
        facts.runtimes = vec![runtime(
            Some(ParkStates {
                workers: vec![ParkState::Condvar],
                driver_held: false,
            }),
            Some(BlockingPool {
                threads: 1,
                idle: 0,
                queued: 3,
            }),
        )];

        let page = thread_section(&facts);
        assert!(
            page.contains("    1  0   entered runtime  block_on caller           12\n"),
            "{page}"
        );
        assert!(
            page.ends_with("    0  0   blocking pool    0 idle, 0 busy, 3 queued  —\n[2 lwps]\n"),
            "{page}"
        );
    }

    /// A runtime whose pool could not be read still lists the threads
    /// that entered it, with nothing claimed about which pool they are.
    #[test]
    fn test_no_pool_reading_leaves_the_entered_row_bare() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12];
        facts.runtime = vec![worker(11, 0), entered(12)];
        let page = thread_section(&facts);
        assert!(
            page.contains("    1  0   entered runtime  —                  12\n"),
            "{page}"
        );
    }

    /// A worker index addresses its own scheduler's parker array and no
    /// other, so a second runtime's worker 0 is classified from that
    /// runtime's parkers — not from the first runtime's, which is a
    /// different thread's state that happens to share an index. The
    /// `RT` column is what tells the two rows apart.
    #[test]
    fn test_each_thread_is_classified_from_its_own_runtimes_parkers() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = vec![11, 12];
        let mut second = worker(12, 0);
        second.runtime = Some(1);
        facts.runtime = vec![worker(11, 0), second];
        facts.runtimes = vec![
            runtime(
                Some(ParkStates {
                    workers: vec![ParkState::Driver],
                    driver_held: true,
                }),
                None,
            ),
            Runtime {
                label: "runtime 1 @ 0x2000".to_string(),
                parks: Some(ParkStates {
                    workers: vec![ParkState::Condvar],
                    driver_held: false,
                }),
                pool: None,
            },
        ];

        assert_eq!(
            thread_section(&facts),
            "Threads: 2 lwps, 2 in 2 runtimes\n\
             \n\
             COUNT  RT  ROLE    STATE      LWPS\n\
             \x20   1  0   worker  in driver  11\n\
             \x20   1  1   worker  parked     12\n\
             [2 lwps]\n"
        );
    }

    /// A task whose future the bundle cannot name is a type row like
    /// any other, spelled as the `TYPE` column spells it.
    #[test]
    fn test_unnamed_futures_are_a_type_row() {
        let mut unnamed = task(1, 0, "x", "x.rs");
        unnamed.future = FutureInfo::Unknown { poll_symbol: None };
        let list = TaskList::new(vec![unnamed]);
        let waits = [wait(1, None, 1)];
        let page = census(&facts(&list, &waits), 5);
        assert!(
            page.contains("COUNT  TYPE / WAITING ON\n    1  <unknown>\n"),
            "{page}"
        );
    }

    /// A finished task parks on nothing: the tally says so rather than
    /// counting it among the chains that stopped short.
    #[test]
    fn test_complete_tasks_wait_on_nothing() {
        let list = TaskList::new(vec![task(1, COMPLETE, "x", "x.rs")]);
        let mut complete = wait(1, None, 1);
        complete.assessment = WaitAssessment::NotWaiting(NotWaitingReason::Complete);
        let waits = [complete];
        let page = census(&facts(&list, &waits), 5);
        assert!(page.contains("└─ 1  — (complete)\n"), "{page}");
    }

    /// A chain ending in a future that is never ready is its own row,
    /// for a task and for a held future alike: waiting, forever, on
    /// nothing that exists is neither `returned` nor `unknown`.
    #[test]
    fn test_never_ready_counts_its_own_row() {
        let list = TaskList::new(
            (1..=3)
                .map(|id| task(id, JOIN_INTEREST, "x::fut", "x.rs"))
                .collect(),
        );
        let never_ready = || WaitAssessment::NeverReady {
            members: Vec::new(),
            capped: 0,
        };
        let assessed = |id, assessment| {
            let mut wait = wait(id, None, 1);
            wait.assessment = assessment;
            wait
        };
        let waits = [
            assessed(1, never_ready()),
            assessed(2, never_ready()),
            assessed(3, WaitAssessment::NotWaiting(NotWaitingReason::Returned)),
        ];
        let continued = |continuation| {
            let mut held = held("h::fut", None);
            held.continuation = continuation;
            held
        };
        let held = [
            continued(ContinuationStatus::NeverReady),
            continued(ContinuationStatus::NeverReady),
            continued(ContinuationStatus::Returned),
        ];
        let mut facts = facts(&list, &waits);
        facts.held = &held;

        let tasks = sections(&facts, Sections::select(false, true, false), 10);
        assert!(
            tasks.contains(
                "    3  future x::fut\n       \
                 ├─ 2  never ready\n       \
                 └─ 1  — (returned)\n"
            ),
            "{tasks}"
        );
        let futures = sections(&facts, Sections::select(false, false, true), 10);
        assert!(
            futures.contains(
                "    3  future h::fut\n       \
                 ├─ 2  never ready\n       \
                 └─ 1  — (returned)\n"
            ),
            "{futures}"
        );
    }

    /// Every bucket a task can land in short of a verified wait counts
    /// on its own: a ready resource, a mid-poll assessment, a returned
    /// or panicked root and a never-polled one each print their own
    /// row with their own count — and a held future lands in the same
    /// rows by its continuation, so none of them can stand in for
    /// another.
    #[test]
    fn test_each_wait_bucket_counts_its_own() {
        use hansei_runtime::tokio::assess::{ReadyReason, RunnableReason};

        let list = TaskList::new(
            (1..=5)
                .map(|id| task(id, JOIN_INTEREST, "x::fut", "x.rs"))
                .collect(),
        );
        let assessed = |id, assessment| {
            let mut wait = wait(id, None, 1);
            wait.assessment = assessment;
            wait
        };
        let waits = [
            assessed(1, WaitAssessment::ResourceReady(ReadyReason::JoinComplete)),
            assessed(2, WaitAssessment::Runnable(RunnableReason::ActivePoll)),
            assessed(3, WaitAssessment::NotWaiting(NotWaitingReason::Returned)),
            assessed(4, WaitAssessment::NotWaiting(NotWaitingReason::Panicked)),
            assessed(5, WaitAssessment::Unresumed),
        ];
        let continued = |continuation| {
            let mut held = held("h::fut", None);
            held.continuation = continuation;
            held
        };
        let held = [
            continued(ContinuationStatus::Returned),
            continued(ContinuationStatus::Panicked),
            continued(ContinuationStatus::ActivePoll),
            continued(ContinuationStatus::Unresumed),
        ];
        let mut facts = facts(&list, &waits);
        facts.held = &held;

        let tasks = sections(&facts, Sections::select(false, true, false), 10);
        assert!(
            tasks.contains(
                "COUNT  TYPE / WAITING ON\n    \
                 5  future x::fut\n       \
                 ├─ 2  — (returned)\n       \
                 ├─ 1  ready\n       \
                 ├─ 1  — (mid-poll)\n       \
                 └─ 1  — (unresumed)\n\
                 [1 type]\n"
            ),
            "{tasks}"
        );
        let futures = sections(&facts, Sections::select(false, false, true), 10);
        assert!(
            futures.contains(
                "COUNT  TYPE / WAITING ON\n    \
                 4  future h::fut\n       \
                 ├─ 2  — (returned)\n       \
                 ├─ 1  — (mid-poll)\n       \
                 └─ 1  — (unresumed)\n\
                 [1 type]\n"
            ),
            "{futures}"
        );
    }

    /// At exactly `top` leaves nothing is summarized, and no leaf row
    /// is pinned to the bottom: every row still ranks among the others.
    #[test]
    fn test_the_wait_rows_rank_by_count_and_cut_nothing() {
        let waits = Waits {
            unknown: 5,
            ready: 2,
            one_of: 3,
            unresumed: 1,
            ..Waits::default()
        };
        let whats: Vec<String> = waits.rows(2).into_iter().map(|r| r.what).collect();
        assert_eq!(
            whats,
            ["unknown", "one of several", "ready", "— (unresumed)"]
        );
    }

    /// A wait set is its own bucket — parked on several things, a
    /// dependency on none — and never counts under any one member's
    /// kind.
    #[test]
    fn test_a_wait_set_counts_as_one_of_several() {
        use hansei_bundle::SemanticIssueKind;
        use hansei_runtime::tokio::observe::ValueKey;
        use hansei_runtime::tokio::waitset::{MemberRoute, SlotRef, WaitMember, WaitSet};

        let list = TaskList::new(vec![task(1, JOIN_INTEREST, "x::fut", "x.rs")]);
        let mut set = wait(1, None, 1);
        set.assessment = WaitAssessment::Set(WaitSet {
            at: Some(ValueKey {
                addr: 0x5000,
                ty: BundleTypeId(7),
            }),
            reason: Some(SemanticIssueKind::NoRule),
            members: vec![WaitMember {
                route: MemberRoute::Branch {
                    local: "a".to_string(),
                    borrowed: false,
                },
                key: None,
                future: None,
                assessment: Some(WaitAssessment::Waiting(VerifiedWait::testkit(
                    WaitTarget::Io {
                        addr: 0x7000,
                        fd: None,
                        interest: None,
                        handshake: false,
                        tls: None,
                    },
                    None,
                ))),
                notes: Vec::new(),
                armed: Some(SlotRef::Protocol),
                entries: None,
            }],
            capped: 0,
        });
        let waits = [set];
        let facts = facts(&list, &waits);
        let tasks = sections(&facts, Sections::select(false, true, false), 10);
        assert!(
            tasks.contains("1  future x::fut\n       └─ 1  one of several\n"),
            "{tasks}"
        );
        assert!(!tasks.contains("io"), "{tasks}");
    }

    /// `top` truncates only past itself: at exactly `top` entries there
    /// is nothing left out and no tail row is added; past it, the tail
    /// sums what was cut and the footer's numbers say how many rows.
    #[test]
    fn test_ranked_summarizes_only_past_top() {
        let rows = |counts: &[usize]| -> Vec<Row> {
            counts
                .iter()
                .enumerate()
                .map(|(i, c)| Row::new(*c, format!("k{i}")))
                .collect()
        };
        let exact = ranked(rows(&[5, 3]), 2, more_types);
        assert_eq!(exact.rows.len(), 2);
        assert_eq!((exact.total, exact.shown), (2, 2));
        let more = ranked(rows(&[5, 3, 1]), 2, more_types);
        assert_eq!(more.rows.len(), 3);
        assert_eq!(more.rows[2].what, "(1 more types)");
        assert_eq!(more.rows[2].count, 1);
        assert_eq!((more.total, more.shown), (3, 2));
    }

    /// Every task lands in exactly one state row and exactly one wait
    /// branch, so both add up to the total over them. A task with no
    /// wait target is bucketed by why it has none, and the wait
    /// branches hang off the future type whose tasks they count. The
    /// state rows are the `STATE` cells, so a cancelled task is its
    /// lifecycle with the bit appended, as `tasks --group state` would
    /// bucket it.
    #[test]
    fn test_task_tallies_count_every_task_once() {
        let list = TaskList::new(vec![
            task(1, JOIN_INTEREST, "a::fut", "a.rs"),
            task(2, JOIN_INTEREST, "a::fut", "a.rs"),
            task(3, JOIN_INTEREST | RUNNING, "b::fut", "b.rs"),
            task(4, NOTIFIED | CANCELLED, "b::fut", "b.rs"),
            task(5, JOIN_INTEREST, "c::fut", "c.rs"),
            task(6, JOIN_INTEREST, "c::fut", "c.rs"),
            task(7, JOIN_INTEREST, "c::fut", "c.rs"),
        ]);
        let waits = vec![
            wait(1, Some(timer(10, 4)), 3),
            wait(2, Some(timer(4, 10)), 2),
            wait(3, None, 1),
            wait(4, Some(mutex()), 1),
            // Parked on futures no rule covers: unknown, whatever type
            // the chain stopped at.
            wait(5, None, 4),
            wait(6, None, 4),
            wait(7, None, 2),
        ];
        let page = sections(
            &facts(&list, &waits),
            Sections::select(false, true, false),
            5,
        );

        assert_eq!(
            page,
            "Tasks: 7 owned by runtime 0 @ 0x1000\n\
             \n\
             COUNT  STATE\n\
             \x20   5  idle\n\
             \x20   1  queued (cancelled)\n\
             \x20   1  running\n\
             [7 tasks]\n\
             \n\
             COUNT  TYPE / WAITING ON\n\
             \x20   3  future c::fut\n\
             \x20      └─ 3  unknown\n\
             \x20   2  future a::fut\n\
             \x20      └─ 2  timer (1 past due)\n\
             \x20   2  future b::fut\n\
             \x20      ├─ 1  a tokio::sync::Mutex (semaphore)\n\
             \x20      └─ 1  — (mid-poll)\n\
             [3 types]\n"
        );
    }

    /// A blocking task's state is the pool spelling its `STATE` cell
    /// carries, less the lwp — one bucket for every running blocking
    /// task, as a census wants.
    #[test]
    fn test_blocking_tasks_are_a_state_row() {
        let mut blocking = task(1, RUNNING, "x", "x.rs");
        blocking.kind = TaskKind::Blocking;
        let list = TaskList::new(vec![blocking, task(2, 0, "x", "x.rs")]);
        let page = census(&facts(&list, &[]), 5);
        assert!(
            page.contains("COUNT  STATE\n    1  blocking (running)\n    1  idle\n[2 tasks]\n"),
            "{page}"
        );
    }

    /// The wait rows are a closed set — the primitives and the reasons
    /// there is nothing to say — so `--limit` bounds none of them:
    /// cutting one would drop a fact rather than a long tail.
    #[test]
    fn test_top_bounds_none_of_the_wait_rows() {
        let mut tasks = Vec::new();
        let mut waits = Vec::new();
        for i in 0..4 {
            for _ in 0..=i {
                let id = tasks.len() as u64;
                tasks.push(task(id, JOIN_INTEREST, "f", "f.rs"));
                waits.push(wait(id, None, 1));
            }
        }
        // One task on a timer, which no bound may cut.
        let id = tasks.len() as u64;
        tasks.push(task(id, JOIN_INTEREST, "f", "f.rs"));
        waits.push(wait(id, Some(timer(10, 4)), 1));

        let list = TaskList::new(tasks);
        let page = census(&facts(&list, &waits), 2);
        assert!(
            page.contains(
                "COUNT  TYPE / WAITING ON\n   \
                 11  future f\n       \
                 ├─ 10  unknown\n       \
                 └─  1  timer\n\
                 [1 type]\n"
            ),
            "{page}"
        );
    }

    /// Two types that print alike are two rows, each labelled with its
    /// id, not one row counting both.
    #[test]
    fn test_types_that_print_alike_are_tallied_apart() {
        let (plain, spelled) = ("app::Wrap<u32>", "app::Wrap<u32, alloc::alloc::Global>");
        let list = TaskList::new(vec![
            task(1, JOIN_INTEREST, plain, "a.rs"),
            task(2, JOIN_INTEREST, spelled, "a.rs"),
            task(3, JOIN_INTEREST, spelled, "a.rs"),
        ]);
        let waits = vec![wait(1, None, 1), wait(2, None, 1), wait(3, None, 1)];
        let page = census(&facts(&list, &waits), 5);
        for (name, count) in [(plain, 1), (spelled, 2)] {
            let row = format!(
                "    {count}  future app::Wrap<u32> (type {})\n",
                named(name).0
            );
            assert!(page.contains(&row), "{row:?} in {page}");
        }
        assert!(page.contains("[2 types]\n"), "{page}");
    }

    /// Every type gets its breakdown, the tasks parked on futures no
    /// rule covers counted as unknown beside the verified waits.
    #[test]
    fn test_every_type_gets_its_breakdown() {
        let list = TaskList::new(vec![
            task(1, JOIN_INTEREST, "a::fut", "a.rs"),
            task(2, JOIN_INTEREST, "a::fut", "a.rs"),
            task(3, JOIN_INTEREST, "b::fut", "b.rs"),
            task(4, JOIN_INTEREST, "b::fut", "b.rs"),
        ]);
        let waits = vec![
            wait(1, None, 1),
            wait(2, None, 1),
            wait(3, None, 1),
            wait(4, Some(timer(10, 4)), 1),
        ];
        let page = census(&facts(&list, &waits), 5);

        assert!(
            page.contains(
                "COUNT  TYPE / WAITING ON\n    \
                 2  future a::fut\n       \
                 └─ 2  unknown\n    \
                 2  future b::fut\n       \
                 ├─ 1  timer\n       \
                 └─ 1  unknown\n\
                 [2 types]\n"
            ),
            "{page}"
        );
    }

    /// A tally bounded by `--limit` sums what it left out into a tail
    /// row rather than dropping it, so the rows still account for
    /// every task, and the footer says how many types there were.
    #[test]
    fn test_top_bounds_the_listings_and_counts_the_rest() {
        let mut tasks = Vec::new();
        for i in 0..6 {
            for _ in 0..=i {
                tasks.push(task(
                    i,
                    JOIN_INTEREST,
                    &format!("f{i}"),
                    &format!("f{i}.rs"),
                ));
            }
        }
        let list = TaskList::new(tasks);
        let page = census(&facts(&list, &[]), 2);

        assert!(
            page.contains(
                "COUNT  TYPE / WAITING ON\n    \
                 6  future f5\n    \
                 5  future f4\n   \
                 10  (4 more types)\n\
                 [6 types, 2 shown]\n"
            ),
            "{page}"
        );
    }

    /// The three future populations are disjoint, so the headline is
    /// their sum: a set's children are not also held futures, and a
    /// reaped slot is neither — it is said on the set row and not
    /// counted, so the table sums to its footer.
    ///
    /// Every one of them counts *futures*, never the frames they stand
    /// on — the two tasks here run three and two frames deep, and are
    /// two futures in flight, not five. The frames are the heading's
    /// second number, where they read as the size of what is in flight
    /// rather than as more of it.
    #[test]
    fn test_future_populations_do_not_overlap() {
        let list = TaskList::new(vec![
            task(1, JOIN_INTEREST, "a::fut", "a.rs"),
            task(2, JOIN_INTEREST, "b::fut", "b.rs"),
        ]);
        let waits = vec![wait(1, None, 3), wait(2, None, 2)];
        let held = vec![held("held::fut", Some(WaitKind::Task { addr: 0x7100 }))];
        let sets = vec![FutureSet {
            owner: 0,
            frame: 0,
            local: "pending".to_string(),
            via: None,
            addr: 0x5000,
            ty: named("FuturesUnordered<f>"),
            children: vec![
                child(Some("child::fut"), Some(WaitKind::Timer { past_due: None })),
                child(None, None),
            ],
        }];
        let mut facts = facts(&list, &waits);
        facts.held = &held;
        facts.sets = &sets;

        let page = sections(&facts, Sections::select(false, false, true), 5);
        assert_eq!(
            page,
            // 2 tasks, 1 held, 1 resident set child: the reaped slot is
            // said, and deliberately not added in. Their chains run
            // 3 + 2 + 1 + 1 frames.
            "Futures: 4 in flight, on 7 await-chain frames, up to 3 deep\n\
             \n\
             COUNT  HELD IN\n\
             \x20   2  task (its own await chain)\n\
             \x20   1  frame (off any await chain)\n\
             \x20   1  set (1 FuturesUnordered, 1 completed and not yet reaped)\n\
             [4 futures]\n\
             \n\
             COUNT  TYPE / WAITING ON\n\
             \x20   1  future child::fut\n\
             \x20      └─ 1  timer\n\
             \x20   1  future held::fut\n\
             \x20      └─ 1  task\n\
             [2 types]\n"
        );
    }

    /// The futures' type tally spans both populations the census names,
    /// bounds itself by `--limit` as the tasks' does, and leaves the
    /// reaped slots — which are no future's type — out.
    #[test]
    fn test_future_types_tally_the_held_and_the_resident() {
        let list = empty();
        let held: Vec<HeldFuture> = (0..3).map(|_| held("hot::fut", None)).collect();
        // One child's continuation is not established: its type's
        // branch counts it as unknown rather than among the unpolled.
        let mut with_leaf = child(Some("cold::fut"), None);
        with_leaf.continuation = ContinuationStatus::Incomplete {
            reason: IncompleteReason::DepthLimit,
            detail: None,
        };
        let sets = vec![FutureSet {
            owner: 0,
            frame: 0,
            local: "pending".to_string(),
            via: None,
            addr: 0x5000,
            ty: named("FuturesUnordered<f>"),
            children: vec![
                child(Some("hot::fut"), None),
                with_leaf,
                child(Some("rare::fut"), None),
                child(None, None),
            ],
        }];
        let mut facts = facts(&list, &[]);
        facts.held = &held;
        facts.sets = &sets;

        let page = census(&facts, 2);
        assert!(
            page.contains(
                "COUNT  TYPE / WAITING ON\n    \
                 4  future hot::fut\n       \
                 └─ 4  — (unresumed)\n    \
                 1  future cold::fut\n       \
                 └─ 1  unknown\n    \
                 1  (1 more types)\n\
                 [3 types, 2 shown]\n"
            ),
            "{page}"
        );
    }

    /// A fit cuts a tallied name to the room its line leaves it, the
    /// count taken off first so the whole line lands within the edge,
    /// with an ellipsis to say so; without a fit the name prints whole
    /// however long. A branch's line is cut the same way, its indent
    /// and stem taken off too.
    #[test]
    fn test_a_fit_cuts_the_tallied_names_to_the_line() {
        const LONG: &str = "a::very::long::module::path::to::some::future_type";
        let list = empty();
        let held: Vec<HeldFuture> = (0..2)
            .map(|_| {
                held(
                    LONG,
                    Some(WaitKind::Io {
                        addr: 0x7000,
                        handshake: false,
                    }),
                )
            })
            .chain([held(LONG, Some(WaitKind::Task { addr: 0x7100 }))])
            .collect();
        let mut facts = facts(&list, &[]);
        facts.held = &held;
        let futures = Sections::select(false, false, true);

        let whole = fitted(&facts, futures, 2, None);
        assert!(
            whole.contains(&format!("\n    3  future {LONG}\n")),
            "{whole}"
        );

        let cut = fitted(&facts, futures, 2, Some(40));
        let line = cut.lines().find(|l| l.contains("future a::")).unwrap();
        assert_eq!(line.chars().count(), 40, "{cut}");
        assert!(line.ends_with('…'), "{cut}");
        assert!(line.starts_with("    3  future a::very"), "{cut}");
        // The branches fit too, and are short enough to print whole.
        assert!(
            cut.contains("\n       ├─ 2  io\n       └─ 1  task\n"),
            "{cut}"
        );
    }

    /// A census names the sections it was asked for and nothing else,
    /// with the blank line between them rather than around them — so a
    /// narrowed page starts on its heading and ends on its last footer.
    #[test]
    fn test_named_sections_print_alone() {
        let list = TaskList::new(vec![task(1, 0, "one::fut", "src/a.rs")]);
        let waits = vec![wait(1, Some(timer(9, 1)), 2)];
        let mut facts = facts(&list, &waits);
        facts.lwps = vec![11];
        facts.runtime = vec![worker(11, 0)];

        let only_tasks = sections(&facts, Sections::select(false, true, false), 5);
        assert!(
            only_tasks.starts_with("Tasks: 1 owned by runtime 0 @ 0x1000\n"),
            "{only_tasks}"
        );
        assert!(only_tasks.ends_with("[1 type]\n"), "{only_tasks}");
        assert!(!only_tasks.contains("Threads:"), "{only_tasks}");
        assert!(!only_tasks.contains("Futures:"), "{only_tasks}");

        // Two of them: the second heading follows the first section's
        // footer after one blank line, and the page ends on a footer.
        let two = sections(&facts, Sections::select(true, false, true), 5);
        assert!(
            two.starts_with("Threads: 1 lwp, 1 in runtime 0 @ 0x1000\n"),
            "{two}"
        );
        assert!(two.contains("\n[1 lwp]\n\nFutures: 1 in flight, "), "{two}");
        assert!(!two.contains("Tasks:"), "{two}");
        // The task's own type is the task section's row, not the
        // future section's: this page names no future type.
        assert!(two.ends_with("[1 future]\n\n[0 types]\n"), "{two}");
    }

    /// A section over nothing is its heading and its footers: a table
    /// with no rows prints no header, since a header over no rows
    /// reads as data missing rather than absent.
    #[test]
    fn test_an_empty_section_is_heading_and_footers() {
        let list = empty();
        let facts = facts(&list, &[]);
        assert_eq!(
            sections(&facts, Sections::select(false, true, false), 5),
            "Tasks: 0 owned by runtime 0 @ 0x1000\n\n[0 tasks]\n\n[0 types]\n"
        );
        assert_eq!(
            sections(&facts, Sections::select(true, false, false), 5),
            "Threads: 0 lwps, 0 in runtime 0 @ 0x1000\n\n[0 lwps]\n"
        );
    }

    /// Naming no section is naming all three, which is the whole census
    /// the command printed before it had flags.
    #[test]
    fn test_no_section_named_prints_all_three() {
        let all = Sections::select(false, false, false);
        assert!(all.threads && all.tasks && all.futures);
    }
}

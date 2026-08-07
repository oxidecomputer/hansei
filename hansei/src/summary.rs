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
//! Nothing here reads the target. It is handed [`Facts`] — the thread
//! classification, the task list, the wait analysis and the future
//! census — and reduces them to a page, which is what lets the tallies
//! be tested from values laid out by hand rather than from a core that
//! happens to hold the shape under test.

use crate::future_name;

use anyhow::Result;
use hansei_types::tokio::Lifecycle;
use hansei_types::tokio::bundle::{
    BlockingPool, FutureInfo, ParkState, ParkStates, Task, TaskList, WaitKind,
};
use hansei_types::tokio::census::{FutureSet, HeldFuture};
use hansei_types::tokio::graph::TaskWait;

use std::collections::BTreeMap;
use std::io;

/// One thread of the target that holds a tokio `Context`.
pub struct Thread {
    pub tid: u32,
    /// Which worker of the scheduler it is running, when it is inside
    /// the run loop; `None` for a thread that has merely entered the
    /// runtime (a `block_on` caller, a blocking-pool thread).
    pub worker: Option<u64>,
    /// The task it is polling, where the runtime still calls that task
    /// running — the same claim `tasks` makes in its `State` row.
    pub polling: Option<u64>,
}

/// Everything a census counts, as the session read it.
pub struct Facts<'a> {
    /// Every lwp the target has, whatever it is doing.
    pub lwps: usize,
    /// Those of them holding a tokio `Context`.
    pub runtime: Vec<Thread>,
    /// What the workers' parkers say; `None` when they could not be
    /// read, which costs the census the park breakdown and nothing
    /// else.
    pub parks: Option<ParkStates>,
    /// The blocking pool's own counters, likewise optional.
    pub pool: Option<BlockingPool>,
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
}

/// Print the census.
///
/// `top` bounds every "most of them are this" listing; the rows past it
/// are counted rather than dropped silently.
pub fn print(facts: &Facts<'_>, top: usize, out: &mut dyn io::Write) -> Result<()> {
    threads(facts, out)?;
    writeln!(out)?;
    tasks(facts, top, out)?;
    writeln!(out)?;
    futures(facts, top, out)
}

// ---------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------

/// Which bucket a runtime thread falls in. The order is the order they
/// print in: what a reader is looking for first, first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ThreadKind {
    Driver,
    Polling,
    Awake,
    Notified,
    Parked,
    Unread,
}

impl ThreadKind {
    fn label(self) -> &'static str {
        match self {
            Self::Driver => "parked in the io driver",
            Self::Polling => "polling a task",
            Self::Awake => "awake, polling no task",
            Self::Notified => "notified, waking",
            Self::Parked => "parked",
            Self::Unread => "park state unread",
        }
    }

    /// Whether a row of this kind names the threads in it. Which worker
    /// holds the driver and which worker is polling what are the two
    /// facts a reader goes on to ask about; the rest are a count.
    fn names_threads(self) -> bool {
        matches!(self, Self::Driver | Self::Polling)
    }
}

fn threads(facts: &Facts<'_>, out: &mut dyn io::Write) -> Result<()> {
    let in_loop: Vec<&Thread> = facts
        .runtime
        .iter()
        .filter(|t| t.worker.is_some())
        .collect();
    let entered = facts.runtime.len() - in_loop.len();
    writeln!(
        out,
        "Threads: {}, {} in the runtime",
        counted(facts.lwps, "lwp"),
        facts.runtime.len()
    )?;
    writeln!(out, "    {} in the scheduler's run loop", in_loop.len())?;

    let mut buckets: BTreeMap<ThreadKind, Vec<&Thread>> = BTreeMap::new();
    for thread in &in_loop {
        buckets.entry(kind(facts, thread)).or_default().push(thread);
    }
    for (kind, threads) in &buckets {
        writeln!(out, "        {} {}", threads.len(), kind.label())?;
        if !kind.names_threads() {
            continue;
        }
        for thread in threads {
            let worker = match thread.worker {
                Some(index) => format!("worker {index}"),
                None => "no worker".to_string(),
            };
            let task = match thread.polling {
                Some(id) => format!("  task {id}"),
                None => String::new(),
            };
            writeln!(out, "            {worker}, lwp {}{task}", thread.tid)?;
        }
    }

    // A driver held by nobody parked in it is a thread polling it
    // without sleeping — a zero-duration park, or one already notified
    // out of its sleep and not yet back in the run loop. Saying so is
    // the difference between "no io thread right now" and "the census
    // could not find it".
    if let Some(parks) = &facts.parks
        && parks.driver_held
        && parks.in_driver().is_none()
    {
        writeln!(
            out,
            "        the io driver is held, but no worker is parked in it"
        )?;
    }

    if entered > 0 {
        writeln!(out, "    {entered} in the runtime, outside the run loop")?;
        blocking_pool(facts, in_loop.len(), entered, out)?;
    }
    let outside = facts.lwps.saturating_sub(facts.runtime.len());
    if outside > 0 {
        writeln!(out, "    {outside} holding no runtime context")?;
    }
    Ok(())
}

/// Split the threads that entered the runtime without running the loop
/// into the pool's and the rest.
///
/// The runtime launches each worker with `spawn_blocking`, so the pool
/// counts the workers among its threads — its `num_threads` is larger
/// than the pool proper by exactly the scheduler's worker count, and
/// netting them out is what makes this row a share of the line above it
/// rather than a second count of threads already listed. The pool's
/// idle count needs no such correction: a worker's blocking task is its
/// run loop and never returns, so a worker is never idle *to the pool*.
///
/// Where the two do not reconcile — a worker thread that has left the
/// pool's tally, a runtime hansei is reading mid-startup — nothing is
/// invented: the pool's own counters are reported as its own, said to
/// include the workers.
fn blocking_pool(
    facts: &Facts<'_>,
    workers: usize,
    entered: usize,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some(pool) = &facts.pool else {
        return Ok(());
    };
    // The scheduler's own count of workers where it was read, since
    // that is what `launch` spawned; the threads seen running the loop
    // otherwise.
    let launched = facts
        .parks
        .as_ref()
        .map(|parks| parks.workers.len())
        .unwrap_or(workers);
    let threads = pool.threads as usize;
    let queued = counted(pool.queued as usize, "task");
    let Some(blocking) = threads
        .checked_sub(launched)
        .filter(|blocking| *blocking <= entered)
    else {
        writeln!(
            out,
            "        the blocking pool counts {} of its own, the workers above \
             among them ({} idle, {queued} queued)",
            counted(threads, "thread"),
            pool.idle,
        )?;
        return Ok(());
    };
    writeln!(
        out,
        "        {blocking} in the blocking pool ({} idle, {queued} queued)",
        pool.idle
    )?;
    let other = entered - blocking;
    if other > 0 {
        writeln!(
            out,
            "        {other} that entered the runtime another way (a block_on caller)"
        )?;
    }
    Ok(())
}

/// What one run-loop thread is doing. Holding the driver comes ahead of
/// everything: a worker parked there is parked on the whole runtime's
/// behalf, and it is the one thread a reader came looking for.
fn kind(facts: &Facts<'_>, thread: &Thread) -> ThreadKind {
    let park = facts
        .parks
        .as_ref()
        .zip(thread.worker)
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

fn tasks(facts: &Facts<'_>, top: usize, out: &mut dyn io::Write) -> Result<()> {
    let list = facts.tasks;
    writeln!(out, "Tasks: {} owned by the runtime", list.tasks.len())?;

    // Lifecycle first: every task is in exactly one of these, so it is
    // the one row that adds up to the total above it.
    let mut lifecycle: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut aborting = 0;
    let mut unknown_future = 0;
    for task in &list.tasks {
        let bucket = match task.state.lifecycle() {
            Lifecycle::Running => "running",
            Lifecycle::Queued => "queued",
            Lifecycle::Idle => "idle",
            Lifecycle::Complete => "complete",
        };
        *lifecycle.entry(bucket).or_default() += 1;
        aborting +=
            usize::from(task.state.is_cancelled() && task.state.lifecycle() != Lifecycle::Complete);
        unknown_future += usize::from(!matches!(task.future, FutureInfo::Known(_)));
    }
    // In the order tokio's own lifecycle reads, not the alphabetical
    // one the tally accumulated in.
    let ordered = ["running", "queued", "idle", "complete"]
        .into_iter()
        .filter_map(|name| Some(format!("{} {name}", lifecycle.get(name)?)))
        .collect::<Vec<_>>();
    if !ordered.is_empty() {
        writeln!(out, "    Lifecycle: {}", ordered.join(", "))?;
    }

    // Only what is out of the ordinary. Every other state word bit is
    // the norm rather than news — nearly every spawned task is
    // detached, and one being joined is already the JoinHandle row of
    // the tally below — so a row counting those is a row that says the
    // same thing about every target.
    let notable = [
        (aborting, "cancelled but not yet complete"),
        (unknown_future, "whose future the bundle cannot name"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, label)| format!("{n} {label}"))
    .collect::<Vec<_>>();
    if !notable.is_empty() {
        writeln!(out, "    Of note: {}", notable.join(", "))?;
    }

    // What the runtime is full of, by the two names a reader can act
    // on: the future a task runs, and the line that spawned it. What
    // the tasks of a type are blocked on hangs off the type rather than
    // being tallied beside it: a thousand tasks on one semaphore is a
    // different target from a thousand types with one waiter each, and
    // only the breakdown under the type tells them apart.
    let mut types: BTreeMap<String, (usize, Waits)> = BTreeMap::new();
    let mut sites: BTreeMap<String, usize> = BTreeMap::new();
    for (index, task) in list.tasks.iter().enumerate() {
        let (count, waits) = types.entry(future_name(&task.future)).or_default();
        *count += 1;
        if let Some(wait) = facts.waits.get(index) {
            waits.add_task(task, wait);
        }
        let site = match &task.spawn_location {
            Some(loc) => loc.to_string(),
            None => "<no spawn location recorded>".to_string(),
        };
        *sites.entry(site).or_default() += 1;
    }
    let futures = types
        .into_iter()
        .map(|(name, (count, waits))| chained(name, count, &waits, top));
    rows(FUTURE_TYPES, ranked(futures, top, "type"), out)?;
    rows("Spawned at", ranked(tally(sites), top, "site"), out)
}

/// The wait tally: one bucket per thing a task or a future can be
/// parked on, plus the reasons there is nothing to report.
#[derive(Default)]
struct Waits {
    timer: usize,
    timer_past_due: usize,
    task: usize,
    /// Keyed by the primitive wrapping the semaphore, which is `None`
    /// where the awaiting frame did not name one (a channel's, say).
    semaphores: BTreeMap<Option<&'static str>, usize>,
    /// Every other leaf, by the type it is: the futures a target is
    /// actually parked on, which on any real one outnumber the
    /// primitives above by two orders of magnitude.
    leaves: BTreeMap<String, usize>,
    /// Mid-poll on a worker: it is running, not waiting.
    running: usize,
    /// Finished, waiting to be joined rather than on anything.
    complete: usize,
    /// A chain that stopped short of any leaf, so there is nothing to
    /// name — an unresolved `dyn Future`, most often.
    undecoded: usize,
}

impl Waits {
    /// Bucket one task by what it is parked on. A task with no wait
    /// target is not one more thing to wait on: it is mid-poll,
    /// finished, or parked on an ordinary future — and that last one is
    /// most of them on any real target, so it is named by the leaf its
    /// chain reached rather than lumped under a bucket saying only that
    /// hansei has no primitive for it.
    fn add_task(&mut self, task: &Task, wait: &TaskWait) {
        match wait.target.as_ref() {
            Some(target) => self.add(target.kind()),
            None => match (task.state.lifecycle(), &wait.leaf) {
                (Lifecycle::Running, _) => self.running += 1,
                (Lifecycle::Complete, _) => self.complete += 1,
                (_, Some(leaf)) => *self.leaves.entry(leaf.clone()).or_default() += 1,
                (_, None) => self.undecoded += 1,
            },
        }
    }

    /// Bucket one future the census named — held in a frame, or a set's
    /// child — by what it is parked on. It has no lifecycle of its own
    /// to be mid-poll or finished by, so the two buckets that reason
    /// about one cannot arise: what is left is the primitive, the leaf,
    /// or a chain that reached neither.
    fn add_future(&mut self, wait: Option<WaitKind>, leaf: &Option<String>) {
        match (wait, leaf) {
            (Some(wait), _) => self.add(wait),
            (None, Some(leaf)) => *self.leaves.entry(leaf.clone()).or_default() += 1,
            (None, None) => self.undecoded += 1,
        }
    }

    fn add(&mut self, kind: WaitKind) {
        match kind {
            WaitKind::Timer { past_due } => {
                self.timer += 1;
                self.timer_past_due += usize::from(past_due.unwrap_or(false));
            }
            WaitKind::Task { .. } => self.task += 1,
            WaitKind::Semaphore { owner } => *self.semaphores.entry(owner).or_default() += 1,
        }
    }

    /// The tally as printable rows, commonest first.
    ///
    /// `top` bounds the leaf types only. The rows above them are a
    /// closed set — three primitives and three reasons there is nothing
    /// to say — so cutting one would drop a fact rather than a long
    /// tail, while the leaves run to as many types as the target has
    /// ways of waiting.
    fn rows(&self, top: usize) -> Vec<Row> {
        // A deadline already passed at the moment the target stopped is
        // a wakeup that was owed and had not been delivered, which is
        // worth saying wherever the timer count is said.
        let timer = match self.timer_past_due {
            0 => "a timer".to_string(),
            n => format!("a timer ({n} already past due)"),
        };
        let mut rows = vec![
            Row::new(self.timer, timer),
            Row::new(self.task, "another task (JoinHandle)"),
            Row::new(self.running, "nothing — mid-poll on a worker"),
            Row::new(self.complete, "nothing — finished"),
            Row::new(self.undecoded, "a chain that stopped before any leaf"),
        ];
        for (owner, count) in &self.semaphores {
            let what = match owner {
                Some(owner) => format!("a {owner}"),
                None => "a semaphore no frame names the owner of".to_string(),
            };
            rows.push(Row::new(*count, what));
        }
        let mut leaves = ranked(tally(self.leaves.clone()), top, "leaf type");
        // The `across N more` row ranking left last stays last, under
        // the rows it summarizes rather than sorted in among them.
        let rest = (self.leaves.len() > top).then(|| leaves.pop()).flatten();
        rows.append(&mut leaves);
        let mut rows = rank(rows);
        rows.extend(rest);
        rows
    }
}

// ---------------------------------------------------------------------
// Futures
// ---------------------------------------------------------------------

fn futures(facts: &Facts<'_>, top: usize, out: &mut dyn io::Write) -> Result<()> {
    let frames: usize = facts.waits.iter().map(|w| w.depth).sum();
    let deepest = facts.waits.iter().map(|w| w.depth).max().unwrap_or(0);
    let held = facts.held.len();

    let mut slots = 0;
    let mut live = 0;
    for set in facts.sets {
        slots += set.children.len();
        live += set.children.iter().filter(|c| c.future.is_some()).count();
    }
    // The three populations are disjoint by construction — a task's own
    // spine, what its frames hold beside it, and what its sets hold —
    // so this total is a sum and not a re-count. They are a block of
    // their own rather than three rows under the heading, so that the
    // tally below cannot be read as a fourth place a future can be.
    writeln!(out, "Futures: {} in flight", frames + held + live)?;
    let reaped = match slots - live {
        0 => String::new(),
        n => format!(", and {n} completed and not yet reaped"),
    };
    let places = [
        Row::new(
            frames,
            format!("on task await chains ({deepest} deep at the deepest)"),
        ),
        Row::new(held, "held in frames, off any await chain"),
        // `FuturesUnordered` names one set however many there are, so
        // it is spelled as tokio spells it rather than pluralized.
        Row::new(
            live,
            format!("in {} FuturesUnordered{reaped}", facts.sets.len()),
        ),
    ];
    rows("Location", places, out)?;

    // The same tally as the tasks', over the futures no task listing
    // shows: they park on the same things and are as worth naming, and
    // a set of ten thousand children all of one type all waiting on one
    // semaphore is the shape this row exists to make visible — which is
    // why what they wait on hangs off the type here too. It runs over
    // what the census *names* — a chain frame is not among them, since
    // this section counts its depth and nothing else, and the future its
    // task runs is already a row of the tasks' own type tally. A reaped
    // slot is a future no longer, counted above rather than here.
    let mut types: BTreeMap<String, (usize, Waits)> = BTreeMap::new();
    let children = facts
        .sets
        .iter()
        .flat_map(|s| &s.children)
        .filter_map(|c| Some((c.future.as_ref()?, c.wait, &c.leaf)));
    for (future, wait, leaf) in facts
        .held
        .iter()
        .map(|h| (&h.future, h.wait, &h.leaf))
        .chain(children)
    {
        let (count, waits) = types.entry(future.clone()).or_default();
        *count += 1;
        waits.add_future(wait, leaf);
    }
    let futures = types
        .into_iter()
        .map(|(name, (count, waits))| chained(name, count, &waits, top));
    rows(FUTURE_TYPES, ranked(futures, top, "type"), out)?;
    Ok(())
}

// ---------------------------------------------------------------------
// Shared shaping
// ---------------------------------------------------------------------

/// The heading both type tallies print under. It carries what the
/// branches are, since a branch is a whole chain collapsed to its far
/// end rather than the next frame down — which is `trace`'s listing,
/// and what a reader goes to when a row here is the one they came for.
const FUTURE_TYPES: &str = "Future types with await chains";

/// One future type as a row, with what the chains rooted at it reach
/// hanging off it.
///
/// A type whose chains all reached no further than that same type has
/// nothing to hang: a lone branch repeating the name above it says only
/// that, at the width of the name. Where there is more to say the row
/// stays, itself among the rest.
fn chained(name: String, count: usize, waits: &Waits, top: usize) -> Row {
    let under = waits.rows(top);
    let under = match under.as_slice() {
        [only] if only.what == name => Vec::new(),
        _ => under,
    };
    Row::new(count, name).under(under)
}

/// A count and the noun it counts, pluralized.
fn counted(n: usize, noun: &str) -> String {
    let plural = if n == 1 { "" } else { "s" };
    format!("{n} {noun}{plural}")
}

/// One row of a listing: how many, of what, and — where the census has
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

/// The `top` commonest entries of a tally, with whatever it leaves out
/// counted rather than dropped in silence.
fn ranked(tally: impl IntoIterator<Item = Row>, top: usize, noun: &str) -> Vec<Row> {
    let mut rows = rank(tally.into_iter().collect());
    let total = rows.len();
    if total > top {
        let rest: usize = rows[top..].iter().map(|row| row.count).sum();
        rows.truncate(top);
        rows.push(Row::new(
            rest,
            format!("across {}", counted(total - top, &format!("more {noun}"))),
        ));
    }
    rows
}

/// Print a labelled block of counted rows. A block with nothing in it
/// is not printed: a heading over no rows reads as data missing rather
/// than absent.
fn rows(label: &str, rows: impl IntoIterator<Item = Row>, out: &mut dyn io::Write) -> Result<()> {
    let rows: Vec<Row> = rows.into_iter().collect();
    if rows.is_empty() {
        return Ok(());
    }
    writeln!(out, "    {label}:")?;
    level(&rows, "        ", false, out)
}

/// Print one level of a listing, the counts right-aligned within the
/// level so the magnitudes line up, and each row's breakdown hanging
/// off the label above it.
///
/// `branch` says whether these rows *are* a breakdown, and so are drawn
/// as branches of the row they hang from rather than as a listing in
/// their own right.
fn level(rows: &[Row], indent: &str, branch: bool, out: &mut dyn io::Write) -> Result<()> {
    let width = rows
        .iter()
        .map(|row| row.count.to_string().len())
        .max()
        .unwrap_or(1);
    for (i, row) in rows.iter().enumerate() {
        let (stem, run) = match (branch, i + 1 == rows.len()) {
            (false, _) => ("", ""),
            (true, true) => ("└─ ", "   "),
            (true, false) => ("├─ ", "│  "),
        };
        writeln!(out, "{indent}{stem}{:>width$}  {}", row.count, row.what)?;
        if !row.under.is_empty() {
            // Indented to where this row's label starts, so what breaks
            // it down reads as hanging from the name and not from the
            // count.
            let under = format!("{indent}{run}{}", " ".repeat(width + 2));
            level(&row.under, &under, true, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use exegesis::bundle::{BundleTypeId, FutureKind, TaskEntryId};
    use hansei_types::tokio::bundle::{KnownFuture, Task, WaitTarget};
    use hansei_types::tokio::census::SetChild;
    use hansei_types::tokio::graph::TaskRef;
    use hansei_types::tokio::{Location, RawInstant, TaskAddr, TaskState};

    const RUNNING: u64 = 0b1;
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
                display_name: future.to_string(),
                kind: FutureKind::AsyncFn,
                decl: None,
                symbol: "_ZN1x".to_string(),
            }),
        }
    }

    fn wait(id: u64, target: Option<WaitTarget>, depth: usize) -> TaskWait {
        leaf_wait(id, target, depth, None)
    }

    /// A wait whose chain reached an ordinary future rather than one of
    /// the primitives hansei decodes.
    fn leaf_wait(
        id: u64,
        target: Option<WaitTarget>,
        depth: usize,
        leaf: Option<&str>,
    ) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000 + id * 0x100),
                task_id: Some(id),
            },
            target,
            depth,
            leaf: leaf.map(str::to_string),
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
        HeldFuture {
            owner: 0,
            frame: 0,
            local: "arm".to_string(),
            via: None,
            addr: 0x4000,
            ty: BundleTypeId(0),
            future: future.to_string(),
            state: None,
            waiting_on: wait.map(|_| "something".to_string()),
            wait,
            leaf: None,
        }
    }

    fn child(future: Option<&str>, wait: Option<WaitKind>) -> SetChild {
        SetChild {
            node: 0x2000,
            future: future.map(str::to_string),
            root: None,
            state: None,
            waiting_on: wait.map(|_| "something".to_string()),
            wait,
            leaf: None,
        }
    }

    /// Print a census over facts a test laid out, and hand back the
    /// page.
    fn census(facts: &Facts<'_>, top: usize) -> String {
        let mut out = Vec::new();
        print(facts, top, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// The facts of an empty runtime, for a test to fill in the part it
    /// is about.
    fn facts<'a>(tasks: &'a TaskList, waits: &'a [TaskWait]) -> Facts<'a> {
        Facts {
            lwps: 0,
            runtime: Vec::new(),
            parks: None,
            pool: None,
            tasks,
            waits,
            held: &[],
            sets: &[],
        }
    }

    fn empty() -> TaskList {
        TaskList {
            tasks: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// The two threads a reader came for — the one holding the driver
    /// and the ones polling — are named; the rest are a count.
    #[test]
    fn test_threads_name_the_driver_holder_and_the_pollers() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = 6;
        facts.runtime = vec![
            Thread {
                tid: 11,
                worker: Some(0),
                polling: None,
            },
            Thread {
                tid: 12,
                worker: Some(1),
                polling: Some(42),
            },
            Thread {
                tid: 13,
                worker: Some(2),
                polling: None,
            },
            Thread {
                tid: 14,
                worker: None,
                polling: None,
            },
        ];
        facts.parks = Some(ParkStates {
            workers: vec![ParkState::Driver, ParkState::Awake, ParkState::Condvar],
            driver_held: true,
        });
        // The pool counts the three workers among its four threads,
        // since the runtime launched each of them with spawn_blocking.
        facts.pool = Some(BlockingPool {
            threads: 4,
            idle: 1,
            queued: 1,
        });

        let page = census(&facts, 5);
        let threads = page.split("\n\n").next().unwrap();
        assert_eq!(
            threads,
            "Threads: 6 lwps, 4 in the runtime\n    \
             3 in the scheduler's run loop\n        \
             1 parked in the io driver\n            \
             worker 0, lwp 11\n        \
             1 polling a task\n            \
             worker 1, lwp 12  task 42\n        \
             1 parked\n    \
             1 in the runtime, outside the run loop\n        \
             1 in the blocking pool (1 idle, 1 task queued)\n    \
             2 holding no runtime context"
        );
    }

    /// A pool whose count does not reconcile with the workers it
    /// launched is reported as its own count rather than netted into a
    /// share of a line it would not add up to.
    #[test]
    fn test_an_unreconciled_pool_count_is_reported_as_the_pools_own() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = 2;
        facts.runtime = vec![
            Thread {
                tid: 11,
                worker: Some(0),
                polling: None,
            },
            Thread {
                tid: 12,
                worker: None,
                polling: None,
            },
        ];
        facts.parks = Some(ParkStates {
            workers: vec![ParkState::Condvar],
            driver_held: false,
        });
        facts.pool = Some(BlockingPool {
            threads: 9,
            idle: 4,
            queued: 0,
        });

        let page = census(&facts, 5);
        assert!(
            page.contains(
                "    1 in the runtime, outside the run loop\n        \
                 the blocking pool counts 9 threads of its own, the workers \
                 above among them (4 idle, 0 tasks queued)\n"
            ),
            "{page}"
        );
    }

    /// A driver held by a worker that is not parked in it is a thread
    /// polling it without sleeping — which the listing says, rather
    /// than leaving a reader to conclude the census missed it.
    #[test]
    fn test_a_held_driver_with_nobody_parked_in_it_says_so() {
        let list = empty();
        let mut facts = facts(&list, &[]);
        facts.lwps = 1;
        facts.runtime = vec![Thread {
            tid: 11,
            worker: Some(0),
            polling: None,
        }];
        facts.parks = Some(ParkStates {
            workers: vec![ParkState::Awake],
            driver_held: true,
        });

        let page = census(&facts, 5);
        assert!(
            page.contains("the io driver is held, but no worker is parked in it"),
            "{page}"
        );
    }

    /// Every task lands in exactly one lifecycle bucket and exactly one
    /// wait bucket, so both rows add up to the total over them. A task
    /// with no wait target is bucketed by why it has none, and the wait
    /// buckets hang off the future type whose tasks they count.
    #[test]
    fn test_task_tallies_count_every_task_once() {
        let list = TaskList {
            tasks: vec![
                task(1, JOIN_INTEREST, "a::fut", "a.rs"),
                task(2, JOIN_INTEREST, "a::fut", "a.rs"),
                task(3, JOIN_INTEREST | RUNNING, "b::fut", "b.rs"),
                task(4, NOTIFIED | CANCELLED, "b::fut", "b.rs"),
                task(5, JOIN_INTEREST, "c::fut", "c.rs"),
                task(6, JOIN_INTEREST, "c::fut", "c.rs"),
                task(7, JOIN_INTEREST, "c::fut", "c.rs"),
            ],
            errors: Vec::new(),
        };
        let io = "tokio::runtime::io::scheduled_io::Readiness";
        let waits = vec![
            wait(1, Some(timer(10, 4)), 3),
            wait(2, Some(timer(4, 10)), 2),
            wait(3, None, 1),
            wait(4, Some(mutex()), 1),
            leaf_wait(5, None, 4, Some(io)),
            leaf_wait(6, None, 4, Some(io)),
            // A chain that stopped short names no leaf, and is not
            // counted as though it had reached one.
            leaf_wait(7, None, 2, None),
        ];
        let page = census(&facts(&list, &waits), 5);

        assert!(page.contains("Tasks: 7 owned by the runtime\n"), "{page}");
        assert!(
            page.contains("    Lifecycle: 1 running, 1 queued, 5 idle\n"),
            "{page}"
        );
        // Only the anomaly: that six of the seven are detached is the
        // norm, and says nothing about this target.
        assert!(
            page.contains("    Of note: 1 cancelled but not yet complete\n"),
            "{page}"
        );
        assert!(
            page.contains(
                "    Future types with await chains:\n        \
                 3  c::fut\n           \
                 ├─ 2  tokio::runtime::io::scheduled_io::Readiness\n           \
                 └─ 1  a chain that stopped before any leaf\n        \
                 2  a::fut\n           \
                 └─ 2  a timer (1 already past due)\n        \
                 2  b::fut\n           \
                 ├─ 1  a tokio::sync::Mutex\n           \
                 └─ 1  nothing — mid-poll on a worker\n"
            ),
            "{page}"
        );
    }

    /// The leaf rows are the ones `--top` bounds: the primitives and
    /// the three reasons there is nothing to say are a closed set, so
    /// cutting one would drop a fact rather than a long tail.
    #[test]
    fn test_top_bounds_the_leaf_rows_and_not_the_rest() {
        let mut tasks = Vec::new();
        let mut waits = Vec::new();
        for i in 0..4 {
            for n in 0..=i {
                let id = tasks.len() as u64;
                tasks.push(task(id, JOIN_INTEREST, "f", "f.rs"));
                waits.push(leaf_wait(id, None, 1, Some(&format!("leaf{i}"))));
                let _ = n;
            }
        }
        // One task on a timer, which no bound may cut.
        let id = tasks.len() as u64;
        tasks.push(task(id, JOIN_INTEREST, "f", "f.rs"));
        waits.push(wait(id, Some(timer(10, 4)), 1));

        let list = TaskList {
            tasks,
            errors: Vec::new(),
        };
        let page = census(&facts(&list, &waits), 2);
        assert!(
            page.contains(
                "    Future types with await chains:\n        \
                 11  f\n            \
                 ├─ 4  leaf3\n            \
                 ├─ 3  leaf2\n            \
                 ├─ 1  a timer\n            \
                 └─ 3  across 2 more leaf types\n"
            ),
            "{page}"
        );
    }

    /// A type whose every task is parked on that same type gets no
    /// breakdown: the chains reached no further than the future the
    /// task runs, and a lone branch repeating the name above it says
    /// only that. A type with more than one thing to say keeps them
    /// all, itself among them.
    #[test]
    fn test_a_type_parked_on_itself_gets_no_breakdown() {
        let list = TaskList {
            tasks: vec![
                task(1, JOIN_INTEREST, "a::fut", "a.rs"),
                task(2, JOIN_INTEREST, "a::fut", "a.rs"),
                task(3, JOIN_INTEREST, "b::fut", "b.rs"),
                task(4, JOIN_INTEREST, "b::fut", "b.rs"),
            ],
            errors: Vec::new(),
        };
        let waits = vec![
            leaf_wait(1, None, 1, Some("a::fut")),
            leaf_wait(2, None, 1, Some("a::fut")),
            leaf_wait(3, None, 1, Some("b::fut")),
            wait(4, Some(timer(10, 4)), 1),
        ];
        let page = census(&facts(&list, &waits), 5);

        assert!(
            page.contains(
                "    Future types with await chains:\n        \
                 2  a::fut\n        \
                 2  b::fut\n           \
                 ├─ 1  a timer\n           \
                 └─ 1  b::fut\n"
            ),
            "{page}"
        );
    }

    /// A listing bounded by `--top` sums what it left out rather than
    /// dropping it, so the rows still account for every task.
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
        let list = TaskList {
            tasks,
            errors: Vec::new(),
        };
        let page = census(&facts(&list, &[]), 2);

        assert!(
            page.contains(
                "    Future types with await chains:\n         \
                 6  f5\n         \
                 5  f4\n        \
                 10  across 4 more types\n"
            ),
            "{page}"
        );
        assert!(page.contains("10  across 4 more sites\n"), "{page}");
    }

    /// The three future populations are disjoint, so the headline is
    /// their sum: a set's children are not also held futures, and a
    /// reaped slot is neither.
    #[test]
    fn test_future_populations_do_not_overlap() {
        let list = empty();
        let waits = vec![wait(1, None, 3), wait(2, None, 2)];
        let held = vec![held("held::fut", Some(WaitKind::Task { addr: 0x7100 }))];
        let sets = vec![FutureSet {
            owner: 0,
            frame: 0,
            local: "pending".to_string(),
            via: None,
            addr: 0x5000,
            ty: "FuturesUnordered<f>".to_string(),
            children: vec![
                child(Some("child::fut"), Some(WaitKind::Timer { past_due: None })),
                child(None, None),
            ],
        }];
        let mut facts = facts(&list, &waits);
        facts.held = &held;
        facts.sets = &sets;

        let page = census(&facts, 5);
        let futures = page.split("\n\n").nth(2).unwrap();
        assert_eq!(
            futures,
            // 5 on the chains, 1 held, 1 resident set child: the
            // reaped slot is counted, and deliberately not added in.
            "Futures: 7 in flight\n    \
             Location:\n        \
             5  on task await chains (3 deep at the deepest)\n        \
             1  held in frames, off any await chain\n        \
             1  in 1 FuturesUnordered, and 1 completed and not yet reaped\n    \
             Future types with await chains:\n        \
             1  child::fut\n           \
             └─ 1  a timer\n        \
             1  held::fut\n           \
             └─ 1  another task (JoinHandle)\n"
        );
    }

    /// The futures' type tally spans both populations the census names,
    /// bounds itself by `--top` as the tasks' does, and leaves the reaped
    /// slots — which are no future's type — out.
    #[test]
    fn test_future_types_tally_the_held_and_the_resident() {
        let list = empty();
        let held: Vec<HeldFuture> = (0..3).map(|_| held("hot::fut", None)).collect();
        let sets = vec![FutureSet {
            owner: 0,
            frame: 0,
            local: "pending".to_string(),
            via: None,
            addr: 0x5000,
            ty: "FuturesUnordered<f>".to_string(),
            children: vec![
                child(Some("hot::fut"), None),
                child(Some("cold::fut"), None),
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
                "    Future types with await chains:\n        \
                 4  hot::fut\n           \
                 └─ 4  a chain that stopped before any leaf\n        \
                 1  cold::fut\n           \
                 └─ 1  a chain that stopped before any leaf\n        \
                 1  across 1 more type\n"
            ),
            "{page}"
        );
    }
}

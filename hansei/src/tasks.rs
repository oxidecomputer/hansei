// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `tasks` and `census` commands: the task listing and the counts
//! over it, plus the naming helpers every listing shares.

use crate::runtimes::RowOwner;
use crate::typenames::{self, TypeNames};
use crate::{Session, output, print_warnings, repl, summary};

use anyhow::{Context as _, Result};
use hansei_bundle::BundleTypeId;
use hansei_runtime::tokio::assess::{
    ContinuationStatus, IncompleteReason, NotWaitingReason, ReadyReason, RunnableReason,
    WaitAssessment, WaitUnknownReason,
};
use hansei_runtime::tokio::graph as rt_graph;
use hansei_runtime::tokio::observe::ValueKey;
use hansei_runtime::tokio::waitset::{self, MemberRoute, WaitMember};
use hansei_runtime::tokio::wakers::Owner;
use hansei_runtime::tokio::{Lifecycle, RawInstant, attribution, bundle, census};

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

/// How a task is referred to in passing: by id, or by Header address
/// when it has none.
/// How output names a task bare: its decimal id, or its Header address
/// where the target records none.
pub(crate) fn task_id(list: &bundle::TaskList, index: usize) -> String {
    match list.tasks[index].task_id {
        Some(id) => id.to_string(),
        None => format!("{:?}", list.tasks[index].addr),
    }
}

/// Whose waker a sweep slot holds, as a listing names them: a task by
/// [`task_label`], a set child by its index in the set, the set's
/// address and the task polling it — the census's account of the set,
/// without which a child cannot be named.
pub(crate) fn owner_label(
    list: &bundle::TaskList,
    census: Option<&census::FutureCensus>,
    owner: Owner,
) -> Option<String> {
    Some(match owner {
        Owner::Task { index, .. } => task_label(list, index),
        Owner::Child { set, child } => {
            let set = &census?.sets[set];
            format!(
                "child {child} of the set at {:#x} (polled by {})",
                set.addr,
                task_label(list, set.owner)
            )
        }
    })
}

/// [`task_id`] worded as a noun phrase: `task 42`, or `task at 0x…`.
pub(crate) fn task_label(list: &bundle::TaskList, index: usize) -> String {
    match list.tasks[index].task_id {
        Some(_) => format!("task {}", task_id(list, index)),
        None => format!("task at {}", task_id(list, index)),
    }
}

/// The census's find lists, as the tree and the listings read them —
/// taken apart from the census itself so a test can lay out a shape no
/// fixture happens to hold. An [`Entry`] is an index into one of them,
/// and every question about one is asked here.
#[derive(Clone, Copy)]
pub(crate) struct Finds<'a> {
    pub(crate) held: &'a [census::HeldFuture],
    pub(crate) sets: &'a [census::FutureSet],
    pub(crate) join_sets: &'a [census::JoinSet],
}

impl<'a> From<&'a census::FutureCensus> for Finds<'a> {
    fn from(census: &'a census::FutureCensus) -> Self {
        Finds {
            held: &census.held,
            sets: &census.sets,
            join_sets: &census.join_sets,
        }
    }
}

impl Finds<'_> {
    /// Every find as an [`Entry`]. Held first, then sets, then join
    /// sets, so each level lists what a frame holds ahead of what it
    /// drives.
    fn entries(self) -> impl Iterator<Item = Entry> {
        let held = (0..self.held.len()).map(Entry::Held);
        let sets = (0..self.sets.len()).map(Entry::Set);
        let join_sets = (0..self.join_sets.len()).map(Entry::JoinSet);
        held.chain(sets).chain(join_sets)
    }

    /// The task whose frames a find was reached from.
    fn owner(self, entry: Entry) -> usize {
        match entry {
            Entry::Held(i) => self.held[i].owner,
            Entry::Set(i) => self.sets[i].owner,
            Entry::JoinSet(i) => self.join_sets[i].owner,
        }
    }

    /// The find it was reached through — `None` for one found in the
    /// task's own frames.
    fn via(self, entry: Entry) -> Option<census::Via> {
        match entry {
            Entry::Held(i) => self.held[i].via,
            Entry::Set(i) => self.sets[i].via,
            Entry::JoinSet(i) => self.join_sets[i].via,
        }
    }
}

/// The census as a tree, which is what a listing shows: two flat lists
/// naming their parent leave the reader matching addresses across them.
/// It holds indices into the finds rather than the finds, so a session
/// builds it once beside the census and every `task` block reads it —
/// `tasks --exec task` over twenty thousand tasks rebuilds nothing.
pub(crate) struct CensusTree {
    /// Each task's finds that named no parent, keyed by its index in
    /// the task list.
    pub(crate) roots: BTreeMap<usize, Vec<Entry>>,
    /// Everything else, keyed by the find it was reached through: a set
    /// can sit in a held future's frames, a future be held in a set
    /// child's.
    pub(crate) nested: HashMap<census::Via, Vec<Entry>>,
    /// What each task owns, tallied.
    counts: BTreeMap<usize, Counts>,
}

/// Build that tree from what the census found, which is all it reads:
/// the census is a walk of a target, but rendering it is not.
pub(crate) fn census_tree(finds: Finds<'_>) -> CensusTree {
    let mut roots: BTreeMap<usize, Vec<Entry>> = BTreeMap::new();
    let mut nested: HashMap<census::Via, Vec<Entry>> = HashMap::new();
    for entry in finds.entries() {
        match finds.via(entry) {
            Some(via) => nested.entry(via).or_default().push(entry),
            None => roots.entry(finds.owner(entry)).or_default().push(entry),
        }
    }
    CensusTree {
        roots,
        nested,
        counts: census_counts(finds),
    }
}

impl CensusTree {
    /// What the census found inside one find, tallied the way a task's
    /// own finds are: only what was reached directly through it, since
    /// anything deeper is inside one of those.
    pub(crate) fn counts_under(&self, finds: Finds<'_>, via: census::Via) -> Counts {
        let mut counts = Counts::default();
        for entry in self.nested.get(&via).into_iter().flatten() {
            counts.add(finds, *entry);
        }
        counts
    }
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
fn census_counts(finds: Finds<'_>) -> BTreeMap<usize, Counts> {
    let mut counts: BTreeMap<usize, Counts> = BTreeMap::new();
    for entry in finds.entries().filter(|&e| finds.via(e).is_none()) {
        counts
            .entry(finds.owner(entry))
            .or_default()
            .add(finds, entry);
    }
    counts
}

/// One find in the nested listing, by its index in the census's list
/// of its kind — the index anything found inside a held future or a
/// set names as its parent. Nothing is ever reached *through* a join
/// set: its members are tasks, scanned as the tasks they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Held(usize),
    Set(usize),
    JoinSet(usize),
}

impl Entry {
    /// Which of a block's two listings this find belongs under: the
    /// futures the task holds itself, or the sets it drives, of either
    /// kind. Only a root is sorted this way — a find inside another is
    /// printed under what holds it, wherever that is.
    pub(crate) fn is_set(self) -> bool {
        matches!(self, Entry::Set(_) | Entry::JoinSet(_))
    }
}

/// A capped census walk looks like completeness, so say it is not.
pub(crate) fn warn_census_capped(capped: census::Capped, fate: &str) -> io::Result<()> {
    if let Some(warning) = census_capped_warning(capped, fate) {
        writeln!(io::stderr(), "warning: {warning}")?;
    }
    Ok(())
}

/// What a capped walk has to say for itself, or `None` when nothing
/// was capped.
///
/// The census stops for two different reasons and a reader can act on
/// neither without being told which: a value abandoned partway down is
/// something the target holds deeply nested, while a chain left
/// unfollowed is a fan-out of futures holding futures. `fate` is what
/// the listing or count would otherwise claim to cover.
fn census_capped_warning(capped: census::Capped, fate: &str) -> Option<String> {
    let mut limits = Vec::new();
    let mut beyond = Vec::new();
    if capped.deep > 0 {
        limits.push(format!("its depth limit in {} place(s)", capped.deep));
        beyond.push("nested deeper");
    }
    if capped.distant > 0 {
        limits.push(format!("its nesting limit in {} place(s)", capped.distant));
        beyond.push("held further out");
    }
    if capped.unavailable > 0 {
        limits.push(format!(
            "storage the tokio info cannot read in {} place(s)",
            capped.unavailable
        ));
        beyond.push("held in it");
    }
    let (limits, beyond) = match (limits.len(), beyond.as_slice()) {
        (0, _) => return None,
        (1, [only]) => (limits.remove(0), *only),
        (2, _) => (limits.join(" and "), "beyond either"),
        _ => (
            format!(
                "{}, and {}",
                limits[..limits.len() - 1].join(", "),
                limits[limits.len() - 1]
            ),
            "beyond any of them",
        ),
    };
    // Only the depth limit is one a session can move, so only it is
    // worth telling a reader how.
    let hint = match capped.deep {
        0 => "",
        _ => " (--search-depth moves the depth limit)",
    };
    Some(format!(
        "the scan stopped at {limits}; anything {beyond} is not {fate}{hint}"
    ))
}

/// A census that dropped finds looks like completeness too.
/// Say what the walk left unread: the locals whose initialization the
/// coroutine layout cannot vouch for — an async block's captures once
/// it has been polled — which no bound would have let it read.
pub(crate) fn warn_census_uncertain(uncertain: usize, fate: &str) -> io::Result<()> {
    if let Some(warning) = census_uncertain_warning(uncertain, fate) {
        writeln!(io::stderr(), "warning: {warning}")?;
    }
    Ok(())
}

/// What a walk that skipped uncertain locals has to say for itself,
/// or `None` when it skipped none.
fn census_uncertain_warning(uncertain: usize, fate: &str) -> Option<String> {
    (uncertain > 0).then(|| {
        format!(
            "the census did not read {} whose initialization the tokio info cannot \
             vouch for (an async block's captures after its first poll); a future held \
             in one is not {fate}",
            summary::counted(uncertain, "local")
        )
    })
}

pub(crate) fn warn_census_refused(refused: usize, fate: &str) -> io::Result<()> {
    if let Some(warning) = census_refused_warning(refused, fate) {
        writeln!(io::stderr(), "warning: {warning}")?;
    }
    Ok(())
}

/// What a walk that refused finds has to say for itself, or `None`
/// when it refused none — which is every healthy target.
///
/// A refusal is the allocator contradicting a pointer the walk was
/// about to believe, so what is missing is not a fact about the
/// program's futures at all: it is memory somebody handed back. The
/// find and everything under it go together, which is what makes this
/// worth a count rather than a silent absence.
fn census_refused_warning(refused: usize, fate: &str) -> Option<String> {
    (refused > 0).then(|| {
        format!(
            "the allocator has taken back the memory {refused} find(s) lay in; \
             they and anything they held are not {fate}"
        )
    })
}

/// The error for a task id the runtime does not own. It says how many
/// tasks there are and no more: a real target owns tens of thousands,
/// so listing their ids here made the error itself a hundred-kilobyte
/// listing, and `tasks` is where the ids are.
pub(crate) fn no_such_task(list: &bundle::TaskList, id: u64) -> anyhow::Error {
    anyhow::anyhow!(
        "no task {id} ({})",
        summary::counted(list.tasks.len(), "task")
    )
}

/// One task's share of the census.
#[derive(Clone, Copy, Default)]
pub(crate) struct Counts {
    /// Futures held in one of the task's own frames.
    pub(crate) held: usize,
    /// Sets of futures it drives from one of those frames. A set is a
    /// container rather than a future outstanding in its own right, so
    /// it is counted apart from both.
    pub(crate) sets: usize,
    /// Children of those sets still holding a future: an empty slot is a
    /// completed child the set has not reaped, not a future outstanding.
    children_live: usize,
    /// Join sets it drives from those frames, and the tasks they hold.
    /// A joined task is not a future off anyone's await chain — it is a
    /// task with a chain of its own, and a block in this same listing —
    /// so it is counted here and nowhere else.
    pub(crate) join_sets: usize,
    joined: usize,
}

impl Counts {
    fn add(&mut self, finds: Finds<'_>, entry: Entry) {
        match entry {
            Entry::Held(_) => self.held += 1,
            Entry::Set(i) => {
                let s = &finds.sets[i];
                self.sets += 1;
                self.children_live += s.children.iter().filter(|c| c.future.is_some()).count();
            }
            Entry::JoinSet(i) => {
                self.join_sets += 1;
                self.joined += finds.join_sets[i].children.len();
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
    pub(crate) fn sets_summary(&self) -> String {
        let sets = self.sets + self.join_sets;
        if sets == 0 {
            return "0".to_string();
        }
        let mut holds = Vec::new();
        if self.join_sets > 0 {
            holds.push(summary::counted(self.joined, "task"));
        }
        if self.sets > 0 {
            holds.push(summary::counted(self.children_live, "future"));
        }
        format!("{sets} ({})", holds.join(" and "))
    }

    /// How many futures the task has in flight beside its own await
    /// chain — the `FUT` column, and what a `futures` clause
    /// compares: the futures held in its frames and the live children
    /// of the sets it drives, which is the population `futures` lists
    /// for the task. A set itself is a container, not a future, and a
    /// joined task is a row of its own, so neither is in the number.
    pub(crate) fn futures(&self) -> usize {
        self.held + self.children_live
    }
}

/// What printing a find needs beyond the find itself: the tree it sits
/// in, and the task listing a joined task is named from — a join set
/// holds tasks the listing already carries, so its rows say what those
/// blocks say rather than something of their own.
pub(crate) struct Listing<'a> {
    pub(crate) blocking_lwps: &'a HashMap<u64, u32>,
    /// The width a row's name is cut to fit within, the way
    /// [`Session::fit_width`] gives it; `None` leaves every name whole.
    /// A cut takes from the name alone — the address, the frame and
    /// local, the state after it all stay — so a row still says what
    /// and where even when it cannot say the whole type.
    pub(crate) fit: Option<usize>,
    pub(crate) finds: Finds<'a>,
    pub(crate) nested: &'a HashMap<census::Via, Vec<Entry>>,
    pub(crate) list: &'a bundle::TaskList,
    pub(crate) polling: &'a HashMap<u64, u32>,
    pub(crate) names: &'a TypeNames<'a>,
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
pub(crate) fn print_future_entry(
    entry: Entry,
    listing: &Listing<'_>,
    indent: usize,
    mark_held: bool,
    out: &mut dyn io::Write,
) -> Result<()> {
    let pad = " ".repeat(indent);
    let nested = listing.nested;
    match entry {
        Entry::Held(index) => {
            let h = &listing.finds.held[index];
            let state = h
                .state
                .as_ref()
                .map(|s| format!("  {s}"))
                .unwrap_or_default();
            let mark = if mark_held { "held " } else { "" };
            let before = format!(
                "{pad}{mark}(frame {}, `{}`): {:#x}  ",
                h.frame, h.local, h.addr
            );
            let name = listing.names.future(h.future);
            let taken = before.chars().count() + state.chars().count();
            let name = output::fit_name(&name, taken, listing.fit);
            writeln!(out, "{before}{name}{state}")?;
            if let Some(waiting) = &h.waiting_on {
                writeln!(out, "{pad}  waiting on {waiting}")?;
            }
            if let Some(tls) = crate::futures::observed_tls(h.observation.as_ref()) {
                writeln!(out, "{pad}    tls: {}", tls_words(&tls))?;
            }
            for inner in nested.get(&census::Via::Held(index)).into_iter().flatten() {
                print_future_entry(*inner, listing, indent + 4, mark_held, out)?;
            }
        }
        Entry::Set(index) => {
            let set = &listing.finds.sets[index];
            let live = set.children.iter().filter(|c| c.future.is_some()).count();
            let plural = if live == 1 { "" } else { "ren" };
            let reaped = match set.children.len() - live {
                0 => String::new(),
                n => format!(", {n} completed and not yet reaped"),
            };
            let after = format!(
                " at {:#x} (frame {}, `{}`): {live} child{plural} in flight{reaped}",
                set.addr, set.frame, set.local
            );
            let name = listing.names.folded(set.ty);
            let taken = indent + 2 + after.chars().count();
            let name = output::fit_name(&name, taken, listing.fit);
            writeln!(out, "{pad}- {name}{after}")?;
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
                let before = format!("{pad}    {:#x}  ", child.node);
                let name = listing.names.future(*future);
                let taken = before.chars().count() + state.chars().count();
                let name = output::fit_name(&name, taken, listing.fit);
                writeln!(out, "{before}{name}{state}")?;
                if let Some(waiting) = &child.waiting_on {
                    writeln!(out, "{pad}      waiting on {waiting}")?;
                }
                if let Some(tls) = crate::futures::observed_tls(child.observation.as_ref()) {
                    writeln!(out, "{pad}        tls: {}", tls_words(&tls))?;
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
        Entry::JoinSet(index) => {
            let set = &listing.finds.join_sets[index];
            let held = set.children.len();
            let plural = if held == 1 { "" } else { "s" };
            // The set keeps its own count; a walk that reached fewer
            // entries than that says so here, since the error saying
            // why is on stderr and this is the row it belongs to.
            let short = match set.length {
                len if len != held as u64 => format!(" (the set records {len})"),
                _ => String::new(),
            };
            let after = format!(
                " at {:#x} (frame {}, `{}`): {held} task{plural}{short}",
                set.addr, set.frame, set.local
            );
            let name = listing.names.folded(set.ty);
            let taken = indent + 2 + after.chars().count();
            let name = output::fit_name(&name, taken, listing.fit);
            writeln!(out, "{pad}- {name}{after}")?;
            for child in &set.children {
                writeln!(out, "{pad}    {}", joined_task(child, listing, indent + 4))?;
            }
        }
    }
    Ok(())
}

/// A task's lifecycle as a listing spells it: the worker holding it
/// where the runtime says one is, since `running` alone leaves a reader
/// asking where — and a blocking cell's queued/running spelling.
pub(crate) fn task_state(
    task: &bundle::Task,
    polling: &HashMap<u64, u32>,
    blocking_lwps: &HashMap<u64, u32>,
) -> String {
    let lwp = task_lwp(task, polling, blocking_lwps);
    if task.is_blocking() {
        return blocking_state(task, lwp);
    }
    match (task.state.lifecycle(), lwp) {
        (Lifecycle::Running, Some(lwp)) => format!("running (lwp {lwp})"),
        (lifecycle, _) => lifecycle.to_string(),
    }
}

/// The thread a task is on, where anything names one: the worker whose
/// current-task word claims it, else — for a blocking cell — the pool
/// thread whose stack is inside its poll. A task that is not running
/// is on no thread.
pub(crate) fn task_lwp(
    task: &bundle::Task,
    polling: &HashMap<u64, u32>,
    blocking_lwps: &HashMap<u64, u32>,
) -> Option<u32> {
    if task.state.lifecycle() != Lifecycle::Running {
        return None;
    }
    task.task_id
        .and_then(|id| polling.get(&id))
        .or_else(|| {
            task.is_blocking()
                .then(|| blocking_lwps.get(&task.addr.0))
                .flatten()
        })
        .copied()
}

/// One joined task's row: how the task listing names it, or — for a
/// task no listing can show — why it is not there to name.
fn joined_task(child: &census::JoinedTask, listing: &Listing<'_>, indent: usize) -> String {
    let who = match child.id {
        Some(id) => format!("task {id}"),
        None => format!("task at {:#x}", child.task),
    };
    if let Some(task) = listing.list.tasks.iter().find(|t| t.addr.0 == child.task) {
        let state = task_state(task, listing.polling, listing.blocking_lwps);
        let name = future_name(&task.future, listing.names);
        let taken = indent + who.chars().count() + 2 + 2 + state.chars().count();
        let name = output::fit_name(&name, taken, listing.fit);
        return format!("{who}  {name}  {state}");
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
/// resolved it: the kind word joined to the folded name for a known
/// future (`async fn foo::bar`), since none of the lines this opens
/// carries a kind column of its own.
pub(crate) fn future_name(future: &bundle::FutureInfo, type_names: &TypeNames<'_>) -> String {
    match future {
        bundle::FutureInfo::Known(known) => type_names.future(known.future),
        bundle::FutureInfo::Unknown {
            poll_symbol: Some(sym),
        } => format!("<unknown: {:#}>", rustc_demangle::demangle(sym)),
        bundle::FutureInfo::Unknown { poll_symbol: None } => "<unknown>".to_string(),
        bundle::FutureInfo::Ambiguous { candidates, .. } => {
            let candidates: Vec<_> = candidates
                .iter()
                .map(|&ty| format!("{} (type {})", type_names.folded(ty), ty.0))
                .collect();
            format!("<ambiguous: {}>", candidates.join(" | "))
        }
    }
}

/// One row of the `tasks` table: the compact per-task answer, built
/// once from the wait analysis and shared by the table, the filters,
/// and the JSON printer.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct TaskRow {
    /// The task's decimal id, or its Header address where the target
    /// records none.
    pub(crate) id: String,
    /// The lifecycle, with ` (cancelled)` appended when the cancel
    /// bit is set.
    pub(crate) state: String,
    /// The owner cell: the group index `runtimes` prints (runtimes
    /// and local sets share the space), or the word for an owner that
    /// is no group. The column prints only on targets holding more
    /// than one group, or a task no group owns.
    pub(crate) rt: RowOwner,
    /// The leaf await site — the line of the reader's own code the
    /// task is parked behind.
    pub(crate) awaiting_at: Option<String>,
    /// What would wake the task: the kind of every live slot holding
    /// its waker, sorted, repeats counted and comma-joined, so a
    /// `select!` over a timer and two channels reads `2x mpsc rx,
    /// timer`; which resource, and what its reader read, are the
    /// detail lines' to print. `unarmed: ` before the assessment's own
    /// word where no slot was found; `—` and its reasons for a task
    /// waiting on nothing at all. Built short of the slots first
    /// ([`base_rows`]) and merged once the sweep is in
    /// ([`with_slots`]).
    pub(crate) waiting_on: String,
    /// The kind-level bucket `--group waiting-on` files the row under:
    /// the slots' kinds, sorted, distinct and comma-joined (`io read,
    /// oneshot tx`), or the assessment's own bucket
    /// ([`assessment_kind`]) under `unarmed: `; `None` where the row
    /// waits on nothing nameable — mid-poll included.
    pub(crate) waiting_kind: Option<String>,
    /// The detail lines under `awaiting on:`: what the assessment has
    /// to say beyond the cell, the members of the stop, and one item
    /// per container the current await reaches a slot in.
    pub(crate) wait_detail: Vec<String>,
    /// What follows `awaiting on:` on its line: the cell, or the
    /// verified target with its reading where a slot accounts for it;
    /// `None` where the lines under it carry the wait whole — a set's
    /// members — so the label stands bare over them rather than
    /// listing the members the lines are about to list.
    pub(crate) wait_line: Option<String>,
    /// What a `waiting-on` clause matches: the label line and every
    /// detail line under it, so a filter can name the wait by its
    /// cell word, by the address of the resource on the label, or by
    /// the address of a primitive a detail names — the one a
    /// connection is parked on `via`, an item's slot.
    pub(crate) wait_text: String,
    /// The lines under `will wake:`: one item per container holding a
    /// slot the current await does not reach — installed by an await
    /// that has since returned, so its wake runs the task and the poll
    /// that follows consumes nothing. Empty for a task with none,
    /// which prints no such label.
    pub(crate) will_wake: Vec<String>,
    /// The root future's display name, folded and never truncated.
    pub(crate) future: String,
    /// The root future's type, where the symbol join resolved one:
    /// what `--group type` buckets the row under.
    #[serde(skip)]
    pub(crate) future_ty: Option<BundleTypeId>,
    /// `Spawned at:` — where the target records one
    /// (`tokio_unstable` task instrumentation).
    pub(crate) spawned: Option<String>,
    /// `Defined at:` — where the root future's source declares it.
    pub(crate) defined: Option<String>,
    /// The thread the task is on ([`task_lwp`]), `None` for a task on
    /// no thread.
    pub(crate) lwp: Option<u32>,
}

/// Which lwp is polling which task right now, by task id: what the
/// workers' `current_task_id` words say, believed or not.
pub(crate) fn polling_map<T: proc::Target>(session: &Session<'_, T>) -> HashMap<u64, u32> {
    session
        .workers
        .iter()
        .filter_map(|w| w.current_task_id.map(|id| (id, w.tid)))
        .collect()
}

/// The table's rows, built on first use and cached on the session.
/// The wait analysis is the cost — the census's own walk — and every
/// later `graph`/`census`/`whatis` then pays nothing more. The launch
/// builds the two halves apart ([`base_rows`] over the bare analysis
/// before the worker is joined, [`with_slots`] over the folded one
/// after) and sets the cell itself.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [TaskRow] {
    session
        .task_rows
        .get_or_init(|| with_slots(base_rows(session, session.analysis()), session))
}

/// The rows from `analysis` alone — the name, state, owner and site
/// columns, and the wait cell as that analysis assesses it. At launch
/// that is the analysis before the sweep's slots are folded in, and
/// [`with_slots`] rewrites the wait cell once they are.
pub(crate) fn base_rows<T: proc::Target>(
    session: &Session<'_, T>,
    analysis: &rt_graph::Analysis,
) -> Vec<TaskRow> {
    let polling = polling_map(session);
    build_rows(
        &session.tasks,
        &session.owners,
        &analysis.waits,
        &polling,
        blocking_lwps(session),
        &TypeNames::of(session),
    )
}

/// The rows finished against the folded analysis and its slots: the
/// wait cell and bucket as the analysis reads with the sweep's slots
/// folded in, the detail lines the attributed slots add, and the
/// `unarmed: ` mark on a task with none.
pub(crate) fn with_slots<T: proc::Target>(
    mut rows: Vec<TaskRow>,
    session: &Session<'_, T>,
) -> Vec<TaskRow> {
    let view = session.ctx.view;
    let containers = Containers::of(session.census());
    apply_slots(
        &mut rows,
        &session.tasks,
        &session.analysis().waits,
        session.attribution(),
        session.registries.stopped,
        &|ty| view.ty(ty).map(|t| t.size()),
        &TypeNames::of(session),
        Some(&containers),
    );
    rows
}

/// Build every row from what it prints — taken apart from the session
/// so a test can lay out a population no fixture holds.
pub(crate) fn build_rows(
    list: &bundle::TaskList,
    owners: &bundle::OwnerIndex,
    waits: &[rt_graph::TaskWait],
    polling: &HashMap<u64, u32>,
    blocking_lwps: &HashMap<u64, u32>,
    stops: &TypeNames<'_>,
) -> Vec<TaskRow> {
    list.tasks
        .iter()
        .enumerate()
        .map(|(index, task)| {
            let lwp = task_lwp(task, polling, blocking_lwps);
            let waiting_on = waiting_on(task, waits.get(index), polling, stops);
            let lines = waits
                .get(index)
                .map(|wait| {
                    let detail = Detail {
                        containers: None,
                        armed: show_armed(task),
                        frames: &wait.frames,
                        caller_at: None,
                        request_of: None,
                    };
                    wait_detail(wait, stops, &[], None, &|_| None, detail)
                })
                .unwrap_or_default();
            TaskRow {
                id: task_id(list, index),
                state: row_state(task, lwp),
                rt: RowOwner::of(task, owners),
                awaiting_at: waits
                    .get(index)
                    .and_then(|w| w.site.as_ref())
                    .map(|(file, line)| format!("{file}:{line}")),
                wait_line: lines.head.line(&waiting_on),
                wait_text: wait_text(&lines, &waiting_on),
                waiting_on,
                waiting_kind: waiting_kind(task, waits.get(index), stops),
                wait_detail: lines.awaiting,
                will_wake: lines.wake,
                future: future_name(&task.future, stops),
                future_ty: match &task.future {
                    bundle::FutureInfo::Known(known) => Some(known.future),
                    _ => None,
                },
                spawned: task.spawn_location.as_ref().map(|loc| loc.to_string()),
                defined: match &task.future {
                    bundle::FutureInfo::Known(known) => known
                        .decl
                        .as_ref()
                        .map(|(file, line)| format!("{file}:{line}")),
                    _ => None,
                },
                lwp,
            }
        })
        .collect()
}

/// Finish each row against `waits` — the analysis with the sweep's
/// slots folded in — and the slots attributed to its task. The cell
/// and the bucket are the folded assessment's own, so a row, a graph
/// line, a census tally and a trace header all read one wait; the
/// detail is one line per branch armed by the slots in it, one per
/// slot on its own. A task with no slot at all keeps the assessment's
/// words under `unarmed: `, since nothing found would wake it — except
/// a task waiting on nothing (`—` and its reasons), which has no slot
/// to miss. Blocking and mid-poll rows are untouched: neither is
/// parked, and the fold left their waits alone.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_slots(
    rows: &mut [TaskRow],
    list: &bundle::TaskList,
    waits: &[rt_graph::TaskWait],
    slots: &attribution::Attributed,
    stopped: Option<RawInstant>,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
    stops: &TypeNames<'_>,
    containers: Option<&Containers<'_>>,
) {
    // Whose waker the sweep found at an address: a connection's caller
    // where its callback's receiver is a set child's, which only the
    // sweep can name.
    let caller_at = |cell: u64| -> Option<String> {
        let slot = slots.at(cell)?;
        owner_label(list, containers.map(|c| c.census), slot.owner)
    };
    // What that caller asked for, read off the finds the census holds
    // for it.
    let request_of = |caller: &bundle::HttpCaller| -> Option<String> {
        crate::connections::caller_request(list, &containers?.requests, slots, caller)
    };
    for (index, (row, task)) in rows.iter_mut().zip(&list.tasks).enumerate() {
        if task.is_blocking() || task.state.lifecycle() == Lifecycle::Running {
            continue;
        }
        let Some(wait) = waits.get(index) else {
            continue;
        };
        row.waiting_on = assessment_cell(wait, stops);
        row.waiting_kind = assessment_kind(wait, stops);
        let detail = Detail {
            containers,
            armed: show_armed(task),
            frames: &wait.frames,
            caller_at: Some(&caller_at),
            request_of: Some(&request_of),
        };
        let owned: Vec<&attribution::AttributedSlot> = slots.of_task(task.addr.0).collect();
        if owned.is_empty() && waits_on_something(&wait.assessment) {
            row.waiting_on = format!("unarmed: {}", row.waiting_on);
            row.waiting_kind = row.waiting_kind.take().map(|k| format!("unarmed: {k}"));
        }
        let lines = wait_detail(wait, stops, &owned, stopped, size_of, detail);
        row.wait_line = lines.head.line(&row.waiting_on);
        row.wait_text = wait_text(&lines, &row.waiting_on);
        row.wait_detail = lines.awaiting;
        row.will_wake = lines.wake;
    }
}

/// Whether a task's members print their `armed:` line. While a
/// `select!` is pending on an idle task, every enabled branch was
/// polled to `Pending` on the last poll and a well-behaved future
/// registered its waker first, so every enabled branch is armed; an
/// unarmed branch there is disabled or never ready by construction,
/// which its own lines already say. The line carries something only
/// on a task that is not idle — notified, on a run queue, running —
/// where a wake may already have consumed the slot, or a poll that
/// ran out of budget left the branches after it unarmed.
fn show_armed(task: &bundle::Task) -> bool {
    task.state.lifecycle() != Lifecycle::Idle
}

/// What the lines under a wait read beside the wait itself.
#[derive(Clone, Copy)]
pub(crate) struct Detail<'a> {
    /// The census's finds by address, which name a container the way
    /// the census found it: a join set by its tasks, a find by its
    /// wait and its type, a member by the frame and local holding it.
    /// `None` for a listing laid out by hand, where every container is
    /// named by its type.
    pub(crate) containers: Option<&'a Containers<'a>>,
    /// Whether the members' `armed:` line prints ([`show_armed`]).
    pub(crate) armed: bool,
    /// The task's chain frames, root first ([`rt_graph::TaskWait::frames`]),
    /// which a `held in:` line's frame number indexes: the frame's type
    /// is what says where the local named beside it is declared.
    pub(crate) frames: &'a [ValueKey],
    /// Who the waker sweep found parked at an address, as a listing
    /// names them ([`owner_label`]): what a connection's `caller:` line
    /// says where its callback's receiver is no task's — a set child,
    /// which the sweep alone can place. `None` for a listing laid out
    /// by hand, where the caller prints as the connection read it.
    pub(crate) caller_at: Option<&'a dyn Fn(u64) -> Option<String>>,
    /// The request a connection's caller holds, as the census read it
    /// off the caller's finds ([`crate::connections::caller_request`]):
    /// what a connection's `request:` line says. `None` for a listing
    /// laid out by hand.
    pub(crate) request_of: Option<RequestOf<'a>>,
}

/// What a connection's caller asked for, by the caller the connection
/// names; see [`Detail::request_of`].
pub(crate) type RequestOf<'a> = &'a dyn Fn(&bundle::HttpCaller) -> Option<String>;

/// The census's finds by address — built once for a listing, since
/// every row's lines look its containers up, and the census holds
/// tens of thousands of finds on a large core.
pub(crate) struct Containers<'a> {
    census: &'a census::FutureCensus,
    held: HashMap<u64, usize>,
    /// The same finds by address and type: two finds share an address
    /// where one is the first member of the other — reqwest's response
    /// future inside the request the client boxed — and a member names
    /// the one of its own type.
    held_by_key: HashMap<(u64, BundleTypeId), usize>,
    sets: HashMap<u64, usize>,
    join_sets: HashMap<u64, usize>,
    /// The requests the census read, by holder, for the `request:`
    /// lines a listing prints per connection and per find.
    requests: crate::connections::RequestIndex,
}

impl<'a> Containers<'a> {
    /// The held find a member's key names, with its index in the
    /// census: the find of the key's own type at its address, or
    /// whichever find is at the address where none is of that type.
    pub(crate) fn held_index(&self, key: ValueKey) -> Option<(usize, &'a census::HeldFuture)> {
        let index = *self
            .held_by_key
            .get(&(key.addr, key.ty))
            .or_else(|| self.held.get(&key.addr))?;
        Some((index, &self.census.held[index]))
    }

    pub(crate) fn of(census: &'a census::FutureCensus) -> Self {
        let by_addr = |addrs: &mut dyn Iterator<Item = u64>| -> HashMap<u64, usize> {
            addrs.enumerate().map(|(i, addr)| (addr, i)).collect()
        };
        Containers {
            census,
            held: by_addr(&mut census.held.iter().map(|h| h.addr)),
            held_by_key: census
                .held
                .iter()
                .enumerate()
                .map(|(i, h)| ((h.addr, h.ty), i))
                .collect(),
            sets: by_addr(&mut census.sets.iter().map(|s| s.addr)),
            join_sets: by_addr(&mut census.join_sets.iter().map(|s| s.addr)),
            requests: crate::connections::RequestIndex::of(census),
        }
    }

    fn set_at(&self, addr: u64) -> Option<&'a census::FutureSet> {
        self.sets.get(&addr).map(|&i| &self.census.sets[i])
    }

    fn join_set_at(&self, addr: u64) -> Option<&'a census::JoinSet> {
        self.join_sets
            .get(&addr)
            .map(|&i| &self.census.join_sets[i])
    }
}

/// What stands on the `awaiting on:` line.
#[derive(Default)]
pub(crate) enum WaitHead {
    /// The cell: what the table says, which the lines under it add to.
    #[default]
    Cell,
    /// Nothing: the lines under it carry the wait whole.
    Listed,
    /// The verified target with its reading — the account of the slot
    /// it was read from, lifted onto the line, since the wait is that
    /// one resource and the slot adds only where the waker sits.
    Verified(String),
}

impl WaitHead {
    /// The text after `awaiting on:`, given the cell; `None` for a
    /// bare label.
    fn line(&self, cell: &str) -> Option<String> {
        match self {
            WaitHead::Cell => Some(cell.to_string()),
            WaitHead::Listed => None,
            WaitHead::Verified(text) => Some(text.clone()),
        }
    }
}

/// The lines a wait prints: what heads its label line, the lines
/// under `awaiting on:`, and the lines under `will wake:`.
#[derive(Default)]
pub(crate) struct WaitLines {
    pub(crate) head: WaitHead,
    pub(crate) awaiting: Vec<String>,
    pub(crate) wake: Vec<String>,
}

/// What a `waiting-on` clause matches for a row: the label line as it
/// prints — the verified target where a slot lifted it, else the cell
/// — and every line under it, one per line, so an address a detail
/// carries is reachable to a filter.
fn wait_text(lines: &WaitLines, cell: &str) -> String {
    let mut text = lines.head.line(cell).unwrap_or_else(|| cell.to_string());
    for line in &lines.awaiting {
        text.push('\n');
        text.push_str(line);
    }
    text
}

/// The cell and the bucket a list of slots amounts to: entries sorted,
/// repeats counted ([`waitset::counted`]) and comma-joined; buckets
/// sorted, distinct and comma-joined.
pub(crate) fn slot_cell(
    slots: &[&attribution::AttributedSlot],
    accounted: &dyn Fn(&attribution::AttributedSlot) -> Option<(String, String)>,
) -> (String, String) {
    let entries = waitset::counted(
        slots
            .iter()
            .map(|slot| accounted(slot).unwrap_or_else(|| (slot.cell(), slot.bucket())))
            .collect(),
    );
    let mut kinds: Vec<&str> = entries.iter().map(|(_, k)| k.as_str()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let kind = kinds.join(", ");
    let cell = entries
        .into_iter()
        .map(|(e, _)| e)
        .collect::<Vec<_>>()
        .join(", ");
    (cell, kind)
}

/// One `waker N:` block per slot, in the grammar an item's lines use:
/// what the wait is on where something names it, and the slot itself
/// where that line did not name the place. `on` is the reading the
/// owner's own reader gave for a slot it accounts for — the verified
/// target with its words, a find's description — which heads the
/// block in place of what the slot's entry names. The blocks are
/// numbered after sorting, so the same slots number them the same way
/// twice.
pub(crate) fn waker_blocks(
    slots: &[&attribution::AttributedSlot],
    on: &dyn Fn(&attribution::AttributedSlot) -> Option<String>,
    stopped: Option<RawInstant>,
) -> Vec<String> {
    let mut blocks: Vec<Vec<String>> = slots
        .iter()
        .map(|slot| waker_block(slot, on(slot), stopped))
        .collect();
    blocks.sort();
    let mut lines = Vec::new();
    for (i, block) in blocks.into_iter().enumerate() {
        lines.push(format!("waker {i}:"));
        lines.extend(block);
    }
    lines
}

/// One waker's lines, indented one step for the `waker N:` heading
/// over them: what the wait is on, and the slot itself. No `armed`
/// field: a slot is listed because it holds the waker, so the answer
/// would be `yes` on every one of them. A branch's says something,
/// because a branch can be held and unarmed.
fn waker_block(
    slot: &attribution::AttributedSlot,
    on: Option<String>,
    stopped: Option<RawInstant>,
) -> Vec<String> {
    let mut block = Vec::new();
    // What the wait is on: the reader's account where it has one —
    // with its reading, since this line carries the primitive and
    // nothing else — else what the slot's own entry names.
    let on = on.or_else(|| slot.waits_on(stopped));
    if let Some(on) = &on {
        block.push(format!("    awaiting on: {on}"));
    }
    if let Some(waker) = slot_waker(slot, on.as_deref(), stopped) {
        block.push(format!("    waker: {waker}"));
    }
    block
}

/// The `waker:` line of a slot: the slot itself, where the line naming
/// the resource (`on`) named the resource rather than the place — the
/// wheel entry holding the waker, the waiter node, or, for a slot no
/// table names, the type it sits in at its address, so a reader who
/// wants the bytes has an address to hand `print` or `whatis`. `None`
/// where there is nothing to add to the resource, or where the line
/// above named the very same thing: a wheel entry with no deadline to
/// give is `timer 0x…` there and `timer @ 0x…` here, and once is
/// enough.
pub(crate) fn slot_waker(
    slot: &attribution::AttributedSlot,
    on: Option<&str>,
    stopped: Option<RawInstant>,
) -> Option<String> {
    let waker = match (slot.wheel_entry(), slot.detail(stopped)) {
        (Some(entry), _) => entry,
        (None, Some(detail)) => detail,
        (None, None) => slot.waits_on(stopped).is_none().then(|| slot.place())?,
    };
    (on != Some(waker.replacen(" @ ", " ", 1).as_str())).then_some(waker)
}

/// Which lwp runs each claimed blocking task: unwind the stacks once
/// and look for a pc inside the task's resolved poll symbol — the
/// same join key `trace` anchors on. Paid only when some blocking row
/// is running, and cached on the session for every listing after.
pub(crate) fn blocking_lwps<'s, T: proc::Target>(
    session: &'s Session<'_, T>,
) -> &'s HashMap<u64, u32> {
    session.blocking_lwps.get_or_init(|| {
        let running: Vec<&bundle::Task> = session
            .tasks
            .tasks
            .iter()
            .filter(|t| t.is_blocking() && t.state.lifecycle() == Lifecycle::Running)
            .collect();
        if running.is_empty() {
            return HashMap::new();
        }
        let stacks = session.stacks();
        let mut map = HashMap::new();
        for task in running {
            let Ok(Some(range)) = session.ctx.poll_symbol_range(task) else {
                continue;
            };
            if let Some((tid, _)) = stacks
                .iter()
                .find(|(_, bt)| bt.frames.iter().any(|f| range.contains(&f.lookup_pc())))
            {
                map.insert(task.addr.0, *tid);
            }
        }
        map
    })
}

/// The `blocking (…)` spelling a pool cell's STATE carries: queued
/// until a thread claims it, running while claimed — plain `blocking`
/// where something names the lwp running it, since the row's thread
/// carries which one.
fn blocking_state(task: &bundle::Task, lwp: Option<u32>) -> String {
    match task.state.lifecycle() {
        Lifecycle::Running => match lwp {
            Some(_) => "blocking".to_string(),
            None => "blocking (running)".to_string(),
        },
        lifecycle => match lifecycle == Lifecycle::Complete {
            true => lifecycle.to_string(),
            false => "blocking (queued)".to_string(),
        },
    }
}

/// The `STATE` cell: the lifecycle — a blocking cell's queued/running
/// spelling — and the cancel bit, which any lifecycle can carry,
/// appended rather than replacing it.
pub(crate) fn row_state(task: &bundle::Task, lwp: Option<u32>) -> String {
    let state = match task.is_blocking() {
        true => blocking_state(task, lwp),
        false => task.state.lifecycle().to_string(),
    };
    match task.state.is_cancelled() {
        true => format!("{state} (cancelled)"),
        false => state,
    }
}

/// The `WAITING ON` cell: what the analysis assessed the task to be
/// waiting on — the verified target where there is one, and otherwise
/// the one word for what there is instead: `ready` for a resource that
/// has already given what was asked, `unknown` where the continuation
/// or the resource's state is not established, and a dash with the
/// reason for a task that waits on nothing at all — except that a
/// mid-poll task names the lwp polling it, since a running task is not
/// waiting at all.
fn waiting_on(
    task: &bundle::Task,
    wait: Option<&rt_graph::TaskWait>,
    polling: &HashMap<u64, u32>,
    stops: &TypeNames<'_>,
) -> String {
    // A blocking cell waits on a pool thread, not on a future — its
    // STATE says which; the cell has nothing to add.
    if task.is_blocking() {
        return "—".to_string();
    }
    if task.state.lifecycle() == Lifecycle::Running {
        return match task.task_id.and_then(|id| polling.get(&id)) {
            Some(lwp) => format!("— (mid-poll on lwp {lwp})"),
            None => "— (mid-poll)".to_string(),
        };
    }
    match wait {
        Some(wait) => assessment_cell(wait, stops),
        None => "—".to_string(),
    }
}

/// The one-word (or one-target) form of an assessment: the
/// `WAITING ON` cell every listing shares, so a task, a graph line and
/// a tally agree on what a wait is called. A verified wait is its
/// target's kind word, with the address and what the reader read
/// about it left to the detail lines. A wait set lists its armed
/// members' kinds, sorted, repeats counted and comma-joined, so a set
/// of one reads as the wait it is. An unknown says what made it one
/// ([`unknown_cell`]), and one whose stop holds futures none of which
/// is armed counts them.
pub(crate) fn assessment_cell(wait: &rt_graph::TaskWait, stops: &TypeNames<'_>) -> String {
    match &wait.assessment {
        WaitAssessment::Waiting(verified) => verified.target().cell(),
        WaitAssessment::Set(set) => set.cell(),
        WaitAssessment::ResourceReady(_) => "ready".to_string(),
        WaitAssessment::Unknown(_) => match wait.held_count() {
            0 => unknown_cell(wait, stops),
            1 => format!("{} (holds 1 future)", unknown_cell(wait, stops)),
            n => format!("{} (holds {n} futures)", unknown_cell(wait, stops)),
        },
        WaitAssessment::NeverReady { .. } => "never ready".to_string(),
        WaitAssessment::Unresumed => "— (unresumed)".to_string(),
        WaitAssessment::NotWaiting(NotWaitingReason::Returned) => "— (returned)".to_string(),
        WaitAssessment::NotWaiting(NotWaitingReason::Panicked) => "— (panicked)".to_string(),
        WaitAssessment::NotWaiting(NotWaitingReason::Complete) => "—".to_string(),
        WaitAssessment::Runnable(RunnableReason::Scheduled) => "— (queued)".to_string(),
        WaitAssessment::Runnable(RunnableReason::ActivePoll) => "— (mid-poll)".to_string(),
    }
}

/// The bucket `--group waiting-on` files an assessment under: the
/// verified target's kind-level label, `ready` as the cell spells it,
/// an unknown by what made it one ([`continuation_bucket`], or the
/// reason where the chain did reach a primitive), and nothing for a
/// task that waits on nothing — complete, runnable, never polled,
/// returned — which is the empty bucket rather than a value.
pub(crate) fn assessment_kind(wait: &rt_graph::TaskWait, stops: &TypeNames<'_>) -> Option<String> {
    match &wait.assessment {
        WaitAssessment::Waiting(verified) => Some(verified.target().group_label()),
        WaitAssessment::Set(set) => Some(set.group_label()),
        WaitAssessment::ResourceReady(_) => Some("ready".to_string()),
        WaitAssessment::Unknown(_) => Some(unknown_cell(wait, stops)),
        // Waiting, forever, on nothing that exists: its own bucket,
        // since a hang investigation wants to list exactly these.
        WaitAssessment::NeverReady { .. } => Some("never ready".to_string()),
        WaitAssessment::Unresumed | WaitAssessment::NotWaiting(_) | WaitAssessment::Runnable(_) => {
            None
        }
    }
}

/// Whether an assessment has the task waiting on anything — what a
/// task with no waker installed anywhere is then `unarmed` against.
/// Never polled, finished and runnable tasks wait on nothing, so no
/// missing waker says anything about them.
fn waits_on_something(assessment: &WaitAssessment) -> bool {
    match assessment {
        WaitAssessment::Waiting(_)
        | WaitAssessment::Set(_)
        | WaitAssessment::ResourceReady(_)
        | WaitAssessment::Unknown(_)
        | WaitAssessment::NeverReady { .. } => true,
        WaitAssessment::Unresumed | WaitAssessment::NotWaiting(_) | WaitAssessment::Runnable(_) => {
            false
        }
    }
}

/// What an unknown assessment says for itself in the cell — the same
/// words its bucket uses, since neither has a target to name: the
/// type the chain stopped at, how it was cut short, or the reason a
/// primitive's protocol declined.
fn unknown_cell(wait: &rt_graph::TaskWait, stops: &TypeNames<'_>) -> String {
    match &wait.assessment {
        WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {
            continuation_bucket(&wait.continuation, stops).unwrap_or_else(|| "unknown".to_string())
        }
        WaitAssessment::Unknown(reason) => format!("unknown ({})", unknown_word(*reason)),
        _ => "unknown".to_string(),
    }
}

/// The bucket an unknown continuation earns: the type the chain
/// stopped at, so a listing over thousands of unknowns separates the
/// hyper connection's `Map` stop from the `PollFn` and `Select` stops
/// and shows the long tail behind them — `unknown at
/// futures_util::future::Map`, generic arguments dropped since they
/// tell monomorphizations apart, not stops. A chain cut short says how
/// (`unknown (ambiguous dyn future)`); a chain that reached a
/// primitive nothing described is the bare `unknown`; a chain ending
/// in a future that is never ready is `never ready`, a bucket of its
/// own. `None` for a finished or mid-poll end, which waits on nothing.
pub(crate) fn continuation_bucket(
    continuation: &ContinuationStatus,
    stops: &TypeNames<'_>,
) -> Option<String> {
    match continuation {
        ContinuationStatus::Primitive => Some("unknown".to_string()),
        ContinuationStatus::NeverReady => Some("never ready".to_string()),
        ContinuationStatus::Unknown { at, .. } => Some(match stops.label(at.ty) {
            Some(stop) => format!("unknown at {stop}"),
            None => "unknown".to_string(),
        }),
        ContinuationStatus::Incomplete { reason, .. } => {
            Some(format!("unknown ({})", incomplete_word(*reason)))
        }
        ContinuationStatus::Unresumed
        | ContinuationStatus::Returned
        | ContinuationStatus::Panicked
        | ContinuationStatus::ActivePoll => None,
    }
}

/// The short form of a non-continuation unknown, for its bucket.
fn unknown_word(reason: WaitUnknownReason) -> &'static str {
    match reason {
        WaitUnknownReason::Continuation => "continuation",
        WaitUnknownReason::ResourceUnreadable => "resource unreadable",
        WaitUnknownReason::ResourceStateUnproven => "resource state unproven",
        WaitUnknownReason::Lifecycle => "lifecycle",
        WaitUnknownReason::TaskKind => "task kind",
        WaitUnknownReason::ConflictingEvidence => "conflicting evidence",
    }
}

/// The short form of a chain cut short, for its bucket.
fn incomplete_word(reason: IncompleteReason) -> &'static str {
    match reason {
        IncompleteReason::UnknownDyn => "dyn future not in the tokio info",
        IncompleteReason::AmbiguousDyn => "ambiguous dyn future",
        IncompleteReason::DepthLimit => "depth limit",
        IncompleteReason::Cycle => "cycle",
        IncompleteReason::Error => "read error",
        IncompleteReason::NoRoot => "no root in the tokio info",
    }
}

/// The lines under a row's wait. What the assessment has to say
/// beyond the cell where it is a word rather than a place (`ready:`,
/// `unknown:` with a reason other than the continuation — an unknown
/// stop is named by the cell); then, at a stop that polls several
/// things, one line per branch the census could read, each armed by
/// the slots that sit in it or were reached through it, or `held, not
/// armed` — the branches of a `select!` nested under a `select!:`
/// heading, so the word names what they are branches of, with the
/// frame holding the `select!` and its suspend point under the
/// heading; then one item per container holding a slot no member
/// accounts for — under `awaiting on:` where the task's current await
/// reaches it, under `will wake:` where an await that has returned
/// installed it ([`slot_items`]). A verified wait's own slot is lifted
/// onto the label line ([`WaitHead::Verified`]), with only its
/// `waker:` line under it. Any one waker wakes the task; nothing here
/// is a dependency.
pub(crate) fn wait_detail(
    wait: &rt_graph::TaskWait,
    stops: &TypeNames<'_>,
    slots: &[&attribution::AttributedSlot],
    stopped: Option<RawInstant>,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
    detail: Detail<'_>,
) -> WaitLines {
    let mut lines = Vec::new();
    let mut head = WaitHead::Cell;
    match &wait.assessment {
        WaitAssessment::ResourceReady(reason) => {
            lines.push(format!("ready: {}", ready_reason(*reason)));
        }
        WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {}
        WaitAssessment::Unknown(reason) => {
            lines.push(format!("unknown: {}", unknown_reason(*reason)));
        }
        // What the analysis saw beside the wait it verified, as a
        // field like every other line under the label.
        WaitAssessment::Waiting(_) => {
            lines.extend(wait.notes.iter().map(|note| format!("note: {note}")))
        }
        // A set's cell is its members' entries, and each armed
        // member's line opens with its entry: the lines carry the
        // cell whole, and the label stands bare over them.
        WaitAssessment::Set(_) if !slots.is_empty() => head = WaitHead::Listed,
        WaitAssessment::Set(_)
        | WaitAssessment::NeverReady { .. }
        | WaitAssessment::Unresumed
        | WaitAssessment::NotWaiting(_)
        | WaitAssessment::Runnable(_) => {}
    }
    let (members, capped) = match &wait.assessment {
        WaitAssessment::Set(set) => (set.members.as_slice(), set.capped),
        WaitAssessment::NeverReady { members, capped } => (members.as_slice(), *capped),
        WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {
            (wait.held.as_slice(), wait.held_capped)
        }
        _ => (&[][..], 0),
    };
    let mut rest: Vec<&attribution::AttributedSlot> = slots.to_vec();
    // The branches of a `select!` sit one step under a `select!:`
    // heading, pushed once before the first of them; they are sorted
    // to the front, so the heading opens a contiguous run. A future
    // held in a plain local is no branch of the macro and stays at
    // the level of the heading.
    let mut in_select = false;
    // A map's entries sit under the `entries:` heading that closes the
    // block of the member the map was reached through, two steps under
    // that member; the entries of a stop that is the map itself sit
    // under an `entries:` heading of their own at the top. The entries
    // the walk did not inspect are counted after the run, at the
    // entries' own depth.
    let mut stop_is_map = false;
    let mut uninspected: Option<(usize, usize)> = None;
    let flush = |lines: &mut Vec<String>, uninspected: &mut Option<(usize, usize)>| {
        if let Some((count, depth)) = uninspected.take()
            && count > 0
        {
            lines.push(format!(
                "{}{count} more entries not inspected",
                "    ".repeat(depth)
            ));
        }
    };
    for member in members {
        // A registry slot in no branch prints as the slot it is —
        // unless there are no slots at all (a target the sweep could
        // not run over), where the registries' account is all there is.
        if let MemberRoute::SlotOnly { within } = &member.route {
            if slots.is_empty() {
                lines.push(slot_only_line(member, within.as_deref()));
            }
            continue;
        }
        let (mine, others): (Vec<_>, Vec<_>) = rest
            .into_iter()
            .partition(|slot| attribution::member_accounts(member, slot, size_of));
        rest = others;
        let block = member_line(member, stops, &mine, stopped, detail);
        let mut depth = 0;
        if in_select_branch(&member.route) {
            if !in_select {
                lines.push("select!:".to_string());
                lines.extend(select_holder(wait));
                in_select = true;
            }
            depth += 1;
        }
        match &member.route {
            MemberRoute::Entry { under: Some(_), .. } => depth += 2,
            MemberRoute::Entry { under: None, .. } => {
                flush(&mut lines, &mut uninspected);
                if !stop_is_map {
                    lines.push("entries:".to_string());
                    stop_is_map = true;
                }
                depth += 1;
            }
            _ => flush(&mut lines, &mut uninspected),
        }
        if let Some(fanout) = member.entries {
            uninspected = Some((fanout.total - fanout.listed, depth + 2));
        }
        let indent = "    ".repeat(depth);
        lines.extend(block.into_iter().map(|line| format!("{indent}{line}")));
    }
    flush(&mut lines, &mut uninspected);
    if capped > 0 {
        let (indent, unit) = match (stop_is_map, in_select) {
            (true, _) => ("    ", "entries"),
            (false, true) => ("    ", "branches"),
            (false, false) => ("", "branches"),
        };
        lines.push(format!("{indent}{capped} more {unit} not inspected"));
    }
    // The verified target accounts for the slot it was read from: the
    // wait is that one resource, so its reading heads the label line
    // and the slot adds only where the waker sits.
    if let WaitAssessment::Waiting(verified) = &wait.assessment {
        let (accounted, others): (Vec<_>, Vec<_>) = rest
            .into_iter()
            .partition(|slot| attribution::verified_accounts(verified, slot, size_of));
        rest = others;
        if !accounted.is_empty() {
            let target = verified.target();
            let text = target.line();
            // A connection's verdict names the primitive it is parked
            // on one level under it: the slot in that primitive is
            // accounted for, and this is where it is said.
            if let Some(via) = target.via() {
                lines.push(format!("via: {}", via.line()));
            }
            // An io wait's route that crossed a TLS connection: where
            // that connection stands, read through the route.
            if let Some(tls) = target.tls() {
                lines.push(format!("tls: {}", tls_words(tls)));
            }
            // And who awaits the response it is carrying, read from
            // the callback the `via` line names — a receiver that is no
            // task's named by the sweep's account of its cell, where
            // the listing has one: the set child holding it, and the
            // task polling that set.
            if let Some(caller) = target.caller() {
                let swept = match (caller, detail.caller_at) {
                    (
                        bundle::HttpCaller::NotATask {
                            cell: Some(cell), ..
                        },
                        Some(at),
                    ) => at(*cell),
                    _ => None,
                };
                lines.push(format!(
                    "caller: {}",
                    swept.unwrap_or_else(|| caller.to_string())
                ));
                // And what that caller asked for, where its finds say.
                if let Some(request) = detail.request_of.and_then(|of| of(caller)) {
                    lines.push(format!("request: {request}"));
                }
            }
            // A server's request is the handler's, read off the frame
            // holding it when the connection was observed.
            if let Some(request) = server_request(wait.observation.as_ref()) {
                lines.push(format!("request: {request}"));
            }
            let mut wakers: Vec<String> = accounted
                .iter()
                .filter_map(|slot| slot_waker(slot, Some(&text), stopped))
                .collect();
            wakers.sort();
            wakers.dedup();
            lines.extend(wakers.into_iter().map(|waker| format!("waker: {waker}")));
            head = WaitHead::Verified(text);
        }
    }
    // The remaining slots, one item per container.
    let (awaited, wake) = slot_items(&rest, wait, stops, stopped, detail);
    lines.extend(awaited);
    WaitLines {
        head,
        awaiting: lines,
        wake,
    }
}

/// The lines under a `select!:` heading that place the `select!`
/// itself: the frame holding it — the coroutine whose awaitee the
/// `select!`'s own future is, one out from the stop at frame #0 — and
/// that frame's suspend point, the line of this task's code the
/// `select!` is written on. Nothing where the chain has no such frame.
fn select_holder(wait: &rt_graph::TaskWait) -> Vec<String> {
    if wait.frames.len() < 2 {
        return Vec::new();
    }
    let mut lines = vec!["    held in: frame 1".to_string()];
    if let Some(site) = frame_site(wait, 1) {
        lines.push(format!("    awaiting at: {site}"));
    }
    lines
}

/// The suspend point of chain frame `frame`, numbered as the listings
/// number frames, where the analysis recorded one for it.
fn frame_site(wait: &rt_graph::TaskWait, frame: usize) -> Option<String> {
    let index = wait.frames.len().checked_sub(1 + frame)?;
    let (file, line) = wait.frame_sites.get(index)?.as_ref()?;
    Some(format!("{file}:{line}"))
}

/// Where chain frame `frame` — numbered as the listings number frames,
/// over `frames` root first — declares its local `local`: the line a
/// `held in: frame N \`local\`` line is followed by as `declared at:`.
/// `None` where the frame is no coroutine or the bundle recorded no
/// declaration for the name.
fn declared_at(
    stops: &TypeNames<'_>,
    frames: &[ValueKey],
    frame: usize,
    local: &str,
) -> Option<String> {
    let index = frames.len().checked_sub(1 + frame)?;
    let (file, line) = stops.local_site(frames[index].ty, local)?;
    Some(format!("{file}:{line}"))
}

/// The items the slots no member accounts for are listed under, one
/// per container, split by whether the task's current await reaches
/// the slot ([`attribution::Reach`]): the items under `awaiting on:`,
/// then the items under `will wake:`. An item is headed by its
/// container as the census names it ([`container_heading`]), then
/// says where it lives (`held in:`), where this task's code reaches
/// it (`awaiting at:`, the holding frame's suspend point — an awaited
/// item's only, since nothing under `will wake:` is awaited), what its
/// slots wait on (`awaiting on:`, or `woken by:` under `will wake:`),
/// where its type is written (`type defined at:`), and the slots
/// themselves last (`waker:`). A slot nothing located is an item of
/// its own, headed by what it names and listed as awaited: the
/// stronger claim, that the poll will not consume it, is the one that
/// needs evidence. Items are sorted by heading, so the same slots
/// list the same way twice.
fn slot_items(
    slots: &[&attribution::AttributedSlot],
    wait: &rt_graph::TaskWait,
    stops: &TypeNames<'_>,
    stopped: Option<RawInstant>,
    detail: Detail<'_>,
) -> (Vec<String>, Vec<String>) {
    use attribution::Reach;

    type Items<'a> = BTreeMap<
        (u64, u32),
        (
            &'a attribution::Holding,
            Vec<&'a attribution::AttributedSlot>,
        ),
    >;
    let mut awaited: Items<'_> = BTreeMap::new();
    let mut parked: Items<'_> = BTreeMap::new();
    let mut loose = Vec::new();
    for &slot in slots {
        let (items, holding) = match &slot.reach {
            Reach::Awaited(holding) => (&mut awaited, holding),
            Reach::Parked(holding) => (&mut parked, holding),
            Reach::Unlocated => {
                loose.push(slot);
                continue;
            }
        };
        items
            .entry((holding.container.addr, holding.container.ty.0))
            .or_insert((holding, Vec::new()))
            .1
            .push(slot);
    }
    let item = |holding: &attribution::Holding,
                slots: &[&attribution::AttributedSlot],
                parked: bool|
     -> Vec<String> {
        let mut lines = vec![container_heading(holding.container, stops, detail)];
        let mut field = |label: &str, value: String| lines.push(format!("    {label}: {value}"));
        field(
            "held in",
            match &holding.local {
                Some(local) => format!("frame {} `{local}`", holding.frame),
                None => format!("frame {}", holding.frame),
            },
        );
        if let Some(local) = &holding.local
            && let Some(site) = declared_at(stops, detail.frames, holding.frame, local)
        {
            field("declared at", site);
        }
        if !parked && let Some(site) = frame_site(wait, holding.frame) {
            field("awaiting at", site);
        }
        let mut on: Vec<String> = slots.iter().filter_map(|s| s.waits_on(stopped)).collect();
        on.sort();
        on.dedup();
        for on in &on {
            field(if parked { "woken by" } else { "awaiting on" }, on.clone());
        }
        if let Some((file, line)) = stops.site(holding.container.ty) {
            field("type defined at", format!("{file}:{line}"));
        }
        let mut wakers: Vec<String> = slots
            .iter()
            .filter_map(|s| slot_waker(s, s.waits_on(stopped).as_deref(), stopped))
            .collect();
        wakers.sort();
        wakers.dedup();
        for waker in wakers {
            field("waker", waker);
        }
        lines
    };
    let flatten = |mut items: Vec<Vec<String>>| -> Vec<String> {
        items.sort();
        items.into_iter().flatten().collect()
    };
    let mut first: Vec<Vec<String>> = awaited
        .values()
        .map(|(holding, slots)| item(holding, slots, false))
        .collect();
    first.extend(loose.iter().map(|slot| {
        let on = slot.waits_on(stopped);
        let mut lines = vec![on.clone().unwrap_or_else(|| slot.place())];
        if let Some(waker) = on.and_then(|on| slot_waker(slot, Some(&on), stopped)) {
            lines.push(format!("    waker: {waker}"));
        }
        lines
    }));
    let second: Vec<Vec<String>> = parked
        .values()
        .map(|(holding, slots)| item(holding, slots, true))
        .collect();
    (flatten(first), flatten(second))
}

/// How an item names its container: the census's account where it
/// found one there — a join set by its tasks, a set of futures by its
/// children in flight, a find by the kind of wait its chain ends in
/// and its type — else the type at the address.
fn container_heading(key: ValueKey, stops: &TypeNames<'_>, detail: Detail<'_>) -> String {
    if let Some(containers) = detail.containers {
        if let Some(set) = containers.join_set_at(key.addr) {
            return format!(
                "join set {:#x} ({})",
                set.addr,
                summary::counted(set.children.len(), "task")
            );
        }
        if let Some(set) = containers.set_at(key.addr) {
            let live = set.children.iter().filter(|c| c.future.is_some()).count();
            return format!(
                "set {:#x} ({} in flight)",
                set.addr,
                summary::counted(live, "future")
            );
        }
        if let Some((_, held)) = containers.held_index(key) {
            let kind = held.wait.map(|wait| wait.word()).unwrap_or("future");
            return format!(
                "{kind} {:#x}: {}",
                held.addr,
                stops
                    .name(held.future)
                    .unwrap_or_else(|| stops.folded(held.future))
            );
        }
    }
    match stops.name(key.ty) {
        Some(name) => format!("{:#x}: {name}", key.addr),
        None => format!("{:#x}", key.addr),
    }
}

/// Whether a member is a branch of the stop's `select!` — one the
/// macro polls by its own index, or an entry reached through one —
/// as against a future the frame holds in a local of its own.
fn in_select_branch(route: &MemberRoute) -> bool {
    match route {
        MemberRoute::Select { .. } | MemberRoute::Disabled { .. } => true,
        MemberRoute::Entry { under, .. } => under.as_deref().is_some_and(in_select_branch),
        MemberRoute::Branch { .. } | MemberRoute::SlotOnly { .. } => false,
    }
}

/// A registry slot in no branch, as the analysis placed it, for a
/// session with no sweep to spell it as a slot.
fn slot_only_line(member: &WaitMember, within: Option<&str>) -> String {
    let slot = member.armed.as_ref();
    let name = slot
        .and_then(waitset::SlotRef::label)
        .unwrap_or_else(|| "a slot".to_string());
    let evidence = slot
        .and_then(waitset::SlotRef::detail)
        .map(|evidence| format!(": {evidence}"))
        .unwrap_or_default();
    let within = within.map(|w| format!(", {w}")).unwrap_or_default();
    format!("{name}{evidence}{within}; in no branch of the stop")
}

/// The future a branch is, named in full: one line stands for one
/// branch, so the generic arguments are what tells an arm from the
/// arm beside it — two `Next<…>`s over different streams, three
/// `recv`s on channels of different messages — where a bucket cuts
/// them because it collects every monomorphization ([`stop_label`]).
/// `ty` is the branch's own type where the analysis recorded one;
/// what it recorded as a name otherwise is worded the same way.
fn member_future(member: &WaitMember, stops: &TypeNames<'_>, ty: Option<BundleTypeId>) -> String {
    ty.and_then(|ty| stops.name(ty))
        .or_else(|| member.future.and_then(|future| stops.name(future)))
        .unwrap_or_default()
}

/// One branch's lines: its local — or its `select!` branch number —
/// whether it was borrowed, the future it is, and under it where it
/// lives, the engine's verdict on it, where its type is written, and
/// what arms it — the slots that sit in it or were reached through
/// it, else the registry or protocol evidence the analysis had. A
/// `select!` branch its mask has disabled is named and placed and
/// nothing more: `disabled` is the whole verdict, and why it is — a
/// false precondition, a completed output that missed its pattern —
/// is not in memory to be read.
///
/// The fields read in one order at every depth, the order the task
/// block's own read in: where it lives (`held in:`), where this
/// task's code reaches it (`awaiting at:`), what it awaits
/// (`awaiting on:`), where its type is written (`type defined at:`),
/// then the memory-side `waker:` line last. `armed:` opens the block
/// on a task that is not idle ([`show_armed`]).
fn member_line(
    member: &WaitMember,
    stops: &TypeNames<'_>,
    armed_by: &[&attribution::AttributedSlot],
    stopped: Option<RawInstant>,
    detail: Detail<'_>,
) -> Vec<String> {
    // Where the type on the heading is written is a fact about the
    // source, printed under the member whatever its state: the `poll`
    // of the first of its types that has one, or a coroutine's own
    // `async fn`. A `select!` branch's arm is a line of this task's
    // code, and is `awaiting at:` — absent on a `_ =` arm, which
    // binds nothing and leaves no declaration.
    let site =
        |types: &[Option<BundleTypeId>]| types.iter().flatten().find_map(|&ty| stops.site(ty));
    // The frame and local holding the member, where the census found
    // it there: a borrowed branch is a find of the frame's own. A
    // `select!` branch the macro owns lives in the macro's own tuple,
    // which the `select!:` heading has already placed.
    // A find of the task's own chain also says where its frame
    // declares the local — a find reached through another chain
    // numbers a frame of that chain, which `detail.frames` is not.
    let held_in = |key: Option<ValueKey>| -> Option<(String, Option<String>)> {
        if matches!(
            member.route,
            MemberRoute::Select {
                borrowed: false,
                ..
            }
        ) {
            return None;
        }
        let (_, held) = detail.containers?.held_index(key?)?;
        let declared = held
            .via
            .is_none()
            .then(|| declared_at(stops, detail.frames, held.frame, &held.local))
            .flatten();
        Some((format!("frame {} `{}`", held.frame, held.local), declared))
    };
    let (local, borrowed, arm, stream) = match &member.route {
        MemberRoute::Branch { local, borrowed } => (local.clone(), *borrowed, None, None),
        MemberRoute::Select {
            index,
            borrowed,
            arm,
        } => (format!("branch {index}"), *borrowed, arm.as_ref(), None),
        MemberRoute::Disabled { index, ty, arm } => {
            let future = member_future(member, stops, Some(*ty));
            let mut lines = vec![format!("branch {index}: {future}: disabled")];
            if let Some((file, line)) = arm {
                lines.push(format!("    awaiting at: {file}:{line}"));
            }
            if let Some((file, line)) = site(&[Some(*ty)]) {
                lines.push(format!("    type defined at: {file}:{line}"));
            }
            return lines;
        }
        // An entry is headed by its key, the name the map hands back
        // with each item; by its index where the key was not read.
        MemberRoute::Entry {
            index,
            key,
            borrowed,
            stream,
            ..
        } => (
            key.clone().unwrap_or_else(|| format!("entry {index}")),
            *borrowed,
            None,
            Some(*stream),
        ),
        MemberRoute::SlotOnly { .. } => unreachable!("only branches print as members"),
    };
    let via = if borrowed { " (borrowed)" } else { "" };
    let ty = member.key.map(|key| key.ty);
    let future = member_future(member, stops, ty);
    // An entry's line is its stream's, the type the map's own line
    // names it by, since the member is whatever that stream is polled
    // through to; a stream with no line of its own — a boxed trait
    // object — leaves it to the member, as any other member's is.
    let type_site = site(&[stream, ty]);
    // An entry's heading is its key alone: the stream it is was named
    // by the map's type on the line it sits under, and the future it
    // holds is the stream's own affair — what it waits on is the line
    // below.
    let heading = match &member.route {
        MemberRoute::Entry { .. } => format!("{local}{via}:"),
        _ => format!("{local}{via}: {future}"),
    };
    let mut lines = vec![heading];
    let mut field = |label: &str, value: String| lines.push(format!("    {label}: {value}"));
    // Whether a waker of this task's sits in the branch at all, which
    // is the question a reader asks first on a task that is not idle:
    // the rest of the lines say what it waits on and where the waker
    // is. A member that fans out holds no waker of its own.
    if detail.armed && member.entries.is_none() {
        field(
            "armed",
            match !armed_by.is_empty() || member.armed.is_some() {
                true => "yes".to_string(),
                false => "no".to_string(),
            },
        );
    }
    if let Some((held, declared)) = held_in(member.key) {
        field("held in", held);
        if let Some(declared) = declared {
            field("declared at", declared);
        }
    }
    if let Some((file, line)) = arm {
        field("awaiting at", format!("{file}:{line}"));
    }
    // A member that fans out — a map polled with this task's own
    // context, or a chain ending at one — is listed for its entries,
    // which follow it under an `entries:` heading that closes its
    // block: it holds no waker of this task's itself, so nothing arms
    // it. Any one entry wakes the task.
    if member.entries.is_some() {
        if let Some((file, line)) = &type_site {
            field("type defined at", format!("{file}:{line}"));
        }
        for note in &member.notes {
            field("note", note.clone());
        }
        lines.push("    entries:".to_string());
        return lines;
    }
    let verified = match &member.assessment {
        Some(WaitAssessment::Waiting(verified)) => Some(verified.target()),
        _ => None,
    };
    // What the wait is on has two routes to it, and they fail apart:
    // the chain route reads the primitive a chain ends at, and stops
    // at a hand-written future it cannot follow through; the slot
    // route names the type a waker sits in, whatever polled it. Where
    // the chain route named nothing, a slot of this task's still
    // names the primitive it is parked in, so that is the answer —
    // the same one arrived at the other way. The items below already
    // fall back like this; a branch that did not read `unknown` here
    // while `future` printed the name.
    let lifted: Vec<String> = match &member.assessment {
        Some(WaitAssessment::Unknown(_)) => {
            let mut named: Vec<String> = armed_by
                .iter()
                .filter_map(|slot| slot.waits_on(stopped))
                .collect();
            named.sort();
            named.dedup();
            named
        }
        _ => Vec::new(),
    };
    // What the `awaiting on` lines name, lifted or verified: a slot
    // naming the same thing adds only its detail below.
    let mut named = lifted.clone();
    for on in &lifted {
        field("awaiting on", on.clone());
    }
    if lifted.is_empty() {
        let on = match &member.assessment {
            Some(WaitAssessment::Waiting(verified)) => verified.target().line(),
            Some(WaitAssessment::Set(set)) => set.cell(),
            Some(WaitAssessment::ResourceReady(reason)) => {
                format!("ready: {}", ready_reason(*reason))
            }
            Some(WaitAssessment::Unknown(WaitUnknownReason::Continuation)) => "unknown".to_string(),
            Some(WaitAssessment::Unknown(reason)) => {
                format!("unknown ({})", unknown_word(*reason))
            }
            Some(WaitAssessment::NeverReady { .. }) => "never ready".to_string(),
            Some(WaitAssessment::Unresumed) => "never polled".to_string(),
            Some(WaitAssessment::NotWaiting(NotWaitingReason::Returned)) => "returned".to_string(),
            Some(WaitAssessment::NotWaiting(NotWaitingReason::Panicked)) => "panicked".to_string(),
            Some(WaitAssessment::NotWaiting(NotWaitingReason::Complete)) => "complete".to_string(),
            Some(WaitAssessment::Runnable(_)) => "runnable".to_string(),
            None => "not inspected".to_string(),
        };
        named.push(on.clone());
        field("awaiting on", on);
        // A connection's verdict names the primitive it is parked on
        // one level under it, as the task block's own does, and who
        // awaits the response with what they asked for.
        if let Some(via) = verified.and_then(bundle::WaitTarget::via) {
            field("via", via.line());
        }
        if let Some(tls) = verified.and_then(bundle::WaitTarget::tls) {
            field("tls", tls_words(tls));
        }
        if let Some(caller) = verified.and_then(bundle::WaitTarget::caller) {
            field("caller", caller.to_string());
            if let Some(request) = detail.request_of.and_then(|of| of(caller)) {
                field("request", request);
            }
        }
    }
    // What the find itself keeps, where the census read a request off
    // its chain: the caller's in-flight request, or — a server
    // connection the census found held — the handler's.
    if let Some((index, held)) = member
        .key
        .and_then(|key| detail.containers?.held_index(key))
    {
        if let Some(request) = detail
            .containers
            .and_then(|containers| containers.requests.of_held(index))
        {
            field("request", request);
        } else if let Some(request) = server_request(held.observation.as_ref()) {
            field("request", request);
        }
    }
    if let Some((file, line)) = &type_site {
        field("type defined at", format!("{file}:{line}"));
    }
    // The slots themselves, last: a wheel entry under a timer verdict
    // drops its deadline, which the line above just gave; a slot
    // whose own name stands on an `awaiting on` line above carries
    // only its detail, the way an item's does — naming it twice says
    // nothing the second time, and a slot with no detail to add says
    // nothing at all; a slot beside a verified wait that did not name
    // it is the slot whole, since nothing above it carries its name;
    // and a slot no table names is the type it sits in at its
    // address.
    let timer = matches!(verified, Some(bundle::WaitTarget::Timer { .. }));
    let mut wakers: Vec<String> = armed_by
        .iter()
        .filter_map(|slot| {
            if timer && let Some(entry) = slot.wheel_entry() {
                return Some(entry);
            }
            match slot.waits_on(stopped) {
                Some(on) if named.contains(&on) => slot_waker(slot, Some(&on), stopped),
                Some(_) if verified.is_some() => Some(slot.line(stopped)),
                Some(_) => Some(slot.entry_line(stopped)),
                None => Some(slot.place()),
            }
        })
        .collect();
    if armed_by.is_empty()
        && let Some(slot) = &member.armed
    {
        wakers.extend(slot.detail().or_else(|| slot.cell_entry()));
    }
    wakers.sort();
    wakers.dedup();
    for waker in wakers {
        field("waker", waker);
    }
    for note in &member.notes {
        field("note", note.clone());
    }
    lines
}

/// The request a server connection's handler is running for, where
/// the connection's observation read one off the handler's frames.
pub(crate) fn server_request(
    observation: Option<&hansei_runtime::tokio::observe::ResourceObservation>,
) -> Option<String> {
    use hansei_runtime::tokio::observe::ResourceObservation;
    match observation? {
        ResourceObservation::HttpConn(http) => http
            .server
            .as_ref()?
            .request
            .as_ref()
            .map(ToString::to_string),
        _ => None,
    }
}

/// What a ready resource has already done, in words.
pub(crate) fn ready_reason(reason: ReadyReason) -> &'static str {
    match reason {
        ReadyReason::JoinComplete => "the joined task is complete; its output awaits the next poll",
        ReadyReason::PermitsGranted => {
            "the acquire has been granted every permit it asked for; the next poll takes them"
        }
        ReadyReason::SemaphoreClosed => "the semaphore is closed; the next poll returns the error",
        ReadyReason::IoReady => {
            "readiness the operation wants has been delivered; the next poll attempts it"
        }
        ReadyReason::IoShutdown => "the io driver has shut the resource down",
        ReadyReason::IoNotified => "the readiness await's own node has been notified",
        ReadyReason::TimerFired => "the timer has fired; the next poll reads it",
        ReadyReason::TimerPendingFire => "the timer is marked to fire; the wake is on its way",
        ReadyReason::MessageReady => "a message is queued; the next poll takes it",
        ReadyReason::ChannelClosed => {
            "the channel is closed and drained; the next poll returns None"
        }
        ReadyReason::Notified => "the Notified has been notified; the next poll returns",
        ReadyReason::OneshotComplete => {
            "the oneshot's sender completed; the next poll takes the outcome"
        }
        ReadyReason::OneshotClosed => {
            "the receiver closed the oneshot; the next poll returns the error"
        }
    }
}

/// Why an assessment is unknown, in words.
pub(crate) fn unknown_reason(reason: WaitUnknownReason) -> &'static str {
    match reason {
        WaitUnknownReason::Continuation => "the chain does not end in a primitive",
        WaitUnknownReason::ResourceUnreadable => "the resource could not be read",
        WaitUnknownReason::ResourceStateUnproven => {
            "the resource's state is not one its protocol vouches for"
        }
        WaitUnknownReason::Lifecycle => "the task's state word and its storage disagree",
        WaitUnknownReason::TaskKind => "the task's kind is in conflict",
        WaitUnknownReason::ConflictingEvidence => "what was read contradicts the protocol",
    }
}

/// The bucket `--group waiting-on` files the row under: the
/// assessment's, except that a blocking cell and a running task wait
/// on nothing and land in the empty bucket.
fn waiting_kind(
    task: &bundle::Task,
    wait: Option<&rt_graph::TaskWait>,
    stops: &TypeNames<'_>,
) -> Option<String> {
    if task.is_blocking() || task.state.lifecycle() == Lifecycle::Running {
        return None;
    }
    assessment_kind(wait?, stops)
}

/// One row's table cells, in column order — the table's rows, and the
/// heading `--exec` opens each task's output with.
fn row_cells(row: &TaskRow, futures: usize, groups: bool) -> Vec<String> {
    let mut cells = vec![row.id.clone(), row.state.clone()];
    if groups {
        cells.push(row.rt.cell());
    }
    cells.push(futures.to_string());
    cells.push(row.awaiting_at.clone().unwrap_or_else(|| "—".to_string()));
    cells.push(row.waiting_on.clone());
    cells.push(row.future.clone());
    cells
}

/// What printing one task reads, taken apart from the session so the
/// offline tests can drive it over a census no fixture holds —
/// [`print_task`] gathers it from a session.
pub(crate) struct TaskView<'a> {
    pub(crate) list: &'a bundle::TaskList,
    pub(crate) rows: &'a [TaskRow],
    pub(crate) names: &'a TypeNames<'a>,
    /// The owner keys numbered as the listings print them.
    pub(crate) owners: &'a bundle::OwnerIndex,
    /// Each task's group — its runtime, or the local set that owns it
    /// — on the targets holding more than one, and empty for the rest.
    pub(crate) group_tags: &'a [String],
    pub(crate) polling: &'a HashMap<u64, u32>,
    pub(crate) blocking_lwps: &'a HashMap<u64, u32>,
    pub(crate) finds: Finds<'a>,
    pub(crate) tree: &'a CensusTree,
    /// The width the finds' names are cut to fit within under
    /// `children` ([`Session::fit_width`]); `None` leaves them whole.
    /// The task's own type line is never cut: it is the one name the
    /// command is about, so it wraps rather than ends in an ellipsis.
    pub(crate) fit: Option<usize>,
}

/// One task as labelled lines — what `task` prints. A row's cells
/// stacked rather than joined: the future type alone outruns a
/// terminal, and stacked, the id and state stay readable at its left.
/// The fields sit four columns in from the `task N` heading, so a run
/// of them under `tasks --exec task` reads as blocks rather than as
/// one long column. A line prints only where the target has something for it — no `—`
/// placeholders — so a missing source anchor is a shorter block. The
/// thread, the waker and the census counts print always, because
/// their empty spellings are answers: `<none>` is "on no thread",
/// `<empty>` is "nothing can wake it", `0` is "holds nothing". The
/// census's finds are counted here and listed by `children`
/// ([`print_task_children`]).
pub(crate) fn print_task_view(
    view: &TaskView<'_>,
    index: usize,
    out: &mut dyn io::Write,
) -> Result<()> {
    let task = &view.list.tasks[index];
    let row = &view.rows[index];
    writeln!(out, "task {}", row.id)?;
    writeln!(out, "    state: {}", row.state)?;
    // The thread the task is on — the worker mid-poll on it, the pool
    // thread running a blocking cell — printed always, since `<none>`
    // is an answer: the task is on no thread.
    writeln!(
        out,
        "    thread: {}",
        row.lwp
            .map(|lwp| lwp.to_string())
            .unwrap_or_else(|| "<none>".to_string())
    )?;
    // A mid-poll task waits on nothing, so it gets no wait line; the
    // table's wait cell says why.
    let polled = !task.is_blocking() && task.state.lifecycle() == Lifecycle::Running;
    if let Some(owner) = RowOwner::detail(task, view.owners, view.group_tags) {
        writeln!(out, "    owner: {owner}")?;
    }
    writeln!(out, "    type: {}", row.future)?;
    if let Some(loc) = &row.awaiting_at {
        writeln!(out, "    awaiting at: {loc}")?;
    }
    // The wait, then what the assessment has to say beyond the cell
    // and one line per slot holding the task's waker: where it sits,
    // and what says it is current. Where the lines carry the cell
    // whole, the label stands bare over them rather than listing the
    // wakers the lines are about to list.
    if !polled && row.waiting_on != "—" {
        match &row.wait_line {
            Some(line) => writeln!(out, "    awaiting on: {line}")?,
            None => writeln!(out, "    awaiting on:")?,
        }
        for line in &row.wait_detail {
            writeln!(out, "        {line}")?;
        }
        // The slots the current await does not reach: installed by an
        // await that has returned, each will wake the task, and the
        // poll that follows will not consume it. Nothing under this
        // label says "awaiting".
        if !row.will_wake.is_empty() {
            writeln!(out, "    will wake:")?;
            for line in &row.will_wake {
                writeln!(out, "        {line}")?;
            }
        }
    }
    if let Some(loc) = &task.spawn_location {
        writeln!(out, "    spawned at: {loc}")?;
    }
    if let bundle::FutureInfo::Known(known) = &task.future
        && let Some((file, line)) = &known.decl
    {
        writeln!(out, "    type defined at: {file}:{line}")?;
    }
    // What the task has off its spine, in two rows rather than one:
    // the futures held in its own frames, and the sets it drives from
    // them. A set is a container, so counting it among the futures
    // made a row saying `Futures: 2` list three finds; keeping the two
    // apart lets each number say what the listing under it shows. The
    // sets are one row whichever kind they are — a listing of what
    // this task drives is one thing to read — with the tasks and the
    // futures they hold counted apart, since those are not the same
    // population. Last, since what `children` lists under them is as
    // long as the census found it to be — which is why the block
    // counts and does not list: a task driving thousands of children
    // would bury its own fields.
    let count = view.tree.counts.get(&index).copied().unwrap_or_default();
    writeln!(out, "    held futures: {}", count.held)?;
    writeln!(out, "    join sets: {}", count.sets_summary())?;
    Ok(())
}

/// The finds at the top of a task's listing: what the census found in
/// its own frames, and the sets it drives from them.
fn task_roots<'a>(view: &'a TaskView<'_>, index: usize) -> &'a [Entry] {
    view.tree
        .roots
        .get(&index)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// What `children` prints under a task cursor: the block's two count
/// rows, `held futures` and `join sets`, at the left margin, with the
/// finds each counts listed under it — the same rows `task` prints at
/// its fields' column, followed by what they count.
pub(crate) fn print_task_children(
    view: &TaskView<'_>,
    index: usize,
    out: &mut dyn io::Write,
) -> Result<()> {
    let listing = Listing {
        blocking_lwps: view.blocking_lwps,
        fit: view.fit,
        finds: view.finds,
        nested: &view.tree.nested,
        list: view.list,
        polling: view.polling,
        names: view.names,
    };
    let count = view.tree.counts.get(&index).copied().unwrap_or_default();
    print_finds(
        &count.held.to_string(),
        &count.sets_summary(),
        task_roots(view, index),
        &listing,
        0,
        out,
    )
}

/// The two rows a block counts the census's finds under — `held
/// futures` and `join sets` — each followed by the finds it counts,
/// one step in. `held` and `sets` are the rows' values as their owner
/// prints them; `entries` the finds at the top of the listing, sorted
/// under the rows by [`Entry::is_set`]; `indent` the rows' column,
/// with the finds four further in and whatever each holds four again
/// ([`print_future_entry`]).
pub(crate) fn print_finds(
    held: &str,
    sets: &str,
    entries: &[Entry],
    listing: &Listing<'_>,
    indent: usize,
    out: &mut dyn io::Write,
) -> Result<()> {
    let pad = " ".repeat(indent);
    for (label, value, is_set) in [("held futures", held, false), ("join sets", sets, true)] {
        writeln!(out, "{pad}{label}: {value}")?;
        for entry in entries.iter().filter(|e| e.is_set() == is_set) {
            print_future_entry(*entry, listing, indent + 4, false, out)?;
        }
    }
    Ok(())
}

/// The [`TaskView`] over the session, handed to `print`: what `task`
/// and `children` both read, built once per command.
fn with_task_view<T: proc::Target>(
    session: &Session<'_, T>,
    fit: Option<usize>,
    print: impl FnOnce(&TaskView<'_>) -> Result<()>,
) -> Result<()> {
    let names = TypeNames::of(session);
    let polling = polling_map(session);
    let view = TaskView {
        list: &session.tasks,
        rows: rows(session),
        names: &names,
        owners: &session.owners,
        group_tags: &session.group_tags(),
        polling: &polling,
        blocking_lwps: blocking_lwps(session),
        finds: session.census().into(),
        tree: session.census_tree(),
        fit,
    };
    print(&view)
}

/// [`print_task_view`] over the session: what `task` prints for the
/// task at `index`. The counts stay quiet about a walk cut short, as
/// the table does; the listing (`children`) is where that is said.
pub(crate) fn print_task<T: proc::Target>(
    session: &Session<'_, T>,
    index: usize,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    with_task_view(session, fit, |view| print_task_view(view, index, out))
}

/// [`print_task_children`] over the session: what `children` prints
/// under a cursor on the task at `index`. The listing is a lower bound
/// the same way `futures` is, so it also says where the walk stopped
/// short — a walk that hit a limit looks like completeness otherwise.
pub(crate) fn print_children<T: proc::Target>(
    session: &Session<'_, T>,
    index: usize,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let census = session.census();
    print_warnings(&census.errors)?;
    warn_census_capped(census.capped, "listed")?;
    warn_census_uncertain(census.uncertain, "listed")?;
    warn_census_refused(census.refused, "listed")?;
    with_task_view(session, fit, |view| print_task_children(view, index, out))
}

/// Print the table: one row per task, in the listing's own id order,
/// each with its [`Counts::futures`] count, the `RT` column only when
/// the target holds more than one group.
fn print_task_table(
    rows: &[(&TaskRow, usize)],
    groups: bool,
    limit: Option<usize>,
    fit: Option<usize>,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let shown = limit.unwrap_or(rows.len()).min(rows.len());
    let mut header = vec!["ID", "STATE"];
    if groups {
        header.push("RT");
    }
    // The count sits with the short cells, right-aligned as a number,
    // ahead of the three that run wide. Its heading is abbreviated
    // because a column is as wide as its widest cell, heading
    // included, and the counts under this one are a digit or two: the
    // word would cost every row four columns to name one of them.
    header.push("FUT");
    let futures = header.len() - 1;
    header.extend(["AWAITING AT", "WAITING ON", "TYPE"]);
    let columns = header.len();
    // The wait and the future are type names: what a terminal cuts
    // to keep a row on one line.
    let mut table = crate::output::Table::new(columns)
        .header(header)
        .align_right(futures)
        .truncatable(columns - 2)
        .truncatable(columns - 1)
        .fit(fit)
        .theme(theme);
    for (row, futures) in &rows[..shown] {
        table.row(row_cells(row, *futures, groups));
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(rows.len(), shown, "task"))?;
    Ok(())
}

/// The line under a listing, bracketed to stand apart from the rows:
/// the count when everything printed, both numbers when a limit cut
/// it — the only truncation there is.
pub(crate) fn listing_footer(total: usize, shown: usize, noun: &str) -> String {
    match shown < total {
        true => format!("[{}, {shown} shown]", summary::counted(total, noun)),
        false => format!("[{}]", summary::counted(total, noun)),
    }
}

/// The distinct spelled values of one column, most frequent first and
/// ties in value order — the order `--group` prints its buckets — with
/// the rows that have nothing in the column left out. What the prompt
/// offers as the argument of a `--with FIELD` clause.
pub(crate) fn distinct_values(values: impl Iterator<Item = Option<String>>) -> Vec<String> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for value in values.flatten() {
        *counts.entry(value).or_default() += 1;
    }
    let mut list: Vec<(String, usize)> = counts.into_iter().collect();
    list.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    list.into_iter().map(|(value, _)| value).collect()
}

/// The values the target holds for `field`, for the prompt to offer
/// after `--with FIELD`: `None` for a field the population does not
/// enumerate — the count comparisons — and whether the field reads
/// its argument as a pattern, which decides how a value is spelled
/// back into the line.
pub(crate) fn field_values<T: proc::Target>(
    session: &Session<'_, T>,
    field: &str,
) -> Option<(Vec<String>, bool)> {
    let field = Field::parse(field).ok()?;
    let values = field.values(rows(session))?;
    Some((values, field.is_pattern()))
}

/// Everything the `tasks` command was asked. The filter grammar rides
/// in as the raw flag values and is parsed here, so the errors name
/// the flag they came from.
pub(crate) struct TasksCmd {
    pub(crate) limit: Option<usize>,
    pub(crate) with: Vec<String>,
    pub(crate) without: Vec<String>,
    pub(crate) group: Option<String>,
    pub(crate) exec: Vec<String>,
    pub(crate) task: Vec<String>,
}

/// One filterable field of the task population — what `--with`,
/// `--without` and `--group` name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    /// The root future name, as the table prints it.
    Type,
    /// The leaf await site, `file:line`.
    Awaiting,
    /// The `WAITING ON` spelling: the slots holding the task's waker.
    /// `waker` and `slots` name it too.
    WaitingOn,
    /// The spawn location.
    Spawned,
    /// The definition site.
    Defined,
    /// The lifecycle, ` (cancelled)` included.
    State,
    /// The group index `runtimes` prints — exact.
    Rt,
    /// The lwp mid-poll on the task — exact.
    Lwp,
    /// A comparison on the `Held futures` count.
    Holds,
    /// A comparison on the `Join sets` count.
    Sets,
    /// A comparison on the `FUT` column, [`Counts::futures`].
    Futures,
    /// The task id — exact, for scripts.
    Id,
}

impl Field {
    const NAMES: [(&'static str, Field); 12] = [
        ("type", Field::Type),
        ("awaiting", Field::Awaiting),
        ("waiting-on", Field::WaitingOn),
        ("spawned", Field::Spawned),
        ("defined", Field::Defined),
        ("state", Field::State),
        ("rt", Field::Rt),
        ("lwp", Field::Lwp),
        ("holds", Field::Holds),
        ("sets", Field::Sets),
        ("futures", Field::Futures),
        ("id", Field::Id),
    ];

    /// Every field name, in the order the errors list them — what the
    /// prompt offers after `--group`, `--with` and `--without`.
    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        Self::NAMES.iter().map(|(n, _)| *n)
    }

    /// Older names for a field, still accepted: the waker slots were a
    /// field of their own before they became the wait cell.
    const ALIASES: [(&'static str, Field); 2] =
        [("waker", Field::WaitingOn), ("slots", Field::WaitingOn)];

    /// The field a flag named, or an error listing what it could have.
    fn parse(name: &str) -> Result<Field> {
        Self::NAMES
            .iter()
            .chain(&Self::ALIASES)
            .find(|(n, _)| *n == name)
            .map(|(_, f)| *f)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no field {name:?}; the fields are {}",
                    Self::NAMES.map(|(n, _)| n).join(", ")
                )
            })
    }

    fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, f)| *f == self)
            .map(|(n, _)| *n)
            .expect("every field is named")
    }

    /// Whether evaluating this field costs the future census.
    fn needs_census(self) -> bool {
        matches!(self, Field::Holds | Field::Sets | Field::Futures)
    }

    /// Whether the field's argument is a pattern rather than an exact
    /// or compared value.
    fn is_pattern(self) -> bool {
        !matches!(
            self,
            Field::Id | Field::Lwp | Field::Rt | Field::Holds | Field::Sets | Field::Futures
        )
    }

    /// The distinct values the rows hold for the field — the kind
    /// level for the wait column, as `--group` buckets it, since the
    /// kind is a prefix of every spelled cell — or `None` for a count
    /// the argument compares against.
    fn values(self, rows: &[TaskRow]) -> Option<Vec<String>> {
        let column = |f: fn(&TaskRow) -> Option<String>| distinct_values(rows.iter().map(f));
        Some(match self {
            Field::Type => column(|r| Some(r.future.clone())),
            Field::Awaiting => column(|r| r.awaiting_at.clone()),
            Field::WaitingOn => column(|r| r.waiting_kind.clone()),
            Field::Spawned => column(|r| r.spawned.clone()),
            Field::Defined => column(|r| r.defined.clone()),
            Field::State => column(|r| Some(r.state.clone())),
            Field::Rt => column(|r| Some(r.rt.to_string())),
            Field::Lwp => column(|r| r.lwp.map(|lwp| lwp.to_string())),
            Field::Id => column(|r| Some(r.id.clone())),
            Field::Holds | Field::Sets | Field::Futures => return None,
        })
    }
}

/// How one clause matches its field's value.
#[derive(Debug)]
enum Matcher {
    /// A case-insensitive regex over the spelled value.
    Pattern(crate::pattern::Pattern),
    /// Exact equality: `id`.
    Exact(String),
    /// Exact lwp: `lwp`.
    Lwp(u32),
    /// A resolved owner cell: `rt`.
    Rt(RowOwner),
    /// `'>N'` / `'<N'` / `'=N'`: `holds`, `sets`, `futures`.
    Cmp(Cmp),
}

/// A count comparison, spelled the way the flag takes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Cmp {
    op: std::cmp::Ordering,
    n: usize,
}

impl Cmp {
    /// Parse `'>N'`, `'<N'` or `'=N'` — the only spellings; the shell
    /// quotes are the user's, hansei never sees them.
    pub(crate) fn parse(arg: &str) -> Result<Cmp> {
        let refuse = || anyhow::anyhow!("a count is compared with '>N', '<N' or '=N', got {arg:?}");
        let op = match arg.chars().next() {
            Some('>') => std::cmp::Ordering::Greater,
            Some('<') => std::cmp::Ordering::Less,
            Some('=') => std::cmp::Ordering::Equal,
            _ => return Err(refuse()),
        };
        let n = arg[1..].parse().map_err(|_| refuse())?;
        Ok(Cmp { op, n })
    }

    pub(crate) fn matches(self, count: usize) -> bool {
        count.cmp(&self.n) == self.op
    }
}

/// One `--with`/`--without` clause.
#[derive(Debug)]
struct Clause {
    field: Field,
    /// The argument's alternatives (`1,2,3`): the clause matches a
    /// row when any one of them does.
    matchers: Vec<Matcher>,
    /// `--without`: the clause keeps the rows it does *not* match.
    negate: bool,
}

/// Parse the flag pairs into clauses. clap delivered FIELD/ARG pairs
/// (`num_args = 2`), so the chunks are exact.
fn parse_clauses(with: &[String], without: &[String], handles: &[u64]) -> Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    for (specs, negate) in [(with, false), (without, true)] {
        let flag = if negate { "--without" } else { "--with" };
        for [name, spec] in specs.as_chunks::<2>().0 {
            let field = Field::parse(name).with_context(|| flag.to_string())?;
            let matchers = alternatives(spec)
                .and_then(|alts| {
                    alts.iter()
                        .map(|alt| matcher(field, alt, handles))
                        .collect()
                })
                .with_context(|| format!("{flag} {}", field.name()))?;
            clauses.push(Clause {
                field,
                matchers,
                negate,
            });
        }
    }
    Ok(clauses)
}

/// The alternatives one clause argument spells: `1,2,3` is three,
/// and the clause matches when any one does. The comma separates
/// everywhere, so a literal one — a regex's `{1,3}`, a type's
/// `(u8, u16)` — is written `\,`; a backslash before anything else
/// passes through untouched, so the regex grammar's own escapes
/// keep their meaning. An empty alternative (`1,,2`, a trailing
/// comma) is refused rather than matching nothing.
pub(crate) fn alternatives(arg: &str) -> Result<Vec<String>> {
    let mut items = vec![String::new()];
    let mut chars = arg.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&',') => {
                chars.next();
                items.last_mut().expect("never empty").push(',');
            }
            '\\' => {
                let item = items.last_mut().expect("never empty");
                item.push(c);
                item.extend(chars.next());
            }
            ',' => items.push(String::new()),
            c => items.last_mut().expect("never empty").push(c),
        }
    }
    if arg.is_empty() {
        anyhow::bail!("an empty argument matches nothing");
    }
    if items.iter().any(String::is_empty) {
        anyhow::bail!(
            "empty alternative in {arg:?}: a list is spelled `A,B` with nothing \
             between, and a literal comma is `\\,`"
        );
    }
    Ok(items)
}

/// The matcher one field's argument compiles to.
fn matcher(field: Field, arg: &str, handles: &[u64]) -> Result<Matcher> {
    Ok(match field {
        Field::Id => Matcher::Exact(arg.to_string()),
        Field::Lwp => Matcher::Lwp(
            arg.parse()
                .map_err(|_| anyhow::anyhow!("an lwp is a decimal id, got {arg:?}"))?,
        ),
        Field::Rt => Matcher::Rt(resolve_rt(arg, handles)?),
        Field::Holds | Field::Sets | Field::Futures => Matcher::Cmp(Cmp::parse(arg)?),
        _ => Matcher::Pattern(crate::pattern::Pattern::new(arg)?),
    })
}

/// Resolve an `rt` argument — a group index, or a runtime's `0x`
/// handle as `runtimes` prints it, with or without a leading
/// `@`, or the word `unknown` or `conflict` — to the owner cell rows
/// carry. Exact, and an unknown handle is an error rather than an
/// empty match.
pub(crate) fn resolve_rt(arg: &str, handles: &[u64]) -> Result<RowOwner> {
    // Both the word and the mark the `RT` column prints for it.
    match arg {
        "unknown" | "?" => return Ok(RowOwner::Unknown),
        "conflict" | "!" => return Ok(RowOwner::Conflict),
        _ => {}
    }
    let addr = arg.strip_prefix('@').unwrap_or(arg);
    if let Some(digits) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) {
        let addr = u64::from_str_radix(digits, 16)
            .map_err(|e| anyhow::anyhow!("invalid handle address {arg:?}: {e}"))?;
        return handles
            .iter()
            .position(|&h| h == addr)
            .map(RowOwner::Group)
            .ok_or_else(|| anyhow::anyhow!("no runtime has the handle {addr:#x}"));
    }
    arg.parse().map(RowOwner::Group).map_err(|_| {
        anyhow::anyhow!(
            "a runtime is named by its index in `runtimes` or by the \
             handle address printed beside it there (or `unknown`/`?` \
             or `conflict`/`!` for a task no group owns), got {arg:?}"
        )
    })
}

/// The census counts the table's `FUT` column and a
/// `holds`/`sets`/`futures` clause read, keyed by task index — built
/// only for the table and for a clause or grouping naming one, since
/// they cost the census walk.
type CountsByTask = BTreeMap<usize, Counts>;

/// One task's counts, zero where the census found nothing for it.
fn counts_of(counts: &CountsByTask, index: usize) -> Counts {
    counts.get(&index).copied().unwrap_or_default()
}

/// Whether one row survives one clause: any alternative matching is
/// a hit, and `--without` keeps the misses.
fn survives(clause: &Clause, index: usize, row: &TaskRow, counts: Option<&CountsByTask>) -> bool {
    let hit = clause.matchers.iter().any(|matcher| match matcher {
        Matcher::Pattern(p) => field_text(clause.field, row).is_some_and(|t| p.is_match(t)),
        Matcher::Exact(id) => row.id == *id,
        Matcher::Lwp(lwp) => row.lwp == Some(*lwp),
        Matcher::Rt(rt) => row.rt == *rt,
        Matcher::Cmp(cmp) => cmp.matches(field_count(clause.field, index, counts)),
    });
    hit != clause.negate
}

/// The spelled value a regex field matches — `None`, nothing to
/// match, where the row has nothing to say.
fn field_text(field: Field, row: &TaskRow) -> Option<&str> {
    match field {
        Field::Type => Some(&row.future),
        Field::Awaiting => row.awaiting_at.as_deref(),
        Field::WaitingOn => Some(&row.wait_text),
        Field::Spawned => row.spawned.as_deref(),
        Field::Defined => row.defined.as_deref(),
        Field::State => Some(&row.state),
        _ => unreachable!("{field:?} is not a regex field"),
    }
}

/// The count a comparison field reads.
fn field_count(field: Field, index: usize, counts: Option<&CountsByTask>) -> usize {
    let count = counts_of(
        counts.expect("census counts are built for a count clause"),
        index,
    );
    match field {
        Field::Holds => count.held,
        // The row the blocks print: how many sets the task drives, of
        // either kind.
        Field::Sets => count.sets + count.join_sets,
        Field::Futures => count.futures(),
        _ => unreachable!("{field:?} is not a count field"),
    }
}

/// The bucket a row with nothing in the grouped field lands in.
pub(crate) const EMPTY_BUCKET: &str = "<empty>";

/// What a bucket is named for one row: the field's spelled value, or
/// `None` for [`EMPTY_BUCKET`].
fn group_value(
    field: Field,
    index: usize,
    row: &TaskRow,
    counts: Option<&CountsByTask>,
) -> Option<String> {
    match field {
        Field::Type => Some(row.future.clone()),
        Field::Awaiting => row.awaiting_at.clone(),
        // Grouped at the kind level — every timer one bucket, not one
        // per deadline — and a task waiting on nothing nameable (the
        // table's `—`, a mid-poll row) is the empty bucket, not a value.
        Field::WaitingOn => row.waiting_kind.clone(),
        Field::Spawned => row.spawned.clone(),
        Field::Defined => row.defined.clone(),
        Field::State => Some(row.state.clone()),
        Field::Rt => Some(row.rt.to_string()),
        Field::Lwp => row.lwp.map(|lwp| lwp.to_string()),
        Field::Holds | Field::Sets | Field::Futures => {
            Some(field_count(field, index, counts).to_string())
        }
        Field::Id => Some(row.id.clone()),
    }
}

/// Up to three member ids and `…` — the sample a bucket row carries.
fn member_sample(rows: &[TaskRow], members: &[usize]) -> String {
    let ids: Vec<&str> = members
        .iter()
        .take(3)
        .map(|&i| rows[i].id.as_str())
        .collect();
    match members.len() > ids.len() {
        true => format!("{}, …", ids.join(", ")),
        false => ids.join(", "),
    }
}

/// The refusal a positional id earns: the grammar that took ids is
/// gone, and one task is the singular selector's business.
fn refuse_positional_ids(task: &[String]) -> Result<()> {
    match task.first() {
        Some(first) => Err(anyhow::anyhow!(
            "tasks takes no task ids; `task {first}` selects that one task"
        )),
        None => Ok(()),
    }
}

pub(crate) fn exec_tasks<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: TasksCmd,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = &session.tasks;
    refuse_positional_ids(&cmd.task)?;
    let group = cmd
        .group
        .as_deref()
        .map(Field::parse)
        .transpose()
        .context("--group")?;
    let handles: Vec<u64> = session.runtimes.iter().map(|rt| rt.handle.addr).collect();
    let clauses = parse_clauses(&cmd.with, &cmd.without, &handles)?;

    // The table's `FUT` column and a count clause or grouping
    // read what only the census counts; `--exec` and the other
    // groupings pay for its walk only when a clause asks.
    let build_counts = || census_counts(session.census().into());
    let counts = (clauses.iter().any(|c| c.field.needs_census())
        || group.is_some_and(Field::needs_census))
    .then(build_counts);

    // The filters' survivors, as indices into the task list — `None`
    // when there is nothing to filter by.
    let survivors: Option<Vec<usize>> = (!clauses.is_empty()).then(|| {
        let rows = rows(session);
        (0..rows.len())
            .filter(|&i| {
                clauses
                    .iter()
                    .all(|c| survives(c, i, &rows[i], counts.as_ref()))
            })
            .collect()
    });

    if !cmd.exec.is_empty() {
        // clap refuses `--group` beside `--exec`; the filters and
        // `--limit` have already chosen who the command runs against.
        return exec_exec(session, &cmd, survivors, theme, out);
    }

    if let Some(field) = group {
        return exec_group(
            session,
            &cmd,
            field,
            survivors,
            counts,
            session.fit_width(theme),
            theme,
            out,
        );
    }

    // The table counts each task's futures, so it pays for the census
    // walk, and, as a count clause does, without the walk's own
    // warnings: those go with a listing of the finds (`children`,
    // `futures`), where a walk cut short is a list cut short.
    print_warnings(&session.analysis().errors)?;
    let counts = counts.unwrap_or_else(build_counts);
    let rows = rows(session);
    let indices: Vec<usize> = survivors.unwrap_or_else(|| (0..rows.len()).collect());
    let listed: Vec<(&TaskRow, usize)> = indices
        .iter()
        .map(|&i| (&rows[i], counts_of(&counts, i).futures()))
        .collect();
    let groups = session.owner_column();
    print_task_table(
        &listed,
        groups,
        cmd.limit,
        session.fit_width(theme),
        theme,
        out,
    )?;
    print_warnings(&list.errors)?;
    Ok(())
}

/// `--group FIELD`: bucket the surviving rows by the field's spelled
/// value — `type` by the type itself ([`typenames::tally`]) — and print
/// `COUNT VALUE` rows, most numerous first (ties in value order), each
/// with up to three member ids. `--limit` cuts buckets.
#[allow(clippy::too_many_arguments)]
fn exec_group<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: &TasksCmd,
    field: Field,
    survivors: Option<Vec<usize>>,
    counts: Option<CountsByTask>,
    fit: Option<usize>,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    print_warnings(&session.analysis().errors)?;
    let rows = rows(session);
    let survivors = survivors.unwrap_or_else(|| (0..rows.len()).collect());
    let names = TypeNames::of(session);
    let mut buckets = typenames::tally(
        survivors.iter().map(|&index| {
            let row = &rows[index];
            let value = group_value(field, index, row, counts.as_ref())
                .unwrap_or_else(|| EMPTY_BUCKET.to_string());
            let ty = if field == Field::Type {
                row.future_ty
            } else {
                None
            };
            (names.bucket(ty, &value), index)
        }),
        |members: &mut Vec<usize>, index| members.push(index),
    );
    // Count descending; the tally already ordered ties by value, and
    // the sort is stable.
    buckets.sort_by_key(|(_, members)| std::cmp::Reverse(members.len()));
    let shown = cmd.limit.unwrap_or(buckets.len()).min(buckets.len());

    let heading = field.name().replace('-', " ").to_uppercase();
    let mut table = crate::output::Table::new(3)
        .align_right(0)
        .header(["COUNT".to_string(), heading, "TASKS".to_string()])
        .truncatable(1)
        .fit(fit)
        .theme(theme);
    for (value, members) in &buckets[..shown] {
        table.row([
            members.len().to_string(),
            value.clone(),
            member_sample(rows, members),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(buckets.len(), shown, "group"))?;
    print_warnings(&session.tasks.errors)?;
    Ok(())
}

/// `--exec COMMAND`: run the command once per surviving task, its
/// omitted target filled with that task, each run's output under a
/// `task N` heading — unless the command is `task` itself, whose
/// block opens with that line. One task's failure never stops the loop — the
/// failed run shows its error in place, the summary line counts them,
/// and the command fails after the loop when any run did, so a script
/// sees one failure with nothing skipped.
fn exec_exec<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: &TasksCmd,
    survivors: Option<Vec<usize>>,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Parse once up front: a command that does not parse is the
    // command line's mistake, not any task's, and fails before the
    // loop prints a heading.
    let parsed = repl::parse_exec_command(&cmd.exec, repl::EXEC_CHECK_ADDR).context("--exec")?;
    let headed = !matches!(parsed, crate::Command::Task { target: None, .. });
    print_warnings(&session.analysis().errors)?;
    let rows = rows(session);
    let survivors = survivors.unwrap_or_else(|| (0..rows.len()).collect());
    let shown = cmd.limit.unwrap_or(survivors.len()).min(survivors.len());
    let mut failed = 0usize;
    // Each run goes under a cursor scoped to its task — the command's
    // omitted target and `$_` are that task's — and the session's own
    // cursor comes back once the loop is done.
    let saved = *session.cursor.borrow();
    for (n, &index) in survivors[..shown].iter().enumerate() {
        let label = format!("task {}", rows[index].id);
        write!(out, "{}", exec_heading(n, headed.then_some(&label)))?;
        crate::cursor::scope_to(session, index);
        // Parsed under the scope, so its `$_` is the task's.
        let last = session.cursor.borrow().last_addr;
        let command = repl::parse_exec_command(&cmd.exec, last).expect("parsed above");
        // `quit` is not a per-task answer, so a Quit flow is ignored
        // and the loop runs on.
        if let Err(e) = crate::dispatch(session, command, theme, out) {
            failed += 1;
            writeln!(out, "error: {e:#}")?;
        }
    }
    *session.cursor.borrow_mut() = saved;
    writeln!(
        out,
        "[Executed against {}, {failed} failed]",
        summary::counted(shown, "task")
    )?;
    if failed > 0 {
        anyhow::bail!(
            "--exec failed against {failed} of {}",
            summary::counted(shown, "task")
        );
    }
    Ok(())
}

/// The heading `--exec` opens task `n`'s output with: a blank line
/// between one task's output and the next, then the task's name the
/// way `task` spells its own heading — or no name, when the command
/// is `task` and prints that line itself.
fn exec_heading(n: usize, label: Option<&str>) -> String {
    let sep = if n > 0 { "\n" } else { "" };
    match label {
        Some(label) => format!("{sep}{label}\n"),
        None => sep.to_string(),
    }
}

/// Gather what a census counts and print it.
///
/// Only what `sections` asks for is gathered, since what a census costs
/// is the gathering: the wait analysis the task section counts, the
/// future census the future section counts, and the target reads the
/// thread section makes. Both walks are the session's cached ones, so a
/// census pays for the ones it prints and every later command that
/// wants either pays for neither.
pub(crate) fn exec_census<T: proc::Target>(
    session: &Session<'_, T>,
    sections: summary::Sections,
    top: usize,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The future section counts the depth of every chain the task
    // section walks, so it wants the analysis too.
    let analysis = (sections.tasks || sections.futures).then(|| session.analysis());
    let census = sections.futures.then(|| session.census());
    print_warnings(
        analysis
            .iter()
            .flat_map(|analysis| &analysis.errors)
            .chain(census.iter().flat_map(|census| &census.errors)),
    )?;
    // As `children`: a walk that hit a depth limit looks like
    // completeness in a count, so it says so.
    if let Some(census) = census {
        warn_census_capped(census.capped, "counted")?;
        warn_census_uncertain(census.uncertain, "counted")?;
        warn_census_refused(census.refused, "counted")?;
    }

    let runtime = match sections.threads {
        true => runtime_threads(session)?,
        false => Vec::new(),
    };
    let runtimes = census_runtimes(session, sections.threads)?;
    let names = TypeNames::of(session);

    let facts = summary::Facts {
        lwps: session.lwps.iter().map(|lwp| lwp.tid).collect(),
        agent: session.proc.agent_lwp(),
        runtime,
        runtimes,
        local_sets: session.local_sets.len(),
        tasks: &session.tasks,
        waits: analysis.map(|analysis| &analysis.waits[..]).unwrap_or(&[]),
        held: census.map(|census| &census.held[..]).unwrap_or(&[]),
        sets: census.map(|census| &census.sets[..]).unwrap_or(&[]),
        names: &names,
    };
    summary::print(&facts, sections, top, session.fit_width(theme), theme, out)
}

/// Every discovered runtime with the readings that are its alone: what
/// its own workers' parkers say, and what its own blocking pool counts.
///
/// Both are read per runtime rather than once for the target. A worker
/// index addresses the parker array of the scheduler that numbered it
/// and no other, and a pool belongs to the runtime that launched it —
/// so one runtime's readings describe one runtime's threads.
fn census_runtimes<T: proc::Target>(
    session: &Session<'_, T>,
    states: bool,
) -> Result<Vec<summary::Runtime>> {
    let mut runtimes = Vec::new();
    for (index, rt) in session.runtimes.iter().enumerate() {
        // Naming a runtime reads nothing from the target, so every
        // section gets the names; only the thread section, which is the
        // one that reports them, pays for the states behind them.
        let (parks, pool) = match states {
            // The parker array is the multi_thread scheduler's; a
            // current_thread runtime has none. The blocking pool's chain
            // is spelled the same on both flavors' handles.
            true => (
                match rt.flavor {
                    bundle::RuntimeFlavor::MultiThread => {
                        optional(session.ctx.park_states(rt.handle), "park state")?
                    }
                    bundle::RuntimeFlavor::CurrentThread => None,
                },
                optional(session.ctx.blocking_pool(rt.handle), "blocking pool")?,
            ),
            false => (None, None),
        };
        runtimes.push(summary::Runtime {
            label: crate::runtimes::runtime_label(index, rt),
            parks,
            pool,
        });
    }
    Ok(runtimes)
}

/// The threads holding a tokio `Context`, each with the place it holds
/// in a scheduler's run loop and the task it is polling.
///
/// This is the read a census makes of its own: which worker — or which
/// runtime's `block_on` thread — each thread is. It is not worth
/// failing the command over — a census without it still counts
/// everything else — so a failure costs the thread its role and warns.
fn runtime_threads<T: proc::Target>(session: &Session<'_, T>) -> Result<Vec<summary::Thread>> {
    let mut runtime = Vec::new();
    for worker in &session.workers {
        let index = session.runtime_of(worker.tid).map(|(index, _)| index);
        // Only a thread no runtime claimed can lack a handle, so only
        // those are read for one.
        let has_handle = match index {
            Some(_) => true,
            None => session.ctx.has_runtime_handle(worker)?,
        };
        runtime.push(summary::Thread {
            tid: worker.tid,
            runtime: index,
            has_handle,
            role: thread_role(session, worker)?,
            polling: polled_task(worker.current_task_id, &session.tasks),
        });
    }
    Ok(runtime)
}

/// The task a thread's `Context` says it is polling, believed only when
/// the listing agrees: a task with that very id that the runtime still
/// calls running. A stale or corrupt word names a task that is idle,
/// complete, or not listed at all, and a summary column repeating it
/// would send a reader chasing a poll that is not happening.
pub(crate) fn polled_task(current_task_id: Option<u64>, list: &bundle::TaskList) -> Option<u64> {
    current_task_id.filter(|id| {
        list.tasks
            .iter()
            .any(|t| t.task_id == Some(*id) && t.state.lifecycle() == Lifecycle::Running)
    })
}

/// The run-loop role one thread holds, of either scheduler flavor, or
/// `None` for a thread that merely entered the runtime. A failed read
/// warns and costs only what it could not read: the worker its index,
/// the block_on thread its park state.
fn thread_role<T: proc::Target>(
    session: &Session<'_, T>,
    worker: &bundle::Worker,
) -> Result<Option<summary::ThreadRole>> {
    match session.ctx.worker_context(worker) {
        Ok(Some(ctx)) => match session.ctx.worker_index(ctx) {
            Ok(index) => return Ok(Some(summary::ThreadRole::Worker(index))),
            Err(e) => {
                writeln!(
                    io::stderr(),
                    "warning: cannot read which worker lwp {} runs: {e:#}",
                    worker.tid
                )?;
                return Ok(None);
            }
        },
        Ok(None) => {}
        Err(e) => {
            writeln!(
                io::stderr(),
                "warning: cannot read the scheduler context of lwp {}: {e:#}",
                worker.tid
            )?;
            return Ok(None);
        }
    }
    match session.ctx.ct_worker_context(worker) {
        Ok(Some(ct_ctx)) => {
            let state = match session.runtime_of(worker.tid) {
                Some((_, rt)) => {
                    match session
                        .ctx
                        .ct_park_state(rt.handle, ct_ctx, worker.current_task_id)
                    {
                        Ok(state) => Some(state),
                        Err(e) => {
                            writeln!(
                                io::stderr(),
                                "warning: cannot read the block_on state of lwp {}: {e:#}",
                                worker.tid
                            )?;
                            None
                        }
                    }
                }
                None => None,
            };
            Ok(Some(summary::ThreadRole::BlockOn(state)))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            writeln!(
                io::stderr(),
                "warning: cannot read the scheduler context of lwp {}: {e:#}",
                worker.tid
            )?;
            Ok(None)
        }
    }
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

/// A TLS reading as its line says it: the words, or why they did not
/// read.
pub(crate) fn tls_words(tls: &Result<bundle::TlsReading, String>) -> String {
    match tls {
        Ok(reading) => reading.to_string(),
        Err(e) => format!("unreadable ({e})"),
    }
}

#[cfg(test)]
mod table_tests {
    use super::{
        Detail, TypeNames, build_rows, listing_footer, member_line, print_task_table, wait_detail,
    };
    use crate::typenames::stop_label;

    use hansei_bundle::{BundleTypeId, SemanticIssueKind};
    use hansei_runtime::tokio::assess::{
        ContinuationStatus, IncompleteReason, NotWaitingReason, VerifiedWait, WaitAssessment,
        WaitUnknownReason,
    };
    use hansei_runtime::tokio::bundle::{
        FutureInfo, OwnerResolution, Task, TaskKind, TaskList, WaitTarget,
    };
    use hansei_runtime::tokio::graph::{TaskRef, TaskWait};
    use hansei_runtime::tokio::observe::ValueKey;
    use hansei_runtime::tokio::waitset::{MemberRoute, SlotRef, WaitMember, WaitSet};
    use hansei_runtime::tokio::{RawInstant, TaskAddr, TaskState};

    use std::collections::HashMap;

    const REF_ONE: u64 = 1 << 6;
    /// A block whose members print their `armed:` line, as one of a
    /// task that is not idle does — what the line tests here assert.
    const ARMED: Detail<'static> = Detail {
        containers: None,
        armed: true,
        frames: &[],
        caller_at: None,
        request_of: None,
    };
    const RUNNING: u64 = 0b0001;
    const NOTIFIED: u64 = 0b0100;
    const CANCELLED: u64 = 0b100_000;

    /// A branch of a stop frame, held in `local`, with the engine's
    /// verdict on it and — armed — its protocol's word for the waker.
    fn branch(local: &str, assessment: WaitAssessment, armed: bool) -> WaitMember {
        WaitMember {
            route: MemberRoute::Branch {
                local: local.to_string(),
                borrowed: false,
            },
            key: Some(ValueKey {
                addr: 0x6000,
                ty: crate::typenames::testing::named("x::branch"),
            }),
            future: Some(crate::typenames::testing::named("x::branch")),
            assessment: Some(assessment),
            notes: Vec::new(),
            armed: armed.then_some(SlotRef::Protocol),
            entries: None,
        }
    }

    /// Branch `index` of a `select!` its mask disabled: named, and
    /// nothing else.
    fn disabled(index: usize) -> WaitMember {
        WaitMember {
            route: MemberRoute::Disabled {
                index,
                ty: crate::typenames::testing::named("x::skipped"),
                arm: None,
            },
            key: None,
            future: Some(crate::typenames::testing::named("x::skipped")),
            assessment: None,
            notes: Vec::new(),
            armed: None,
            entries: None,
        }
    }

    /// Branch `index` of a `select!`, borrowed from the frame.
    fn select_branch(index: usize, assessment: WaitAssessment, armed: bool) -> WaitMember {
        WaitMember {
            route: MemberRoute::Select {
                index,
                borrowed: true,
                arm: None,
            },
            ..branch("", assessment, armed)
        }
    }

    /// Where a branch's arm is written is its `awaiting at:` line — a
    /// line of this task's code — above its verdict, under the
    /// heading of a branch that fans out, and as the second line of a
    /// disabled branch; a branch with none prints as before, and an
    /// entry never carries one.
    #[test]
    fn test_defined_at_follows_the_verdict_on_every_kind_of_branch() {
        let stops = crate::typenames::testing::type_names();
        let line = |member: &WaitMember| member_line(member, stops, &[], None, ARMED).join("\n");
        let arm = || Some(("qorb-0.4.1/src/pool.rs".to_string(), 286));
        let inspected = WaitMember {
            route: MemberRoute::Select {
                index: 0,
                borrowed: true,
                arm: arm(),
            },
            ..select_branch(
                0,
                WaitAssessment::Unknown(WaitUnknownReason::Continuation),
                false,
            )
        };
        assert_eq!(
            line(&inspected),
            "branch 0 (borrowed): x::branch\n    armed: no\n    awaiting at: qorb-0.4.1/src/pool.rs:286\n    awaiting on: unknown"
        );
        let fanning = WaitMember {
            route: MemberRoute::Select {
                index: 1,
                borrowed: false,
                arm: arm(),
            },
            assessment: None,
            entries: Some(hansei_runtime::tokio::waitset::Fanout {
                listed: 2,
                total: 5,
            }),
            ..branch("m", WaitAssessment::Unresumed, true)
        };
        assert_eq!(
            line(&fanning),
            "branch 1: x::branch\n    awaiting at: qorb-0.4.1/src/pool.rs:286\n    entries:"
        );
        let off = WaitMember {
            route: MemberRoute::Disabled {
                index: 2,
                ty: crate::typenames::testing::named("x::skipped"),
                arm: arm(),
            },
            ..disabled(2)
        };
        assert_eq!(
            line(&off),
            "branch 2: x::skipped: disabled\n    awaiting at: qorb-0.4.1/src/pool.rs:286"
        );
        assert_eq!(line(&disabled(2)), "branch 2: x::skipped: disabled");
        let entry = WaitMember {
            route: MemberRoute::Entry {
                index: 0,
                key: None,
                under: Some(Box::new(MemberRoute::Select {
                    index: 1,
                    borrowed: false,
                    arm: arm(),
                })),
                borrowed: false,
                stream: BundleTypeId(0),
            },
            ..select_branch(
                0,
                WaitAssessment::Unknown(WaitUnknownReason::Continuation),
                false,
            )
        };
        assert!(!line(&entry).contains("defined at"), "{}", line(&entry));
    }

    /// A member prints where its type's `poll` is written as `type
    /// defined at:`, after the verdict and before the slots, under the
    /// heading of a member that fans out, and as the last line of a
    /// disabled branch. An entry prints its stream's. A branch with an
    /// arm prints both: the arm is a line of this task's code, the
    /// type's line is where the thing on the heading is written, and
    /// the two labels name different things; a type the bundle
    /// recorded no declaration for prints nothing.
    /// A bundle laid out by hand with every kind of source line a
    /// listing reads: a hand-written future's `poll` (`x::branch`, type
    /// 0), a coroutine's own `async fn` (`x::run`, type 2) and the
    /// `let` of that coroutine's frame-resident local `tasks`.
    fn sited_bundle() -> hansei_bundle::Bundle {
        use hansei_bundle::{
            Bundle, FORMAT_VERSION, InfraTypes, Meta, SourceLoc, StringInterner, TypeDef, TypeTable,
        };

        let mut strings = StringInterner::new();
        let n_branch = strings.intern("x::branch");
        let n_plain = strings.intern("x::plain");
        let n_coro = strings.intern("x::run::{async_fn_env#0}");
        let n_file = strings.intern("hyper-1.10.1/src/proto/h1/dispatch.rs");
        let n_src = strings.intern("src/run.rs");
        let n_tasks = strings.intern("tasks");
        let strings = strings.finish();
        let ty = BundleTypeId(0);
        let mut bundle = Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings,
            types: TypeTable {
                types: vec![
                    TypeDef::Struct {
                        name: n_branch,
                        size: 8,
                        members: vec![],
                    },
                    TypeDef::Struct {
                        name: n_plain,
                        size: 8,
                        members: vec![],
                    },
                    TypeDef::Struct {
                        name: n_coro,
                        size: 8,
                        members: vec![],
                    },
                ],
                poll_decls: [(
                    ty,
                    SourceLoc {
                        file: n_file,
                        line: 512,
                    },
                )]
                .into_iter()
                .collect(),
                // A coroutine has no `poll` of its own: its line is the
                // `async fn` it is the body of.
                env_decls: [(
                    BundleTypeId(2),
                    SourceLoc {
                        file: n_src,
                        line: 33,
                    },
                )]
                .into_iter()
                .collect(),
                // The coroutine holds `tasks` across an await, declared
                // two lines into its body.
                local_decls: [(
                    BundleTypeId(2),
                    vec![(
                        n_tasks,
                        SourceLoc {
                            file: n_src,
                            line: 35,
                        },
                    )],
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            tasks: Default::default(),
            dyn_futures: Default::default(),
            statics: Default::default(),
            walks: Default::default(),
            infra: InfraTypes {
                header: ty,
                vtable: ty,
                trailer: ty,
                context: ty,
                scheduler_handle: ty,
                mt_handle: ty,
                ct_handle: ty,
                location: ty,
                raw_waker_vtable: ty,
            },
            provenance: Default::default(),
            impls: Default::default(),
            semantics: Default::default(),
        };
        // The coroutine's kind, as extraction records it.
        hansei_runtime::testkit::coroutine_kinds(
            &mut bundle,
            &[(
                BundleTypeId(2),
                hansei_bundle::SemanticRuleKind::RustcAsyncFn,
            )],
        );
        bundle
    }

    #[test]
    fn test_a_member_with_no_arm_prints_where_its_type_is_written() {
        use hansei_bundle::BundleView;
        use hansei_runtime::tokio::attribution::{
            AttributedSlot, Attribution, OwnerKind, SlotPath, SlotRoot, Validity,
        };
        use hansei_runtime::tokio::wakers::Owner;

        let bundle = sited_bundle();
        let impls = Default::default();
        let stops = TypeNames::over(BundleView::new(&bundle), &impls);
        let site = "    type defined at: hyper-1.10.1/src/proto/h1/dispatch.rs:512";
        let arm = || Some(("src/bin/armed-select.rs".to_string(), 50));

        // The line sits between the verdict and the slot's location.
        let slot = AttributedSlot {
            hit: 0,
            slot: 0x6010,
            owner: Owner::Task {
                header: 0x1100,
                index: 0,
            },
            attribution: Attribution::Owner {
                kind: OwnerKind::Mpsc,
                primitive: 0x9000,
                holder: "Chan".to_string(),
                member: "rx_waker".to_string(),
                path: SlotPath {
                    root: SlotRoot::Find {
                        index: 0,
                        addr: 0x6000,
                        frame: 0,
                    },
                    steps: vec!["rx_waker".to_string()],
                    hop: None,
                },
                validity: Validity::SelfDescribing,
                reading: None,
            },
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
        };
        let held = branch(
            "inner",
            WaitAssessment::Unknown(WaitUnknownReason::Continuation),
            false,
        );
        assert_eq!(
            member_line(&held, &stops, &[&slot], None, ARMED),
            vec![
                "inner: x::branch",
                "    armed: yes",
                "    awaiting on: mpsc rx 0x9000",
                site,
            ]
        );

        let line = |member: &WaitMember| member_line(member, &stops, &[], None, ARMED).join("\n");
        // A `select!` branch with an arm prints both lines; one without
        // prints its type's alone.
        let armed = WaitMember {
            route: MemberRoute::Select {
                index: 0,
                borrowed: true,
                arm: arm(),
            },
            ..select_branch(0, WaitAssessment::Unresumed, false)
        };
        assert_eq!(
            line(&armed),
            "branch 0 (borrowed): x::branch\n    armed: no\n    awaiting at: src/bin/armed-select.rs:50\n    awaiting on: never polled\n    type defined at: hyper-1.10.1/src/proto/h1/dispatch.rs:512"
        );
        let unarmed = WaitMember {
            route: MemberRoute::Select {
                index: 0,
                borrowed: true,
                arm: None,
            },
            ..select_branch(0, WaitAssessment::Unresumed, false)
        };
        assert_eq!(
            line(&unarmed),
            format!(
                "branch 0 (borrowed): x::branch\n    armed: no\n    awaiting on: never polled\n{site}"
            )
        );
        // One that fans out, and a disabled branch.
        let fanning = WaitMember {
            assessment: None,
            entries: Some(hansei_runtime::tokio::waitset::Fanout {
                listed: 2,
                total: 5,
            }),
            ..branch("m", WaitAssessment::Unresumed, true)
        };
        assert_eq!(
            line(&fanning),
            format!("m: x::branch\n{site}\n    entries:")
        );
        let off = WaitMember {
            route: MemberRoute::Disabled {
                index: 2,
                ty: BundleTypeId(0),
                arm: None,
            },
            future: Some(BundleTypeId(0)),
            ..disabled(2)
        };
        assert_eq!(line(&off), format!("branch 2: x::branch: disabled\n{site}"));
        // An entry: its key on the heading, its stream's line below,
        // whatever the member past the stream's adapters is; a stream
        // with no line leaves it to that member.
        let entry = |stream: u32, member: u32| WaitMember {
            route: MemberRoute::Entry {
                index: 0,
                key: Some("\"alpha\"".to_string()),
                under: None,
                borrowed: false,
                stream: BundleTypeId(stream),
            },
            key: Some(ValueKey {
                addr: 0x6000,
                ty: BundleTypeId(member),
            }),
            ..branch("", WaitAssessment::Unresumed, false)
        };
        for (stream, member) in [(0, 1), (1, 0)] {
            assert_eq!(
                line(&entry(stream, member)),
                format!("\"alpha\":\n    armed: no\n    awaiting on: never polled\n{site}"),
                "stream {stream}, member {member}"
            );
        }
        assert!(!line(&entry(1, 1)).contains("type defined at"));
        // A type with no declaration recorded.
        let plain = WaitMember {
            key: Some(ValueKey {
                addr: 0x6000,
                ty: BundleTypeId(1),
            }),
            ..branch("inner", WaitAssessment::Unresumed, false)
        };
        assert_eq!(
            line(&plain),
            "inner: x::plain\n    armed: no\n    awaiting on: never polled"
        );
        // A coroutine's line is its own `async fn`'s.
        let coro = WaitMember {
            key: Some(ValueKey {
                addr: 0x6000,
                ty: BundleTypeId(2),
            }),
            ..branch("inner", WaitAssessment::Unresumed, false)
        };
        assert_eq!(
            line(&coro),
            "inner: async fn x::run\n    armed: no\n    awaiting on: never polled\n    type defined at: src/run.rs:33"
        );
    }

    fn one_of(members: Vec<WaitMember>) -> WaitAssessment {
        WaitAssessment::Set(WaitSet {
            at: Some(ValueKey {
                addr: 0x5000,
                ty: crate::typenames::testing::NAMELESS,
            }),
            reason: Some(SemanticIssueKind::NoRule),
            members,
            capped: 0,
        })
    }

    fn task(id: u64, state: u64) -> Task {
        Task {
            addr: TaskAddr(0x1000 + id * 0x100),
            state: TaskState(REF_ONE | state),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
        }
    }

    /// A blocking-pool task: no future, no wait.
    fn blocking(id: u64, state: u64) -> Task {
        Task {
            kind: TaskKind::Blocking,
            ..task(id, state)
        }
    }

    /// A task with an explicit assessment.
    fn assessed(id: u64, assessment: WaitAssessment) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000 + id * 0x100),
                task_id: Some(id),
            },
            assessment,
            continuation: ContinuationStatus::Incomplete {
                reason: IncompleteReason::NoRoot,
                detail: None,
            },
            depth: 1,
            site: None,
            observation: None,
            notes: Vec::new(),
            held: Vec::new(),
            held_capped: 0,
            frames: Vec::new(),
            frame_sites: Vec::new(),
        }
    }

    /// A task assessed as verified-waiting on `target`, or — with no
    /// target — with its continuation unknown.
    fn wait(id: u64, target: Option<WaitTarget>) -> TaskWait {
        assessed(
            id,
            match target {
                Some(target) => WaitAssessment::Waiting(VerifiedWait::testkit(target, None)),
                None => WaitAssessment::Unknown(WaitUnknownReason::Continuation),
            },
        )
    }

    fn rows_of(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        polling: HashMap<u64, u32>,
    ) -> Vec<super::TaskRow> {
        let list = TaskList::new(tasks);
        build_rows(
            &list,
            &Default::default(),
            &waits,
            &polling,
            &Default::default(),
            crate::typenames::testing::type_names(),
        )
    }

    /// A member that fans out arms nothing itself and closes its block
    /// with an `entries:` heading, no verdict or slot text; its entries
    /// follow under that heading, each headed by its key — its index
    /// where no key was read — and the count the cap left uninspected
    /// closes the run. The entries of a stop that is the map itself
    /// sit under an `entries:` heading of their own at the top.
    #[test]
    fn test_a_fan_out_member_lists_its_count_and_nests_its_entries() {
        let entry = |index: usize, key: Option<&str>, under: Option<MemberRoute>| WaitMember {
            route: MemberRoute::Entry {
                index,
                key: key.map(str::to_string),
                under: under.map(Box::new),
                borrowed: false,
                stream: BundleTypeId(0),
            },
            ..branch(
                "e",
                WaitAssessment::Unknown(WaitUnknownReason::Continuation),
                false,
            )
        };
        let fanning = |listed: usize, total: usize| WaitMember {
            route: MemberRoute::Select {
                index: 1,
                borrowed: true,
                arm: None,
            },
            assessment: None,
            entries: Some(hansei_runtime::tokio::waitset::Fanout { listed, total }),
            ..branch("m", WaitAssessment::Unresumed, true)
        };
        let stops = crate::typenames::testing::type_names();
        // A fan-out member arms nothing, so its block is the one line.
        let line = |member: &WaitMember| member_line(member, stops, &[], None, ARMED).join("\n");
        for (listed, total) in [(3, 3), (8, 12), (1, 1), (0, 0)] {
            assert_eq!(
                line(&fanning(listed, total)),
                "branch 1 (borrowed): x::branch\n    entries:"
            );
        }
        let under = MemberRoute::Select {
            index: 1,
            borrowed: true,
            arm: None,
        };
        let wait = assessed(
            1,
            one_of(vec![
                fanning(2, 5),
                entry(0, Some("\"key-a\""), Some(under.clone())),
                entry(1, None, Some(under)),
                entry(0, Some("7"), None),
            ]),
        );
        let lines = wait_detail(&wait, stops, &[], None, &|_| None, ARMED).awaiting;
        // The `select!` branch and the entries reached through it sit
        // under the heading, the entries two steps under the branch and
        // the uninspected count after them; the entry of the stop
        // itself sits under a heading at the top.
        assert_eq!(
            lines,
            [
                "select!:",
                "    branch 1 (borrowed): x::branch",
                "        entries:",
                "            \"key-a\":",
                "                armed: no",
                "                awaiting on: unknown",
                "            entry 1:",
                "                armed: no",
                "                awaiting on: unknown",
                "            3 more entries not inspected",
                "entries:",
                "    7:",
                "        armed: no",
                "        awaiting on: unknown",
            ]
        );
    }

    /// What a branch is blocked on has two routes to it, and the
    /// branch takes whichever answers. Where the chain route stopped
    /// short — a hand-written future it cannot follow through — a slot
    /// of this task's names the primitive it is parked in, and that is
    /// the line; where the chain route answered, its word stands and
    /// the slot is a line of its own. A slot lifted onto the line
    /// keeps its `location:`, and one named there is not named twice:
    /// its own line carries only its detail.
    #[test]
    fn test_a_branch_the_chain_cannot_name_is_named_by_its_slot() {
        use hansei_runtime::tokio::attribution::{
            AttributedSlot, Attribution, OwnerKind, RegistrySlot, SlotPath, SlotRoot, Validity,
        };
        use hansei_runtime::tokio::bundle::IoSlot;
        use hansei_runtime::tokio::wakers::Owner;

        let stops = crate::typenames::testing::type_names();
        let owner = Owner::Task {
            header: 0x1100,
            index: 0,
        };
        let slot = |at: u64, attribution: Attribution| AttributedSlot {
            hit: 0,
            slot: at,
            owner,
            attribution,
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
        };
        let channel = slot(
            0x6010,
            Attribution::Owner {
                kind: OwnerKind::Mpsc,
                primitive: 0x9000,
                holder: "Chan".to_string(),
                member: "rx_waker".to_string(),
                path: SlotPath {
                    root: SlotRoot::Find {
                        index: 0,
                        addr: 0x6000,
                        frame: 0,
                    },
                    steps: vec!["rx_waker".to_string()],
                    hop: None,
                },
                validity: Validity::SelfDescribing,
                reading: None,
            },
        );
        let reader = slot(
            0x6020,
            Attribution::Registry(RegistrySlot::Io {
                resource: 0xaa00,
                slot: IoSlot::Reader,
                ready: None,
            }),
        );
        let cannot_name = branch(
            "inner",
            WaitAssessment::Unknown(WaitUnknownReason::Continuation),
            false,
        );
        // The slot names the primitive the chain route never reached,
        // and still says where the waker sits.
        assert_eq!(
            member_line(&cannot_name, stops, &[&channel], None, ARMED),
            [
                "inner: x::branch",
                "    armed: yes",
                "    awaiting on: mpsc rx 0x9000",
            ]
        );
        // A registry slot answers the same way, and having been named
        // on the line above it adds only its detail below.
        assert_eq!(
            member_line(&cannot_name, stops, &[&reader], None, ARMED),
            [
                "inner: x::branch",
                "    armed: yes",
                "    awaiting on: io 0xaa00 read",
                "    waker: the read-waiter slot, awaiting readable",
            ]
        );
        // Both, one line each, sorted.
        assert_eq!(
            member_line(&cannot_name, stops, &[&channel, &reader], None, ARMED)
                .iter()
                .filter(|line| line.starts_with("    awaiting on: "))
                .collect::<Vec<_>>(),
            [
                "    awaiting on: io 0xaa00 read",
                "    awaiting on: mpsc rx 0x9000"
            ]
        );
        // With no slot to ask, the chain route's own word stands.
        assert_eq!(
            member_line(&cannot_name, stops, &[], None, ARMED)
                .last()
                .unwrap(),
            "    awaiting on: unknown"
        );
        // A chain route that answered is not second-guessed: its
        // target is the line, and the slot beside it is its own.
        let named = branch(
            "inner",
            WaitAssessment::Waiting(VerifiedWait::testkit(
                WaitTarget::Io {
                    addr: 0xbb00,
                    fd: None,
                    interest: None,
                    handshake: false,
                    tls: None,
                },
                None,
            )),
            false,
        );
        assert_eq!(
            member_line(&named, stops, &[&channel], None, ARMED),
            [
                "inner: x::branch",
                "    armed: yes",
                "    awaiting on: io 0xbb00 (readiness)",
                "    waker: mpsc rx 0x9000",
            ]
        );
        // A registry slot beside an answered chain route keeps its own
        // name the same way, since nothing above it carries one: the
        // line is the slot whole, not the detail a lifted slot is
        // left with.
        assert_eq!(
            member_line(&named, stops, &[&reader], None, ARMED),
            [
                "inner: x::branch",
                "    armed: yes",
                "    awaiting on: io 0xbb00 (readiness)",
                "    waker: io 0xaa00 read: the read-waiter slot, awaiting readable",
            ]
        );
        // An owner slot with a reading beside an answered chain route
        // is the slot whole too, its reading and all; beside a branch
        // whose verdict names no resource — never polled — the line
        // is the entry, the reading left to a line that has room for
        // it.
        let read = slot(
            0x6010,
            Attribution::Owner {
                kind: OwnerKind::Mpsc,
                primitive: 0x9000,
                holder: "Chan".to_string(),
                member: "rx_waker".to_string(),
                path: SlotPath {
                    root: SlotRoot::Find {
                        index: 0,
                        addr: 0x6000,
                        frame: 0,
                    },
                    steps: vec!["rx_waker".to_string()],
                    hop: None,
                },
                validity: Validity::SelfDescribing,
                reading: Some(hansei_runtime::tokio::attribution::Reading::Mpsc {
                    senders: 1,
                    capacity: Some(4),
                    unread: 0,
                }),
            },
        );
        assert_eq!(
            member_line(&named, stops, &[&read], None, ARMED)
                .last()
                .unwrap(),
            "    waker: mpsc rx 0x9000 (1 sender, capacity 4, 0 unread)"
        );
        let unpolled = branch("inner", WaitAssessment::Unresumed, false);
        assert_eq!(
            member_line(&unpolled, stops, &[&read], None, ARMED),
            [
                "inner: x::branch",
                "    armed: yes",
                "    awaiting on: never polled",
                "    waker: mpsc rx 0x9000",
            ]
        );
    }

    /// An unknown says what made it one, in the cell and in its bucket
    /// alike — the stop type where the chain stopped at one (bare
    /// `unknown` where no bundle names it), how a chain was cut short,
    /// or the reason where the chain reached a primitive its protocol
    /// could not vouch for. A stop label is the type's path, generics
    /// dropped, with a coroutine's kind word in front.
    #[test]
    fn test_unknown_buckets_say_what_made_them_unknown() {
        let mut stopped = wait(1, None);
        stopped.continuation = ContinuationStatus::Unknown {
            at: ValueKey {
                addr: 0x5000,
                ty: crate::typenames::testing::NAMELESS,
            },
            reason: SemanticIssueKind::NoRule,
        };
        let mut cut = wait(2, None);
        cut.continuation = ContinuationStatus::Incomplete {
            reason: IncompleteReason::AmbiguousDyn,
            detail: None,
        };
        let unproven = assessed(
            3,
            WaitAssessment::Unknown(WaitUnknownReason::ResourceStateUnproven),
        );
        let rows = rows_of(
            vec![task(1, 0), task(2, 0), task(3, 0)],
            vec![stopped, cut, unproven],
            HashMap::new(),
        );
        assert_eq!(rows[0].waiting_on, "unknown");
        assert_eq!(rows[1].waiting_on, "unknown (ambiguous dyn future)");
        assert_eq!(rows[2].waiting_on, "unknown (resource state unproven)");
        // The bucket is the cell: an unknown has no target to fold to a kind.
        for row in &rows {
            assert_eq!(row.waiting_kind.as_deref(), Some(row.waiting_on.as_str()));
        }

        let impls = hansei_bundle::names::ImplFold::default();
        let mut bundle = hansei_runtime::testkit::named_types(&[
            "futures_util::future::map::Map<hyper::client::conn::Connection<A, B>, \
             hyper_util::client::legacy::{closure_env#3}>",
            "app::serve::{async_fn_env#0}",
            "core::future::poll_fn::PollFn<app::run::{async_fn_env#0}::{closure_env#1}>",
        ]);
        hansei_runtime::testkit::coroutine_kinds(
            &mut bundle,
            &[(
                BundleTypeId(1),
                hansei_bundle::SemanticRuleKind::RustcAsyncFn,
            )],
        );
        let view = hansei_bundle::BundleView::new(&bundle);
        let label = |id| stop_label(view.ty(BundleTypeId(id)).unwrap(), &impls);
        assert_eq!(label(0), "futures_util::future::map::Map");
        assert_eq!(label(1), "async fn app::serve");
        assert_eq!(label(2), "core::future::poll_fn::PollFn");
    }

    /// A wait set's cell is its armed members, sorted and comma-joined — the
    /// verified target where a member's protocol produced one, the
    /// slot's own entry where it did not — and its bucket the
    /// distinct kinds; an unarmed branch is in neither, only in the
    /// detail. A stop whose branches are all unarmed stays `unknown`
    /// with their count in the cell and out of the bucket.
    #[test]
    fn test_a_wait_set_lists_its_armed_members() {
        let timer = WaitTarget::Timer {
            deadline: RawInstant {
                tv_sec: 12,
                tv_nsec: 0,
            },
            stopped: Some(RawInstant {
                tv_sec: 2,
                tv_nsec: 0,
            }),
        };
        let verified = WaitAssessment::Waiting(VerifiedWait::testkit(timer, None));
        let unknown = || WaitAssessment::Unknown(WaitUnknownReason::Continuation);
        let slot = WaitMember {
            route: MemberRoute::SlotOnly {
                within: Some("inside #1's storage at +0x10".to_string()),
            },
            key: None,
            future: None,
            assessment: None,
            notes: Vec::new(),
            armed: Some(SlotRef::Io {
                resource: 0x7000,
                slot: hansei_runtime::tokio::bundle::IoSlot::Reader,
                fd: None,
                ready: None,
            }),
            entries: None,
        };
        let mut set = one_of(vec![
            branch("a", verified, true),
            branch("b", unknown(), false),
            slot,
        ]);
        if let WaitAssessment::Set(set) = &mut set {
            set.capped = 1;
        }
        let set = assessed(1, set);
        let mut held = wait(2, None);
        held.continuation = ContinuationStatus::Unknown {
            at: ValueKey {
                addr: 0x5000,
                ty: crate::typenames::testing::NAMELESS,
            },
            reason: SemanticIssueKind::NoRule,
        };
        held.held = vec![branch("a", unknown(), false), branch("b", unknown(), false)];
        held.held_capped = 1;
        let rows = rows_of(
            vec![task(1, 0), task(2, 0)],
            vec![set, held],
            HashMap::new(),
        );
        assert_eq!(rows[0].waiting_on, "io, timer");
        // With no swept slot the members' entries are the cell's, but
        // the lines do not carry it whole: the label keeps the cell.
        assert_eq!(rows[0].wait_line.as_deref(), Some("io, timer"));
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("io, timer"));
        assert_eq!(
            rows[0].wait_detail,
            [
                "a: x::branch",
                "    awaiting on: timer (deadline +10.000s)",
                "    waker: the resource, read by its protocol",
                "b: x::branch",
                "    awaiting on: unknown",
                "io 0x7000 (readable): the read-waiter slot, inside #1's storage at +0x10; \
                 in no branch of the stop",
                "1 more branches not inspected",
            ]
        );
        assert_eq!(rows[1].waiting_on, "unknown (holds 3 futures)");
        assert_eq!(rows[1].waiting_kind.as_deref(), Some("unknown"));
        assert_eq!(
            rows[1].wait_detail,
            [
                "a: x::branch",
                "    awaiting on: unknown",
                "b: x::branch",
                "    awaiting on: unknown",
                "1 more branches not inspected",
            ]
        );
    }

    /// A never-ready verdict at a `select!` stop lists the branches it
    /// was rolled up from, each with the verdict and the armed half a
    /// held branch prints, and counts the ones past the cap; the cell
    /// and the bucket are the verdict alone.
    #[test]
    fn test_a_never_ready_stop_lists_its_branches() {
        let never_ready = |members, capped| WaitAssessment::NeverReady { members, capped };
        let rolled = assessed(
            1,
            never_ready(
                vec![
                    branch("a", never_ready(Vec::new(), 0), false),
                    branch("b", never_ready(Vec::new(), 0), false),
                ],
                1,
            ),
        );
        let rows = rows_of(vec![task(1, 0)], vec![rolled], HashMap::new());
        assert_eq!(rows[0].waiting_on, "never ready");
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("never ready"));
        assert_eq!(
            rows[0].wait_detail,
            [
                "a: x::branch",
                "    awaiting on: never ready",
                "b: x::branch",
                "    awaiting on: never ready",
                "1 more branches not inspected",
            ]
        );
    }

    /// A `select!`'s branches print by number, and a disabled one by
    /// its type and the word `disabled`: it is neither held nor armed,
    /// so the cell counts the live branches alone and a stop whose
    /// every branch is disabled reads as the bare unknown.
    #[test]
    fn test_select_branches_print_by_number_and_disabled_ones_by_name() {
        let unknown = || WaitAssessment::Unknown(WaitUnknownReason::Continuation);
        let verified = WaitAssessment::Waiting(VerifiedWait::testkit(
            WaitTarget::Timer {
                deadline: RawInstant {
                    tv_sec: 10,
                    tv_nsec: 0,
                },
                stopped: Some(RawInstant {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            },
            None,
        ));
        let set = assessed(
            1,
            one_of(vec![
                select_branch(0, unknown(), false),
                select_branch(1, verified, true),
                disabled(2),
            ]),
        );
        let mut held = wait(2, None);
        held.continuation = ContinuationStatus::Unknown {
            at: ValueKey {
                addr: 0x5000,
                ty: crate::typenames::testing::NAMELESS,
            },
            reason: SemanticIssueKind::NoRule,
        };
        held.held = vec![select_branch(0, unknown(), false), disabled(1)];
        let mut all_disabled = wait(3, None);
        all_disabled.continuation = held.continuation.clone();
        all_disabled.held = vec![disabled(0), disabled(1)];
        let rows = rows_of(
            vec![task(1, 0), task(2, 0), task(3, 0)],
            vec![set, held, all_disabled],
            HashMap::new(),
        );
        assert_eq!(rows[0].waiting_on, "timer");
        // Every branch sits under one `select!:` heading, the
        // disabled ones included: the word says what they are
        // branches of.
        assert_eq!(
            rows[0].wait_detail,
            [
                "select!:",
                "    branch 0 (borrowed): x::branch",
                "        awaiting on: unknown",
                "    branch 1 (borrowed): x::branch",
                "        awaiting on: timer (deadline +10.000s)",
                "        waker: the resource, read by its protocol",
                "    branch 2: x::skipped: disabled",
            ]
        );
        assert_eq!(rows[1].waiting_on, "unknown (holds 1 future)");
        assert_eq!(
            rows[1].wait_detail,
            [
                "select!:",
                "    branch 0 (borrowed): x::branch",
                "        awaiting on: unknown",
                "    branch 1: x::skipped: disabled",
            ]
        );
        assert_eq!(rows[2].waiting_on, "unknown");
        assert_eq!(
            rows[2].wait_detail,
            [
                "select!:",
                "    branch 0: x::skipped: disabled",
                "    branch 1: x::skipped: disabled"
            ]
        );
    }

    /// Each cell says what its column promises: the site as
    /// `file:line`, the wait as `graph` spells it, `unknown` where the
    /// continuation is not established, `—` where there is nothing to
    /// say, and the cancel bit appended to whatever lifecycle carries
    /// it.
    #[test]
    fn test_rows_spell_site_wait_and_cancellation() {
        let timer = WaitTarget::Timer {
            deadline: RawInstant {
                tv_sec: 12,
                tv_nsec: 0,
            },
            stopped: None,
        };
        let mut sited = wait(1, Some(timer));
        sited.site = Some(("src/app.rs".to_string(), 42));
        let unknown = wait(2, None);
        let bare = assessed(3, WaitAssessment::NotWaiting(NotWaitingReason::Complete));

        let rows = rows_of(
            vec![task(1, 0), task(2, CANCELLED), task(3, 0)],
            vec![sited, unknown, bare],
            HashMap::new(),
        );

        assert_eq!(rows[0].awaiting_at.as_deref(), Some("src/app.rs:42"));
        assert_eq!(rows[0].waiting_on, "timer");
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("timer"));
        assert_eq!(rows[0].state, "idle");

        assert_eq!(rows[1].state, "idle (cancelled)");
        assert_eq!(rows[1].waiting_on, "unknown (no root in the tokio info)");
        assert_eq!(
            rows[1].waiting_kind.as_deref(),
            Some(rows[1].waiting_on.as_str())
        );
        assert_eq!(rows[1].awaiting_at, None);
        // An unknown stop is named by the cell; the block adds nothing.
        assert!(rows[1].wait_detail.is_empty());

        assert_eq!(rows[2].waiting_on, "—");
        assert_eq!(rows[2].waiting_kind, None);

        // The columns only the filters read: nothing recorded is
        // nothing to match, and a Known future's decl is the
        // `defined` value and its type what `--group type` buckets.
        assert_eq!(rows[0].spawned, None);
        assert_eq!(rows[0].defined, None);
        assert_eq!(rows[0].future_ty, None);
        let known = rows_of(
            vec![Task {
                future: FutureInfo::Known(hansei_runtime::tokio::bundle::KnownFuture {
                    entry: hansei_bundle::TaskEntryId(0),
                    future: crate::typenames::testing::named("app::work::{async_fn_env#0}"),
                    kind: hansei_bundle::FutureKind::AsyncFn,
                    decl: Some(("src/app.rs".to_string(), 7)),
                    symbol: String::new(),
                }),
                ..task(9, 0)
            }],
            vec![wait(9, None)],
            HashMap::new(),
        );
        assert_eq!(known[0].defined.as_deref(), Some("src/app.rs:7"));
        assert_eq!(
            known[0].future_ty,
            Some(crate::typenames::testing::named(
                "app::work::{async_fn_env#0}"
            ))
        );
    }

    /// A ready resource's row says `ready` in the cell and, in its
    /// detail, what the resource has already done — the assessor's
    /// words for the reason, not a bare label.
    #[test]
    fn test_a_ready_row_says_what_was_delivered() {
        use hansei_runtime::tokio::assess::ReadyReason;

        let ready = assessed(1, WaitAssessment::ResourceReady(ReadyReason::JoinComplete));
        let rows = rows_of(vec![task(1, 0)], vec![ready], HashMap::new());
        assert_eq!(rows[0].waiting_on, "ready");
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("ready"));
        assert_eq!(
            rows[0].wait_detail,
            ["ready: the joined task is complete; its output awaits the next poll"]
        );
    }

    /// A blocking cell's STATE spells where it is in the pool — queued,
    /// running, or plain `blocking` where the stacks name the lwp
    /// running it, which the row's thread then carries — its wait
    /// column stays empty, and the cancel bit rides whichever spelling.
    #[test]
    fn test_blocking_rows_spell_queue_and_thread() {
        let blocking = |id: u64, state: u64| Task {
            kind: TaskKind::Blocking,
            ..task(id, state)
        };
        let rows = rows_of(
            vec![blocking(1, 0), blocking(2, RUNNING), blocking(3, CANCELLED)],
            vec![wait(1, None), wait(2, None), wait(3, None)],
            HashMap::new(),
        );
        assert_eq!(rows[0].state, "blocking (queued)");
        assert_eq!(rows[1].state, "blocking (running)");
        assert_eq!(rows[2].state, "blocking (queued) (cancelled)");
        assert_eq!(rows[0].waiting_on, "—");
        assert_eq!(rows[0].waiting_kind, None);

        // The stacks named the lwp running it.
        let with_lwp = build_rows(
            &TaskList::new(vec![blocking(2, RUNNING)]),
            &Default::default(),
            &[],
            &HashMap::new(),
            &HashMap::from([(0x1000 + 2 * 0x100, 42)]),
            crate::typenames::testing::type_names(),
        );
        assert_eq!(with_lwp[0].state, "blocking");
        assert_eq!(with_lwp[0].lwp, Some(42));

        // The block form agrees, complete stays plain.
        let polling = HashMap::new();
        assert_eq!(
            super::task_state(&blocking(1, 0), &polling, &HashMap::new()),
            "blocking (queued)"
        );
        assert_eq!(
            super::task_state(
                &blocking(2, RUNNING),
                &polling,
                &HashMap::from([(0x1000 + 2 * 0x100, 7)])
            ),
            "blocking"
        );
        const COMPLETE: u64 = 0b010;
        assert_eq!(
            super::task_state(&blocking(4, COMPLETE), &polling, &HashMap::new()),
            "complete"
        );
    }

    /// The merge rewrites the wait cell from the task's slots: every
    /// slot spelled by what holds it, sorted and joined, the buckets
    /// their kinds, `unknown` slots past the first collapsed to a
    /// count; a task with no slot keeps its assessment's word under
    /// `unarmed: `; a mid-poll task is untouched. The detail gains one
    /// line per slot, sorted by label.
    #[test]
    fn test_the_merge_spells_each_slot_and_marks_the_unarmed() {
        use hansei_runtime::tokio::attribution::{
            Attributed, AttributedSlot, Attribution, RegistrySlot,
        };
        use hansei_runtime::tokio::bundle::IoSlot;
        use hansei_runtime::tokio::wakers::Owner;

        let t1 = 0x1000 + 0x100;
        let owner = Owner::Task {
            header: t1,
            index: 0,
        };
        let slot = |at: u64, attribution: Attribution| AttributedSlot {
            hit: at as usize,
            slot: at,
            owner,
            attribution,
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
        };
        let slots = Attributed::from_slots(vec![
            slot(
                0xdd00,
                Attribution::Registry(RegistrySlot::Timer {
                    entry: 0xdd00,
                    state: None,
                    deadline: None,
                }),
            ),
            slot(
                0xaa08,
                Attribution::Registry(RegistrySlot::Io {
                    resource: 0xaa00,
                    slot: IoSlot::Reader,
                    ready: None,
                }),
            ),
            slot(
                0xe100,
                Attribution::Registry(RegistrySlot::Semaphore {
                    semaphore: 0x9000,
                    node: 0xe100,
                }),
            ),
            slot(
                0x1250,
                Attribution::Registry(RegistrySlot::Join {
                    task: TaskRef {
                        addr: TaskAddr(0x1000 + 2 * 0x100),
                        task_id: Some(2),
                    },
                }),
            ),
            slot(0x7000, Attribution::Unknown),
            slot(0x8000, Attribution::Unknown),
            // Task 4's one unknown slot, and a blocking task's slot.
            AttributedSlot {
                hit: 7,
                slot: 0x7100,
                owner: Owner::Task {
                    header: 0x1000 + 4 * 0x100,
                    index: 3,
                },
                attribution: Attribution::Unknown,
                within: None,
                through: Vec::new(),
                aliases: Vec::new(),
                reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
            },
            AttributedSlot {
                hit: 8,
                slot: 0x7200,
                owner: Owner::Task {
                    header: 0x1000 + 5 * 0x100,
                    index: 4,
                },
                attribution: Attribution::Registry(RegistrySlot::Timer {
                    entry: 0x7200,
                    state: None,
                    deadline: None,
                }),
                within: None,
                through: Vec::new(),
                aliases: Vec::new(),
                reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
            },
        ]);
        let list = TaskList::new(vec![
            task(1, 0),
            task(2, 0),
            task(3, RUNNING),
            task(4, 0),
            blocking(5, 0),
        ]);
        let mut waits = vec![
            wait(1, None),
            wait(2, None),
            wait(3, None),
            wait(4, None),
            wait(5, None),
        ];
        let rows = folded_rows(&list, &mut waits, &slots);
        assert_eq!(
            rows[0].waiting_on,
            "io, join task 2, semaphore, timer, 2x unknown"
        );
        assert_eq!(
            rows[0].waiting_kind.as_deref(),
            Some("io read, join task 2, semaphore 0x9000, timer, unknown")
        );
        // One item per slot, sorted, each headed by what it names —
        // nothing located these, so nothing places them; a stop's own
        // reason is the cell's.
        assert_eq!(
            rows[0].wait_detail,
            [
                "io 0xaa00 read",
                "    waker: the read-waiter slot, awaiting readable",
                "join task 2",
                "    waker: its trailer",
                "semaphore 0x9000",
                "    waker: its wake-queue node @ 0xe100",
                // A wheel entry with no deadline to give names itself
                // once.
                "timer 0xdd00",
                "unknown @ 0x7000",
                "unknown @ 0x8000",
            ]
        );
        assert!(rows[0].will_wake.is_empty());
        // No slot: the assessment's own word, marked.
        assert_eq!(
            rows[1].waiting_on,
            "unarmed: unknown (no root in the tokio info)"
        );
        assert_eq!(
            rows[1].waiting_kind.as_deref(),
            Some("unarmed: unknown (no root in the tokio info)")
        );
        assert!(rows[1].wait_detail.is_empty());
        // Mid-poll: not parked, so nothing to mark.
        assert_eq!(rows[2].waiting_on, "— (mid-poll)");
        assert_eq!(rows[2].waiting_kind, None);
        // One unknown slot is `unknown`; several are counted, and the
        // address is the waker block's to print.
        assert_eq!(rows[3].waiting_on, "unknown");
        assert_eq!(rows[3].waiting_kind.as_deref(), Some("unknown"));
        assert_eq!(rows[3].wait_detail, ["unknown @ 0x7100"]);
        // A blocking cell waits on a pool thread, slot or no slot.
        assert_eq!(rows[4].waiting_on, "—");
        assert_eq!(rows[4].waiting_kind, None);
        assert!(rows[4].wait_detail.is_empty());
    }

    /// A verified wait is the cell whatever the sweep found: the join
    /// slot in the awaited task's trailer is the wait's own evidence,
    /// and a second slot the wait does not account for is a line under
    /// it, never a second entry — a slot beside a verified wait is a
    /// diagnostic, not a member.
    #[test]
    fn test_a_slot_beside_a_verified_wait_is_a_line_not_a_member() {
        use hansei_runtime::tokio::attribution::{
            Attributed, AttributedSlot, Attribution, RegistrySlot,
        };
        use hansei_runtime::tokio::wakers::Owner;

        let t1 = 0x1000 + 0x100;
        let t2 = 0x1000 + 2 * 0x100;
        let joined = TaskRef {
            addr: TaskAddr(t2),
            task_id: Some(2),
        };
        let owner = Owner::Task {
            header: t1,
            index: 0,
        };
        let slots = Attributed::from_slots(vec![
            AttributedSlot {
                hit: 0,
                slot: 0x1250,
                owner,
                attribution: Attribution::Registry(RegistrySlot::Join { task: joined }),
                within: None,
                through: Vec::new(),
                aliases: Vec::new(),
                reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
            },
            AttributedSlot {
                hit: 1,
                slot: 0xdd00,
                owner,
                attribution: Attribution::Registry(RegistrySlot::Timer {
                    entry: 0xdd00,
                    state: None,
                    deadline: None,
                }),
                within: None,
                through: Vec::new(),
                aliases: Vec::new(),
                reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
            },
        ]);
        let target = WaitTarget::Task {
            addr: t2,
            task_id: Some(2),
            state: TaskState(REF_ONE),
            listed: true,
            kind: None,
        };
        let list = TaskList::new(vec![task(1, 0), task(2, 0)]);
        let mut waits = vec![wait(1, Some(target)), wait(2, None)];
        let rows = folded_rows(&list, &mut waits, &slots);
        assert_eq!(rows[0].waiting_on, "task 2");
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("task 2"));
        // The join is the label line, with the trailer slot's own
        // line under it; the timer stands as the item it is.
        assert_eq!(rows[0].wait_line.as_deref(), Some("task 2"));
        assert_eq!(rows[0].wait_detail, ["waker: its trailer", "timer 0xdd00"]);
    }

    /// The slots no member accounts for are listed by what the
    /// attribution says about the current await: those it reaches are
    /// items under `awaiting on:`, one per container, placed in the
    /// holding frame and local with that frame's suspend point and
    /// every slot's `waker:` line; those an await that has returned
    /// installed are items under `will wake:`, placed the same way
    /// but with no `awaiting at:` — nothing under that label is
    /// awaited — and their resource under `woken by:`; a slot nothing
    /// located is an item headed by what it names, under `awaiting
    /// on:`. Items sort by heading.
    #[test]
    fn test_slots_split_into_awaited_items_and_the_ones_that_will_wake() {
        use hansei_runtime::tokio::attribution::{
            Attributed, AttributedSlot, Attribution, Holding, OwnerKind, Reach, RegistrySlot,
            SlotPath, SlotRoot, Validity,
        };
        use hansei_runtime::tokio::wakers::Owner;

        let owner = Owner::Task {
            header: 0x1000 + 0x100,
            index: 0,
        };
        let container = |addr: u64| ValueKey {
            addr,
            ty: crate::typenames::testing::NAMELESS,
        };
        let held = |addr: u64, frame: usize, local: &str| Holding {
            container: container(addr),
            frame,
            local: Some(local.to_string()),
        };
        let typed = |hit: usize, at: u64, reach: Reach| AttributedSlot {
            hit,
            slot: at,
            owner,
            attribution: Attribution::Typed {
                holder: "ListsInner".to_string(),
                member: "waker".to_string(),
                path: SlotPath {
                    root: SlotRoot::Frame { task: 0, frame: 3 },
                    steps: vec!["set".to_string()],
                    hop: None,
                },
                validity: Validity::SelfDescribing,
            },
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach,
        };
        let slots = Attributed::from_slots(vec![
            // Two slots in one awaited container are one item.
            typed(0, 0x6010, Reach::Awaited(held(0x6000, 3, "tasks"))),
            typed(1, 0x6020, Reach::Awaited(held(0x6000, 3, "tasks"))),
            // A parked typed slot, and a parked owner slot whose
            // resource is named under `woken by:`.
            typed(2, 0x7010, Reach::Parked(held(0x7000, 7, "interval"))),
            AttributedSlot {
                attribution: Attribution::Owner {
                    kind: OwnerKind::Mpsc,
                    primitive: 0x9000,
                    holder: "Chan".to_string(),
                    member: "rx_waker".to_string(),
                    path: SlotPath {
                        root: SlotRoot::Frame { task: 0, frame: 5 },
                        steps: vec!["rx".to_string()],
                        hop: None,
                    },
                    validity: Validity::SelfDescribing,
                    reading: None,
                },
                ..typed(3, 0x8010, Reach::Parked(held(0x8000, 5, "rx")))
            },
            // A registry slot nothing located.
            AttributedSlot {
                attribution: Attribution::Registry(RegistrySlot::Timer {
                    entry: 0xdd00,
                    state: None,
                    deadline: None,
                }),
                ..typed(4, 0xdd00, Reach::Unlocated)
            },
        ]);
        let list = TaskList::new(vec![task(1, 0)]);
        let mut wait = wait(1, None);
        // A chain of eight frames, root first; frame 3's site is the
        // one the awaited item prints.
        wait.frames = (0..8)
            .map(|i| ValueKey {
                addr: 0x2000 + i * 0x100,
                ty: BundleTypeId(2),
            })
            .collect();
        wait.frame_sites = (0..8)
            .map(|i| Some((format!("src/f{}.rs", 7 - i), 10 + i as u32)))
            .collect();
        let mut waits = vec![wait];
        let rows = folded_rows(&list, &mut waits, &slots);
        // The slots made a set, whose members the lines list whole.
        assert_eq!(rows[0].wait_line, None);
        assert_eq!(
            rows[0].wait_detail,
            [
                "0x6000",
                "    held in: frame 3 `tasks`",
                "    awaiting at: src/f3.rs:14",
                "    waker: ListsInner @ 0x6010",
                "    waker: ListsInner @ 0x6020",
                "timer 0xdd00",
            ]
        );
        assert_eq!(
            rows[0].will_wake,
            [
                "0x7000",
                "    held in: frame 7 `interval`",
                "    waker: ListsInner @ 0x7010",
                "0x8000",
                "    held in: frame 5 `rx`",
                "    woken by: mpsc rx 0x9000",
            ]
        );
    }

    /// A `held in:` line naming a local is followed by where the frame
    /// declares it, when the frame is a coroutine whose `let` the
    /// bundle recorded: under an awaited item and a parked one alike,
    /// and under a member the census found in the task's own frame.
    /// Nothing follows a `held in:` naming no local, a local the table
    /// does not carry, a frame that is no coroutine, or a find reached
    /// through another chain, whose frame number is that chain's.
    #[test]
    fn test_declared_at_follows_a_held_in_naming_a_coroutines_local() {
        use super::Containers;
        use hansei_bundle::BundleView;
        use hansei_runtime::tokio::attribution::{
            AttributedSlot, Attribution, Holding, Reach, SlotPath, SlotRoot, Validity,
        };
        use hansei_runtime::tokio::census::{FutureCensus, HeldFuture, Via};
        use hansei_runtime::tokio::wakers::Owner;

        let bundle = sited_bundle();
        let impls = Default::default();
        let stops = TypeNames::over(BundleView::new(&bundle), &impls);
        // Eight frames, all the coroutine but frame 5 (index 2), a
        // hand-written future.
        let frames: Vec<ValueKey> = (0..8)
            .map(|i| ValueKey {
                addr: 0x2000 + i * 0x100,
                ty: BundleTypeId(if i == 2 { 0 } else { 2 }),
            })
            .collect();
        let owner = Owner::Task {
            header: 0x1100,
            index: 0,
        };
        let held = |addr: u64, frame: usize, local: Option<&str>| Holding {
            container: ValueKey {
                addr,
                ty: BundleTypeId(1),
            },
            frame,
            local: local.map(str::to_string),
        };
        let slot = |hit: usize, at: u64, reach: Reach| AttributedSlot {
            hit,
            slot: at,
            owner,
            attribution: Attribution::Typed {
                holder: "ListsInner".to_string(),
                member: "waker".to_string(),
                path: SlotPath {
                    root: SlotRoot::Frame { task: 0, frame: 3 },
                    steps: vec!["set".to_string()],
                    hop: None,
                },
                validity: Validity::SelfDescribing,
            },
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach,
        };
        let slots = [
            slot(0, 0x6010, Reach::Awaited(held(0x6000, 3, Some("tasks")))),
            slot(1, 0x7010, Reach::Parked(held(0x7000, 7, Some("tasks")))),
            slot(2, 0x8010, Reach::Parked(held(0x8000, 5, Some("tasks")))),
            slot(3, 0x9010, Reach::Parked(held(0x9000, 4, Some("interval")))),
            slot(4, 0xa010, Reach::Parked(held(0xa000, 4, None))),
        ];
        let refs: Vec<&AttributedSlot> = slots.iter().collect();
        let mut wait = wait(1, None);
        wait.frames = frames.clone();
        let detail = Detail {
            containers: None,
            armed: false,
            frames: &frames,
            caller_at: None,
            request_of: None,
        };
        let lines = wait_detail(&wait, &stops, &refs, None, &|_| None, detail);
        assert_eq!(
            lines.awaiting,
            [
                "0x6000: x::plain",
                "    held in: frame 3 `tasks`",
                "    declared at: src/run.rs:35",
                "    waker: ListsInner @ 0x6010",
            ]
        );
        assert_eq!(
            lines.wake,
            [
                "0x7000: x::plain",
                "    held in: frame 7 `tasks`",
                "    declared at: src/run.rs:35",
                "    waker: ListsInner @ 0x7010",
                "0x8000: x::plain",
                "    held in: frame 5 `tasks`",
                "    waker: ListsInner @ 0x8010",
                "0x9000: x::plain",
                "    held in: frame 4 `interval`",
                "    waker: ListsInner @ 0x9010",
                "0xa000: x::plain",
                "    held in: frame 4",
                "    waker: ListsInner @ 0xa010",
            ]
        );

        // A member the census placed in frame 2's `tasks`, then the
        // same find reached through a held future's chain.
        let find = |via: Option<Via>| HeldFuture {
            owner: 0,
            frame: 2,
            local: "tasks".to_string(),
            via,
            slot: 0x6000,
            addr: 0x6000,
            ty: BundleTypeId(0),
            depth: 1,
            frames: Vec::new(),
            future: crate::typenames::testing::named("x::branch"),
            state: None,
            waiting_on: None,
            wait: None,
            observation: None,
            request: None,
            continuation: ContinuationStatus::Incomplete {
                reason: IncompleteReason::NoRoot,
                detail: None,
            },
        };
        let member = branch("inner", WaitAssessment::Unresumed, false);
        let member_lines = |census: &FutureCensus| {
            let containers = Containers::of(census);
            let detail = Detail {
                containers: Some(&containers),
                armed: false,
                frames: &frames,
                caller_at: None,
                request_of: None,
            };
            member_line(&member, &stops, &[], None, detail)
        };
        let own = FutureCensus::from_finds(vec![find(None)], vec![], vec![]);
        assert_eq!(
            member_lines(&own),
            [
                "inner: x::branch",
                "    held in: frame 2 `tasks`",
                "    declared at: src/run.rs:35",
                "    awaiting on: never polled",
                "    type defined at: hyper-1.10.1/src/proto/h1/dispatch.rs:512",
            ]
        );
        let through = FutureCensus::from_finds(vec![find(Some(Via::Held(0)))], vec![], vec![]);
        assert_eq!(
            member_lines(&through),
            [
                "inner: x::branch",
                "    held in: frame 2 `tasks`",
                "    awaiting on: never polled",
                "    type defined at: hyper-1.10.1/src/proto/h1/dispatch.rs:512",
            ]
        );
    }

    /// The `armed:` line prints only on a task that is not idle: on an
    /// idle one every enabled branch of a pending `select!` is armed
    /// by construction, so the line says nothing; on a notified one a
    /// wake may have consumed a slot already, which is what the line
    /// is for.
    #[test]
    fn test_armed_prints_only_on_a_task_that_is_not_idle() {
        let stops = crate::typenames::testing::type_names();
        let member = select_branch(0, WaitAssessment::Unresumed, true);
        let idle = Detail {
            containers: None,
            armed: false,
            frames: &[],
            caller_at: None,
            request_of: None,
        };
        assert_eq!(
            member_line(&member, stops, &[], None, idle),
            [
                "branch 0 (borrowed): x::branch",
                "    awaiting on: never polled",
                "    waker: the resource, read by its protocol",
            ]
        );
        assert_eq!(
            member_line(&member, stops, &[], None, ARMED),
            [
                "branch 0 (borrowed): x::branch",
                "    armed: yes",
                "    awaiting on: never polled",
                "    waker: the resource, read by its protocol",
            ]
        );
        // Through the rows: the same set on an idle task and on a
        // notified one.
        let set = || one_of(vec![select_branch(0, WaitAssessment::Unresumed, true)]);
        let rows = rows_of(
            vec![task(1, 0), task(2, NOTIFIED)],
            vec![assessed(1, set()), assessed(2, set())],
            HashMap::new(),
        );
        assert!(
            !rows[0].wait_detail.iter().any(|l| l.contains("armed:")),
            "{:?}",
            rows[0].wait_detail
        );
        assert!(
            rows[1]
                .wait_detail
                .contains(&"        armed: yes".to_string()),
            "{:?}",
            rows[1].wait_detail
        );
    }

    /// A connection's `caller:` line under its `via:`: the task the
    /// callback's receiver cell names; a receiver that is no task's,
    /// named by the sweep's account of its cell where the listing has
    /// one — the set child holding it and the task polling the set —
    /// and by its vtable where it has none.
    #[test]
    fn test_a_connections_caller_prints_under_its_via() {
        use hansei_runtime::tokio::attribution::{
            AttributedSlot, Attribution, OwnerKind, Reach, SlotPath, SlotRoot, Validity,
        };
        use hansei_runtime::tokio::bundle::{
            HttpCaller, HttpPhase, HttpRole, HttpVersion, OneshotSide, OneshotState,
        };
        use hansei_runtime::tokio::wakers::Owner;
        let state = OneshotState {
            word: 0b1001,
            value_present: Some(false),
        };
        let conn = |caller| WaitTarget::HttpConn {
            addr: 0xc000,
            role: HttpRole::Client,
            version: Some(HttpVersion::Http1),
            phase: HttpPhase::AwaitingResponse,
            method: Some("GET".to_string()),
            keep_alive: true,
            header_read_timer: false,
            via: Some(Box::new(WaitTarget::Oneshot {
                addr: 0xd000,
                state,
                side: OneshotSide::Tx,
            })),
            caller: Some(caller),
            tls: None,
            fd: None,
        };
        let slot = AttributedSlot {
            hit: 0,
            slot: 0xd000,
            owner: Owner::Task {
                header: 0x1100,
                index: 0,
            },
            attribution: Attribution::Owner {
                kind: OwnerKind::OneshotTx,
                primitive: 0xd000,
                holder: "Inner".to_string(),
                member: "tx_task".to_string(),
                path: SlotPath {
                    root: SlotRoot::Frame { task: 0, frame: 0 },
                    steps: vec!["tx_task".to_string()],
                    hop: None,
                },
                validity: Validity::Gated("tx_task_set"),
                reading: None,
            },
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
        };
        let stops = crate::typenames::testing::type_names();
        let named = |cell: u64| {
            (cell == 0xd010)
                .then(|| "child 3 of the set at 0xfeb66c0 (polled by task 621)".to_string())
        };
        let lines = |caller, caller_at: Option<&dyn Fn(u64) -> Option<String>>| {
            let detail = Detail {
                containers: None,
                armed: false,
                frames: &[],
                caller_at,
                request_of: None,
            };
            wait_detail(
                &wait(1, Some(conn(caller))),
                stops,
                &[&slot],
                None,
                &|_| None,
                detail,
            )
            .awaiting
        };
        let child = HttpCaller::NotATask {
            vtable: 0xeebc0d0,
            cell: Some(0xd010),
        };
        assert_eq!(
            lines(child.clone(), Some(&named)),
            [
                "via: oneshot tx 0xd000 (nothing sent, receiver alive)",
                "caller: child 3 of the set at 0xfeb66c0 (polled by task 621)",
            ]
        );
        assert_eq!(
            lines(child, None)[1],
            "caller: not a task (waker vtable 0xeebc0d0)"
        );
        let uncelled = HttpCaller::NotATask {
            vtable: 0xeebc0d0,
            cell: None,
        };
        assert_eq!(
            lines(uncelled, Some(&named))[1],
            "caller: not a task (waker vtable 0xeebc0d0)"
        );
        let task = HttpCaller::Task(TaskRef {
            addr: TaskAddr(0x1700),
            task_id: Some(7),
        });
        assert_eq!(lines(task, Some(&named))[1], "caller: task 7");
        assert_eq!(
            lines(HttpCaller::Gone, Some(&named))[1],
            "caller: gone (receiver dropped)"
        );
    }

    /// Whose waker a slot holds, named for a listing: a task by its
    /// id, a set child by its index, its set's address and the task
    /// polling it — and nothing for a child without the census that
    /// knows the set.
    #[test]
    fn test_an_owner_label_names_a_child_by_its_set() {
        use hansei_runtime::tokio::census::{FutureCensus, FutureSet};
        use hansei_runtime::tokio::wakers::Owner;
        let list = TaskList::new(vec![task(7, 0), task(621, 0)]);
        let by_task = Owner::Task {
            header: 0,
            index: 1,
        };
        assert_eq!(
            super::owner_label(&list, None, by_task).as_deref(),
            Some("task 621")
        );
        let child = Owner::Child { set: 0, child: 3 };
        assert_eq!(super::owner_label(&list, None, child), None);
        let census = FutureCensus::from_finds(
            Vec::new(),
            vec![FutureSet {
                owner: 1,
                frame: 10,
                local: "dependencies".to_string(),
                via: None,
                addr: 0xfeb66c0,
                ty: crate::typenames::testing::named(
                    "futures_util::stream::futures_unordered::FuturesUnordered<()>",
                ),
                children: Vec::new(),
            }],
            Vec::new(),
        );
        assert_eq!(
            super::owner_label(&list, Some(&census), child).as_deref(),
            Some("child 3 of the set at 0xfeb66c0 (polled by task 621)")
        );
    }

    /// The rows as the launch builds them: the slots folded into each
    /// wait, then the rows built from the waits and finished against
    /// the slots.
    fn folded_rows(
        list: &TaskList,
        waits: &mut [TaskWait],
        slots: &hansei_runtime::tokio::attribution::Attributed,
    ) -> Vec<super::TaskRow> {
        folded_rows_sized(list, waits, slots, &|_| None)
    }

    /// [`folded_rows`] with a size for every type, so a slot can lie
    /// inside a member's storage.
    fn folded_rows_sized(
        list: &TaskList,
        waits: &mut [TaskWait],
        slots: &hansei_runtime::tokio::attribution::Attributed,
        size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
    ) -> Vec<super::TaskRow> {
        for (task, wait) in list.tasks.iter().zip(waits.iter_mut()) {
            let owned: Vec<_> = slots.of_task(task.addr.0).collect();
            if !owned.is_empty() {
                hansei_runtime::tokio::waitset::fold_wait(task, wait, &owned, None, size_of);
            }
        }
        let stops = crate::typenames::testing::type_names();
        let mut rows = build_rows(
            list,
            &Default::default(),
            waits,
            &HashMap::new(),
            &Default::default(),
            stops,
        );
        super::apply_slots(&mut rows, list, waits, slots, None, size_of, stops, None);
        rows
    }

    /// A `select!` rolled up to never ready keeps the verdict as its
    /// cell and its bucket whatever the sweep found: a swept slot
    /// inside a branch arms that branch's line and nothing more, a
    /// slot in no branch is a line of its own after the branches, and
    /// the disabled branch is named among them.
    #[test]
    fn test_a_never_ready_select_keeps_its_verdict_beside_a_swept_slot() {
        use hansei_runtime::tokio::attribution::{Attributed, AttributedSlot, Attribution};
        use hansei_runtime::tokio::wakers::Owner;

        let never_ready = |members, capped| WaitAssessment::NeverReady { members, capped };
        let owner = Owner::Task {
            header: 0x1000 + 0x100,
            index: 0,
        };
        let slot = |hit: usize, at: u64| AttributedSlot {
            hit,
            slot: at,
            owner,
            attribution: Attribution::Unknown,
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
        };
        let slots = Attributed::from_slots(vec![slot(0, 0x6010), slot(1, 0x7000)]);
        let list = TaskList::new(vec![task(1, 0)]);
        let mut waits = vec![assessed(
            1,
            never_ready(
                vec![
                    select_branch(0, never_ready(Vec::new(), 0), false),
                    select_branch(1, never_ready(Vec::new(), 0), false),
                    disabled(2),
                ],
                0,
            ),
        )];
        let rows = folded_rows_sized(&list, &mut waits, &slots, &|_| Some(0x40));
        assert!(
            matches!(waits[0].assessment, WaitAssessment::NeverReady { .. }),
            "{:?}",
            waits[0].assessment
        );
        assert_eq!(rows[0].waiting_on, "never ready");
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("never ready"));
        // The swept slot no branch accounts for is a `waker` block
        // beside the `select!:` heading, not under it.
        assert_eq!(
            rows[0].wait_detail,
            [
                "select!:",
                "    branch 0 (borrowed): x::branch",
                "        awaiting on: never ready",
                "        waker: unknown @ 0x6010",
                "    branch 1 (borrowed): x::branch",
                "        awaiting on: never ready",
                "    branch 2: x::skipped: disabled",
                "unknown @ 0x7000",
            ]
        );
    }

    /// A running task waits on nothing: its cell names the lwp polling
    /// it where the runtime says one, and says only mid-poll where it
    /// does not.
    #[test]
    fn test_a_running_row_names_its_lwp() {
        let rows = rows_of(
            vec![task(1, RUNNING), task(2, RUNNING), task(3, 0)],
            vec![wait(1, None), wait(2, None), wait(3, None)],
            HashMap::from([(1, 115), (3, 116)]),
        );
        assert_eq!(rows[0].waiting_on, "— (mid-poll on lwp 115)");
        assert_eq!(rows[1].waiting_on, "— (mid-poll)");
        // The `lwp` column is the same belief: the polling word is a
        // running task's, so an idle task the map still names gets
        // none.
        assert_eq!(rows[0].lwp, Some(115));
        assert_eq!(rows[1].lwp, None);
        assert_eq!(rows[2].lwp, None);
    }

    /// The footer is the only truncation: the count alone when
    /// everything printed, both numbers when a limit cut the listing,
    /// and brackets either way.
    #[test]
    fn test_the_footer_counts_the_cut() {
        assert_eq!(
            listing_footer(22498, 100, "task"),
            "[22498 tasks, 100 shown]"
        );
        assert_eq!(listing_footer(2, 2, "task"), "[2 tasks]");
        assert_eq!(listing_footer(1, 1, "task"), "[1 task]");
        assert_eq!(listing_footer(0, 0, "task"), "[0 tasks]");
        assert_eq!(listing_footer(2, 1, "root"), "[2 roots, 1 shown]");
    }

    /// The `RT` column exists exactly when the population holds more
    /// than one group, so the common single-runtime table never
    /// carries a column of zeros.
    #[test]
    fn test_the_rt_column_prints_only_for_groups() {
        let rows = rows_of(vec![task(1, 0)], vec![wait(1, None)], HashMap::new());
        let rows: Vec<(&super::TaskRow, usize)> = rows.iter().map(|r| (r, 0)).collect();
        let print = |groups: bool| {
            let mut out = Vec::new();
            print_task_table(
                &rows,
                groups,
                None,
                None,
                crate::output::Theme::plain(),
                &mut out,
            )
            .expect("table prints");
            String::from_utf8(out).expect("utf8")
        };
        assert!(print(true).contains("RT"), "{}", print(true));
        assert!(!print(false).contains("RT"), "{}", print(false));
    }

    /// Each row carries its futures count, right-aligned under a
    /// `FUT` heading between the state and the await site.
    #[test]
    fn test_the_futures_column_counts_each_row() {
        let rows = rows_of(
            vec![task(1, 0), task(2, 0)],
            vec![wait(1, None), wait(2, None)],
            HashMap::new(),
        );
        let rows: Vec<(&super::TaskRow, usize)> = rows.iter().zip([0, 3075]).collect();
        let mut out = Vec::new();
        print_task_table(
            &rows,
            false,
            None,
            None,
            crate::output::Theme::plain(),
            &mut out,
        )
        .expect("table prints");
        let out = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            lines[0].starts_with("ID  STATE   FUT  AWAITING AT"),
            "{out}"
        );
        assert!(lines[1].starts_with("1   idle      0  "), "{out}");
        assert!(lines[2].starts_with("2   idle   3075  "), "{out}");
    }

    /// `--limit` cuts the rows and earns the footer; without it every
    /// row prints above the plain count.
    #[test]
    fn test_a_limit_cuts_the_rows_and_says_so() {
        let rows = rows_of(
            vec![task(1, 0), task(2, 0), task(3, 0)],
            vec![wait(1, None), wait(2, None), wait(3, None)],
            HashMap::new(),
        );
        let rows: Vec<(&super::TaskRow, usize)> = rows.iter().map(|r| (r, 0)).collect();
        let mut out = Vec::new();
        print_task_table(
            &rows,
            false,
            Some(2),
            None,
            crate::output::Theme::plain(),
            &mut out,
        )
        .expect("table prints");
        let out = String::from_utf8(out).expect("utf8");
        assert!(out.contains("\n1 "), "{out}");
        assert!(out.contains("\n2 "), "{out}");
        assert!(!out.contains("\n3 "), "{out}");
        assert!(out.ends_with("[3 tasks, 2 shown]\n"), "{out}");
    }
}

#[cfg(test)]
mod filter_tests {
    use super::{
        Clause, Cmp, Counts, EMPTY_BUCKET, Field, RowOwner, TaskRow, alternatives, group_value,
        matcher, member_sample, parse_clauses, refuse_positional_ids, resolve_rt, survives,
    };

    use std::collections::BTreeMap;

    fn row(id: &str) -> TaskRow {
        TaskRow {
            id: id.to_string(),
            state: "idle".to_string(),
            rt: RowOwner::Group(0),
            awaiting_at: None,
            waiting_on: "—".to_string(),
            waiting_kind: None,
            wait_detail: Vec::new(),
            wait_line: None,
            wait_text: "—".to_string(),
            will_wake: Vec::new(),
            future: "async fn app::work".to_string(),
            future_ty: None,
            spawned: None,
            defined: None,
            lwp: None,
        }
    }

    fn clause(field: &str, arg: &str) -> Clause {
        let field = Field::parse(field).expect("a test field parses");
        Clause {
            field,
            matchers: vec![matcher(field, arg, &[0x7f11c0]).expect("a test matcher compiles")],
            negate: false,
        }
    }

    fn keeps(c: &Clause, row: &TaskRow) -> bool {
        survives(c, 0, row, None)
    }

    /// Every string field matches its own column, case-insensitively,
    /// and a row with nothing in the field matches no pattern.
    #[test]
    fn test_each_string_field_reads_its_own_column() {
        let mut r = row("129");
        r.state = "idle (cancelled)".to_string();
        r.awaiting_at = Some("src/app.rs:42".to_string());
        r.waiting_on = "timer".to_string();
        r.wait_text = "timer (deadline +38.364s)".to_string();
        r.spawned = Some("src/main.rs:10:5".to_string());
        r.defined = Some("src/app.rs:7".to_string());

        assert!(keeps(&clause("type", "APP::WORK"), &r));
        assert!(!keeps(&clause("type", "qorb"), &r));
        assert!(keeps(&clause("state", "cancelled"), &r));
        assert!(keeps(&clause("awaiting", "app.rs:42$"), &r));
        assert!(keeps(&clause("waiting-on", "^timer"), &r));
        assert!(keeps(&clause("spawned", "main.rs"), &r));
        assert!(keeps(&clause("defined", "app.rs:7"), &r));
        r.waiting_on = "task 2, timer".to_string();
        r.wait_text = "task 2, timer (deadline +38.364s)".to_string();
        // The older names reach the same field.
        assert!(keeps(&clause("waker", "task 2"), &r));
        assert!(keeps(&clause("slots", "task 2"), &r));
        assert!(!keeps(&clause("waker", "semaphore"), &r));
        assert!(!keeps(&clause("waker", "unknown"), &row("1")));
        // The field is the wait as the block prints it, detail lines
        // included: an address on the label line or on a line under
        // it — a connection's `via:` primitive — reaches the filter,
        // and the cell alone is not what is matched.
        r.waiting_on = "http1 client".to_string();
        r.wait_text = "http1 client 0xc72d000 (idle, keep-alive)\nvia: mpsc rx 0xfb0f700 (1 sender, 0 unread)".to_string();
        assert!(keeps(&clause("waiting-on", "0xc72d000"), &r));
        assert!(keeps(&clause("waiting-on", "0xfb0f700"), &r));
        assert!(keeps(&clause("waiting-on", "^http1 client"), &r));
        assert!(!keeps(&clause("waiting-on", "^via"), &r));
        // The caller a connection names is a detail line too.
        r.wait_text.push_str("\ncaller: task 4307675");
        assert!(keeps(&clause("waiting-on", "4307675"), &r));
        assert!(!keeps(&clause("waiting-on", "^caller"), &r));

        // Nothing in the field is nothing to match.
        assert!(!keeps(&clause("awaiting", "."), &row("1")));
        assert!(!keeps(&clause("spawned", "."), &row("1")));
        assert!(!keeps(&clause("defined", "."), &row("1")));
    }

    /// The exact fields are exact: the id, the polling lwp, and the
    /// group index — which an `rt` handle resolves to through the
    /// runtimes list, or errors, rather than matching nothing.
    #[test]
    fn test_the_exact_fields_are_exact() {
        let mut r = row("129");
        r.lwp = Some(115);
        r.rt = RowOwner::Group(1);
        assert!(keeps(&clause("id", "129"), &r));
        assert!(!keeps(&clause("id", "12"), &r));
        assert!(keeps(&clause("lwp", "115"), &r));
        assert!(!keeps(&clause("lwp", "116"), &r));
        assert!(!keeps(&clause("lwp", "115"), &row("129")));
        assert!(keeps(&clause("rt", "1"), &r));
        assert!(!keeps(&clause("rt", "0"), &r));

        assert_eq!(
            resolve_rt("@0x7f11c0", &[0x10, 0x7f11c0]).unwrap(),
            RowOwner::Group(1)
        );
        assert_eq!(
            resolve_rt("0x7f11c0", &[0x10, 0x7f11c0]).unwrap(),
            RowOwner::Group(1)
        );
        assert_eq!(resolve_rt("unknown", &[]).unwrap(), RowOwner::Unknown);
        assert_eq!(resolve_rt("conflict", &[]).unwrap(), RowOwner::Conflict);
        // The marks the `RT` column prints for those two name them
        // as well as the words do, so a value read off the table can
        // be typed back into the clause.
        assert_eq!(resolve_rt("?", &[]).unwrap(), RowOwner::Unknown);
        assert_eq!(resolve_rt("!", &[]).unwrap(), RowOwner::Conflict);
        assert!(resolve_rt("@0xdead", &[0x10]).is_err());
        assert!(resolve_rt("nope", &[]).is_err());
        assert!(matcher(Field::Lwp, "x", &[]).is_err());
    }

    /// `holds`, `sets` and `futures` compare the census's counts with
    /// the three spellings and no others; `sets` is the blocks' own
    /// row — both kinds of set together — `futures` is the table's
    /// column — the held futures and the sets' live children — and a
    /// task the census found nothing for counts zero.
    #[test]
    fn test_count_fields_compare_the_census() {
        let mut counts: BTreeMap<usize, Counts> = BTreeMap::new();
        counts.insert(
            0,
            Counts {
                held: 2,
                sets: 1,
                children_live: 5,
                join_sets: 1,
                joined: 3,
            },
        );
        let keeps =
            |field: &str, arg: &str| survives(&clause(field, arg), 0, &row("1"), Some(&counts));

        assert!(keeps("holds", ">1"));
        assert!(keeps("holds", "=2"));
        assert!(!keeps("holds", "<2"));
        assert!(keeps("sets", "=2"));
        assert!(!keeps("sets", ">2"));
        assert!(keeps("futures", "=7"));
        assert!(!keeps("futures", "<7"));
        assert_eq!(
            group_value(Field::Futures, 0, &row("1"), Some(&counts)).as_deref(),
            Some("7")
        );
        for field in ["holds", "sets", "futures"] {
            assert!(survives(&clause(field, "=0"), 5, &row("1"), Some(&counts)));
        }

        let err = Cmp::parse("2").unwrap_err();
        assert!(err.to_string().contains("'>N', '<N' or '=N'"), "{err}");
        assert!(Cmp::parse(">x").is_err());
        assert!(Cmp::parse("").is_err());
    }

    /// `--without` keeps what the clause does not match, and clauses
    /// AND across both flags.
    #[test]
    fn test_without_negates_and_clauses_and() {
        let mut running = row("2");
        running.state = "running".to_string();
        let rows = [row("1"), running, row("3")];
        let with = ["state".to_string(), "idle".to_string()];
        let without = ["id".to_string(), "1".to_string()];
        let clauses = parse_clauses(&with, &without, &[]).expect("the clauses parse");
        let survivors: Vec<&str> = rows
            .iter()
            .enumerate()
            .filter(|(i, r)| clauses.iter().all(|c| survives(c, *i, r, None)))
            .map(|(_, r)| r.id.as_str())
            .collect();
        // idle AND not id 1: row 1 is excluded by id, row 2 by state.
        assert_eq!(survivors, ["3"]);
    }

    /// A clause argument lists alternatives: `1,3` keeps either id,
    /// `--without` drops both, and the OR stays inside its clause —
    /// clauses still AND.
    #[test]
    fn test_alternatives_or_within_a_clause() {
        let rows = [row("1"), row("2"), row("3")];
        let ids = |with: &[&str], without: &[&str]| -> Vec<&str> {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            let without: Vec<String> = without.iter().map(|s| s.to_string()).collect();
            let clauses = parse_clauses(&with, &without, &[]).expect("the clauses parse");
            rows.iter()
                .enumerate()
                .filter(|(i, r)| clauses.iter().all(|c| survives(c, *i, r, None)))
                .map(|(_, r)| r.id.as_str())
                .collect()
        };
        assert_eq!(ids(&["id", "1,3"], &[]), ["1", "3"]);
        assert_eq!(ids(&[], &["id", "1,3"]), ["2"]);
        assert_eq!(ids(&["id", "1,3"], &["id", "3"]), ["1"]);
        // A pattern field's alternatives are each a regex of their
        // own, and `\,` puts a literal comma in one.
        let mut ready = row("4");
        ready.state = "ready, queued".to_string();
        let rows = [row("1"), ready];
        let clauses =
            parse_clauses(&["state".into(), "^idle$,ready\\, q".into()], &[], &[]).unwrap();
        assert!(
            rows.iter()
                .all(|r| clauses.iter().all(|c| survives(c, 0, r, None)))
        );
        let clauses = parse_clauses(&["state".into(), "ready,q".into()], &[], &[]).unwrap();
        assert!(!survives(&clauses[0], 0, &rows[0], None));
        // One bad alternative fails the clause, naming its flag.
        let err = parse_clauses(&["lwp".into(), "1,x".into()], &[], &[]).unwrap_err();
        assert!(format!("{err:#}").contains("--with lwp"), "{err:#}");
    }

    /// The split behind every listing's clauses: unescaped commas
    /// separate, `\,` is a comma, any other backslash pair is left
    /// for the regex, and an empty alternative is refused.
    #[test]
    fn test_alternatives_split_at_unescaped_commas() {
        assert_eq!(alternatives("1").unwrap(), ["1"]);
        assert_eq!(alternatives("1,2,3").unwrap(), ["1", "2", "3"]);
        assert_eq!(alternatives("a\\,b,c{1\\,3}").unwrap(), ["a,b", "c{1,3}"]);
        assert_eq!(alternatives("\\d+,\\\\").unwrap(), ["\\d+", "\\\\"]);
        assert_eq!(alternatives("\\\\,x").unwrap(), ["\\\\", "x"]);
        for bad in ["", "1,,2", "1,", ",1"] {
            let err = alternatives(bad).expect_err(bad).to_string();
            assert!(err.contains("empty"), "{bad:?}: {err}");
        }
    }

    /// An unknown field lists the fields there are; a broken argument
    /// names the flag and field it came from.
    #[test]
    fn test_filter_errors_name_their_flag() {
        let err = parse_clauses(&["nope".into(), "x".into()], &[], &[]).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("--with"), "{text}");
        assert!(text.contains("waiting-on"), "{text}");
        let err = parse_clauses(&[], &["type".into(), "(".into()], &[]).unwrap_err();
        assert!(format!("{err:#}").contains("--without type"), "{err:#}");
        let err = parse_clauses(&["holds".into(), "3".into()], &[], &[]).unwrap_err();
        assert!(format!("{err:#}").contains("--with holds"), "{err:#}");
    }

    /// The bucket names: the field's spelled value, `<empty>` where it
    /// has nothing — the table's `—` wait cell included — and the
    /// member sample stops at three ids.
    #[test]
    fn test_group_values_and_the_empty_bucket() {
        let r = row("129");
        assert_eq!(group_value(Field::WaitingOn, 0, &r, None), None);
        assert_eq!(group_value(Field::Awaiting, 0, &r, None), None);
        assert_eq!(group_value(Field::Lwp, 0, &r, None), None);
        assert_eq!(
            group_value(Field::State, 0, &r, None).as_deref(),
            Some("idle")
        );
        assert_eq!(group_value(Field::Rt, 0, &r, None).as_deref(), Some("0"));
        let mut waited = r.clone();
        waited.waiting_on = "task 42".to_string();
        waited.waiting_kind = Some("task 42".to_string());
        waited.lwp = Some(115);
        assert_eq!(
            group_value(Field::WaitingOn, 0, &waited, None).as_deref(),
            Some("task 42")
        );
        // The bucket is the kind, not the row's full spelling: a
        // deadline-bearing row groups under its kind label.
        let mut timed = r.clone();
        timed.waiting_on = "timer (deadline +12.000s)".to_string();
        timed.waiting_kind = Some("timer".to_string());
        assert_eq!(
            group_value(Field::WaitingOn, 0, &timed, None).as_deref(),
            Some("timer")
        );
        assert_eq!(
            group_value(Field::Lwp, 0, &waited, None).as_deref(),
            Some("115")
        );
        // A row waiting on nothing nameable is the empty bucket.
        assert_eq!(group_value(Field::WaitingOn, 0, &r, None), None);
        assert_eq!(EMPTY_BUCKET, "<empty>");

        let rows: Vec<TaskRow> = (0..5).map(|i| row(&i.to_string())).collect();
        assert_eq!(member_sample(&rows, &[0, 1]), "0, 1");
        assert_eq!(member_sample(&rows, &[0, 1, 2]), "0, 1, 2");
        assert_eq!(member_sample(&rows, &[0, 1, 2, 3]), "0, 1, 2, …");
    }

    /// Exactly the count fields cost the census; a census built for a
    /// field that does not need it is a walk paid for nothing, and one
    /// not built for a field that does is a panic downstream.
    #[test]
    fn test_field_values_are_the_columns_distinct_spellings() {
        let mut a = row("129");
        a.waiting_on = "io 0xf9c3d00 (readable)".to_string();
        a.waiting_kind = Some("io".to_string());
        a.lwp = Some(7);
        let mut b = row("130");
        b.state = "running".to_string();
        b.waiting_kind = Some("timer".to_string());
        b.future = "async fn app::serve".to_string();
        let mut c = row("131");
        c.waiting_kind = Some("timer".to_string());
        let rows = [a, b, c];
        let values = |field: &str| Field::parse(field).expect("a field name").values(&rows);
        // Most frequent first, ties in value order; a row with nothing
        // in the column contributes nothing.
        assert_eq!(values("state"), Some(vec!["idle".into(), "running".into()]));
        assert_eq!(
            values("waiting-on"),
            Some(vec!["timer".into(), "io".into()])
        );
        // The alias reads the same column.
        assert_eq!(values("waker"), values("waiting-on"));
        assert_eq!(values("lwp"), Some(vec!["7".into()]));
        assert_eq!(values("rt"), Some(vec!["0".into()]));
        assert_eq!(
            values("id"),
            Some(vec!["129".into(), "130".into(), "131".into()])
        );
        assert_eq!(
            values("type"),
            Some(vec![
                "async fn app::work".into(),
                "async fn app::serve".into()
            ])
        );
        assert_eq!(values("awaiting"), Some(Vec::new()));
        assert_eq!(values("holds"), None);
        assert_eq!(values("sets"), None);
        assert_eq!(values("futures"), None);
        // Pattern fields escape their values on the way back into the
        // line; the exact and compared ones do not.
        for exact in ["id", "lwp", "rt", "holds", "sets", "futures"] {
            assert!(!Field::parse(exact).unwrap().is_pattern(), "{exact}");
        }
        for pattern in [
            "type",
            "state",
            "waiting-on",
            "waker",
            "awaiting",
            "spawned",
            "defined",
        ] {
            assert!(Field::parse(pattern).unwrap().is_pattern(), "{pattern}");
        }
    }

    #[test]
    fn test_only_the_count_fields_need_the_census() {
        for (name, field) in Field::NAMES {
            assert_eq!(
                field.needs_census(),
                matches!(field, Field::Holds | Field::Sets | Field::Futures),
                "{name}"
            );
        }
    }

    /// The first task's heading opens the output; every later one is
    /// set off by one blank line — the blank line alone when the
    /// command prints its own heading.
    #[test]
    fn test_exec_headings_separate_tasks_with_one_blank_line() {
        use super::exec_heading;
        assert_eq!(exec_heading(0, Some("task 129")), "task 129\n");
        assert_eq!(exec_heading(1, Some("task 129")), "\ntask 129\n");
        assert_eq!(exec_heading(0, None), "");
        assert_eq!(exec_heading(1, None), "\n");
    }

    /// A positional id is refused with the selector spelling that
    /// took its place.
    #[test]
    fn test_positional_ids_are_refused_with_the_filter_spelling() {
        assert!(refuse_positional_ids(&[]).is_ok());
        let err = refuse_positional_ids(&["129".to_string()]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "tasks takes no task ids; `task 129` selects that one task"
        );
    }
}

#[cfg(test)]
mod census_warning_tests {
    use super::{census_capped_warning, census_refused_warning, census_uncertain_warning};

    use hansei_runtime::tokio::census::Capped;

    /// A walk that reached everything says nothing: the warning exists
    /// to contradict the completeness a listing otherwise implies, so
    /// it must not be the noise every run prints.
    #[test]
    fn test_an_uncapped_walk_warns_of_nothing() {
        assert_eq!(census_capped_warning(Capped::default(), "listed"), None);
    }

    /// Each limit names itself and its own count, so a reader who has
    /// to decide what to do about it knows which one to chase — and the
    /// sentence ends in what the command it interrupted was claiming to
    /// cover.
    #[test]
    fn test_each_limit_names_itself_and_the_listing_it_shortened() {
        let deep = census_capped_warning(
            Capped {
                deep: 2,
                distant: 0,
                unavailable: 0,
            },
            "listed",
        )
        .expect("a capped walk warns");
        assert_eq!(
            deep,
            "the scan stopped at its depth limit in 2 place(s); \
             anything nested deeper is not listed \
             (--search-depth moves the depth limit)"
        );

        let distant = census_capped_warning(
            Capped {
                deep: 0,
                distant: 5,
                unavailable: 0,
            },
            "counted",
        )
        .expect("a capped walk warns");
        assert_eq!(
            distant,
            "the scan stopped at its nesting limit in 5 place(s); \
             anything held further out is not counted"
        );
    }

    /// Storage the bundle declares unreadable is a third stop of its
    /// own — nothing a session flag moves, and nothing nested or held
    /// out: the value is right there and cannot be read.
    #[test]
    fn test_unavailable_storage_names_itself() {
        let unavailable = census_capped_warning(
            Capped {
                deep: 0,
                distant: 0,
                unavailable: 3,
            },
            "listed",
        )
        .expect("a capped walk warns");
        assert_eq!(
            unavailable,
            "the scan stopped at storage the tokio info cannot read in 3 \
             place(s); anything held in it is not listed"
        );
        let all = census_capped_warning(
            Capped {
                deep: 2,
                distant: 5,
                unavailable: 3,
            },
            "counted",
        )
        .expect("a capped walk warns");
        assert_eq!(
            all,
            "the scan stopped at its depth limit in 2 place(s), its nesting \
             limit in 5 place(s), and storage the tokio info cannot read in 3 \
             place(s); anything beyond any of them is not counted \
             (--search-depth moves the depth limit)"
        );
    }

    /// A walk that refused nothing says nothing, for the reason an
    /// uncapped one does: on every healthy target this is zero, and a
    /// line printed there would be the noise that hides the run where
    /// it is not.
    #[test]
    fn test_a_walk_that_refused_nothing_warns_of_nothing() {
        assert_eq!(census_refused_warning(0, "listed"), None);
    }

    /// A refusal names what was refused and what the listing it
    /// shortened was claiming to cover — and says that the finds under
    /// the ones dropped went with them, which is the part a reader
    /// cannot see from the listing.
    #[test]
    fn test_a_refusal_says_what_the_listing_is_missing() {
        assert_eq!(
            census_refused_warning(3, "counted").expect("a refusing walk warns"),
            "the allocator has taken back the memory 3 find(s) lay in; \
             they and anything they held are not counted"
        );
    }

    /// A walk that read every local it was offered says nothing; one
    /// that skipped locals the layout could not vouch for says how
    /// many, why, and what the listing it shortened was claiming to
    /// cover.
    #[test]
    fn test_uncertain_locals_are_counted_in_the_warning() {
        assert_eq!(census_uncertain_warning(0, "listed"), None);
        assert_eq!(
            census_uncertain_warning(2, "counted").expect("an uncertain walk warns"),
            "the census did not read 2 locals whose initialization the tokio info cannot \
             vouch for (an async block's captures after its first poll); a future held \
             in one is not counted"
        );
    }

    /// Both at once is one sentence carrying both counts, rather than
    /// one limit standing for the other or two warnings for one walk.
    #[test]
    fn test_both_limits_are_reported_together() {
        let both = census_capped_warning(
            Capped {
                deep: 2,
                distant: 5,
                unavailable: 0,
            },
            "listed",
        )
        .expect("a capped walk warns");
        assert_eq!(
            both,
            "the scan stopped at its depth limit in 2 place(s) and its \
             nesting limit in 5 place(s); anything beyond either is not listed \
             (--search-depth moves the depth limit)"
        );
    }
}

#[cfg(test)]
mod census_listing_tests {
    use super::{Entry, Finds, Listing, bundle, census, census_counts, print_future_entry};
    use hansei_runtime::tokio::assess::ContinuationStatus;

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::TaskState;
    use hansei_runtime::tokio::census::Via;

    use std::collections::HashMap;

    fn held(owner: usize, via: Option<Via>) -> census::HeldFuture {
        census::HeldFuture {
            owner,
            frame: 0,
            local: "fut".to_string(),
            via,
            slot: 0x1000,
            addr: 0x1000,
            ty: BundleTypeId(0),
            depth: 1,
            frames: Vec::new(),
            future: crate::typenames::testing::named("app::work"),
            state: None,
            waiting_on: None,
            wait: None,
            observation: None,
            request: None,
            continuation: ContinuationStatus::Unresumed,
        }
    }

    fn set_child(future: Option<&str>) -> census::SetChild {
        census::SetChild {
            node: 0x4000,
            depth: 1,
            future: future.map(crate::typenames::testing::named),
            root: None,
            state: None,
            waiting_on: None,
            wait: None,
            observation: None,
            request: None,
            continuation: ContinuationStatus::Unresumed,
        }
    }

    fn future_set(owner: usize) -> census::FutureSet {
        census::FutureSet {
            owner,
            frame: 1,
            local: "unordered".to_string(),
            via: None,
            addr: 0x2000,
            ty: crate::typenames::testing::named("FuturesUnordered"),
            children: vec![set_child(Some("app::child")), set_child(None)],
        }
    }

    fn joined(id: Option<u64>) -> census::JoinedTask {
        census::JoinedTask {
            entry: 0x5000,
            task: 0x6000,
            id,
            state: TaskState(0),
            listed: false,
        }
    }

    fn join_set(owner: usize, length: u64, children: Vec<census::JoinedTask>) -> census::JoinSet {
        census::JoinSet {
            owner,
            frame: 0,
            local: "workers".to_string(),
            via: None,
            addr: 0x3000,
            ty: crate::typenames::testing::named("JoinSet<()>"),
            length,
            children,
        }
    }

    /// Counts are keyed by the owning task's index in the task list, and
    /// only a find at the top of the listing is counted — one the census
    /// reached through another is inside it.
    #[test]
    fn test_census_counts_key_by_owner_and_skip_nested_finds() {
        let held_list = vec![held(2, None), held(2, Some(Via::Held(0)))];
        let sets = vec![future_set(3)];
        let join_sets = vec![join_set(2, 2, vec![joined(Some(7)), joined(None)])];
        let finds = Finds {
            held: &held_list,
            sets: &sets,
            join_sets: &join_sets,
        };
        let counts = census_counts(finds);

        assert_eq!(counts.keys().copied().collect::<Vec<_>>(), [2, 3]);
        let two = counts[&2];
        assert_eq!((two.held, two.join_sets, two.joined), (1, 1, 2));
        assert_eq!((two.sets, two.children_live), (0, 0));
        let three = counts[&3];
        assert_eq!((three.sets, three.children_live), (1, 1));
        assert_eq!(three.held, 0);
        // The table's count: what is held plus what the sets hold
        // live, never the joined tasks.
        assert_eq!((two.futures(), three.futures()), (1, 1));
    }

    /// Under a fit width, a row's name is cut to the room its other
    /// columns leave — the address and frame before it, the state after
    /// it, all kept — on every row kind, and left whole with no width.
    #[test]
    fn test_a_fit_width_cuts_the_names_and_keeps_the_columns() {
        use crate::typenames::testing::{LONG, LONG_JOIN_SET, LONG_SET, named};
        let long = LONG;
        let mut held_future = held(0, None);
        held_future.future = named(LONG);
        held_future.state = Some("Suspend0 — app.rs:9".to_string());
        let held_list = [held_future];
        let mut set = future_set(0);
        set.ty = named(LONG_SET);
        set.children[0].future = Some(named(LONG));
        let sets = [set];
        let mut joined_set = join_set(0, 0, vec![]);
        joined_set.ty = named(LONG_JOIN_SET);
        let join_sets = [joined_set];
        let nested = HashMap::new();
        let list = bundle::TaskList::new(vec![]);
        let polling = HashMap::new();
        let blocking = HashMap::new();
        let show = |fit: Option<usize>| {
            let listing = Listing {
                blocking_lwps: &blocking,
                fit,
                finds: Finds {
                    held: &held_list,
                    sets: &sets,
                    join_sets: &join_sets,
                },
                nested: &nested,
                list: &list,
                polling: &polling,
                names: crate::typenames::testing::type_names(),
            };
            let mut out = Vec::new();
            for entry in [Entry::Held(0), Entry::Set(0), Entry::JoinSet(0)] {
                print_future_entry(entry, &listing, 0, false, &mut out)
                    .expect("printing a row succeeds");
            }
            String::from_utf8(out).expect("the listing is utf8")
        };

        // Fitted: every row that carried the long name is exactly the
        // width, its name ending in an ellipsis, its other columns
        // intact.
        let fitted = show(Some(100));
        let rows: Vec<&str> = fitted.lines().collect();
        assert_eq!(rows.len(), 5, "{fitted}");
        for row in [rows[0], rows[1], rows[2], rows[4]] {
            assert_eq!(row.chars().count(), 100, "{row}");
            assert!(row.contains('…'), "{row}");
        }
        assert!(
            rows[0].starts_with("(frame 0, `fut`): 0x1000  future app::"),
            "{fitted}"
        );
        assert!(rows[0].ends_with("…  Suspend0 — app.rs:9"), "{fitted}");
        assert!(rows[1].starts_with("- Futures"), "{fitted}");
        assert!(
            rows[1].ends_with(
                "… at 0x2000 (frame 1, `unordered`): 1 child in flight, \
                 1 completed and not yet reaped"
            ),
            "{fitted}"
        );
        assert!(rows[2].starts_with("    0x4000  future app::"), "{fitted}");
        assert_eq!(
            rows[3], "    0x4000  <completed, not yet reaped>",
            "{fitted}"
        );
        assert!(rows[4].starts_with("- JoinSet<app::"), "{fitted}");
        assert!(
            rows[4].ends_with("… at 0x3000 (frame 0, `workers`): 0 tasks"),
            "{fitted}"
        );

        // No width: every name whole.
        let whole = show(None);
        assert!(!whole.contains('…'), "{whole}");
        assert_eq!(whole.matches(long).count(), 4, "{whole}");
    }

    /// A join set's row carries the count the walk reached; what the set
    /// records for itself is appended only when the walk fell short of
    /// it, since that is the row the stderr error belongs to.
    #[test]
    fn test_short_join_set_row_reports_the_recorded_length() {
        let nested = HashMap::new();
        let list = bundle::TaskList::new(vec![]);
        let polling = HashMap::new();
        let blocking = HashMap::new();
        let show = |set: &census::JoinSet| {
            let join_sets = std::slice::from_ref(set);
            let listing = Listing {
                blocking_lwps: &blocking,
                fit: None,
                finds: Finds {
                    held: &[],
                    sets: &[],
                    join_sets,
                },
                nested: &nested,
                list: &list,
                polling: &polling,
                names: crate::typenames::testing::type_names(),
            };
            let mut out = Vec::new();
            print_future_entry(Entry::JoinSet(0), &listing, 0, false, &mut out)
                .expect("printing a join set row succeeds");
            String::from_utf8(out).expect("the listing is utf8")
        };

        // The walk reached what the set records: no annotation.
        let full = join_set(2, 2, vec![joined(Some(7)), joined(None)]);
        assert_eq!(
            show(&full),
            "- JoinSet<()> at 0x3000 (frame 0, `workers`): 2 tasks\n\
             \x20   task 7  <idle, not in the scheduler's owned tasks>\n\
             \x20   task at 0x6000  <idle, not in the scheduler's owned tasks>\n"
        );

        // The walk fell short: the row says what the set records.
        let short = join_set(2, 5, vec![joined(Some(7))]);
        assert_eq!(
            show(&short),
            "- JoinSet<()> at 0x3000 (frame 0, `workers`): 1 task (the set records 5)\n\
             \x20   task 7  <idle, not in the scheduler's owned tasks>\n"
        );
    }
}

#[cfg(test)]
mod task_state_tests {
    use super::task_state;

    use hansei_runtime::tokio::bundle::{FutureInfo, OwnerResolution, Task, TaskKind};
    use hansei_runtime::tokio::{TaskAddr, TaskState};

    use std::collections::HashMap;

    /// A task in one state, with an id or without.
    fn task(state: u64, task_id: Option<u64>) -> Task {
        Task {
            addr: TaskAddr(0x1000),
            state: TaskState(state),
            owner_id: None,
            task_id,
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
        }
    }

    /// The summary's polling column believes a `Context`'s current-task
    /// word only when the listing agrees — a running task with that very
    /// id. Each leg of that belief is stated apart, because no capture
    /// can: a healthy core never records an id whose task is not
    /// mid-poll, so only a constructed list reaches the disagreeing
    /// arms.
    ///
    /// No fixture cores a target with a task actually running on a
    /// worker, so this too is stated here or nowhere.
    #[test]
    fn test_a_polled_task_is_believed_only_when_the_listing_agrees() {
        use super::polled_task;
        use hansei_runtime::tokio::bundle::TaskList;

        const RUNNING: u64 = 0b0001;
        const IDLE: u64 = 0;
        let list = |state: u64, task_id: Option<u64>| TaskList::new(vec![task(state, task_id)]);

        // The listing shows task 7 running: the word is believed.
        assert_eq!(polled_task(Some(7), &list(RUNNING, Some(7))), Some(7));

        // The id names a task the listing calls idle, a different task,
        // or no task at all: the word is dropped, not repeated.
        assert_eq!(polled_task(Some(7), &list(IDLE, Some(7))), None);
        assert_eq!(polled_task(Some(9), &list(RUNNING, Some(7))), None);
        assert_eq!(polled_task(Some(7), &list(RUNNING, None)), None);

        // No word, nothing to believe.
        assert_eq!(polled_task(None, &list(RUNNING, Some(7))), None);
    }

    /// Which worker is mid-poll on a task is the one thing `running`
    /// alone leaves a reader asking, so it is named where the runtime
    /// says one — and where it does not, the row says only what it
    /// knows rather than the worker it last saw.
    ///
    /// No fixture cores a target with a task actually running on a
    /// worker, so this is stated here or nowhere: on a parked capture
    /// the map is empty and every arm reads the same.
    #[test]
    fn test_a_running_task_names_its_worker_where_there_is_one() {
        const RUNNING: u64 = 0b0001;
        const IDLE: u64 = 0;
        let polling = HashMap::from([(7, 42)]);

        assert_eq!(
            task_state(&task(RUNNING, Some(7)), &polling, &HashMap::new()),
            "running (lwp 42)"
        );

        // Running, but the runtime does not say a worker holds it: some
        // other task's id, or none of its own.
        assert_eq!(
            task_state(&task(RUNNING, Some(9)), &polling, &HashMap::new()),
            "running"
        );
        assert_eq!(
            task_state(&task(RUNNING, None), &polling, &HashMap::new()),
            "running"
        );

        // A worker polling *something* says nothing about a task that
        // is not running, whatever id it carries.
        assert_eq!(
            task_state(&task(IDLE, Some(7)), &polling, &HashMap::new()),
            "idle"
        );
        assert_eq!(
            task_state(&task(RUNNING, Some(7)), &HashMap::new(), &HashMap::new()),
            "running"
        );
    }
}

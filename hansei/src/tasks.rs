// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `tasks` and `census` commands: the task listing and the counts
//! over it, plus the naming helpers every listing shares.

use crate::runtimes::RowOwner;
use crate::{Session, output, print_warnings, repl, summary};

use anyhow::{Context as _, Result};
use hansei_bundle::{BundleTypeId, BundleView, names};
use hansei_runtime::tokio::assess::{
    ContinuationStatus, IncompleteReason, NotWaitingReason, ReadyReason, RunnableReason,
    WaitAssessment, WaitUnknownReason,
};
use hansei_runtime::tokio::graph as rt_graph;
use hansei_runtime::tokio::waitset::{MemberRoute, WaitMember};
use hansei_runtime::tokio::{Lifecycle, RawInstant, attribution, bundle, census};

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::sync::RwLock;

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
    pub(crate) impls: &'a names::ImplFold,
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
            let name = names::display_future_name(&h.future, listing.impls);
            let taken = before.chars().count() + state.chars().count();
            let name = output::fit_name(&name, taken, listing.fit);
            writeln!(out, "{before}{name}{state}")?;
            if let Some(waiting) = &h.waiting_on {
                writeln!(out, "{pad}  waiting on {waiting}")?;
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
            let name = names::fold_type_name(&set.ty, listing.impls);
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
                let name = names::display_future_name(future, listing.impls);
                let taken = before.chars().count() + state.chars().count();
                let name = output::fit_name(&name, taken, listing.fit);
                writeln!(out, "{before}{name}{state}")?;
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
            let name = names::fold_type_name(&set.ty, listing.impls);
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
        let name = future_name(&task.future, listing.impls);
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
pub fn future_name(future: &bundle::FutureInfo, impls: &names::ImplFold) -> String {
    match future {
        bundle::FutureInfo::Known(known) => names::display_future_name(&known.display_name, impls),
        bundle::FutureInfo::Unknown {
            poll_symbol: Some(sym),
        } => format!("<unknown: {:#}>", rustc_demangle::demangle(sym)),
        bundle::FutureInfo::Unknown { poll_symbol: None } => "<unknown>".to_string(),
        bundle::FutureInfo::Ambiguous { candidates, .. } => {
            let candidates: Vec<_> = candidates
                .iter()
                .map(|c| {
                    format!(
                        "{} (type {})",
                        names::fold_type_name(&c.name, impls),
                        c.ty.0
                    )
                })
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
    /// What would wake the task: every live slot holding its waker,
    /// each spelled by what holds it and — where the task's own
    /// assessment accounts for the slot — by that reader's detail,
    /// sorted and comma-joined, so a `select!` over a timer and a
    /// channel names both. `unarmed: ` before the assessment's own
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
    /// The detail lines under the wait: what the assessment has to say
    /// beyond the cell, then one line per slot — where it sits, and
    /// what says it is current.
    pub(crate) wait_detail: Vec<String>,
    /// Whether those lines carry every word of the cell — a wait
    /// set's entries, each on its slot's line; a verified target,
    /// heading the line of the slot it accounts for — so the task
    /// block prints the lines under a bare `waiting on:` rather than
    /// the cell and then the lines again.
    pub(crate) wait_listed: bool,
    /// The root future's display name, folded and never truncated.
    pub(crate) future: String,
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
        &session.impl_fold,
        blocking_lwps(session),
        &StopNames::of(session),
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
    apply_slots(
        &mut rows,
        &session.tasks,
        &session.analysis().waits,
        session.attribution(),
        session.registries.stopped,
        &|ty| view.ty(ty).map(|t| t.size()),
        &StopNames::of(session),
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
    impls: &names::ImplFold,
    blocking_lwps: &HashMap<u64, u32>,
    stops: &StopNames<'_>,
) -> Vec<TaskRow> {
    list.tasks
        .iter()
        .enumerate()
        .map(|(index, task)| {
            let lwp = task_lwp(task, polling, blocking_lwps);
            TaskRow {
                id: task_id(list, index),
                state: row_state(task, lwp),
                rt: RowOwner::of(task, owners),
                awaiting_at: waits
                    .get(index)
                    .and_then(|w| w.site.as_ref())
                    .map(|(file, line)| format!("{file}:{line}")),
                waiting_on: waiting_on(task, waits.get(index), polling, stops),
                waiting_kind: waiting_kind(task, waits.get(index), stops),
                wait_detail: waits
                    .get(index)
                    .map(|wait| wait_detail(wait, stops, &[], None, &|_| None))
                    .unwrap_or_default(),
                wait_listed: false,
                future: future_name(&task.future, impls),
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
pub(crate) fn apply_slots(
    rows: &mut [TaskRow],
    list: &bundle::TaskList,
    waits: &[rt_graph::TaskWait],
    slots: &attribution::Attributed,
    stopped: Option<RawInstant>,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
    stops: &StopNames<'_>,
) {
    for (index, (row, task)) in rows.iter_mut().zip(&list.tasks).enumerate() {
        if task.is_blocking() || task.state.lifecycle() == Lifecycle::Running {
            continue;
        }
        let Some(wait) = waits.get(index) else {
            continue;
        };
        row.waiting_on = assessment_cell(wait, stops);
        row.waiting_kind = assessment_kind(wait, stops);
        let owned: Vec<&attribution::AttributedSlot> = slots.of_task(task.addr.0).collect();
        if owned.is_empty() {
            row.wait_detail = wait_detail(wait, stops, &[], stopped, size_of);
            if !row.waiting_on.starts_with('—') {
                row.waiting_on = format!("unarmed: {}", row.waiting_on);
                row.waiting_kind = row.waiting_kind.take().map(|k| format!("unarmed: {k}"));
            }
            continue;
        }
        row.wait_detail = wait_detail(wait, stops, &owned, stopped, size_of);
        row.wait_listed = cell_in_detail(wait, &owned, size_of);
    }
}

/// Whether the detail lines carry the cell whole: a wait set's cell
/// is its members' entries, and each armed member's line opens with
/// its entry; a verified wait's cell is its target, and the line of
/// the slot the target accounts for opens with it. Every other cell —
/// a stop's type, a reason, `ready` — says something the lines do
/// not, and stays on the wait line.
fn cell_in_detail(
    wait: &rt_graph::TaskWait,
    slots: &[&attribution::AttributedSlot],
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> bool {
    match &wait.assessment {
        WaitAssessment::Set(_) => !slots.is_empty(),
        WaitAssessment::Waiting(verified) => slots
            .iter()
            .any(|slot| attribution::verified_accounts(verified, slot, size_of)),
        _ => false,
    }
}

/// The cell and the bucket a list of slots spells: entries sorted and
/// comma-joined, `unknown` entries past the first collapsed to their
/// count, buckets sorted, distinct and comma-joined.
pub(crate) fn slot_cell(
    slots: &[&attribution::AttributedSlot],
    stopped: Option<RawInstant>,
    accounted: &dyn Fn(&attribution::AttributedSlot) -> Option<(String, String)>,
) -> (String, String) {
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut unknown = 0usize;
    for slot in slots {
        if matches!(slot.attribution, attribution::Attribution::Unknown) {
            unknown += 1;
            if unknown > 1 {
                continue;
            }
        }
        entries.push(accounted(slot).unwrap_or_else(|| (slot.entry(stopped), slot.bucket())));
    }
    if unknown > 1 {
        for entry in &mut entries {
            if entry.1 == "unknown" {
                entry.0 = format!("{unknown}× unknown");
            }
        }
    }
    entries.sort();
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

/// One detail line per slot, sorted: where it sits and what says it
/// is current, a wheel entry by its deadline.
pub(crate) fn slot_lines(
    slots: &[&attribution::AttributedSlot],
    stopped: Option<RawInstant>,
) -> Vec<String> {
    let mut lines: Vec<String> = slots.iter().map(|slot| slot.line(stopped)).collect();
    lines.sort();
    lines
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
    stops: &StopNames<'_>,
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

/// The one-word (or one-target) spelling of an assessment: the
/// `WAITING ON` cell every listing shares, so a task, a future and a
/// tally agree on what a wait is called. A wait set lists its armed
/// members, sorted and comma-joined, so a set of one reads as the wait
/// it is. An unknown says what made it one ([`unknown_cell`]), and one
/// whose stop holds futures none of which is armed counts them.
pub(crate) fn assessment_cell(wait: &rt_graph::TaskWait, stops: &StopNames<'_>) -> String {
    match &wait.assessment {
        WaitAssessment::Waiting(verified) => verified.target().to_string(),
        WaitAssessment::Set(set) => set.cell(),
        WaitAssessment::ResourceReady(_) => "ready".to_string(),
        WaitAssessment::Unknown(_) => match wait.held_count() {
            0 => unknown_cell(wait, stops),
            1 => format!("{} (holds 1 future)", unknown_cell(wait, stops)),
            n => format!("{} (holds {n} futures)", unknown_cell(wait, stops)),
        },
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
pub(crate) fn assessment_kind(wait: &rt_graph::TaskWait, stops: &StopNames<'_>) -> Option<String> {
    match &wait.assessment {
        WaitAssessment::Waiting(verified) => Some(verified.target().group_label()),
        WaitAssessment::Set(set) => Some(set.group_label()),
        WaitAssessment::ResourceReady(_) => Some("ready".to_string()),
        WaitAssessment::Unknown(_) => Some(unknown_cell(wait, stops)),
        WaitAssessment::Unresumed | WaitAssessment::NotWaiting(_) | WaitAssessment::Runnable(_) => {
            None
        }
    }
}

/// What an unknown assessment says for itself in the cell — the same
/// words its bucket uses, since neither has a target to name: the
/// type the chain stopped at, how it was cut short, or the reason a
/// primitive's protocol declined.
fn unknown_cell(wait: &rt_graph::TaskWait, stops: &StopNames<'_>) -> String {
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
/// primitive nothing described is the bare `unknown`. `None` for a
/// terminal or mid-poll end, which waits on nothing.
pub(crate) fn continuation_bucket(
    continuation: &ContinuationStatus,
    stops: &StopNames<'_>,
) -> Option<String> {
    match continuation {
        ContinuationStatus::Primitive => Some("unknown".to_string()),
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

/// How the listings name the type an unknown continuation stopped at:
/// the bundle's spelling, folded for display and cut to its path.
/// Built over the session's bundle; over none for a listing test laid
/// out by hand, where every stop is nameless.
pub(crate) struct StopNames<'a> {
    view: Option<BundleView<'a>>,
    impls: &'a names::ImplFold,
    /// Labels by type id. A listing's stops are a few dozen types over
    /// tens of thousands of rows, and each label is a fold pass over
    /// the name — 0.4 s of wall time (0.9 s of CPU) across the nexus
    /// core's futures rows uncached, against a 1.5 s launch.
    labels: RwLock<HashMap<BundleTypeId, Option<String>>>,
}

impl<'a> StopNames<'a> {
    pub(crate) fn of<T: proc::Target>(session: &'a Session<'_, T>) -> Self {
        StopNames {
            view: Some(session.ctx.view),
            impls: &session.impl_fold,
            labels: RwLock::default(),
        }
    }

    /// No bundle to name a stop from.
    #[cfg(test)]
    pub(crate) fn none(impls: &'a names::ImplFold) -> Self {
        StopNames {
            view: None,
            impls,
            labels: RwLock::default(),
        }
    }

    /// The stop's label, or `None` where the type is not in the bundle.
    fn label(&self, ty: BundleTypeId) -> Option<String> {
        if let Some(label) = self.labels.read().unwrap().get(&ty) {
            return label.clone();
        }
        let label = self
            .view
            .and_then(|view| view.ty(ty))
            .map(|ty| stop_label(ty.name(), self.impls));
        self.labels
            .write()
            .unwrap()
            .entry(ty)
            .or_insert(label)
            .clone()
    }
}

/// The label a stop type buckets under: its path folded for display
/// and cut of its generic arguments — `futures_util::future::Map` —
/// with a coroutine's kind word in front, as the listings spell one
/// (`async fn app::serve`).
pub(crate) fn stop_label(name: &str, impls: &names::ImplFold) -> String {
    let path = names::outer_path(&names::fold_type_name(name, impls));
    match names::coroutine_kind(name) {
        Some(kind) => format!("{kind} {path}"),
        None => path,
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

/// The detail lines under a row's wait. What the assessment has to say
/// beyond the cell where it is a word rather than a place (`ready:`,
/// `unknown:` with a reason other than the continuation — an unknown
/// stop is named by the cell); then, at a stop that polls several
/// things, one line per branch the census could read, each armed by
/// the slots that sit in it or were reached through it, or `held, not
/// armed`; then one line per remaining slot — where it sits and what
/// says it is current, a wheel entry by its deadline. Any one slot
/// wakes the task; nothing here is a dependency.
pub(crate) fn wait_detail(
    wait: &rt_graph::TaskWait,
    stops: &StopNames<'_>,
    slots: &[&attribution::AttributedSlot],
    stopped: Option<RawInstant>,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> Vec<String> {
    let mut lines = Vec::new();
    match &wait.assessment {
        WaitAssessment::ResourceReady(reason) => {
            lines.push(format!("ready: {}", ready_reason(*reason)));
        }
        WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {}
        WaitAssessment::Unknown(reason) => {
            lines.push(format!("unknown: {}", unknown_reason(*reason)));
        }
        WaitAssessment::Waiting(_) => lines.extend(wait.notes.iter().cloned()),
        WaitAssessment::Set(_)
        | WaitAssessment::Unresumed
        | WaitAssessment::NotWaiting(_)
        | WaitAssessment::Runnable(_) => {}
    }
    let (members, capped) = match &wait.assessment {
        WaitAssessment::Set(set) => (set.members.as_slice(), set.capped),
        WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {
            (wait.held.as_slice(), wait.held_capped)
        }
        _ => (&[][..], 0),
    };
    let mut rest: Vec<&attribution::AttributedSlot> = slots.to_vec();
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
        let line = member_line(member, stops, &mine, stopped);
        // An entry reached through a member listed before it — a
        // branch whose chain ends at the map, a local holding one —
        // sits one step under that member; an entry of a stop that is
        // the map itself is a branch of the stop like any other.
        match &member.route {
            MemberRoute::Entry { under: Some(_), .. } => lines.push(format!("    {line}")),
            _ => lines.push(line),
        }
    }
    if capped > 0 {
        lines.push(format!("{capped} more branches not inspected"));
    }
    // The remaining slots, each headed by its entry — the reading
    // included, since no cell above carries it — except that the slot
    // a verified target accounts for is headed by the target itself,
    // the way a branch line is: the verdict, then what arms it. A
    // wheel entry's own line already says everything its target does.
    let verified = match &wait.assessment {
        WaitAssessment::Waiting(verified) => Some(verified),
        _ => None,
    };
    let mut slot_lines: Vec<String> = rest
        .iter()
        .map(|slot| match verified {
            Some(verified) if attribution::verified_accounts(verified, slot, size_of) => {
                let wheel = matches!(
                    slot.attribution,
                    attribution::Attribution::Registry(attribution::RegistrySlot::Timer { .. })
                );
                match slot.detail(stopped) {
                    Some(detail) if !wheel => {
                        format!("{}; armed: {detail}", verified.target())
                    }
                    _ => slot.line(stopped),
                }
            }
            _ => slot.entry_line(stopped),
        })
        .collect();
    slot_lines.sort();
    lines.extend(slot_lines);
    lines
}

/// A registry slot in no branch, as the analysis placed it, for a
/// session with no sweep to spell it as a slot.
fn slot_only_line(member: &WaitMember, within: Option<&str>) -> String {
    let name = member.cell_entry().unwrap_or_else(|| "a slot".to_string());
    let evidence = member
        .armed
        .as_ref()
        .and_then(hansei_runtime::tokio::waitset::SlotRef::detail)
        .map(|evidence| format!(": {evidence}"))
        .unwrap_or_default();
    let within = within.map(|w| format!(", {w}")).unwrap_or_default();
    format!("{name}{evidence}{within}; in no branch of the stop")
}

/// One branch's line: its local — or its `select!` branch number —
/// whether it was borrowed, the future it is and where, the engine's
/// verdict on it, and what arms it — the slots that sit in it or were
/// reached through it, else the registry or protocol evidence the
/// analysis had, else `held, not armed`. A `select!` branch its mask
/// has disabled is named and nothing more: `disabled` is the whole
/// verdict, and why it is — a false precondition, a completed output
/// that missed its pattern — is not in memory to be read.
fn member_line(
    member: &WaitMember,
    stops: &StopNames<'_>,
    armed_by: &[&attribution::AttributedSlot],
    stopped: Option<RawInstant>,
) -> String {
    let (local, borrowed) = match &member.route {
        MemberRoute::Branch { local, borrowed } => (local.clone(), *borrowed),
        MemberRoute::Select { index, borrowed } => (format!("branch {index}"), *borrowed),
        MemberRoute::Disabled { index, ty } => {
            let future = stops
                .label(*ty)
                .or_else(|| member.future.clone())
                .unwrap_or_default();
            return format!("branch {index}: {future}: disabled");
        }
        MemberRoute::Entry {
            index, borrowed, ..
        } => (format!("entry {index}"), *borrowed),
        MemberRoute::SlotOnly { .. } => unreachable!("only branches print as members"),
    };
    let via = if borrowed { " (borrowed)" } else { "" };
    let future = member
        .key
        .and_then(|key| stops.label(key.ty))
        .or_else(|| member.future.clone())
        .unwrap_or_default();
    let at = member
        .key
        .map(|key| format!(" at {:#x}", key.addr))
        .unwrap_or_default();
    // A member that fans out — a map polled with this task's own
    // context, or a chain ending at one — is listed for its entries,
    // which follow it: it holds no waker of this task's itself, so
    // nothing arms it, and the verdict is the count. Any one entry
    // wakes the task.
    if let Some(fanout) = member.entries {
        let inspected = if fanout.listed < fanout.total {
            format!(" ({} inspected)", fanout.listed)
        } else {
            String::new()
        };
        let verdict = match fanout.total {
            0 => "no entries".to_string(),
            1 => "1 entry, which wakes it".to_string(),
            n => format!("{n} entries{inspected}, any one wakes it"),
        };
        let mut line = format!("{local}{via}: {future}{at} — {verdict}");
        for note in &member.notes {
            line.push_str("; ");
            line.push_str(note);
        }
        return line;
    }
    let verdict = match &member.assessment {
        Some(WaitAssessment::Waiting(verified)) => verified.target().to_string(),
        Some(WaitAssessment::Set(set)) => set.cell(),
        Some(WaitAssessment::ResourceReady(reason)) => {
            format!("ready: {}", ready_reason(*reason))
        }
        Some(WaitAssessment::Unknown(WaitUnknownReason::Continuation)) => "unknown".to_string(),
        Some(WaitAssessment::Unknown(reason)) => format!("unknown ({})", unknown_word(*reason)),
        Some(WaitAssessment::Unresumed) => "never polled".to_string(),
        Some(WaitAssessment::NotWaiting(NotWaitingReason::Returned)) => "returned".to_string(),
        Some(WaitAssessment::NotWaiting(NotWaitingReason::Panicked)) => "panicked".to_string(),
        Some(WaitAssessment::NotWaiting(NotWaitingReason::Complete)) => "complete".to_string(),
        Some(WaitAssessment::Runnable(_)) => "runnable".to_string(),
        None => "not inspected".to_string(),
    };
    let armed = if !armed_by.is_empty() {
        // A verified verdict names the primitive and its words, so the
        // slot is headed by its label; any other verdict leaves the
        // words to the slot's entry.
        let named = matches!(member.assessment, Some(WaitAssessment::Waiting(_)));
        let mut slots: Vec<String> = armed_by
            .iter()
            .map(|s| match named {
                true => s.line(stopped),
                false => s.entry_line(stopped),
            })
            .collect();
        slots.sort();
        format!("armed: {}", slots.join("; "))
    } else {
        match (&member.armed, &member.assessment) {
            (Some(slot), Some(WaitAssessment::Waiting(_))) => slot
                .detail()
                .or_else(|| slot.cell_entry())
                .unwrap_or_default(),
            (Some(slot), _) => match (member.cell_entry(), slot.detail()) {
                (Some(entry), Some(detail)) => format!("{entry}: {detail}"),
                (Some(entry), None) => entry,
                (None, detail) => detail.unwrap_or_default(),
            },
            (None, _) => "held, not armed".to_string(),
        }
    };
    let mut line = format!("{local}{via}: {future}{at} — {verdict}; {armed}");
    for note in &member.notes {
        line.push_str("; ");
        line.push_str(note);
    }
    line
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
    stops: &StopNames<'_>,
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
    pub(crate) impls: &'a names::ImplFold,
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
        match row.wait_listed {
            true => writeln!(out, "    waiting on:")?,
            false => writeln!(out, "    waiting on: {}", row.waiting_on)?,
        }
        for line in &row.wait_detail {
            writeln!(out, "        {line}")?;
        }
    }
    if let Some(loc) = &task.spawn_location {
        writeln!(out, "    spawned at: {loc}")?;
    }
    if let bundle::FutureInfo::Known(known) = &task.future
        && let Some((file, line)) = &known.decl
    {
        writeln!(out, "    defined at: {file}:{line}")?;
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
        impls: view.impls,
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
    let polling = polling_map(session);
    let view = TaskView {
        list: &session.tasks,
        rows: rows(session),
        impls: &session.impl_fold,
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
        Field::WaitingOn => Some(&row.waiting_on),
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
/// value and print `COUNT VALUE` rows, most numerous first (ties in
/// value order), each with up to three member ids. `--limit` cuts
/// buckets.
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
    let mut grouped: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &index in &survivors {
        let value = group_value(field, index, &rows[index], counts.as_ref())
            .unwrap_or_else(|| EMPTY_BUCKET.to_string());
        grouped.entry(value).or_default().push(index);
    }
    let mut buckets: Vec<(String, Vec<usize>)> = grouped.into_iter().collect();
    // Count descending; the map already ordered ties by value, and the
    // sort is stable.
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
    let parsed = repl::parse_exec_command(&cmd.exec).context("--exec")?;
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
        let command = repl::parse_exec_command(&cmd.exec).expect("parsed above");
        crate::cursor::scope_to(session, index);
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

    let facts = summary::Facts {
        lwps: session.lwps.iter().map(|lwp| lwp.tid).collect(),
        runtime,
        runtimes,
        local_sets: session.local_sets.len(),
        tasks: &session.tasks,
        waits: analysis.map(|analysis| &analysis.waits[..]).unwrap_or(&[]),
        held: census.map(|census| &census.held[..]).unwrap_or(&[]),
        sets: census.map(|census| &census.sets[..]).unwrap_or(&[]),
        impls: &session.impl_fold,
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
        runtime.push(summary::Thread {
            tid: worker.tid,
            runtime: session.runtime_of(worker.tid).map(|(index, _)| index),
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

#[cfg(test)]
mod table_tests {
    use super::{
        StopNames, build_rows, listing_footer, member_line, print_task_table, stop_label,
        wait_detail,
    };

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
    const RUNNING: u64 = 0b0001;
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
                ty: BundleTypeId(0),
            }),
            future: Some("x::branch".to_string()),
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
                ty: BundleTypeId(0),
            },
            key: None,
            future: Some("x::skipped".to_string()),
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
            },
            ..branch("", assessment, armed)
        }
    }

    fn one_of(members: Vec<WaitMember>) -> WaitAssessment {
        WaitAssessment::Set(WaitSet {
            at: Some(ValueKey {
                addr: 0x5000,
                ty: BundleTypeId(7),
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
            &hansei_bundle::names::ImplFold::default(),
            &Default::default(),
            &StopNames::none(&Default::default()),
        )
    }

    /// A member that fans out is listed for its count and arms nothing
    /// itself: the count, with how many were inspected where the cap
    /// cut it short, and no verdict or slot text; its entries follow
    /// as `entry N` lines one step in, while an entry of a stop that
    /// is the map itself sits at the top like any branch.
    #[test]
    fn test_a_fan_out_member_lists_its_count_and_nests_its_entries() {
        let entry = |index: usize, under: Option<MemberRoute>| WaitMember {
            route: MemberRoute::Entry {
                index,
                under: under.map(Box::new),
                borrowed: false,
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
            },
            assessment: None,
            entries: Some(hansei_runtime::tokio::waitset::Fanout { listed, total }),
            ..branch("m", WaitAssessment::Unresumed, true)
        };
        let impls = Default::default();
        let stops = StopNames::none(&impls);
        let line = |member: &WaitMember| member_line(member, &stops, &[], None);
        assert_eq!(
            line(&fanning(3, 3)),
            "branch 1 (borrowed): x::branch at 0x6000 — 3 entries, any one wakes it"
        );
        assert_eq!(
            line(&fanning(8, 12)),
            "branch 1 (borrowed): x::branch at 0x6000 — 12 entries (8 inspected), any one wakes it"
        );
        assert_eq!(
            line(&fanning(1, 1)),
            "branch 1 (borrowed): x::branch at 0x6000 — 1 entry, which wakes it"
        );
        assert_eq!(
            line(&fanning(0, 0)),
            "branch 1 (borrowed): x::branch at 0x6000 — no entries"
        );
        let under = MemberRoute::Select {
            index: 1,
            borrowed: true,
        };
        let wait = assessed(
            1,
            one_of(vec![
                fanning(2, 2),
                entry(0, Some(under.clone())),
                entry(1, Some(under)),
                entry(0, None),
            ]),
        );
        let lines = wait_detail(&wait, &stops, &[], None, &|_| None);
        assert_eq!(
            lines,
            [
                "branch 1 (borrowed): x::branch at 0x6000 — 2 entries, any one wakes it",
                "    entry 0: x::branch at 0x6000 — unknown; held, not armed",
                "    entry 1: x::branch at 0x6000 — unknown; held, not armed",
                "entry 0: x::branch at 0x6000 — unknown; held, not armed",
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
                ty: BundleTypeId(7),
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
        assert_eq!(
            stop_label(
                "futures_util::future::map::Map<hyper::client::conn::Connection<A, B>, \
                 hyper_util::client::legacy::{closure_env#3}>",
                &impls
            ),
            "futures_util::future::map::Map"
        );
        assert_eq!(
            stop_label("app::serve::{async_fn_env#0}", &impls),
            "async fn app::serve"
        );
        assert_eq!(
            stop_label(
                "core::future::poll_fn::PollFn<app::run::{async_fn_env#0}::{closure_env#1}>",
                &impls
            ),
            "core::future::poll_fn::PollFn"
        );
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
                ty: BundleTypeId(7),
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
        assert_eq!(
            rows[0].waiting_on,
            "io 0x7000 (readable), timer (deadline +10.000s)"
        );
        assert_eq!(rows[0].waiting_kind.as_deref(), Some("io, timer"));
        assert_eq!(
            rows[0].wait_detail,
            [
                "a: x::branch at 0x6000 — timer (deadline +10.000s); its protocol read this \
                 task's waker",
                "b: x::branch at 0x6000 — unknown; held, not armed",
                "io 0x7000 (readable): this task's waker in the read-waiter slot, inside #1's \
                 storage at +0x10; in no branch of the stop",
                "1 more branches not inspected",
            ]
        );
        assert_eq!(rows[1].waiting_on, "unknown (holds 3 futures)");
        assert_eq!(rows[1].waiting_kind.as_deref(), Some("unknown"));
        assert_eq!(
            rows[1].wait_detail,
            [
                "a: x::branch at 0x6000 — unknown; held, not armed",
                "b: x::branch at 0x6000 — unknown; held, not armed",
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
                ty: BundleTypeId(7),
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
        assert_eq!(rows[0].waiting_on, "timer (deadline +10.000s)");
        assert_eq!(
            rows[0].wait_detail,
            [
                "branch 0 (borrowed): x::branch at 0x6000 — unknown; held, not armed",
                "branch 1 (borrowed): x::branch at 0x6000 — timer (deadline +10.000s); its \
                 protocol read this task's waker",
                "branch 2: x::skipped: disabled",
            ]
        );
        assert_eq!(rows[1].waiting_on, "unknown (holds 1 future)");
        assert_eq!(
            rows[1].wait_detail,
            [
                "branch 0 (borrowed): x::branch at 0x6000 — unknown; held, not armed",
                "branch 1: x::skipped: disabled",
            ]
        );
        assert_eq!(rows[2].waiting_on, "unknown");
        assert_eq!(
            rows[2].wait_detail,
            [
                "branch 0: x::skipped: disabled",
                "branch 1: x::skipped: disabled"
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
        assert!(
            rows[0].waiting_on.starts_with("timer (deadline 12.000s"),
            "{}",
            rows[0].waiting_on
        );
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
        // `defined` value.
        assert_eq!(rows[0].spawned, None);
        assert_eq!(rows[0].defined, None);
        let known = rows_of(
            vec![Task {
                future: FutureInfo::Known(hansei_runtime::tokio::bundle::KnownFuture {
                    entry: hansei_bundle::TaskEntryId(0),
                    display_name: "app::work::{async_fn_env#0}".to_string(),
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
            &hansei_bundle::names::ImplFold::default(),
            &HashMap::from([(0x1000 + 2 * 0x100, 42)]),
            &StopNames::none(&Default::default()),
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
            "2× unknown, io 0xaa00 read, join task 2, semaphore 0x9000, timer 0xdd00"
        );
        assert_eq!(
            rows[0].waiting_kind.as_deref(),
            Some("io read, join task 2, semaphore 0x9000, timer, unknown")
        );
        // One line per slot, sorted; a stop's own reason is the cell's.
        assert_eq!(
            rows[0].wait_detail,
            vec![
                "io 0xaa00 read: awaiting readable via the read-waiter slot".to_string(),
                "join task 2: waker in its trailer".to_string(),
                "semaphore 0x9000: waker in its wake-queue node 0xe100".to_string(),
                "timer 0xdd00".to_string(),
                "unknown @ 0x7000".to_string(),
                "unknown @ 0x8000".to_string(),
            ]
        );
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
        // One unknown slot is named by its address; only several
        // collapse to a count.
        assert_eq!(rows[3].waiting_on, "unknown @ 0x7100");
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
        // The join heads the trailer slot's line, so the lines carry
        // the cell whole; the timer stands as the slot it is.
        assert_eq!(
            rows[0].wait_detail,
            ["task 2; armed: waker in its trailer", "timer 0xdd00"]
        );
        assert!(rows[0].wait_listed);
    }

    /// The rows as the launch builds them: the slots folded into each
    /// wait, then the rows built from the waits and finished against
    /// the slots.
    fn folded_rows(
        list: &TaskList,
        waits: &mut [TaskWait],
        slots: &hansei_runtime::tokio::attribution::Attributed,
    ) -> Vec<super::TaskRow> {
        for (task, wait) in list.tasks.iter().zip(waits.iter_mut()) {
            let owned: Vec<_> = slots.of_task(task.addr.0).collect();
            if !owned.is_empty() {
                hansei_runtime::tokio::waitset::fold_wait(task, wait, &owned, None, &|_| None);
            }
        }
        let impls = Default::default();
        let stops = StopNames::none(&impls);
        let mut rows = build_rows(
            list,
            &Default::default(),
            waits,
            &HashMap::new(),
            &hansei_bundle::names::ImplFold::default(),
            &Default::default(),
            &stops,
        );
        super::apply_slots(&mut rows, list, waits, slots, None, &|_| None, &stops);
        rows
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
            wait_listed: false,
            future: "async fn app::work".to_string(),
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
        r.waiting_on = "timer (deadline +38.364s)".to_string();
        r.spawned = Some("src/main.rs:10:5".to_string());
        r.defined = Some("src/app.rs:7".to_string());

        assert!(keeps(&clause("type", "APP::WORK"), &r));
        assert!(!keeps(&clause("type", "qorb"), &r));
        assert!(keeps(&clause("state", "cancelled"), &r));
        assert!(keeps(&clause("awaiting", "app.rs:42$"), &r));
        assert!(keeps(&clause("waiting-on", "^timer"), &r));
        assert!(keeps(&clause("spawned", "main.rs"), &r));
        assert!(keeps(&clause("defined", "app.rs:7"), &r));
        r.waiting_on = "task 2, timer (deadline +38.364s)".to_string();
        // The older names reach the same field.
        assert!(keeps(&clause("waker", "task 2"), &r));
        assert!(keeps(&clause("slots", "task 2"), &r));
        assert!(!keeps(&clause("waker", "semaphore"), &r));
        assert!(!keeps(&clause("waker", "unknown"), &row("1")));

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
            future: "app::work".to_string(),
            state: None,
            waiting_on: None,
            wait: None,
            continuation: ContinuationStatus::Unresumed,
        }
    }

    fn set_child(future: Option<&str>) -> census::SetChild {
        census::SetChild {
            node: 0x4000,
            depth: 1,
            future: future.map(str::to_string),
            root: None,
            state: None,
            waiting_on: None,
            wait: None,
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
            ty: "FuturesUnordered".to_string(),
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
            ty: "JoinSet<()>".to_string(),
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
        let long = "app::a::very::long::module::path::down::to::the::future::in::question::\
                    with::generic::arguments::spelled::out::in::full::Type";
        let mut held_future = held(0, None);
        held_future.future = long.to_string();
        held_future.state = Some("Suspend0 — app.rs:9".to_string());
        let held_list = [held_future];
        let mut set = future_set(0);
        set.ty = format!("FuturesUnordered<{long}>");
        set.children[0].future = Some(long.to_string());
        let sets = [set];
        let mut joined_set = join_set(0, 0, vec![]);
        joined_set.ty = format!("JoinSet<{long}>");
        let join_sets = [joined_set];
        let nested = HashMap::new();
        let list = bundle::TaskList::new(vec![]);
        let polling = HashMap::new();
        let blocking = HashMap::new();
        let impls = hansei_bundle::names::ImplFold::default();
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
                impls: &impls,
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
        let impls = hansei_bundle::names::ImplFold::default();
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
                impls: &impls,
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

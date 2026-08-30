//! The `tasks` and `census` commands: the task listing and the counts
//! over it, plus the naming helpers every listing shares.

use crate::summary;
use crate::{Session, print_warnings};

use anyhow::Result;
use hansei_bundle::names;
use hansei_runtime::tokio::graph as rt_graph;
use hansei_runtime::tokio::{Lifecycle, bundle, census};

use std::collections::{BTreeMap, BTreeSet, HashMap};
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

/// [`task_id`] worded as a noun phrase: `task 42`, or `task at 0x…`.
pub(crate) fn task_label(list: &bundle::TaskList, index: usize) -> String {
    match list.tasks[index].task_id {
        Some(_) => format!("task {}", task_id(list, index)),
        None => format!("task at {}", task_id(list, index)),
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

/// A capped census walk looks like completeness, so say it is not.
fn warn_census_capped(capped: census::Capped, fate: &str) -> io::Result<()> {
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
    let (limits, beyond) = match (capped.deep, capped.distant) {
        (0, 0) => return None,
        (deep, 0) => (
            format!("its depth limit in {deep} place(s)"),
            "nested deeper",
        ),
        (0, distant) => (
            format!("its nesting limit in {distant} place(s)"),
            "held further out",
        ),
        (deep, distant) => (
            format!(
                "its depth limit in {deep} place(s) and its nesting \
                 limit in {distant} place(s)"
            ),
            "beyond either",
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
fn warn_census_refused(refused: usize, fate: &str) -> io::Result<()> {
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
            holds.push(summary::counted(self.joined, "task"));
        }
        if self.sets > 0 {
            holds.push(summary::counted(self.children_live, "future"));
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
    impls: &'a names::ImplFold,
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
                h.frame,
                h.local,
                h.addr,
                names::display_future_name(&h.future, listing.impls)
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
                names::fold_type_name(&set.ty, listing.impls),
                set.addr,
                set.frame,
                set.local
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
                writeln!(
                    out,
                    "{pad}    {:#x}  {}{state}",
                    child.node,
                    names::display_future_name(future, listing.impls)
                )?;
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
                names::fold_type_name(&set.ty, listing.impls),
                set.addr,
                set.frame,
                set.local
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
pub(crate) fn task_state(task: &bundle::Task, polling: &HashMap<u64, u32>) -> String {
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
        None => format!("task at {:#x}", child.task),
    };
    if let Some(task) = listing.list.tasks.iter().find(|t| t.addr.0 == child.task) {
        let state = task_state(task, listing.polling);
        return format!(
            "{who}  {}  {state}",
            future_name(&task.future, listing.impls)
        );
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
    /// The group index `runtimes --list` prints (runtimes and local
    /// sets share the space); the column prints only on targets
    /// holding more than one group.
    pub(crate) rt: usize,
    /// The leaf await site — the line of the reader's own code the
    /// task is parked behind, the site `census`'s "Awaiting at"
    /// counts.
    pub(crate) awaiting_at: Option<String>,
    /// What the task waits on, spelled the way `graph` spells it.
    pub(crate) waiting_on: String,
    /// The root future's display name, folded and never truncated.
    pub(crate) future: String,
}

/// The table's rows, built on first use and cached on the session.
/// The wait analysis is the cost — the census's own walk — and every
/// later `graph`/`census`/`whatis` then pays nothing more.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [TaskRow] {
    session.task_rows.get_or_init(|| {
        let polling: HashMap<u64, u32> = session
            .workers
            .iter()
            .filter_map(|w| w.current_task_id.map(|id| (id, w.tid)))
            .collect();
        build_rows(
            &session.tasks,
            &session.analysis().waits,
            &polling,
            &session.impl_fold,
        )
    })
}

/// Build every row from what it prints — taken apart from the session
/// so a test can lay out a population no fixture holds.
fn build_rows(
    list: &bundle::TaskList,
    waits: &[rt_graph::TaskWait],
    polling: &HashMap<u64, u32>,
    impls: &names::ImplFold,
) -> Vec<TaskRow> {
    list.tasks
        .iter()
        .enumerate()
        .map(|(index, task)| TaskRow {
            id: task_id(list, index),
            state: row_state(task),
            rt: task.group,
            awaiting_at: waits
                .get(index)
                .and_then(|w| w.site.as_ref())
                .map(|(file, line)| format!("{file}:{line}")),
            waiting_on: waiting_on(task, waits.get(index), polling, impls),
            future: future_name(&task.future, impls),
        })
        .collect()
}

/// The `STATE` cell: the lifecycle, and the cancel bit — which any
/// lifecycle can carry — appended rather than replacing it.
fn row_state(task: &bundle::Task) -> String {
    let lifecycle = task.state.lifecycle();
    match task.state.is_cancelled() {
        true => format!("{lifecycle} (cancelled)"),
        false => lifecycle.to_string(),
    }
}

/// The `WAITING ON` cell: what `graph` computes for the task — the
/// decoded primitive, else the leaf type the chain bottoms out in —
/// except that a mid-poll task names the lwp polling it, since a
/// running task is not waiting at all.
fn waiting_on(
    task: &bundle::Task,
    wait: Option<&rt_graph::TaskWait>,
    polling: &HashMap<u64, u32>,
    impls: &names::ImplFold,
) -> String {
    if task.state.lifecycle() == Lifecycle::Running {
        return match task.task_id.and_then(|id| polling.get(&id)) {
            Some(lwp) => format!("— (mid-poll on lwp {lwp})"),
            None => "— (mid-poll)".to_string(),
        };
    }
    match wait.map(|w| (&w.target, &w.leaf)) {
        Some((Some(target), _)) => target.to_string(),
        Some((None, Some(leaf))) => names::display_future_name(leaf, impls),
        _ => "—".to_string(),
    }
}

/// Print the table: one row per task, in the listing's own id order,
/// the `RT` column only when the target holds more than one group.
fn print_task_table(
    rows: &[TaskRow],
    groups: bool,
    limit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let shown = limit.unwrap_or(rows.len()).min(rows.len());
    let mut header = vec!["ID", "STATE"];
    if groups {
        header.push("RT");
    }
    header.extend(["AWAITING AT", "WAITING ON", "FUTURE"]);
    let mut table = crate::output::Table::new(header.len()).header(header);
    for row in &rows[..shown] {
        let mut cells = vec![row.id.clone(), row.state.clone()];
        if groups {
            cells.push(row.rt.to_string());
        }
        cells.push(row.awaiting_at.clone().unwrap_or_else(|| "—".to_string()));
        cells.push(row.waiting_on.clone());
        cells.push(row.future.clone());
        table.row(cells);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(rows.len(), shown, "task"))?;
    Ok(())
}

/// The line under a listing: the plain count when everything printed,
/// both numbers when a limit cut it — the only truncation there is.
pub(crate) fn listing_footer(total: usize, shown: usize, noun: &str) -> String {
    match shown < total {
        true => format!("[{}, {shown} shown]", summary::counted(total, noun)),
        false => summary::counted(total, noun),
    }
}

pub(crate) fn exec_tasks<T: proc::Target>(
    session: &Session<'_, T>,
    verbose: bool,
    futures: bool,
    limit: Option<usize>,
    tasks: &[u64],
    out: &mut dyn io::Write,
) -> Result<()> {
    let list = &session.tasks;

    // The bare command is the table; ids, -v, or --futures ask for
    // the block form. The table reads the wait analysis and nothing
    // else, so it does not pay for the future census the blocks
    // count.
    if tasks.is_empty() && !verbose && !futures {
        print_warnings(&session.analysis().errors)?;
        print_task_table(rows(session), !session.group_tags().is_empty(), limit, out)?;
        print_warnings(&list.errors)?;
        return Ok(());
    }

    // Which lwp is polling which task right now.
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
        print_warnings(&census.errors)?;
        // A walk that failed says so above; one that hit a limit says so
        // here, because it looks like completeness otherwise. The listing
        // is a lower bound either way (`help tasks`), but this is the part
        // of it that varies by target rather than being inherent.
        warn_census_capped(census.capped, "listed")?;
        warn_census_refused(census.refused, "listed")?;
    }

    print_tasks(
        list,
        &session.impl_fold,
        &session.group_tags(),
        &polling,
        &census.held,
        &census.sets,
        &census.join_sets,
        futures,
        limit,
        tasks,
        out,
    )?;

    print_warnings(&list.errors)?;

    Ok(())
}

/// Print the task listing: a block per task, and — under `futures` —
/// the census's finds for it, listed beneath the count each belongs
/// under.
/// `tasks` narrows the listing to the named tasks, and is empty for the
/// whole list.
/// `group_tags` labels each task's group — its runtime, or the local
/// set that owns it — on the targets holding more than one, and is
/// empty — no row — for the rest.
///
/// It takes what it prints rather than a session so the offline tests
/// can drive it, the census as its flat lists so a test can lay out a
/// shape no fixture happens to hold.
#[allow(clippy::too_many_arguments)]
pub(crate) fn print_tasks(
    list: &bundle::TaskList,
    impls: &names::ImplFold,
    group_tags: &[String],
    polling: &HashMap<u64, u32>,
    census_held: &[census::HeldFuture],
    census_sets: &[census::FutureSet],
    census_join_sets: &[census::JoinSet],
    futures: bool,
    limit: Option<usize>,
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
            return Err(no_such_task(list, id));
        };
        only.insert(index);
    }
    let selected = |index: usize| tasks.is_empty() || only.contains(&index);
    let census = census_tree(census_held, census_sets, census_join_sets);
    let listing = Listing {
        nested: &census.nested,
        list,
        polling,
        impls,
    };

    // A block per task rather than a row: a future type is long enough
    // that column-aligning it pushes the two source locations off the
    // right of any terminal.
    let mut shown = 0;
    for (index, task) in list.tasks.iter().enumerate() {
        if !selected(index) {
            continue;
        }
        if limit.is_some_and(|limit| shown >= limit) {
            break;
        }
        shown += 1;
        let id = task_id(list, index);
        writeln!(out, "Task {id}: {}", future_name(&task.future, impls))?;
        writeln!(out, "    State: {}", task_state(task, polling))?;
        if let Some(tag) = group_tags.get(task.group) {
            writeln!(out, "    Owner: {tag}")?;
        }
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
        writeln!(out, "{}", listing_footer(list.tasks.len(), shown, "task"))?;
    }
    Ok(())
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
    // As `tasks --futures`: a walk that hit a depth limit looks like
    // completeness in a count, so it says so.
    if let Some(census) = census {
        warn_census_capped(census.capped, "counted")?;
        warn_census_refused(census.refused, "counted")?;
    }

    let runtime = match sections.threads {
        true => runtime_threads(session)?,
        false => Vec::new(),
    };
    let runtimes = census_runtimes(session, sections.threads)?;

    let facts = summary::Facts {
        lwps: session.lwps.len(),
        runtime,
        runtimes,
        local_sets: session.local_sets.len(),
        tasks: &session.tasks,
        waits: analysis.map(|analysis| &analysis.waits[..]).unwrap_or(&[]),
        held: census.map(|census| &census.held[..]).unwrap_or(&[]),
        sets: census.map(|census| &census.sets[..]).unwrap_or(&[]),
        impls: &session.impl_fold,
        fatal: session.proc.fatal_signal(),
    };
    summary::print(&facts, sections, top, out)
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
                Some((_, rt)) => match session.ctx.ct_park_state(rt.handle, ct_ctx) {
                    Ok(state) => Some(state),
                    Err(e) => {
                        writeln!(
                            io::stderr(),
                            "warning: cannot read the block_on state of lwp {}: {e:#}",
                            worker.tid
                        )?;
                        None
                    }
                },
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
    use super::{build_rows, listing_footer, print_task_table};

    use hansei_runtime::tokio::bundle::{FutureInfo, Task, TaskList, WaitTarget};
    use hansei_runtime::tokio::graph::{TaskRef, TaskWait};
    use hansei_runtime::tokio::{RawInstant, TaskAddr, TaskState};

    use std::collections::HashMap;

    const REF_ONE: u64 = 1 << 6;
    const RUNNING: u64 = 0b0001;
    const CANCELLED: u64 = 0b100_000;

    fn task(id: u64, state: u64) -> Task {
        Task {
            addr: TaskAddr(0x1000 + id * 0x100),
            state: TaskState(REF_ONE | state),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            group: 0,
        }
    }

    fn wait(id: u64, target: Option<WaitTarget>) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000 + id * 0x100),
                task_id: Some(id),
            },
            target,
            depth: 1,
            leaf: None,
            site: None,
        }
    }

    fn rows_of(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        polling: HashMap<u64, u32>,
    ) -> Vec<super::TaskRow> {
        let list = TaskList {
            tasks,
            errors: vec![],
        };
        build_rows(
            &list,
            &waits,
            &polling,
            &hansei_bundle::names::ImplFold::default(),
        )
    }

    /// Each cell says what its column promises: the site as
    /// `file:line`, the wait as `graph` spells it, the leaf type where
    /// no primitive decoded, `—` where there is nothing to say, and
    /// the cancel bit appended to whatever lifecycle carries it.
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
        let mut leafed = wait(2, None);
        leafed.leaf = Some("app::child::{async_fn_env#0}".to_string());
        let bare = wait(3, None);

        let rows = rows_of(
            vec![task(1, 0), task(2, CANCELLED), task(3, 0)],
            vec![sited, leafed, bare],
            HashMap::new(),
        );

        assert_eq!(rows[0].awaiting_at.as_deref(), Some("src/app.rs:42"));
        assert!(
            rows[0]
                .waiting_on
                .starts_with("the timer: deadline 12.000s")
        );
        assert_eq!(rows[0].state, "idle");

        assert_eq!(rows[1].state, "idle (cancelled)");
        assert_eq!(rows[1].waiting_on, "async fn app::child");
        assert_eq!(rows[1].awaiting_at, None);

        assert_eq!(rows[2].waiting_on, "—");
    }

    /// A running task waits on nothing: its cell names the lwp polling
    /// it where the runtime says one, and says only mid-poll where it
    /// does not.
    #[test]
    fn test_a_running_row_names_its_lwp() {
        let rows = rows_of(
            vec![task(1, RUNNING), task(2, RUNNING)],
            vec![wait(1, None), wait(2, None)],
            HashMap::from([(1, 115)]),
        );
        assert_eq!(rows[0].waiting_on, "— (mid-poll on lwp 115)");
        assert_eq!(rows[1].waiting_on, "— (mid-poll)");
    }

    /// The footer is the only truncation: the plain count when
    /// everything printed, both numbers when a limit cut the listing.
    #[test]
    fn test_the_footer_counts_the_cut() {
        assert_eq!(
            listing_footer(22498, 100, "task"),
            "[22498 tasks, 100 shown]"
        );
        assert_eq!(listing_footer(2, 2, "task"), "2 tasks");
        assert_eq!(listing_footer(1, 1, "task"), "1 task");
        assert_eq!(listing_footer(0, 0, "task"), "0 tasks");
        assert_eq!(listing_footer(2, 1, "root"), "[2 roots, 1 shown]");
    }

    /// The `RT` column exists exactly when the population holds more
    /// than one group, so the common single-runtime table never
    /// carries a column of zeros.
    #[test]
    fn test_the_rt_column_prints_only_for_groups() {
        let rows = rows_of(vec![task(1, 0)], vec![wait(1, None)], HashMap::new());
        let print = |groups: bool| {
            let mut out = Vec::new();
            print_task_table(&rows, groups, None, &mut out).expect("table prints");
            String::from_utf8(out).expect("utf8")
        };
        assert!(print(true).contains("RT"), "{}", print(true));
        assert!(!print(false).contains("RT"), "{}", print(false));
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
        let mut out = Vec::new();
        print_task_table(&rows, false, Some(2), &mut out).expect("table prints");
        let out = String::from_utf8(out).expect("utf8");
        assert!(out.contains("\n1 "), "{out}");
        assert!(out.contains("\n2 "), "{out}");
        assert!(!out.contains("\n3 "), "{out}");
        assert!(out.ends_with("[3 tasks, 2 shown]\n"), "{out}");
    }
}

#[cfg(test)]
mod census_warning_tests {
    use super::{census_capped_warning, census_refused_warning};

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

    /// Both at once is one sentence carrying both counts, rather than
    /// one limit standing for the other or two warnings for one walk.
    #[test]
    fn test_both_limits_are_reported_together() {
        let both = census_capped_warning(
            Capped {
                deep: 2,
                distant: 5,
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
    use super::{Entry, Listing, bundle, census, census_counts, print_future_entry};

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
            leaf: None,
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
            leaf: None,
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
        let counts = census_counts(&held_list, &sets, &join_sets);

        assert_eq!(counts.keys().copied().collect::<Vec<_>>(), [2, 3]);
        let two = counts[&2];
        assert_eq!((two.held, two.join_sets, two.joined), (1, 1, 2));
        assert_eq!((two.sets, two.children_live), (0, 0));
        let three = counts[&3];
        assert_eq!((three.sets, three.children_live), (1, 1));
        assert_eq!(three.held, 0);
    }

    /// A join set's row carries the count the walk reached; what the set
    /// records for itself is appended only when the walk fell short of
    /// it, since that is the row the stderr error belongs to.
    #[test]
    fn test_short_join_set_row_reports_the_recorded_length() {
        let nested = HashMap::new();
        let list = bundle::TaskList {
            tasks: vec![],
            errors: vec![],
        };
        let polling = HashMap::new();
        let impls = hansei_bundle::names::ImplFold::default();
        let listing = Listing {
            nested: &nested,
            list: &list,
            polling: &polling,
            impls: &impls,
        };
        let show = |set: &census::JoinSet| {
            let mut out = Vec::new();
            print_future_entry(Entry::JoinSet(set), &listing, 0, false, &mut out)
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

    use hansei_runtime::tokio::bundle::{FutureInfo, Task};
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
            group: 0,
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
        let list = |state: u64, task_id: Option<u64>| TaskList {
            tasks: vec![task(state, task_id)],
            errors: vec![],
        };

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
            task_state(&task(RUNNING, Some(7)), &polling),
            "running (lwp 42)"
        );

        // Running, but the runtime does not say a worker holds it: some
        // other task's id, or none of its own.
        assert_eq!(task_state(&task(RUNNING, Some(9)), &polling), "running");
        assert_eq!(task_state(&task(RUNNING, None), &polling), "running");

        // A worker polling *something* says nothing about a task that
        // is not running, whatever id it carries.
        assert_eq!(task_state(&task(IDLE, Some(7)), &polling), "idle");
        assert_eq!(
            task_state(&task(RUNNING, Some(7)), &HashMap::new()),
            "running"
        );
    }
}

//! The `tasks` and `census` commands: the task listing and the counts
//! over it, plus the naming helpers every listing shares.

use crate::summary;
use crate::{Session, print_warnings};

use anyhow::Result;
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

/// A capped census walk looks like completeness, so say it is not:
/// `fate` is what the listing or count would otherwise claim to cover.
fn warn_census_capped(capped: usize, fate: &str) -> io::Result<()> {
    if capped > 0 {
        writeln!(
            io::stderr(),
            "warning: the scan stopped at a depth limit in {capped} place(s); \
             anything held deeper is not {fate}"
        )?;
    }
    Ok(())
}

/// The error for a task id the runtime does not own, naming the ids it
/// does.
pub(crate) fn no_such_task(list: &bundle::TaskList, id: u64) -> anyhow::Error {
    let ids: Vec<u64> = list.tasks.iter().filter_map(|t| t.task_id).collect();
    anyhow::anyhow!(
        "no task with id {id} is listed; the target owns {} task(s): {ids:?}",
        list.tasks.len()
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

pub(crate) fn exec_tasks(
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
        print_warnings(&census.errors)?;
        // A walk that failed says so above; one that hit a limit says so
        // here, because it looks like completeness otherwise. The listing
        // is a lower bound either way (`help tasks`), but this is the part
        // of it that varies by target rather than being inherent.
        warn_census_capped(census.capped.total(), "listed")?;
    }

    print_tasks(
        list,
        &session.group_tags(),
        &polling,
        &census.held,
        &census.sets,
        &census.join_sets,
        futures,
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
    group_tags: &[String],
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
        let id = task_id(list, index);
        writeln!(out, "Task {id}: {}", future_name(&task.future))?;
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
        let plural = if shown == 1 { "" } else { "s" };
        writeln!(out, "{shown} task{plural}")?;
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
pub(crate) fn exec_census(
    session: &Session<'_>,
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
        warn_census_capped(census.capped.total(), "counted")?;
    }

    let runtime = match sections.threads {
        true => runtime_threads(session)?,
        false => Vec::new(),
    };
    let runtimes = census_runtimes(session, sections.threads)?;

    let facts = summary::Facts {
        lwps: session.lwps,
        runtime,
        runtimes,
        local_sets: session.local_sets.len(),
        tasks: &session.tasks,
        waits: analysis.map(|analysis| &analysis.waits[..]).unwrap_or(&[]),
        held: census.map(|census| &census.held[..]).unwrap_or(&[]),
        sets: census.map(|census| &census.sets[..]).unwrap_or(&[]),
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
fn census_runtimes(session: &Session<'_>, states: bool) -> Result<Vec<summary::Runtime>> {
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
fn runtime_threads(session: &Session<'_>) -> Result<Vec<summary::Thread>> {
    let mut runtime = Vec::new();
    for worker in &session.workers {
        runtime.push(summary::Thread {
            tid: worker.tid,
            runtime: session.runtime_of(worker.tid).map(|(index, _)| index),
            role: thread_role(session, worker)?,
            polling: worker.current_task_id.filter(|id| {
                session
                    .tasks
                    .tasks
                    .iter()
                    .any(|t| t.task_id == Some(*id) && t.state.lifecycle() == Lifecycle::Running)
            }),
        });
    }
    Ok(runtime)
}

/// The run-loop role one thread holds, of either scheduler flavor, or
/// `None` for a thread that merely entered the runtime. A failed read
/// warns and costs only what it could not read: the worker its index,
/// the block_on thread its park state.
fn thread_role(
    session: &Session<'_>,
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

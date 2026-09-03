//! The `sync` command: the resource-centric view of every relation
//! hansei knows — `graph` turned inside out. One block per contended
//! semaphore (the primitive backing tokio's Mutex, RwLock and
//! Semaphore), per joined task (a task as the resource a `JoinHandle`
//! names), and per driven task set; an address no primitive owns falls
//! through to the tasks whose frames hold it by value.

use crate::relations::Relations;
use crate::summary::counted;
use crate::tasks::{future_name, task_label};
use crate::{Session, print_warnings};

use anyhow::{Result, bail};
use hansei_bundle::names;
use hansei_runtime::tokio::bundle::{QueuedWaker, SemaphoreWaiter, WaitTarget};
use hansei_runtime::tokio::graph::{Analysis, Futurelock, TaskRef};
use hansei_runtime::tokio::{Lifecycle, bundle, census};

use std::collections::BTreeMap;
use std::io;

/// The block kinds `--kind` narrows to.
#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Kind {
    /// Contended semaphores: permits, holders, blocked tasks, the
    /// wake queue.
    Semaphore,
    /// Tasks as join resources: waited on, their handles held, or
    /// members of a set.
    Join,
    /// `JoinSet`s and `FuturesUnordered`s: the driver and the members.
    Set,
    /// The by-value fallback: tasks whose frames hold an address.
    Address,
}

/// Everything the printers read, taken apart from the session so the
/// tests can lay out a population no fixture holds.
struct View<'a> {
    list: &'a bundle::TaskList,
    analysis: &'a Analysis,
    relations: &'a Relations,
    sets: &'a [census::FutureSet],
    join_sets: &'a [census::JoinSet],
    impls: &'a names::ImplFold,
}

pub(crate) fn exec_sync<T: proc::Target>(
    session: &Session<'_, T>,
    addr: Option<u64>,
    kind: Option<Kind>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let analysis = session.analysis();
    print_warnings(&analysis.errors)?;
    let relations = session.relations();
    let census = session.census();
    let view = View {
        list: &session.tasks,
        analysis,
        relations,
        sets: &census.sets,
        join_sets: &census.join_sets,
        impls: &session.impl_fold,
    };
    if let Some(addr) = addr {
        let task_at = |addr: u64| session.extents().locate(addr).map(|(index, _)| index);
        let references = |addr: u64| collect_references(session, view.impls, addr);
        return print_addressed(&view, addr, kind, &task_at, &references, out);
    }
    if kind == Some(Kind::Address) {
        bail!("--kind address narrows an address lookup; `sync 0x…` names one");
    }
    // The omitted-target rule: a task cursor scopes the listing to the
    // relations that task is party to; without one, everything.
    if let Some(index) = crate::cursor::cursor_task(session) {
        return print_task_scoped(&view, index, kind, out);
    }
    print_listing(&view, kind, out)
}

/// The bare listing: every contended resource, one block each —
/// semaphores in address order, then joined tasks in task order, then
/// nonempty sets in address order.
fn print_listing(view: &View<'_>, kind: Option<Kind>, out: &mut dyn io::Write) -> Result<()> {
    let mut printed = 0usize;
    let mut sep = |out: &mut dyn io::Write| -> Result<()> {
        if printed > 0 {
            writeln!(out)?;
        }
        printed += 1;
        Ok(())
    };
    if kind.is_none_or(|k| k == Kind::Semaphore) {
        for block in blocks(view.analysis).values() {
            sep(out)?;
            print_semaphore(block, view.impls, out)?;
        }
    }
    if kind.is_none_or(|k| k == Kind::Join) {
        for index in 0..view.list.tasks.len() {
            if view.relations.joined(index) {
                sep(out)?;
                print_join(view, index, out)?;
            }
        }
    }
    if kind.is_none_or(|k| k == Kind::Set) {
        for &(addr, _, _) in &set_index(view) {
            sep(out)?;
            print_set(view, addr, out)?;
        }
    }
    Ok(())
}

/// One address, resolved against everything `sync` lists — the
/// semaphores, the sets, the tasks themselves — and, when no primitive
/// owns it, against the frames that hold it by value. `--kind` skips
/// the resolution order and asks for one reading.
fn print_addressed(
    view: &View<'_>,
    addr: u64,
    kind: Option<Kind>,
    task_at: &dyn Fn(u64) -> Option<usize>,
    references: &dyn Fn(u64) -> Vec<String>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let semaphores = blocks(view.analysis);
    let semaphore = semaphores.get(&addr);
    let set = set_index(view).iter().any(|&(a, ..)| a == addr);
    let task = task_at(addr);
    match kind {
        Some(Kind::Semaphore) => match semaphore {
            Some(block) => print_semaphore(block, view.impls, out),
            None => bail!(
                "no decoded semaphore at {addr:#x}; `sync` lists the ones \
                 the tasks' await chains reach"
            ),
        },
        Some(Kind::Join) => match task {
            Some(index) => print_join(view, index, out),
            None => bail!("{addr:#x} is in no task's allocation"),
        },
        Some(Kind::Set) => match set {
            true => print_set(view, addr, out),
            false => bail!("no decoded JoinSet or FuturesUnordered at {addr:#x}"),
        },
        Some(Kind::Address) => print_references(addr, &references(addr), out),
        None => {
            if let Some(block) = semaphore {
                return print_semaphore(block, view.impls, out);
            }
            if set {
                return print_set(view, addr, out);
            }
            if let Some(index) = task {
                return print_join(view, index, out);
            }
            print_references(addr, &references(addr), out)
        }
    }
}

/// The cursor's task: every relation it is party to — the semaphores
/// it is blocked on or holds, its own join block, the join blocks of
/// the tasks it awaits, and the sets it drives.
fn print_task_scoped(
    view: &View<'_>,
    index: usize,
    kind: Option<Kind>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let addr = view.list.tasks[index].addr.0;
    let mut printed = 0usize;
    let mut sep = |out: &mut dyn io::Write| -> Result<()> {
        if printed > 0 {
            writeln!(out)?;
        }
        printed += 1;
        Ok(())
    };
    if kind.is_none_or(|k| k == Kind::Semaphore) {
        for block in blocks(view.analysis).values() {
            let blocked = block.blocked.iter().any(|(t, _)| t.addr.0 == addr);
            let holds = block.locks.iter().any(|fl| fl.holder.addr.0 == addr);
            if blocked || holds {
                sep(out)?;
                print_semaphore(block, view.impls, out)?;
            }
        }
    }
    if kind.is_none_or(|k| k == Kind::Join) {
        // The tasks it awaits: a semaphore holder is a Waiting edge
        // too, but its relation is the semaphore block above, not a
        // join, so only the edges the join index reverses count — and
        // the task's own block prints only when something joins *it*.
        let awaits = view.relations.edges[index]
            .iter()
            .filter(|e| e.kind == crate::relations::EdgeKind::Waiting)
            .map(|e| e.to)
            .filter(|&to| view.relations.waited_by[to].contains(&index));
        let mut joins: Vec<usize> = [index]
            .into_iter()
            .filter(|&i| view.relations.joined(i))
            .chain(awaits)
            .collect();
        joins.sort_unstable();
        joins.dedup();
        for join in joins {
            sep(out)?;
            print_join(view, join, out)?;
        }
    }
    if kind.is_none_or(|k| k == Kind::Set) {
        for &(set_addr, owner, _) in &set_index(view) {
            let member = view.relations.member_of[index].is_some_and(|(a, _)| a == set_addr);
            if owner == index || member {
                sep(out)?;
                print_set(view, set_addr, out)?;
            }
        }
    }
    if printed == 0 {
        writeln!(
            out,
            "{} is party to no decoded relation: nothing waits to join \
             it, and it blocks on no semaphore and drives no set",
            task_label(view.list, index)
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Join blocks: a task as a resource.
// ---------------------------------------------------------------------------

/// One task as the resource a `JoinHandle` names: who waits to join
/// it, who holds its handle without awaiting, and the set that will
/// collect it.
fn print_join(view: &View<'_>, index: usize, out: &mut dyn io::Write) -> Result<()> {
    let task = &view.list.tasks[index];
    let state = match task.state.is_cancelled() {
        true => format!("{} (cancelled)", task.state.lifecycle()),
        false => task.state.lifecycle().to_string(),
    };
    writeln!(
        out,
        "{} ({}): {state}",
        task_label(view.list, index),
        future_name(&task.future, view.impls)
    )?;
    let named = |tasks: &[usize]| {
        tasks
            .iter()
            .map(|&i| task_label(view.list, i))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let waited = &view.relations.waited_by[index];
    if !waited.is_empty() {
        writeln!(out, "    Waited by: {}", named(waited))?;
    }
    let held = &view.relations.held_by[index];
    if !held.is_empty() {
        writeln!(out, "    Handle held by: {}, unawaited", named(held))?;
    }
    if let Some((set_addr, owner)) = view.relations.member_of[index] {
        writeln!(
            out,
            "    Member of: {}, driven by {}",
            set_name(view, set_addr),
            task_label(view.list, owner)
        )?;
    }
    if waited.is_empty() && held.is_empty() && view.relations.member_of[index].is_none() {
        writeln!(
            out,
            "    No task waits to join it, holds its handle, or drives \
             it in a set"
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Set blocks: a JoinSet or FuturesUnordered as a resource.
// ---------------------------------------------------------------------------

/// Every set the census found, `(address, owner index, is_join_set)`,
/// in address order, empties left out — a set with no members contends
/// with nothing.
fn set_index(view: &View<'_>) -> Vec<(u64, usize, bool)> {
    let mut sets: Vec<(u64, usize, bool)> = view
        .sets
        .iter()
        .filter(|s| !s.children.is_empty())
        .map(|s| (s.addr, s.owner, false))
        .chain(
            view.join_sets
                .iter()
                .filter(|s| !s.children.is_empty())
                .map(|s| (s.addr, s.owner, true)),
        )
        .collect();
    sets.sort_unstable();
    sets
}

/// The heading spelling of the set at `addr`, folded like every other
/// type the listings print.
fn set_name(view: &View<'_>, addr: u64) -> String {
    let ty = view
        .join_sets
        .iter()
        .find(|s| s.addr == addr)
        .map(|s| &s.ty)
        .or_else(|| view.sets.iter().find(|s| s.addr == addr).map(|s| &s.ty));
    match ty {
        Some(ty) => format!(
            "a {} (set {addr:#x})",
            names::fold_type_name(ty, view.impls)
        ),
        None => format!("the set at {addr:#x}"),
    }
}

/// `counted` pluralizes with an `s`; a set's futures are children.
fn children(n: usize) -> String {
    match n {
        1 => "1 child".to_string(),
        n => format!("{n} children"),
    }
}

/// One set's block: who drives it and what it holds, members grouped
/// by state — a `JoinSet`'s members are listed tasks, a
/// `FuturesUnordered`'s are resident futures only its own nodes hold.
fn print_set(view: &View<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    if let Some(set) = view.join_sets.iter().find(|s| s.addr == addr) {
        writeln!(
            out,
            "{}: {}, driven by {} (`{}`)",
            set_name(view, addr),
            counted(set.children.len(), "member"),
            task_label(view.list, set.owner),
            set.local,
        )?;
        // Members grouped by state, listed tasks by their ids; a
        // complete member has left the owned list and only the set's
        // entry keeps it alive, which is worth its own words.
        let mut by_state: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for child in &set.children {
            let who = match child.id {
                Some(id) => format!("task {id}"),
                None => format!("the task at {:#x}", child.task),
            };
            let state = match child.state.lifecycle() {
                Lifecycle::Complete => "complete, awaiting join".to_string(),
                state if !child.listed => format!("{state}, unlisted"),
                state => state.to_string(),
            };
            by_state.entry(state).or_default().push(who);
        }
        for (state, members) in by_state {
            writeln!(out, "    Members ({state}): {}", members.join(", "))?;
        }
        return Ok(());
    }
    let Some(set) = view.sets.iter().find(|s| s.addr == addr) else {
        bail!("no decoded JoinSet or FuturesUnordered at {addr:#x}");
    };
    writeln!(
        out,
        "{}: {}, driven by {} (`{}`)",
        set_name(view, addr),
        children(set.children.len()),
        task_label(view.list, set.owner),
        set.local,
    )?;
    let in_flight = set.children.iter().filter(|c| c.future.is_some()).count();
    let completed = set.children.len() - in_flight;
    if in_flight > 0 {
        writeln!(out, "    In flight: {in_flight}")?;
    }
    if completed > 0 {
        writeln!(out, "    Completed, not yet reaped: {completed}")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The address fallback: referenced by value.
// ---------------------------------------------------------------------------

/// The tasks whose await-chain frames hold `addr` by value — the
/// census's answer turned around: `whatis` names the task an address
/// is *in*, this names the tasks that *point at* it. The frames are
/// the ones the analysis already walks; nothing is swept.
fn collect_references<T: proc::Target>(
    session: &Session<'_, T>,
    impls: &names::ImplFold,
    addr: u64,
) -> Vec<String> {
    let mut lines = Vec::new();
    // An unmapped word is no address at all: scanning frames for it
    // would report every integer that happens to share its value
    // (`sync 0x1` matching a discriminant), so the fallback answers
    // only for addresses the target actually maps.
    if !session.ctx.is_mapped(addr) {
        return lines;
    }
    for (index, task) in session.tasks.tasks.iter().enumerate() {
        if !matches!(task.future, bundle::FutureInfo::Known(_)) {
            continue;
        }
        let Ok(bundle::TaskStage::Running(future)) = session.ctx.task_stage(task) else {
            continue;
        };
        let chain = session.ctx.await_chain(future);
        for (n, frame) in chain.frames.iter().enumerate() {
            let value = match &frame.state {
                Some(state) => state.payload,
                None => frame.future,
            };
            let Some(offset) = value
                .bytes
                .as_chunks::<8>()
                .0
                .iter()
                .position(|w| u64::from_le_bytes(*w) == addr)
                .map(|i| i as u64 * 8)
            else {
                continue;
            };
            // The member covering the hit, where one does — the name a
            // reader can hand to `print`.
            let member = value
                .ty
                .members()
                .find(|m| member_covers(m.offset(), m.ty().size(), offset))
                .map(|m| format!(", in `{}`", m.name()));
            lines.push(format!(
                "{} (frame #{} {}{})",
                task_label(&session.tasks, index),
                chain.frames.len() - 1 - n,
                names::display_future_name(value.ty.name(), impls),
                member.unwrap_or_default(),
            ));
        }
    }
    lines
}

/// Whether the member laid out at `offset` for `size` bytes covers
/// `hit` — half-open, so a hit at a member's end belongs to whatever
/// follows, and a zero-sized member still claims its one address.
fn member_covers(offset: u64, size: u64, hit: u64) -> bool {
    offset <= hit && hit < offset + size.max(1)
}

/// The fallback block those references print as — refused when there
/// are none, so a miss is an error naming what `sync` does list.
fn print_references(addr: u64, lines: &[String], out: &mut dyn io::Write) -> Result<()> {
    if lines.is_empty() {
        bail!(
            "no decoded resource at {addr:#x}, and no task's frames hold \
             it by value; `sync` lists semaphores, joined tasks and sets"
        );
    }
    writeln!(out, "{addr:#x}: no decoded resource owns this address")?;
    writeln!(out, "    Referenced by value: {}", lines.join(", "))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Semaphore blocks (the original `sync`).
// ---------------------------------------------------------------------------

/// One contended semaphore, assembled from every place the analysis
/// mentions it: the tasks whose active chains are blocked on it (each
/// carrying a snapshot of its state), and the futurelock diagnoses
/// whose abandoned acquires touch it.
struct SemaphoreBlock<'a> {
    addr: u64,
    /// The primitive wrapping it, from the first observer that named
    /// one — every acquire of one Mutex names the Mutex.
    owner: Option<&'static str>,
    /// The semaphore's own state, from the first blocked task's
    /// snapshot. `None` for a semaphore only a futurelock reached: an
    /// abandoned acquire records what *it* holds, not the queue.
    seen: Option<Seen<'a>>,
    /// The tasks actively blocked on it, in task-list order, each with
    /// the permits its acquire asked for.
    blocked: Vec<(TaskRef, u64)>,
    /// The futurelock diagnoses on it: abandoned acquires holding
    /// permits, or places in its queue, that no poll will ever release.
    locks: Vec<&'a Futurelock>,
}

/// A semaphore's state as one blocked task's wait target recorded it.
/// A core does not change while it is read, so every observer's copy
/// agrees; the first is as good as any.
struct Seen<'a> {
    available: u64,
    closed: bool,
    waiters: &'a [SemaphoreWaiter],
}

/// Group the analysis by semaphore address. A `BTreeMap` so the blocks
/// print in address order, which is stable across runs over one core.
fn blocks(analysis: &Analysis) -> BTreeMap<u64, SemaphoreBlock<'_>> {
    fn block<'a, 'b>(
        blocks: &'b mut BTreeMap<u64, SemaphoreBlock<'a>>,
        addr: u64,
    ) -> &'b mut SemaphoreBlock<'a> {
        blocks.entry(addr).or_insert(SemaphoreBlock {
            addr,
            owner: None,
            seen: None,
            blocked: Vec::new(),
            locks: Vec::new(),
        })
    }
    let mut blocks: BTreeMap<u64, SemaphoreBlock<'_>> = BTreeMap::new();
    for wait in &analysis.waits {
        let Some(WaitTarget::Semaphore {
            addr,
            owner,
            num_permits,
            available,
            closed,
            waiters,
        }) = &wait.target
        else {
            continue;
        };
        let entry = block(&mut blocks, *addr);
        entry.owner = entry.owner.or(*owner);
        entry.seen.get_or_insert(Seen {
            available: *available,
            closed: *closed,
            waiters,
        });
        entry.blocked.push((wait.task, *num_permits));
    }
    for fl in &analysis.futurelocks {
        let entry = block(&mut blocks, fl.acquire.semaphore);
        entry.owner = entry.owner.or(fl.acquire.owner);
        entry.locks.push(fl);
    }
    blocks
}

/// One semaphore's block: what it is, what its permit word says, who
/// holds it where that is knowable at all, who is blocked on it, and
/// its wake queue in wake order.
fn print_semaphore(
    block: &SemaphoreBlock<'_>,
    impls: &names::ImplFold,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The same spelling the trace's `waiting on` line and the graph's
    // rows use, so the addresses paste between the three.
    let name = match block.owner {
        Some(owner) => format!("a {owner} (semaphore {:#x})", block.addr),
        None => format!("the semaphore at {:#x}", block.addr),
    };
    match &block.seen {
        Some(seen) => {
            let closed = if seen.closed { ", closed" } else { "" };
            writeln!(
                out,
                "{name}: {} available{closed}",
                counted(seen.available as usize, "permit")
            )?;
        }
        None => {
            // Reached only through an abandoned acquire, which records
            // what it holds, not the semaphore's own state.
            writeln!(out, "{name}: state not read (no task is blocked on it)")?;
        }
    }

    // A tokio semaphore records no owner, so a holder is knowable only
    // where the futurelock analysis found an abandoned acquire holding
    // permits; an ungranted one holds a place in the queue instead.
    for fl in &block.locks {
        let acq = &fl.acquire;
        let future = names::display_future_name(&acq.future, impls);
        if acq.granted() {
            writeln!(
                out,
                "    Held by: {} — {} granted to `{}` ({future}), \
                 a future it stopped polling",
                fl.holder,
                counted(acq.num_permits as usize, "permit"),
                acq.local,
            )?;
        } else {
            writeln!(
                out,
                "    Abandoned in its queue: {}'s `{}` ({future}), \
                 still waiting for {}",
                fl.holder,
                acq.local,
                counted(acq.needed as usize, "permit"),
            )?;
        }
    }

    if !block.blocked.is_empty() {
        let blocked = block
            .blocked
            .iter()
            .map(|(task, permits)| {
                format!(
                    "{task} ({} requested)",
                    counted(*permits as usize, "permit")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "    Blocked on it: {blocked}")?;
    }

    if let Some(seen) = &block.seen
        && !seen.waiters.is_empty()
    {
        let nodes: std::collections::HashSet<u64> =
            block.locks.iter().map(|fl| fl.acquire.node).collect();
        let queue = seen
            .waiters
            .iter()
            .map(|w| waiter_name(w, nodes.contains(&w.addr)))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "    Wake queue: {queue}")?;
    }
    Ok(())
}

/// How one wake-queue entry reads: who waking it schedules, in the
/// spelling the trace's inline queue uses, plus what this listing can
/// say about the node itself — that its acquire was granted everything
/// it asked for and merely awaits a poll, and that the futurelock
/// analysis proved that poll will never come.
fn waiter_name(w: &SemaphoreWaiter, abandoned: bool) -> String {
    let mut name = match &w.waker {
        QueuedWaker::Task {
            task_id: Some(id), ..
        } => format!("task {id}"),
        QueuedWaker::Task {
            addr,
            task_id: None,
        } => format!("the task at {addr:#x}"),
        QueuedWaker::Other { .. } => "a non-task waiter".to_string(),
        QueuedWaker::Unarmed => "an unarmed waiter".to_string(),
    };
    let marks: Vec<&str> = [(w.needed == 0, "granted"), (abandoned, "abandoned")]
        .into_iter()
        .filter_map(|(on, mark)| on.then_some(mark))
        .collect();
    if !marks.is_empty() {
        name.push_str(&format!(" ({})", marks.join(", ")));
    }
    name
}

#[cfg(test)]
mod sync_tests {
    use super::{Kind, View, print_addressed, print_listing};

    use crate::relations::Relations;

    use hansei_bundle::names;
    use hansei_runtime::tokio::bundle::{
        AbandonedAcquire, FutureInfo, QueuedWaker, SemaphoreWaiter, Task, TaskList, WaitTarget,
    };
    use hansei_runtime::tokio::census;
    use hansei_runtime::tokio::graph::{Analysis, Futurelock, TaskRef, TaskWait};
    use hansei_runtime::tokio::{TaskAddr, TaskState};

    const REF_ONE: u64 = 1 << 6;
    const SEMAPHORE: u64 = 0x9000;

    fn addr(id: u64) -> TaskAddr {
        TaskAddr(0x1000 + id * 0x100)
    }

    fn task_ref(id: u64) -> TaskRef {
        TaskRef {
            addr: addr(id),
            task_id: Some(id),
        }
    }

    fn task(id: u64) -> Task {
        Task {
            addr: addr(id),
            state: TaskState(REF_ONE),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            group: 0,
            blocking: false,
        }
    }

    fn wait(id: u64, target: Option<WaitTarget>) -> TaskWait {
        TaskWait {
            task: task_ref(id),
            target,
            depth: 1,
            leaf: None,
            site: None,
        }
    }

    /// A queued waiter node whose waker schedules `id`'s task.
    fn waiter(id: u64, node: u64, needed: u64) -> SemaphoreWaiter {
        SemaphoreWaiter {
            addr: node,
            needed,
            waker: QueuedWaker::Task {
                addr: addr(id).0,
                task_id: Some(id),
            },
        }
    }

    fn semaphore(waiters: Vec<SemaphoreWaiter>) -> WaitTarget {
        WaitTarget::Semaphore {
            addr: SEMAPHORE,
            owner: Some("tokio::sync::Mutex"),
            num_permits: 1,
            available: 0,
            closed: false,
            waiters,
        }
    }

    /// Waiting to join the task with this id.
    fn joining(id: u64) -> WaitTarget {
        WaitTarget::Task {
            addr: addr(id).0,
            task_id: Some(id),
            state: TaskState(REF_ONE),
            listed: true,
            kind: None,
        }
    }

    /// The task holding an acquire on the semaphore, granted or not,
    /// in a future it stopped polling.
    fn futurelock(holder: u64, node: u64, needed: u64) -> Futurelock {
        Futurelock {
            holder: task_ref(holder),
            acquire: AbandonedAcquire {
                frame: "worker::{async_fn_env#0}".to_string(),
                state: "Suspend0".to_string(),
                await_loc: None,
                local: "lock".to_string(),
                future: "Mutex::lock::{async_fn_env#0}".to_string(),
                owner: Some("tokio::sync::Mutex"),
                semaphore: SEMAPHORE,
                node,
                num_permits: 1,
                needed,
            },
            blocked: Vec::new(),
        }
    }

    /// The default population behind the semaphore tests: one task per
    /// wait, so the relation index has rows to land on.
    fn list_for(waits: &[TaskWait]) -> TaskList {
        TaskList {
            tasks: waits
                .iter()
                .map(|w| task(w.task.task_id.unwrap()))
                .collect(),
            errors: Vec::new(),
        }
    }

    struct Fixture {
        list: TaskList,
        analysis: Analysis,
        sets: Vec<census::FutureSet>,
        join_sets: Vec<census::JoinSet>,
    }

    impl Fixture {
        fn new(waits: Vec<TaskWait>, futurelocks: Vec<Futurelock>) -> Fixture {
            let list = list_for(&waits);
            Fixture {
                list,
                analysis: Analysis {
                    waits,
                    futurelocks,
                    join_wakers: Vec::new(),
                    errors: Vec::new(),
                },
                sets: Vec::new(),
                join_sets: Vec::new(),
            }
        }

        fn print_scoped(&self, index: usize, kind: Option<Kind>) -> anyhow::Result<String> {
            let relations = Relations::build(&self.list, &self.analysis, &[], &self.join_sets);
            let view = View {
                list: &self.list,
                analysis: &self.analysis,
                relations: &relations,
                sets: &self.sets,
                join_sets: &self.join_sets,
                impls: &names::ImplFold::default(),
            };
            let mut out = Vec::new();
            super::print_task_scoped(&view, index, kind, &mut out)?;
            Ok(String::from_utf8(out).unwrap())
        }

        fn print(&self, select: Option<u64>, kind: Option<Kind>) -> anyhow::Result<String> {
            let relations = Relations::build(&self.list, &self.analysis, &[], &self.join_sets);
            let view = View {
                list: &self.list,
                analysis: &self.analysis,
                relations: &relations,
                sets: &self.sets,
                join_sets: &self.join_sets,
                impls: &names::ImplFold::default(),
            };
            let mut out = Vec::new();
            let task_at = |addr: u64| self.list.tasks.iter().position(|t| t.addr.0 == addr);
            let references = |_: u64| Vec::new();
            match select {
                Some(addr) => print_addressed(&view, addr, kind, &task_at, &references, &mut out)?,
                None => print_listing(&view, kind, &mut out)?,
            }
            Ok(String::from_utf8(out).unwrap())
        }
    }

    fn sync(
        waits: Vec<TaskWait>,
        futurelocks: Vec<Futurelock>,
        select: Option<u64>,
    ) -> anyhow::Result<String> {
        Fixture::new(waits, futurelocks).print(select, Some(Kind::Semaphore))
    }

    /// The whole block of a contended, futurelocked Mutex: the holder
    /// named from the diagnosis, the blocked tasks with what each
    /// asked for, and the wake queue in wake order with the granted
    /// abandoned node marked — the RFD 609 shape read off the
    /// resource.
    #[test]
    fn test_a_contended_mutex_gets_one_block() {
        let waits = vec![
            wait(
                40,
                Some(semaphore(vec![
                    waiter(40, 0xe100, 1),
                    waiter(41, 0xe200, 1),
                    waiter(7, 0xa000, 0),
                ])),
            ),
            wait(41, Some(semaphore(Vec::new()))),
            wait(9, None),
        ];
        let out = sync(waits, vec![futurelock(7, 0xa000, 0)], None).unwrap();
        assert_eq!(
            out,
            "a tokio::sync::Mutex (semaphore 0x9000): 0 permits available\n    \
             Held by: task 7 — 1 permit granted to `lock` (async fn Mutex::lock), \
             a future it stopped polling\n    \
             Blocked on it: task 40 (1 permit requested), task 41 (1 permit requested)\n    \
             Wake queue: task 40, task 41, task 7 (granted, abandoned)\n"
        );
    }

    /// An abandoned acquire the semaphore has not granted yet holds a
    /// place in the queue, not permits: the diagnosis line says what it
    /// still waits for, and its node is marked without a granted claim.
    #[test]
    fn test_an_ungranted_abandoned_acquire_is_marked_in_the_queue() {
        let waits = vec![wait(
            40,
            Some(semaphore(vec![waiter(7, 0xa000, 1), waiter(40, 0xe100, 1)])),
        )];
        let out = sync(waits, vec![futurelock(7, 0xa000, 1)], None).unwrap();
        assert!(
            out.contains(
                "    Abandoned in its queue: task 7's `lock` (async fn Mutex::lock), \
                 still waiting for 1 permit\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("    Wake queue: task 7 (abandoned), task 40\n"),
            "{out}"
        );
        assert!(!out.contains("Held by"), "{out}");
    }

    /// Blocks print in address order, a blank line between them; a
    /// semaphore no frame names the owner of keeps the bare spelling,
    /// and its state line carries the closed bit and the plural.
    #[test]
    fn test_blocks_print_in_address_order() {
        let bare = WaitTarget::Semaphore {
            addr: 0x4000,
            owner: None,
            num_permits: 3,
            available: 2,
            closed: true,
            waiters: vec![SemaphoreWaiter {
                addr: 0xe300,
                needed: 3,
                waker: QueuedWaker::Unarmed,
            }],
        };
        let waits = vec![wait(40, Some(semaphore(Vec::new()))), wait(41, Some(bare))];
        let out = sync(waits, Vec::new(), None).unwrap();
        assert_eq!(
            out,
            "the semaphore at 0x4000: 2 permits available, closed\n    \
             Blocked on it: task 41 (3 permits requested)\n    \
             Wake queue: an unarmed waiter\n\
             \n\
             a tokio::sync::Mutex (semaphore 0x9000): 0 permits available\n    \
             Blocked on it: task 40 (1 permit requested)\n"
        );
    }

    /// `sync 0x…` prints that one block alone, and an address the
    /// analysis never decoded is refused rather than answered with
    /// silence.
    #[test]
    fn test_selection_prints_one_block_and_a_miss_is_refused() {
        let waits = vec![wait(40, Some(semaphore(Vec::new())))];
        let out = sync(waits, Vec::new(), Some(SEMAPHORE)).unwrap();
        assert!(out.starts_with("a tokio::sync::Mutex"), "{out}");

        let waits = vec![wait(40, Some(semaphore(Vec::new())))];
        let err = sync(waits, Vec::new(), Some(0x1)).unwrap_err();
        assert!(
            err.to_string().contains("no decoded semaphore at 0x1"),
            "{err}"
        );
    }

    /// A semaphore only a futurelock reached has no snapshot to spell
    /// permits or a queue from — the abandoned acquire records what it
    /// holds, not the semaphore's state — so the block says that
    /// rather than printing zeros read from nothing.
    #[test]
    fn test_a_futurelock_only_semaphore_prints_a_reduced_block() {
        let out = sync(Vec::new(), vec![futurelock(7, 0xa000, 0)], None).unwrap();
        assert_eq!(
            out,
            "a tokio::sync::Mutex (semaphore 0x9000): state not read \
             (no task is blocked on it)\n    \
             Held by: task 7 — 1 permit granted to `lock` (async fn Mutex::lock), \
             a future it stopped polling\n"
        );
    }

    /// Nothing prints when the analysis reached no relation at all: an
    /// empty answer is "none found here", the same claim `graph` makes.
    #[test]
    fn test_no_contention_prints_nothing() {
        let out = Fixture::new(vec![wait(9, None)], Vec::new())
            .print(None, None)
            .unwrap();
        assert_eq!(out, "");
    }

    /// The scoped view prints exactly what the task is party to: the
    /// semaphore it is blocked on, the same block for its holder —
    /// whose own un-joined block is *not* among them, the semaphore
    /// already being its relation — and, for a joiner, the joined
    /// task's block.
    #[test]
    fn test_scoped_sync_prints_what_the_task_is_party_to() {
        let waits = vec![wait(40, Some(semaphore(Vec::new()))), wait(7, None)];
        let fixture = Fixture::new(waits, vec![futurelock(7, 0xa000, 0)]);
        let blocked = fixture.print_scoped(0, None).unwrap();
        assert!(blocked.starts_with("a tokio::sync::Mutex"), "{blocked}");
        assert!(!blocked.contains("party to no"), "{blocked}");
        let holder = fixture.print_scoped(1, None).unwrap();
        assert!(holder.starts_with("a tokio::sync::Mutex"), "{holder}");
        assert!(!holder.contains("No task waits"), "{holder}");

        // The family filter answers with the family asked for, and a
        // family the task is not party to answers the one-liner.
        let fixture = Fixture::new(
            vec![wait(40, Some(semaphore(Vec::new()))), wait(7, None)],
            vec![futurelock(7, 0xa000, 0)],
        );
        let sem_only = fixture.print_scoped(0, Some(Kind::Semaphore)).unwrap();
        assert!(sem_only.starts_with("a tokio::sync::Mutex"), "{sem_only}");
        let join_only = fixture.print_scoped(0, Some(Kind::Join)).unwrap();
        assert!(join_only.contains("party to no decoded"), "{join_only}");

        let fixture = Fixture::new(vec![wait(7, Some(joining(8))), wait(8, None)], Vec::new());
        let joiner = fixture.print_scoped(0, None).unwrap();
        assert_eq!(joiner, "task 8 (<unknown>): idle\n    Waited by: task 7\n");
        assert_eq!(fixture.print_scoped(0, Some(Kind::Join)).unwrap(), joiner);
        let sem_only = fixture.print_scoped(0, Some(Kind::Semaphore)).unwrap();
        assert!(sem_only.contains("party to no decoded"), "{sem_only}");
    }

    /// A set relates its driver and each member: the member's scope
    /// prints its one set, the driver of two prints both, blank-line
    /// separated and nothing before the first.
    #[test]
    fn test_scoped_sync_prints_driven_and_member_sets() {
        let joinset = |set_addr: u64, member: u64| census::JoinSet {
            owner: 0,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: set_addr,
            ty: "tokio::task::join_set::JoinSet<()>".to_string(),
            length: 1,
            children: vec![census::JoinedTask {
                entry: 0xc000,
                task: addr(member).0,
                id: Some(member),
                state: TaskState(REF_ONE),
                listed: true,
            }],
        };
        let mut fixture = Fixture::new(vec![wait(9, None), wait(21, None)], Vec::new());
        fixture.join_sets = vec![joinset(0xb000, 21), joinset(0xb100, 99)];
        let member = fixture.print_scoped(1, None).unwrap();
        assert_eq!(
            member,
            "task 21 (<unknown>): idle\n    Member of: a tokio::task::join_set::JoinSet<()> (set 0xb000), driven by task 9\n\na tokio::task::join_set::JoinSet<()> (set 0xb000): 1 member, driven by task 9 (`tasks`)\n    Members (idle): task 21\n"
        );
        let driver = fixture.print_scoped(0, None).unwrap();
        assert!(driver.starts_with("a tokio"), "{driver}");
        assert_eq!(driver.matches("(set 0x").count(), 2, "{driver}");
        assert_eq!(driver.matches("\n\n").count(), 1, "{driver}");
        // The set family alone keeps the member's one set and answers
        // the one-liner for a family it is not party to.
        let set_only = fixture.print_scoped(1, Some(Kind::Set)).unwrap();
        assert!(set_only.contains("(set 0xb000)"), "{set_only}");
        assert!(!set_only.contains("(set 0xb100)"), "{set_only}");
        let sem_only = fixture.print_scoped(1, Some(Kind::Semaphore)).unwrap();
        assert!(sem_only.contains("party to no decoded"), "{sem_only}");
    }

    /// A set whose every child has completed unreaped counts no
    /// in-flight line at all — a zero would claim a count the set does
    /// not have.
    #[test]
    fn test_a_set_of_only_reaped_children_counts_no_flight() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.sets = vec![census::FutureSet {
            owner: 0,
            frame: 0,
            local: "work".to_string(),
            via: None,
            addr: 0xb000,
            ty: "futures_util::stream::futures_unordered::FuturesUnordered<()>".to_string(),
            children: vec![census::SetChild {
                node: 0xc100,
                depth: 0,
                future: None,
                root: None,
                state: None,
                waiting_on: None,
                wait: None,
                leaf: None,
            }],
        }];
        assert_eq!(
            fixture.print(None, None).unwrap(),
            "a futures_util::stream::futures_unordered::FuturesUnordered<()> (set 0xb000): 1 child, driven by task 9 (`work`)\n    Completed, not yet reaped: 1\n"
        );
    }

    /// Member coverage is half-open with a floor of one byte: the
    /// start is in, the end is the next member's, and a zero-sized
    /// member still claims its one address.
    #[test]
    fn test_member_coverage_is_half_open() {
        use super::member_covers;
        assert!(member_covers(0, 8, 0));
        assert!(member_covers(0, 8, 7));
        assert!(!member_covers(0, 8, 8));
        assert!(!member_covers(8, 8, 7));
        assert!(member_covers(8, 0, 8));
        assert!(!member_covers(8, 0, 9));
    }

    /// The reference fallback's block: both lines when frames hold the
    /// address, the refusal naming the address when none do.
    #[test]
    fn test_the_reference_block_prints_or_refuses() {
        let mut out = Vec::new();
        super::print_references(0x40, &["task 7 (frame #0 x)".to_string()], &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "0x40: no decoded resource owns this address\n    Referenced by value: task 7 (frame #0 x)\n"
        );
        let err = super::print_references(0x40, &[], &mut Vec::new()).unwrap_err();
        assert!(
            err.to_string().contains("no decoded resource at 0x40"),
            "{err}"
        );
    }

    /// A joined task earns one block naming every join relation it is
    /// on the resource end of: who waits on it, who holds its handle,
    /// and the set that will collect it — and only joined tasks get
    /// one, never one block per task.
    #[test]
    fn test_a_joined_task_gets_a_join_block() {
        let mut fixture = Fixture::new(
            vec![wait(7, Some(joining(8))), wait(8, None), wait(9, None)],
            Vec::new(),
        );
        fixture.join_sets = vec![census::JoinSet {
            owner: 2,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: 0xb000,
            ty: "tokio::task::join_set::JoinSet<()>".to_string(),
            length: 1,
            children: vec![census::JoinedTask {
                entry: 0xc000,
                task: addr(8).0,
                id: Some(8),
                state: TaskState(REF_ONE),
                listed: true,
            }],
        }];
        let out = fixture.print(None, Some(Kind::Join)).unwrap();
        assert_eq!(
            out,
            "task 8 (<unknown>): idle\n    \
             Waited by: task 7\n    \
             Member of: a tokio::task::join_set::JoinSet<()> (set 0xb000), \
             driven by task 9\n"
        );
    }

    /// The set view: a JoinSet's members grouped by state under the
    /// task driving it, and `--kind set` narrowing the listing to it.
    #[test]
    fn test_a_join_set_block_groups_members_by_state() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.join_sets = vec![census::JoinSet {
            owner: 0,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: 0xb000,
            ty: "tokio::task::join_set::JoinSet<()>".to_string(),
            length: 2,
            children: vec![
                census::JoinedTask {
                    entry: 0xc000,
                    task: 0x7000,
                    id: Some(21),
                    state: TaskState(REF_ONE),
                    listed: true,
                },
                census::JoinedTask {
                    entry: 0xc100,
                    task: 0x7100,
                    id: Some(22),
                    state: TaskState(REF_ONE | 1),
                    listed: false,
                },
            ],
        }];
        let out = fixture.print(None, Some(Kind::Set)).unwrap();
        assert_eq!(
            out,
            "a tokio::task::join_set::JoinSet<()> (set 0xb000): 2 members, \
             driven by task 9 (`tasks`)\n    \
             Members (idle): task 21\n    \
             Members (running, unlisted): task 22\n"
        );
    }

    /// A FuturesUnordered's children are futures, not listed tasks:
    /// the block counts what is resident against what has completed
    /// unreaped, and an addressed ask prints the same block.
    #[test]
    fn test_a_future_set_block_counts_children() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.sets = vec![census::FutureSet {
            owner: 0,
            frame: 0,
            local: "work".to_string(),
            via: None,
            addr: 0xb000,
            ty: "futures_util::stream::futures_unordered::FuturesUnordered<()>".to_string(),
            children: vec![
                census::SetChild {
                    node: 0xc000,
                    depth: 1,
                    future: Some("app::poll::{async_fn_env#0}".to_string()),
                    root: None,
                    state: None,
                    waiting_on: None,
                    wait: None,
                    leaf: None,
                },
                census::SetChild {
                    node: 0xc100,
                    depth: 0,
                    future: None,
                    root: None,
                    state: None,
                    waiting_on: None,
                    wait: None,
                    leaf: None,
                },
            ],
        }];
        let listed = fixture.print(None, None).unwrap();
        let addressed = fixture.print(Some(0xb000), None).unwrap();
        assert_eq!(listed, addressed);
        assert_eq!(
            listed,
            "a futures_util::stream::futures_unordered::FuturesUnordered<()> (set 0xb000): \
             2 children, driven by task 9 (`work`)\n    \
             In flight: 1\n    \
             Completed, not yet reaped: 1\n"
        );
    }

    /// `--kind` narrows the listing to one block family: the join
    /// blocks alone, with the contended semaphore left out.
    #[test]
    fn test_kind_narrows_the_listing() {
        let waits = vec![
            wait(40, Some(semaphore(Vec::new()))),
            wait(7, Some(joining(40))),
        ];
        let fixture = Fixture::new(waits, Vec::new());
        let joins = fixture.print(None, Some(Kind::Join)).unwrap();
        assert!(joins.starts_with("task 40 ("), "{joins}");
        assert!(!joins.contains("semaphore"), "{joins}");
        let semaphores = fixture.print(None, Some(Kind::Semaphore)).unwrap();
        assert!(
            semaphores.starts_with("a tokio::sync::Mutex"),
            "{semaphores}"
        );
        assert!(!semaphores.contains("Waited by"), "{semaphores}");
    }

    /// An addressed ask resolves a task header to that task's join
    /// block, an un-joined task included — the addressed form answers
    /// the address it was given.
    #[test]
    fn test_an_addressed_task_prints_its_join_block() {
        let fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        let out = fixture.print(Some(addr(9).0), None).unwrap();
        assert_eq!(
            out,
            "task 9 (<unknown>): idle\n    \
             No task waits to join it, holds its handle, or drives it in a set\n"
        );
    }
}

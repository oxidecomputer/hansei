//! The `sync` command: the contended synchronization primitives, one
//! block per semaphore — `graph` turned resource-centric.

use crate::summary::counted;
use crate::{Session, print_warnings};

use anyhow::{Result, bail};
use hansei_bundle::names;
use hansei_runtime::tokio::bundle::{QueuedWaker, SemaphoreWaiter, WaitTarget};
use hansei_runtime::tokio::graph::{Analysis, Futurelock, TaskRef};

use std::collections::BTreeMap;
use std::io;

pub(crate) fn exec_sync<T: proc::Target>(
    session: &Session<'_, T>,
    addr: Option<u64>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let analysis = session.analysis();
    print_warnings(&analysis.errors)?;
    print_sync(analysis, addr, &session.impl_fold, out)
}

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

/// Print one block per contended semaphore, or just the one `select`
/// names. It takes what it prints rather than a session so the offline
/// tests can drive it.
fn print_sync(
    analysis: &Analysis,
    select: Option<u64>,
    impls: &names::ImplFold,
    out: &mut dyn io::Write,
) -> Result<()> {
    let blocks = blocks(analysis);
    if let Some(addr) = select {
        let Some(block) = blocks.get(&addr) else {
            bail!(
                "no decoded semaphore at {addr:#x}; `sync` lists the ones \
                 the tasks' await chains reach"
            );
        };
        return print_block(block, impls, out);
    }
    for (i, block) in blocks.values().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        print_block(block, impls, out)?;
    }
    Ok(())
}

/// One semaphore's block: what it is, what its permit word says, who
/// holds it where that is knowable at all, who is blocked on it, and
/// its wake queue in wake order.
fn print_block(
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
    use super::print_sync;

    use hansei_bundle::names;
    use hansei_runtime::tokio::TaskAddr;
    use hansei_runtime::tokio::bundle::{
        AbandonedAcquire, QueuedWaker, SemaphoreWaiter, WaitTarget,
    };
    use hansei_runtime::tokio::graph::{Analysis, Futurelock, TaskRef, TaskWait};

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

    fn sync(
        waits: Vec<TaskWait>,
        futurelocks: Vec<Futurelock>,
        select: Option<u64>,
    ) -> anyhow::Result<String> {
        let analysis = Analysis {
            waits,
            futurelocks,
            join_wakers: Vec::new(),
            errors: Vec::new(),
        };
        let mut out = Vec::new();
        print_sync(&analysis, select, &names::ImplFold::default(), &mut out)?;
        Ok(String::from_utf8(out).unwrap())
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

    /// Nothing prints when the analysis reached no semaphore: an empty
    /// answer is "none found here", the same claim `graph` makes.
    #[test]
    fn test_no_contention_prints_nothing() {
        let out = sync(vec![wait(9, None)], Vec::new(), None).unwrap();
        assert_eq!(out, "");
    }
}

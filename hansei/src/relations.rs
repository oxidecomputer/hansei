//! One index of every task-to-task relation the analysis and the
//! census know — forward for `graph`'s trees, reversed for `sync`'s
//! resource blocks and the tasks listing's waker slots — built once
//! per session and shared, so no two commands can disagree about an
//! edge.

use hansei_runtime::tokio::{bundle, census, graph};

use std::collections::HashMap;

/// Why one task's graph row hangs under another's.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum EdgeKind {
    /// The task is awaiting it right now — the row's own `WAITING ON`
    /// says how, so the edge needs no mark of its own.
    Waiting,
    /// It is a member of a `JoinSet` the task holds. The task will join
    /// it, though its own wait says whether it is doing so yet.
    JoinSet,
    /// The task holds a `JoinHandle` to it in one of its frames, off
    /// its await chain: it can join or abort it, and may be doing
    /// neither.
    Handle,
    // Both marks say "above" rather than "its": the mark is printed on
    // the row of the task being waited *for*, so a possessive there
    // reads as that task's own set or handle — the opposite of what it
    // means, and in opposite directions for the two of them.
}

impl EdgeKind {
    pub(crate) fn mark(self) -> &'static str {
        match self {
            Self::Waiting => "",
            Self::JoinSet => " [in the JoinSet above]",
            Self::Handle => " [its handle held above]",
        }
    }
}

/// One task's row, and why it hangs where it does.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct Edge {
    pub(crate) to: usize,
    pub(crate) kind: EdgeKind,
}

/// The relation index, everything by index into the [`bundle::TaskList`]
/// it was built from.
///
/// Three things relate one task to another. Two are the task's own
/// wait: a `JoinHandle` names the task being joined outright, and a
/// contended semaphore names whoever the futurelock analysis found
/// holding an acquire on it — the only case where a holder is knowable
/// at all, since a tokio `Mutex` records no owner. A timer names
/// nobody, and neither does a leaf hansei does not decode.
///
/// The third is what the census found in the task's frames: the members
/// of a `JoinSet` it drives, and the tasks it holds a `JoinHandle` to
/// without awaiting. Those are the edges a real target mostly has —
/// `join_next` on a set is not a `JoinHandle` await, so nothing about
/// the task's own wait mentions the tasks it is there to collect — and
/// leaving them out made the graph of a runtime running dozens of
/// parallel task sets look like a runtime with no structure at all.
pub(crate) struct Relations {
    /// Which tasks each task is waiting for — `graph`'s trees.
    pub(crate) edges: Vec<Vec<Edge>>,
    /// Per task: the tasks whose await-chain leaf is a `JoinHandle` to
    /// it — who is actively waiting to join it.
    pub(crate) waited_by: Vec<Vec<usize>>,
    /// Per task: the tasks holding its `JoinHandle` in a frame off
    /// their await chains — who could join or abort it, and is doing
    /// neither right now.
    pub(crate) held_by: Vec<Vec<usize>>,
    /// Per task: the `JoinSet` holding it, as the set's address and
    /// the task driving it.
    pub(crate) member_of: Vec<Option<(u64, usize)>>,
}

impl Relations {
    pub(crate) fn build(
        list: &bundle::TaskList,
        analysis: &graph::Analysis,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
    ) -> Relations {
        let index: HashMap<u64, usize> = list
            .tasks
            .iter()
            .enumerate()
            .map(|(i, t)| (t.addr.0, i))
            .collect();
        let tasks = list.tasks.len();
        let mut edges: Vec<Vec<Edge>> = vec![Vec::new(); tasks];
        let mut waited_by: Vec<Vec<usize>> = vec![Vec::new(); tasks];
        let mut held_by: Vec<Vec<usize>> = vec![Vec::new(); tasks];
        let mut member_of: Vec<Option<(u64, usize)>> = vec![None; tasks];
        // A task the runtime no longer owns has no row to point at; the
        // wait's own text says as much where it came from a wait.
        let resolve = |addr: u64| index.get(&addr).copied();
        for (from, wait) in analysis.waits.iter().enumerate() {
            match &wait.target {
                Some(bundle::WaitTarget::Task { addr, .. }) => {
                    if let Some(to) = resolve(*addr) {
                        edges[from].push(Edge {
                            to,
                            kind: EdgeKind::Waiting,
                        });
                        waited_by[to].push(from);
                    }
                }
                Some(bundle::WaitTarget::Semaphore { addr, .. }) => {
                    for fl in analysis
                        .futurelocks
                        .iter()
                        .filter(|fl| fl.acquire.semaphore == *addr)
                    {
                        if let Some(to) = resolve(fl.holder.addr.0) {
                            edges[from].push(Edge {
                                to,
                                kind: EdgeKind::Waiting,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        for set in join_sets {
            for child in &set.children {
                if let Some(to) = resolve(child.task) {
                    edges[set.owner].push(Edge {
                        to,
                        kind: EdgeKind::JoinSet,
                    });
                    member_of[to].get_or_insert((set.addr, set.owner));
                }
            }
        }
        for future in held {
            if let Some(bundle::WaitKind::Task { addr }) = future.wait
                && let Some(to) = resolve(addr)
            {
                edges[future.owner].push(Edge {
                    to,
                    kind: EdgeKind::Handle,
                });
                held_by[to].push(future.owner);
            }
        }
        for from in &mut edges {
            // By task, then by kind, so a task named twice keeps the
            // most direct claim: an await it is actually in, over a set
            // it is merely a member of, over a handle someone merely
            // holds.
            from.sort_unstable();
            from.dedup_by_key(|edge| edge.to);
        }
        for list in waited_by.iter_mut().chain(held_by.iter_mut()) {
            // Two frames holding one handle are one relation.
            list.sort_unstable();
            list.dedup();
        }
        Relations {
            edges,
            waited_by,
            held_by,
            member_of,
        }
    }

    /// Whether anything relates to `index` as a resource: some task
    /// waits to join it, holds its handle, or drives the set it is in.
    /// This is what earns a task a join block in a bare `sync` listing
    /// — "contended" in the join sense — as opposed to one per task.
    pub(crate) fn joined(&self, index: usize) -> bool {
        !self.waited_by[index].is_empty()
            || !self.held_by[index].is_empty()
            || self.member_of[index].is_some()
    }
}

#[cfg(test)]
mod relations_tests {
    use super::{EdgeKind, Relations};

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::bundle::{FutureInfo, Task, TaskList, WaitKind, WaitTarget};
    use hansei_runtime::tokio::census;
    use hansei_runtime::tokio::graph::{Analysis, TaskRef, TaskWait};
    use hansei_runtime::tokio::{TaskAddr, TaskState};

    const REF_ONE: u64 = 1 << 6;

    fn addr(id: u64) -> TaskAddr {
        TaskAddr(0x1000 + id * 0x100)
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
            task: TaskRef {
                addr: addr(id),
                task_id: Some(id),
            },
            target,
            depth: 1,
            leaf: None,
            site: None,
        }
    }

    fn joining(id: u64) -> WaitTarget {
        WaitTarget::Task {
            addr: addr(id).0,
            task_id: Some(id),
            state: TaskState(REF_ONE),
            listed: true,
            kind: None,
        }
    }

    fn held_handle(owner: usize, id: u64) -> census::HeldFuture {
        census::HeldFuture {
            depth: 1,
            owner,
            frame: 0,
            local: "handle".to_string(),
            via: None,
            slot: 0xd000,
            addr: 0xd000,
            ty: BundleTypeId(0),
            future: "tokio::runtime::task::join::JoinHandle<()>".to_string(),
            state: None,
            waiting_on: None,
            wait: Some(WaitKind::Task { addr: addr(id).0 }),
            leaf: None,
        }
    }

    fn join_set(owner: usize, ids: &[u64]) -> census::JoinSet {
        census::JoinSet {
            owner,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: 0xb000,
            ty: "tokio::task::join_set::JoinSet<()>".to_string(),
            length: ids.len() as u64,
            children: ids
                .iter()
                .map(|id| census::JoinedTask {
                    entry: 0xc000,
                    task: addr(*id).0,
                    id: Some(*id),
                    state: TaskState(REF_ONE),
                    listed: true,
                })
                .collect(),
        }
    }

    fn build(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
    ) -> Relations {
        let list = TaskList {
            tasks,
            errors: Vec::new(),
        };
        let analysis = Analysis {
            waits,
            futurelocks: Vec::new(),
            join_wakers: Vec::new(),
            errors: Vec::new(),
        };
        Relations::build(&list, &analysis, held, join_sets)
    }

    /// Every relation lands in both directions: the joiner's forward
    /// edge and the joined task's `waited_by`, the holder's edge and
    /// the held task's `held_by`, the driver's edge and the member's
    /// set — and only the related tasks read as joined.
    #[test]
    fn test_the_index_reverses_every_edge_kind() {
        let rel = build(
            vec![task(1), task(2), task(3), task(4), task(5)],
            vec![
                wait(1, Some(joining(2))),
                wait(2, None),
                wait(3, None),
                wait(4, None),
                wait(5, None),
            ],
            &[held_handle(1, 3)],
            &[join_set(2, &[4])],
        );
        assert_eq!(
            rel.edges[0],
            vec![super::Edge {
                to: 1,
                kind: EdgeKind::Waiting
            }]
        );
        assert_eq!(rel.waited_by[1], vec![0]);
        assert_eq!(
            rel.edges[1],
            vec![super::Edge {
                to: 2,
                kind: EdgeKind::Handle
            }]
        );
        assert_eq!(rel.held_by[2], vec![1]);
        assert_eq!(
            rel.edges[2],
            vec![super::Edge {
                to: 3,
                kind: EdgeKind::JoinSet
            }]
        );
        assert_eq!(rel.member_of[3], Some((0xb000, 2)));
        for joined in [1, 2, 3] {
            assert!(rel.joined(joined), "task index {joined} is joined");
        }
        for alone in [0, 4] {
            assert!(!rel.joined(alone), "task index {alone} is not joined");
        }
    }

    /// A task named by an edge but absent from the listing — completed
    /// and off the owned list — indexes nothing: there is no row for
    /// the relation to land on, and the wait's own text says so where
    /// it matters.
    #[test]
    fn test_an_unlisted_task_indexes_no_edge() {
        let rel = build(vec![task(1)], vec![wait(1, Some(joining(99)))], &[], &[]);
        assert!(rel.edges[0].is_empty());
        assert!(!rel.joined(0));
    }

    /// Two frames holding one task's handle are one relation, not two
    /// rows of a `held by` line.
    #[test]
    fn test_reverse_lists_dedup() {
        let rel = build(
            vec![task(1), task(2)],
            vec![wait(1, None), wait(2, None)],
            &[held_handle(0, 2), held_handle(0, 2)],
            &[],
        );
        assert_eq!(rel.held_by[1], vec![0]);
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `graph` command: the assessed dependency graph and the
//! conditional futurelock diagnosis.

use crate::relations::{Edge, EdgeKind, Relations};
use crate::tasks::{StopNames, assessment_cell, task_id};
use crate::{Session, output, print_warnings};

use anyhow::Result;
use hansei_bundle::names;
use hansei_runtime::tokio::assess::PollingBarrier;
use hansei_runtime::tokio::graph::{BarrierRelation, TaskRef};
use hansei_runtime::tokio::{bundle, graph};

use std::io;

pub(crate) fn exec_graph<T: proc::Target>(
    session: &Session<'_, T>,
    limit: Option<usize>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let analysis = session.analysis();
    print_warnings(&analysis.errors)?;
    print_graph(
        &session.tasks,
        analysis,
        session.relations(),
        &StopNames::of(session),
        limit,
        theme,
        out,
    )?;

    // A diagnosis is printed when there is one to print, and nothing is
    // said when there is not: the analysis reads only the edges it
    // knows how to read, so an empty result is "none found here",
    // which is not the same as the "no futurelock detected" it used to
    // claim.
    let behind = analysis.behind();
    for (index, barrier) in analysis.barriers.iter().enumerate() {
        writeln!(out)?;
        let behind: Vec<(TaskRef, BarrierRelation)> = behind
            .iter()
            .filter(|b| b.barrier == index)
            .map(|b| (analysis.waits[b.waiter].task, b.relation))
            .collect();
        let holder = TaskRef {
            addr: barrier.holder,
            task_id: barrier.holder_id,
        };
        print_barrier(holder, barrier, &behind, &session.impl_fold, out)?;
    }
    Ok(())
}

/// Print the wait graph: one row per task, nested under whatever is
/// waiting for it.
///
/// Reading down a tree is reading further into what blocks its root: a
/// task's own row says what it waits on, and its children are the rows
/// of the tasks that answer for it. Every task in the graph appears
/// exactly once, under the task waiting for it where one is and at the
/// left margin otherwise. A task in no graph at all — naming none and
/// named by none — is left out: it has a row in `tasks` and a wait in
/// `census`, and on a target where thirty tasks are related and twenty
/// thousand are not, printing the twenty thousand is what makes the
/// thirty impossible to find.
///
/// It takes what it prints rather than a session so the offline tests
/// can drive it.
fn print_graph(
    list: &bundle::TaskList,
    analysis: &graph::Analysis,
    relations: &Relations,
    stops: &StopNames<'_>,
    limit: Option<usize>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let edges = &relations.edges;
    let mut waited_for = vec![false; list.tasks.len()];
    for edge in edges.iter().flatten() {
        waited_for[edge.to] = true;
    }
    // A task that names none and is named by none is not part of any
    // graph. It has a row in `tasks` and a wait in `census`; here it
    // would be one line of a page of them, and on a target where a few
    // dozen tasks are related and twenty thousand are not, those lines
    // are the whole reason the related ones cannot be found.
    let alone = |i: usize| edges[i].is_empty() && !waited_for[i];

    let mut rows = Vec::new();
    let mut walk = GraphWalk {
        list,
        analysis,
        stops,
        edges,
        printed: vec![false; list.tasks.len()],
        path: Vec::new(),
        rows: &mut rows,
    };
    // The tasks nothing waits for are the tops of the trees. What is
    // left over after them is in a cycle — a task joining itself, or two
    // waiting on each other — which has no such top; those are walked
    // from wherever they are reached, and the row that closes the loop
    // says so.
    // Where each tree's rows begin, so a limit cuts between trees
    // rather than mid-subtree.
    let mut starts = Vec::new();
    for (root, waited) in waited_for.iter().enumerate() {
        if !waited && !alone(root) {
            starts.push(walk.rows.len());
            walk.visit(root, "", None, EdgeKind::Waiting);
        }
    }
    for root in 0..list.tasks.len() {
        if !walk.printed[root] && !alone(root) {
            starts.push(walk.rows.len());
            walk.visit(root, "", None, EdgeKind::Waiting);
        }
    }

    let roots = starts.len();
    let shown = limit.unwrap_or(roots).min(roots);
    let cut = starts.get(shown).copied().unwrap_or(rows.len());
    let mut table = output::Table::new(3)
        .header(["TASK", "STATE", "WAITING ON"])
        .theme(theme);
    for [id, state, target] in rows.drain(..cut) {
        table.row([id, state, target]);
    }
    // A heading over nothing reads as a graph that failed to print
    // rather than a target with no edges to draw.
    if !table.is_empty() {
        table.write(out)?;
    }
    // The footer earns its line only when a limit cut the listing —
    // an uncut graph never printed a count, and every tree there is
    // remains the quiet answer.
    if shown < roots {
        writeln!(
            out,
            "{}",
            crate::tasks::listing_footer(roots, shown, "root")
        )?;
    }
    Ok(())
}

/// The walk behind [`print_graph`], carrying what one recursive step
/// needs.
struct GraphWalk<'a> {
    list: &'a bundle::TaskList,
    analysis: &'a graph::Analysis,
    stops: &'a StopNames<'a>,
    edges: &'a [Vec<Edge>],
    /// Every task already given a row, so one reached twice — two tasks
    /// blocked on the semaphore one acquire holds — is spelled out once
    /// and referred back to after that.
    printed: Vec<bool>,
    /// The tasks between the root and here, each with the edge that
    /// led to it, for spotting a wait that closes back on one of them.
    path: Vec<(usize, EdgeKind)>,
    rows: &'a mut Vec<[String; 3]>,
}

impl GraphWalk<'_> {
    /// Give `task` a row and walk what it waits for. `last` says
    /// whether it is the final child of the task above it, which is
    /// what decides its branch glyph and whether the rows under it
    /// carry a rule down to their own; `None` is a task at the margin,
    /// which has neither.
    fn visit(&mut self, task: usize, prefix: &str, last: Option<bool>, kind: EdgeKind) {
        let glyph = match last {
            None => "",
            Some(true) => "└─ ",
            Some(false) => "├─ ",
        };
        let name = format!("{prefix}{glyph}{}{}", task_id(self.list, task), kind.mark());
        let state = self.list.tasks[task].state.lifecycle().to_string();

        // A wait that closes back on the path is a cycle — the task is
        // blocked on something that is blocked on it; a task joining
        // itself is the one-node case — but only where every edge of
        // the closing segment, this one included, is a verified wait.
        // A reservation, a queue place, a set membership or a held
        // handle on the way round is a relation, not a dependency, and
        // the row is referred back to as one reached again. What lies
        // before the segment does not decide: a containment edge can
        // lead into a genuine cycle of waits.
        if let Some(start) = self.path.iter().position(|(t, _)| *t == task) {
            let closing = kind.is_wait() && self.path[start + 1..].iter().all(|(_, k)| k.is_wait());
            let mark = if closing { "← cycle" } else { "(above)" };
            self.rows
                .push([format!("{name} {mark}"), state, String::new()]);
            return;
        }
        // Reached a second time by another route — two tasks blocked on
        // the semaphore one acquire holds. Its own subtree is wherever
        // it was first printed; repeating it would double every task
        // under it.
        if self.printed[task] {
            self.rows
                .push([format!("{name} (above)"), state, String::new()]);
            return;
        }

        // What the analysis assessed the task to be waiting on, spelled
        // the way the task table spells it. A `-` is for a task with no
        // assessment at all.
        let target = match self.analysis.waits.get(task) {
            Some(wait) => assessment_cell(wait, self.stops),
            None => "-".to_string(),
        };
        self.rows.push([name, state, target]);
        self.printed[task] = true;

        let below = match last {
            None => prefix.to_string(),
            Some(true) => format!("{prefix}   "),
            Some(false) => format!("{prefix}│  "),
        };
        self.path.push((task, kind));
        let children = &self.edges[task];
        for (i, child) in children.iter().enumerate() {
            self.visit(child.to, &below, Some(i + 1 == children.len()), child.kind);
        }
        self.path.pop();
    }
}

/// Render one conditional futurelock diagnosis: who holds what, the
/// condition under which it cannot poll it, where the future is
/// parked, and who stands behind the reservation or the queue place.
///
/// The condition is spelled, not elided: an exclusive chain proves
/// the holder cannot poll the acquire before its terminal completes,
/// and nothing here proves the terminal never will, or that the
/// waiters behind it depend on this holder alone.
fn print_barrier(
    holder: TaskRef,
    barrier: &PollingBarrier,
    behind: &[(TaskRef, BarrierRelation)],
    impls: &names::ImplFold,
    out: &mut dyn io::Write,
) -> Result<()> {
    let acq = &barrier.acquire;
    let semaphore = match barrier.owner {
        Some(owner) => format!("a {owner} (semaphore {:#x})", acq.semaphore.addr),
        None => format!("the semaphore at {:#x}", acq.semaphore.addr),
    };
    let held = if barrier.granted() {
        let plural = if acq.requested == 1 { "" } else { "s" };
        format!("{} granted permit{plural}", acq.requested)
    } else {
        match acq.queue_position {
            Some(position) => format!("place {position} in the wake queue"),
            None => "a place in the wake queue".to_string(),
        }
    };
    writeln!(
        out,
        "futurelock: {holder} holds {held} of {semaphore} in a future it cannot poll \
         until the {} it awaits completes:",
        names::display_future_name(&barrier.terminal, impls)
    )?;
    let loc = barrier
        .await_loc
        .as_ref()
        .map(|(file, line)| format!(" — {file}:{line}"))
        .unwrap_or_default();
    writeln!(
        out,
        "  `{}` ({})",
        barrier.local,
        names::display_future_name(&barrier.future, impls)
    )?;
    writeln!(
        out,
        "  held across {} state {}{loc}",
        names::display_future_name(&barrier.frame_type, impls),
        barrier.state
    )?;
    let reserved: Vec<String> = behind
        .iter()
        .filter(|(_, relation)| *relation == BarrierRelation::Reservation)
        .map(|(task, _)| task.to_string())
        .collect();
    let queued: Vec<String> = behind
        .iter()
        .filter(|(_, relation)| *relation == BarrierRelation::QueueOrder)
        .map(|(task, _)| task.to_string())
        .collect();
    if reserved.is_empty() && queued.is_empty() {
        writeln!(out, "  nothing is waiting on the semaphore behind it yet")?;
    }
    if !reserved.is_empty() {
        writeln!(
            out,
            "  waiting on the permits it holds: {}",
            reserved.join(", ")
        )?;
    }
    if !queued.is_empty() {
        writeln!(out, "  queued behind it: {}", queued.join(", "))?;
    }
    Ok(())
}

#[cfg(test)]
mod graph_tests {
    use super::{BarrierRelation, StopNames, names, print_barrier, print_graph};

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::assess::{
        ContinuationStatus, IncompleteReason, PollingBarrier, VerifiedWait, WaitAssessment,
        WaitUnknownReason,
    };
    use hansei_runtime::tokio::bundle::{
        FutureInfo, OwnerResolution, Task, TaskKind, TaskList, WaitKind, WaitTarget,
    };
    use hansei_runtime::tokio::census;
    use hansei_runtime::tokio::graph::{Analysis, TaskRef, TaskWait};
    use hansei_runtime::tokio::observe::{AcquireObservation, ValueKey};
    use hansei_runtime::tokio::{RawInstant, TaskAddr, TaskState};

    const REF_ONE: u64 = 1 << 6;
    const SEMAPHORE: u64 = 0x9000;

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
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
        }
    }

    /// A task assessed as verified-waiting on `target`, or — with no
    /// target — with its continuation unknown: parked on a future no
    /// reviewed rule covers.
    fn wait(id: u64, target: Option<WaitTarget>) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: addr(id),
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

    fn semaphore() -> WaitTarget {
        WaitTarget::Semaphore {
            addr: SEMAPHORE,
            owner: Some("tokio::sync::Mutex"),
            num_permits: 1,
            available: 0,
            closed: false,
            waiters: Vec::new(),
        }
    }

    fn timer() -> WaitTarget {
        WaitTarget::Timer {
            deadline: RawInstant {
                tv_sec: 12,
                tv_nsec: 0,
            },
            stopped: Some(RawInstant {
                tv_sec: 2,
                tv_nsec: 0,
            }),
        }
    }

    /// The task holding a granted acquire on the semaphore in a future
    /// its exclusive chain cannot poll until its terminal completes —
    /// the relation that says whose reservation a lock's waiters stand
    /// behind.
    fn barrier(holder: u64) -> PollingBarrier {
        let key = |addr: u64| ValueKey {
            addr,
            ty: BundleTypeId(0),
        };
        PollingBarrier {
            holder: addr(holder),
            holder_id: Some(holder),
            frame: 0,
            frame_type: "worker::{async_fn_env#0}".to_string(),
            state: "Suspend0".to_string(),
            await_loc: None,
            local: "lock".to_string(),
            candidate: key(0xa000),
            future: "Mutex::lock::{async_fn_env#0}".to_string(),
            owner: Some("tokio::sync::Mutex"),
            acquire: AcquireObservation {
                future: key(0xa000),
                semaphore: key(SEMAPHORE),
                node: 0xa000,
                requested: 1,
                needed: 0,
                queued: true,
                queue_position: None,
            },
            primitive: key(0xb000),
            terminal: "tokio::sync::batch_semaphore::Acquire".to_string(),
            edges: Vec::new(),
        }
    }

    fn graph(tasks: Vec<Task>, waits: Vec<TaskWait>, barriers: Vec<PollingBarrier>) -> String {
        graph_with(tasks, waits, barriers, &[], &[])
    }

    /// The same graph cut to its first `limit` trees.
    fn graph_limited(tasks: Vec<Task>, waits: Vec<TaskWait>, limit: usize) -> String {
        graph_full(tasks, waits, Vec::new(), &[], &[], Some(limit))
    }

    /// A graph over what the census found in the tasks' frames as well:
    /// the sets they drive and the handles they hold.
    fn graph_with(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        barriers: Vec<PollingBarrier>,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
    ) -> String {
        graph_full(tasks, waits, barriers, held, join_sets, None)
    }

    fn graph_full(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        barriers: Vec<PollingBarrier>,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
        limit: Option<usize>,
    ) -> String {
        let list = TaskList::new(tasks);
        let analysis = Analysis {
            waits,
            barriers,
            join_wakers: Vec::new(),
            errors: Vec::new(),
        };
        let relations = crate::relations::Relations::build(&list, &analysis, held, join_sets);
        let mut out = Vec::new();
        print_graph(
            &list,
            &analysis,
            &relations,
            &StopNames::none(&Default::default()),
            limit,
            crate::output::Theme::plain(),
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    /// A `JoinSet` in `owner`'s frames holding the tasks with these ids.
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

    /// A `JoinHandle` to `id` sitting in `owner`'s frames, off its
    /// await chain.
    fn held_handle(owner: usize, id: u64) -> census::HeldFuture {
        census::HeldFuture {
            depth: 1,
            frames: Vec::new(),
            owner,
            frame: 0,
            local: "cancel_task".to_string(),
            via: None,
            slot: 0xd000,
            addr: 0xd000,
            ty: BundleTypeId(0),
            future: "tokio::runtime::task::join::JoinHandle<()>".to_string(),
            state: None,
            waiting_on: None,
            wait: Some(WaitKind::Task { addr: addr(id).0 }),
            observation: None,
            continuation: ContinuationStatus::Primitive,
        }
    }

    /// A chain of waits reads as one tree: the joiner at the margin, the
    /// task it joins under it, and — since the analysis names who holds
    /// permits of the lock that task waits on — the holder under that,
    /// marked as the reservation it is rather than a wait. Every task
    /// keeps its one row.
    #[test]
    fn test_a_wait_chain_nests_to_its_depth() {
        let page = graph(
            vec![task(12), task(40), task(51)],
            vec![
                wait(12, Some(joining(40))),
                wait(40, Some(semaphore())),
                wait(51, Some(timer())),
            ],
            vec![barrier(51)],
        );
        assert_eq!(
            page,
            "\
TASK                                    STATE  WAITING ON
12                                      idle   task 40
└─ 40                                   idle   semaphore
   └─ 51 [holds permits awaited above]  idle   timer
"
        );
    }

    /// A task waiting on something that is waiting on it has no top to
    /// hang from. It is walked anyway, and the row that closes the loop
    /// says so rather than recurring forever.
    #[test]
    fn test_a_cycle_is_walked_once_and_marked() {
        let page = graph(
            vec![task(88)],
            vec![wait(88, Some(joining(88)))],
            Vec::new(),
        );
        assert_eq!(
            page,
            "\
TASK           STATE  WAITING ON
88             idle   task 88
└─ 88 ← cycle  idle   
"
        );
    }

    /// Two tasks waiting on the same lock both stand behind its
    /// holder's reservation. It is spelled out under the first and
    /// referred back to under the second, so its subtree is not printed
    /// twice.
    #[test]
    fn test_a_task_reached_twice_is_printed_once() {
        let page = graph(
            vec![task(40), task(41), task(51)],
            vec![
                wait(40, Some(semaphore())),
                wait(41, Some(semaphore())),
                wait(51, Some(timer())),
            ],
            vec![barrier(51)],
        );
        assert_eq!(
            page,
            "\
TASK                                         STATE  WAITING ON
40                                           idle   semaphore
└─ 51 [holds permits awaited above]          idle   timer
41                                           idle   semaphore
└─ 51 [holds permits awaited above] (above)  idle   
"
        );
    }

    /// A join that is one of several things a task is parked on closes
    /// no cycle either: the task polling its own join among other
    /// branches is referred back to, marked as the weaker relation,
    /// and its cell names the set — here the one armed member.
    #[test]
    fn test_a_one_of_edge_closing_the_path_is_no_cycle() {
        use hansei_bundle::SemanticIssueKind;
        use hansei_runtime::tokio::waitset::{MemberRoute, SlotRef, WaitMember, WaitSet};

        let mut set = wait(88, None);
        set.assessment = WaitAssessment::Set(WaitSet {
            at: Some(ValueKey {
                addr: 0x5000,
                ty: BundleTypeId(0),
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
                    joining(88),
                    None,
                ))),
                notes: Vec::new(),
                armed: Some(SlotRef::Protocol),
                entries: None,
            }],
            capped: 0,
        });
        let page = graph(vec![task(88)], vec![set], Vec::new());
        assert_eq!(
            page,
            "\
TASK                                    STATE  WAITING ON
88                                      idle   task 88
└─ 88 [one of the waits above] (above)  idle   
"
        );
    }

    /// A reservation that closes back on the path is no cycle: the
    /// task waiting on a lock whose permits it holds itself — the
    /// futurelock shape — is referred back to, not marked as blocked
    /// on itself, since the relation is conditional on its own chain
    /// and nothing proves that chain never completes.
    #[test]
    fn test_a_weak_edge_closing_the_path_is_no_cycle() {
        let page = graph(
            vec![task(40)],
            vec![wait(40, Some(semaphore()))],
            vec![barrier(40)],
        );
        assert_eq!(
            page,
            "\
TASK                                         STATE  WAITING ON
40                                           idle   semaphore
└─ 40 [holds permits awaited above] (above)  idle   
"
        );
    }

    /// A cycle of verified waits reached through a containment edge is
    /// still a cycle: only the closing segment decides, and every edge
    /// of it is a wait.
    #[test]
    fn test_a_wait_cycle_behind_a_held_handle_is_marked() {
        let page = graph_with(
            vec![task(7), task(8), task(9)],
            vec![
                wait(7, None),
                wait(8, Some(joining(9))),
                wait(9, Some(joining(8))),
            ],
            Vec::new(),
            &[held_handle(0, 8)],
            &[],
        );
        assert_eq!(
            page,
            "\
TASK                          STATE  WAITING ON
7                             idle   unknown (no root in the tokio info)
└─ 8 [its handle held above]  idle   task 9
   └─ 9                       idle   task 8
      └─ 8 ← cycle            idle   
"
        );
    }

    /// A `JoinSet`'s members hang under the task driving it. Nothing
    /// about that task's own wait names them — `join_next` is not a
    /// `JoinHandle` await — so without this edge a runtime built out of
    /// parallel task sets graphs as a runtime with no structure.
    #[test]
    fn test_join_set_members_hang_under_their_owner() {
        let page = graph_with(
            vec![task(7), task(8), task(9)],
            vec![wait(7, None), wait(8, None), wait(9, None)],
            Vec::new(),
            &[],
            &[join_set(0, &[8, 9])],
        );
        assert_eq!(
            page,
            "\
TASK                         STATE  WAITING ON
7                            idle   unknown (no root in the tokio info)
├─ 8 [in the JoinSet above]  idle   unknown (no root in the tokio info)
└─ 9 [in the JoinSet above]  idle   unknown (no root in the tokio info)
"
        );
    }

    /// A handle a frame merely holds is an edge too, and marked as one:
    /// the task can join or abort what it points at, and may be doing
    /// neither.
    #[test]
    fn test_a_held_handle_is_marked_as_held() {
        let page = graph_with(
            vec![task(7), task(8)],
            vec![wait(7, None), wait(8, Some(timer()))],
            Vec::new(),
            &[held_handle(0, 8)],
            &[],
        );
        assert_eq!(
            page,
            "\
TASK                          STATE  WAITING ON
7                             idle   unknown (no root in the tokio info)
└─ 8 [its handle held above]  idle   timer
"
        );
    }

    /// A task in no graph is left out of it: `tasks` is where it is
    /// listed, and `census` where its wait is counted.
    #[test]
    fn test_tasks_in_no_graph_are_left_out() {
        let page = graph_with(
            vec![task(7), task(8), task(1), task(2)],
            vec![
                wait(7, None),
                wait(8, Some(timer())),
                wait(1, None),
                wait(2, None),
            ],
            Vec::new(),
            &[held_handle(0, 8)],
            &[],
        );
        assert_eq!(
            page,
            "\
TASK                          STATE  WAITING ON
7                             idle   unknown (no root in the tokio info)
└─ 8 [its handle held above]  idle   timer
"
        );
    }

    /// The diagnosis prose names the acquiring future, the frame it is
    /// held across and the terminal whose completion is the condition,
    /// with the display fold applied: env marker gone, kind word
    /// joined — and says who stands behind the reservation, by the
    /// relation they stand in.
    #[test]
    fn test_futurelock_prose_folds_its_names() {
        let mut out = Vec::new();
        let holder = TaskRef {
            addr: addr(51),
            task_id: Some(51),
        };
        let behind = [(
            TaskRef {
                addr: addr(40),
                task_id: Some(40),
            },
            BarrierRelation::Reservation,
        )];
        print_barrier(
            holder,
            &barrier(51),
            &behind,
            &names::ImplFold::default(),
            &mut out,
        )
        .unwrap();
        let prose = String::from_utf8(out).unwrap();
        assert!(
            prose.starts_with(
                "futurelock: task 51 holds 1 granted permit of a tokio::sync::Mutex \
                 (semaphore 0x9000) in a future it cannot poll until the future \
                 tokio::sync::batch_semaphore::Acquire it awaits completes:\n"
            ),
            "{prose}"
        );
        assert!(prose.contains("`lock` (async fn Mutex::lock)"), "{prose}");
        assert!(
            prose.contains("held across async fn worker state Suspend0"),
            "{prose}"
        );
        assert!(
            prose.ends_with("  waiting on the permits it holds: task 40\n"),
            "{prose}"
        );

        let mut out = Vec::new();
        print_barrier(
            holder,
            &barrier(51),
            &[],
            &names::ImplFold::default(),
            &mut out,
        )
        .unwrap();
        let prose = String::from_utf8(out).unwrap();
        assert!(
            prose.ends_with("  nothing is waiting on the semaphore behind it yet\n"),
            "{prose}"
        );
    }

    /// With nothing related at all there is nothing to print: a heading
    /// over no rows reads as a graph that failed rather than a target
    /// with no edges to draw.
    #[test]
    fn test_a_target_with_no_edges_prints_no_table() {
        let page = graph(vec![task(1)], vec![wait(1, None)], Vec::new());
        assert_eq!(page, "");
    }
    /// `--limit` counts trees by their roots: the cut falls between
    /// trees, never mid-subtree, and earns the footer; an uncut graph
    /// prints no count at all.
    #[test]
    fn test_a_limit_cuts_whole_trees_and_says_so() {
        // Two trees: 2 → 1 (a chain) and 3 → 4.
        let tasks = || vec![task(1), task(2), task(3), task(4)];
        let waits = || {
            vec![
                wait(1, None),
                wait(2, Some(joining(1))),
                wait(3, Some(joining(4))),
                wait(4, None),
            ]
        };

        let cut = graph_limited(tasks(), waits(), 1);
        assert!(cut.contains("\n2 "), "{cut}");
        assert!(cut.contains("└─ 1"), "{cut}");
        assert!(!cut.contains("\n3 "), "{cut}");
        assert!(!cut.contains("└─ 4"), "{cut}");
        assert!(cut.ends_with("[2 roots, 1 shown]\n"), "{cut}");

        let whole = graph_limited(tasks(), waits(), 2);
        assert!(whole.contains("└─ 4"), "{whole}");
        assert!(!whole.contains("shown]"), "{whole}");
    }
}

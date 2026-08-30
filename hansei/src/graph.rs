//! The `graph` command: the waker-based dependency graph and the
//! futurelock diagnosis.

use crate::tasks::task_id;
use crate::{Session, output, print_warnings};

use anyhow::Result;
use hansei_bundle::names;
use hansei_runtime::tokio::{bundle, census, graph};

use std::collections::HashMap;
use std::io;

pub(crate) fn exec_graph<T: proc::Target>(
    session: &Session<'_, T>,
    limit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let analysis = session.analysis();
    print_warnings(&analysis.errors)?;
    let census = session.census();
    print_graph(
        &session.tasks,
        analysis,
        &census.held,
        &census.join_sets,
        &session.impl_fold,
        limit,
        out,
    )?;

    // A diagnosis is printed when there is one to print, and nothing is
    // said when there is not: the analysis reads only the edges it
    // knows how to read, so an empty result is "none found here",
    // which is not the same as the "no futurelock detected" it used to
    // claim.
    for fl in &analysis.futurelocks {
        writeln!(out)?;
        print_futurelock(fl, &session.impl_fold, out)?;
    }
    Ok(())
}

/// Why one task's row hangs under another's.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EdgeKind {
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
    fn mark(self) -> &'static str {
        match self {
            Self::Waiting => "",
            Self::JoinSet => " [in the JoinSet above]",
            Self::Handle => " [its handle held above]",
        }
    }
}

/// One task's row, and why it hangs where it does.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    to: usize,
    kind: EdgeKind,
}

/// Which tasks each task is waiting for, by index into the task list.
///
/// Three things name a task. Two are the task's own wait: a
/// `JoinHandle` names the task being joined outright, and a contended
/// semaphore names whoever the futurelock analysis found holding an
/// acquire on it — the only case where a holder is knowable at all,
/// since a tokio `Mutex` records no owner. A timer names nobody, and
/// neither does a leaf hansei does not decode.
///
/// The third is what the census found in the task's frames: the members
/// of a `JoinSet` it drives, and the tasks it holds a `JoinHandle` to
/// without awaiting. Those are the edges a real target mostly has —
/// `join_next` on a set is not a `JoinHandle` await, so nothing about
/// the task's own wait mentions the tasks it is there to collect — and
/// leaving them out made the graph of a runtime running dozens of
/// parallel task sets look like a runtime with no structure at all.
fn wait_edges(
    list: &bundle::TaskList,
    analysis: &graph::Analysis,
    held: &[census::HeldFuture],
    join_sets: &[census::JoinSet],
) -> Vec<Vec<Edge>> {
    let index: HashMap<u64, usize> = list
        .tasks
        .iter()
        .enumerate()
        .map(|(i, t)| (t.addr.0, i))
        .collect();
    let mut edges: Vec<Vec<Edge>> = vec![Vec::new(); list.tasks.len()];
    let mut add = |from: usize, addr: u64, kind: EdgeKind| {
        // A task the runtime no longer owns has no row to point at; the
        // wait's own text says as much where it came from a wait.
        if let Some(&to) = index.get(&addr) {
            edges[from].push(Edge { to, kind });
        }
    };
    for (from, wait) in analysis.waits.iter().enumerate() {
        match &wait.target {
            Some(bundle::WaitTarget::Task { addr, .. }) => add(from, *addr, EdgeKind::Waiting),
            Some(bundle::WaitTarget::Semaphore { addr, .. }) => {
                for fl in analysis
                    .futurelocks
                    .iter()
                    .filter(|fl| fl.acquire.semaphore == *addr)
                {
                    add(from, fl.holder.addr.0, EdgeKind::Waiting);
                }
            }
            _ => {}
        }
    }
    for set in join_sets {
        for child in &set.children {
            add(set.owner, child.task, EdgeKind::JoinSet);
        }
    }
    for future in held {
        if let Some(bundle::WaitKind::Task { addr }) = future.wait {
            add(future.owner, addr, EdgeKind::Handle);
        }
    }
    for from in &mut edges {
        // By task, then by kind, so a task named twice keeps the most
        // direct claim: an await it is actually in, over a set it is
        // merely a member of, over a handle someone merely holds.
        from.sort_unstable();
        from.dedup_by_key(|edge| edge.to);
    }
    edges
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
    held: &[census::HeldFuture],
    join_sets: &[census::JoinSet],
    impls: &names::ImplFold,
    limit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let edges = wait_edges(list, analysis, held, join_sets);
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
        edges: &edges,
        printed: vec![false; list.tasks.len()],
        path: Vec::new(),
        rows: &mut rows,
        impls,
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
    let mut table = output::Table::new(3).header(["TASK", "STATE", "WAITING ON"]);
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
    edges: &'a [Vec<Edge>],
    /// Every task already given a row, so one reached twice — two tasks
    /// blocked on the semaphore one acquire holds — is spelled out once
    /// and referred back to after that.
    printed: Vec<bool>,
    /// The tasks between the root and here, for spotting a wait that
    /// closes back on one of them.
    path: Vec<usize>,
    rows: &'a mut Vec<[String; 3]>,
    impls: &'a names::ImplFold,
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

        // A wait that closes back on the path is a cycle: the task is
        // blocked on something that is blocked on it. A task joining
        // itself is the one-node case of it.
        if self.path.contains(&task) {
            self.rows
                .push([format!("{name} ← cycle"), state, String::new()]);
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

        // The primitive where hansei decodes one, and the type the
        // chain bottoms out in otherwise — which is most rows on a real
        // target. A `-` is for a task with no chain to have reached a
        // leaf at all: one mid-poll, finished, or whose walk stopped
        // short.
        let wait = &self.analysis.waits[task];
        let target = match (&wait.target, &wait.leaf) {
            (Some(target), _) => target.to_string(),
            (None, Some(leaf)) => names::display_future_name(leaf, self.impls),
            (None, None) => "-".to_string(),
        };
        self.rows.push([name, state, target]);
        self.printed[task] = true;

        let below = match last {
            None => prefix.to_string(),
            Some(true) => format!("{prefix}   "),
            Some(false) => format!("{prefix}│  "),
        };
        self.path.push(task);
        let children = &self.edges[task];
        for (i, child) in children.iter().enumerate() {
            self.visit(child.to, &below, Some(i + 1 == children.len()), child.kind);
        }
        self.path.pop();
    }
}

/// Render one futurelock diagnosis: who holds what, where the
/// abandoned future is parked, and who is stuck behind it.
fn print_futurelock(
    fl: &graph::Futurelock,
    impls: &names::ImplFold,
    out: &mut dyn io::Write,
) -> Result<()> {
    let acq = &fl.acquire;
    let semaphore = match acq.owner {
        Some(owner) => format!("a {owner} (semaphore {:#x})", acq.semaphore),
        None => format!("the semaphore at {:#x}", acq.semaphore),
    };
    let held = if acq.granted() {
        let plural = if acq.num_permits == 1 { "" } else { "s" };
        format!("{} granted permit{plural}", acq.num_permits)
    } else {
        "a place in the wake queue".to_string()
    };
    writeln!(
        out,
        "futurelock: {} holds {held} of {semaphore} in a future it stopped polling:",
        fl.holder
    )?;
    let loc = acq
        .await_loc
        .as_ref()
        .map(|(file, line)| format!(" — {file}:{line}"))
        .unwrap_or_default();
    writeln!(
        out,
        "  `{}` ({})",
        acq.local,
        names::display_future_name(&acq.future, impls)
    )?;
    writeln!(
        out,
        "  held across {} state {}{loc}",
        names::display_future_name(&acq.frame, impls),
        acq.state
    )?;
    if fl.blocked.is_empty() {
        writeln!(out, "  nothing is blocked behind it yet")?;
    } else {
        let blocked = fl
            .blocked
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "  blocked behind it: {blocked}")?;
    }
    Ok(())
}

#[cfg(test)]
mod graph_tests {
    use super::{names, print_futurelock, print_graph};

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::bundle::{
        AbandonedAcquire, FutureInfo, Task, TaskList, WaitKind, WaitTarget,
    };
    use hansei_runtime::tokio::census;
    use hansei_runtime::tokio::graph::{Analysis, Futurelock, TaskRef, TaskWait};
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
            group: 0,
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

    /// A task parked on an ordinary future rather than on one of the
    /// primitives hansei decodes into a wait target.
    fn leaf_wait(id: u64, leaf: &str) -> TaskWait {
        TaskWait {
            leaf: Some(leaf.to_string()),
            ..wait(id, None)
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

    /// The task holding an acquire on the semaphore in a future it
    /// stopped polling — the edge that says who a lock's waiters are
    /// really waiting for.
    fn futurelock(holder: u64) -> Futurelock {
        Futurelock {
            holder: TaskRef {
                addr: addr(holder),
                task_id: Some(holder),
            },
            acquire: AbandonedAcquire {
                frame: "worker::{async_fn_env#0}".to_string(),
                state: "Suspend0".to_string(),
                await_loc: None,
                local: "lock".to_string(),
                future: "Mutex::lock::{async_fn_env#0}".to_string(),
                owner: Some("tokio::sync::Mutex"),
                semaphore: SEMAPHORE,
                node: 0xa000,
                num_permits: 1,
                needed: 0,
            },
            blocked: Vec::new(),
        }
    }

    fn graph(tasks: Vec<Task>, waits: Vec<TaskWait>, futurelocks: Vec<Futurelock>) -> String {
        graph_with(tasks, waits, futurelocks, &[], &[])
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
        futurelocks: Vec<Futurelock>,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
    ) -> String {
        graph_full(tasks, waits, futurelocks, held, join_sets, None)
    }

    fn graph_full(
        tasks: Vec<Task>,
        waits: Vec<TaskWait>,
        futurelocks: Vec<Futurelock>,
        held: &[census::HeldFuture],
        join_sets: &[census::JoinSet],
        limit: Option<usize>,
    ) -> String {
        let list = TaskList {
            tasks,
            errors: Vec::new(),
        };
        let analysis = Analysis {
            waits,
            futurelocks,
            errors: Vec::new(),
        };
        let mut out = Vec::new();
        print_graph(
            &list,
            &analysis,
            held,
            join_sets,
            &names::ImplFold::default(),
            limit,
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
            leaf: None,
        }
    }

    /// A chain of waits reads as one tree: the joiner at the margin, the
    /// task it joins under it, and — since the futurelock analysis names
    /// who holds the lock that task is blocked on — the holder under
    /// that. Every task keeps its one row.
    #[test]
    fn test_a_wait_chain_nests_to_its_depth() {
        let page = graph(
            vec![task(12), task(40), task(51)],
            vec![
                wait(12, Some(joining(40))),
                wait(40, Some(semaphore())),
                wait(51, Some(timer())),
            ],
            vec![futurelock(51)],
        );
        assert_eq!(
            page,
            "\
TASK      STATE  WAITING ON
12        idle   task 40 (JoinHandle)
└─ 40     idle   a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available
   └─ 51  idle   the timer: deadline 10.000s
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
88             idle   task 88 (JoinHandle)
└─ 88 ← cycle  idle   
"
        );
    }

    /// Two tasks blocked on the same lock both point at its holder. It
    /// is spelled out under the first and referred back to under the
    /// second, so its subtree is not printed twice.
    #[test]
    fn test_a_task_reached_twice_is_printed_once() {
        let page = graph(
            vec![task(40), task(41), task(51)],
            vec![
                wait(40, Some(semaphore())),
                wait(41, Some(semaphore())),
                wait(51, Some(timer())),
            ],
            vec![futurelock(51)],
        );
        assert_eq!(
            page,
            "\
TASK           STATE  WAITING ON
40             idle   a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available
└─ 51          idle   the timer: deadline 10.000s
41             idle   a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available
└─ 51 (above)  idle   
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
7                            idle   -
├─ 8 [in the JoinSet above]  idle   -
└─ 9 [in the JoinSet above]  idle   -
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
7                             idle   -
└─ 8 [its handle held above]  idle   the timer: deadline 10.000s
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
                leaf_wait(1, "tokio::runtime::io::scheduled_io::Readiness"),
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
7                             idle   -
└─ 8 [its handle held above]  idle   the timer: deadline 10.000s
"
        );
    }

    /// The diagnosis prose names the acquiring future and the frame it
    /// is held across with the display fold applied: env marker gone,
    /// kind word joined.
    #[test]
    fn test_futurelock_prose_folds_its_names() {
        let mut out = Vec::new();
        print_futurelock(&futurelock(51), &names::ImplFold::default(), &mut out).unwrap();
        let prose = String::from_utf8(out).unwrap();
        assert!(prose.contains("`lock` (async fn Mutex::lock)"), "{prose}");
        assert!(
            prose.contains("held across async fn worker state Suspend0"),
            "{prose}"
        );
    }

    /// With nothing related at all there is nothing to print: a heading
    /// over no rows reads as a graph that failed rather than a target
    /// with no edges to draw.
    #[test]
    fn test_a_target_with_no_edges_prints_no_table() {
        let page = graph(
            vec![task(1)],
            vec![leaf_wait(1, "tokio::runtime::io::scheduled_io::Readiness")],
            Vec::new(),
        );
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

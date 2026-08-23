//! The `whatis` command: what an address is, outermost first.

use crate::Session;
use crate::tasks::{future_name, task_id, task_label};

use anyhow::Result;
use hansei_bundle::BundleView;
use hansei_bundle::names;
use hansei_runtime::tokio::{bundle, census};

use std::io;

pub(crate) fn exec_whatis(session: &Session<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    report_whatis(
        &session.ctx.view,
        &session.runtimes,
        &session.local_sets,
        &session.tasks,
        session.extents(),
        session.census(),
        &session.impl_fold,
        addr,
        out,
    )
}

/// The `whatis` answer, apart from the session so the offline fixture
/// tests can drive it.
///
/// An address belongs to whatever contains it, and those things nest:
/// a held future lives in a frame of its task's allocation, a set in a
/// frame of whatever drives it, a set child in a heap node of its own.
/// So this reports every claim rather than the first one it finds, in
/// containment order — the task's allocation, then a set child's node,
/// then the held futures from widest to narrowest, then a set — which
/// makes reading down the report reading inward.
///
/// The executors come first, outside that nesting rather than at the
/// top of it: a runtime handle contains no task's memory and no task's
/// memory contains it, but it is the coarsest thing an address can be,
/// and the one a reader is least able to recognize by eye.
#[allow(clippy::too_many_arguments)]
fn report_whatis(
    view: &BundleView<'_>,
    runtimes: &[bundle::RuntimeRef<'_>],
    local_sets: &[bundle::LocalSetRef<'_>],
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    impls: &names::ImplFold,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut blocks = 0;
    let owned = |group: usize| list.tasks.iter().filter(|t| t.group == group).count();

    for (index, rt) in runtimes.iter().enumerate() {
        let Some(offset) = within(rt.handle.addr, rt.handle.ty.size(), addr) else {
            continue;
        };
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "{}: {}",
            capitalized(&crate::runtimes::runtime_label(index, rt)),
            rt.flavor
        )?;
        writeln!(out, "    At: offset {offset:#x} in the runtime's handle")?;
        let threads = match rt.worker_tids.is_empty() {
            true => "none inside it".to_string(),
            false => {
                let tids: Vec<String> = rt.worker_tids.iter().map(|t| t.to_string()).collect();
                format!("lwp {}", tids.join(", "))
            }
        };
        writeln!(out, "    Threads: {threads}")?;
        writeln!(out, "    Found via: {}", rt.route)?;
        writeln!(out, "    Tasks: {}", owned(index))?;
    }

    for (index, set) in local_sets.iter().enumerate() {
        let Some(offset) = within(set.shared.addr, set.shared.ty.size(), addr) else {
            continue;
        };
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "{}:",
            capitalized(&crate::runtimes::local_set_label(index, set))
        )?;
        writeln!(out, "    At: offset {offset:#x} in the set's shared state")?;
        let pinned = match set.owner_tid {
            Some(tid) => format!("lwp {tid}"),
            None => "no thread hansei can name".to_string(),
        };
        writeln!(out, "    Pinned to: {pinned}")?;
        writeln!(out, "    Found via: {}", set.route)?;
        writeln!(out, "    Tasks: {}", owned(runtimes.len() + index))?;
    }

    if let Some((index, offset)) = extents.locate(addr) {
        let task = &list.tasks[index];
        let id = task_id(list, index);
        separate(&mut blocks, out)?;
        writeln!(out, "Task {id}: {}", future_name(&task.future, impls))?;
        writeln!(
            out,
            "    At: offset {offset:#x} in the task's allocation (header {:?})",
            task.addr
        )?;
        writeln!(out, "    State: {}", task.state.lifecycle())?;
        if let Some(loc) = &task.spawn_location {
            writeln!(out, "    Spawned at: {loc}")?;
        }
    }

    // A set child's node is its own heap allocation, outside every
    // task's — but the task that polls the set is what a wake there
    // ultimately runs, so the block names it.
    if let Some((set_index, child_index, offset)) = census.locate(addr) {
        let set = &census.sets[set_index];
        let child = &set.children[child_index];
        separate(&mut blocks, out)?;
        let future = match &child.future {
            Some(future) => names::display_future_name(future, impls),
            None => "<completed, not yet reaped>".to_string(),
        };
        writeln!(out, "Future {:#x}: {future}", child.node)?;
        writeln!(
            out,
            "    At: offset {offset:#x} in a FuturesUnordered child node"
        )?;
        if let Some(state) = &child.state {
            writeln!(out, "    State: {state}")?;
        }
        if let Some(waiting) = &child.waiting_on {
            writeln!(out, "    Waiting on: {waiting}")?;
        }
        writeln!(
            out,
            "    Child of: {} at {:#x} (frame {}, `{}`{})",
            names::fold_type_name(&set.ty, impls),
            set.addr,
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
        writeln!(
            out,
            "    Polled by: {} — {}",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future, impls)
        )?;
    }

    // Widest first: a future awaited by value sits inside the one
    // awaiting it, so an interior address is claimed by each of them
    // and the narrowest is the future the address is really in.
    let mut held: Vec<(u64, &census::HeldFuture)> = census
        .held
        .iter()
        .filter_map(|h| {
            // A size the bundle does not carry leaves the future's own
            // address, which is what a reader pastes in anyway.
            let size = view.ty(h.ty).map_or(0, |ty| ty.size());
            let extent = h.addr..h.addr.saturating_add(size);
            (h.addr == addr || extent.contains(&addr)).then_some((size, h))
        })
        .collect();
    held.sort_by_key(|&(size, h)| (std::cmp::Reverse(size), h.addr));
    for (_, h) in held {
        separate(&mut blocks, out)?;
        writeln!(
            out,
            "Future {:#x}: {}",
            h.addr,
            names::display_future_name(&h.future, impls)
        )?;
        writeln!(out, "    At: offset {:#x} in the future", addr - h.addr)?;
        if let Some(state) = &h.state {
            writeln!(out, "    State: {state}")?;
        }
        if let Some(waiting) = &h.waiting_on {
            writeln!(out, "    Waiting on: {waiting}")?;
        }
        writeln!(
            out,
            "    Held by: {} — {} (frame {}, `{}`{})",
            task_label(list, h.owner),
            future_name(&list.tasks[h.owner].future, impls),
            h.frame,
            h.local,
            via_suffix(census, h.via)
        )?;
    }

    // A set is claimed by its own address alone: the census records
    // where one starts but not how long it is, so an address inside one
    // is reported as whatever frame holds it instead.
    for set in census.sets.iter().filter(|s| s.addr == addr) {
        separate(&mut blocks, out)?;
        let live = set.children.iter().filter(|c| c.future.is_some()).count();
        let reaped = match set.children.len() - live {
            0 => String::new(),
            n => format!(", {n} completed and not yet reaped"),
        };
        writeln!(
            out,
            "Set {addr:#x}: {}",
            names::fold_type_name(&set.ty, impls)
        )?;
        writeln!(out, "    Children: {live} in flight{reaped}")?;
        writeln!(
            out,
            "    Driven by: {} — {} (frame {}, `{}`{})",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future, impls),
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
    }

    if blocks == 0 {
        writeln!(
            out,
            "no task's allocation and no future the census found contains {addr:#x}"
        )?;
    }
    Ok(())
}

/// A group's label as a block heading: the listings spell it in
/// running prose, and every other heading here leads with a capital.
fn capitalized(label: &str) -> String {
    let mut chars = label.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Where `addr` falls in an object of `size` bytes at `start`, or
/// `None` when it falls outside it. A zero size claims the start
/// address alone: a type the bundle carries no size for still has an
/// address worth recognizing, and it is the one a reader pastes in.
fn within(start: u64, size: u64, addr: u64) -> Option<u64> {
    let end = start.saturating_add(size.max(1));
    (start..end).contains(&addr).then(|| addr - start)
}

/// Open a block, with a blank line between it and the one before.
fn separate(blocks: &mut usize, out: &mut dyn io::Write) -> Result<()> {
    if *blocks > 0 {
        writeln!(out)?;
    }
    *blocks += 1;
    Ok(())
}

/// How the census reached a find, for the line that says where it
/// lives: empty when it was found in a task's own frames, and naming
/// the future or set child whose frames it was found in otherwise.
pub(crate) fn via_suffix(census: &census::FutureCensus, via: Option<census::Via>) -> String {
    via.map(|v| format!(", via {}", census.describe(v)))
        .unwrap_or_default()
}

/// Offline `whatis` tests: what an address resolves to over a real
/// extracted bundle joined against a real captured snapshot.
#[cfg(test)]
mod whatis_tests {
    use super::{report_whatis, separate};
    use crate::parse_hex_addr;
    use hansei_bundle::BundleView;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::{LocalSetRef, RuntimeRef, TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};

    /// Everything a report is made from: the whole of what an attach
    /// finds, so a test can point at any of it.
    struct Target<'a> {
        view: BundleView<'a>,
        runtimes: Vec<RuntimeRef<'a>>,
        local_sets: Vec<LocalSetRef<'a>>,
        list: TaskList,
        extents: TaskExtents,
        census: FutureCensus,
    }

    fn with_tasks(program: &str, check: impl FnOnce(&Target<'_>)) {
        let (bundle, snapshot) = testkit::load_any(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&Target {
            view: ctx.view,
            runtimes,
            local_sets,
            list,
            extents,
            census,
        });
    }

    fn report(target: &Target<'_>, addr: u64) -> String {
        let mut out = Vec::new();
        report_whatis(
            &target.view,
            &target.runtimes,
            &target.local_sets,
            &target.list,
            &target.extents,
            &target.census,
            &hansei_bundle::names::ImplFold::default(),
            addr,
            &mut out,
        )
        .expect("the report renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// An address inside a task's allocation — its header, or any
    /// offset short of the trailer's end — names that task; one
    /// outside every allocation reports the miss.
    #[test]
    fn test_addresses_resolve_to_the_containing_task() {
        with_tasks("sleep-join", |t| {
            let sleeper = t
                .list
                .tasks
                .iter()
                .find(|t| t.task_id == Some(3))
                .expect("the sleeper is task 3");
            let header = sleeper.addr.0;

            let shown = report(t, header);
            assert!(
                shown.contains("Task 3: async fn sleep_join::sleeper\n"),
                "{shown}"
            );
            assert!(
                shown.contains(&format!(
                    "    At: offset 0x0 in the task's allocation (header {header:#x})"
                )),
                "{shown}"
            );
            assert!(shown.contains("    State: idle"), "{shown}");

            let inside = report(t, header + 0x10);
            assert!(inside.contains("Task 3: "), "{inside}");
            assert!(
                inside.contains("    At: offset 0x10 in the task's allocation"),
                "{inside}"
            );

            let miss = report(t, 0x10);
            assert_eq!(
                miss,
                "no task's allocation and no future the census found contains 0x10\n"
            );
        });
    }

    /// An address is reported against the futures the census found as
    /// well as against the tasks, and a pointer *into* a future
    /// resolves to it the way one into a task's allocation does. This
    /// future is `.boxed()`, so it is a heap allocation of its own and
    /// no task's allocation claims it — the block naming what holds it
    /// is the only thing that says whose it is.
    #[test]
    fn test_addresses_resolve_to_the_containing_future() {
        with_tasks("futurelock", |t| {
            let future1 = t
                .census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", t.census.held));
            let owner = t.list.tasks[future1.owner]
                .task_id
                .expect("the holder is an owned task");
            let size = t
                .view
                .ty(future1.ty)
                .expect("the bundle carries the held future's type")
                .size();
            assert!(
                size > 0x10,
                "the fixture's future is too small to point into"
            );

            for offset in [0, 0x10] {
                let shown = report(t, future1.addr + offset);
                assert!(
                    shown.contains(&format!(
                        "Future {:#x}: {}",
                        future1.addr,
                        hansei_bundle::names::display_future_name(
                            &future1.future,
                            &hansei_bundle::names::ImplFold::default()
                        )
                    )),
                    "{shown}"
                );
                assert!(
                    shown.contains(&format!("    At: offset {offset:#x} in the future")),
                    "{shown}"
                );
                assert!(
                    shown.contains(&format!("    Held by: task {owner} — ")),
                    "{shown}"
                );
                assert!(shown.contains("(frame 1, `future1`)"), "{shown}");
            }

            // Past its end it is somebody else's memory, and this
            // heap allocation is nobody's as far as hansei can say.
            let past = report(t, future1.addr + size);
            assert!(
                past.starts_with("no task's allocation and no future"),
                "{past}"
            );
        });
    }

    /// The executors answer for their own addresses: the handle a
    /// `runtimes` row prints resolves to that runtime, an address
    /// inside the handle resolves to it the way one inside a task's
    /// allocation does, and a local set's shared state answers for
    /// itself. The fixture holds a runtime no thread is inside, which
    /// is the one whose block has a route to report and no threads.
    #[test]
    fn test_addresses_resolve_to_the_owning_executor() {
        with_tasks("foreign-runtime", |t| {
            let hidden = t
                .runtimes
                .iter()
                .position(|rt| rt.worker_tids.is_empty())
                .expect("the fixture hides a runtime from every thread's context");
            let handle = t.runtimes[hidden].handle.addr;

            let shown = report(t, handle);
            assert!(
                shown.contains(&format!("Runtime {hidden} @{handle:#x}: current_thread")),
                "{shown}"
            );
            assert!(
                shown.contains("    At: offset 0x0 in the runtime's handle"),
                "{shown}"
            );
            assert!(shown.contains("    Threads: none inside it"), "{shown}");
            assert!(
                shown.contains("    Found via: a JoinHandle held by an enumerated task"),
                "{shown}"
            );

            let inside = report(t, handle + 0x8);
            assert!(
                inside.contains(&format!("Runtime {hidden} @{handle:#x}: ")),
                "{inside}"
            );
            assert!(
                inside.contains("    At: offset 0x8 in the runtime's handle"),
                "{inside}"
            );

            let set = t.local_sets.first().expect("the fixture holds a local set");
            let shared = set.shared.addr;
            let shown = report(t, shared);
            assert!(
                shown.contains(&format!("Local set 0 @{shared:#x}:")),
                "{shown}"
            );
            assert!(shown.contains("    Tasks: 1"), "{shown}");
        });
    }

    /// Every task claims its own header and nothing claims the word
    /// before it: the extents tile the tasks without bleeding.
    #[test]
    fn test_extents_cover_each_task_exactly() {
        with_tasks("dyn-future", |t| {
            for (index, task) in t.list.tasks.iter().enumerate() {
                assert_eq!(
                    t.extents.locate(task.addr.0),
                    Some((index, 0)),
                    "task {:?} does not claim its own header",
                    task.addr
                );
                let before = t.extents.locate(task.addr.0 - 1);
                assert_ne!(
                    before.map(|(i, _)| i),
                    Some(index),
                    "task {:?} claims the byte before its header",
                    task.addr
                );
            }
        });
    }

    /// A set's own address names the set, counting the children in
    /// flight and the completed ones not yet reaped — the reaped count
    /// being the empty slots, not the sum of everything.
    #[test]
    fn test_a_sets_children_count_the_reaped() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let extents = ctx.task_extents(&list);
        let mut census = census::census(&ctx, &list);
        let child = |future: Option<&str>| census::SetChild {
            node: 0x2000,
            depth: usize::from(future.is_some()),
            future: future.map(str::to_string),
            root: None,
            state: None,
            waiting_on: None,
            wait: None,
            leaf: None,
        };
        census.sets.push(census::FutureSet {
            owner: 0,
            frame: 0,
            local: "set".to_string(),
            via: None,
            addr: 0xdead_0000,
            ty: "FuturesUnordered<F>".to_string(),
            children: vec![child(Some("f::{async_fn_env#0}")), child(None), child(None)],
        });
        let target = Target {
            view: ctx.view,
            runtimes,
            local_sets,
            list,
            extents,
            census,
        };
        let shown = report(&target, 0xdead_0000);
        assert!(
            shown.contains("Children: 1 in flight, 2 completed and not yet reaped\n"),
            "{shown}"
        );
    }

    /// A find reached through another find says so: the suffix names
    /// the route, and a find in the task's own frames adds nothing.
    #[test]
    fn test_the_via_suffix_names_the_route() {
        let (bundle, snapshot) = testkit::load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census::census(&ctx, &list);
        assert!(!census.held.is_empty(), "the fixture holds a future");

        assert_eq!(super::via_suffix(&census, None), "");
        let via = super::via_suffix(&census, Some(census::Via::Held(0)));
        assert!(via.starts_with(", via "), "{via:?}");
        assert!(via.len() > ", via ".len(), "{via:?}");
    }

    /// Blocks are separated by one blank line between each other: none
    /// before the first, exactly one before each that follows.
    #[test]
    fn test_blocks_separate_only_between_each_other() {
        let mut out = Vec::new();
        let mut blocks = 0;
        separate(&mut blocks, &mut out).expect("separate writes");
        assert_eq!(out, b"", "a leading blank line before the first block");
        separate(&mut blocks, &mut out).expect("separate writes");
        assert_eq!(out, b"\n", "one blank line between two blocks");
        assert_eq!(blocks, 2);
    }

    /// The `0x` prefix is required, and the digits behind it parse as
    /// hex — the contract the command's help text states.
    #[test]
    fn test_addresses_parse_only_with_a_0x_prefix() {
        assert_eq!(parse_hex_addr("0x7fffb1c26100"), Ok(0x7fffb1c26100));
        assert_eq!(parse_hex_addr("0XFF"), Ok(0xff));
        assert!(parse_hex_addr("7fffb1c26100").is_err());
        assert!(parse_hex_addr("42").is_err());
        assert!(parse_hex_addr("0x").is_err());
        assert!(parse_hex_addr("0xzz").is_err());
    }
}

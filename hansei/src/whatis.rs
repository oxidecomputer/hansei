//! The `whatis` command: what an address is, outermost first.

use crate::Session;
use crate::tasks::{future_name, task_id, task_label};

use anyhow::Result;
use hansei_bundle::BundleView;
use hansei_runtime::tokio::{bundle, census};

use std::io;

pub(crate) fn exec_whatis(session: &Session<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    report_whatis(
        &session.ctx.view,
        &session.tasks,
        session.extents(),
        session.census(),
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
fn report_whatis(
    view: &BundleView<'_>,
    list: &bundle::TaskList,
    extents: &bundle::TaskExtents,
    census: &census::FutureCensus,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut blocks = 0;

    if let Some((index, offset)) = extents.locate(addr) {
        let task = &list.tasks[index];
        let id = task_id(list, index);
        separate(&mut blocks, out)?;
        writeln!(out, "Task {id}: {}", future_name(&task.future))?;
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
        let future = child
            .future
            .as_deref()
            .unwrap_or("<completed, not yet reaped>");
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
            set.ty,
            set.addr,
            set.frame,
            set.local,
            via_suffix(census, set.via)
        )?;
        writeln!(
            out,
            "    Polled by: {} — {}",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future)
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
        writeln!(out, "Future {:#x}: {}", h.addr, h.future)?;
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
            future_name(&list.tasks[h.owner].future),
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
        writeln!(out, "Set {addr:#x}: {}", set.ty)?;
        writeln!(out, "    Children: {live} in flight{reaped}")?;
        writeln!(
            out,
            "    Driven by: {} — {} (frame {}, `{}`{})",
            task_label(list, set.owner),
            future_name(&list.tasks[set.owner].future),
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
    use super::report_whatis;
    use crate::parse_hex_addr;
    use hansei_bundle::BundleView;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::{TaskExtents, TaskList};
    use hansei_runtime::tokio::census::{self, FutureCensus};

    fn with_tasks(
        program: &str,
        check: impl FnOnce(&BundleView<'_>, &TaskList, &TaskExtents, &FutureCensus),
    ) {
        let (bundle, snapshot) = testkit::load(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let extents = ctx.task_extents(&list);
        let census = census::census(&ctx, &list);
        check(&ctx.view, &list, &extents, &census);
    }

    fn report(
        view: &BundleView<'_>,
        list: &TaskList,
        extents: &TaskExtents,
        census: &FutureCensus,
        addr: u64,
    ) -> String {
        let mut out = Vec::new();
        report_whatis(view, list, extents, census, addr, &mut out).expect("the report renders");
        String::from_utf8(out).expect("rendered output is UTF-8")
    }

    /// An address inside a task's allocation — its header, or any
    /// offset short of the trailer's end — names that task; one
    /// outside every allocation reports the miss.
    #[test]
    fn test_addresses_resolve_to_the_containing_task() {
        with_tasks("sleep-join", |view, list, extents, census| {
            let sleeper = list
                .tasks
                .iter()
                .find(|t| t.task_id == Some(3))
                .expect("the sleeper is task 3");
            let header = sleeper.addr.0;

            let shown = report(view, list, extents, census, header);
            assert!(
                shown.contains("Task 3: sleep_join::sleeper::{async_fn_env#0}\n"),
                "{shown}"
            );
            assert!(
                shown.contains(&format!(
                    "    At: offset 0x0 in the task's allocation (header {header:#x})"
                )),
                "{shown}"
            );
            assert!(shown.contains("    State: idle"), "{shown}");

            let inside = report(view, list, extents, census, header + 0x10);
            assert!(inside.contains("Task 3: "), "{inside}");
            assert!(
                inside.contains("    At: offset 0x10 in the task's allocation"),
                "{inside}"
            );

            let miss = report(view, list, extents, census, 0x10);
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
        with_tasks("futurelock", |view, list, extents, census| {
            let future1 = census
                .held
                .iter()
                .find(|h| h.local == "future1")
                .unwrap_or_else(|| panic!("no held `future1` in {:#?}", census.held));
            let owner = list.tasks[future1.owner]
                .task_id
                .expect("the holder is an owned task");
            let size = view
                .ty(future1.ty)
                .expect("the bundle carries the held future's type")
                .size();
            assert!(
                size > 0x10,
                "the fixture's future is too small to point into"
            );

            for offset in [0, 0x10] {
                let shown = report(view, list, extents, census, future1.addr + offset);
                assert!(
                    shown.contains(&format!("Future {:#x}: {}", future1.addr, future1.future)),
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
            let past = report(view, list, extents, census, future1.addr + size);
            assert!(
                past.starts_with("no task's allocation and no future"),
                "{past}"
            );
        });
    }

    /// Every task claims its own header and nothing claims the word
    /// before it: the extents tile the tasks without bleeding.
    #[test]
    fn test_extents_cover_each_task_exactly() {
        with_tasks("dyn-future", |_view, list, extents, _census| {
            for (index, task) in list.tasks.iter().enumerate() {
                assert_eq!(
                    extents.locate(task.addr.0),
                    Some((index, 0)),
                    "task {:?} does not claim its own header",
                    task.addr
                );
                let before = extents.locate(task.addr.0 - 1);
                assert_ne!(
                    before.map(|(i, _)| i),
                    Some(index),
                    "task {:?} claims the byte before its header",
                    task.addr
                );
            }
        });
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

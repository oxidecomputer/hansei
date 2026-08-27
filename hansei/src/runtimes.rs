//! The `runtimes` command: the state of each executor the target holds,
//! and — with `--list` — which executors those are.

use crate::summary::counted;
use crate::threads::render;
use crate::{RenderOpts, RuntimeScope, Session, output};

use anyhow::{Result, anyhow};
use hansei_runtime::tokio::{bundle, census};

use std::io;

/// One entry of the target's group space: a discovered runtime, or a
/// discovered `LocalSet`, with what the merged task population
/// attributes to it.
///
/// The two are listed together because that is how the population is
/// tagged — a task belongs to exactly one of them, and the question
/// "whose task is this" is answered by an index into the pair of lists
/// in this order.
pub(crate) struct Group {
    /// What kind of executor it is, and its index among the ones of
    /// that kind: together the identifier the task listing tags a block
    /// with, and the one `runtimes` selects by. They are kept apart so
    /// a column of indices lines up under itself however the kinds
    /// beside them are spelled.
    kind: &'static str,
    index: usize,
    /// The scheduler flavor, empty for a local set — which is not a
    /// scheduler and has none.
    flavor: String,
    /// A runtime's handle, or a local set's `Shared`: the address the
    /// group is identified by, and the one that can be given in place
    /// of the index.
    addr: u64,
    tasks: usize,
    futures: usize,
    /// The threads inside it, or — for a group nothing is inside — the
    /// route discovery reached it by. Never empty: which of the two a
    /// row says is the difference between a group being run and being
    /// merely found.
    where_: String,
}

/// How a runtime is named wherever one is meant: the index the
/// `runtimes --list` listing lists it under, and the handle address
/// printed beside it there.
///
/// Both halves identify it on their own — `runtimes` takes either, `@`
/// included, and `--runtime` the index — so a name printed anywhere in
/// a session pastes straight back in, and an index that shifts under
/// `--runtime` is still pinned by the address next to it.
pub(crate) fn runtime_label(index: usize, rt: &bundle::RuntimeRef<'_>) -> String {
    format!("runtime {index} @{:#x}", rt.handle.addr)
}

/// The same for a local set, which is named by the `Shared` its tasks
/// hang off — the address every discovery route converges on.
pub(crate) fn local_set_label(index: usize, set: &bundle::LocalSetRef<'_>) -> String {
    format!("local set {index} @{:#x}", set.shared.addr)
}

/// Every group in the target, in the order tasks are stamped with.
///
/// It takes the discovery results rather than a session so the offline
/// fixture tests can drive it, the way [`crate::tasks::print_tasks`]
/// does.
pub(crate) fn groups(
    runtimes: &[bundle::RuntimeRef<'_>],
    local_sets: &[bundle::LocalSetRef<'_>],
    list: &bundle::TaskList,
    census: &census::FutureCensus,
) -> Vec<Group> {
    let futures = futures_by_group(list, census, runtimes.len() + local_sets.len());
    let tasks = |group: usize| list.tasks.iter().filter(|t| t.group == group).count();

    let mut groups = Vec::new();
    for (i, rt) in runtimes.iter().enumerate() {
        // A runtime no thread's context reaches has no lwp to name, and
        // how it was found is the interesting part instead.
        let where_ = if rt.worker_tids.is_empty() {
            format!("no thread inside it, found via {}", rt.route)
        } else {
            let tids: Vec<String> = rt.worker_tids.iter().map(|t| t.to_string()).collect();
            format!("on lwp {}", tids.join(", "))
        };
        groups.push(Group {
            kind: "runtime",
            index: i,
            flavor: rt.flavor.to_string(),
            addr: rt.handle.addr,
            tasks: tasks(i),
            futures: futures[i],
            where_,
        });
    }
    for (i, set) in local_sets.iter().enumerate() {
        // A set is pinned to one thread by construction, so its lwp and
        // its route are both worth saying: the thread it belongs to, and
        // the reason hansei can see it at all.
        let where_ = match set.owner_tid {
            Some(tid) => format!("on lwp {tid}, found via {}", set.route),
            None => format!("no thread holds it, found via {}", set.route),
        };
        // The listing already holds one row per runtime, so the next
        // row's position *is* the set's group index.
        let group = groups.len();
        groups.push(Group {
            kind: "local set",
            index: i,
            flavor: String::new(),
            addr: set.shared.addr,
            tasks: tasks(group),
            futures: futures[group],
            where_,
        });
    }
    groups
}

/// How many futures in flight each group holds.
///
/// The three populations counted are the census's own — the tasks, what
/// their frames hold beside their await chains, and what their
/// `FuturesUnordered` hold — attributed to a group through the task
/// that owns each find. Counting them the way [`crate::summary`] counts
/// them is deliberate: these rows sum to the number a census prints,
/// rather than to a second differently-drawn one.
fn futures_by_group(
    list: &bundle::TaskList,
    census: &census::FutureCensus,
    groups: usize,
) -> Vec<usize> {
    let mut counts = vec![0; groups];
    for task in &list.tasks {
        if let Some(count) = counts.get_mut(task.group) {
            *count += 1;
        }
    }
    // A find is its owner's, and its owner's group is the task's: the
    // census records held futures and sets by the task whose frames they
    // were found in, however many hops away.
    let mut held_by = |owner: usize, n: usize| {
        if let Some(count) = list.tasks.get(owner).and_then(|t| counts.get_mut(t.group)) {
            *count += n;
        }
    };
    for held in &census.held {
        held_by(held.owner, 1);
    }
    for set in &census.sets {
        let live = set.children.iter().filter(|c| c.future.is_some()).count();
        held_by(set.owner, live);
    }
    counts
}

/// Print the listing: one row per group, the columns padded so the
/// counts and the lwps line up down the page.
///
/// `excluded` is how many runtimes `--runtime` left out of the session,
/// so a filtered listing cannot be read as the whole target.
pub(crate) fn print_groups(
    groups: &[Group],
    excluded: usize,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut table =
        output::Table::new(6).header(["KIND", "ID", "FLAVOR", "HANDLE", "HOLDS", "WHERE"]);
    for g in groups {
        table.row([
            g.kind.to_string(),
            g.index.to_string(),
            g.flavor.clone(),
            format!("@{:#x}", g.addr),
            format!(
                "{}, {}",
                counted(g.tasks, "task"),
                counted(g.futures, "future")
            ),
            g.where_.clone(),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    if excluded > 0 {
        writeln!(
            out,
            "{} excluded by --runtime; attach without it to see them",
            counted(excluded, "runtime")
        )?;
    }
    Ok(())
}

/// `runtimes --list`: every executor the target holds, a row apiece.
pub(crate) fn exec_list(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let groups = groups(
        &session.runtimes,
        &session.local_sets,
        &session.tasks,
        session.census(),
    );
    print_groups(&groups, session.excluded.len(), out)
}

/// Which of the runtime handle's members `runtimes` was asked for.
#[derive(Copy, Clone)]
pub(crate) struct Fields {
    drivers: bool,
    shared: bool,
}

impl Fields {
    /// The sections the flags name. Naming none asks for the whole
    /// runtime, as [`crate::summary::Sections::select`] reads a census's
    /// flags.
    pub(crate) fn select(drivers: bool, shared: bool) -> Self {
        let all = !(drivers || shared);
        Self {
            drivers: drivers || all,
            shared: shared || all,
        }
    }

    /// The handle members to print, each with the heading it goes
    /// under, in the order a full listing prints them.
    fn members(self) -> Vec<(&'static str, &'static str)> {
        let mut members = Vec::new();
        if self.drivers {
            members.push(("drivers", "driver"));
        }
        if self.shared {
            members.push(("shared", "shared"));
        }
        members
    }
}

/// Render each named runtime's own state out of the target: the
/// scheduler state its workers share, and the drivers they park on.
///
/// Both are read straight through the bundle's layouts rather than into
/// a hand-written mirror of tokio's structs, so a field tokio adds shows
/// up without hansei being taught about it.
pub(crate) fn exec_runtimes(
    session: &Session<'_>,
    scopes: &[RuntimeScope],
    fields: Fields,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let selected = select(session, scopes)?;
    let members = fields.members();
    // The bundle's `Elided` formats hide the runtime graph from *user*
    // values; this command exists to show the runtime's own insides, so
    // they must never apply here — a new elided row must not be able to
    // blank part of this output.
    let no_elide = reify::ElideOverride {
        no_elide: true,
        types: Vec::new(),
        impls: Default::default(),
    };

    // A heading is only earned by an ambiguity it resolves: one runtime
    // and one section is the value alone, as it was before either could
    // be more than one.
    let head_runtimes = selected.len() > 1;
    let head_members = members.len() > 1;
    let mut printed = false;
    for (index, rt) in selected {
        if head_runtimes {
            if printed {
                writeln!(out)?;
            }
            writeln!(out, "{} ({}):", runtime_label(index, rt), rt.flavor)?;
            printed = true;
        }
        for (i, (heading, member)) in members.iter().enumerate() {
            if blank_before(printed, head_runtimes, i) {
                writeln!(out)?;
            }
            if head_members {
                writeln!(out, "{heading}:")?;
            }
            let value = rt.handle.member(member)?;
            let heap = session.heap_view();
            let heap = heap.as_ref().map(|view| view as &dyn reify::Heap);
            writeln!(
                out,
                "{:#}",
                render(session, &value, opts, heap).elide_override(&no_elide)
            )?;
            printed = true;
        }
    }
    Ok(())
}

/// Whether a blank line goes before this member section: between
/// everything the command prints, except ahead of the first section
/// under a runtime's own heading, which already introduces it.
fn blank_before(printed: bool, head_runtimes: bool, i: usize) -> bool {
    printed && !(head_runtimes && i == 0)
}

/// The runtimes the scopes name, with the index each is listed under —
/// every discovered runtime when the command named none.
///
/// A scope that names nothing is an error before anything is printed,
/// the way [`crate::threads::exec_threads`] resolves its lwps: a number
/// that came from somewhere else says so rather than quietly showing
/// the rest. What survives is in listing order however the scopes were
/// written, and a runtime named twice is still shown once.
fn select<'s, 'b>(
    session: &'s Session<'b>,
    scopes: &[RuntimeScope],
) -> Result<Vec<(usize, &'s bundle::RuntimeRef<'b>)>> {
    let handles: Vec<u64> = session.runtimes.iter().map(|rt| rt.handle.addr).collect();
    match selected(&handles, scopes) {
        Ok(indices) => Ok(indices
            .into_iter()
            .map(|index| (index, &session.runtimes[index]))
            .collect()),
        Err(scope) => Err(no_such_runtime(session, scope)),
    }
}

/// The positions the scopes pick out of the runtimes, named here by
/// their handle addresses alone — or the first scope that names none of
/// them.
fn selected(handles: &[u64], scopes: &[RuntimeScope]) -> Result<Vec<usize>, RuntimeScope> {
    for &scope in scopes {
        if !(0..handles.len()).any(|index| names(scope, index, handles[index])) {
            return Err(scope);
        }
    }
    Ok((0..handles.len())
        .filter(|&index| {
            scopes.is_empty()
                || scopes
                    .iter()
                    .any(|&scope| names(scope, index, handles[index]))
        })
        .collect())
}

/// Whether a scope names the runtime at this position. Either
/// identifier stands on its own, so the two arms are one question asked
/// of two spellings.
fn names(scope: RuntimeScope, index: usize, handle: u64) -> bool {
    match scope {
        RuntimeScope::Index(named) => index == named,
        RuntimeScope::Handle(addr) => handle == addr,
    }
}

/// The error for a scope that names nothing: what was asked for, and
/// the runtimes there are — the same answer `runtimes --list` gives,
/// since a reader who guessed wrong wants the list and not a refusal.
fn no_such_runtime(session: &Session<'_>, scope: RuntimeScope) -> anyhow::Error {
    let named = match scope {
        RuntimeScope::Index(index) => index.to_string(),
        RuntimeScope::Handle(addr) => format!("{addr:#x}"),
    };
    let listed: Vec<String> = session
        .runtimes
        .iter()
        .enumerate()
        .map(|(index, rt)| format!("{} ({})", runtime_label(index, rt), rt.flavor))
        .collect();
    anyhow!(
        "no runtime {named} in this target; it has {}: {}",
        counted(session.runtimes.len(), "runtime"),
        listed.join(", ")
    )
}

/// Offline listing tests: the groups a real extracted bundle joined
/// against a real captured snapshot resolves to.
#[cfg(test)]
mod runtimes_tests {
    use super::{Fields, blank_before, groups, print_groups, selected};
    use crate::RuntimeScope;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::census;

    /// Naming no runtime asks for all of them; naming some asks for
    /// those, by index or by handle address, in listing order however
    /// they were written and once each however often they were named.
    #[test]
    fn test_scopes_select_by_either_identifier() {
        let handles = [0x10, 0x20, 0x30];
        let select = |scopes: &[RuntimeScope]| selected(&handles, scopes);
        assert_eq!(select(&[]), Ok(vec![0, 1, 2]));
        assert_eq!(select(&[RuntimeScope::Index(1)]), Ok(vec![1]));
        assert_eq!(select(&[RuntimeScope::Handle(0x30)]), Ok(vec![2]));
        assert_eq!(
            select(&[RuntimeScope::Handle(0x30), RuntimeScope::Index(0)]),
            Ok(vec![0, 2])
        );
        assert_eq!(
            select(&[RuntimeScope::Index(1), RuntimeScope::Handle(0x20)]),
            Ok(vec![1])
        );

        // A scope that names nothing fails the whole selection, rather
        // than showing the runtimes the others named as if the number
        // that fit none had not been asked for.
        assert_eq!(
            select(&[RuntimeScope::Index(0), RuntimeScope::Index(3)]),
            Err(RuntimeScope::Index(3))
        );
        assert_eq!(
            select(&[RuntimeScope::Handle(0x40)]),
            Err(RuntimeScope::Handle(0x40))
        );
        // An index is never read as an address, nor an address as an
        // index: neither identifier answers for the other's spelling.
        assert_eq!(
            select(&[RuntimeScope::Handle(1)]),
            Err(RuntimeScope::Handle(1))
        );
        assert_eq!(
            select(&[RuntimeScope::Index(0x10)]),
            Err(RuntimeScope::Index(0x10))
        );
    }

    /// The futures column counts what the census found through each
    /// group's tasks: the tasks themselves, plus the held futures and
    /// live set children attributed to their owners.
    #[test]
    fn test_futures_count_the_censuss_finds() {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let census = census::census(&ctx, &list);
        assert!(
            !census.held.is_empty() && !census.sets.is_empty(),
            "the fixture must hold futures for this to say anything"
        );

        let live: usize = census
            .sets
            .iter()
            .map(|s| s.children.iter().filter(|c| c.future.is_some()).count())
            .sum();
        let rows = groups(&runtimes, &local_sets, &list, &census);
        let total: usize = rows.iter().map(|g| g.futures).sum();
        assert_eq!(total, list.tasks.len() + census.held.len() + live);
    }

    /// Naming no section asks for the whole runtime; naming one asks
    /// for it alone, and naming both is spelling the whole out.
    #[test]
    fn test_naming_no_section_asks_for_all_of_them() {
        let all = Fields::select(false, false);
        assert!(all.drivers && all.shared);
        let drivers = Fields::select(true, false);
        assert!(drivers.drivers && !drivers.shared);
        let shared = Fields::select(false, true);
        assert!(!shared.drivers && shared.shared);
        let both = Fields::select(true, true);
        assert!(both.drivers && both.shared);
    }

    /// Blank lines fall between the pieces the command prints, and
    /// nowhere else: never ahead of the very first piece, and never
    /// between a runtime's heading and its first member section.
    #[test]
    fn test_blank_lines_fall_between_pieces() {
        assert!(!blank_before(false, false, 0));
        assert!(!blank_before(false, true, 0));
        assert!(blank_before(true, false, 0));
        assert!(!blank_before(true, true, 0));
        assert!(blank_before(true, true, 1));
        assert!(blank_before(true, false, 1));
    }

    /// The listing over the fixture that holds every kind of row: a
    /// runtime threads are inside, a runtime none are — found only
    /// because a `JoinHandle` pointed at one of its tasks — and a
    /// `LocalSet` inside that hidden runtime, found by harvesting its
    /// wheel.
    #[test]
    fn test_every_group_is_listed_with_its_route() {
        let (bundle, snapshot) = testkit::load_any("foreign-runtime");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let census = census::census(&ctx, &list);

        let rows = groups(&runtimes, &local_sets, &list, &census);
        assert_eq!(rows.len(), 3, "two runtimes and a local set");

        let mut out = Vec::new();
        print_groups(&rows, 0, &mut out).expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(lines.len(), 4, "{shown}");

        // The header names the columns, padded with the rows it names —
        // which is what lets the acceptance suite slice them by label.
        assert!(lines[0].starts_with("KIND       ID  FLAVOR"), "{shown}");
        for label in ["HANDLE", "HOLDS", "WHERE"] {
            assert!(lines[0].contains(label), "{shown}");
        }
        assert!(
            lines[1].starts_with("runtime    0   current_thread  @0x"),
            "{shown}"
        );
        assert!(lines[1].contains(" on lwp "), "{shown}");
        // The counts are the census's own: each group sums its tasks
        // and the futures their frames hold.
        assert!(lines[1].contains("  1 task, 1 future "), "{shown}");
        assert!(lines[2].contains("  2 tasks, 2 futures  "), "{shown}");
        assert!(lines[3].contains("  1 task, 1 future "), "{shown}");
        assert!(
            lines[2].starts_with("runtime    1   current_thread  @0x"),
            "{shown}"
        );
        assert!(
            lines[2].ends_with(
                "  no thread inside it, found via a JoinHandle held by an enumerated task"
            ),
            "{shown}"
        );
        // The set has no flavor to print, and its index still lands in
        // the column the runtimes' indices are in.
        assert!(lines[3].starts_with("local set  0   "), "{shown}");
        assert!(lines[3].contains("  @0x"), "{shown}");
        assert!(
            lines[3].ends_with("found via a task waker on a timer parked in a runtime's wheel"),
            "{shown}"
        );

        // Every task is attributed to exactly one group, and every
        // group's futures are at least its tasks — a task is a future in
        // flight itself, so a row counting fewer would mean the census's
        // populations had been double-counted or lost.
        assert_eq!(
            rows.iter().map(|g| g.tasks).sum::<usize>(),
            list.tasks.len(),
            "{shown}"
        );
        for row in &rows {
            assert!(
                row.futures >= row.tasks,
                "{} {}: {shown}",
                row.kind,
                row.index
            );
        }
    }

    /// A filtered session says so, rather than reading as a target with
    /// fewer runtimes than it has.
    #[test]
    fn test_an_excluded_runtime_is_reported() {
        let (bundle, snapshot) = testkit::load_any("foreign-runtime");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        let local_sets = e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let census = census::census(&ctx, &list);
        let rows = groups(&runtimes, &local_sets, &list, &census);

        let mut out = Vec::new();
        print_groups(&rows, 1, &mut out).expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");
        assert!(
            shown.ends_with("1 runtime excluded by --runtime; attach without it to see them\n"),
            "{shown}"
        );
    }
}

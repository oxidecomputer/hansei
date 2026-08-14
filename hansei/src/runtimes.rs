//! The `runtimes` and `runtime` commands: which executors the target
//! holds, and the state of each.

use crate::summary::counted;
use crate::threads::render;
use crate::{RenderOpts, RuntimeScope, Session};

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
    /// with, and the one the `runtime` command selects by. They are
    /// kept apart so a column of indices lines up under itself however
    /// the kinds beside them are spelled.
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
/// `runtimes` listing lists it under, and the handle address printed
/// beside it there.
///
/// Both halves identify it on their own — `--runtime` and the `runtime`
/// command take either — so a name printed anywhere in a session pastes
/// straight back in, and an index that shifts under `--runtime` is
/// still pinned by the address next to it.
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
        let group = runtimes.len() + i;
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
    let rows: Vec<[String; 6]> = groups
        .iter()
        .map(|g| {
            [
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
            ]
        })
        .collect();
    // The last column is what varies most in length and nothing follows
    // it, so only the five before it are padded.
    let mut widths = [0; 5];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(&row[..5]) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for row in &rows {
        let padded: Vec<String> = row[..5]
            .iter()
            .zip(&widths)
            .map(|(cell, &width)| format!("{cell:<width$}"))
            .collect();
        writeln!(out, "{}  {}", padded.join("  "), row[5])?;
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

/// List every executor the target holds.
pub(crate) fn exec_runtimes(session: &Session<'_>, out: &mut dyn io::Write) -> Result<()> {
    let groups = groups(
        &session.runtimes,
        &session.local_sets,
        &session.tasks,
        session.census(),
    );
    print_groups(&groups, session.excluded.len(), out)
}

/// Which of the runtime handle's members `runtime` was asked for.
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

/// Render a runtime's own state out of the target: the scheduler state
/// its workers share, and the drivers they park on.
///
/// Both are read straight through the bundle's layouts rather than into
/// a hand-written mirror of tokio's structs, so a field tokio adds shows
/// up without hansei being taught about it.
pub(crate) fn exec_runtime(
    session: &Session<'_>,
    scope: Option<RuntimeScope>,
    fields: Fields,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let selected = select(session, scope)?;
    let members = fields.members();
    // The bundle's `Elided` formats hide the runtime graph from *user*
    // values; this command exists to show the runtime's own insides, so
    // they must never apply here — a new elided row must not be able to
    // blank part of this output.
    let no_elide = reify::ElideOverride {
        no_elide: true,
        types: Vec::new(),
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
            if printed && !(head_runtimes && i == 0) {
                writeln!(out)?;
            }
            if head_members {
                writeln!(out, "{heading}:")?;
            }
            let value = rt.handle.member(member)?;
            writeln!(
                out,
                "{:#}",
                render(session, &value, opts).elide_override(&no_elide)
            )?;
            printed = true;
        }
    }
    Ok(())
}

/// The runtimes a scope names, with the index each is listed under:
/// one, or every discovered runtime when the command named none.
fn select<'s, 'b>(
    session: &'s Session<'b>,
    scope: Option<RuntimeScope>,
) -> Result<Vec<(usize, &'s bundle::RuntimeRef<'b>)>> {
    let Some(scope) = scope else {
        return Ok(session.runtimes.iter().enumerate().collect());
    };
    let found = session
        .runtimes
        .iter()
        .enumerate()
        .find(|(index, rt)| match scope {
            RuntimeScope::Index(named) => *index == named,
            RuntimeScope::Handle(addr) => rt.handle.addr == addr,
        });
    match found {
        Some(hit) => Ok(vec![hit]),
        None => Err(no_such_runtime(session, scope)),
    }
}

/// The error for a scope that names nothing: what was asked for, and
/// the runtimes there are — the same answer `runtimes` gives, since a
/// reader who guessed wrong wants the list and not a refusal.
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
    use super::{groups, print_groups};
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::census;

    /// The listing over the fixture that holds every kind of row: a
    /// runtime threads are inside, a runtime none are — found only
    /// because a `JoinHandle` pointed at one of its tasks — and a
    /// `LocalSet` inside that hidden runtime, found by harvesting its
    /// wheel.
    #[test]
    fn test_every_group_is_listed_with_its_route() {
        let (bundle, snapshot) = testkit::load("foreign-runtime");
        let ctx = testkit::context(&bundle, &snapshot);
        let (runtimes, local_sets, list) = testkit::discover(&ctx, &snapshot);
        let census = census::census(&ctx, &list);

        let rows = groups(&runtimes, &local_sets, &list, &census);
        assert_eq!(rows.len(), 3, "two runtimes and a local set");

        let mut out = Vec::new();
        print_groups(&rows, 0, &mut out).expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(lines.len(), 3, "{shown}");

        assert!(
            lines[0].starts_with("runtime    0  current_thread  @0x"),
            "{shown}"
        );
        assert!(lines[0].contains(" on lwp "), "{shown}");
        assert!(
            lines[1].starts_with("runtime    1  current_thread  @0x"),
            "{shown}"
        );
        assert!(
            lines[1].ends_with(
                "  no thread inside it, found via a JoinHandle held by an enumerated task"
            ),
            "{shown}"
        );
        // The set has no flavor to print, and its index still lands in
        // the column the runtimes' indices are in.
        assert!(lines[2].starts_with("local set  0  "), "{shown}");
        assert!(lines[2].contains("  @0x"), "{shown}");
        assert!(
            lines[2].ends_with("found via a task waker on a timer parked in a runtime's wheel"),
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
        let (bundle, snapshot) = testkit::load("foreign-runtime");
        let ctx = testkit::context(&bundle, &snapshot);
        let (runtimes, local_sets, list) = testkit::discover(&ctx, &snapshot);
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `runtimes` listing — every runtime the target holds, a row
//! apiece — and the `runtime` block: one runtime in full.

use crate::summary::counted;
use crate::tasks::{Cmp, EMPTY_BUCKET, alternatives, distinct_values, listing_footer};
use crate::threads::print_rendered;
use crate::{RenderOpts, RuntimeScope, Session, output};

use anyhow::{Context as _, Result, anyhow};
use hansei_runtime::tokio::{bundle, census};

use std::collections::BTreeMap;
use std::io;

/// One row of the listing: a discovered runtime, with what the merged
/// task population attributes to it.
///
/// The population is tagged by group — a task belongs to exactly one
/// runtime or `LocalSet`, the runtimes numbered first — and this
/// listing is the runtimes' half of that space: a local set is not a
/// scheduler, has no flavor, workers or drivers, and is named only
/// where a task's owner tag or `whatis` names it.
pub(crate) struct Group {
    /// Its index among the runtimes: the identifier the task listing
    /// tags a block with, and the one `runtime` selects by.
    index: usize,
    flavor: String,
    /// The handle's address: what the runtime is identified by, and
    /// what can be given in place of the index.
    addr: u64,
    tasks: usize,
    futures: usize,
    /// The scheduler's worker count: a multi_thread runtime's worker
    /// slots — `None` where its parker array could not be read — and
    /// one for a current_thread runtime, which runs everything on the
    /// thread that entered it.
    workers: Option<usize>,
    /// The lwps whose context reaches it — zero for a runtime nothing
    /// is currently inside.
    threads: usize,
    /// How discovery reached it. For a runtime with threads inside it
    /// that is a thread's context; for one with none, the pointer
    /// something already discovered held — which is what makes a
    /// row with no threads worth reading beside this one.
    route: String,
}

impl Group {
    /// How the row names itself — `runtime 0` — the sample a bucket
    /// carries.
    fn label(&self) -> String {
        format!("runtime {}", self.index)
    }
}

/// How a runtime is named wherever one is meant: the index the
/// `runtimes` listing lists it under, and the handle address printed
/// beside it there.
///
/// Both halves identify it on their own — `runtime` takes either, the
/// address with or without a leading `@`, and `--runtime` the index —
/// so a name printed anywhere in a session pastes straight back in,
/// and an index that shifts under `--runtime` is still pinned by the
/// address next to it.
pub(crate) fn runtime_label(index: usize, rt: &bundle::RuntimeRef<'_>) -> String {
    format!("runtime {index} @ {:#x}", rt.handle.addr)
}

/// The same for a local set, which is named by the `Shared` its tasks
/// hang off — the address every discovery route converges on.
pub(crate) fn local_set_label(index: usize, set: &bundle::LocalSetRef<'_>) -> String {
    format!("local set {index} @ {:#x}", set.shared.addr)
}

/// Every runtime in the target, in the order tasks are stamped with.
///
/// It takes the discovery results rather than a session so the offline
/// fixture tests can drive it, the way [`crate::tasks::print_tasks`]
/// does; the context is for the one reading a row needs, the worker
/// count.
pub(crate) fn groups<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    runtimes: &[bundle::RuntimeRef<'_>],
    list: &bundle::TaskList,
    census: &census::FutureCensus,
) -> Vec<Group> {
    let futures = futures_by_group(list, census, runtimes.len());
    let tasks = |group: usize| list.tasks.iter().filter(|t| t.group == group).count();
    runtimes
        .iter()
        .enumerate()
        .map(|(i, rt)| Group {
            index: i,
            flavor: rt.flavor.to_string(),
            addr: rt.handle.addr,
            tasks: tasks(i),
            futures: futures[i],
            workers: worker_count(ctx, rt),
            threads: rt.worker_tids.len(),
            route: rt.route.to_string(),
        })
        .collect()
}

/// The scheduler's worker count, as tokio's own `num_workers` counts
/// it: the multi_thread runtime's remotes — one per worker slot,
/// whether or not a thread currently holds it — and one for a
/// current_thread runtime. `None` where the remotes could not be read.
fn worker_count<T: proc::Target>(
    ctx: &bundle::Context<'_, T>,
    rt: &bundle::RuntimeRef<'_>,
) -> Option<usize> {
    match rt.flavor {
        bundle::RuntimeFlavor::MultiThread => {
            ctx.park_states(rt.handle).ok().map(|p| p.workers.len())
        }
        bundle::RuntimeFlavor::CurrentThread => Some(1),
    }
}

/// How many futures in flight each of the first `groups` groups holds
/// — the runtimes, numbered ahead of the local sets, whose finds fall
/// off the end and are not counted.
///
/// The three populations counted are the census's own — the tasks, what
/// their frames hold beside their await chains, and what their
/// `FuturesUnordered` hold — attributed to a group through the task
/// that owns each find. Counting them the way [`crate::summary`] counts
/// them is deliberate: these rows sum to the number a census prints
/// for the runtimes, rather than to a second differently-drawn one.
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

/// The rows over a session: every runtime the target holds.
fn rows<T: proc::Target>(session: &Session<'_, T>) -> Vec<Group> {
    groups(
        &session.ctx,
        &session.runtimes,
        &session.tasks,
        session.census(),
    )
}

/// Print the listing: one row per runtime, the counts right-aligned as
/// numbers, and the count under it.
///
/// `excluded` is how many runtimes `--runtime` left out of the session,
/// so a filtered listing cannot be read as the whole target.
pub(crate) fn print_groups(
    groups: &[&Group],
    excluded: usize,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let dash = || "—".to_string();
    // The route is a sentence, the one cell that runs wide: what a
    // terminal cuts to keep a row on one line.
    let mut table = output::Table::new(8)
        .header([
            "ID",
            "FLAVOR",
            "HANDLE",
            "TASKS",
            "FUTURES",
            "WORKERS",
            "THREADS",
            "FOUND VIA",
        ])
        .align_right(3)
        .align_right(4)
        .align_right(5)
        .align_right(6)
        .truncatable(7)
        .fit(fit);
    for g in groups {
        table.row([
            g.index.to_string(),
            g.flavor.clone(),
            format!("{:#x}", g.addr),
            g.tasks.to_string(),
            g.futures.to_string(),
            g.workers.map_or_else(dash, |n| n.to_string()),
            g.threads.to_string(),
            g.route.clone(),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "[{}]", counted(groups.len(), "runtime"))?;
    if excluded > 0 {
        writeln!(
            out,
            "{} excluded by --runtime; attach without it to see them",
            counted(excluded, "runtime")
        )?;
    }
    Ok(())
}

/// Everything the `runtimes` command was asked. The filter grammar
/// rides in as the raw flag values and is parsed here, so the errors
/// name the flag they came from.
pub(crate) struct RuntimesCmd {
    /// The runtime names the old grammar took, kept so the refusal can
    /// name the way forward.
    pub(crate) scope: Vec<String>,
    pub(crate) with: Vec<String>,
    pub(crate) without: Vec<String>,
    pub(crate) group: Option<String>,
}

/// One filterable field of the runtime population — what `--with`,
/// `--without` and `--group` name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    /// The index in the listing — exact.
    Id,
    /// The scheduler flavor.
    Flavor,
    /// The handle address — exact.
    Handle,
    /// The tasks the population attributes to it.
    Tasks,
    /// The futures in flight the census attributes to it.
    Futures,
    /// The scheduler's worker count.
    Workers,
    /// The lwps inside it.
    Threads,
    /// The route discovery reached it by.
    FoundVia,
}

impl Field {
    const NAMES: [(&'static str, Field); 8] = [
        ("id", Field::Id),
        ("flavor", Field::Flavor),
        ("handle", Field::Handle),
        ("tasks", Field::Tasks),
        ("futures", Field::Futures),
        ("workers", Field::Workers),
        ("threads", Field::Threads),
        ("found-via", Field::FoundVia),
    ];

    /// Every field name, in the order the errors list them — what the
    /// prompt offers after `--group`, `--with` and `--without`.
    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        Self::NAMES.iter().map(|(n, _)| *n)
    }

    /// The field a flag named, or an error listing what it could have.
    fn parse(name: &str) -> Result<Field> {
        Self::NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, f)| *f)
            .ok_or_else(|| {
                anyhow!(
                    "no field {name:?}; the fields are {}",
                    Self::NAMES.map(|(n, _)| n).join(", ")
                )
            })
    }

    fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, f)| *f == self)
            .map(|(n, _)| *n)
            .expect("every field is named")
    }

    /// Whether the field's argument is a pattern rather than an exact
    /// or compared value.
    fn is_pattern(self) -> bool {
        matches!(self, Field::Flavor | Field::FoundVia)
    }

    /// The count a compared field reads off a row — `None` for a
    /// worker count that could not be read, which no comparison
    /// matches.
    fn count(self, g: &Group) -> Option<usize> {
        match self {
            Field::Tasks => Some(g.tasks),
            Field::Futures => Some(g.futures),
            Field::Workers => g.workers,
            Field::Threads => Some(g.threads),
            _ => unreachable!("{self:?} is not a count field"),
        }
    }

    /// The distinct values the rows hold for the field, or `None` for
    /// a count the argument compares against.
    fn values(self, rows: &[Group]) -> Option<Vec<String>> {
        let column = |f: fn(&Group) -> Option<String>| distinct_values(rows.iter().map(f));
        Some(match self {
            Field::Id => column(|g| Some(g.index.to_string())),
            Field::Flavor => column(|g| Some(g.flavor.clone())),
            Field::Handle => column(|g| Some(format!("{:#x}", g.addr))),
            Field::FoundVia => column(|g| Some(g.route.clone())),
            Field::Tasks | Field::Futures | Field::Workers | Field::Threads => return None,
        })
    }
}

/// The values the target holds for `field`, for the prompt to offer
/// after `--with FIELD` (see `tasks::field_values`).
pub(crate) fn field_values<T: proc::Target>(
    session: &Session<'_, T>,
    field: &str,
) -> Option<(Vec<String>, bool)> {
    let field = Field::parse(field).ok()?;
    Some((field.values(&rows(session))?, field.is_pattern()))
}

/// How one clause matches its field's value.
#[derive(Debug)]
enum Matcher {
    /// A case-insensitive regex over the spelled value.
    Pattern(crate::pattern::Pattern),
    /// Exact index: `id`.
    Id(usize),
    /// Exact address: `handle`.
    Handle(u64),
    /// `'>N'` / `'<N'` / `'=N'`: the count fields.
    Cmp(Cmp),
}

/// One `--with`/`--without` clause.
#[derive(Debug)]
struct Clause {
    field: Field,
    /// The argument's alternatives (`0,1`): the clause matches a row
    /// when any one of them does.
    matchers: Vec<Matcher>,
    /// `--without`: the clause keeps the rows it does *not* match.
    negate: bool,
}

/// Parse the flag pairs into clauses. clap delivered FIELD/ARG pairs
/// (`num_args = 2`), so the chunks are exact.
fn parse_clauses(with: &[String], without: &[String]) -> Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    for (specs, negate) in [(with, false), (without, true)] {
        let flag = if negate { "--without" } else { "--with" };
        for [name, spec] in specs.as_chunks::<2>().0 {
            let field = Field::parse(name).with_context(|| flag.to_string())?;
            let matchers = alternatives(spec)
                .and_then(|alts| alts.iter().map(|alt| matcher(field, alt)).collect())
                .with_context(|| format!("{flag} {}", field.name()))?;
            clauses.push(Clause {
                field,
                matchers,
                negate,
            });
        }
    }
    Ok(clauses)
}

/// The matcher one field's argument compiles to.
fn matcher(field: Field, arg: &str) -> Result<Matcher> {
    Ok(match field {
        Field::Id => Matcher::Id(
            arg.parse()
                .map_err(|_| anyhow!("an id is the index a runtimes row carries, got {arg:?}"))?,
        ),
        Field::Handle => Matcher::Handle(parse_handle(arg)?),
        Field::Tasks | Field::Futures | Field::Workers | Field::Threads => {
            Matcher::Cmp(Cmp::parse(arg)?)
        }
        Field::Flavor | Field::FoundVia => Matcher::Pattern(crate::pattern::Pattern::new(arg)?),
    })
}

/// A handle as the listing prints it — `0x` hex, with or without the
/// `@` a label dresses it in — and nothing else: a bare number would
/// be an index, and an index is never read as an address.
fn parse_handle(arg: &str) -> Result<u64> {
    let addr = arg.strip_prefix('@').unwrap_or(arg);
    let digits = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .ok_or_else(|| anyhow!("a handle is the 0x address a runtimes row prints, got {arg:?}"))?;
    u64::from_str_radix(digits, 16).map_err(|e| anyhow!("invalid handle address {arg:?}: {e}"))
}

/// Whether one row survives one clause: any alternative matching is
/// a hit, and `--without` keeps the misses.
fn survives(clause: &Clause, g: &Group) -> bool {
    let hit = clause.matchers.iter().any(|matcher| match matcher {
        Matcher::Pattern(p) => field_text(clause.field, g).is_some_and(|t| p.is_match(t)),
        Matcher::Id(index) => g.index == *index,
        Matcher::Handle(addr) => g.addr == *addr,
        Matcher::Cmp(cmp) => clause.field.count(g).is_some_and(|n| cmp.matches(n)),
    });
    hit != clause.negate
}

/// The spelled value a regex field matches — `None`, nothing to
/// match, where the row has nothing to say.
fn field_text(field: Field, g: &Group) -> Option<&str> {
    match field {
        Field::Flavor => Some(&g.flavor),
        Field::FoundVia => Some(&g.route),
        _ => unreachable!("{field:?} is not a regex field"),
    }
}

/// What a bucket is named for one row: the field's spelled value, or
/// `None` for [`EMPTY_BUCKET`].
fn group_value(field: Field, g: &Group) -> Option<String> {
    match field {
        Field::Id => Some(g.index.to_string()),
        Field::Flavor => Some(g.flavor.clone()),
        Field::Handle => Some(format!("{:#x}", g.addr)),
        Field::FoundVia => Some(g.route.clone()),
        Field::Tasks | Field::Futures | Field::Workers | Field::Threads => {
            field.count(g).map(|n| n.to_string())
        }
    }
}

/// Up to three member labels and `…` — the sample a bucket row
/// carries.
fn member_sample(rows: &[Group], members: &[usize]) -> String {
    let labels: Vec<String> = members.iter().take(3).map(|&i| rows[i].label()).collect();
    match members.len() > labels.len() {
        true => format!("{}, …", labels.join(", ")),
        false => labels.join(", "),
    }
}

/// Every runtime the target holds, one table row each. The filter
/// clauses narrow the listing; one runtime's insides — its threads by
/// lwp, its drivers, the scheduler state its workers share — are
/// [`print_runtime`]'s, under `runtime`.
pub(crate) fn exec_runtimes<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: RuntimesCmd,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    if let Some(first) = cmd.scope.first() {
        anyhow::bail!("runtimes takes no runtime names; `runtime {first}` prints that one runtime");
    }
    let group = cmd
        .group
        .as_deref()
        .map(Field::parse)
        .transpose()
        .context("--group")?;
    let clauses = parse_clauses(&cmd.with, &cmd.without)?;

    let rows = rows(session);
    let survivors: Vec<usize> = (0..rows.len())
        .filter(|&i| clauses.iter().all(|c| survives(c, &rows[i])))
        .collect();

    if let Some(field) = group {
        return exec_group(&rows, field, &survivors, session.fit_width(theme), out);
    }
    let shown: Vec<&Group> = survivors.iter().map(|&i| &rows[i]).collect();
    print_groups(
        &shown,
        session.excluded.len(),
        session.fit_width(theme),
        out,
    )
}

/// `--group FIELD`: bucket the surviving rows by the field's spelled
/// value and print `COUNT VALUE` rows, most numerous first (ties in
/// value order), each with up to three member labels.
fn exec_group(
    rows: &[Group],
    field: Field,
    survivors: &[usize],
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut grouped: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &index in survivors {
        let value = group_value(field, &rows[index]).unwrap_or_else(|| EMPTY_BUCKET.to_string());
        grouped.entry(value).or_default().push(index);
    }
    let mut buckets: Vec<(String, Vec<usize>)> = grouped.into_iter().collect();
    // Count descending; the map already ordered ties by value, and the
    // sort is stable.
    buckets.sort_by_key(|(_, members)| std::cmp::Reverse(members.len()));

    let heading = field.name().replace('-', " ").to_uppercase();
    let mut table = output::Table::new(3)
        .align_right(0)
        .header(["COUNT".to_string(), heading, "RUNTIMES".to_string()])
        .truncatable(1)
        .fit(fit);
    for (value, members) in &buckets {
        table.row([
            members.len().to_string(),
            value.clone(),
            member_sample(rows, members),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(
        out,
        "{}",
        listing_footer(buckets.len(), buckets.len(), "group")
    )?;
    Ok(())
}

/// `runtime`: print the named runtime in full — or the one runtime,
/// on a target holding one, when none is named.
pub(crate) fn exec_runtime<T: proc::Target>(
    session: &Session<'_, T>,
    scope: Option<RuntimeScope>,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let index = match scope {
        Some(scope) => select(session, scope)?,
        None => match session.runtimes.len() {
            1 => 0,
            0 => anyhow::bail!("the target holds no runtime"),
            n => anyhow::bail!(
                "{} runtimes; name one by its index or handle (`runtimes` lists them)",
                n
            ),
        },
    };
    print_runtime(session, index, opts, out)
}

/// One runtime as `runtime` prints it: its heading — the index and
/// handle address the way the listing names it — then, four columns
/// in, its flavor, the tasks and futures it holds, its worker count,
/// the lwps inside it, the route discovery reached it by, and the two
/// halves of its handle: the drivers its workers park on, and the
/// scheduler state they share.
///
/// Both halves are read straight through the bundle's layouts rather
/// than into a hand-written mirror of tokio's structs, so a field
/// tokio adds shows up without hansei being taught about it.
fn print_runtime<T: proc::Target>(
    session: &Session<'_, T>,
    index: usize,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let rt = &session.runtimes[index];
    let rows = rows(session);
    let g = &rows[index];
    writeln!(out, "{}", runtime_label(index, rt))?;
    writeln!(out, "    flavor: {}", rt.flavor)?;
    writeln!(out, "    tasks: {}", g.tasks)?;
    writeln!(out, "    futures: {}", g.futures)?;
    let workers = match g.workers {
        Some(n) => n.to_string(),
        None => "unreadable".to_string(),
    };
    writeln!(out, "    workers: {workers}")?;
    writeln!(out, "    threads: {}", threads_line(&rt.worker_tids))?;
    writeln!(out, "    found via: {}", rt.route)?;
    // The handle's `driver` member holds every driver, so it prints
    // under the plural.
    for (label, member) in [("drivers", "driver"), ("shared", "shared")] {
        let value = rt.handle.member(member)?;
        print_rendered(session, label, &value, opts, out)?;
    }
    Ok(())
}

/// The `threads:` line: how many lwps are inside the runtime, and
/// which — this block is the one place they are listed, since the
/// listing counts them and `threads` has no runtime column — or that
/// none is, which is the state a found-but-not-run runtime is in.
fn threads_line(tids: &[u32]) -> String {
    if tids.is_empty() {
        return "none inside it".to_string();
    }
    let tids: Vec<String> = tids.iter().map(|t| t.to_string()).collect();
    format!("{} (lwp {})", tids.len(), tids.join(", "))
}

/// The runtime a scope names, as its index in the session's list.
///
/// A scope that names nothing is an error, the way `thread` resolves
/// its lwp: a number that came from somewhere else says so rather than
/// quietly showing something else.
fn select<T: proc::Target>(session: &Session<'_, T>, scope: RuntimeScope) -> Result<usize> {
    let handles: Vec<u64> = session.runtimes.iter().map(|rt| rt.handle.addr).collect();
    position(&handles, scope).ok_or_else(|| no_such_runtime(session, scope))
}

/// The position the scope picks out of the runtimes, named here by
/// their handle addresses alone. Either identifier stands on its own,
/// so the two arms are one question asked of two spellings.
fn position(handles: &[u64], scope: RuntimeScope) -> Option<usize> {
    match scope {
        RuntimeScope::Index(index) => (index < handles.len()).then_some(index),
        RuntimeScope::Handle(addr) => handles.iter().position(|&h| h == addr),
    }
}

/// The error for a scope that names nothing: what was asked for and
/// how many runtimes there are. `runtimes` is the listing.
fn no_such_runtime<T: proc::Target>(
    session: &Session<'_, T>,
    scope: RuntimeScope,
) -> anyhow::Error {
    let named = match scope {
        RuntimeScope::Index(index) => index.to_string(),
        RuntimeScope::Handle(addr) => format!("{addr:#x}"),
    };
    anyhow!(
        "no runtime {named} ({})",
        counted(session.runtimes.len(), "runtime")
    )
}

/// Offline listing tests: the groups a real extracted bundle joined
/// against a real captured snapshot resolves to.
#[cfg(test)]
mod runtimes_tests {
    use super::{
        Field, Group, groups, parse_clauses, position, print_groups, survives, threads_line,
    };
    use crate::RuntimeScope;
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::census;

    /// A scope names a runtime by index or by handle address, and the
    /// two spellings cannot be confused for one another: an index is
    /// never read as an address, nor an address as an index.
    #[test]
    fn test_a_scope_names_by_either_identifier() {
        let handles = [0x10, 0x20, 0x30];
        assert_eq!(position(&handles, RuntimeScope::Index(1)), Some(1));
        assert_eq!(position(&handles, RuntimeScope::Handle(0x30)), Some(2));
        assert_eq!(position(&handles, RuntimeScope::Index(3)), None);
        assert_eq!(position(&handles, RuntimeScope::Handle(0x40)), None);
        assert_eq!(position(&handles, RuntimeScope::Handle(1)), None);
        assert_eq!(position(&handles, RuntimeScope::Index(0x10)), None);
    }

    /// The rows over a fixture, for the tests that filter them.
    fn rows_of(program: &str) -> Vec<Group> {
        let (bundle, snapshot) = testkit::load_any(program);
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        e.discover(&ctx, &[]);
        let (runtimes, list) = (e.runtimes, e.list);
        let census = census::census(&ctx, &list);
        groups(&ctx, &runtimes, &list, &census)
    }

    /// The futures column counts what the census found through each
    /// group's tasks: the tasks themselves, plus the held futures and
    /// live set children attributed to their owners.
    #[test]
    fn test_futures_count_the_censuss_finds() {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        e.discover(&ctx, &[]);
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
        let rows = groups(&ctx, &runtimes, &list, &census);
        let total: usize = rows.iter().map(|g| g.futures).sum();
        assert_eq!(total, list.tasks.len() + census.held.len() + live);
    }

    /// The listing over the fixture that holds both kinds of runtime
    /// row: one threads are inside, and one none are — found only
    /// because a `JoinHandle` pointed at one of its tasks. The fixture
    /// also holds a `LocalSet`, which is not a runtime and gets no
    /// row: its task is counted nowhere here.
    #[test]
    fn test_every_runtime_is_listed_with_its_route() {
        let rows = rows_of("foreign-runtime");
        assert_eq!(rows.len(), 2, "two runtimes; the local set is not one");

        let mut out = Vec::new();
        let shown: Vec<&Group> = rows.iter().collect();
        print_groups(&shown, 0, None, &mut out).expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(lines.len(), 4, "{shown}");

        // The header names the columns, padded with the rows it names —
        // which is what lets the acceptance suite slice them by label.
        assert!(lines[0].starts_with("ID  FLAVOR"), "{shown}");
        for label in [
            "HANDLE",
            "TASKS",
            "FUTURES",
            "WORKERS",
            "THREADS",
            "FOUND VIA",
        ] {
            assert!(lines[0].contains(label), "{shown}");
        }
        // The counts are the census's own: each runtime sums its tasks
        // and the futures their frames hold. A current_thread runtime
        // has one worker, and the one thread inside it is the one
        // that entered it.
        assert!(lines[1].starts_with("0   current_thread  0x"), "{shown}");
        assert!(
            lines[1].contains("      1        1        1        1  "),
            "{shown}"
        );
        assert!(
            lines[1].ends_with("  a thread's runtime context"),
            "{shown}"
        );
        assert!(lines[2].starts_with("1   current_thread  0x"), "{shown}");
        assert!(
            lines[2].contains("      2        2        1        0  "),
            "{shown}"
        );
        assert!(
            lines[2].ends_with("  a JoinHandle held by an enumerated task"),
            "{shown}"
        );
        assert_eq!(lines[3], "[2 runtimes]", "{shown}");

        // The runtimes' tasks are the population less the set's one,
        // and every runtime's futures are at least its tasks — a task
        // is a future in flight itself, so a row counting fewer would
        // mean the census's populations had been double-counted or
        // lost.
        assert_eq!(rows.iter().map(|g| g.tasks).sum::<usize>(), 3, "{shown}");
        for row in &rows {
            assert!(row.futures >= row.tasks, "{}: {shown}", row.label());
        }
    }

    /// The clauses read the rows' fields: a pattern over the spelled
    /// flavor and route, an exact id or handle, and a comparison over
    /// each count.
    #[test]
    fn test_clauses_select_by_every_field() {
        let rows = rows_of("foreign-runtime");
        let survivors = |with: &[&str], without: &[&str]| -> Vec<String> {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            let without: Vec<String> = without.iter().map(|s| s.to_string()).collect();
            let clauses = parse_clauses(&with, &without).expect("the clauses parse");
            rows.iter()
                .filter(|g| clauses.iter().all(|c| survives(c, g)))
                .map(Group::label)
                .collect()
        };
        assert_eq!(
            survivors(&["flavor", "current"], &[]),
            ["runtime 0", "runtime 1"]
        );
        assert!(survivors(&["flavor", "multi"], &[]).is_empty());
        assert_eq!(survivors(&["id", "1"], &[]), ["runtime 1"]);
        assert_eq!(survivors(&[], &["id", "1"]), ["runtime 0"]);
        assert_eq!(survivors(&["threads", "=0"], &[]), ["runtime 1"]);
        assert_eq!(survivors(&["threads", ">0"], &[]), ["runtime 0"]);
        assert_eq!(survivors(&["tasks", ">1"], &[]), ["runtime 1"]);
        assert_eq!(
            survivors(&["workers", "=1"], &[]),
            ["runtime 0", "runtime 1"]
        );
        assert_eq!(survivors(&["found-via", "joinhandle"], &[]), ["runtime 1"]);
        let handle = format!("{:#x}", rows[1].addr);
        assert_eq!(survivors(&["handle", &handle], &[]), ["runtime 1"]);
        assert_eq!(
            survivors(&["handle", &format!("@{handle}")], &[]),
            ["runtime 1"]
        );
        // Alternatives, and clauses ANDed.
        assert_eq!(survivors(&["id", "0,1"], &[]), ["runtime 0", "runtime 1"]);
        assert_eq!(
            survivors(&["flavor", "current"], &["threads", "=0"]),
            ["runtime 0"]
        );
    }

    /// An argument that does not fit its field is refused by name: an
    /// index is never read as an address, a count wants its operator,
    /// and a field that does not exist lists the ones that do.
    #[test]
    fn test_malformed_clauses_are_refused() {
        let refuse = |with: &[&str]| {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            format!("{:#}", parse_clauses(&with, &[]).expect_err("refused"))
        };
        assert!(refuse(&["handle", "1"]).contains("0x address"));
        assert!(refuse(&["id", "0x10"]).contains("index"));
        assert!(refuse(&["tasks", "3"]).contains("'>N'"));
        assert!(refuse(&["lwp", "3"]).contains("the fields are id, flavor"));
        assert!(refuse(&["tasks", "3"]).starts_with("--with tasks"));
    }

    /// A count field offers no values to complete — the argument is a
    /// comparison — and the others offer what the rows hold.
    #[test]
    fn test_fields_offer_their_values() {
        let rows = rows_of("foreign-runtime");
        assert_eq!(Field::Flavor.values(&rows).unwrap(), ["current_thread"]);
        assert_eq!(Field::Id.values(&rows).unwrap(), ["0", "1"]);
        assert!(Field::Tasks.values(&rows).is_none());
        assert!(Field::Workers.values(&rows).is_none());
    }

    /// The block's threads line counts the lwps and names them, or
    /// says none is inside.
    #[test]
    fn test_the_threads_line_names_the_lwps() {
        assert_eq!(threads_line(&[]), "none inside it");
        assert_eq!(threads_line(&[7]), "1 (lwp 7)");
        assert_eq!(threads_line(&[3, 7, 12]), "3 (lwp 3, 7, 12)");
    }

    /// A filtered session says so, rather than reading as a target with
    /// fewer runtimes than it has.
    #[test]
    fn test_an_excluded_runtime_is_reported() {
        let rows = rows_of("foreign-runtime");
        let shown: Vec<&Group> = rows.iter().collect();
        let mut out = Vec::new();
        print_groups(&shown, 1, None, &mut out).expect("the listing renders");
        let shown = String::from_utf8(out).expect("rendered output is UTF-8");
        assert!(
            shown.ends_with("1 runtime excluded by --runtime; attach without it to see them\n"),
            "{shown}"
        );
    }
}

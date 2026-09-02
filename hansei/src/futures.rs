//! The `futures` command: every future the census found in flight
//! beside the tasks' own await chains, listed as one population rather
//! than under the tasks that hold them.

use crate::tasks::{
    self, CensusTree, Cmp, EMPTY_BUCKET, Entry, Listing, census_tree, listing_footer,
    print_future_entry, resolve_rt, task_id,
};
use crate::trace::FutureAt;
use crate::whatis::via_suffix;
use crate::{Session, print_warnings, repl, summary};

use anyhow::{Context as _, Result};
use hansei_bundle::names;
use hansei_runtime::tokio::{bundle, census};

use std::collections::{BTreeMap, HashMap};
use std::io;

/// Which of the census's two populations a row came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A future sitting in a frame's local, off the await chain.
    Held,
    /// A `FuturesUnordered` child, in its own heap node.
    Child,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Held => "held",
            Kind::Child => "child",
        }
    }
}

/// One row of the `futures` table: the compact per-future answer,
/// built once from the census and shared by the table, the filters,
/// and the blocks.
#[derive(Clone, Debug)]
pub(crate) struct FutureRow {
    /// The census entry the row stands for — what `trace`, `whatis`
    /// and the exec scope resolve the address back to.
    pub(crate) at: FutureAt,
    /// The address the listings print for it: a held future's own, a
    /// set child's node — what `trace <0xaddr>` accepts.
    pub(crate) addr: u64,
    /// The task whose frames it was found in, as an index into the
    /// task list, and as `tasks` names it.
    pub(crate) owner: usize,
    pub(crate) task: String,
    /// The owner's group index (`runtimes --list`).
    pub(crate) rt: usize,
    pub(crate) kind: Kind,
    /// The `HELD IN` cell: `frame N, \`local\`` for a held future,
    /// `set 0x…` for a child, either with `, via …` appended when the
    /// census reached the frame through another find.
    pub(crate) held_in: String,
    /// The holding frame and local — a held future's only.
    pub(crate) frame: Option<usize>,
    pub(crate) local: Option<String>,
    pub(crate) via: Option<census::Via>,
    /// Its own suspend state, `Suspend1 — file:line` style.
    pub(crate) state: Option<String>,
    /// What its chain bottoms out in, where recognized.
    pub(crate) waiting_on: Option<String>,
    /// The kind-level bucket `--group waiting-on` files the row under:
    /// the primitive's kind, else the leaf type.
    pub(crate) waiting_kind: Option<String>,
    /// The concrete future type, folded and never truncated.
    pub(crate) future: String,
    /// How many frames its own chain ran to.
    pub(crate) depth: usize,
    /// What the census found inside it: the counts its block carries.
    pub(crate) holds: usize,
    pub(crate) sets: usize,
    pub(crate) sets_summary: String,
}

/// The table's rows, built on first use and cached on the session.
/// The census is the cost, and every later command that wants it pays
/// nothing more.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [FutureRow] {
    session
        .future_rows
        .get_or_init(|| build_rows(&session.tasks, session.census(), &session.impl_fold))
}

/// Build every row from what it prints — taken apart from the session
/// so a test can lay out a population no fixture holds. Rows come in
/// the order `tasks --futures` prints the same finds: task by task,
/// each task's held futures ahead of its set children, and whatever
/// the census found inside a find directly after it — so a listing
/// read top to bottom meets a future before the ones it holds. A
/// completed child the set has not reaped is no future in flight and
/// gets no row.
pub(crate) fn build_rows(
    list: &bundle::TaskList,
    census: &census::FutureCensus,
    impls: &names::ImplFold,
) -> Vec<FutureRow> {
    let tree = census_tree(&census.held, &census.sets, &census.join_sets);
    let rows = Rows {
        list,
        census,
        tree: &tree,
        impls,
    };
    let mut out = Vec::new();
    for roots in tree.roots.values() {
        for entry in roots {
            rows.push(*entry, &mut out);
        }
    }
    out
}

/// What building a row reads: the census the finds are in, the tree
/// that says what is inside each, and the task listing the owner is
/// named from.
struct Rows<'a> {
    list: &'a bundle::TaskList,
    census: &'a census::FutureCensus,
    tree: &'a CensusTree<'a>,
    impls: &'a names::ImplFold,
}

impl Rows<'_> {
    /// Push one find's rows — a held future's own, or one per live
    /// child of a set — each followed by the rows of what the census
    /// found inside it. A join set holds tasks, which have rows of
    /// their own in `tasks`, so it contributes none here.
    fn push(&self, entry: Entry<'_>, out: &mut Vec<FutureRow>) {
        let inside = |via: census::Via, out: &mut Vec<FutureRow>| {
            for entry in self.tree.nested.get(&via).into_iter().flatten() {
                self.push(*entry, out);
            }
        };
        match entry {
            Entry::Held(i, h) => {
                out.push(self.held(i, h));
                inside(census::Via::Held(i), out);
            }
            Entry::Set(set, s) => {
                for (child, c) in s.children.iter().enumerate() {
                    let Some(future) = &c.future else {
                        continue;
                    };
                    out.push(self.child(set, child, s, c, future));
                    inside(census::Via::SetChild { set, child }, out);
                }
            }
            Entry::JoinSet(_) => {}
        }
    }

    fn held(&self, i: usize, h: &census::HeldFuture) -> FutureRow {
        let inside = self.tree.counts_under(census::Via::Held(i));
        FutureRow {
            at: FutureAt::Held(i),
            addr: h.addr,
            owner: h.owner,
            task: task_id(self.list, h.owner),
            rt: self.list.tasks[h.owner].group,
            kind: Kind::Held,
            held_in: format!(
                "frame {}, `{}`{}",
                h.frame,
                h.local,
                via_suffix(self.census, h.via)
            ),
            frame: Some(h.frame),
            local: Some(h.local.clone()),
            via: h.via,
            state: h.state.clone(),
            waiting_on: h.waiting_on.clone(),
            waiting_kind: waiting_kind(h.wait, h.leaf.as_deref(), self.list, self.impls),
            future: names::display_future_name(&h.future, self.impls),
            depth: h.depth,
            holds: inside.held,
            sets: inside.sets + inside.join_sets,
            sets_summary: inside.sets_summary(),
        }
    }

    fn child(
        &self,
        set: usize,
        child: usize,
        s: &census::FutureSet,
        c: &census::SetChild,
        future: &str,
    ) -> FutureRow {
        let inside = self.tree.counts_under(census::Via::SetChild { set, child });
        FutureRow {
            at: FutureAt::Child { set, child },
            addr: c.node,
            owner: s.owner,
            task: task_id(self.list, s.owner),
            rt: self.list.tasks[s.owner].group,
            kind: Kind::Child,
            held_in: format!("set {:#x}{}", s.addr, via_suffix(self.census, s.via)),
            frame: None,
            local: None,
            via: s.via,
            state: c.state.clone(),
            waiting_on: c.waiting_on.clone(),
            waiting_kind: waiting_kind(c.wait, c.leaf.as_deref(), self.list, self.impls),
            future: names::display_future_name(future, self.impls),
            depth: c.depth,
            holds: inside.held,
            sets: inside.sets + inside.join_sets,
            sets_summary: inside.sets_summary(),
        }
    }
}

/// The bucket `--group waiting-on` files a row under: the primitive's
/// kind where one decoded — with the identity that groups usefully,
/// which task, which kind of lock — else the leaf type its chain
/// bottoms out in, which is kind-level already.
fn waiting_kind(
    wait: Option<bundle::WaitKind>,
    leaf: Option<&str>,
    list: &bundle::TaskList,
    impls: &names::ImplFold,
) -> Option<String> {
    match (wait, leaf) {
        (Some(bundle::WaitKind::Timer { .. }), _) => Some("timer".to_string()),
        (Some(bundle::WaitKind::Task { addr }), _) => {
            Some(match list.tasks.iter().position(|t| t.addr.0 == addr) {
                Some(index) => tasks::task_label(list, index),
                None => format!("the task at {addr:#x}"),
            })
        }
        (Some(bundle::WaitKind::Io), _) => Some("io".to_string()),
        (Some(bundle::WaitKind::Semaphore { owner }), _) => Some(match owner {
            Some(owner) => format!("a {owner} (semaphore)"),
            None => "a semaphore".to_string(),
        }),
        (None, Some(leaf)) => Some(names::display_future_name(leaf, impls)),
        (None, None) => None,
    }
}

/// One row's table cells, in column order — the table's rows, and the
/// heading `--exec` opens each future's output with.
fn row_cells(row: &FutureRow, groups: bool) -> Vec<String> {
    let dash = || "—".to_string();
    let mut cells = vec![format!("{:#x}", row.addr), row.task.clone()];
    if groups {
        cells.push(row.rt.to_string());
    }
    cells.push(row.held_in.clone());
    cells.push(row.state.clone().unwrap_or_else(dash));
    cells.push(row.waiting_on.clone().unwrap_or_else(dash));
    cells.push(row.future.clone());
    cells
}

/// One future's table row as a single line, cells joined — the
/// spelling `--exec` heads each future's output with.
pub(crate) fn row_line<T: proc::Target>(session: &Session<'_, T>, index: usize) -> String {
    let groups = !session.group_tags().is_empty();
    row_cells(&rows(session)[index], groups).join("  ")
}

/// Print the table: one row per future, the `RT` column only when the
/// target holds more than one group.
fn print_future_table(
    rows: &[&FutureRow],
    groups: bool,
    limit: Option<usize>,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let shown = limit.unwrap_or(rows.len()).min(rows.len());
    let mut header = vec!["ADDR", "TASK"];
    if groups {
        header.push("RT");
    }
    header.extend(["HELD IN", "STATE", "WAITING ON", "FUTURE"]);
    let columns = header.len();
    // The wait and the future are type names: what a terminal cuts
    // to keep a row on one line.
    let mut table = crate::output::Table::new(columns)
        .header(header)
        .truncatable(columns - 2)
        .truncatable(columns - 1)
        .fit(fit);
    for row in &rows[..shown] {
        table.row(row_cells(row, groups));
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(rows.len(), shown, "future"))?;
    Ok(())
}

/// What printing a block needs beyond its row: the census tree the
/// finds inside it are read from, and the task listing a nested join
/// set names its members from.
struct Blocks<'a> {
    list: &'a bundle::TaskList,
    census: &'a census::FutureCensus,
    tree: CensusTree<'a>,
    impls: &'a names::ImplFold,
    group_tags: Vec<String>,
    polling: HashMap<u64, u32>,
    blocking_lwps: &'a HashMap<u64, u32>,
}

impl Blocks<'_> {
    /// The via key everything found inside this row's future is filed
    /// under.
    fn via_of(row: &FutureRow) -> census::Via {
        match row.at {
            FutureAt::Held(i) => census::Via::Held(i),
            FutureAt::Child { set, child } => census::Via::SetChild { set, child },
        }
    }

    /// One future's full block — what `futures -v` prints for it:
    /// where it sits, its own state and depth, what it waits on, and
    /// the census's finds inside it, listed under the count each
    /// belongs to. Every block carries every row, so a missing value
    /// reads as a gap in what the census could say rather than as a
    /// shorter block.
    fn print(&self, row: &FutureRow, out: &mut dyn io::Write) -> Result<()> {
        writeln!(out, "Future {:#x}: {}", row.addr, row.future)?;
        match row.at {
            FutureAt::Held(_) => writeln!(
                out,
                "    Held by: {} ({}){}",
                tasks::task_label(self.list, row.owner),
                row.held_in
                    .split(", via ")
                    .next()
                    .expect("split yields at least one piece"),
                via_suffix(self.census, row.via)
            )?,
            FutureAt::Child { set, .. } => {
                let s = &self.census.sets[set];
                writeln!(
                    out,
                    "    Child of: {} at {:#x}, polled by {}{}",
                    names::fold_type_name(&s.ty, self.impls),
                    s.addr,
                    tasks::task_label(self.list, row.owner),
                    via_suffix(self.census, row.via)
                )?
            }
        }
        if let Some(tag) = self.group_tags.get(row.rt) {
            writeln!(out, "    Owner: {tag}")?;
        }
        writeln!(out, "    State: {}", row.state.as_deref().unwrap_or("-"))?;
        writeln!(out, "    Depth: {}", summary::counted(row.depth, "frame"))?;
        writeln!(
            out,
            "    Waiting on: {}",
            row.waiting_on.as_deref().unwrap_or("—")
        )?;
        // What the census found inside this future, the way a task's
        // block lists what it found in the task's own frames: the
        // futures held in its frames, then the sets driven from them.
        let via = Self::via_of(row);
        let listing = Listing {
            blocking_lwps: self.blocking_lwps,
            nested: &self.tree.nested,
            list: self.list,
            polling: &self.polling,
            impls: self.impls,
        };
        let inside = || self.tree.nested.get(&via).into_iter().flatten();
        for (label, value, sets) in [
            ("Held futures", row.holds.to_string(), false),
            ("Join sets", row.sets_summary.clone(), true),
        ] {
            writeln!(out, "    {label}: {value}")?;
            for entry in inside().filter(|e| e.is_set() == sets) {
                print_future_entry(*entry, &listing, 8, false, out)?;
            }
        }
        writeln!(out)?;
        Ok(())
    }
}

/// Everything the `futures` command was asked. The filter grammar
/// rides in as the raw flag values and is parsed here, so the errors
/// name the flag they came from.
pub(crate) struct FuturesCmd {
    pub(crate) verbose: bool,
    pub(crate) limit: Option<usize>,
    pub(crate) with: Vec<String>,
    pub(crate) without: Vec<String>,
    pub(crate) group: Option<String>,
    pub(crate) exec: Vec<String>,
    pub(crate) addr: Vec<String>,
}

/// One filterable field of the future population — what `--with`,
/// `--without` and `--group` name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    /// The future type, as the table prints it.
    Type,
    /// The suspend state, `Suspend1 — file:line` style.
    State,
    /// The `WAITING ON` spelling.
    WaitingOn,
    /// The holding frame's local — a held future's only.
    Local,
    /// `held` or `child` — exact.
    Kind,
    /// The owning task's id, as `tasks` prints it — exact.
    Task,
    /// The owner's group index `runtimes --list` prints — exact.
    Rt,
    /// The holding frame number — exact, a held future's only.
    Frame,
    /// The address, for scripts — exact.
    Addr,
    /// A comparison on the chain's depth.
    Depth,
    /// A comparison on the `Held futures` count.
    Holds,
    /// A comparison on the `Join sets` count.
    Sets,
}

impl Field {
    const NAMES: [(&'static str, Field); 12] = [
        ("type", Field::Type),
        ("state", Field::State),
        ("waiting-on", Field::WaitingOn),
        ("local", Field::Local),
        ("kind", Field::Kind),
        ("task", Field::Task),
        ("rt", Field::Rt),
        ("frame", Field::Frame),
        ("addr", Field::Addr),
        ("depth", Field::Depth),
        ("holds", Field::Holds),
        ("sets", Field::Sets),
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
                anyhow::anyhow!(
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
        matches!(
            self,
            Field::Type | Field::State | Field::WaitingOn | Field::Local
        )
    }

    /// The distinct values the rows hold for the field — the kind
    /// level for the wait column, as `--group` buckets it — or `None`
    /// for an address or a count the argument compares against.
    fn values(self, rows: &[FutureRow]) -> Option<Vec<String>> {
        let column =
            |f: fn(&FutureRow) -> Option<String>| crate::tasks::distinct_values(rows.iter().map(f));
        Some(match self {
            Field::Type => column(|r| Some(r.future.clone())),
            Field::State => column(|r| r.state.clone()),
            Field::WaitingOn => column(|r| r.waiting_kind.clone()),
            Field::Local => column(|r| r.local.clone()),
            Field::Kind => vec!["held".to_string(), "child".to_string()],
            Field::Task => column(|r| Some(r.task.clone())),
            Field::Rt => column(|r| Some(r.rt.to_string())),
            Field::Frame => column(|r| r.frame.map(|frame| frame.to_string())),
            Field::Addr | Field::Depth | Field::Holds | Field::Sets => return None,
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
    let values = field.values(rows(session))?;
    Some((values, field.is_pattern()))
}

/// How one clause matches its field's value.
#[derive(Debug)]
enum Matcher {
    /// A case-insensitive regex over the spelled value.
    Pattern(crate::pattern::Pattern),
    /// Exact equality over the spelled value: `task`, `kind`.
    Exact(String),
    /// An exact address: `addr`.
    Addr(u64),
    /// An exact frame number: `frame`.
    Frame(usize),
    /// A resolved group index: `rt`.
    Rt(usize),
    /// `'>N'` / `'<N'` / `'=N'`: `depth`, `holds`, `sets`.
    Cmp(Cmp),
}

/// One `--with`/`--without` clause.
#[derive(Debug)]
struct Clause {
    field: Field,
    matcher: Matcher,
    /// `--without`: the clause keeps the rows it does *not* match.
    negate: bool,
}

/// Parse the flag pairs into clauses. clap delivered FIELD/ARG pairs
/// (`num_args = 2`), so the chunks are exact.
fn parse_clauses(with: &[String], without: &[String], handles: &[u64]) -> Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    for (specs, negate) in [(with, false), (without, true)] {
        let flag = if negate { "--without" } else { "--with" };
        for pair in specs.chunks_exact(2) {
            let field = Field::parse(&pair[0]).with_context(|| flag.to_string())?;
            let matcher = matcher(field, &pair[1], handles)
                .with_context(|| format!("{flag} {}", field.name()))?;
            clauses.push(Clause {
                field,
                matcher,
                negate,
            });
        }
    }
    Ok(clauses)
}

/// The matcher one field's argument compiles to.
fn matcher(field: Field, arg: &str, handles: &[u64]) -> Result<Matcher> {
    Ok(match field {
        Field::Task => Matcher::Exact(arg.to_string()),
        Field::Kind => match arg {
            "held" | "child" => Matcher::Exact(arg.to_string()),
            _ => anyhow::bail!("a kind is `held` or `child`, got {arg:?}"),
        },
        Field::Addr => Matcher::Addr(crate::parse_hex_addr(arg).map_err(anyhow::Error::msg)?),
        Field::Frame => Matcher::Frame(
            arg.parse()
                .map_err(|_| anyhow::anyhow!("a frame is a decimal number, got {arg:?}"))?,
        ),
        Field::Rt => Matcher::Rt(resolve_rt(arg, handles)?),
        Field::Depth | Field::Holds | Field::Sets => Matcher::Cmp(Cmp::parse(arg)?),
        _ => Matcher::Pattern(crate::pattern::Pattern::new(arg)?),
    })
}

/// Whether one row survives one clause.
fn survives(clause: &Clause, row: &FutureRow) -> bool {
    let hit = match &clause.matcher {
        Matcher::Pattern(p) => field_text(clause.field, row).is_some_and(|t| p.is_match(t)),
        Matcher::Exact(value) => field_text(clause.field, row) == Some(value.as_str()),
        Matcher::Addr(addr) => row.addr == *addr,
        Matcher::Frame(frame) => row.frame == Some(*frame),
        Matcher::Rt(rt) => row.rt == *rt,
        Matcher::Cmp(cmp) => cmp.matches(field_count(clause.field, row)),
    };
    hit != clause.negate
}

/// The spelled value a text field matches — `None`, nothing to match,
/// where the row has nothing to say.
fn field_text(field: Field, row: &FutureRow) -> Option<&str> {
    match field {
        Field::Type => Some(&row.future),
        Field::State => row.state.as_deref(),
        Field::WaitingOn => row.waiting_on.as_deref(),
        Field::Local => row.local.as_deref(),
        Field::Kind => Some(row.kind.name()),
        Field::Task => Some(&row.task),
        _ => unreachable!("{field:?} is not a text field"),
    }
}

/// The count a comparison field reads.
fn field_count(field: Field, row: &FutureRow) -> usize {
    match field {
        Field::Depth => row.depth,
        Field::Holds => row.holds,
        Field::Sets => row.sets,
        _ => unreachable!("{field:?} is not a count field"),
    }
}

/// What a bucket is named for one row: the field's spelled value, or
/// `None` for [`EMPTY_BUCKET`].
fn group_value(field: Field, row: &FutureRow) -> Option<String> {
    match field {
        Field::Type => Some(row.future.clone()),
        Field::State => row.state.clone(),
        // Grouped at the kind level — every timer one bucket — and a
        // chain that reached no leaf is the empty bucket, not a value.
        Field::WaitingOn => row.waiting_kind.clone(),
        Field::Local => row.local.clone(),
        Field::Kind => Some(row.kind.name().to_string()),
        Field::Task => Some(row.task.clone()),
        Field::Rt => Some(row.rt.to_string()),
        Field::Frame => row.frame.map(|frame| frame.to_string()),
        Field::Addr => Some(format!("{:#x}", row.addr)),
        Field::Depth | Field::Holds | Field::Sets => Some(field_count(field, row).to_string()),
    }
}

/// Up to three member addresses and `…` — the sample a bucket row
/// carries.
fn member_sample(rows: &[FutureRow], members: &[usize]) -> String {
    let addrs: Vec<String> = members
        .iter()
        .take(3)
        .map(|&i| format!("{:#x}", rows[i].addr))
        .collect();
    match members.len() > addrs.len() {
        true => format!("{}, …", addrs.join(", ")),
        false => addrs.join(", "),
    }
}

/// The refusal a positional address earns: one future is the singular
/// selector's business.
fn refuse_positional_addrs(addr: &[String]) -> Result<()> {
    match addr.first() {
        Some(first) => Err(anyhow::anyhow!(
            "futures takes no addresses; `future {first}` selects that one future \
             (-v for its chain), and `futures --with addr {first}` is its row"
        )),
        None => Ok(()),
    }
}

/// The census's own account of itself, printed before any listing
/// that claims to cover it: the per-find failures, and the limits and
/// refusals that make it a lower bound.
fn print_census_warnings(census: &census::FutureCensus) -> Result<()> {
    print_warnings(&census.errors)?;
    tasks::warn_census_capped(census.capped, "listed")?;
    tasks::warn_census_refused(census.refused, "listed")?;
    Ok(())
}

pub(crate) fn exec_futures<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: FuturesCmd,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    refuse_positional_addrs(&cmd.addr)?;
    let group = cmd
        .group
        .as_deref()
        .map(Field::parse)
        .transpose()
        .context("--group")?;
    let handles: Vec<u64> = session.runtimes.iter().map(|rt| rt.handle.addr).collect();
    let clauses = parse_clauses(&cmd.with, &cmd.without, &handles)?;

    // Every path reads the census, so its warnings open every one.
    let census = session.census();
    print_census_warnings(census)?;

    // The filters' survivors, as indices into the rows.
    let rows = rows(session);
    let survivors: Vec<usize> = (0..rows.len())
        .filter(|&i| clauses.iter().all(|c| survives(c, &rows[i])))
        .collect();

    if !cmd.exec.is_empty() {
        // clap refuses `--group` beside `--exec`; the filters and
        // `--limit` have already chosen who the command runs against.
        return exec_exec(session, &cmd, &survivors, theme, out);
    }

    if let Some(field) = group {
        return exec_group(
            session,
            &cmd,
            field,
            &survivors,
            session.fit_width(theme),
            out,
        );
    }

    let groups = !session.group_tags().is_empty();
    if !cmd.verbose {
        let selected: Vec<&FutureRow> = survivors.iter().map(|&i| &rows[i]).collect();
        print_future_table(&selected, groups, cmd.limit, session.fit_width(theme), out)?;
        print_warnings(&session.tasks.errors)?;
        return Ok(());
    }

    let blocks = blocks(session);
    let shown = cmd.limit.unwrap_or(survivors.len()).min(survivors.len());
    for &index in &survivors[..shown] {
        blocks.print(&rows[index], out)?;
    }
    writeln!(out, "{}", listing_footer(survivors.len(), shown, "future"))?;
    print_warnings(&session.tasks.errors)?;
    Ok(())
}

/// What the block printer reads, gathered from the session once per
/// command.
fn blocks<'s, T: proc::Target>(session: &'s Session<'_, T>) -> Blocks<'s> {
    let census = session.census();
    Blocks {
        list: &session.tasks,
        census,
        tree: census_tree(&census.held, &census.sets, &census.join_sets),
        impls: &session.impl_fold,
        group_tags: session.group_tags(),
        polling: tasks::polling_map(session),
        blocking_lwps: tasks::blocking_lwps(session),
    }
}

/// `--group FIELD`: bucket the surviving rows by the field's spelled
/// value and print `COUNT VALUE` rows, most numerous first (ties in
/// value order), each with up to three member addresses — or, under
/// `-v`, every member's block under its bucket. `--limit` cuts
/// buckets.
fn exec_group<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: &FuturesCmd,
    field: Field,
    survivors: &[usize],
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let rows = rows(session);
    let mut grouped: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &index in survivors {
        let value = group_value(field, &rows[index]).unwrap_or_else(|| EMPTY_BUCKET.to_string());
        grouped.entry(value).or_default().push(index);
    }
    let mut buckets: Vec<(String, Vec<usize>)> = grouped.into_iter().collect();
    // Count descending; the map already ordered ties by value, and the
    // sort is stable.
    buckets.sort_by_key(|(_, members)| std::cmp::Reverse(members.len()));
    let shown = cmd.limit.unwrap_or(buckets.len()).min(buckets.len());

    if cmd.verbose {
        let blocks = blocks(session);
        for (value, members) in &buckets[..shown] {
            writeln!(out, "{}  {value}", members.len())?;
            for &index in members {
                blocks.print(&rows[index], out)?;
            }
        }
    } else {
        let heading = field.name().replace('-', " ").to_uppercase();
        let mut table = crate::output::Table::new(3)
            .align_right(0)
            .header(["COUNT".to_string(), heading, "FUTURES".to_string()])
            .truncatable(1)
            .fit(fit);
        for (value, members) in &buckets[..shown] {
            table.row([
                members.len().to_string(),
                value.clone(),
                member_sample(rows, members),
            ]);
        }
        if !table.is_empty() {
            table.write(out)?;
        }
    }
    writeln!(out, "{}", listing_footer(buckets.len(), shown, "group"))?;
    print_warnings(&session.tasks.errors)?;
    Ok(())
}

/// `--exec COMMAND`: run the command once per surviving future, its
/// omitted target filled with that future, each run's output under
/// the future's table row. One future's failure never stops the loop —
/// the failed run shows its error in place, the summary line counts
/// them, and the command fails after the loop when any run did, so a
/// script sees one failure with nothing skipped.
fn exec_exec<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: &FuturesCmd,
    survivors: &[usize],
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    // Parse once up front: a command that does not parse is the
    // command line's mistake, not any future's, and fails before the
    // loop prints a heading.
    repl::parse_exec_command(&cmd.exec).context("--exec")?;
    let rows = rows(session);
    let shown = cmd.limit.unwrap_or(survivors.len()).min(survivors.len());
    let mut failed = 0usize;
    // Each run goes under a cursor scoped to its future — the
    // command's omitted target and `$_` are that future's — and the
    // session's own cursor comes back once the loop is done.
    let saved = *session.cursor.borrow();
    for (n, &index) in survivors[..shown].iter().enumerate() {
        write!(out, "{}", exec_heading(n, &row_line(session, index)))?;
        let command = repl::parse_exec_command(&cmd.exec).expect("parsed above");
        crate::cursor::scope_to_future(session, rows[index].at);
        // `quit` is not a per-future answer, so a Quit flow is ignored
        // and the loop runs on.
        if let Err(e) = crate::dispatch(session, command, theme, out) {
            failed += 1;
            writeln!(out, "error: {e:#}")?;
        }
    }
    *session.cursor.borrow_mut() = saved;
    writeln!(out, "Executed against {shown} futures, {failed} failed")?;
    if failed > 0 {
        anyhow::bail!("--exec failed against {failed} of {shown} futures");
    }
    Ok(())
}

/// The heading `--exec` opens future `n`'s output with: a blank line
/// between one future's output and the next, then the future's table
/// row.
fn exec_heading(n: usize, row: &str) -> String {
    let sep = if n > 0 { "\n" } else { "" };
    format!("{sep}{row}\n")
}

#[cfg(test)]
mod tests {
    use super::{
        Clause, Field, FutureRow, Kind, build_rows, exec_heading, group_value, matcher, survives,
    };

    use crate::trace::FutureAt;

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::bundle::{FutureInfo, Task, TaskList, WaitKind};
    use hansei_runtime::tokio::census::{self, FutureCensus, Via};
    use hansei_runtime::tokio::{TaskAddr, TaskState};

    fn task(id: u64, group: usize) -> Task {
        Task {
            addr: TaskAddr(0x1000 + id * 0x100),
            state: TaskState(1 << 6),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            group,
            blocking: false,
        }
    }

    /// Two tasks in two groups, with ids one of which spells a prefix
    /// of the other — so an exact match and a regex disagree.
    fn list() -> TaskList {
        TaskList {
            tasks: vec![task(1, 0), task(12, 1)],
            errors: vec![],
        }
    }

    fn held(owner: usize, addr: u64, via: Option<Via>) -> census::HeldFuture {
        census::HeldFuture {
            owner,
            frame: 1,
            local: "arm".to_string(),
            via,
            slot: addr,
            addr,
            ty: BundleTypeId(0),
            depth: 2,
            future: "app::work::{async_fn_env#0}".to_string(),
            state: Some("Suspend1 — src/app.rs:9".to_string()),
            waiting_on: Some("a timer".to_string()),
            wait: Some(WaitKind::Timer { past_due: None }),
            leaf: None,
        }
    }

    fn child(node: u64, future: Option<&str>) -> census::SetChild {
        census::SetChild {
            node,
            depth: 1,
            future: future.map(str::to_string),
            root: future.map(|_| census::FutureRoot {
                addr: node + 0x10,
                ty: BundleTypeId(0),
            }),
            state: None,
            waiting_on: None,
            wait: Some(WaitKind::Task { addr: 0x1c00 }),
            leaf: None,
        }
    }

    fn set(owner: usize, children: Vec<census::SetChild>) -> census::FutureSet {
        census::FutureSet {
            owner,
            frame: 0,
            local: "set".to_string(),
            via: None,
            addr: 0x2000,
            ty: "FuturesUnordered<app::child>".to_string(),
            children,
        }
    }

    /// An empty set found inside another find: it counts on that
    /// find's row and adds no rows of its own.
    fn nested_set(via: Via) -> census::FutureSet {
        census::FutureSet {
            via: Some(via),
            addr: 0x2100,
            children: vec![],
            ..set(0, vec![])
        }
    }

    fn nested_join_set(via: Via) -> census::JoinSet {
        census::JoinSet {
            owner: 0,
            frame: 0,
            local: "workers".to_string(),
            via: Some(via),
            addr: 0x2200,
            ty: "JoinSet<()>".to_string(),
            length: 0,
            children: vec![],
        }
    }

    /// The census as the offline suites build one: the flat lists,
    /// with the spans a child lookup would need left empty.
    fn census(held: Vec<census::HeldFuture>, sets: Vec<census::FutureSet>) -> FutureCensus {
        FutureCensus::from_finds(held, sets, vec![])
    }

    fn rows_of(census: &FutureCensus) -> Vec<FutureRow> {
        build_rows(&list(), census, &hansei_bundle::names::ImplFold::default())
    }

    /// Rows come in task order with a task's held futures ahead of its
    /// set children and a nested find right after what holds it, a
    /// reaped child gets no row, and each cell says what its column
    /// promises: where the future sits, spelled the way `whatis`
    /// spells a nested find's origin.
    #[test]
    fn test_rows_follow_tree_order_and_spell_where_each_sits() {
        let inside_held = Via::Held(1);
        let inside_child = Via::SetChild { set: 0, child: 0 };
        let census = FutureCensus::from_finds(
            vec![
                held(1, 0x5000, None),
                held(0, 0x3000, None),
                held(0, 0x3100, Some(inside_child)),
            ],
            vec![
                set(
                    0,
                    vec![child(0x4000, Some("app::child")), child(0x4100, None)],
                ),
                nested_set(inside_held),
                nested_set(inside_child),
            ],
            vec![nested_join_set(inside_held), nested_join_set(inside_child)],
        );
        let rows = rows_of(&census);
        let addrs: Vec<u64> = rows.iter().map(|r| r.addr).collect();
        assert_eq!(addrs, [0x3000, 0x4000, 0x3100, 0x5000]);

        let direct = &rows[0];
        assert_eq!((direct.kind, direct.task.as_str()), (Kind::Held, "1"));
        assert_eq!(direct.held_in, "frame 1, `arm`");
        assert_eq!(direct.future, "async fn app::work");
        assert_eq!(direct.waiting_kind.as_deref(), Some("timer"));
        assert_eq!(direct.rt, 0);

        let nested = &rows[2];
        assert_eq!(nested.held_in, "frame 1, `arm`, via set child at 0x4000");
        assert_eq!(nested.via, Some(Via::SetChild { set: 0, child: 0 }));

        let child = &rows[1];
        assert_eq!((child.kind, child.task.as_str()), (Kind::Child, "1"));
        assert_eq!(child.held_in, "set 0x2000");
        assert_eq!((child.frame, child.local.as_deref()), (None, None));
        assert_eq!(child.waiting_kind.as_deref(), Some("task 12"));
        assert!(matches!(child.at, FutureAt::Child { set: 0, child: 0 }));
        // What the census found inside a find is counted on its row,
        // not on the task's: the held future, and the sets of either
        // kind, which are one count between them.
        assert_eq!((child.holds, child.sets), (1, 2));
        assert_eq!((direct.holds, direct.sets), (0, 2));
        assert_eq!(direct.sets_summary, "2 (0 tasks and 0 futures)");

        let other = &rows[3];
        assert_eq!((other.task.as_str(), other.rt), ("12", 1));
    }

    fn clause(field: &str, arg: &str, negate: bool) -> Clause {
        let field = Field::parse(field).expect("a named field");
        Clause {
            field,
            matcher: matcher(field, arg, &[]).expect("a valid argument"),
            negate,
        }
    }

    /// Each matcher reads the field its name promises — the exact
    /// ones exactly, the count ones by comparison, the text ones as
    /// regexes — and a row with nothing in a text field matches
    /// nothing rather than the empty string.
    #[test]
    fn test_clauses_read_their_fields() {
        let census = census(
            vec![held(0, 0x3000, None), held(1, 0x5000, None)],
            vec![set(0, vec![child(0x4000, Some("app::child"))])],
        );
        let rows = rows_of(&census);
        let (h, c, other) = (&rows[0], &rows[1], &rows[2]);
        assert!(survives(&clause("kind", "held", false), h));
        assert!(!survives(&clause("kind", "held", false), c));
        assert!(survives(&clause("kind", "held", true), c));
        assert!(survives(&clause("addr", "0x4000", false), c));
        assert!(survives(&clause("task", "1", false), c));
        assert!(!survives(&clause("task", "10", false), c));
        // Exact, not a prefix: task 1 is not task 12.
        assert!(!survives(&clause("task", "1", false), other));
        assert!(survives(&clause("rt", "1", false), other));
        assert!(!survives(&clause("rt", "1", false), h));
        assert!(survives(&clause("waiting-on", "TIMER", false), h));
        assert!(!survives(&clause("waiting-on", ".", false), c));
        assert!(survives(&clause("frame", "1", false), h));
        assert!(!survives(&clause("frame", "1", false), c));
        assert!(survives(&clause("local", "AR", false), h));
        assert!(!survives(&clause("local", "AR", false), c));
        assert!(survives(&clause("type", "work", false), h));
        assert!(survives(&clause("state", "app.rs", false), h));
        assert!(!survives(&clause("state", ".", false), c));
        assert!(survives(&clause("depth", ">1", false), h));
        assert!(!survives(&clause("depth", ">1", false), c));
        assert!(survives(&clause("holds", "=0", false), h));
        assert!(survives(&clause("sets", "=0", false), h));
        assert!(!survives(&clause("sets", ">0", false), h));
        assert!(matcher(Field::Kind, "set", &[]).is_err());
        assert!(matcher(Field::Addr, "4000", &[]).is_err());
        assert!(Field::parse("lwp").is_err());
    }

    /// Only the first heading goes without a blank line above it.
    #[test]
    fn test_exec_headings_are_separated_after_the_first() {
        assert_eq!(
            exec_heading(0, "0x4000  1  set 0x2000"),
            "0x4000  1  set 0x2000\n"
        );
        assert_eq!(
            exec_heading(1, "0x4000  1  set 0x2000"),
            "\n0x4000  1  set 0x2000\n"
        );
    }

    /// A positional address is refused with the two spellings that do
    /// take one, and only a positional address is.
    #[test]
    fn test_positional_addresses_are_refused_with_the_way_forward() {
        use super::refuse_positional_addrs;
        assert!(refuse_positional_addrs(&[]).is_ok());
        let err = refuse_positional_addrs(&["0x4000".to_string(), "0x5000".to_string()])
            .expect_err("addresses are the selector's");
        assert_eq!(
            err.to_string(),
            "futures takes no addresses; `future 0x4000` selects that one future \
             (-v for its chain), and `futures --with addr 0x4000` is its row"
        );
    }

    /// A bucket is the field's spelled value, kind-level for the wait,
    /// and `None` — the empty bucket — where a row has nothing there.
    #[test]
    fn test_group_values() {
        let census = census(
            vec![held(0, 0x3000, None)],
            vec![set(0, vec![child(0x4000, Some("app::child"))])],
        );
        let rows = rows_of(&census);
        let (h, c) = (&rows[0], &rows[1]);
        assert_eq!(group_value(Field::Kind, h).as_deref(), Some("held"));
        assert_eq!(group_value(Field::WaitingOn, h).as_deref(), Some("timer"));
        assert_eq!(group_value(Field::WaitingOn, c).as_deref(), Some("task 12"));
        assert_eq!(group_value(Field::Frame, c), None);
        assert_eq!(group_value(Field::State, c), None);
        assert_eq!(group_value(Field::Addr, c).as_deref(), Some("0x4000"));
        assert_eq!(group_value(Field::Depth, h).as_deref(), Some("2"));
    }

    /// Each field's values are its column's distinct spellings — the
    /// wait at its kind level, the fixed held/child for kind — and
    /// `None` for an address or a compared count. The pattern fields
    /// are the four string columns.
    #[test]
    fn test_field_values_are_the_columns_distinct_spellings() {
        let census = census(
            vec![held(0, 0x3000, None)],
            vec![set(0, vec![child(0x4000, Some("app::child"))])],
        );
        let rows = rows_of(&census);
        let values = |field: Field| field.values(&rows);
        assert_eq!(
            values(Field::Kind),
            Some(vec!["held".into(), "child".into()])
        );
        assert_eq!(
            values(Field::WaitingOn),
            Some(vec!["task 12".into(), "timer".into()])
        );
        assert_eq!(values(Field::Task), Some(vec![rows[0].task.clone()]));
        assert_eq!(values(Field::Rt), Some(vec!["0".into()]));
        assert_eq!(
            values(Field::Frame),
            Some(vec![rows[0].frame.unwrap().to_string()])
        );
        assert_eq!(
            values(Field::Type),
            Some(vec![rows[0].future.clone(), rows[1].future.clone()])
        );
        assert_eq!(
            values(Field::Local),
            Some(vec![rows[0].local.clone().unwrap()])
        );
        assert_eq!(
            values(Field::State),
            Some(vec![rows[0].state.clone().unwrap()])
        );
        assert_eq!(values(Field::Addr), None);
        assert_eq!(values(Field::Depth), None);
        assert_eq!(values(Field::Holds), None);
        assert_eq!(values(Field::Sets), None);
        for pattern in [Field::Type, Field::State, Field::WaitingOn, Field::Local] {
            assert!(pattern.is_pattern(), "{pattern:?}");
        }
        for exact in [
            Field::Kind,
            Field::Task,
            Field::Rt,
            Field::Frame,
            Field::Addr,
            Field::Depth,
            Field::Holds,
            Field::Sets,
        ] {
            assert!(!exact.is_pattern(), "{exact:?}");
        }
    }
}

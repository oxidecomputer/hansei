// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `futures` command: every future the census found in flight
//! beside the tasks' own await chains, listed as one population rather
//! than under the tasks that hold them.

use crate::runtimes::RowOwner;
use crate::tasks::{
    self, CensusTree, Cmp, EMPTY_BUCKET, Entry, Finds, Listing, StopNames, alternatives,
    census_tree, listing_footer, print_future_entry, resolve_rt, task_id,
};
use crate::trace::FutureAt;
use crate::whatis::via_suffix;
use crate::{Session, print_warnings, repl, summary};

use anyhow::{Context as _, Result};
use hansei_bundle::names;
use hansei_runtime::tokio::assess::ContinuationStatus;
use hansei_runtime::tokio::{RawInstant, attribution, bundle, census};

use rayon::iter::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
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
    /// The owner's group index (`runtimes`), or the word for an owner
    /// that is no group.
    pub(crate) rt: RowOwner,
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
    /// The `WAITING ON` cell: the slots holding the polling task's
    /// waker that sit in this future or were reached through a pointer
    /// it holds, each spelled by its reader where the future's own
    /// wait accounts for it; `unarmed: ` before what its chain says
    /// where no slot does and no protocol read the waker. Built short
    /// of the slots first and merged once the sweep is in
    /// ([`with_slots`]).
    pub(crate) waiting_on: Option<String>,
    /// The kind-level bucket `--group waiting-on` files the row under:
    /// the slots' kinds, else the primitive's kind or what the
    /// continuation says instead, under `unarmed: ` where no slot
    /// arms it.
    pub(crate) waiting_kind: Option<String>,
    /// The `ARMED` cell: whether a slot attributes to the future — in
    /// its storage, through a pointer it holds, or inside a future it
    /// holds in turn — or its own protocol read the polling task's
    /// waker in the resource. `no` is a future held and awaited by
    /// nothing found.
    pub(crate) armed: bool,
    /// One detail line per slot, for the block: where it sits and
    /// what says it is current.
    pub(crate) slot_lines: Vec<String>,
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
    session.future_rows.get_or_init(|| {
        let rows = build_rows(
            &session.tasks,
            &session.owners,
            session.census(),
            &session.impl_fold,
            &StopNames::of(session),
        );
        with_slots(
            rows,
            &session.tasks,
            session.census(),
            session.attribution(),
            session.registries.stopped,
        )
    })
}

/// The rows with their slots merged in: each find's cell, bucket,
/// `ARMED` and detail lines rewritten from the slots attributed to it.
/// A slot is a find's when it sits in the find's storage or in a
/// future the find holds in turn, was reached through a pointer the
/// find holds, or is the slot of the very primitive the find's own
/// reader names — the channel a `recv` polls, the `Notify` a queued
/// `Notified` is on — held by the same owner. A find with none is
/// `unarmed: ` before what its chain said.
pub(crate) fn with_slots(
    mut rows: Vec<FutureRow>,
    list: &bundle::TaskList,
    census: &census::FutureCensus,
    slots: &attribution::Attributed,
    stopped: Option<RawInstant>,
) -> Vec<FutureRow> {
    // Which held finds sit inside which: a slot in a nested find is
    // in the outer one's storage too.
    let mut nested: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, held) in census.held.iter().enumerate() {
        if let Some(census::Via::Held(outer)) = held.via {
            nested.entry(outer).or_default().push(i);
        }
    }
    fn gather<'a>(
        slots: &'a attribution::Attributed,
        nested: &HashMap<usize, Vec<usize>>,
        i: usize,
        out: &mut Vec<&'a attribution::AttributedSlot>,
    ) {
        out.extend(slots.of_find(i));
        for &inner in nested.get(&i).into_iter().flatten() {
            gather(slots, nested, inner, out);
        }
    }
    // Whose slots a find's reader can name: the polling task's for a
    // find under a task, the set child's own for one under a child.
    let owner_slots =
        |via: Option<census::Via>, owner: usize| -> Vec<&attribution::AttributedSlot> {
            let mut via = via;
            loop {
                match via {
                    Some(census::Via::SetChild { set, child }) => {
                        return slots.of_child(set, child).collect();
                    }
                    Some(census::Via::Held(outer)) => via = census.held[outer].via,
                    None => return slots.of_task(list.tasks[owner].addr.0).collect(),
                }
            }
        };
    // Each row reads only its own find: the rows are rewritten side
    // by side, as they were built.
    rows.par_iter_mut().for_each(|row| {
        let mut owned: Vec<&attribution::AttributedSlot> = Vec::new();
        let (wait, via) = match row.at {
            FutureAt::Held(i) => {
                gather(slots, &nested, i, &mut owned);
                (census.held[i].wait, census.held[i].via)
            }
            FutureAt::Child { set, child } => {
                owned.extend(slots.of_child(set, child));
                (
                    census.sets[set].children[child].wait,
                    Some(census::Via::SetChild { set, child }),
                )
            }
        };
        if let Some(kind) = wait {
            owned.extend(
                owner_slots(via, row.owner)
                    .into_iter()
                    .filter(|slot| names_primitive(kind, slot)),
            );
        }
        owned.sort_by_key(|s| s.slot);
        owned.dedup_by_key(|s| s.slot);
        row.armed = !owned.is_empty();
        if owned.is_empty() {
            row.waiting_on = row.waiting_on.take().map(|w| format!("unarmed: {w}"));
            row.waiting_kind = row.waiting_kind.take().map(|k| format!("unarmed: {k}"));
            return;
        }
        // The find's own reader accounts for the slot of its kind:
        // that slot takes the reader's cell.
        let reader = wait.and_then(|_| Some((row.waiting_on.clone()?, row.waiting_kind.clone()?)));
        let accounted = |slot: &attribution::AttributedSlot| {
            let kind = wait?;
            kind_matches(kind, slot).then(|| reader.clone()).flatten()
        };
        let (cell, kind) = tasks::slot_cell(&owned, stopped, &accounted);
        row.waiting_on = Some(cell);
        row.waiting_kind = Some(kind);
        row.slot_lines = tasks::slot_lines(&owned, stopped);
    });
    rows
}

/// Whether a slot is of the kind a find's verified wait names: the
/// reader's cell then speaks for the slot.
fn kind_matches(kind: bundle::WaitKind, slot: &attribution::AttributedSlot) -> bool {
    use attribution::{Attribution, OwnerKind, RegistrySlot};
    match (kind, &slot.attribution) {
        (bundle::WaitKind::Timer { .. }, Attribution::Registry(RegistrySlot::Timer { .. })) => true,
        (bundle::WaitKind::Io, Attribution::Registry(RegistrySlot::Io { .. })) => true,
        (bundle::WaitKind::Task { addr }, Attribution::Registry(RegistrySlot::Join { task })) => {
            task.addr.0 == addr
        }
        (
            bundle::WaitKind::Semaphore { .. },
            Attribution::Registry(RegistrySlot::Semaphore { .. }),
        ) => true,
        (bundle::WaitKind::Channel { .. }, Attribution::Owner { kind, .. }) => {
            *kind == OwnerKind::Mpsc
        }
        (bundle::WaitKind::Notify { .. }, Attribution::Owner { kind, .. }) => {
            *kind == OwnerKind::Notify
        }
        (bundle::WaitKind::Oneshot { .. }, Attribution::Owner { kind, .. }) => {
            *kind == OwnerKind::OneshotRx
        }
        (bundle::WaitKind::Watch { .. }, Attribution::Owner { kind, .. }) => {
            *kind == OwnerKind::Watch
        }
        _ => false,
    }
}

/// Whether a slot is the slot of the primitive a find's wait names:
/// the receiver cell of the channel a `recv` polls, the node queued on
/// the `Notify` a `Notified` waits on, the trailer of the task a
/// `JoinHandle` awaits. Only waits that name an address qualify; a
/// timer's entry is in the find's own storage and needs no join.
fn names_primitive(kind: bundle::WaitKind, slot: &attribution::AttributedSlot) -> bool {
    use attribution::{Attribution, OwnerKind, RegistrySlot};
    match (kind, &slot.attribution) {
        (
            bundle::WaitKind::Channel { addr },
            Attribution::Owner {
                kind: OwnerKind::Mpsc,
                primitive,
                ..
            },
        )
        | (
            bundle::WaitKind::Notify { addr },
            Attribution::Owner {
                kind: OwnerKind::Notify,
                primitive,
                ..
            },
        )
        | (
            bundle::WaitKind::Oneshot { addr },
            Attribution::Owner {
                kind: OwnerKind::OneshotRx,
                primitive,
                ..
            },
        )
        | (
            bundle::WaitKind::Watch { addr },
            Attribution::Owner {
                kind: OwnerKind::Watch,
                primitive,
                ..
            },
        ) => *primitive == addr,
        (bundle::WaitKind::Task { addr }, Attribution::Registry(RegistrySlot::Join { task })) => {
            task.addr.0 == addr
        }
        _ => false,
    }
}

/// Build every row from what it prints — taken apart from the session
/// so a test can lay out a population no fixture holds. Rows come in
/// the order `task --futures` prints the same finds: task by task,
/// each task's held futures ahead of its set children, and whatever
/// the census found inside a find directly after it — so a listing
/// read top to bottom meets a future before the ones it holds. A
/// completed child the set has not reaped is no future in flight and
/// gets no row.
pub(crate) fn build_rows(
    list: &bundle::TaskList,
    owners: &bundle::OwnerIndex,
    census: &census::FutureCensus,
    impls: &names::ImplFold,
    stops: &StopNames<'_>,
) -> Vec<FutureRow> {
    let tree = census_tree(census.into());
    let rows = Rows {
        list,
        owners,
        census,
        tree: &tree,
        impls,
        stops,
        task_at: list
            .tasks
            .iter()
            .enumerate()
            .map(|(i, t)| (t.addr.0, i))
            .collect(),
    };
    // Each root's rows are independent of every other's, and inside a
    // root the fan-out continues wherever a find has many siblings —
    // the census's biggest finds are sets with tens of thousands of
    // children — so the build is parallel at every level and the rows
    // still come out in the listing's order.
    let roots: Vec<&Vec<Entry>> = tree.roots.values().collect();
    roots
        .par_iter()
        .map(|entries| rows.rows_of_all(entries))
        .flatten_iter()
        .collect()
}

/// Below this many siblings a find's rows are built on the calling
/// thread; splitting a handful across the pool costs more than the
/// rows do.
const PARALLEL_ROWS: usize = 64;

/// What building a row reads: the census the finds are in, the tree
/// that says what is inside each, and the task listing the owner is
/// named from.
struct Rows<'a> {
    list: &'a bundle::TaskList,
    owners: &'a bundle::OwnerIndex,
    census: &'a census::FutureCensus,
    tree: &'a CensusTree,
    impls: &'a names::ImplFold,
    /// How an unknown continuation's stop is named for its bucket.
    stops: &'a StopNames<'a>,
    /// Task index by address, for the rows that wait on a task: a
    /// scan of the listing per row is a scan of megabytes per row.
    task_at: HashMap<u64, usize>,
}

impl Rows<'_> {
    /// The rows of several finds in order, built side by side once
    /// there are enough of them for the split to pay for itself.
    fn rows_of_all(&self, entries: &[Entry]) -> Vec<FutureRow> {
        if entries.len() < PARALLEL_ROWS {
            return entries.iter().flat_map(|e| self.rows_of(*e)).collect();
        }
        entries
            .par_iter()
            .map(|e| self.rows_of(*e))
            .flatten_iter()
            .collect()
    }

    /// The rows the census found inside one find.
    fn rows_under(&self, via: census::Via) -> Vec<FutureRow> {
        match self.tree.nested.get(&via) {
            Some(entries) => self.rows_of_all(entries),
            None => Vec::new(),
        }
    }

    /// One find's rows — a held future's own, or one per live child
    /// of a set — each followed by the rows of what the census found
    /// inside it. A join set holds tasks, which have rows of their own
    /// in `tasks`, so it contributes none here.
    fn rows_of(&self, entry: Entry) -> Vec<FutureRow> {
        match entry {
            Entry::Held(i) => {
                let mut out = vec![self.held(i, &self.census.held[i])];
                out.extend(self.rows_under(census::Via::Held(i)));
                out
            }
            Entry::Set(set) => {
                let s = &self.census.sets[set];
                let live: Vec<(usize, &census::SetChild, &str)> = s
                    .children
                    .iter()
                    .enumerate()
                    .filter_map(|(child, c)| Some((child, c, c.future.as_deref()?)))
                    .collect();
                let child_rows = |&(child, c, future): &(usize, &census::SetChild, &str)| {
                    let mut out = vec![self.child(set, child, s, c, future)];
                    out.extend(self.rows_under(census::Via::SetChild { set, child }));
                    out
                };
                if live.len() < PARALLEL_ROWS {
                    return live.iter().flat_map(child_rows).collect();
                }
                live.par_iter().map(child_rows).flatten_iter().collect()
            }
            Entry::JoinSet(_) => Vec::new(),
        }
    }

    fn held(&self, i: usize, h: &census::HeldFuture) -> FutureRow {
        let inside = self
            .tree
            .counts_under(self.census.into(), census::Via::Held(i));
        FutureRow {
            at: FutureAt::Held(i),
            addr: h.addr,
            owner: h.owner,
            task: task_id(self.list, h.owner),
            rt: RowOwner::of(&self.list.tasks[h.owner], self.owners),
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
            waiting_on: h
                .waiting_on
                .clone()
                .or_else(|| tasks::continuation_bucket(&h.continuation, self.stops)),
            waiting_kind: waiting_kind(
                h.wait,
                &h.continuation,
                self.list,
                &self.task_at,
                self.stops,
            ),
            armed: false,
            slot_lines: Vec::new(),
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
        let inside = self
            .tree
            .counts_under(self.census.into(), census::Via::SetChild { set, child });
        FutureRow {
            at: FutureAt::Child { set, child },
            addr: c.node,
            owner: s.owner,
            task: task_id(self.list, s.owner),
            rt: RowOwner::of(&self.list.tasks[s.owner], self.owners),
            kind: Kind::Child,
            held_in: format!("set {:#x}{}", s.addr, via_suffix(self.census, s.via)),
            frame: None,
            local: None,
            via: s.via,
            state: c.state.clone(),
            waiting_on: c
                .waiting_on
                .clone()
                .or_else(|| tasks::continuation_bucket(&c.continuation, self.stops)),
            waiting_kind: waiting_kind(
                c.wait,
                &c.continuation,
                self.list,
                &self.task_at,
                self.stops,
            ),
            armed: false,
            slot_lines: Vec::new(),
            future: names::display_future_name(future, self.impls),
            depth: c.depth,
            holds: inside.held,
            sets: inside.sets + inside.join_sets,
            sets_summary: inside.sets_summary(),
        }
    }
}

/// The bucket `--group waiting-on` files a row under: the resource's
/// kind where its chain ends in one — with the identity that groups
/// usefully, which task, which kind of lock — else what the
/// continuation says instead ([`tasks::continuation_bucket`]): the
/// type it stopped at, how it was cut short, or nothing.
fn waiting_kind(
    wait: Option<bundle::WaitKind>,
    continuation: &ContinuationStatus,
    list: &bundle::TaskList,
    task_at: &HashMap<u64, usize>,
    stops: &StopNames<'_>,
) -> Option<String> {
    match wait {
        Some(bundle::WaitKind::Timer { .. }) => Some("timer".to_string()),
        Some(bundle::WaitKind::Task { addr }) => Some(match task_at.get(&addr) {
            Some(&index) => tasks::task_label(list, index),
            None => format!("the task at {addr:#x}"),
        }),
        Some(bundle::WaitKind::Io) => Some("io".to_string()),
        Some(bundle::WaitKind::Semaphore { owner }) => Some(match owner {
            Some(owner) => format!("a {owner} (semaphore)"),
            None => "a semaphore".to_string(),
        }),
        Some(bundle::WaitKind::Channel { .. }) => Some("mpsc".to_string()),
        Some(bundle::WaitKind::Notify { .. }) => Some("notify".to_string()),
        Some(bundle::WaitKind::Oneshot { .. }) => Some("oneshot rx".to_string()),
        Some(bundle::WaitKind::Watch { .. }) => Some("watch".to_string()),
        None => tasks::continuation_bucket(continuation, stops),
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
    cells.push(armed_word(row.armed).to_string());
    cells.push(row.future.clone());
    cells
}

/// The `ARMED` cell's word.
fn armed_word(armed: bool) -> &'static str {
    if armed { "yes" } else { "no" }
}

/// Print the table: one row per future, the `RT` column only when the
/// target holds more than one group.
fn print_future_table(
    rows: &[&FutureRow],
    groups: bool,
    limit: Option<usize>,
    fit: Option<usize>,
    theme: crate::output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let shown = limit.unwrap_or(rows.len()).min(rows.len());
    let mut header = vec!["ADDR", "TASK"];
    if groups {
        header.push("RT");
    }
    header.extend(["HELD IN", "STATE", "WAITING ON", "ARMED", "TYPE"]);
    let columns = header.len();
    // The wait and the future are type names: what a terminal cuts
    // to keep a row on one line.
    let mut table = crate::output::Table::new(columns)
        .header(header)
        .truncatable(columns - 3)
        .truncatable(columns - 1)
        .fit(fit)
        .theme(theme);
    for row in &rows[..shown] {
        table.row(row_cells(row, groups));
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(rows.len(), shown, "future"))?;
    Ok(())
}

/// What printing one future reads beyond its row: the census tree the
/// finds inside it are read from, and the task listing a nested join
/// set names its members from.
struct Blocks<'a> {
    list: &'a bundle::TaskList,
    owners: &'a bundle::OwnerIndex,
    census: &'a census::FutureCensus,
    tree: &'a CensusTree,
    impls: &'a names::ImplFold,
    group_tags: Vec<String>,
    polling: HashMap<u64, u32>,
    blocking_lwps: &'a HashMap<u64, u32>,
    /// The width the finds' names are cut to fit within
    /// ([`Session::fit_width`]); `None` leaves them whole. The
    /// future's own `type:` line is never cut.
    fit: Option<usize>,
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

    /// One future as labelled lines — what `future` prints: its type,
    /// where it sits (the holding frame and local, or the set whose
    /// child node it is, and the task either belongs to), its owner
    /// where the target has more than one group, its own state and
    /// depth, what it waits on, and the census's finds inside it,
    /// listed under the count each belongs to. The fields sit four
    /// columns in from the `future 0x…` heading, the finds four more.
    /// A line prints only where the census has something for it — a
    /// child whose state could not be read is a shorter block — while
    /// the counts print always, since `0` is an answer.
    fn print(&self, row: &FutureRow, out: &mut dyn io::Write) -> Result<()> {
        writeln!(out, "future {:#x}", row.addr)?;
        writeln!(out, "    type: {}", row.future)?;
        match row.at {
            FutureAt::Held(_) => writeln!(
                out,
                "    held by: {} ({}){}",
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
                    "    child of: {} at {:#x}, polled by {}{}",
                    names::fold_type_name(&s.ty, self.impls),
                    s.addr,
                    tasks::task_label(self.list, row.owner),
                    via_suffix(self.census, row.via)
                )?
            }
        }
        if let Some(owner) =
            RowOwner::detail(&self.list.tasks[row.owner], self.owners, &self.group_tags)
        {
            writeln!(out, "    owner: {owner}")?;
        }
        if let Some(state) = &row.state {
            writeln!(out, "    state: {state}")?;
        }
        writeln!(out, "    depth: {}", summary::counted(row.depth, "frame"))?;
        // The wait, one line per slot under it, and whether anything
        // arms the future at all — `no` is an answer, so it prints.
        if let Some(waiting) = &row.waiting_on {
            writeln!(out, "    waiting on: {waiting}")?;
            for line in &row.slot_lines {
                writeln!(out, "        {line}")?;
            }
        }
        writeln!(out, "    armed: {}", armed_word(row.armed))?;
        // What the census found inside this future, the way `task`
        // lists what it found in the task's own frames: the futures
        // held in its frames, then the sets driven from them.
        let via = Self::via_of(row);
        let listing = Listing {
            blocking_lwps: self.blocking_lwps,
            fit: self.fit,
            finds: Finds::from(self.census),
            nested: &self.tree.nested,
            list: self.list,
            polling: &self.polling,
            impls: self.impls,
        };
        let inside = || self.tree.nested.get(&via).into_iter().flatten();
        for (label, value, sets) in [
            ("held futures", row.holds.to_string(), false),
            ("join sets", row.sets_summary.clone(), true),
        ] {
            writeln!(out, "    {label}: {value}")?;
            for entry in inside().filter(|e| e.is_set() == sets) {
                print_future_entry(*entry, &listing, 8, false, out)?;
            }
        }
        Ok(())
    }
}

/// What `future` prints for the census find at `at`: the block above,
/// over the session. A set child the set has already reaped is no
/// future in flight, has no row, and is refused by name.
pub(crate) fn print_future<T: proc::Target>(
    session: &Session<'_, T>,
    at: FutureAt,
    fit: Option<usize>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let rows = rows(session);
    let Some(row) = rows.iter().find(|row| row.at == at) else {
        anyhow::bail!("that child has completed and awaits reaping; nothing is in flight there");
    };
    let census = session.census();
    let blocks = Blocks {
        list: &session.tasks,
        owners: &session.owners,
        census,
        tree: session.census_tree(),
        impls: &session.impl_fold,
        group_tags: session.group_tags(),
        polling: tasks::polling_map(session),
        blocking_lwps: tasks::blocking_lwps(session),
        fit,
    };
    blocks.print(row, out)
}

/// Everything the `futures` command was asked. The filter grammar
/// rides in as the raw flag values and is parsed here, so the errors
/// name the flag they came from.
pub(crate) struct FuturesCmd {
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
    /// `yes` or `no`: whether a slot arms the future — exact.
    Armed,
    /// The owning task's id, as `tasks` prints it — exact.
    Task,
    /// The owner's group index `runtimes` prints — exact.
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
    const NAMES: [(&'static str, Field); 13] = [
        ("type", Field::Type),
        ("state", Field::State),
        ("waiting-on", Field::WaitingOn),
        ("local", Field::Local),
        ("kind", Field::Kind),
        ("armed", Field::Armed),
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
            Field::Armed => vec!["yes".to_string(), "no".to_string()],
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
    /// A resolved owner cell: `rt`.
    Rt(RowOwner),
    /// `'>N'` / `'<N'` / `'=N'`: `depth`, `holds`, `sets`.
    Cmp(Cmp),
}

/// One `--with`/`--without` clause.
#[derive(Debug)]
struct Clause {
    field: Field,
    /// The argument's alternatives (`0x10,0x20`): the clause matches
    /// a row when any one of them does.
    matchers: Vec<Matcher>,
    /// `--without`: the clause keeps the rows it does *not* match.
    negate: bool,
}

/// Parse the flag pairs into clauses. clap delivered FIELD/ARG pairs
/// (`num_args = 2`), so the chunks are exact.
fn parse_clauses(with: &[String], without: &[String], handles: &[u64]) -> Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    for (specs, negate) in [(with, false), (without, true)] {
        let flag = if negate { "--without" } else { "--with" };
        for [name, spec] in specs.as_chunks::<2>().0 {
            let field = Field::parse(name).with_context(|| flag.to_string())?;
            let matchers = alternatives(spec)
                .and_then(|alts| {
                    alts.iter()
                        .map(|alt| matcher(field, alt, handles))
                        .collect()
                })
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
fn matcher(field: Field, arg: &str, handles: &[u64]) -> Result<Matcher> {
    Ok(match field {
        Field::Task => Matcher::Exact(arg.to_string()),
        Field::Kind => match arg {
            "held" | "child" => Matcher::Exact(arg.to_string()),
            _ => anyhow::bail!("a kind is `held` or `child`, got {arg:?}"),
        },
        Field::Armed => match arg {
            "yes" | "no" => Matcher::Exact(arg.to_string()),
            _ => anyhow::bail!("armed is `yes` or `no`, got {arg:?}"),
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

/// Whether one row survives one clause: any alternative matching is
/// a hit, and `--without` keeps the misses.
fn survives(clause: &Clause, row: &FutureRow) -> bool {
    let hit = clause.matchers.iter().any(|matcher| match matcher {
        Matcher::Pattern(p) => field_text(clause.field, row).is_some_and(|t| p.is_match(t)),
        Matcher::Exact(value) => field_text(clause.field, row) == Some(value.as_str()),
        Matcher::Addr(addr) => row.addr == *addr,
        Matcher::Frame(frame) => row.frame == Some(*frame),
        Matcher::Rt(rt) => row.rt == *rt,
        Matcher::Cmp(cmp) => cmp.matches(field_count(clause.field, row)),
    });
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
        Field::Armed => Some(armed_word(row.armed)),
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
        Field::Armed => Some(armed_word(row.armed).to_string()),
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
    tasks::warn_census_uncertain(census.uncertain, "listed")?;
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
            theme,
            out,
        );
    }

    let groups = session.owner_column();
    let selected: Vec<&FutureRow> = survivors.iter().map(|&i| &rows[i]).collect();
    print_future_table(
        &selected,
        groups,
        cmd.limit,
        session.fit_width(theme),
        theme,
        out,
    )?;
    print_warnings(&session.tasks.errors)?;
    Ok(())
}

/// `--group FIELD`: bucket the surviving rows by the field's spelled
/// value and print `COUNT VALUE` rows, most numerous first (ties in
/// value order), each with up to three member addresses. `--limit`
/// cuts buckets.
fn exec_group<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: &FuturesCmd,
    field: Field,
    survivors: &[usize],
    fit: Option<usize>,
    theme: crate::output::Theme,
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

    let heading = field.name().replace('-', " ").to_uppercase();
    let mut table = crate::output::Table::new(3)
        .align_right(0)
        .header(["COUNT".to_string(), heading, "FUTURES".to_string()])
        .truncatable(1)
        .fit(fit)
        .theme(theme);
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
    writeln!(out, "{}", listing_footer(buckets.len(), shown, "group"))?;
    print_warnings(&session.tasks.errors)?;
    Ok(())
}

/// `--exec COMMAND`: run the command once per surviving future, its
/// omitted target filled with that future, each run's output under a
/// `future 0x…` heading — unless the command is `future` itself,
/// whose block opens with that line. One future's failure never stops the loop —
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
    let parsed = repl::parse_exec_command(&cmd.exec).context("--exec")?;
    let headed = !matches!(parsed, crate::Command::Future { addr: None, .. });
    let rows = rows(session);
    let shown = cmd.limit.unwrap_or(survivors.len()).min(survivors.len());
    let mut failed = 0usize;
    // Each run goes under a cursor scoped to its future — the
    // command's omitted target and `$_` are that future's — and the
    // session's own cursor comes back once the loop is done.
    let saved = *session.cursor.borrow();
    for (n, &index) in survivors[..shown].iter().enumerate() {
        let label = format!("future {:#x}", rows[index].addr);
        write!(out, "{}", exec_heading(n, headed.then_some(&label)))?;
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
    writeln!(
        out,
        "[Executed against {}, {failed} failed]",
        summary::counted(shown, "future")
    )?;
    if failed > 0 {
        anyhow::bail!(
            "--exec failed against {failed} of {}",
            summary::counted(shown, "future")
        );
    }
    Ok(())
}

/// The heading `--exec` opens future `n`'s output with: a blank line
/// between one future's output and the next, then the future's
/// address the way `future` spells its own heading — or no address,
/// when the command is `future` and prints that line itself.
fn exec_heading(n: usize, label: Option<&str>) -> String {
    let sep = if n > 0 { "\n" } else { "" };
    match label {
        Some(label) => format!("{sep}{label}\n"),
        None => sep.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Clause, Field, FutureRow, Kind, build_rows, exec_heading, group_value, matcher,
        parse_clauses, survives,
    };

    use crate::trace::FutureAt;

    use crate::runtimes::{OwnerCounts, RowOwner, owner_label};
    use crate::tasks::StopNames;
    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::assess::{ContinuationStatus, IncompleteReason};
    use hansei_runtime::tokio::bundle::{
        FutureInfo, IoSlot, OwnerIndex, OwnerKey, OwnerResolution, RuntimeFlavor, Task, TaskKind,
        TaskList, WaitKind,
    };
    use hansei_runtime::tokio::census::{self, FutureCensus, Via};
    use hansei_runtime::tokio::{TaskAddr, TaskState};

    const GROUPS: [OwnerKey; 2] = [
        OwnerKey::Runtime {
            flavor: RuntimeFlavor::MultiThread,
            handle: 0x10,
        },
        OwnerKey::LocalSet { shared: 0x20 },
    ];

    fn owners() -> OwnerIndex {
        OwnerIndex::from_keys(GROUPS.to_vec(), 1)
    }

    fn task(id: u64, group: usize) -> Task {
        Task {
            addr: TaskAddr(0x1000 + id * 0x100),
            state: TaskState(1 << 6),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind: TaskKind::Async,
            owner: OwnerResolution::Known(GROUPS[group]),
        }
    }

    /// Two tasks in two groups, with ids one of which spells a prefix
    /// of the other — so an exact match and a regex disagree.
    fn list() -> TaskList {
        TaskList::new(vec![task(1, 0), task(12, 1)])
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
            continuation: ContinuationStatus::Primitive,
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
            continuation: ContinuationStatus::Unresumed,
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
        build_rows(
            &list(),
            &owners(),
            census,
            &hansei_bundle::names::ImplFold::default(),
            &StopNames::none(&Default::default()),
        )
    }

    /// The merge arms a find by the slots that sit in it and by the
    /// slot of the primitive its reader names, and only those: a wheel
    /// entry inside a `Sleep` takes the reader's cell while a typed
    /// slot beside it keeps its own; a channel's receiver slot names
    /// the `recv` find whose `Chan` it is; a `Notify` slot on another
    /// `Notify` arms nothing, so that find is `unarmed: `; a set child
    /// awaiting a task is armed by that task's trailer.
    #[test]
    fn test_the_merge_arms_a_find_by_its_own_slots_and_its_readers_primitive() {
        use super::with_slots;
        use hansei_runtime::tokio::attribution::{
            Attributed, AttributedSlot, Attribution, OwnerKind, RegistrySlot, SlotPath, SlotRoot,
            Validity,
        };
        use hansei_runtime::tokio::graph::TaskRef;
        use hansei_runtime::tokio::wakers::Owner;

        let sleep = held(0, 0x5000, None);
        let mut recv = held(0, 0x6000, None);
        recv.waiting_on = Some("mpsc 0x9000 (1 sender, 0 unread)".to_string());
        recv.wait = Some(WaitKind::Channel { addr: 0x9000 });
        let mut notified = held(0, 0x7000, None);
        notified.waiting_on = Some("notify 0x9100 (waiting)".to_string());
        notified.wait = Some(WaitKind::Notify { addr: 0x9100 });
        // Three more finds whose own slots sit in their storage: the
        // reader's cell speaks for a slot of the reader's kind.
        let mut reading = held(0, 0xa000, None);
        reading.waiting_on = Some("io fd 3 (readable)".to_string());
        reading.wait = Some(WaitKind::Io);
        let mut locking = held(0, 0xb000, None);
        locking.waiting_on = Some("the semaphore at 0x9300".to_string());
        locking.wait = Some(WaitKind::Semaphore { owner: None });
        let mut queued = held(0, 0xc000, None);
        queued.waiting_on = Some("notify 0x9400 (waiting)".to_string());
        queued.wait = Some(WaitKind::Notify { addr: 0x9400 });
        // A JoinHandle awaited in the task's own frame: the trailer of
        // the task it awaits is the task's slot, not the find's.
        let mut joining = held(0, 0xd000, None);
        joining.waiting_on = Some("task 29".to_string());
        joining.wait = Some(WaitKind::Task { addr: 0x1d00 });
        let mut joiner = child(0x2010, Some("app::child"));
        joiner.waiting_on = Some("task 28".to_string());
        let census = census(
            vec![sleep, recv, notified, reading, locking, queued, joining],
            vec![set(0, vec![joiner])],
        );

        let owner = Owner::Task {
            header: 0x1100,
            index: 0,
        };
        let frame = SlotPath {
            root: SlotRoot::Frame { task: 0, frame: 1 },
            steps: Vec::new(),
            hop: None,
        };
        let in_sleep = SlotRoot::Find {
            index: 0,
            addr: 0x5000,
        };
        let slot = |at: u64, attribution: Attribution, within: Option<SlotRoot>| AttributedSlot {
            hit: at as usize,
            slot: at,
            owner,
            attribution,
            within,
        };
        let slots = Attributed::from_slots(vec![
            // The Sleep's wheel entry, inside the Sleep.
            slot(
                0x5010,
                Attribution::Registry(RegistrySlot::Timer {
                    entry: 0x5010,
                    state: None,
                    deadline: None,
                }),
                Some(in_sleep),
            ),
            // A typed slot inside the Sleep too: no reader speaks for it.
            slot(
                0x5020,
                Attribution::Typed {
                    holder: "x::Holder".to_string(),
                    member: "w".to_string(),
                    path: SlotPath {
                        root: in_sleep,
                        steps: vec!["w".to_string()],
                        hop: None,
                    },
                    validity: Validity::Raw,
                },
                None,
            ),
            // The channel's receiver slot, reached from the frame.
            slot(
                0x9080,
                Attribution::Owner {
                    kind: OwnerKind::Mpsc,
                    primitive: 0x9000,
                    holder: "Chan".to_string(),
                    member: "rx_waker".to_string(),
                    path: frame.clone(),
                    validity: Validity::SelfDescribing,
                    reading: None,
                },
                None,
            ),
            // A node on some other Notify.
            slot(
                0x9280,
                Attribution::Owner {
                    kind: OwnerKind::Notify,
                    primitive: 0x9200,
                    holder: "Notified".to_string(),
                    member: "waiter".to_string(),
                    path: frame,
                    validity: Validity::SelfDescribing,
                    reading: None,
                },
                None,
            ),
            // The trailers of the awaited task and of some other one.
            slot(
                0x1d50,
                Attribution::Registry(RegistrySlot::Join {
                    task: TaskRef {
                        addr: TaskAddr(0x1d00),
                        task_id: Some(29),
                    },
                }),
                None,
            ),
            slot(
                0x1e50,
                Attribution::Registry(RegistrySlot::Join {
                    task: TaskRef {
                        addr: TaskAddr(0x1e00),
                        task_id: Some(30),
                    },
                }),
                None,
            ),
            // An io waiter node inside the readiness future.
            slot(
                0xa010,
                Attribution::Registry(RegistrySlot::Io {
                    resource: 0x9500,
                    slot: IoSlot::Listed { interest: None },
                    ready: None,
                }),
                Some(SlotRoot::Find {
                    index: 3,
                    addr: 0xa000,
                }),
            ),
            // A queue node inside the acquire.
            slot(
                0xb010,
                Attribution::Registry(RegistrySlot::Semaphore {
                    semaphore: 0x9300,
                    node: 0xb010,
                }),
                Some(SlotRoot::Find {
                    index: 4,
                    addr: 0xb000,
                }),
            ),
            // A Notified node inside the queued find — on a Notify other
            // than the one its reader read, so the kind alone speaks.
            slot(
                0xc010,
                Attribution::Owner {
                    kind: OwnerKind::Notify,
                    primitive: 0x9500,
                    holder: "Notified".to_string(),
                    member: "waiter".to_string(),
                    path: SlotPath {
                        root: SlotRoot::Find {
                            index: 5,
                            addr: 0xc000,
                        },
                        steps: vec!["waiter".to_string()],
                        hop: None,
                    },
                    validity: Validity::SelfDescribing,
                    reading: None,
                },
                None,
            ),
        ]);
        let child_slots = Attributed::from_slots(vec![AttributedSlot {
            hit: 9,
            slot: 0x1c50,
            owner: Owner::Child { set: 0, child: 0 },
            attribution: Attribution::Registry(RegistrySlot::Join {
                task: TaskRef {
                    addr: TaskAddr(0x1c00),
                    task_id: Some(28),
                },
            }),
            within: None,
        }]);

        let rows = with_slots(rows_of(&census), &list(), &census, &slots, None);
        let row = |addr: u64| rows.iter().find(|r| r.addr == addr).unwrap();
        assert!(row(0x5000).armed);
        assert_eq!(
            row(0x5000).waiting_on.as_deref(),
            Some("a timer, slot 0x5020 in x::Holder")
        );
        assert_eq!(
            row(0x5000).waiting_kind.as_deref(),
            Some("slot in x::Holder, timer")
        );
        assert_eq!(
            row(0x5000).slot_lines,
            [
                "slot 0x5020: waker in x::Holder.w, in the future at 0x5000 w",
                "timer 0x5010"
            ]
        );
        assert!(row(0x6000).armed);
        assert_eq!(
            row(0x6000).waiting_on.as_deref(),
            Some("mpsc 0x9000 (1 sender, 0 unread)")
        );
        assert_eq!(row(0x6000).waiting_kind.as_deref(), Some("mpsc"));
        assert!(!row(0x7000).armed);
        assert_eq!(
            row(0x7000).waiting_on.as_deref(),
            Some("unarmed: notify 0x9100 (waiting)")
        );
        assert_eq!(row(0x7000).waiting_kind.as_deref(), Some("unarmed: notify"));
        assert!(row(0x7000).slot_lines.is_empty());
        for (addr, cell) in [
            (0xa000, "io fd 3 (readable)"),
            (0xb000, "the semaphore at 0x9300"),
            (0xc000, "notify 0x9400 (waiting)"),
            (0xd000, "task 29"),
        ] {
            assert!(row(addr).armed, "{addr:#x}");
            assert_eq!(row(addr).waiting_on.as_deref(), Some(cell), "{addr:#x}");
        }
        // The armed field reads the same answer.
        assert!(survives(&clause("armed", "yes", false), row(0xa000)));
        assert!(!survives(&clause("armed", "yes", false), row(0x7000)));
        assert!(survives(&clause("armed", "no", false), row(0x7000)));
        assert!(matcher(Field::Armed, "maybe", &[]).is_err());

        let rows = with_slots(rows_of(&census), &list(), &census, &child_slots, None);
        let joiner = rows.iter().find(|r| r.addr == 0x2010).unwrap();
        assert!(joiner.armed);
        assert_eq!(joiner.waiting_on.as_deref(), Some("task 28"));
        assert_eq!(joiner.slot_lines, ["join task 28: waker in its trailer"]);
    }

    /// A find whose chain ends in no described resource says what cut
    /// its chain short, in the cell and in its bucket alike, the way a
    /// task row does.
    #[test]
    fn test_a_cut_chain_buckets_by_how_it_was_cut() {
        let mut cut = held(0, 0x3000, None);
        cut.waiting_on = None;
        cut.wait = None;
        cut.continuation = ContinuationStatus::Incomplete {
            reason: IncompleteReason::UnknownDyn,
            detail: None,
        };
        let rows = rows_of(&census(vec![cut], vec![]));
        assert_eq!(
            rows[0].waiting_on.as_deref(),
            Some("unknown (dyn future not in the tokio info)")
        );
        assert_eq!(rows[0].waiting_kind, rows[0].waiting_on);
    }

    /// The owner counts are exact per group and count the unowned
    /// apart: a task no group owns, a task whose owners conflict, and
    /// every find of either, land in the apart counts, never in a
    /// group's and never nowhere.
    #[test]
    fn test_owner_counts_are_exact_and_count_the_unowned_apart() {
        let mut unknown = task(3, 0);
        unknown.owner = OwnerResolution::Unknown;
        let mut conflict = task(4, 0);
        conflict.owner = OwnerResolution::Conflict(GROUPS.to_vec());
        let list = TaskList::new(vec![
            task(1, 0),
            task(12, 1),
            unknown.clone(),
            conflict.clone(),
        ]);
        // Task 1 (group 0) holds one future and a set of two live
        // children; task 12 (group 1) holds one; the unknown task
        // holds one; the conflicted task holds a set of one child.
        let census = census(
            vec![
                held(0, 0x3000, None),
                held(1, 0x3100, None),
                held(2, 0x3200, None),
            ],
            vec![
                set(
                    0,
                    vec![
                        child(0x4000, Some("app::child")),
                        child(0x4100, Some("app::child")),
                        child(0x4200, None),
                    ],
                ),
                set(3, vec![child(0x4300, Some("app::child"))]),
            ],
        );
        let counts = OwnerCounts::count(&list, &census, &owners());
        assert_eq!(counts.tasks, [1, 1]);
        assert_eq!(counts.futures, [1 + 1 + 2, 1 + 1]);
        assert_eq!(
            (
                counts.unknown_tasks,
                counts.conflict_tasks,
                counts.unowned_futures
            ),
            (1, 1, 2 + 1 + 1)
        );

        // The owner cell and its detail line for each kind of owner.
        let tags = vec![
            "runtime 0 @ 0x10 (multi_thread)".to_string(),
            "local set 0 @ 0x20".to_string(),
        ];
        let owned = &list.tasks[0];
        assert_eq!(RowOwner::of(owned, &owners()), RowOwner::Group(0));
        assert_eq!(
            RowOwner::detail(owned, &owners(), &tags).as_deref(),
            Some("runtime 0 @ 0x10 (multi_thread)")
        );
        assert_eq!(RowOwner::detail(owned, &owners(), &[]), None);
        assert_eq!(RowOwner::of(&unknown, &owners()), RowOwner::Unknown);
        assert_eq!(
            RowOwner::detail(&unknown, &owners(), &tags).as_deref(),
            Some("unknown (no list, queue or cell scheduler established one)")
        );
        assert_eq!(RowOwner::of(&conflict, &owners()), RowOwner::Conflict);
        assert_eq!(
            RowOwner::detail(&conflict, &owners(), &[]).as_deref(),
            Some("conflict (runtime 0 @ 0x10; local set 0 @ 0x20)")
        );
        // A known owner the index does not number spells the key.
        let mut stranger = task(5, 0);
        stranger.owner = OwnerResolution::Known(OwnerKey::LocalSet { shared: 0x30 });
        assert_eq!(RowOwner::of(&stranger, &owners()), RowOwner::Unknown);
        assert_eq!(
            RowOwner::detail(&stranger, &owners(), &tags).as_deref(),
            Some("unknown (the local set at 0x30 is not a group of this session)")
        );
        assert_eq!(
            owner_label(OwnerKey::LocalSet { shared: 0x30 }, &owners()),
            "the local set at 0x30"
        );
        assert_eq!(
            RowOwner::Unknown.to_string() + " " + &RowOwner::Conflict.to_string(),
            "unknown conflict"
        );
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
        assert_eq!(direct.rt, RowOwner::Group(0));

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
        assert_eq!((other.task.as_str(), other.rt), ("12", RowOwner::Group(1)));
    }

    fn clause(field: &str, arg: &str, negate: bool) -> Clause {
        let field = Field::parse(field).expect("a named field");
        Clause {
            field,
            matchers: vec![matcher(field, arg, &[]).expect("a valid argument")],
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

    /// A clause argument lists alternatives, exact fields included:
    /// `addr 0x3000,0x4000` keeps either address, and `--without`
    /// drops both.
    #[test]
    fn test_alternatives_or_within_a_clause() {
        let census = census(
            vec![held(0, 0x3000, None), held(1, 0x5000, None)],
            vec![set(0, vec![child(0x4000, Some("app::child"))])],
        );
        let rows = rows_of(&census);
        let addrs = |with: &[&str], without: &[&str]| -> Vec<u64> {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            let without: Vec<String> = without.iter().map(|s| s.to_string()).collect();
            let clauses = parse_clauses(&with, &without, &[]).expect("the clauses parse");
            rows.iter()
                .filter(|r| clauses.iter().all(|c| survives(c, r)))
                .map(|r| r.addr)
                .collect()
        };
        assert_eq!(addrs(&["addr", "0x3000,0x4000"], &[]), [0x3000, 0x4000]);
        assert_eq!(addrs(&[], &["addr", "0x3000,0x4000"]), [0x5000]);
        assert_eq!(
            addrs(&["kind", "held,child"], &[]),
            [0x3000, 0x4000, 0x5000]
        );
        assert_eq!(
            addrs(&["kind", "held,child"], &["addr", "0x5000"]),
            [0x3000, 0x4000]
        );
        let err = parse_clauses(&["kind".into(), "held,set".into()], &[], &[]).unwrap_err();
        assert!(format!("{err:#}").contains("--with kind"), "{err:#}");
    }

    /// Only the first heading goes without a blank line above it —
    /// and a command that prints its own heading gets the blank line
    /// alone.
    #[test]
    fn test_exec_headings_are_separated_after_the_first() {
        assert_eq!(exec_heading(0, Some("future 0x4000")), "future 0x4000\n");
        assert_eq!(exec_heading(1, Some("future 0x4000")), "\nfuture 0x4000\n");
        assert_eq!(exec_heading(0, None), "");
        assert_eq!(exec_heading(1, None), "\n");
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

    /// A fit cuts the two type-name columns — the wait and the future —
    /// and nothing else: the cells beside them print whole however
    /// narrow the terminal.
    #[test]
    fn test_a_fit_cuts_the_wait_and_the_future_and_nothing_else() {
        let mut long = held(0, 0x5000, None);
        long.future =
            "app::a::very::long::module::path::to::the::work::{async_fn_env#0}".to_string();
        long.waiting_on = Some("mpsc 0x9000 (1 sender, 0 unread, cap 1024)".to_string());
        let rows = rows_of(&census(vec![long], vec![]));
        let rows: Vec<&FutureRow> = rows.iter().collect();
        let mut out = Vec::new();
        super::print_future_table(
            &rows,
            false,
            None,
            Some(90),
            crate::output::Theme::plain(),
            &mut out,
        )
        .expect("table prints");
        let out = String::from_utf8(out).expect("utf8");
        assert_eq!(
            out.lines().nth(1),
            Some(
                "0x5000  1     frame 1, `arm`  Suspend1 — src/app.rs:9  mpsc 0x9000 …  no     async fn app…"
            ),
            "{out}"
        );
    }
}

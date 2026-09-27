// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `sync` command: the resource-centric view of every relation
//! hansei knows — `graph` turned inside out. One block per contended
//! semaphore (the primitive backing tokio's Mutex, RwLock and
//! Semaphore), per joined task (a task as the resource a `JoinHandle`
//! names), per driven task set, and per channel a parked waker names
//! — a oneshot, an mpsc, a watch — with the owner on each side; an
//! address no primitive owns falls through to the tasks whose frames
//! hold it by value.

use crate::relations::Relations;
use crate::summary::counted;
use crate::tasks::{future_name, task_label};
use crate::typenames::TypeNames;
use crate::{Session, print_warnings};

use anyhow::{Result, bail};
use hansei_bundle::{BundleTypeId, names};
use hansei_runtime::tokio::assess::PollingBarrier;
use hansei_runtime::tokio::attribution::{Attributed, Attribution, OwnerKind, Reading};
use hansei_runtime::tokio::bundle::{QueuedWaker, SemaphoreWaiter, WaitTarget};
use hansei_runtime::tokio::graph::{Analysis, BarrierRelation, TaskRef};
use hansei_runtime::tokio::wakers::Owner;
use hansei_runtime::tokio::{Lifecycle, bundle, census};

use std::collections::BTreeMap;
use std::io;

/// The block kinds `--kind` narrows to.
#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Kind {
    /// Contended semaphores: permits, holders, blocked tasks, the
    /// wake queue.
    Semaphore,
    /// Tasks as join resources: waited on, their handles held, or
    /// members of a set.
    Join,
    /// `JoinSet`s and `FuturesUnordered`s: the driver and the members.
    Set,
    /// The by-value fallback: tasks whose frames hold an address.
    Address,
    /// oneshot channels a parked waker names: the state, and the
    /// owner on each side.
    Oneshot,
    /// mpsc channels a parked receiver names: the words a `recv`
    /// prints, the receiver, and the senders blocked on capacity.
    Mpsc,
    /// watch channels a parked receiver names: the version, the
    /// handle counts, and the receivers waiting for a change.
    Watch,
    /// `Notify`s a queued waiter names: the state word and the tasks
    /// parked on it.
    Notify,
}

/// The channel kinds, in the order their blocks print — what
/// `channels` asks for.
pub const CHANNELS: [Kind; 3] = [Kind::Oneshot, Kind::Mpsc, Kind::Watch];

/// Every family whose blocks are built from the waker slots, in the
/// order their blocks print: the channels, then the `Notify`s.
const SLOT_FAMILIES: [Kind; 4] = [Kind::Oneshot, Kind::Mpsc, Kind::Watch, Kind::Notify];

/// Whether a listing narrowed to `kinds` prints the `kind` family: an
/// empty list is every family.
fn wants(kinds: &[Kind], kind: Kind) -> bool {
    kinds.is_empty() || kinds.contains(&kind)
}

/// Everything the printers read, taken apart from the session so the
/// tests can lay out a population no fixture holds.
struct View<'a> {
    list: &'a bundle::TaskList,
    analysis: &'a Analysis,
    relations: &'a Relations,
    sets: &'a [census::FutureSet],
    join_sets: &'a [census::JoinSet],
    names: &'a TypeNames<'a>,
    /// The attributed waker slots, which name the channels.
    slots: &'a Attributed,
    /// A type's size, for the extent of a channel reached through a
    /// hop — the range a sender blocked on its semaphore falls in.
    size_of: &'a dyn Fn(BundleTypeId) -> Option<u64>,
}

pub(crate) fn exec_sync<T: proc::Target>(
    session: &Session<'_, T>,
    addr: Option<u64>,
    kinds: Vec<Kind>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let analysis = session.analysis();
    print_warnings(&analysis.errors)?;
    let relations = session.relations();
    let census = session.census();
    let bundle_view = session.ctx.view;
    let size_of = |ty: BundleTypeId| bundle_view.ty(ty).map(|t| t.size());
    let names = TypeNames::of(session);
    let view = View {
        list: &session.tasks,
        analysis,
        relations,
        sets: &census.sets,
        join_sets: &census.join_sets,
        names: &names,
        slots: session.attribution(),
        size_of: &size_of,
    };
    if kinds.contains(&Kind::Address) && kinds.len() > 1 {
        bail!("--kind address is a reading of one address, not a block family to combine");
    }
    if let Some(addr) = addr {
        let task_at = |addr: u64| session.extents().locate(addr).map(|(index, _)| index);
        let references = |addr: u64| collect_references(session, view.names.impls(), addr);
        return print_addressed(&view, addr, &kinds, &task_at, &references, out);
    }
    if kinds.contains(&Kind::Address) {
        bail!("--kind address narrows an address lookup; `sync 0x…` names one");
    }
    // The omitted-target rule: a task cursor scopes the listing to the
    // relations that task is party to; without one, everything.
    if let Some(index) = crate::cursor::cursor_task(session) {
        return print_task_scoped(&view, index, &kinds, out);
    }
    print_listing(&view, &kinds, out)
}

/// The bare listing: every contended resource, one block each —
/// semaphores in address order, then joined tasks in task order, then
/// nonempty sets in address order, then each channel family in
/// address order.
fn print_listing(view: &View<'_>, kinds: &[Kind], out: &mut dyn io::Write) -> Result<()> {
    let mut printed = 0usize;
    let mut sep = |out: &mut dyn io::Write| -> Result<()> {
        if printed > 0 {
            writeln!(out)?;
        }
        printed += 1;
        Ok(())
    };
    if wants(kinds, Kind::Semaphore) {
        for block in blocks(view.analysis).values() {
            sep(out)?;
            print_semaphore(block, view.names, out)?;
        }
    }
    if wants(kinds, Kind::Join) {
        for index in 0..view.list.tasks.len() {
            if view.relations.joined(index) {
                sep(out)?;
                print_join(view, index, out)?;
            }
        }
    }
    if wants(kinds, Kind::Set) {
        for &(addr, _, _) in &set_index(view) {
            sep(out)?;
            print_set(view, addr, out)?;
        }
    }
    for kind in SLOT_FAMILIES {
        if wants(kinds, kind) {
            for block in channel_blocks(view, kind).values() {
                sep(out)?;
                print_channel(block, out)?;
            }
        }
    }
    Ok(())
}

/// One address, resolved against everything `sync` lists — the
/// semaphores, the sets, the channels, the tasks themselves — and,
/// when no primitive owns it, against the frames that hold it by
/// value. `--kind` skips the resolution order and asks for one reading.
fn print_addressed(
    view: &View<'_>,
    addr: u64,
    kinds: &[Kind],
    task_at: &dyn Fn(u64) -> Option<usize>,
    references: &dyn Fn(u64) -> Vec<String>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let semaphores = blocks(view.analysis);
    let semaphore = semaphores.get(&addr);
    let set = set_index(view).iter().any(|&(a, ..)| a == addr);
    let task = task_at(addr);
    let channel = |kind: Kind| channel_blocks(view, kind).remove(&addr);
    match kinds {
        [Kind::Semaphore] => match semaphore {
            Some(block) => print_semaphore(block, view.names, out),
            None => bail!(
                "no decoded semaphore at {addr:#x}; `sync` lists the ones \
                 the tasks' await chains reach"
            ),
        },
        [Kind::Join] => match task {
            Some(index) => print_join(view, index, out),
            None => bail!("{addr:#x} is in no task's allocation"),
        },
        [Kind::Set] => match set {
            true => print_set(view, addr, out),
            false => bail!("no decoded JoinSet or FuturesUnordered at {addr:#x}"),
        },
        [Kind::Address] => print_references(addr, &references(addr), out),
        [] => {
            if let Some(block) = semaphore {
                return print_semaphore(block, view.names, out);
            }
            if set {
                return print_set(view, addr, out);
            }
            if let Some(block) = SLOT_FAMILIES.into_iter().find_map(channel) {
                return print_channel(&block, out);
            }
            if let Some(index) = task {
                return print_join(view, index, out);
            }
            print_references(addr, &references(addr), out)
        }
        // A slot-named family, or several: the one block at the
        // address among them, else the refusal naming what was asked.
        kinds => {
            let family: Vec<Kind> = SLOT_FAMILIES
                .into_iter()
                .filter(|k| kinds.contains(k))
                .collect();
            if family.len() != kinds.len() {
                bail!(
                    "--kind combines only the families a waker slot names \
                     (oneshot, mpsc, watch, notify)"
                );
            }
            match family.into_iter().find_map(channel) {
                Some(block) => print_channel(&block, out),
                None => bail!(
                    "no {} at {addr:#x} holds a parked waker; `sync --kind {}` lists the \
                     ones a slot names",
                    channel_words_of(kinds),
                    kinds.iter().map(|k| k.word()).collect::<Vec<_>>().join(",")
                ),
            }
        }
    }
}

/// `oneshot`, `oneshot or mpsc`, `oneshot, mpsc or watch`.
fn channel_words_of(kinds: &[Kind]) -> String {
    let words: Vec<&str> = kinds.iter().map(|k| k.word()).collect();
    match words.split_last() {
        Some((last, [])) => last.to_string(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    }
}

impl Kind {
    /// The word the block headings and the cells use for the family.
    fn word(self) -> &'static str {
        match self {
            Kind::Semaphore => "semaphore",
            Kind::Join => "join",
            Kind::Set => "set",
            Kind::Address => "address",
            Kind::Oneshot => "oneshot",
            Kind::Mpsc => "mpsc",
            Kind::Watch => "watch",
            Kind::Notify => "notify",
        }
    }
}

/// The cursor's task: every relation it is party to — the semaphores
/// it is blocked on or holds, its own join block, the join blocks of
/// the tasks it awaits, the sets it drives, and the channels it parks
/// in on either side.
fn print_task_scoped(
    view: &View<'_>,
    index: usize,
    kinds: &[Kind],
    out: &mut dyn io::Write,
) -> Result<()> {
    let addr = view.list.tasks[index].addr.0;
    let mut printed = 0usize;
    let mut sep = |out: &mut dyn io::Write| -> Result<()> {
        if printed > 0 {
            writeln!(out)?;
        }
        printed += 1;
        Ok(())
    };
    if wants(kinds, Kind::Semaphore) {
        for block in blocks(view.analysis).values() {
            let blocked = block.blocked.iter().any(|(t, _)| t.addr.0 == addr);
            let holds = block.locks.iter().any(|fl| fl.holder.addr.0 == addr);
            if blocked || holds {
                sep(out)?;
                print_semaphore(block, view.names, out)?;
            }
        }
    }
    if wants(kinds, Kind::Join) {
        // The tasks it awaits: a semaphore holder is a Waiting edge
        // too, but its relation is the semaphore block above, not a
        // join, so only the edges the join index reverses count — and
        // the task's own block prints only when something joins *it*.
        let awaits = view.relations.edges[index]
            .iter()
            .filter(|e| e.kind == crate::relations::EdgeKind::Waiting)
            .map(|e| e.to)
            .filter(|&to| view.relations.waited_by[to].contains(&index));
        let mut joins: Vec<usize> = [index]
            .into_iter()
            .filter(|&i| view.relations.joined(i))
            .chain(awaits)
            .collect();
        joins.sort_unstable();
        joins.dedup();
        for join in joins {
            sep(out)?;
            print_join(view, join, out)?;
        }
    }
    if wants(kinds, Kind::Set) {
        for &(set_addr, owner, _) in &set_index(view) {
            let member = view.relations.member_of[index].is_some_and(|(a, _)| a == set_addr);
            if owner == index || member {
                sep(out)?;
                print_set(view, set_addr, out)?;
            }
        }
    }
    for kind in SLOT_FAMILIES {
        if wants(kinds, kind) {
            for block in channel_blocks(view, kind).values() {
                if block.parties.iter().any(|(_, party)| *party == index) {
                    sep(out)?;
                    print_channel(block, out)?;
                }
            }
        }
    }
    if printed == 0 {
        writeln!(
            out,
            "{} is party to no decoded relation: nothing waits to join \
             it, and it blocks on no semaphore, drives no set and parks \
             in no channel",
            task_label(view.list, index)
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel blocks: a oneshot, an mpsc or a watch as a resource.
// ---------------------------------------------------------------------------

/// One channel — or one `Notify`, which has a waiting side only —
/// assembled from the slots that name it: the primitive the cells
/// print, its own words, and who is parked on each side.
struct ChannelBlock {
    kind: Kind,
    addr: u64,
    /// The primitive's words, from the first slot that read them; a
    /// core does not change while it is read, so every slot's agree.
    reading: Option<Reading>,
    /// Who holds a waker on the receiving side, in slot order, named
    /// as the listings name owners.
    rx: Vec<String>,
    /// Who holds a waker on the sending side: a oneshot sender polling
    /// `poll_closed`.
    tx: Vec<String>,
    /// The tasks blocked on the channel's semaphore for capacity —
    /// their verified semaphore waits fall in the channel's bytes.
    tx_blocked: Vec<TaskRef>,
    /// The tasks party to the block, for the cursor-scoped listing:
    /// each side's owning task, and every blocked sender.
    parties: Vec<(Side, usize)>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Side {
    Rx,
    Tx,
}

/// The owner kinds whose slots name a channel of `kind`, with the
/// side each is parked on.
fn sides_of(kind: Kind) -> &'static [(OwnerKind, Side)] {
    match kind {
        Kind::Oneshot => &[
            (OwnerKind::OneshotRx, Side::Rx),
            (OwnerKind::OneshotTx, Side::Tx),
        ],
        Kind::Mpsc => &[(OwnerKind::Mpsc, Side::Rx)],
        Kind::Watch => &[(OwnerKind::Watch, Side::Rx)],
        Kind::Notify => &[(OwnerKind::Notify, Side::Rx)],
        Kind::Semaphore | Kind::Join | Kind::Set | Kind::Address => &[],
    }
}

/// The owner of a slot as a block names it: the task, or the set child
/// with the set and the task polling it.
fn owner_name(view: &View<'_>, owner: Owner) -> (String, usize) {
    match owner {
        Owner::Task { index, .. } => (task_label(view.list, index), index),
        Owner::Child { set, child } => {
            let polled_by = view.sets[set].owner;
            (
                format!(
                    "child {child} of the set at {:#x} (polled by {})",
                    view.sets[set].addr,
                    task_label(view.list, polled_by)
                ),
                polled_by,
            )
        }
    }
}

/// Every channel of `kind` a slot names, by the primitive's address.
fn channel_blocks(view: &View<'_>, kind: Kind) -> BTreeMap<u64, ChannelBlock> {
    let mut blocks: BTreeMap<u64, ChannelBlock> = BTreeMap::new();
    for slot in &view.slots.slots {
        let Attribution::Owner {
            kind: owner_kind,
            primitive,
            reading,
            path,
            ..
        } = &slot.attribution
        else {
            continue;
        };
        let Some(&(_, side)) = sides_of(kind).iter().find(|(k, _)| k == owner_kind) else {
            continue;
        };
        let block = blocks.entry(*primitive).or_insert_with(|| ChannelBlock {
            kind,
            addr: *primitive,
            reading: None,
            rx: Vec::new(),
            tx: Vec::new(),
            tx_blocked: Vec::new(),
            parties: Vec::new(),
        });
        if block.reading.is_none() {
            block.reading = reading.clone();
        }
        let (name, party) = owner_name(view, slot.owner);
        let names = match side {
            Side::Rx => &mut block.rx,
            Side::Tx => &mut block.tx,
        };
        if !names.contains(&name) {
            names.push(name);
        }
        if !block.parties.contains(&(side, party)) {
            block.parties.push((side, party));
        }
        // A bounded channel's senders block on its semaphore, which
        // sits in the `Chan` behind the receiver's `Arc`: the hop that
        // reached the slot names the `ArcInner` and its type, so the
        // channel's extent is known and a semaphore wait inside it is
        // a sender waiting for capacity.
        if kind == Kind::Mpsc
            && let Some(hop) = &path.hop
            && let Some(size) = (view.size_of)(hop.pointee_ty)
        {
            for wait in &view.analysis.waits {
                let Some(WaitTarget::Semaphore { addr, .. }) = wait.verified().map(|w| w.target())
                else {
                    continue;
                };
                let within = *addr >= hop.addr && *addr - hop.addr < size;
                if within && !block.tx_blocked.iter().any(|t| t.addr == wait.task.addr) {
                    block.tx_blocked.push(wait.task);
                    if let Some(index) = view
                        .list
                        .tasks
                        .iter()
                        .position(|t| t.addr == wait.task.addr)
                    {
                        block.parties.push((Side::Tx, index));
                    }
                }
            }
        }
    }
    blocks
}

/// One channel's block: the kind word and address the cells print, the
/// primitive's own words, then who is parked on each side.
fn print_channel(block: &ChannelBlock, out: &mut dyn io::Write) -> Result<()> {
    // The reading's own variant picks its words; the owner kind only
    // decides which side a oneshot is read from, and a block reads it
    // from the receiver's.
    let words = match &block.reading {
        Some(reading) => reading.words(OwnerKind::OneshotRx),
        None => "state not read".to_string(),
    };
    writeln!(out, "{} {:#x}: {words}", block.kind.word(), block.addr)?;
    if !block.rx.is_empty() {
        writeln!(out, "    rx: {}", block.rx.join(", "))?;
    }
    if !block.tx.is_empty() {
        writeln!(out, "    tx: {}", block.tx.join(", "))?;
    }
    if !block.tx_blocked.is_empty() {
        let blocked: Vec<String> = block.tx_blocked.iter().map(|t| t.to_string()).collect();
        writeln!(out, "    tx blocked on capacity: {}", blocked.join(", "))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Join blocks: a task as a resource.
// ---------------------------------------------------------------------------

/// One task as the resource a `JoinHandle` names: who waits to join
/// it, who holds its handle without awaiting, and the set that will
/// collect it.
fn print_join(view: &View<'_>, index: usize, out: &mut dyn io::Write) -> Result<()> {
    let task = &view.list.tasks[index];
    let state = match task.state.is_cancelled() {
        true => format!("{} (cancelled)", task.state.lifecycle()),
        false => task.state.lifecycle().to_string(),
    };
    writeln!(
        out,
        "{} ({}): {state}",
        task_label(view.list, index),
        future_name(&task.future, view.names)
    )?;
    let named = |tasks: &[usize]| {
        tasks
            .iter()
            .map(|&i| task_label(view.list, i))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let waited = &view.relations.waited_by[index];
    if !waited.is_empty() {
        writeln!(out, "    Waited by: {}", named(waited))?;
    }
    let held = &view.relations.held_by[index];
    if !held.is_empty() {
        writeln!(out, "    Handle held by: {}, unawaited", named(held))?;
    }
    if let Some((set_addr, owner)) = view.relations.member_of[index] {
        writeln!(
            out,
            "    Member of: {}, driven by {}",
            set_name(view, set_addr),
            task_label(view.list, owner)
        )?;
    }
    if waited.is_empty() && held.is_empty() && view.relations.member_of[index].is_none() {
        writeln!(
            out,
            "    No task waits to join it, holds its handle, or drives \
             it in a set"
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Set blocks: a JoinSet or FuturesUnordered as a resource.
// ---------------------------------------------------------------------------

/// Every set the census found, `(address, owner index, is_join_set)`,
/// in address order, empties left out — a set with no members contends
/// with nothing.
fn set_index(view: &View<'_>) -> Vec<(u64, usize, bool)> {
    let mut sets: Vec<(u64, usize, bool)> = view
        .sets
        .iter()
        .filter(|s| !s.children.is_empty())
        .map(|s| (s.addr, s.owner, false))
        .chain(
            view.join_sets
                .iter()
                .filter(|s| !s.children.is_empty())
                .map(|s| (s.addr, s.owner, true)),
        )
        .collect();
    sets.sort_unstable();
    sets
}

/// The heading spelling of the set at `addr`, folded like every other
/// type the listings print.
fn set_name(view: &View<'_>, addr: u64) -> String {
    let ty = view
        .join_sets
        .iter()
        .find(|s| s.addr == addr)
        .map(|s| &s.ty)
        .or_else(|| view.sets.iter().find(|s| s.addr == addr).map(|s| &s.ty));
    match ty {
        Some(ty) => format!("a {} (set {addr:#x})", view.names.folded(*ty)),
        None => format!("the set at {addr:#x}"),
    }
}

/// `counted` pluralizes with an `s`; a set's futures are children.
fn children(n: usize) -> String {
    match n {
        1 => "1 child".to_string(),
        n => format!("{n} children"),
    }
}

/// One set's block: who drives it and what it holds, members grouped
/// by state — a `JoinSet`'s members are listed tasks, a
/// `FuturesUnordered`'s are resident futures only its own nodes hold.
fn print_set(view: &View<'_>, addr: u64, out: &mut dyn io::Write) -> Result<()> {
    if let Some(set) = view.join_sets.iter().find(|s| s.addr == addr) {
        writeln!(
            out,
            "{}: {}, driven by {} (`{}`)",
            set_name(view, addr),
            counted(set.children.len(), "member"),
            task_label(view.list, set.owner),
            set.local,
        )?;
        // Members grouped by state, listed tasks by their ids; a
        // complete member has left the owned list and only the set's
        // entry keeps it alive, which is worth its own words.
        let mut by_state: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for child in &set.children {
            let who = match child.id {
                Some(id) => format!("task {id}"),
                None => format!("the task at {:#x}", child.task),
            };
            let state = match child.state.lifecycle() {
                Lifecycle::Complete => "complete, awaiting join".to_string(),
                state if !child.listed => format!("{state}, unlisted"),
                state => state.to_string(),
            };
            by_state.entry(state).or_default().push(who);
        }
        for (state, members) in by_state {
            writeln!(out, "    Members ({state}): {}", members.join(", "))?;
        }
        return Ok(());
    }
    let Some(set) = view.sets.iter().find(|s| s.addr == addr) else {
        bail!("no decoded JoinSet or FuturesUnordered at {addr:#x}");
    };
    writeln!(
        out,
        "{}: {}, driven by {} (`{}`)",
        set_name(view, addr),
        children(set.children.len()),
        task_label(view.list, set.owner),
        set.local,
    )?;
    let in_flight = set.children.iter().filter(|c| c.future.is_some()).count();
    let completed = set.children.len() - in_flight;
    if in_flight > 0 {
        writeln!(out, "    In flight: {in_flight}")?;
    }
    if completed > 0 {
        writeln!(out, "    Completed, not yet reaped: {completed}")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The address fallback: referenced by value.
// ---------------------------------------------------------------------------

/// The tasks whose await-chain frames hold `addr` by value — the
/// census's answer turned around: `whatis` names the task an address
/// is *in*, this names the tasks that *point at* it. The frames are
/// the ones the analysis already walks; nothing is swept.
fn collect_references<T: proc::Target>(
    session: &Session<'_, T>,
    impls: &names::ImplFold,
    addr: u64,
) -> Vec<String> {
    let mut lines = Vec::new();
    // An unmapped word is no address at all: scanning frames for it
    // would report every integer that happens to share its value
    // (`sync 0x1` matching a discriminant), so the fallback answers
    // only for addresses the target actually maps.
    if !session.ctx.is_mapped(addr) {
        return lines;
    }
    for (index, task) in session.tasks.tasks.iter().enumerate() {
        if !matches!(task.future, bundle::FutureInfo::Known(_)) {
            continue;
        }
        let Some(chain) = session.task_chain(task) else {
            continue;
        };
        for (n, frame) in chain.frames.iter().enumerate() {
            let value = match &frame.state {
                Some(state) => state.payload,
                None => frame.future,
            };
            let Some(offset) = value
                .bytes
                .as_chunks::<8>()
                .0
                .iter()
                .position(|w| u64::from_le_bytes(*w) == addr)
                .map(|i| i as u64 * 8)
            else {
                continue;
            };
            // The member covering the hit, where one does — the name a
            // reader can hand to `print`.
            let member = value
                .ty
                .members()
                .find(|m| member_covers(m.offset(), m.ty().size(), offset))
                .map(|m| format!(", in `{}`", m.name()));
            lines.push(format!(
                "{} (frame #{} {}{})",
                task_label(&session.tasks, index),
                chain.frames.len() - 1 - n,
                names::display_future_name(value.ty.name(), impls),
                member.unwrap_or_default(),
            ));
        }
    }
    lines
}

/// Whether the member laid out at `offset` for `size` bytes covers
/// `hit` — half-open, so a hit at a member's end belongs to whatever
/// follows, and a zero-sized member still claims its one address.
fn member_covers(offset: u64, size: u64, hit: u64) -> bool {
    offset <= hit && hit < offset + size.max(1)
}

/// The fallback block those references print as — refused when there
/// are none, so a miss is an error naming what `sync` does list.
fn print_references(addr: u64, lines: &[String], out: &mut dyn io::Write) -> Result<()> {
    if lines.is_empty() {
        bail!(
            "no decoded resource at {addr:#x}, and no task's frames hold \
             it by value; `sync` lists semaphores, joined tasks and sets"
        );
    }
    writeln!(out, "{addr:#x}: no decoded resource owns this address")?;
    writeln!(out, "    Referenced by value: {}", lines.join(", "))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Semaphore blocks (the original `sync`).
// ---------------------------------------------------------------------------

/// One contended semaphore, assembled from every place the analysis
/// mentions it: the tasks whose verified waits are on it (each
/// carrying a snapshot of its state), and the polling barriers whose
/// held acquires touch it.
struct SemaphoreBlock<'a> {
    addr: u64,
    /// The primitive wrapping it, from the first observer that named
    /// one — every acquire of one Mutex names the Mutex.
    owner: Option<&'static str>,
    /// The semaphore's own state, from the first waiting task's
    /// snapshot. `None` for a semaphore only a barrier reached: a held
    /// acquire records what *it* holds, not the queue.
    seen: Option<Seen<'a>>,
    /// The tasks verified waiting on it, in task-list order, each with
    /// the permits its acquire asked for.
    blocked: Vec<(TaskRef, u64)>,
    /// The polling barriers on it: held acquires holding permits, or
    /// places in its queue, that their holder cannot poll until its
    /// own terminal completes — each with the holder and the waiters
    /// standing behind it.
    locks: Vec<Barrier<'a>>,
}

/// One barrier as the block prints it.
struct Barrier<'a> {
    holder: TaskRef,
    barrier: &'a PollingBarrier,
    behind: Vec<(TaskRef, BarrierRelation)>,
}

/// A semaphore's state as one blocked task's wait target recorded it.
/// A core does not change while it is read, so every observer's copy
/// agrees; the first is as good as any.
struct Seen<'a> {
    available: u64,
    closed: bool,
    waiters: &'a [SemaphoreWaiter],
}

/// Group the analysis by semaphore address. A `BTreeMap` so the blocks
/// print in address order, which is stable across runs over one core.
fn blocks(analysis: &Analysis) -> BTreeMap<u64, SemaphoreBlock<'_>> {
    fn block<'a, 'b>(
        blocks: &'b mut BTreeMap<u64, SemaphoreBlock<'a>>,
        addr: u64,
    ) -> &'b mut SemaphoreBlock<'a> {
        blocks.entry(addr).or_insert(SemaphoreBlock {
            addr,
            owner: None,
            seen: None,
            blocked: Vec::new(),
            locks: Vec::new(),
        })
    }
    let mut blocks: BTreeMap<u64, SemaphoreBlock<'_>> = BTreeMap::new();
    for wait in &analysis.waits {
        let Some(WaitTarget::Semaphore {
            addr,
            owner,
            num_permits,
            available,
            closed,
            waiters,
        }) = wait.verified().map(|w| w.target())
        else {
            continue;
        };
        let entry = block(&mut blocks, *addr);
        entry.owner = entry.owner.or(*owner);
        entry.seen.get_or_insert(Seen {
            available: *available,
            closed: *closed,
            waiters,
        });
        entry.blocked.push((wait.task, *num_permits));
    }
    let behind = analysis.behind();
    for (index, barrier) in analysis.barriers.iter().enumerate() {
        let entry = block(&mut blocks, barrier.acquire.semaphore.addr);
        entry.owner = entry.owner.or(barrier.owner);
        entry.locks.push(Barrier {
            holder: TaskRef {
                addr: barrier.holder,
                task_id: barrier.holder_id,
            },
            barrier,
            behind: behind
                .iter()
                .filter(|b| b.barrier == index)
                .map(|b| (analysis.waits[b.waiter].task, b.relation))
                .collect(),
        });
    }
    blocks
}

/// One semaphore's block: what it is, what its permit word says, who
/// holds it where that is knowable at all, who is blocked on it, and
/// its wake queue in wake order.
fn print_semaphore(
    block: &SemaphoreBlock<'_>,
    type_names: &TypeNames<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The same spelling the trace's `waiting on` line and the graph's
    // rows use, so the addresses paste between the three.
    let name = match block.owner {
        Some(owner) => format!("a {owner} (semaphore {:#x})", block.addr),
        None => format!("the semaphore at {:#x}", block.addr),
    };
    match &block.seen {
        Some(seen) => {
            let closed = if seen.closed { ", closed" } else { "" };
            writeln!(
                out,
                "{name}: {} available{closed}",
                counted(seen.available as usize, "permit")
            )?;
        }
        None => {
            // Reached only through a held acquire, which records what
            // it holds, not the semaphore's own state.
            writeln!(out, "{name}: state not read (no task is blocked on it)")?;
        }
    }

    // A tokio semaphore records no owner, so a holder is knowable only
    // where the analysis found a polling barrier over an acquire
    // holding permits; an ungranted one holds a place in the queue
    // instead. Either is conditional: the holder cannot poll it until
    // the terminal of its own chain completes.
    for lock in &block.locks {
        let barrier = lock.barrier;
        let acq = &barrier.acquire;
        let future = type_names.future(barrier.future);
        let terminal = type_names.future(barrier.terminal);
        if barrier.granted() {
            writeln!(
                out,
                "    Held by: {} — {} granted to `{}` ({future}), \
                 a future it cannot poll until the {terminal} it awaits completes",
                lock.holder,
                counted(acq.requested as usize, "permit"),
                barrier.local,
            )?;
        } else {
            writeln!(
                out,
                "    Queued by: {}'s `{}` ({future}), still waiting for {}, \
                 a future it cannot poll until the {terminal} it awaits completes",
                lock.holder,
                barrier.local,
                counted(acq.needed as usize, "permit"),
            )?;
        }
        let queued: Vec<String> = lock
            .behind
            .iter()
            .filter(|(_, relation)| *relation == BarrierRelation::QueueOrder)
            .map(|(task, _)| task.to_string())
            .collect();
        if !queued.is_empty() {
            writeln!(out, "    Queued behind it: {}", queued.join(", "))?;
        }
    }

    if !block.blocked.is_empty() {
        let blocked = block
            .blocked
            .iter()
            .map(|(task, permits)| {
                format!(
                    "{task} ({} requested)",
                    counted(*permits as usize, "permit")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "    Blocked on it: {blocked}")?;
    }

    if let Some(seen) = &block.seen
        && !seen.waiters.is_empty()
    {
        let nodes: std::collections::HashSet<u64> = block
            .locks
            .iter()
            .map(|lock| lock.barrier.acquire.node)
            .collect();
        let queue = seen
            .waiters
            .iter()
            .map(|w| waiter_name(w, nodes.contains(&w.addr)))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "    Wake queue: {queue}")?;
    }
    Ok(())
}

/// How one wake-queue entry reads: who waking it schedules, in the
/// spelling the trace's inline queue uses, plus what this listing can
/// say about the node itself — that its acquire was granted everything
/// it asked for and merely awaits a poll, and that a polling barrier
/// holds that poll off until its holder's terminal completes.
fn waiter_name(w: &SemaphoreWaiter, held: bool) -> String {
    let mut name = match &w.waker {
        QueuedWaker::Task {
            task_id: Some(id), ..
        } => format!("task {id}"),
        QueuedWaker::Task {
            addr,
            task_id: None,
        } => format!("the task at {addr:#x}"),
        QueuedWaker::Other { .. } => "a non-task waiter".to_string(),
        QueuedWaker::Unarmed => "an unarmed waiter".to_string(),
    };
    let marks: Vec<&str> = [(w.needed == 0, "granted"), (held, "held off")]
        .into_iter()
        .filter_map(|(on, mark)| on.then_some(mark))
        .collect();
    if !marks.is_empty() {
        name.push_str(&format!(" ({})", marks.join(", ")));
    }
    name
}

#[cfg(test)]
mod sync_tests {
    use super::{CHANNELS, Kind, View, print_addressed, print_listing};

    use crate::relations::Relations;

    use hansei_bundle::BundleTypeId;
    use hansei_runtime::tokio::assess::{
        ContinuationStatus, IncompleteReason, PollingBarrier, VerifiedWait, WaitAssessment,
        WaitUnknownReason,
    };
    use hansei_runtime::tokio::attribution::{
        Attributed, AttributedSlot, Attribution, Hop, OwnerKind, Reading, SlotPath, SlotRoot,
        Validity,
    };
    use hansei_runtime::tokio::bundle::{
        FutureInfo, OneshotState, OwnerResolution, QueuedWaker, SemaphoreWaiter, Task, TaskKind,
        TaskList, WaitTarget,
    };
    use hansei_runtime::tokio::census;
    use hansei_runtime::tokio::graph::{Analysis, TaskRef, TaskWait};
    use hansei_runtime::tokio::observe::{AcquireObservation, ValueKey};
    use hansei_runtime::tokio::wakers::Owner;
    use hansei_runtime::tokio::{TaskAddr, TaskState};

    const REF_ONE: u64 = 1 << 6;
    const SEMAPHORE: u64 = 0x9000;

    /// `--kind` as the tests give it: one family, or every one.
    fn kinds(kind: Option<Kind>) -> Vec<Kind> {
        kind.into_iter().collect()
    }

    fn addr(id: u64) -> TaskAddr {
        TaskAddr(0x1000 + id * 0x100)
    }

    fn task_ref(id: u64) -> TaskRef {
        TaskRef {
            addr: addr(id),
            task_id: Some(id),
        }
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

    /// A task assessed as verified-waiting on `target` at `position`
    /// in its semaphore's wake order, or — with no target — with its
    /// continuation unknown.
    fn wait_at(id: u64, target: Option<WaitTarget>, position: Option<usize>) -> TaskWait {
        TaskWait {
            task: task_ref(id),
            assessment: match target {
                Some(target) => WaitAssessment::Waiting(VerifiedWait::testkit(target, position)),
                None => WaitAssessment::Unknown(WaitUnknownReason::Continuation),
            },
            continuation: no_chain(),
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

    fn wait(id: u64, target: Option<WaitTarget>) -> TaskWait {
        wait_at(id, target, None)
    }

    /// The continuation of a find laid out by hand.
    fn no_chain() -> ContinuationStatus {
        ContinuationStatus::Incomplete {
            reason: IncompleteReason::NoRoot,
            detail: None,
        }
    }

    /// A queued waiter node whose waker schedules `id`'s task.
    fn waiter(id: u64, node: u64, needed: u64) -> SemaphoreWaiter {
        SemaphoreWaiter {
            addr: node,
            needed,
            waker: QueuedWaker::Task {
                addr: addr(id).0,
                task_id: Some(id),
            },
            waker_at: None,
        }
    }

    fn semaphore(waiters: Vec<SemaphoreWaiter>) -> WaitTarget {
        WaitTarget::Semaphore {
            addr: SEMAPHORE,
            owner: Some("tokio::sync::Mutex"),
            num_permits: 1,
            available: 0,
            closed: false,
            waiters,
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

    /// The task holding an acquire on the semaphore, granted or not,
    /// in a future its exclusive chain cannot poll until its terminal
    /// completes; `position` is the node's place in the wake order
    /// where the queue established one.
    fn barrier_at(holder: u64, node: u64, needed: u64, position: Option<usize>) -> PollingBarrier {
        let key = |addr: u64| ValueKey {
            addr,
            ty: BundleTypeId(0),
        };
        PollingBarrier {
            holder: addr(holder),
            holder_id: Some(holder),
            frame: 0,
            frame_type: crate::typenames::testing::named("worker::{async_fn_env#0}"),
            state: "Suspend0".to_string(),
            await_loc: None,
            local: "lock".to_string(),
            candidate: key(node),
            future: crate::typenames::testing::named("Mutex::lock::{async_fn_env#0}"),
            owner: Some("tokio::sync::Mutex"),
            acquire: AcquireObservation {
                future: key(node),
                semaphore: key(SEMAPHORE),
                node,
                requested: 1,
                needed,
                queued: true,
                queue_position: position,
            },
            primitive: key(0xb000),
            terminal: crate::typenames::testing::named("tokio::sync::batch_semaphore::Acquire"),
            edges: Vec::new(),
        }
    }

    fn barrier(holder: u64, node: u64, needed: u64) -> PollingBarrier {
        barrier_at(holder, node, needed, None)
    }

    /// The default population behind the semaphore tests: one task per
    /// wait, so the relation index has rows to land on.
    fn list_for(waits: &[TaskWait]) -> TaskList {
        TaskList::new(
            waits
                .iter()
                .map(|w| task(w.task.task_id.unwrap()))
                .collect(),
        )
    }

    struct Fixture {
        list: TaskList,
        analysis: Analysis,
        sets: Vec<census::FutureSet>,
        join_sets: Vec<census::JoinSet>,
        slots: Attributed,
        /// The size every type has, for a hop's extent.
        size: Option<u64>,
    }

    impl Fixture {
        fn new(waits: Vec<TaskWait>, barriers: Vec<PollingBarrier>) -> Fixture {
            let list = list_for(&waits);
            Fixture {
                list,
                analysis: Analysis {
                    waits,
                    barriers,
                    join_wakers: Vec::new(),
                    errors: Vec::new(),
                },
                sets: Vec::new(),
                join_sets: Vec::new(),
                slots: Attributed::from_slots(Vec::new()),
                size: None,
            }
        }

        fn print_scoped(&self, index: usize, kind: Option<Kind>) -> anyhow::Result<String> {
            self.print_scoped_kinds(index, &kinds(kind))
        }

        fn print_scoped_kinds(&self, index: usize, kinds: &[Kind]) -> anyhow::Result<String> {
            let relations = Relations::build(&self.list, &self.analysis, &[], &self.join_sets);
            let size = self.size;
            let size_of = move |_: BundleTypeId| size;
            let view = View {
                list: &self.list,
                analysis: &self.analysis,
                relations: &relations,
                sets: &self.sets,
                join_sets: &self.join_sets,
                names: crate::typenames::testing::type_names(),
                slots: &self.slots,
                size_of: &size_of,
            };
            let mut out = Vec::new();
            super::print_task_scoped(&view, index, kinds, &mut out)?;
            Ok(String::from_utf8(out).unwrap())
        }

        fn print(&self, select: Option<u64>, kind: Option<Kind>) -> anyhow::Result<String> {
            self.print_kinds(select, &kinds(kind))
        }

        fn print_kinds(&self, select: Option<u64>, kinds: &[Kind]) -> anyhow::Result<String> {
            let relations = Relations::build(&self.list, &self.analysis, &[], &self.join_sets);
            let size = self.size;
            let size_of = move |_: BundleTypeId| size;
            let view = View {
                list: &self.list,
                analysis: &self.analysis,
                relations: &relations,
                sets: &self.sets,
                join_sets: &self.join_sets,
                names: crate::typenames::testing::type_names(),
                slots: &self.slots,
                size_of: &size_of,
            };
            let mut out = Vec::new();
            let task_at = |addr: u64| self.list.tasks.iter().position(|t| t.addr.0 == addr);
            let references = |_: u64| Vec::new();
            match select {
                Some(addr) => print_addressed(&view, addr, kinds, &task_at, &references, &mut out)?,
                None => print_listing(&view, kinds, &mut out)?,
            }
            Ok(String::from_utf8(out).unwrap())
        }
    }

    /// A slot of task `id`'s waker (or a set child's), named by the
    /// owner-name table as `kind` at `primitive`, with the primitive's
    /// reading; `hop` is the `ArcInner` the slot was reached through.
    fn owner_slot(
        at: u64,
        owner: Owner,
        kind: OwnerKind,
        primitive: u64,
        reading: Option<Reading>,
        hop: Option<u64>,
    ) -> AttributedSlot {
        AttributedSlot {
            hit: at as usize,
            slot: at,
            owner,
            attribution: Attribution::Owner {
                kind,
                primitive,
                holder: "Inner".to_string(),
                member: "rx_task".to_string(),
                path: SlotPath {
                    root: SlotRoot::Frame { task: 0, frame: 0 },
                    steps: Vec::new(),
                    hop: hop.map(|addr| Hop {
                        from: 0x100,
                        addr,
                        pointee: "alloc::sync::ArcInner<x>".to_string(),
                        pointee_ty: BundleTypeId(0),
                        steps: Vec::new(),
                    }),
                },
                validity: Validity::Raw,
                reading,
            },
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: hansei_runtime::tokio::attribution::Reach::Unlocated,
        }
    }

    fn task_owner(id: u64, index: usize) -> Owner {
        Owner::Task {
            header: addr(id).0,
            index,
        }
    }

    /// A parked oneshot's state: both task cells set, nothing sent.
    fn parked_oneshot() -> Reading {
        Reading::Oneshot(OneshotState {
            word: 0b1001,
            value_present: Some(false),
        })
    }

    /// One channel of each family, named by the slots of three tasks:
    /// task 40 receives on all three, task 7 watches the oneshot's
    /// receiver from the sending side, task 41 shares the watch; task
    /// 9 and 12 are blocked on the mpsc's semaphore, which lies in the
    /// `Chan` the receiver's slot was reached through, and tasks 10 and
    /// 11 on semaphores outside it — one past the `Chan`, one exactly
    /// at its end — which are no senders of the channel.
    fn channels_fixture() -> Fixture {
        let semaphore = |addr| {
            Some(WaitTarget::Semaphore {
                addr,
                owner: None,
                num_permits: 1,
                available: 0,
                closed: false,
                waiters: Vec::new(),
            })
        };
        let mut fixture = Fixture::new(
            vec![
                wait(40, None),
                wait(7, None),
                wait(41, None),
                wait(9, semaphore(0xb0c0)),
                wait(10, semaphore(0xd0c0)),
                wait(11, semaphore(0xb200)),
                wait(12, semaphore(0xb0c0)),
            ],
            Vec::new(),
        );
        fixture.size = Some(0x200);
        fixture.slots = Attributed::from_slots(vec![
            owner_slot(
                0xa020,
                task_owner(40, 0),
                OwnerKind::OneshotRx,
                0xa010,
                Some(parked_oneshot()),
                Some(0xa000),
            ),
            owner_slot(
                0xa030,
                task_owner(7, 1),
                OwnerKind::OneshotTx,
                0xa010,
                Some(parked_oneshot()),
                Some(0xa000),
            ),
            owner_slot(
                0xb080,
                task_owner(40, 0),
                OwnerKind::Mpsc,
                0xb010,
                Some(Reading::Mpsc {
                    senders: 2,
                    capacity: Some(4),
                    unread: 4,
                }),
                Some(0xb000),
            ),
            owner_slot(
                0xc080,
                task_owner(40, 0),
                OwnerKind::Watch,
                0xc010,
                Some(Reading::Watch {
                    version: 3,
                    closed: false,
                    receivers: 2,
                    senders: 1,
                }),
                None,
            ),
            owner_slot(
                0xc090,
                task_owner(41, 2),
                OwnerKind::Watch,
                0xc010,
                Some(Reading::Watch {
                    version: 3,
                    closed: false,
                    receivers: 2,
                    senders: 1,
                }),
                None,
            ),
        ]);
        fixture
    }

    /// The channel blocks: one per primitive, the heading printed as
    /// the cells print the slot, the owners on each side, and a sender
    /// blocked on capacity found through its semaphore wait inside the
    /// `Chan`. `channels` prints the three families and nothing else.
    #[test]
    fn test_channel_blocks_name_both_sides() {
        let fixture = channels_fixture();
        let out = fixture.print_kinds(None, &CHANNELS).unwrap();
        assert_eq!(
            out,
            "oneshot 0xa010: nothing sent, sender alive\n    \
             rx: task 40\n    \
             tx: task 7\n\
             \n\
             mpsc 0xb010: 2 senders, capacity 4, 4 unread\n    \
             rx: task 40\n    \
             tx blocked on capacity: task 9, task 12\n\
             \n\
             watch 0xc010: version 3, 1 sender, 2 receivers\n    \
             rx: task 40, task 41\n"
        );
        // The bare listing prints the semaphore's block first, then
        // the channels; one family alone prints that family.
        let all = fixture.print(None, None).unwrap();
        assert!(all.starts_with("the semaphore at 0xb0c0"), "{all}");
        assert!(all.ends_with(&out), "{all}");
        let watch = fixture.print(None, Some(Kind::Watch)).unwrap();
        assert!(watch.starts_with("watch 0xc010"), "{watch}");
        assert!(!watch.contains("oneshot"), "{watch}");
    }

    /// A `Notify` block: the state word's reading and every task
    /// queued on it, one line — listed after the channels and not by
    /// `channels`, which asks for the channel families alone.
    #[test]
    fn test_a_notify_block_lists_its_waiters() {
        let mut fixture = Fixture::new(vec![wait(40, None), wait(41, None)], Vec::new());
        fixture.slots = Attributed::from_slots(vec![
            owner_slot(
                0xe020,
                task_owner(40, 0),
                OwnerKind::Notify,
                0xe000,
                Some(Reading::Notify { state: 0b01 }),
                None,
            ),
            owner_slot(
                0xe120,
                task_owner(41, 1),
                OwnerKind::Notify,
                0xe000,
                Some(Reading::Notify { state: 0b01 }),
                None,
            ),
        ]);
        let block = "notify 0xe000: waiting\n    rx: task 40, task 41\n";
        assert_eq!(fixture.print(None, Some(Kind::Notify)).unwrap(), block);
        assert_eq!(fixture.print(None, None).unwrap(), block);
        assert_eq!(fixture.print_kinds(None, &CHANNELS).unwrap(), "");
        assert_eq!(fixture.print(Some(0xe000), None).unwrap(), block);
        assert_eq!(fixture.print_scoped(1, None).unwrap(), block);
    }

    /// A slot whose primitive nothing read prints the heading without
    /// words, and a set child's slot names the child and the task
    /// polling it.
    #[test]
    fn test_a_channel_block_without_a_reading_or_owned_by_a_child() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.sets = vec![census::FutureSet {
            owner: 0,
            frame: 0,
            local: "work".to_string(),
            via: None,
            addr: 0xd000,
            ty: crate::typenames::testing::named(
                "futures_util::stream::futures_unordered::FuturesUnordered<()>",
            ),
            children: Vec::new(),
        }];
        fixture.slots = Attributed::from_slots(vec![owner_slot(
            0xa020,
            Owner::Child { set: 0, child: 3 },
            OwnerKind::OneshotRx,
            0xa010,
            None,
            None,
        )]);
        assert_eq!(
            fixture.print(None, Some(Kind::Oneshot)).unwrap(),
            "oneshot 0xa010: state not read\n    \
             rx: child 3 of the set at 0xd000 (polled by task 9)\n"
        );
    }

    /// An addressed ask resolves a channel's address to its block, the
    /// family filter refuses an address of another family by name, and
    /// the cursor-scoped listing prints the channels the task parks in
    /// on either side.
    #[test]
    fn test_channels_resolve_by_address_and_by_task() {
        let fixture = channels_fixture();
        let by_addr = fixture.print(Some(0xa010), None).unwrap();
        assert!(by_addr.starts_with("oneshot 0xa010"), "{by_addr}");
        assert_eq!(
            fixture.print(Some(0xa010), Some(Kind::Oneshot)).unwrap(),
            by_addr
        );
        let err = fixture
            .print_kinds(Some(0xa010), &[Kind::Mpsc, Kind::Watch])
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "no mpsc or watch at 0xa010 holds a parked waker; `sync --kind mpsc,watch` \
             lists the ones a slot names"
        );
        let err = fixture
            .print_kinds(Some(0xa010), &[Kind::Mpsc, Kind::Join])
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("only the families a waker slot names"),
            "{err}"
        );

        // Task 7 is party to the oneshot alone, on the sending side;
        // task 9 to the mpsc, as a blocked sender, beside its own
        // semaphore block.
        let sender = fixture.print_scoped(1, None).unwrap();
        assert_eq!(
            sender,
            "oneshot 0xa010: nothing sent, sender alive\n    rx: task 40\n    tx: task 7\n"
        );
        let blocked = fixture.print_scoped_kinds(3, &CHANNELS).unwrap();
        assert!(blocked.starts_with("mpsc 0xb010"), "{blocked}");
        assert!(!blocked.contains("oneshot"), "{blocked}");
        let none = fixture.print_scoped(1, Some(Kind::Mpsc)).unwrap();
        assert!(none.contains("parks in no channel"), "{none}");
    }

    fn sync(
        waits: Vec<TaskWait>,
        barriers: Vec<PollingBarrier>,
        select: Option<u64>,
    ) -> anyhow::Result<String> {
        Fixture::new(waits, barriers).print(select, Some(Kind::Semaphore))
    }

    /// The whole block of a contended, futurelocked Mutex: the holder
    /// named from the barrier with the condition it holds under, the
    /// waiting tasks with what each asked for, and the wake queue in
    /// wake order with the granted, held-off node marked — the RFD 609
    /// shape read off the resource.
    #[test]
    fn test_a_contended_mutex_gets_one_block() {
        let waits = vec![
            wait(
                40,
                Some(semaphore(vec![
                    waiter(40, 0xe100, 1),
                    waiter(41, 0xe200, 1),
                    waiter(7, 0xa000, 0),
                ])),
            ),
            wait(41, Some(semaphore(Vec::new()))),
            wait(9, None),
        ];
        let out = sync(waits, vec![barrier(7, 0xa000, 0)], None).unwrap();
        assert_eq!(
            out,
            "a tokio::sync::Mutex (semaphore 0x9000): 0 permits available\n    \
             Held by: task 7 — 1 permit granted to `lock` (async fn Mutex::lock), \
             a future it cannot poll until the future \
             tokio::sync::batch_semaphore::Acquire it awaits completes\n    \
             Blocked on it: task 40 (1 permit requested), task 41 (1 permit requested)\n    \
             Wake queue: task 40, task 41, task 7 (granted, held off)\n"
        );
    }

    /// A held-off acquire the semaphore has not granted yet holds a
    /// place in the queue, not permits: the diagnosis line says what it
    /// still waits for, the waiter behind it in wake order is named as
    /// queued behind it, and its node is marked without a granted
    /// claim.
    #[test]
    fn test_an_ungranted_held_acquire_is_marked_in_the_queue() {
        let waits = vec![wait_at(
            40,
            Some(semaphore(vec![waiter(7, 0xa000, 1), waiter(40, 0xe100, 1)])),
            Some(1),
        )];
        let out = sync(waits, vec![barrier_at(7, 0xa000, 1, Some(0))], None).unwrap();
        assert!(
            out.contains(
                "    Queued by: task 7's `lock` (async fn Mutex::lock), \
                 still waiting for 1 permit, a future it cannot poll until the future \
                 tokio::sync::batch_semaphore::Acquire it awaits completes\n    \
                 Queued behind it: task 40\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("    Wake queue: task 7 (held off), task 40\n"),
            "{out}"
        );
        assert!(!out.contains("Held by"), "{out}");

        // With no established wake order nothing is queued behind it:
        // a reversed partial prefix places nobody.
        let waits = vec![wait(
            40,
            Some(semaphore(vec![waiter(7, 0xa000, 1), waiter(40, 0xe100, 1)])),
        )];
        let out = sync(waits, vec![barrier(7, 0xa000, 1)], None).unwrap();
        assert!(!out.contains("Queued behind it"), "{out}");
    }

    /// Blocks print in address order, a blank line between them; a
    /// semaphore no frame names the owner of keeps the bare spelling,
    /// and its state line carries the closed bit and the plural.
    #[test]
    fn test_blocks_print_in_address_order() {
        let bare = WaitTarget::Semaphore {
            addr: 0x4000,
            owner: None,
            num_permits: 3,
            available: 2,
            closed: true,
            waiters: vec![SemaphoreWaiter {
                addr: 0xe300,
                needed: 3,
                waker_at: None,
                waker: QueuedWaker::Unarmed,
            }],
        };
        let waits = vec![wait(40, Some(semaphore(Vec::new()))), wait(41, Some(bare))];
        let out = sync(waits, Vec::new(), None).unwrap();
        assert_eq!(
            out,
            "the semaphore at 0x4000: 2 permits available, closed\n    \
             Blocked on it: task 41 (3 permits requested)\n    \
             Wake queue: an unarmed waiter\n\
             \n\
             a tokio::sync::Mutex (semaphore 0x9000): 0 permits available\n    \
             Blocked on it: task 40 (1 permit requested)\n"
        );
    }

    /// `sync 0x…` prints that one block alone, and an address the
    /// analysis never decoded is refused rather than answered with
    /// silence.
    #[test]
    fn test_selection_prints_one_block_and_a_miss_is_refused() {
        let waits = vec![wait(40, Some(semaphore(Vec::new())))];
        let out = sync(waits, Vec::new(), Some(SEMAPHORE)).unwrap();
        assert!(out.starts_with("a tokio::sync::Mutex"), "{out}");

        let waits = vec![wait(40, Some(semaphore(Vec::new())))];
        let err = sync(waits, Vec::new(), Some(0x1)).unwrap_err();
        assert!(
            err.to_string().contains("no decoded semaphore at 0x1"),
            "{err}"
        );
    }

    /// A semaphore only a barrier reached has no snapshot to spell
    /// permits or a queue from — the held acquire records what it
    /// holds, not the semaphore's state — so the block says that
    /// rather than printing zeros read from nothing.
    #[test]
    fn test_a_barrier_only_semaphore_prints_a_reduced_block() {
        let out = sync(Vec::new(), vec![barrier(7, 0xa000, 0)], None).unwrap();
        assert_eq!(
            out,
            "a tokio::sync::Mutex (semaphore 0x9000): state not read \
             (no task is blocked on it)\n    \
             Held by: task 7 — 1 permit granted to `lock` (async fn Mutex::lock), \
             a future it cannot poll until the future \
             tokio::sync::batch_semaphore::Acquire it awaits completes\n"
        );
    }

    /// Nothing prints when the analysis reached no relation at all: an
    /// empty answer is "none found here", the same claim `graph` makes.
    #[test]
    fn test_no_contention_prints_nothing() {
        let out = Fixture::new(vec![wait(9, None)], Vec::new())
            .print(None, None)
            .unwrap();
        assert_eq!(out, "");
    }

    /// The scoped view prints exactly what the task is party to: the
    /// semaphore it is blocked on, the same block for its holder —
    /// whose own un-joined block is *not* among them, the semaphore
    /// already being its relation — and, for a joiner, the joined
    /// task's block.
    #[test]
    fn test_scoped_sync_prints_what_the_task_is_party_to() {
        let waits = vec![wait(40, Some(semaphore(Vec::new()))), wait(7, None)];
        let fixture = Fixture::new(waits, vec![barrier(7, 0xa000, 0)]);
        let blocked = fixture.print_scoped(0, None).unwrap();
        assert!(blocked.starts_with("a tokio::sync::Mutex"), "{blocked}");
        assert!(!blocked.contains("party to no"), "{blocked}");
        let holder = fixture.print_scoped(1, None).unwrap();
        assert!(holder.starts_with("a tokio::sync::Mutex"), "{holder}");
        assert!(!holder.contains("No task waits"), "{holder}");

        // The family filter answers with the family asked for, and a
        // family the task is not party to answers the one-liner.
        let fixture = Fixture::new(
            vec![wait(40, Some(semaphore(Vec::new()))), wait(7, None)],
            vec![barrier(7, 0xa000, 0)],
        );
        let sem_only = fixture.print_scoped(0, Some(Kind::Semaphore)).unwrap();
        assert!(sem_only.starts_with("a tokio::sync::Mutex"), "{sem_only}");
        let join_only = fixture.print_scoped(0, Some(Kind::Join)).unwrap();
        assert!(join_only.contains("party to no decoded"), "{join_only}");

        let fixture = Fixture::new(vec![wait(7, Some(joining(8))), wait(8, None)], Vec::new());
        let joiner = fixture.print_scoped(0, None).unwrap();
        assert_eq!(joiner, "task 8 (<unknown>): idle\n    Waited by: task 7\n");
        assert_eq!(fixture.print_scoped(0, Some(Kind::Join)).unwrap(), joiner);
        let sem_only = fixture.print_scoped(0, Some(Kind::Semaphore)).unwrap();
        assert!(sem_only.contains("party to no decoded"), "{sem_only}");
    }

    /// A set relates its driver and each member: the member's scope
    /// prints its one set, the driver of two prints both, blank-line
    /// separated and nothing before the first.
    #[test]
    fn test_scoped_sync_prints_driven_and_member_sets() {
        let joinset = |set_addr: u64, member: u64| census::JoinSet {
            owner: 0,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: set_addr,
            ty: crate::typenames::testing::named("tokio::task::join_set::JoinSet<()>"),
            length: 1,
            children: vec![census::JoinedTask {
                entry: 0xc000,
                task: addr(member).0,
                id: Some(member),
                state: TaskState(REF_ONE),
                listed: true,
            }],
        };
        let mut fixture = Fixture::new(vec![wait(9, None), wait(21, None)], Vec::new());
        fixture.join_sets = vec![joinset(0xb000, 21), joinset(0xb100, 99)];
        let member = fixture.print_scoped(1, None).unwrap();
        assert_eq!(
            member,
            "task 21 (<unknown>): idle\n    Member of: a tokio::task::join_set::JoinSet<()> (set 0xb000), driven by task 9\n\na tokio::task::join_set::JoinSet<()> (set 0xb000): 1 member, driven by task 9 (`tasks`)\n    Members (idle): task 21\n"
        );
        let driver = fixture.print_scoped(0, None).unwrap();
        assert!(driver.starts_with("a tokio"), "{driver}");
        assert_eq!(driver.matches("(set 0x").count(), 2, "{driver}");
        assert_eq!(driver.matches("\n\n").count(), 1, "{driver}");
        // The set family alone keeps the member's one set and answers
        // the one-liner for a family it is not party to.
        let set_only = fixture.print_scoped(1, Some(Kind::Set)).unwrap();
        assert!(set_only.contains("(set 0xb000)"), "{set_only}");
        assert!(!set_only.contains("(set 0xb100)"), "{set_only}");
        let sem_only = fixture.print_scoped(1, Some(Kind::Semaphore)).unwrap();
        assert!(sem_only.contains("party to no decoded"), "{sem_only}");
    }

    /// A set whose every child has completed unreaped counts no
    /// in-flight line at all — a zero would claim a count the set does
    /// not have.
    #[test]
    fn test_a_set_of_only_reaped_children_counts_no_flight() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.sets = vec![census::FutureSet {
            owner: 0,
            frame: 0,
            local: "work".to_string(),
            via: None,
            addr: 0xb000,
            ty: crate::typenames::testing::named(
                "futures_util::stream::futures_unordered::FuturesUnordered<()>",
            ),
            children: vec![census::SetChild {
                node: 0xc100,
                depth: 0,
                future: None,
                root: None,
                state: None,
                waiting_on: None,
                wait: None,
                observation: None,
                continuation: no_chain(),
                request: None,
            }],
        }];
        assert_eq!(
            fixture.print(None, None).unwrap(),
            "a futures_util::stream::futures_unordered::FuturesUnordered<()> (set 0xb000): 1 child, driven by task 9 (`work`)\n    Completed, not yet reaped: 1\n"
        );
    }

    /// Member coverage is half-open with a floor of one byte: the
    /// start is in, the end is the next member's, and a zero-sized
    /// member still claims its one address.
    #[test]
    fn test_member_coverage_is_half_open() {
        use super::member_covers;
        assert!(member_covers(0, 8, 0));
        assert!(member_covers(0, 8, 7));
        assert!(!member_covers(0, 8, 8));
        assert!(!member_covers(8, 8, 7));
        assert!(member_covers(8, 0, 8));
        assert!(!member_covers(8, 0, 9));
    }

    /// The reference fallback's block: both lines when frames hold the
    /// address, the refusal naming the address when none do.
    #[test]
    fn test_the_reference_block_prints_or_refuses() {
        let mut out = Vec::new();
        super::print_references(0x40, &["task 7 (frame #0 x)".to_string()], &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "0x40: no decoded resource owns this address\n    Referenced by value: task 7 (frame #0 x)\n"
        );
        let err = super::print_references(0x40, &[], &mut Vec::new()).unwrap_err();
        assert!(
            err.to_string().contains("no decoded resource at 0x40"),
            "{err}"
        );
    }

    /// A joined task earns one block naming every join relation it is
    /// on the resource end of: who waits on it, who holds its handle,
    /// and the set that will collect it — and only joined tasks get
    /// one, never one block per task.
    #[test]
    fn test_a_joined_task_gets_a_join_block() {
        let mut fixture = Fixture::new(
            vec![wait(7, Some(joining(8))), wait(8, None), wait(9, None)],
            Vec::new(),
        );
        fixture.join_sets = vec![census::JoinSet {
            owner: 2,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: 0xb000,
            ty: crate::typenames::testing::named("tokio::task::join_set::JoinSet<()>"),
            length: 1,
            children: vec![census::JoinedTask {
                entry: 0xc000,
                task: addr(8).0,
                id: Some(8),
                state: TaskState(REF_ONE),
                listed: true,
            }],
        }];
        let out = fixture.print(None, Some(Kind::Join)).unwrap();
        assert_eq!(
            out,
            "task 8 (<unknown>): idle\n    \
             Waited by: task 7\n    \
             Member of: a tokio::task::join_set::JoinSet<()> (set 0xb000), \
             driven by task 9\n"
        );
    }

    /// The set view: a JoinSet's members grouped by state under the
    /// task driving it, and `--kind set` narrowing the listing to it.
    #[test]
    fn test_a_join_set_block_groups_members_by_state() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.join_sets = vec![census::JoinSet {
            owner: 0,
            frame: 0,
            local: "tasks".to_string(),
            via: None,
            addr: 0xb000,
            ty: crate::typenames::testing::named("tokio::task::join_set::JoinSet<()>"),
            length: 2,
            children: vec![
                census::JoinedTask {
                    entry: 0xc000,
                    task: 0x7000,
                    id: Some(21),
                    state: TaskState(REF_ONE),
                    listed: true,
                },
                census::JoinedTask {
                    entry: 0xc100,
                    task: 0x7100,
                    id: Some(22),
                    state: TaskState(REF_ONE | 1),
                    listed: false,
                },
            ],
        }];
        let out = fixture.print(None, Some(Kind::Set)).unwrap();
        assert_eq!(
            out,
            "a tokio::task::join_set::JoinSet<()> (set 0xb000): 2 members, \
             driven by task 9 (`tasks`)\n    \
             Members (idle): task 21\n    \
             Members (running, unlisted): task 22\n"
        );
    }

    /// A FuturesUnordered's children are futures, not listed tasks:
    /// the block counts what is resident against what has completed
    /// unreaped, and an addressed ask prints the same block.
    #[test]
    fn test_a_future_set_block_counts_children() {
        let mut fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        fixture.sets = vec![census::FutureSet {
            owner: 0,
            frame: 0,
            local: "work".to_string(),
            via: None,
            addr: 0xb000,
            ty: crate::typenames::testing::named(
                "futures_util::stream::futures_unordered::FuturesUnordered<()>",
            ),
            children: vec![
                census::SetChild {
                    node: 0xc000,
                    depth: 1,
                    future: Some(crate::typenames::testing::named(
                        "app::poll::{async_fn_env#0}",
                    )),
                    root: None,
                    state: None,
                    waiting_on: None,
                    wait: None,
                    observation: None,
                    continuation: ContinuationStatus::Unresumed,
                    request: None,
                },
                census::SetChild {
                    node: 0xc100,
                    depth: 0,
                    future: None,
                    root: None,
                    state: None,
                    waiting_on: None,
                    wait: None,
                    observation: None,
                    continuation: no_chain(),
                    request: None,
                },
            ],
        }];
        let listed = fixture.print(None, None).unwrap();
        let addressed = fixture.print(Some(0xb000), None).unwrap();
        assert_eq!(listed, addressed);
        assert_eq!(
            listed,
            "a futures_util::stream::futures_unordered::FuturesUnordered<()> (set 0xb000): \
             2 children, driven by task 9 (`work`)\n    \
             In flight: 1\n    \
             Completed, not yet reaped: 1\n"
        );
    }

    /// `--kind` narrows the listing to one block family: the join
    /// blocks alone, with the contended semaphore left out.
    #[test]
    fn test_kind_narrows_the_listing() {
        let waits = vec![
            wait(40, Some(semaphore(Vec::new()))),
            wait(7, Some(joining(40))),
        ];
        let fixture = Fixture::new(waits, Vec::new());
        let joins = fixture.print(None, Some(Kind::Join)).unwrap();
        assert!(joins.starts_with("task 40 ("), "{joins}");
        assert!(!joins.contains("semaphore"), "{joins}");
        let semaphores = fixture.print(None, Some(Kind::Semaphore)).unwrap();
        assert!(
            semaphores.starts_with("a tokio::sync::Mutex"),
            "{semaphores}"
        );
        assert!(!semaphores.contains("Waited by"), "{semaphores}");
    }

    /// An addressed ask resolves a task header to that task's join
    /// block, an un-joined task included — the addressed form answers
    /// the address it was given.
    #[test]
    fn test_an_addressed_task_prints_its_join_block() {
        let fixture = Fixture::new(vec![wait(9, None)], Vec::new());
        let out = fixture.print(Some(addr(9).0), None).unwrap();
        assert_eq!(
            out,
            "task 9 (<unknown>): idle\n    \
             No task waits to join it, holds its handle, or drives it in a set\n"
        );
    }
}

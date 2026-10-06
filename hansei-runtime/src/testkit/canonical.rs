// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A fresh core with what its capture decided renamed out of it.
//!
//! Two captures of one program differ in what nothing in the program
//! controls: the kernel's thread ids, which worker happened to hold the
//! driver when the core was taken, and the task ids tokio's counter
//! handed out to spawns that raced (inside hyper and reqwest, say).
//! Printers sort by both and print both, so a golden over a fresh core
//! moves with every capture unless they are made stable at the source.
//!
//! [`Canonical`] does that in two passes. The first reads the raw core
//! the way a session would and orders what it found by what the program
//! decided: each lwp by its role, its runtime and its park state, each
//! task by where it was spawned, what it runs and its state, with the
//! real id breaking ties. The second wraps the core so that its lwps
//! carry canonical tids, numbered from [`TID_BASE`] in that order, and
//! every word holding an id from one of tokio's process-wide counters
//! reads back as a canonical one — each counter its own [`Space`]:
//!
//! - task ids, from [`TASK_BASE`]: each task's own, each worker's
//!   current-task slot, and a finished `JoinSet` member's, which no
//!   task list holds;
//! - tokio `ThreadId`s, from [`THREAD_BASE`]: each thread's `Context`
//!   and each local set's recorded owner, ordered by the thread that
//!   holds the id;
//! - owned-list ids, from [`OWNED_BASE`]: each runtime's list and each
//!   local set's, and every task header's `owner_id`, ordered by the
//!   runtime's or set's threads.
//!
//! Memory and symbols otherwise pass through untouched, and nothing
//! outside this module knows the renaming happened.
//!
//! The renaming is sound only while nothing joins memory against an lwp
//! id, and while every id the analysis reads is one of the words
//! overlaid. The guard tests read every overlaid word back renamed, and
//! hold a renamed run's output to the raw run's with the renamings
//! undone. Two ids of a space the program does not tell apart — the
//! same ordering key — would number by their raw values, which is the
//! race the renaming exists to remove, so the plan records each such
//! tie and a guard test fails on it.

use crate::testkit::{self, Enumeration};
use crate::tokio::bundle::{Context, LocalSetRef};
use crate::tokio::census::{Bounds, census_bounded};
use crate::tokio::observe::ReadContext;

use hansei_bundle::{Bundle, BundleView, WalkRole};
use proc::RecordedHeapEvidence;
use proc::{
    BuildIds, FatalSignal, LwpInfo, Mappings, ProcessFacts, Regs, Result, SymbolBuf, Target,
};
use reify::Value;

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Mutex;

/// The first canonical tid. Well clear of an illumos lwp id (1 up) and
/// of a Linux tid (the pid's range), so a renamed run's output cannot be
/// mistaken for a raw one's.
pub const TID_BASE: u32 = 1001;

/// The first canonical task id, clear of the canonical tids and of the
/// handful tokio's counter reaches in a fixture.
pub const TASK_BASE: u64 = 2001;

/// The first canonical tokio `ThreadId`, clear of the other spaces.
pub const THREAD_BASE: u64 = 3001;

/// The first canonical owned-list id, clear of the other spaces.
pub const OWNED_BASE: u64 = 4001;

/// Which of tokio's process-wide counters an id came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Space {
    /// `task::Id`.
    Task,
    /// `runtime::thread_id::ThreadId`.
    Thread,
    /// The id an `OwnedTasks` or `LocalOwnedTasks` list was given, which
    /// every task it owns carries as its header's `owner_id`.
    Owned,
}

/// A word the overlay renames: where it is, which space its id is from,
/// and the real id it held.
#[derive(Clone, Copy, Debug)]
pub struct Holder {
    pub space: Space,
    pub addr: u64,
    pub real: u64,
}

/// Patched copies of reads, by the read they answer.
type Lent = Mutex<HashMap<(u64, u64), Box<[u8]>>>;

/// What [`plan`] decides: the renamings, the words that carry them out,
/// and the overlay those words make.
#[derive(Default)]
struct Plan {
    tids: Vec<(u32, u32)>,
    task_ids: Vec<(u64, u64)>,
    thread_ids: Vec<(u64, u64)>,
    owned_ids: Vec<(u64, u64)>,
    holders: Vec<Holder>,
    ties: Vec<String>,
}

/// `inner` with its lwps and tokio's counter-given ids renamed. See the
/// module docs.
pub struct Canonical<T> {
    inner: T,
    /// Real tid to canonical, and back.
    tids: Vec<(u32, u32)>,
    /// Real task id to canonical.
    task_ids: Vec<(u64, u64)>,
    /// Real tokio `ThreadId` to canonical.
    thread_ids: Vec<(u64, u64)>,
    /// Real owned-list id to canonical.
    owned_ids: Vec<(u64, u64)>,
    /// Every word the overlay renames.
    holders: Vec<Holder>,
    /// The ids of a space that shared an ordering key with another.
    ties: Vec<String>,
    /// The overlay, byte by byte: what each overlaid address reads as.
    patches: BTreeMap<u64, u8>,
    /// Patched copies of the reads that crossed an overlaid byte, kept
    /// for as long as `self` so the slices lent out of them live as
    /// long as a read of `inner` would. Keyed by the read, so a read
    /// asked again is answered from the copy it made the first time.
    lent: Lent,
}

impl<T: Target> Canonical<T> {
    /// Rename `inner`'s lwps and counter-given ids, reading it through
    /// `bundle` the way a session does. A target the pipeline cannot
    /// read is renamed as far as it got: every lwp by its real tid, and
    /// no id.
    pub fn new(inner: T, bundle: &Bundle) -> Self {
        let plan = plan(&inner, bundle);
        let mut patches = BTreeMap::new();
        for holder in &plan.holders {
            let renaming = match holder.space {
                Space::Task => &plan.task_ids,
                Space::Thread => &plan.thread_ids,
                Space::Owned => &plan.owned_ids,
            };
            if let Some(&(_, canonical)) = renaming.iter().find(|(r, _)| *r == holder.real) {
                overlay(&mut patches, holder.addr, canonical);
            }
        }
        Canonical {
            inner,
            tids: plan.tids,
            task_ids: plan.task_ids,
            thread_ids: plan.thread_ids,
            owned_ids: plan.owned_ids,
            holders: plan.holders,
            ties: plan.ties,
            patches,
            lent: Mutex::new(HashMap::new()),
        }
    }

    /// The target under the renaming.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// The canonical tid of real tid `tid`.
    pub fn canonical_tid(&self, tid: u32) -> Option<u32> {
        self.tids
            .iter()
            .find(|(real, _)| *real == tid)
            .map(|(_, c)| *c)
    }

    /// The real tid canonical tid `tid` stands for.
    pub fn real_tid(&self, tid: u32) -> Option<u32> {
        self.tids
            .iter()
            .find(|(_, c)| *c == tid)
            .map(|(real, _)| *real)
    }

    /// Every real tid with its canonical one.
    pub fn tid_renaming(&self) -> &[(u32, u32)] {
        &self.tids
    }

    /// Every real task id with its canonical one.
    pub fn task_renaming(&self) -> &[(u64, u64)] {
        &self.task_ids
    }

    /// Every real tokio `ThreadId` with its canonical one.
    pub fn thread_renaming(&self) -> &[(u64, u64)] {
        &self.thread_ids
    }

    /// Every real owned-list id with its canonical one.
    pub fn owned_renaming(&self) -> &[(u64, u64)] {
        &self.owned_ids
    }

    /// Every word the overlay renames.
    pub fn holders(&self) -> &[Holder] {
        &self.holders
    }

    /// Each pair of ids a space numbered by their raw values, for want
    /// of anything the program decided between them.
    pub fn ties(&self) -> &[String] {
        &self.ties
    }

    /// The overlaid bytes in `addr..addr + len`, if any.
    fn overlaid(&self, addr: u64, len: u64) -> Option<impl Iterator<Item = (u64, u8)> + '_> {
        let end = addr.checked_add(len)?;
        let mut range = self.patches.range(addr..end).peekable();
        range.peek()?;
        Some(range.map(|(a, b)| (*a, *b)))
    }
}

/// What orders an lwp: its role, its runtime, and its park state.
type LwpKey = (u8, usize, String);

/// What orders an id of a space: a rank for the kind of thing holding
/// it, then that thing's place among its kind.
type IdKey = (u8, u64);

/// Order `target`'s lwps, then number each of tokio's id spaces by what
/// the program decided, recording every word that holds an id.
fn plan<T: Target>(target: &T, bundle: &Bundle) -> Plan {
    let lwps = target.lwps().unwrap_or_default();
    let mut keys: BTreeMap<u32, LwpKey> = lwps
        .iter()
        .map(|lwp| (lwp.tid, (ROLE_OTHER, 0, String::new())))
        .collect();
    let mut plan = Plan::default();

    let ctx = Context::new(target, BundleView::new(bundle)).ok();
    let mut found = None;
    if let Some(ctx) = &ctx
        && let Ok(mut e) = testkit::try_enumerate(ctx, target)
    {
        let sets = e.discover(ctx, &[]);
        for (runtime, rt) in e.runtimes.iter().enumerate() {
            let parks = ctx.park_states(rt.handle).ok();
            for worker in e.workers.iter().filter(|w| rt.worker_tids.contains(&w.tid)) {
                let key = if let Ok(Some(wctx)) = ctx.worker_context(worker) {
                    let state = ctx
                        .worker_index(wctx)
                        .ok()
                        .and_then(|i| parks.as_ref()?.workers.get(i as usize))
                        .map(|s| format!("{s:?}"))
                        .unwrap_or_default();
                    (ROLE_WORKER, runtime, state)
                } else if let Ok(Some(_)) = ctx.ct_worker_context(worker) {
                    (ROLE_BLOCK_ON, runtime, String::new())
                } else {
                    let polling = worker.current_task_id.is_some();
                    (ROLE_ENTERED, runtime, polling.to_string())
                };
                keys.insert(worker.tid, key);
            }
        }
        // The thread a program starts on was there first, whatever it
        // went on to do.
        if let Some(main) = keys.keys().next().copied() {
            keys.get_mut(&main).unwrap().0 = ROLE_MAIN;
        }
        found = Some((e, sets));
    }
    if let Some(agent) = target.agent_lwp()
        && let Some(key) = keys.get_mut(&agent)
    {
        key.0 = ROLE_AGENT;
    }

    let mut order: Vec<(&LwpKey, u32)> = keys.iter().map(|(tid, key)| (key, *tid)).collect();
    order.sort();
    plan.tids = order
        .iter()
        .enumerate()
        .map(|(i, (_, real))| (*real, TID_BASE + i as u32))
        .collect();
    let rank: HashMap<u32, u64> = order
        .iter()
        .enumerate()
        .map(|(i, (_, tid))| (*tid, i as u64))
        .collect();

    if let (Some(ctx), Some((e, sets))) = (&ctx, &found) {
        let members = tasks(ctx, target, e, &keys, &mut plan);
        threads(ctx, target, e, sets, &rank, &mut plan);
        owned(ctx, target, e, sets, &members, &rank, &mut plan);
    }
    plan
}

/// The task-id space. Each listed task by what the program decided —
/// where it was spawned, what it runs, its state — with the real id
/// breaking ties; then an id only a worker's current-task slot holds, a
/// task between lists as the core was taken, in the workers' own order;
/// then a finished `JoinSet` member's, off every list and alive only
/// through its set's entry, by the task holding the set and the entry's
/// place in it. Returns those members, as (header, real id).
fn tasks<T: Target>(
    ctx: &Context<'_, T>,
    target: &T,
    e: &Enumeration<'_>,
    keys: &BTreeMap<u32, LwpKey>,
    plan: &mut Plan,
) -> Vec<(u64, u64)> {
    let mut listed: Vec<(String, u64, u64)> = e
        .list
        .tasks
        .iter()
        .filter_map(|task| {
            let id = task.task_id?;
            let key = format!(
                "{}\0{:?}\0{:?}",
                task.spawn_location
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                task.future,
                task.state.lifecycle(),
            );
            Some((key, id, task.addr.0))
        })
        .collect();
    listed.sort();
    let mut by_real = HashMap::new();
    let mut number = |real: u64, plan: &mut Plan| -> u64 {
        let next = TASK_BASE + by_real.len() as u64;
        *by_real.entry(real).or_insert_with(|| {
            plan.task_ids.push((real, next));
            next
        })
    };
    for (_, real, header) in &listed {
        number(*real, plan);
        if let Some(at) = id_word(ctx, target, *header) {
            plan.holders.push(Holder {
                space: Space::Task,
                addr: at,
                real: *real,
            });
        }
    }

    let mut workers: Vec<&_> = e.workers.iter().collect();
    workers.sort_by_key(|w| (keys.get(&w.tid).cloned(), w.tid));
    for worker in workers {
        let Some(real) = worker.current_task_id else {
            continue;
        };
        number(real, plan);
        let slot = ctx
            .context_info(worker.context_addr)
            .and_then(|info| ctx.walk(WalkRole::CurrentTaskId).walk_at(info));
        if let Some(at) = word(slot)
            && target.read_u64(at).ok() == Some(real)
        {
            plan.holders.push(Holder {
                space: Space::Task,
                addr: at,
                real,
            });
        }
    }

    // The census finds a set's entries; unaudited, since a damaged
    // target is renamed as far as it reads, not judged here.
    let census = census_bounded(ctx, &e.list, Bounds::default(), &ReadContext::none());
    let canonical_of = |real: Option<u64>| -> u64 {
        real.and_then(|real| {
            plan.task_ids
                .iter()
                .find(|(r, _)| *r == real)
                .map(|(_, c)| *c)
        })
        .unwrap_or(u64::MAX)
    };
    let mut members: Vec<((u64, String, usize), u64, u64)> = Vec::new();
    for set in &census.join_sets {
        let holder = canonical_of(e.list.tasks.get(set.owner).and_then(|t| t.task_id));
        for (i, child) in set.children.iter().enumerate() {
            if let (false, Some(real)) = (child.listed, child.id) {
                members.push(((holder, set.local.clone(), i), real, child.task));
            }
        }
    }
    members.sort();
    let mut found = Vec::new();
    for (_, real, header) in members {
        number(real, plan);
        if let Some(at) = id_word(ctx, target, header) {
            plan.holders.push(Holder {
                space: Space::Task,
                addr: at,
                real,
            });
        }
        found.push((header, real));
    }
    plan.task_ids.sort();
    found
}

/// The tokio `ThreadId` space: the id each thread's `Context` records,
/// by that thread's canonical order; then a local set's recorded owner
/// that no live thread holds, by the set's own thread.
fn threads<T: Target>(
    ctx: &Context<'_, T>,
    target: &T,
    e: &Enumeration<'_>,
    sets: &[LocalSetRef<'_>],
    rank: &HashMap<u32, u64>,
    plan: &mut Plan,
) {
    let mut claims: Vec<(IdKey, u64)> = Vec::new();
    for worker in &e.workers {
        let slot = ctx
            .context_info(worker.context_addr)
            .and_then(|info| ctx.walk(WalkRole::ContextThreadId).walk_at(info));
        let key = (0, rank.get(&worker.tid).copied().unwrap_or(u64::MAX));
        claim(target, Space::Thread, word(slot), key, &mut claims, plan);
    }
    for set in sets {
        let slot = ctx.walk(WalkRole::LocalSetOwner).walk_at(set.shared);
        let key = (1, owner_rank(set, rank));
        claim(target, Space::Thread, word(slot), key, &mut claims, plan);
    }
    plan.thread_ids = number_space(Space::Thread, THREAD_BASE, claims, &mut plan.ties);
}

/// The owned-list space: each runtime's list, by its first thread in
/// canonical order; each local set's, by the set's own thread; then an
/// owner id only task headers carry, by the task.
fn owned<T: Target>(
    ctx: &Context<'_, T>,
    target: &T,
    e: &Enumeration<'_>,
    sets: &[LocalSetRef<'_>],
    members: &[(u64, u64)],
    rank: &HashMap<u32, u64>,
    plan: &mut Plan,
) {
    let mut claims: Vec<(IdKey, u64)> = Vec::new();
    for runtime in &e.runtimes {
        let slot = ctx
            .walk(WalkRole::HandleShared)
            .walk_at(runtime.handle)
            .and_then(|shared| ctx.walk(WalkRole::SchedulerOwnedId).walk_at(shared));
        let first = runtime
            .worker_tids
            .iter()
            .filter_map(|tid| rank.get(tid))
            .min()
            .copied()
            .unwrap_or(u64::MAX);
        claim(
            target,
            Space::Owned,
            word(slot),
            (0, first),
            &mut claims,
            plan,
        );
    }
    for set in sets {
        let slot = ctx.walk(WalkRole::LocalOwnedId).walk_at(set.shared);
        let key = (1, owner_rank(set, rank));
        claim(target, Space::Owned, word(slot), key, &mut claims, plan);
    }
    let headers = e
        .list
        .tasks
        .iter()
        .filter_map(|task| Some((task.addr.0, task.task_id?)))
        .chain(members.iter().copied());
    for (header, task) in headers {
        let canonical = plan
            .task_ids
            .iter()
            .find(|(r, _)| *r == task)
            .map_or(u64::MAX, |(_, c)| *c);
        let at = header_value(ctx, target, header)
            .and_then(|header| word(ctx.walk(WalkRole::HeaderOwnerId).walk_at(header)));
        claim(target, Space::Owned, at, (2, canonical), &mut claims, plan);
    }
    plan.owned_ids = number_space(Space::Owned, OWNED_BASE, claims, &mut plan.ties);
}

/// The canonical rank of the thread a local set belongs to, or after
/// every thread when none live does.
fn owner_rank(set: &LocalSetRef<'_>, rank: &HashMap<u32, u64>) -> u64 {
    set.owner_tid
        .and_then(|tid| rank.get(&tid).copied())
        .unwrap_or(u64::MAX)
}

/// The address of a word a walk reached, when it is one.
fn word<E>(slot: std::result::Result<Value<'_>, E>) -> Option<u64> {
    slot.ok().filter(|v| v.ty.size() == 8).map(|v| v.addr)
}

/// Record the id at `at`, if it holds one (zero is `None` for every
/// id tokio counts from one), as a holder of `space` claiming `key`.
fn claim<T: Target>(
    target: &T,
    space: Space,
    at: Option<u64>,
    key: IdKey,
    claims: &mut Vec<(IdKey, u64)>,
    plan: &mut Plan,
) {
    let Some(at) = at else { return };
    let Some(real) = target.read_u64(at).ok().filter(|&id| id != 0) else {
        return;
    };
    claims.push((key, real));
    plan.holders.push(Holder {
        space,
        addr: at,
        real,
    });
}

/// Number a space from `base`: each real id at the least key any of its
/// holders claims for it, in key order. Two ids at one key are told
/// apart only by their raw values, which is recorded as a tie.
fn number_space(
    space: Space,
    base: u64,
    claims: Vec<(IdKey, u64)>,
    ties: &mut Vec<String>,
) -> Vec<(u64, u64)> {
    let mut least: BTreeMap<u64, IdKey> = BTreeMap::new();
    for (key, real) in claims {
        least
            .entry(real)
            .and_modify(|k| *k = (*k).min(key))
            .or_insert(key);
    }
    let mut order: Vec<(IdKey, u64)> = least.into_iter().map(|(real, key)| (key, real)).collect();
    order.sort();
    for pair in order.windows(2) {
        if pair[0].0 == pair[1].0 {
            ties.push(format!(
                "{space:?} ids {} and {} share the key {:?}",
                pair[0].1, pair[1].1, pair[0].0
            ));
        }
    }
    let mut renaming: Vec<(u64, u64)> = order
        .iter()
        .enumerate()
        .map(|(i, (_, real))| (*real, base + i as u64))
        .collect();
    renaming.sort();
    renaming
}

/// The thread a program starts on.
const ROLE_MAIN: u8 = 0;
/// A multi_thread runtime's worker.
const ROLE_WORKER: u8 = 1;
/// A current_thread runtime's `block_on` thread.
const ROLE_BLOCK_ON: u8 = 2;
/// A thread that entered a runtime without running its scheduler: a
/// blocking-pool thread, a `block_on` caller of a multi_thread runtime.
const ROLE_ENTERED: u8 = 3;
/// Any other thread of the program's.
const ROLE_OTHER: u8 = 4;
/// The lwp the capture made, not the program.
const ROLE_AGENT: u8 = 5;

/// The task header at `header`, read as the bundle's `Header` type.
fn header_value<'b, T: Target>(
    ctx: &Context<'b, T>,
    target: &'b T,
    header: u64,
) -> Option<Value<'b>> {
    let header_ty = ctx
        .infra_ty(ctx.view.bundle().infra.header, "task Header")
        .ok()?;
    Value::read(target, header_ty, header).ok()
}

/// The address of the task id word of the task whose header is at
/// `header`: where the vtable the header names says it is.
fn id_word<T: Target>(ctx: &Context<'_, T>, target: &T, header: u64) -> Option<u64> {
    let infra = &ctx.view.bundle().infra;
    let header_value = header_value(ctx, target, header)?;
    let vtable: u64 = ctx.walk(WalkRole::HeaderVtable).read(header_value).ok()?;
    let vtable_ty = ctx.infra_ty(infra.vtable, "task Vtable").ok()?;
    let vtable_value = Value::read(target, vtable_ty, vtable).ok()?;
    let offset: u64 = ctx.walk(WalkRole::VtableIdOffset).read(vtable_value).ok()?;
    header.checked_add(offset)
}

/// Overlay the little-endian word `value` at `addr`.
fn overlay(patches: &mut BTreeMap<u64, u8>, addr: u64, value: u64) {
    for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
        patches.insert(addr + i as u64, byte);
    }
}

impl<T: Target> Target for Canonical<T> {
    fn read_bytes(&self, addr: u64, len: u64) -> Result<&[u8]> {
        let bytes = self.inner.read_bytes(addr, len)?;
        let Some(overlaid) = self.overlaid(addr, len) else {
            return Ok(bytes);
        };
        let mut lent = self.lent.lock().unwrap_or_else(|e| e.into_inner());
        let copy = lent.entry((addr, len)).or_insert_with(|| {
            let mut copy = bytes.to_vec().into_boxed_slice();
            for (at, byte) in overlaid {
                copy[(at - addr) as usize] = byte;
            }
            copy
        });
        let ptr: *const [u8] = &**copy;
        // SAFETY: the copy is a heap allocation owned by `self.lent`,
        // which only ever inserts: an entry is never removed or
        // replaced, and a map rehashing moves the `Box`, not the bytes
        // it points to. So the bytes live, unmoved and unwritten, until
        // `self` is dropped, which is the lifetime the slice is lent
        // for.
        Ok(unsafe { &*ptr })
    }

    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        self.inner.readable_len(addr, max)
    }

    fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
        self.inner.lookup_symbol_by_addr(addr)
    }

    fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
        self.inner.lookup_symbol_by_name(name)
    }

    fn symbols(&self) -> Result<Vec<SymbolBuf>> {
        self.inner.symbols()
    }

    fn object_symbols(&self) -> Result<Vec<SymbolBuf>> {
        self.inner.object_symbols()
    }

    fn fatal_signal(&self) -> Option<FatalSignal> {
        self.inner.fatal_signal()
    }

    fn lwp_name(&self, tid: u32) -> Option<String> {
        self.inner.lwp_name(self.real_tid(tid)?)
    }

    fn agent_lwp(&self) -> Option<u32> {
        self.canonical_tid(self.inner.agent_lwp()?)
    }

    fn process_facts(&self) -> Option<ProcessFacts> {
        self.inner.process_facts()
    }

    fn exec_path(&self) -> Option<PathBuf> {
        self.inner.exec_path()
    }

    fn build_ids(&self) -> Option<BuildIds> {
        self.inner.build_ids()
    }

    fn backing_file_problem(&self, path: &str) -> Option<String> {
        self.inner.backing_file_problem(path)
    }

    fn recorded_heap_evidence(&self) -> Option<RecordedHeapEvidence> {
        self.inner.recorded_heap_evidence()
    }

    fn mappings(&self) -> Result<Mappings> {
        self.inner.mappings()
    }

    fn captured_runs(&self) -> Option<Vec<Range<u64>>> {
        self.inner.captured_runs()
    }

    /// The real lwps, renamed, in canonical order.
    fn lwps(&self) -> Result<Vec<LwpInfo>> {
        let mut lwps: Vec<LwpInfo> = self
            .inner
            .lwps()?
            .into_iter()
            .map(|mut lwp| {
                lwp.tid = self.canonical_tid(lwp.tid).unwrap_or(lwp.tid);
                lwp
            })
            .collect();
        lwps.sort_by_key(|lwp| lwp.tid);
        Ok(lwps)
    }

    fn read_u64(&self, addr: u64) -> Result<u64> {
        let bytes = self.read_bytes(addr, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u32(&self, addr: u64) -> Result<u32> {
        let bytes = self.read_bytes(addr, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u16(&self, addr: u64) -> Result<u16> {
        let bytes = self.read_bytes(addr, 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn read_u8(&self, addr: u64) -> Result<u8> {
        Ok(self.read_bytes(addr, 1)?[0])
    }

    fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        self.inner.tls_var_addr(regs, sym)
    }

    /// Forwarded: a thread-local word is a pointer to the thread's
    /// state, never one of the overlaid ids.
    fn tls_word(&self, regs: &Regs, sym: &SymbolBuf) -> Result<Option<u64>> {
        self.inner.tls_word(regs, sym)
    }

    fn exec_bias(&self) -> Option<u64> {
        self.inner.exec_bias()
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Canonical<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Canonical")
            .field("inner", &self.inner)
            .field("tids", &self.tids)
            .field("task_ids", &self.task_ids)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, PROGRAMS, fixture_sets};

    /// Every name the analysis reads back is a renamed one, and the
    /// right one: each task at its header carries the canonical id of
    /// the real id it had there, each lwp the canonical tid of its real
    /// tid, and each worker's current task the same canonical id the
    /// task itself now carries; every word of every id space reads back
    /// renamed; every canonical name is dense from its base, so no real
    /// one slipped through; and no space numbered two ids by their raw
    /// values for want of anything the program decided between them.
    #[test]
    fn test_every_task_and_lwp_reads_back_renamed() {
        for set in fixture_sets() {
            for program in PROGRAMS {
                let (bundle, raw) = testkit::load(set, program);
                let (_, again) = testkit::load(set, program);
                let renamed = Canonical::new(again, &bundle);
                let what = format!("[{set}] {program}");

                let raw_ctx = testkit::context(&bundle, &raw);
                let raw_tasks = testkit::tasks(&raw_ctx, &raw);
                let ctx = Context::new(&renamed, BundleView::new(&bundle)).unwrap();
                let tasks = testkit::tasks(&ctx, &renamed);
                let task_ids: HashMap<u64, u64> = renamed.task_renaming().iter().copied().collect();
                for task in &raw_tasks.tasks {
                    let Some(real) = task.task_id else { continue };
                    let read = tasks
                        .tasks
                        .iter()
                        .find(|t| t.addr == task.addr)
                        .and_then(|t| t.task_id);
                    assert_eq!(read, task_ids.get(&real).copied(), "{what}: task {real}");
                }
                let mut canonical: Vec<u64> = task_ids.values().copied().collect();
                canonical.sort_unstable();
                assert!(
                    canonical
                        .iter()
                        .copied()
                        .eq(TASK_BASE..TASK_BASE + canonical.len() as u64),
                    "{what}: {canonical:?}"
                );

                let tids: Vec<u32> = renamed.lwps().unwrap().iter().map(|l| l.tid).collect();
                let expected: Vec<u32> = (0..tids.len() as u32).map(|i| TID_BASE + i).collect();
                assert_eq!(tids, expected, "{what}");
                for lwp in raw.lwps().unwrap() {
                    let tid = renamed
                        .canonical_tid(lwp.tid)
                        .expect("every lwp is renamed");
                    assert_eq!(renamed.real_tid(tid), Some(lwp.tid), "{what}");
                }

                // Every word of every space reads back as its id's
                // canonical one, each space is dense from its base, and
                // nothing numbered by a raw value for want of a key.
                assert_eq!(renamed.ties(), &[] as &[String], "{what}");
                for (space, base, renaming) in [
                    (Space::Task, TASK_BASE, renamed.task_renaming()),
                    (Space::Thread, THREAD_BASE, renamed.thread_renaming()),
                    (Space::Owned, OWNED_BASE, renamed.owned_renaming()),
                ] {
                    let map: HashMap<u64, u64> = renaming.iter().copied().collect();
                    for holder in renamed.holders().iter().filter(|h| h.space == space) {
                        assert_eq!(
                            renamed.read_u64(holder.addr).ok(),
                            map.get(&holder.real).copied(),
                            "{what}: {space:?} id {} at {:#x}",
                            holder.real,
                            holder.addr
                        );
                    }
                    let mut ids: Vec<u64> = map.values().copied().collect();
                    ids.sort_unstable();
                    assert!(
                        ids.iter().copied().eq(base..base + ids.len() as u64),
                        "{what}: {space:?} {ids:?}"
                    );
                }

                let raw_lwps = raw.lwps().unwrap();
                let lwps = renamed.lwps().unwrap();
                let raw_workers = raw_ctx.find_workers(&raw_lwps).unwrap();
                let workers = ctx.find_workers(&lwps).unwrap();
                for worker in &raw_workers {
                    let tid = renamed.canonical_tid(worker.tid).unwrap();
                    let read = workers.iter().find(|w| w.tid == tid).unwrap();
                    assert_eq!(
                        read.current_task_id,
                        worker.current_task_id.map(|id| task_ids[&id]),
                        "{what}: lwp {}",
                        worker.tid
                    );
                }
            }
        }
    }
}

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
//! every word holding a task id — the task's own and each worker's
//! current-task slot — reads back as a canonical id from [`TASK_BASE`].
//! Memory and symbols otherwise pass through untouched, and nothing
//! outside this module knows the renaming happened.
//!
//! The renaming is sound only while nothing joins memory against an lwp
//! id, and while every task id the analysis reads is one of the words
//! overlaid; the guard test holds a renamed run's output to the raw
//! run's, with both renamings undone.

use crate::testkit;
use crate::tokio::bundle::Context;

use hansei_bundle::{Bundle, BundleView, WalkRole};
use proc::snapshot::RecordedHeapEvidence;
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

/// Patched copies of reads, by the read they answer.
type Lent = Mutex<HashMap<(u64, u64), Box<[u8]>>>;

/// What [`plan`] decides: the tid renaming, the task id renaming, and
/// the overlay that carries out the second.
type Plan = (Vec<(u32, u32)>, Vec<(u64, u64)>, BTreeMap<u64, u8>);

/// `inner` with its lwps and task ids renamed. See the module docs.
pub struct Canonical<T> {
    inner: T,
    /// Real tid to canonical, and back.
    tids: Vec<(u32, u32)>,
    /// Real task id to canonical.
    task_ids: Vec<(u64, u64)>,
    /// The overlay, byte by byte: what each overlaid address reads as.
    patches: BTreeMap<u64, u8>,
    /// Patched copies of the reads that crossed an overlaid byte, kept
    /// for as long as `self` so the slices lent out of them live as
    /// long as a read of `inner` would. Keyed by the read, so a read
    /// asked again is answered from the copy it made the first time.
    lent: Lent,
}

impl<T: Target> Canonical<T> {
    /// Rename `inner`'s lwps and task ids, reading it through `bundle`
    /// the way a session does. A target the pipeline cannot read is
    /// renamed as far as it got: every lwp by its real tid, and no task.
    pub fn new(inner: T, bundle: &Bundle) -> Self {
        let (tids, task_ids, patches) = plan(&inner, bundle);
        Canonical {
            inner,
            tids,
            task_ids,
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

    /// The overlaid bytes in `addr..addr + len`, if any.
    fn overlaid(&self, addr: u64, len: u64) -> Option<impl Iterator<Item = (u64, u8)> + '_> {
        let end = addr.checked_add(len)?;
        let mut range = self.patches.range(addr..end).peekable();
        range.peek()?;
        Some(range.map(|(a, b)| (*a, *b)))
    }
}

/// Order `target`'s lwps and tasks and plan the overlay that renames
/// its task ids.
fn plan<T: Target>(target: &T, bundle: &Bundle) -> Plan {
    let lwps = target.lwps().unwrap_or_default();
    let mut keys: BTreeMap<u32, (u8, usize, String)> = lwps
        .iter()
        .map(|lwp| (lwp.tid, (ROLE_OTHER, 0, String::new())))
        .collect();
    let mut task_ids = Vec::new();
    let mut patches = BTreeMap::new();

    if let Ok(ctx) = Context::new(target, BundleView::new(bundle))
        && let Ok(mut e) = testkit::try_enumerate(&ctx, target)
    {
        e.discover(&ctx, &[]);
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

        // Each task's canonical id, by what the program decided.
        let mut tasks: Vec<(String, u64, u64)> = e
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
        tasks.sort();
        let mut by_real = HashMap::new();
        for (i, (_, real, header)) in tasks.iter().enumerate() {
            let canonical = TASK_BASE + i as u64;
            by_real.insert(*real, canonical);
            task_ids.push((*real, canonical));
            if let Some(at) = id_word(&ctx, target, *header) {
                overlay(&mut patches, at, canonical);
            }
        }
        // Each worker's current-task slot names a task by the same id —
        // or one no list holds, a task between lists as the core was
        // taken, which is numbered after every listed one, in the
        // workers' own order.
        let mut workers: Vec<&_> = e.workers.iter().collect();
        workers.sort_by_key(|w| (keys.get(&w.tid).cloned(), w.tid));
        for worker in workers {
            let Some(real) = worker.current_task_id else {
                continue;
            };
            let next = TASK_BASE + by_real.len() as u64;
            let canonical = *by_real.entry(real).or_insert_with(|| {
                task_ids.push((real, next));
                next
            });
            let slot = ctx
                .context_info(worker.context_addr)
                .and_then(|info| ctx.walk(WalkRole::CurrentTaskId).walk_at(info));
            if let Ok(slot) = slot
                && slot.ty.size() == 8
                && target.read_u64(slot.addr).ok() == Some(real)
            {
                overlay(&mut patches, slot.addr, canonical);
            }
        }
        task_ids.sort();
    }
    if let Some(agent) = target.agent_lwp()
        && let Some(key) = keys.get_mut(&agent)
    {
        key.0 = ROLE_AGENT;
    }

    let mut order: Vec<(&(u8, usize, String), u32)> =
        keys.iter().map(|(tid, key)| (key, *tid)).collect();
    order.sort();
    let tids = order
        .iter()
        .enumerate()
        .map(|(i, (_, real))| (*real, TID_BASE + i as u32))
        .collect();
    (tids, task_ids, patches)
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

/// The address of the task id word of the task whose header is at
/// `header`: where the vtable the header names says it is.
fn id_word<T: Target>(ctx: &Context<'_, T>, target: &T, header: u64) -> Option<u64> {
    let infra = &ctx.view.bundle().infra;
    let header_ty = ctx.infra_ty(infra.header, "task Header").ok()?;
    let header_value = Value::read(target, header_ty, header).ok()?;
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
    /// task itself now carries — and every canonical name is dense from
    /// its base, so no real one slipped through.
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

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bundle-based parsing of tokio runtime state.
//!
//! Layouts come only from the bundle; addresses and bytes come only from the
//! target; the only thing that crosses between the two binaries is symbol
//! names. Runtime discovery is the pthread-key flow: the bundle names the
//! TLS-key static, the target's symtab locates it, and its value indexes
//! each LWP's fast-TSD slots to find that thread's
//! `tokio::runtime::context::Context`.

pub use super::model::*;

use super::contract::{self, ContractReport, WalkPolicy, Walked};
use super::{Location, RawInstant, TaskAddr, TaskState};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use hansei_bundle::symbols::normalized_v0_key;
use hansei_bundle::{
    BundleType, BundleTypeId, BundleView, DynPointer, FutureKind, StaticRole, SymbolLookup,
    TaskEntryId, TaskFutureEntry, TypeDef, WalkOutcome, WalkRole, strip_build_prefix,
    strip_llvm_suffix,
};
use proc::{LwpInfo, Mappings, SymbolBuf, Target};
use reify::Value;

use foldhash::{HashMap, HashSet};
use std::cell::RefCell;

use std::collections::BTreeMap;

/// Hard bound on await-chain depth: anything deeper indicates corrupt
/// memory (or a pathological program), and the walk must report it
/// rather than hang.
const MAX_AWAIT_DEPTH: usize = 64;

/// How far to unwrap a member's type looking for the future inside it
/// (see [`Context::is_future`]). Real wrapper stacks are two or three
/// deep; the bound is what keeps a recursive type from spinning.
const MAX_WRAPPER_DEPTH: usize = 8;

/// Rust vtables place the drop-in-place glue in slot 0, size and align
/// in slots 1 and 2, and the trait's methods after; `Future`'s only
/// method is `poll`, so it is slot 3.
const VTABLE_SLOT_DROP: u64 = 0;
const VTABLE_SLOT_FUTURE_POLL: u64 = 3;

/// The leaf-future knowledge base: the wait primitives hansei
/// can interpret, keyed by leaf type name
/// ([`contract::leaf_matches`]). It grows one row (and one reader fn)
/// at a time, with no structural change.
///
/// The chain walker consults it too: a matching awaitee is a leaf even
/// when it peels to a pointer — a `JoinHandle` peels to the joined
/// task's `NonNull<Header>`, and following that would walk into another
/// task entirely.
const LEAF_FUTURES: &[(&str, LeafKind)] = &[
    (contract::SLEEP, LeafKind::Sleep),
    (contract::JOIN_HANDLE, LeafKind::JoinHandle),
    (contract::ACQUIRE, LeafKind::SemaphoreAcquire),
];

#[derive(Copy, Clone, Debug)]
pub(crate) enum LeafKind {
    Sleep,
    JoinHandle,
    SemaphoreAcquire,
}

/// The list a task's recorded scheduler `S` binds it into — see
/// [`Context::scheduler_kind`].
#[derive(Copy, Clone, Debug)]
enum SchedulerKind {
    LocalSet,
    Blocking,
    MultiThread,
    CurrentThread,
    Unknown,
}

/// Whether an `Arc<…>` type name's first parameter is exactly `inner`.
/// The next character must close the parameter — `,` before the
/// allocator or `>` without one — so a name cannot take a lookalike
/// sibling with it, the same exactness the leaf keys keep.
fn arc_of(name: &str, inner: &str) -> bool {
    let Some(rest) = name.strip_prefix("alloc::sync::Arc<") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(inner) else {
        return false;
    };
    rest.starts_with(',') || rest.starts_with('>')
}

pub(crate) fn leaf_kind(name: &str) -> Option<LeafKind> {
    LEAF_FUTURES
        .iter()
        .find(|(key, _)| contract::leaf_matches(key, name))
        .map(|(_, kind)| *kind)
}

/// Awaiter-frame prefixes naming the primitive whose semaphore an
/// `Acquire` leaf is queued on.
const SEMAPHORE_OWNERS: &[(&str, &str)] = &[
    ("tokio::sync::mutex::", "tokio::sync::Mutex"),
    ("tokio::sync::rwlock", "tokio::sync::RwLock"),
    ("tokio::sync::semaphore", "tokio::sync::Semaphore"),
];

/// The primitive wrapping an acquired semaphore, when a frame above the
/// `Acquire` leaf names it.
///
/// The search runs up the chain rather than reading the frame directly
/// above the leaf: a wrapper the walk now follows (`Instrumented`, a
/// `Map`) can sit between `Mutex::lock`'s coroutine and the `Acquire` it
/// awaits, and a fixed offset would read that wrapper and report a
/// semaphore nobody owns.
fn semaphore_owner(chain: &AwaitChain<'_>) -> Option<&'static str> {
    chain.frames.iter().rev().skip(1).find_map(|frame| {
        let name = frame.future.ty.name();
        SEMAPHORE_OWNERS
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix))
            .map(|(_, owner)| *owner)
    })
}

/// A get-or-compute cache behind a `RefCell`, for the per-target
/// lookup memos below: one command asks about the same few dozen keys
/// tens of thousands of times.
struct Memo<K, V>(RefCell<HashMap<K, V>>);

// Not derived: the derive would demand `K: Default + V: Default` for a
// bound neither the map nor the cell needs.
impl<K, V> Default for Memo<K, V> {
    fn default() -> Self {
        Memo(RefCell::new(HashMap::default()))
    }
}

impl<K: Eq + std::hash::Hash, V: Clone> Memo<K, V> {
    fn get_or<Q>(&self, key: &Q, compute: impl FnOnce() -> V) -> V
    where
        Q: Eq + std::hash::Hash + ToOwned<Owned = K> + ?Sized,
        K: std::borrow::Borrow<Q>,
    {
        if let Some(hit) = self.0.borrow().get(key) {
            return hit.clone();
        }
        let value = compute();
        self.0.borrow_mut().insert(key.to_owned(), value.clone());
        value
    }
}

/// Everything needed to interpret a target process through a loaded bundle.
pub struct Context<'b, T> {
    pub proc: &'b T,
    pub view: BundleView<'b>,
    pub mappings: Mappings,
    /// Target text address → mangled symtab name (`None` when the address
    /// resolves to no symbol). Mangled names are the join keys; demangling
    /// is display-only.
    symbols: Memo<u64, Option<String>>,
    /// Normalized object-symbol name → target symbols. Populated lazily
    /// because most commands do not need named statics.
    object_symbols: RefCell<Option<HashMap<String, Vec<SymbolBuf>>>>,
    /// Task vtables decoded from target memory, keyed by vtable address.
    vtables: RefCell<HashMap<u64, TaskVtable>>,
    /// Memoized address of tokio's task `WAKER_VTABLE` static in the
    /// target, including a cached diagnostic when resolution is ambiguous.
    waker_vtable: RefCell<Option<std::result::Result<Option<u64>, String>>>,
    /// Memoized stop time of the target on its own monotonic clock (see
    /// [`Context::stopped_at`]).
    stopped: RefCell<Option<Option<RawInstant>>>,
    /// Memo of the task join's symbol resolution. Against a rebuilt
    /// target every lookup misses the exact table and pays a demangle,
    /// and the same few dozen symbols are asked about tens of thousands
    /// of times in one command.
    task_lookups: Memo<String, SymbolLookup<TaskEntryId>>,
    /// The same memo for the dyn-future join.
    dyn_future_lookups: Memo<String, SymbolLookup<BundleTypeId>>,
    /// Every type the bundle recorded a `Future::poll` impl for, which is
    /// what lets the await chain tell a wrapper's inner future from the
    /// rest of its members. Collected once: the walk asks per member of
    /// per frame of per task.
    futures: HashSet<BundleTypeId>,
    /// The walk contract resolved against this bundle at attach time.
    contract: ContractReport,
}

impl<'b, T: Target> Context<'b, T> {
    /// Attach strictly: any walk-contract breakage refuses, so a tokio
    /// whose layouts have moved is a comprehensive report up front, not
    /// a mid-walk failure or a silently degraded listing.
    pub fn new(proc: &'b T, view: BundleView<'b>) -> Result<Self> {
        Self::with_policy(proc, view, WalkPolicy::Strict)
    }

    /// Attach under the given policy; [`WalkPolicy::BestEffort`] walks
    /// past broken non-essential paths, degrading at the site that
    /// reads them. The report is kept either way
    /// ([`Context::contract_report`]).
    pub fn with_policy(proc: &'b T, view: BundleView<'b>, policy: WalkPolicy) -> Result<Self> {
        let mappings = proc.mappings().context("failed to read target mappings")?;
        let contract = contract::verify_walk_contract(&view);
        contract.check(policy)?;
        Ok(Self {
            proc,
            view,
            mappings,
            symbols: Memo::default(),
            object_symbols: RefCell::new(None),
            vtables: RefCell::new(HashMap::default()),
            waker_vtable: RefCell::new(None),
            stopped: RefCell::new(None),
            task_lookups: Memo::default(),
            dyn_future_lookups: Memo::default(),
            futures: view.future_type_ids().collect(),
            contract,
        })
    }

    /// The walk contract as it resolved against this bundle: which
    /// alternative spellings bound, and — under
    /// [`WalkPolicy::BestEffort`] — which paths are broken and will
    /// degrade when something walks them.
    pub fn contract_report(&self) -> &ContractReport {
        &self.contract
    }

    /// The target's monotonic clock at the moment it stopped: the latest lwp
    /// stop timestamp (`pr_tstamp`, which illumos stamps from the same
    /// `gethrtime` clock `Instant` reads). For a core that is the moment it
    /// was dumped — "now" as of everything else this session reads. `None` when no
    /// lwp reports a usable stamp — a Linux core records no stop times, and
    /// its reader fills the field with zero, which no real clock reads.
    fn stopped_at(&self) -> Option<RawInstant> {
        *self.stopped.borrow_mut().get_or_insert_with(|| {
            let zero = proc::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let lwps = self.proc.lwps().ok()?;
            let latest = lwps
                .iter()
                .map(|lwp| lwp.tstamp)
                .filter(|tstamp| *tstamp != zero)
                .max()?;
            RawInstant::try_from(latest).ok()
        })
    }

    /// Resolve an infra type id to a usable layout, rejecting the opaque
    /// placeholders `--allow-missing-infra` extraction leaves behind.
    fn infra_ty(&self, id: BundleTypeId, what: &str) -> Result<BundleType<'b>> {
        let ty = self
            .view
            .ty(id)
            .ok_or_else(|| anyhow!("bundle has no type entry for {what}"))?;
        if matches!(ty.def(), TypeDef::Opaque { .. }) {
            bail!(
                "bundle has no layout for {what} \
                 (was it extracted with --allow-missing-infra?)"
            );
        }
        Ok(ty)
    }

    /// The mangled symtab name covering `addr`, if any (cached).
    fn symbol_at(&self, addr: u64) -> Option<String> {
        self.symbols.get_or(&addr, || {
            self.proc.lookup_symbol_by_addr(addr).map(|s| s.name)
        })
    }

    /// [`BundleView::task_ids_for_symbol`], answered from
    /// [`Context::task_lookups`] when the symbol has been asked before.
    fn task_ids_memoized(&self, symbol: &str) -> SymbolLookup<TaskEntryId> {
        self.task_lookups
            .get_or(symbol, || self.view.task_ids_for_symbol(symbol))
    }

    /// [`BundleView::dyn_future_ids_for_symbol`], answered from
    /// [`Context::dyn_future_lookups`] when the symbol has been asked
    /// before.
    fn dyn_future_ids_memoized(&self, symbol: &str) -> SymbolLookup<BundleTypeId> {
        self.dyn_future_lookups
            .get_or(symbol, || self.view.dyn_future_ids_for_symbol(symbol))
    }

    /// Resolve a named static exactly when possible, then by a normalized v0
    /// key. Aliases at one address are benign; multiple addresses are not.
    fn object_symbol(&self, name: &str) -> Result<Option<SymbolBuf>> {
        if let Some(symbol) = self.proc.lookup_symbol_by_name(name) {
            return Ok(Some(symbol));
        }
        let Some(key) = normalized_v0_key(name) else {
            return Ok(None);
        };
        if self.object_symbols.borrow().is_none() {
            let mut index: HashMap<String, Vec<SymbolBuf>> = HashMap::default();
            for symbol in self.proc.object_symbols()? {
                if let Some(key) = normalized_v0_key(&symbol.name) {
                    index.entry(key).or_default().push(symbol);
                }
            }
            *self.object_symbols.borrow_mut() = Some(index);
        }
        let symbols = self.object_symbols.borrow();
        let Some(candidates) = symbols.as_ref().unwrap().get(&key) else {
            return Ok(None);
        };
        let by_addr: BTreeMap<u64, &SymbolBuf> = candidates
            .iter()
            .map(|symbol| (symbol.st_value, symbol))
            .collect();
        match by_addr.len() {
            0 => Ok(None),
            1 => Ok(Some((*by_addr.values().next().unwrap()).clone())),
            _ => bail!(
                "normalized static {name} matched multiple target addresses: {}",
                by_addr
                    .keys()
                    .map(|addr| format!("{addr:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Attach-time validation
    // -----------------------------------------------------------------------

    /// Resolve the bundle's symbol fingerprint against the target's symtab.
    ///
    /// A less-than-complete match means the target was not built from the
    /// same commit/toolchain/flags as the debug binary, and interpreting it
    /// with this bundle would misparse memory.
    pub fn validate_fingerprint(&self) -> Fingerprint {
        let syms = &self.view.bundle().meta.symbol_fingerprint;
        let mut missing: Vec<String> = syms
            .iter()
            .filter(|s| self.proc.lookup_symbol_by_name(s).is_none())
            .cloned()
            .collect();

        // A symbol may exist in the target only as `.llvm.<hash>`-suffixed
        // internalized copies; those still count as a match (the suffix is
        // path-sensitive and never participates in joins).
        if !missing.is_empty()
            && let Ok(all) = self.proc.symbols()
        {
            let stripped: HashSet<&str> = all.iter().map(|s| strip_llvm_suffix(&s.name)).collect();
            missing.retain(|s| !stripped.contains(s.as_str()));

            if !missing.is_empty() {
                let normalized = normalized_key_set(&all);
                missing
                    .retain(|s| normalized_v0_key(s).is_none_or(|key| !normalized.contains(&key)));
            }
        }

        Fingerprint {
            total: syms.len(),
            matched: syms.len() - missing.len(),
            missing,
        }
    }

    // -----------------------------------------------------------------------
    // Runtime discovery
    // -----------------------------------------------------------------------

    /// The symbol under which each thread stores its
    /// `tokio::runtime::context::Context`: the bundle names the static and
    /// the target's symtab locates it.
    ///
    /// What the symbol *means* is the target's business, not the bundle's —
    /// a `pthread_key_t` on illumos, an offset into the thread's TLS block
    /// on Linux — so this resolves the symbol and hands it straight to
    /// [`Target::tls_var_addr`].
    pub fn tls_context_symbol(&self) -> Result<SymbolBuf> {
        let def = self
            .view
            .bundle()
            .statics
            .entries
            .get(&StaticRole::TlsContextKey)
            .ok_or_else(|| {
                anyhow!(
                    "bundle records no TLS context static \
                     (was it extracted with --allow-missing-infra?)"
                )
            })?;
        self.object_symbol(&def.symbol)?.ok_or_else(|| {
            anyhow!(
                "TLS context static {} ({}) not found in the target's symtab; \
                 wrong binary, or symtab stripped?",
                def.display,
                def.symbol
            )
        })
    }

    /// Probe every LWP for a live `Context` (all LWPs, never thread
    /// names). LWPs holding none are skipped; an LWP whose `Context` fails
    /// to parse is an error, not a skip — the target told us it has one.
    pub fn find_workers(&self, lwps: &[LwpInfo]) -> Result<Vec<Worker>> {
        let sym = self.tls_context_symbol()?;
        let mut workers = Vec::new();
        let mut failure = None;
        for lwp in lwps {
            let addr = match self.proc.tls_var_addr(&lwp.regs, &sym) {
                Ok(Some(addr)) => addr,
                Ok(None) => continue,
                // Some LWPs (e.g. exiting ones) cannot be reached through
                // whatever the target's TLS model walks. That is ordinary
                // enough to skip, but if it turns out that *no* LWP
                // resolved, the first reason is worth reporting rather
                // than claiming the process runs no tokio runtime.
                Err(e) => {
                    failure.get_or_insert((lwp.tid, e));
                    continue;
                }
            };
            if !self.mappings.contains_addr(addr) {
                continue;
            }
            let worker = self
                .worker_at(lwp.tid, addr)
                .with_context(|| format!("failed to parse Context of LWP {}", lwp.tid))?;
            workers.push(worker);
        }
        if workers.is_empty()
            && let Some((tid, e)) = failure
        {
            return Err(anyhow::Error::new(e).context(format!(
                "no LWP holds a tokio Context; reading {} of LWP {tid} failed",
                sym.name
            )));
        }
        Ok(workers)
    }

    /// Parse the thread-local `Context` at `context_addr`, as found via
    /// the thread-local the bundle names.
    pub fn worker_at(&self, tid: u32, context_addr: u64) -> Result<Worker> {
        let info = self.context_info(context_addr)?;
        let current_task_id = self
            .walk(WalkRole::CurrentTaskId)
            .read(info)
            .context("failed to parse Context.current_task_id")?;
        Ok(Worker {
            tid,
            context_addr,
            current_task_id,
        })
    }

    /// The thread-local `tokio::runtime::context::Context` at `addr`, as
    /// [`Context::find_workers`] located it.
    pub fn context_info(&self, addr: u64) -> Result<Value<'b>> {
        let ty = self.infra_ty(
            self.view.bundle().infra.context,
            "tokio::runtime::context::Context",
        )?;
        Value::read(self.proc, ty, addr)
            .with_context(|| format!("failed to read Context at {addr:#x}"))
    }

    /// Navigate from the workers' `Context`s to every runtime they run:
    /// `Context.current.handle` → `Option<scheduler::Handle>` → the
    /// flavor's variant (`MultiThread(Arc<Handle>)` or
    /// `CurrentThread(Arc<Handle>)`) → deref → `.data`, grouped by
    /// handle address.
    ///
    /// Each handle is the root of everything its runtime shares: the
    /// scheduler state under `shared`, the io/time/signal drivers under
    /// `driver`. The grouping is what current_thread makes necessary:
    /// each `block_on` thread can carry its own runtime, so a process
    /// holding several is ordinary. A multi_thread target's workers all
    /// share one handle, so its vec has one element.
    pub fn find_runtimes(&self, workers: &[Worker]) -> Result<Vec<RuntimeRef<'b>>> {
        let mut runtimes: Vec<RuntimeRef<'b>> = Vec::new();
        for worker in workers {
            let info = self.context_info(worker.context_addr)?;
            let Some((flavor, handle)) = self.flavor_handle(info)? else {
                // No handle in this thread's Context.
                continue;
            };
            match runtimes.iter_mut().find(|r| r.handle.addr == handle.addr) {
                Some(runtime) => runtime.worker_tids.push(worker.tid),
                None => runtimes.push(RuntimeRef {
                    flavor,
                    handle,
                    worker_tids: vec![worker.tid],
                    route: DiscoveryRoute::WorkerContext,
                }),
            }
        }
        if runtimes.is_empty() {
            let outcomes: Vec<String> = [WalkRole::WorkerHandle, WalkRole::CtWorkerHandle]
                .iter()
                .filter_map(|role| self.contract.entry(role.name()))
                .map(|entry| format!("  {}", entry.line()))
                .collect();
            bail!(
                "no worker thread's Context reaches a runtime handle of either \
                 scheduler flavor:\n{}",
                outcomes.join("\n")
            );
        }
        Ok(runtimes)
    }

    /// The flavor handle one thread's `Context` points at, if any. Each
    /// flavor's discovery row is consulted through `try_walk`: a flavor
    /// the target never compiled in is recorded absent, which here means
    /// only that this thread does not run it.
    fn flavor_handle(&self, info: Value<'b>) -> Result<Option<(RuntimeFlavor, Value<'b>)>> {
        for (flavor, role) in [
            (RuntimeFlavor::MultiThread, WalkRole::WorkerHandle),
            (RuntimeFlavor::CurrentThread, WalkRole::CtWorkerHandle),
        ] {
            match self.walk(role).try_walk(info)? {
                Some(Walked::At(handle)) => return Ok(Some((flavor, handle))),
                // The other flavor's variant (or no handle) is live, or
                // the row is absent on this build — try the next flavor.
                Some(Walked::Inactive(_)) | None => {}
                Some(Walked::Null) => bail!("the runtime handle's Arc is null"),
            }
        }
        Ok(None)
    }

    /// The scheduler state a runtime's workers share, from the handle
    /// [`Context::find_runtimes`] reached. Both flavors' `Handle`s spell
    /// the member identically, and the recorded steps resolve by name
    /// against whichever `Shared` this handle actually has.
    pub fn find_shared(&self, runtime: &RuntimeRef<'b>) -> Result<Value<'b>> {
        self.walk(WalkRole::HandleShared).walk_at(runtime.handle)
    }

    /// Every discovered runtime's tasks, merged into one list with the
    /// per-runtime enumeration's own ordering applied across the whole.
    /// Each task is stamped with the index of the runtime that owns it,
    /// so a listing over the merge can still say which is whose.
    pub fn enumerate_all_tasks(&self, runtimes: &[RuntimeRef<'b>]) -> Result<TaskList> {
        let mut all = TaskList {
            tasks: Vec::new(),
            errors: Vec::new(),
        };
        for (index, runtime) in runtimes.iter().enumerate() {
            let shared = self.find_shared(runtime)?;
            let mut list = self.enumerate_tasks(shared)?;
            for task in &mut list.tasks {
                task.group = index;
            }
            all.tasks.extend(list.tasks);
            all.errors.extend(list.errors);
        }
        all.tasks
            .sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        Ok(all)
    }

    /// The scheduler context a worker thread is running under: the
    /// `multi_thread::worker::Context` its stack holds, reached through
    /// the scoped pointer in its thread-local `Context`.
    ///
    /// `None` when the thread is in the runtime without being inside the
    /// scheduler — the pointer is set only for the duration of a
    /// worker's run loop — or when it runs the other scheduler flavor
    /// ([`Context::ct_worker_context`] is the current_thread sibling).
    pub fn worker_context(&self, worker: &Worker) -> Result<Option<Value<'b>>> {
        let info = self.context_info(worker.context_addr)?;
        // The scoped pointer is null outside the run loop, another
        // scheduler flavor may be the live variant, and a build without
        // the multi_thread scheduler records the row absent — all
        // ordinary. Anything else has to be readable: an unreadable
        // pointer is a failure to report, not a thread to pass over.
        Ok(self
            .walk(WalkRole::WorkerContext)
            .try_walk(info)?
            .and_then(Walked::optional))
    }

    /// Which worker of the scheduler a thread is running, as the
    /// scheduler numbers them, from the context
    /// [`Context::worker_context`] returned.
    pub fn worker_index(&self, worker_ctx: Value<'b>) -> Result<u64> {
        self.walk(WalkRole::WorkerIndex).read(worker_ctx)
    }

    /// The current_thread scheduler context a thread is running under —
    /// [`Context::worker_context`]'s sibling for the other flavor. A
    /// thread with one active is a CT runtime's `block_on` thread, the
    /// single "worker" that flavor has.
    pub fn ct_worker_context(&self, worker: &Worker) -> Result<Option<Value<'b>>> {
        let info = self.context_info(worker.context_addr)?;
        Ok(self
            .walk(WalkRole::CtWorkerContext)
            .try_walk(info)?
            .and_then(Walked::optional))
    }

    /// What a CT runtime's `block_on` thread is doing, from the handle
    /// [`Context::find_runtimes`] reached and the scheduler context
    /// [`Context::ct_worker_context`] returned for that thread.
    ///
    /// The core's whereabouts are the state: checked into the context's
    /// `RefCell` while the thread parks (driver taken out of it) or
    /// polls the root future (driver still in it), held on the stack —
    /// unreadable from here — while it runs tasks.
    pub fn ct_park_state(&self, handle: Value<'b>, ct_ctx: Value<'b>) -> Result<CtParkState> {
        let woken = self.walk(WalkRole::CtSharedWoken).read(handle)?;
        let activity = match self.walk(WalkRole::CtWorkerCore).walk(ct_ctx)?.optional() {
            None => CtActivity::RunningTasks,
            Some(core) => match self.walk(WalkRole::CtCoreDriver).walk(core)? {
                Walked::At(_) => CtActivity::PollingBlockOn,
                Walked::Inactive(_) | Walked::Null => CtActivity::Parked,
            },
        };
        Ok(CtParkState { woken, activity })
    }

    /// What every worker's parker says, in worker-index order.
    ///
    /// A parked worker's `Parker` is a stack local — the run loop moves
    /// it out of the `Core` before parking — so it is not reachable from
    /// the thread. The `Unparker` in the worker's `Remote` shares the
    /// same allocation, though, and that hangs off the shared scheduler
    /// state, so every worker's state word is readable from one place
    /// whether or not the thread holding it can be walked.
    ///
    /// Multi_thread only — `handle` must be an MT runtime's; a
    /// current_thread runtime has no remotes and no parker array.
    pub fn park_states(&self, handle: Value<'b>) -> Result<ParkStates> {
        let remotes = self.walk(WalkRole::SharedRemotes).walk_at(handle)?;
        // The driver's lock lives under the parkers' own shared state,
        // which every `Inner` points at; the first one answers for all.
        let mut driver_held = None;
        let remotes = remotes.elements(self.proc)?;
        ensure!(
            remotes.truncated().is_none(),
            "the remotes array claims {} workers, only {} readable",
            remotes.truncated().unwrap_or_default(),
            remotes.len(),
        );
        let workers = (|| -> Result<Vec<ParkState>> {
            let mut workers = Vec::with_capacity(remotes.len() as usize);
            for remote in remotes.iter() {
                let inner = self.walk(WalkRole::RemoteUnpark).walk_at(remote)?;
                if driver_held.is_none() {
                    driver_held = Some(self.walk(WalkRole::ParkerDriverLock).read(inner)?);
                }
                let state = self.walk(WalkRole::ParkerState).read(inner)?;
                workers.push(ParkState::from_word(state));
            }
            Ok(workers)
        })()
        .context("failed to read the workers' park state")?;
        Ok(ParkStates {
            workers,
            driver_held: driver_held.unwrap_or(false),
        })
    }

    /// The blocking pool's own counters: the threads it runs, how many
    /// of them are idle, and how much work is queued for them.
    ///
    /// These are the pool's, not a walk of the target's threads: a
    /// blocking thread carries no scheduler state to be recognized by,
    /// so what the pool says about itself is all there is to say.
    pub fn blocking_pool(&self, handle: Value<'b>) -> Result<BlockingPool> {
        let metrics = self.walk(WalkRole::BlockingMetrics).walk_at(handle)?;
        Ok(BlockingPool {
            threads: self.walk(WalkRole::BlockingThreads).read(metrics)?,
            idle: self.walk(WalkRole::BlockingIdle).read(metrics)?,
            queued: self.walk(WalkRole::BlockingQueueDepth).read(metrics)?,
        })
    }

    // -----------------------------------------------------------------------
    // Task enumeration
    // -----------------------------------------------------------------------

    /// Walk `Shared.owned`'s sharded intrusive lists and parse every task.
    ///
    /// Corrupt memory degrades per shard: the failing shard contributes an
    /// error, the rest of the listing is unaffected.
    pub fn enumerate_tasks(&self, shared: Value<'b>) -> Result<TaskList> {
        let lists = self.walk(WalkRole::OwnedLists).walk_at(shared)?;

        let mut tasks = Vec::new();
        let mut errors = Vec::new();
        // Guards against cycles from corrupt memory, across shards: the
        // same Header must never appear twice.
        let mut visited = HashSet::default();

        let shards = lists
            .elements(self.proc)
            .context("failed to walk OwnedTasks shards")?;
        ensure!(
            shards.truncated().is_none(),
            "the OwnedTasks shard array claims {} shards, only {} readable",
            shards.truncated().unwrap_or_default(),
            shards.len(),
        );
        for (this_shard, elem) in shards.iter().enumerate() {
            // A failure to navigate a shard itself (as opposed to a node in
            // its list) means every shard is unreadable the same way; abort
            // the enumeration rather than reporting it once per shard.
            let head_addr = match self.walk(WalkRole::ShardHead).walk(elem) {
                Ok(Walked::At(head)) => head
                    .parse::<u64>(self.proc)
                    .context("failed to walk OwnedTasks shards")?,
                // An empty shard.
                Ok(_) => continue,
                Err(e) => return Err(e.context("failed to walk OwnedTasks shards")),
            };
            self.walk_owned_list(
                head_addr,
                &mut visited,
                &mut tasks,
                &mut errors,
                &format!("shard {this_shard}"),
            );
        }

        tasks.sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        Ok(TaskList { tasks, errors })
    }

    /// Walk one intrusive owned-task list from its head, appending every
    /// parsed task. Corrupt memory degrades per list: the failing node
    /// contributes an error under `what`'s name, the rest of the
    /// caller's enumeration is unaffected. The caller owns the cycle
    /// guard, so lists that (corruptly) share a node are caught across
    /// calls.
    fn walk_owned_list(
        &self,
        head_addr: u64,
        visited: &mut HashSet<u64>,
        tasks: &mut Vec<Task>,
        errors: &mut Vec<anyhow::Error>,
        what: &str,
    ) {
        let mut cur = Some(head_addr);
        while let Some(addr) = cur {
            let step = (|| -> Result<Option<u64>> {
                ensure!(
                    self.mappings.contains_addr(addr),
                    "task pointer {addr:#x} is unmapped"
                );
                ensure!(visited.insert(addr), "owned-task list cycle at {addr:#x}");
                let (task, next) = self.parse_task(addr)?;
                tasks.push(task);
                Ok(next)
            })();
            match step {
                Ok(next) => cur = next,
                Err(e) => {
                    errors.push(e.context(format!("task walk failed in {what} at {addr:#x}")));
                    break;
                }
            }
        }
    }

    /// Parse one task from its `Header` address; returns the task and the
    /// next Header in the owned list (via `Trailer.owned`).
    fn parse_task(&self, addr: u64) -> Result<(Task, Option<u64>)> {
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let info = Value::read(self.proc, header_ty, addr)
            .with_context(|| format!("failed to read task Header at {addr:#x}"))?;

        let state = TaskState(self.walk(WalkRole::HeaderState).read(info)?);
        let owner_id = self.walk(WalkRole::HeaderOwnerId).read(info)?;

        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(info)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;

        let raw_id = self.proc.read_u64(addr + vtable.id_offset).map_err(|e| {
            anyhow!(e).context(format!(
                "failed to read task id at {addr:#x}+{:#x}",
                vtable.id_offset
            ))
        })?;
        // The id is a NonZeroU64; zero means we misread something.
        let task_id = (raw_id != 0).then_some(raw_id);

        let spawn_location = match vtable.spawn_location_offset {
            Some(off) => {
                let loc_ptr = self
                    .proc
                    .read_u64(addr + off)
                    .map_err(|e| anyhow!(e).context("failed to read spawn location pointer"))?;
                Some(self.read_location(loc_ptr)?)
            }
            None => None,
        };

        let future = self.resolve_future(&vtable);
        if let FutureInfo::Known(known) = &future {
            self.cross_check_offsets(&vtable, known)?;
        }

        let next = self
            .owned_next(addr + vtable.trailer_offset)
            .context("failed to read Trailer.owned links")?;

        let task = Task {
            addr: TaskAddr(addr),
            state,
            owner_id,
            task_id,
            spawn_location,
            future,
            group: 0,
        };
        Ok((task, next))
    }

    /// Decode a `task::raw::Vtable` from target memory using the bundle's
    /// layout — the struct is `#[repr(Rust)]`, so offsets must never be
    /// assumed from declaration order.
    fn task_vtable(&self, vtable_addr: u64) -> Result<TaskVtable> {
        if let Some(vt) = self.vtables.borrow().get(&vtable_addr) {
            return Ok(vt.clone());
        }

        let ty = self.infra_ty(self.view.bundle().infra.vtable, "task Vtable")?;
        let info = Value::read(self.proc, ty, vtable_addr)?;

        let vt = TaskVtable {
            poll: self.walk(WalkRole::VtablePoll).read(info)?,
            dealloc: self.walk(WalkRole::VtableDealloc).try_read(info)?,
            try_read_output: self.walk(WalkRole::VtableTryReadOutput).try_read(info)?,
            drop_join_handle_slow: self
                .walk(WalkRole::VtableDropJoinHandleSlow)
                .try_read(info)?,
            drop_abort_handle: self.walk(WalkRole::VtableDropAbortHandle).try_read(info)?,
            shutdown: self.walk(WalkRole::VtableShutdown).try_read(info)?,
            trailer_offset: self.walk(WalkRole::VtableTrailerOffset).read(info)?,
            id_offset: self.walk(WalkRole::VtableIdOffset).read(info)?,
            // Only present under `tokio_unstable` + task instrumentation.
            spawn_location_offset: self
                .walk(WalkRole::VtableSpawnLocationOffset)
                .try_read(info)?,
        };
        self.vtables.borrow_mut().insert(vtable_addr, vt.clone());
        Ok(vt)
    }

    /// The v0 pivot: resolve the vtable's monomorphized fns via the
    /// target's symtab and join them against the bundle's task table.
    /// Falls through the sibling vtable fns before giving up; never guesses.
    fn resolve_future(&self, vt: &TaskVtable) -> FutureInfo {
        let candidates = [
            Some(vt.poll),
            vt.dealloc,
            vt.try_read_output,
            vt.drop_join_handle_slow,
            vt.drop_abort_handle,
            vt.shutdown,
        ];
        let mut ambiguous: Option<(String, Vec<TypeCandidate>)> = None;
        for addr in candidates.into_iter().flatten() {
            let Some(symbol) = self.symbol_at(addr) else {
                continue;
            };
            let entry_id = match self.task_ids_memoized(&symbol) {
                SymbolLookup::Unique(id) => id,
                SymbolLookup::Ambiguous(ids) => {
                    let names = ids
                        .into_iter()
                        .filter_map(|id| self.view.bundle().tasks.entries.get(id.0 as usize))
                        .filter_map(|entry| {
                            Some(TypeCandidate {
                                name: self.view.str(entry.display_name)?.to_owned(),
                                ty: entry.future,
                            })
                        })
                        .collect();
                    ambiguous.get_or_insert((symbol, names));
                    continue;
                }
                SymbolLookup::Missing => continue,
            };
            let entry = &self.view.bundle().tasks.entries[entry_id.0 as usize];
            let display_name = self
                .view
                .str(entry.display_name)
                .unwrap_or("<anon>")
                .to_owned();
            let provenance = self.view.provenance(entry_id);
            let decl = provenance
                .and_then(|p| p.decl)
                .and_then(|loc| Some((self.view.str(loc.file)?.to_owned(), loc.line)));
            let kind = provenance.map(|p| p.kind).unwrap_or(FutureKind::Manual);
            return FutureInfo::Known(KnownFuture {
                entry: entry_id,
                display_name,
                kind,
                decl,
                symbol,
            });
        }
        if let Some((symbol, candidates)) = ambiguous {
            return FutureInfo::Ambiguous { symbol, candidates };
        }
        FutureInfo::Unknown {
            poll_symbol: self.symbol_at(vt.poll),
        }
    }

    /// Cheap bundle/target mismatch canary: the offsets stored in the
    /// target's vtable must equal the ones computed from the bundle's
    /// `Cell<T, S>` layout. Disagreement is a hard diagnostic, not a silent
    /// misparse.
    fn cross_check_offsets(&self, vt: &TaskVtable, known: &KnownFuture) -> Result<()> {
        let entry = self.task_entry(known.entry);
        let Some(cell) = self.view.ty(entry.cell) else {
            return Ok(());
        };
        // The Cell may be an opaque placeholder if extraction could not
        // bind it; nothing to check then.
        let Some(trailer_offset) = self.walk(WalkRole::CellTrailer).member_offset(cell) else {
            return Ok(());
        };
        ensure!(
            trailer_offset == vt.trailer_offset,
            "bundle/target layout mismatch for {}: bundle Cell.trailer at {:#x}, \
             target vtable trailer_offset {:#x}",
            known.display_name,
            trailer_offset,
            vt.trailer_offset
        );
        if let Some(id_offset) = self.walk(WalkRole::CellTaskId).member_offset(cell) {
            ensure!(
                id_offset == vt.id_offset,
                "bundle/target layout mismatch for {}: bundle Core.task_id at {:#x}, \
                 target vtable id_offset {:#x}",
                known.display_name,
                id_offset,
                vt.id_offset
            );
        }
        Ok(())
    }

    fn task_entry(&self, id: TaskEntryId) -> &'b TaskFutureEntry {
        // Ids handed out by task_ids_for_symbol always index the table.
        &self.view.bundle().tasks.entries[id.0 as usize]
    }

    /// Read a `core::panic::Location` from target memory. The strings live
    /// in the *target's* rodata; the bundle only supplies the layout.
    fn read_location(&self, loc_ptr: u64) -> Result<Location> {
        let ty = self.infra_ty(self.view.bundle().infra.location, "core::panic::Location")?;
        let info = Value::read(self.proc, ty, loc_ptr)
            .with_context(|| format!("failed to read Location at {loc_ptr:#x}"))?;
        // `file!()` records the path as rustc saw it on the build machine,
        // so a registry crate names itself in full. Cut it down the same way
        // extraction cuts a line-table path, or one file is spelled two ways
        // in one listing (`tasks` prints a task's spawn site beside its
        // future's declaration).
        let filename: String = self.walk(WalkRole::LocationFile).read(info)?;
        let line = self.walk(WalkRole::LocationLine).read(info)?;
        let col = self.walk(WalkRole::LocationCol).read(info)?;
        Ok(Location {
            filename: strip_build_prefix(&filename).into_owned(),
            line,
            col,
        })
    }

    /// Follow the owned-list link out of a task's `Trailer` (the
    /// next/prev pointers live in `Trailer.owned`, not the Header).
    fn owned_next(&self, trailer_addr: u64) -> Result<Option<u64>> {
        let ty = self.infra_ty(self.view.bundle().infra.trailer, "task Trailer")?;
        let info = Value::read(self.proc, ty, trailer_addr)
            .with_context(|| format!("failed to read Trailer at {trailer_addr:#x}"))?;
        // Trailer.owned: linked_list::Pointers<Header>, which peels down to
        // its inner { prev, next } struct.
        self.walk(WalkRole::TrailerNext)
            .walk(info)?
            .optional()
            .map(|ptr| ptr.parse(self.proc).map_err(anyhow::Error::from))
            .transpose()
    }

    // -----------------------------------------------------------------------
    // Task tracing
    // -----------------------------------------------------------------------

    /// Decode a task's `Stage<T>`: the future lives at
    /// `header_addr + offset(Cell.core) + offset(Core.stage)`, and the
    /// stage's discriminant says whether the state machine is resident.
    ///
    /// Requires the future type to have been resolved; an unknown
    /// future has no `Cell` layout to interpret the memory with, and we
    /// never guess.
    pub fn task_stage(&self, task: &Task) -> Result<TaskStage<'b>> {
        let known = match &task.future {
            FutureInfo::Known(known) => known,
            FutureInfo::Unknown { poll_symbol } => {
                let sym = poll_symbol
                    .as_ref()
                    .map(|s| format!(" (poll symbol {s})"))
                    .unwrap_or_default();
                bail!("the task's future type is not in the bundle{sym}; nothing can be traced");
            }
            FutureInfo::Ambiguous { symbol, candidates } => bail!(
                "the task's normalized future symbol {symbol} is ambiguous: {}; nothing can be traced",
                candidates
                    .iter()
                    .map(|c| format!("{} (type {})", c.name, c.ty.0))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let entry = self.task_entry(known.entry);
        let cell_ty = self.infra_ty(entry.cell, &format!("the Cell of {}", known.display_name))?;
        let cell = Value::read(self.proc, cell_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Cell at {:?}", task.addr))?;
        // Cell.core.stage peels through CoreStage and the UnsafeCells down
        // to the Stage<T> enum.
        let stage = self.walk(WalkRole::CellStage).walk_at(cell)?;
        let (state, payload) = stage
            .active_variant()
            .context("failed to decode the task's Stage")?;
        match state {
            // The payload peels to its single sized member: T itself for
            // Running, Result<T::Output, JoinError> for Finished.
            contract::STAGE_RUNNING => Ok(TaskStage::Running(payload)),
            contract::STAGE_FINISHED => Ok(TaskStage::Finished(payload)),
            contract::STAGE_CONSUMED => Ok(TaskStage::Consumed),
            other => bail!("unexpected Stage variant {other:?}"),
        }
    }

    /// Walk a resident future's await chain, outermost future first.
    ///
    /// The walk never fails outright: whatever decoded cleanly is in
    /// [`AwaitChain::frames`], and [`AwaitChain::end`] says why it
    /// stopped. Corrupt memory is contained by the depth bound and an
    /// (address, type) cycle guard.
    pub fn await_chain(&self, root: Value<'b>) -> AwaitChain<'b> {
        let mut frames: Vec<AwaitFrame<'b>> = Vec::new();
        let mut visited: HashSet<(u64, BundleTypeId)> = HashSet::default();
        let mut cur = root;
        // The dyn-vtable symbol that identified `cur`, when it was not
        // reached structurally.
        let mut dyn_symbol: Option<String> = None;

        let end = loop {
            if frames.len() >= MAX_AWAIT_DEPTH {
                break ChainEnd::DepthLimit;
            }
            if !visited.insert((cur.addr, cur.ty.id())) {
                break ChainEnd::Cycle { addr: cur.addr };
            }
            // A recognized wait primitive is where the chain ends
            // whatever it holds inside, since [`Context::wait_target`]
            // reads it as the thing being waited on.
            let is_primitive = leaf_kind(cur.ty.name()).is_some();

            // A future that *is* a dyn wide pointer (a spawned
            // `Pin<Box<dyn Future>>`): resolve the concrete type through
            // its vtable before decoding anything.
            if let Some(dp) = cur.peel().ty.dyn_pointer() {
                match self.resolve_dyn_future(cur.peel(), &dp) {
                    Ok(DynAwaitee::Resolved { future, symbol }) => {
                        cur = future;
                        dyn_symbol = Some(symbol);
                        continue;
                    }
                    Ok(DynAwaitee::Unknown { poll_symbol }) => {
                        break ChainEnd::UnknownDyn {
                            pointee: dp.pointee.name().to_owned(),
                            poll_symbol,
                        };
                    }
                    Ok(DynAwaitee::Ambiguous { symbol, candidates }) => {
                        break ChainEnd::AmbiguousDyn {
                            pointee: dp.pointee.name().to_owned(),
                            symbol,
                            candidates,
                        };
                    }
                    Err(e) => break ChainEnd::Error(e),
                }
            }

            // Decode the coroutine state. Non-enums are sync primitives,
            // I/O futures and combinator structs: none has a suspend
            // state, so none names an awaitee. A wrapper holding exactly
            // one future is still a step of the chain — see
            // [`Context::sole_inner_future`] — so it is followed; a
            // genuine leaf ends the walk.
            let decoded = match cur.ty.active_variant(cur.bytes) {
                None => {
                    let inner = self.sole_inner_future(cur).filter(|_| !is_primitive);
                    frames.push(AwaitFrame {
                        future: cur,
                        state: None,
                        dyn_symbol: dyn_symbol.take(),
                        inner: inner.as_ref().map(|(name, _)| *name),
                    });
                    let Some((_, inner)) = inner else {
                        break ChainEnd::Leaf;
                    };
                    match inner {
                        Follow::Next { future, symbol } => {
                            cur = future;
                            dyn_symbol = symbol;
                            continue;
                        }
                        Follow::Stop(end) => break end,
                    }
                }
                Some(Ok(v)) => v,
                Some(Err(e)) => {
                    let err = anyhow!(e).context(format!(
                        "failed to decode the state of {} at {:#x}",
                        cur.ty.name(),
                        cur.addr,
                    ));
                    frames.push(AwaitFrame {
                        future: cur,
                        state: None,
                        dyn_symbol,
                        inner: None,
                    });
                    break ChainEnd::Error(err);
                }
            };

            // Coroutine variant members are numbered; their state names
            // live on the payload structs. An ordinary enum is a
            // combinator written by hand — `futures_util`'s `Map` is an
            // `Incomplete { future, f }` — so it names no awaitee, and
            // what it holds decides whether the chain goes on.
            let is_coroutine_state =
                !decoded.name.is_empty() && decoded.name.bytes().all(|b| b.is_ascii_digit());

            // Slice out the variant payload *without* peeling: its
            // members are the state's live locals.
            let start = decoded.offset as usize;
            let size = decoded.ty.size() as usize;
            let Some(bytes) = cur.bytes.get(start..start + size) else {
                let err = anyhow!(
                    "variant payload {}..{} does not fit {} bytes of {}",
                    start,
                    start + size,
                    cur.bytes.len(),
                    cur.ty.name(),
                );
                frames.push(AwaitFrame {
                    future: cur,
                    state: None,
                    dyn_symbol,
                    inner: None,
                });
                break ChainEnd::Error(err);
            };
            let payload = Value::new(decoded.ty, cur.addr + decoded.offset, bytes);
            frames.push(AwaitFrame {
                future: cur,
                state: Some(FrameState {
                    name: decoded.state_name(),
                    await_loc: decoded.await_loc(),
                    payload,
                }),
                dyn_symbol: dyn_symbol.take(),
                inner: None,
            });
            if !is_coroutine_state {
                // The variant's payload holds the combinator's live
                // futures, so the same arity rule decides: one and the
                // chain goes on through it, none or several and it ends
                // here.
                let frame = frames.last_mut().unwrap();
                let payload = frame.state.as_ref().unwrap().payload;
                let inner = self.sole_inner_future(payload).filter(|_| !is_primitive);
                frame.inner = inner.as_ref().map(|(name, _)| *name);
                match inner {
                    Some((_, Follow::Next { future, symbol })) => {
                        cur = future;
                        dyn_symbol = symbol;
                        continue;
                    }
                    Some((_, Follow::Stop(end))) => break end,
                    None => break ChainEnd::Leaf,
                }
            }

            // A suspended coroutine stores what it awaits in the
            // variant's `__awaitee` member; states that aren't waiting
            // (Unresumed, Returned, Panicked) have none.
            let payload = frames.last().unwrap().state.as_ref().unwrap().payload;
            let Some(member) = payload.ty.member("__awaitee") else {
                break ChainEnd::Leaf;
            };
            let start = member.offset() as usize;
            let size = member.ty().size() as usize;
            let Some(bytes) = payload.bytes.get(start..start + size) else {
                break ChainEnd::Error(anyhow!(
                    "__awaitee {}..{} does not fit {} bytes of {}",
                    start,
                    start + size,
                    payload.bytes.len(),
                    payload.ty.name(),
                ));
            };
            let awaitee = Value::new(member.ty(), payload.addr + member.offset(), bytes);

            match self.follow(awaitee) {
                Follow::Next { future, symbol } => {
                    cur = future;
                    dyn_symbol = symbol;
                }
                Follow::Stop(end) => break end,
            }
        };

        AwaitChain { frames, end }
    }

    /// Follow one future the chain reached to the frame it stands for.
    ///
    /// Wrappers (`Pin`, mainly) hide what the pointer-shaped ones really
    /// are; plain ones keep their own type so the chain reports e.g.
    /// `oneshot::Receiver<u32>` rather than whatever its innards peel
    /// down to.
    fn follow(&self, awaitee: Value<'b>) -> Follow<'b> {
        let peeled = awaitee.peel();
        if let Some(dp) = peeled.ty.dyn_pointer() {
            // A boxed trait object: only its vtable knows the concrete
            // type.
            return match self.resolve_dyn_future(peeled, &dp) {
                Ok(DynAwaitee::Resolved { future, symbol }) => Follow::Next {
                    future,
                    symbol: Some(symbol),
                },
                Ok(DynAwaitee::Unknown { poll_symbol }) => Follow::Stop(ChainEnd::UnknownDyn {
                    pointee: dp.pointee.name().to_owned(),
                    poll_symbol,
                }),
                Ok(DynAwaitee::Ambiguous { symbol, candidates }) => {
                    Follow::Stop(ChainEnd::AmbiguousDyn {
                        pointee: dp.pointee.name().to_owned(),
                        symbol,
                        candidates,
                    })
                }
                Err(e) => Follow::Stop(ChainEnd::Error(e)),
            };
        }
        if leaf_kind(awaitee.ty.name()).is_none() && peeled.ty.pointer_target().is_some()
        // A recognized wait primitive is a leaf regardless of its
        // shape; [`Context::wait_target`] interprets it.
        {
            // `(&mut fut).await`, `Box<fut>`: follow the thin pointer.
            return match peeled.deref_ptr(self.proc) {
                Ok(future) => Follow::Next {
                    future,
                    symbol: None,
                },
                Err(e) => Follow::Stop(ChainEnd::Error(
                    anyhow!(e).context("failed to follow an awaited pointer"),
                )),
            };
        }
        Follow::Next {
            future: awaitee,
            symbol: None,
        }
    }

    /// The one future a non-coroutine frame holds, where holding exactly
    /// one is what it means.
    ///
    /// A future that is not a coroutine has no suspend state and so names
    /// no `__awaitee`, but that does not make it the end of the chain: a
    /// wrapper written by hand — `Instrumented`, `Map`, `MapErr`, the
    /// `poll` that delegates to one inner future — is as much a step as a
    /// suspended `async fn`, and stopping at one leaves a task reported as
    /// waiting on a combinator rather than on whatever it wraps.
    ///
    /// What separates a wrapper from a leaf is arity, not spelling, so
    /// nothing here is keyed by name: a wrapper holds exactly one member
    /// that is itself a future, while a real leaf (`Notified`, an io
    /// readiness future) holds none and a combinator that polls several
    /// (`select!`, `Timeout`, a stream fold) holds more than one. Only the
    /// first can extend a chain that is a list, so the other two end it.
    ///
    /// `scan` is the value whose members are the candidates: the future
    /// itself where it is a plain struct, and the active variant's
    /// payload where it is an enum, since that is where a combinator's
    /// live futures sit.
    ///
    /// A type whose `poll` rustc inlined out of the symtab is not in the
    /// bundle's future set, so a wrapper around it declines and the chain
    /// ends exactly where it did before — the miss costs the old
    /// behaviour, not a wrong one.
    fn sole_inner_future(&self, scan: Value<'b>) -> Option<(&'b str, Follow<'b>)> {
        let mut sole = None;
        for member in scan.ty.members() {
            if !self.is_future(member.ty()) {
                continue;
            }
            if sole.is_some() {
                return None;
            }
            sole = Some(member);
        }
        let member = sole?;
        let start = member.offset() as usize;
        let bytes = scan.bytes.get(start..start + member.ty().size() as usize)?;
        let follow = self.follow(Value::new(member.ty(), scan.addr + member.offset(), bytes));
        Some((member.name(), follow))
    }

    /// Whether a type is a future: one whose `poll` extraction recorded,
    /// a coroutine (whose `poll` may be inlined away, but whose numbered
    /// variants say what it is), a recognized wait primitive, or a boxed
    /// `dyn Future` whose concrete type only its vtable knows.
    ///
    /// A member is often wrapped before the future is reached
    /// (`ManuallyDrop<Pin<Box<dyn Future>>>`, `IntoFuture<Conn>`), so the
    /// wrapper chain is walked a step at a time and the *first* level
    /// that is a future decides. Testing only the fully unwrapped type
    /// would walk past `IntoFuture` and the connection inside it alike,
    /// and land on the `Option` at the bottom of both.
    /// The bundle's poll table: the types whose `<T as Future>::poll`
    /// extraction recorded. A floor, not a census — an inlined-away
    /// `poll` leaves no symbol and so no entry.
    pub(crate) fn known_futures(&self) -> &HashSet<BundleTypeId> {
        &self.futures
    }

    fn is_future(&self, ty: BundleType<'b>) -> bool {
        let mut ty = ty;
        for _ in 0..MAX_WRAPPER_DEPTH {
            if let Some(dp) = ty.dyn_pointer() {
                return contract::is_dyn_future_pointee(dp.pointee.name());
            }
            if self.futures.contains(&ty.id())
                || ty.is_coroutine()
                || leaf_kind(ty.name()).is_some()
            {
                return true;
            }
            // Not one itself: unwrap one layer, the way `peel` does, and
            // ask again. Anything that is not a single-field wrapper
            // ends the search.
            let mut sized = ty.members().map(|m| m.ty()).filter(|t| t.size() > 0);
            match (sized.next(), sized.next()) {
                (Some(inner), None) => ty = inner,
                _ => return false,
            }
        }
        false
    }

    /// Resolve a `dyn Future` wide pointer: read its data and
    /// vtable pointers from the already-read payload bytes, resolve the
    /// vtable's poll fn — or its drop glue, for polls internalized out of
    /// the symtab — through the *target's* symtab, and join the mangled
    /// symbol against the bundle's dyn-future table. Never guesses.
    fn resolve_dyn_future(&self, ptr: Value<'b>, dp: &DynPointer<'b>) -> Result<DynAwaitee<'b>> {
        let word = |off: u64| -> Result<u64> {
            let bytes = ptr
                .bytes
                .get(off as usize..off as usize + 8)
                .ok_or_else(|| anyhow!("wide-pointer bytes truncated at +{off:#x}"))?;
            Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let data = word(dp.data_offset)?;
        let vtable = word(dp.vtable_offset)?;
        ensure!(
            self.mappings.contains_addr(data),
            "dyn future data pointer {data:#x} is unmapped"
        );
        ensure!(
            self.mappings.contains_addr(vtable),
            "dyn future vtable pointer {vtable:#x} is unmapped"
        );

        let mut poll_symbol = None;
        for slot in [VTABLE_SLOT_FUTURE_POLL, VTABLE_SLOT_DROP] {
            let fn_addr = self.proc.read_u64(vtable + slot * 8).map_err(|e| {
                anyhow!(e).context(format!("failed to read slot {slot} of vtable {vtable:#x}"))
            })?;
            let Some(symbol) = self.symbol_at(fn_addr) else {
                continue;
            };
            if slot == VTABLE_SLOT_FUTURE_POLL {
                poll_symbol = Some(symbol.clone());
            }
            match self.dyn_future_ids_memoized(&symbol) {
                SymbolLookup::Unique(id) => {
                    let ty = self.view.ty(id).expect("validated bundle type id");
                    let future = Value::read(self.proc, ty, data)
                        .with_context(|| format!("failed to read {} at {data:#x}", ty.name()))?;
                    return Ok(DynAwaitee::Resolved { future, symbol });
                }
                SymbolLookup::Ambiguous(ids) => {
                    let candidates = ids
                        .into_iter()
                        .filter_map(|id| self.view.ty(id))
                        .map(|ty| TypeCandidate {
                            name: ty.name().to_owned(),
                            ty: ty.id(),
                        })
                        .collect();
                    return Ok(DynAwaitee::Ambiguous { symbol, candidates });
                }
                SymbolLookup::Missing => {}
            }
        }
        Ok(DynAwaitee::Unknown { poll_symbol })
    }

    // -----------------------------------------------------------------------
    // The leaf-future knowledge base
    // -----------------------------------------------------------------------

    /// What the chain's leaf future is waiting on, when it is a
    /// recognized primitive. `list` is the enumerated task list, so a
    /// join edge can say whether its target is a task any listing shows.
    ///
    /// `None` for incomplete chains and unrecognized leaves; `Some(Err)`
    /// when the leaf was recognized but its innards could not be read
    /// (torn memory, or a tokio whose internals moved).
    pub fn wait_target(
        &self,
        chain: &AwaitChain<'b>,
        list: &TaskList,
    ) -> Option<Result<WaitTarget>> {
        if !matches!(chain.end, ChainEnd::Leaf) {
            return None;
        }
        let leaf = chain.frames.last()?;
        let kind = leaf_kind(leaf.future.ty.name())?;
        Some(match kind {
            LeafKind::Sleep => self.read_sleep(leaf.future),
            LeafKind::JoinHandle => self.read_join_handle(leaf.future, list),
            LeafKind::SemaphoreAcquire => self.read_acquire(leaf.future, chain),
        })
    }

    /// `tokio::time::Sleep`: the deadline its timer entry registered.
    /// Where this tokio keeps it was the binder's business at
    /// extraction; the recorded steps already spell the route.
    fn read_sleep(&self, sleep: Value<'b>) -> Result<WaitTarget> {
        // The deadline lands on the std Timespec inside tokio's
        // Instant, on the target's monotonic clock.
        let deadline = self.walk(WalkRole::SleepDeadline).walk_at(sleep)?;
        let tv_sec: i64 = self.walk(WalkRole::DeadlineTvSec).read(deadline)?;
        let tv_nsec: u32 = self.walk(WalkRole::DeadlineTvNsec).read(deadline)?;
        Ok(WaitTarget::Timer {
            deadline: RawInstant {
                tv_sec: tv_sec as u64,
                tv_nsec,
            },
            stopped: self.stopped_at(),
        })
    }

    /// A `JoinHandle<T>`: the task being awaited — a dependency edge
    /// between tasks.
    fn read_join_handle(&self, handle: Value<'b>, list: &TaskList) -> Result<WaitTarget> {
        // JoinHandle.raw: RawTask, which peels to the NonNull<Header>.
        let addr: u64 = self.walk(WalkRole::JoinHandleRaw).read(handle)?;
        let (task_id, state) = self
            .header_task_ref(addr)
            .context("failed to identify the joined task")?;
        let listed = list.contains(addr);
        // An unlisted task gets classified by its cell's recorded
        // scheduler type — a definite statement where the vtable join
        // resolves, silence where it does not.
        let kind = if listed {
            None
        } else {
            self.header_unlisted_kind(addr)
        };
        Ok(WaitTarget::Task {
            addr,
            task_id,
            state,
            listed,
            kind,
        })
    }

    /// Resolve a bare task `Header` pointer from target memory to its
    /// task id and state word, going through the task's own vtable for
    /// the id offset. JoinHandles and task wakers both hand us such
    /// pointers — including to a task that has already completed and
    /// left the owned list (the handle's reference keeps the Header
    /// alive), which only the state word reveals.
    pub(crate) fn header_task_ref(&self, addr: u64) -> Result<(Option<u64>, TaskState)> {
        ensure!(
            self.mappings.contains_addr(addr),
            "task Header pointer {addr:#x} is unmapped"
        );
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let header = Value::read(self.proc, header_ty, addr)
            .with_context(|| format!("failed to read the task Header at {addr:#x}"))?;
        let state = TaskState(self.walk(WalkRole::HeaderState).read(header)?);
        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;
        let raw_id = self.proc.read_u64(addr + vtable.id_offset).map_err(|e| {
            anyhow!(e).context(format!(
                "failed to read the task id at {addr:#x}+{:#x}",
                vtable.id_offset
            ))
        })?;
        Ok(((raw_id != 0).then_some(raw_id), state))
    }

    /// The memory a task's allocation covers: the `Cell<T, S>` holding
    /// its Header, Core (the future), and Trailer, starting at the
    /// Header address that identifies the task.
    ///
    /// A known future has the whole `Cell` layout in the bundle, tail
    /// padding included. For any other the target's own vtable places
    /// the Trailer, and the Trailer is the Cell's last member — short
    /// of the allocation's true end only by any tail padding.
    pub fn task_extent(&self, task: &Task) -> Result<std::ops::Range<u64>> {
        if let FutureInfo::Known(known) = &task.future {
            let entry = self.task_entry(known.entry);
            if let Some(cell) = self.view.ty(entry.cell)
                && !matches!(cell.def(), TypeDef::Opaque { .. })
            {
                return Ok(task.addr.0..task.addr.0 + cell.size());
            }
        }
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let header = Value::read(self.proc, header_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Header at {:?}", task.addr))?;
        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;
        let trailer = self.infra_ty(self.view.bundle().infra.trailer, "task Trailer")?;
        Ok(task.addr.0..task.addr.0 + vtable.trailer_offset + trailer.size())
    }

    /// Index every task's allocation for address lookup — which task a
    /// raw pointer points into. A task whose extent cannot be computed
    /// is simply absent: it claims no address.
    pub fn task_extents(&self, list: &TaskList) -> TaskExtents {
        let mut spans: Vec<(u64, u64, usize)> = list
            .tasks
            .iter()
            .enumerate()
            .filter_map(|(index, task)| {
                let extent = self.task_extent(task).ok()?;
                (extent.end > extent.start).then_some((extent.start, extent.end, index))
            })
            .collect();
        spans.sort_unstable();
        TaskExtents { spans }
    }

    /// `batch_semaphore::Acquire`: queued on the semaphore that backs
    /// tokio's Mutex, RwLock, and Semaphore. The semaphore address
    /// identifies the contended resource; the frame that awaits the
    /// Acquire names which primitive wraps it.
    fn read_acquire(&self, acquire: Value<'b>, chain: &AwaitChain<'b>) -> Result<WaitTarget> {
        let semaphore = self.walk(WalkRole::AcquireSemaphore).walk_at(acquire)?;
        let addr: u64 = semaphore.parse(self.proc)?;
        let num_permits: u64 = self.walk(WalkRole::AcquireNumPermits).read(acquire)?;
        // Read the pointee as its own type, not deref_ptr's peeled view:
        // the semaphore walks root at the Semaphore itself.
        let sem_ty = semaphore
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("Acquire.semaphore is not pointer-shaped"))?;
        let sem = Value::read(self.proc, sem_ty, addr).context("failed to read the Semaphore")?;
        // `permits` keeps the available count shifted above the CLOSED
        // bit.
        let raw: u64 = self.walk(WalkRole::SemaphorePermits).read(sem)?;
        let owner = semaphore_owner(chain);
        let waiters = self
            .semaphore_waiters(sem)
            .context("failed to walk the semaphore's wait queue")?;
        Ok(WaitTarget::Semaphore {
            addr,
            owner,
            num_permits,
            available: raw >> 1,
            closed: raw & 1 != 0,
            waiters,
        })
    }

    /// Walk a semaphore's wait queue: who its permits will wake, in wake
    /// order. tokio enqueues waiters at the list head and wakes from the
    /// tail, so the walk runs front-to-back and is reversed at the end.
    fn semaphore_waiters(&self, sem: Value<'b>) -> Result<Vec<SemaphoreWaiter>> {
        // Semaphore.waiters is a loom Mutex over the Waitlist; both the
        // parking_lot and std mutexes beneath it spell the payload
        // member `data`.
        let Some(head) = self
            .walk(WalkRole::SemaphoreQueueHead)
            .walk(sem)?
            .optional()
        else {
            return Ok(Vec::new());
        };
        // The Some payload peels through the NonNull to the raw Waiter
        // pointer: its target is the layout each node decodes with.
        let waiter_ty = head
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("the wait-queue head is not pointer-shaped"))?;

        let mut waiters = Vec::new();
        let mut visited = HashSet::default();
        let mut cur = Some(head.parse::<u64>(self.proc)?);
        while let Some(addr) = cur {
            ensure!(
                self.mappings.contains_addr(addr),
                "wait-queue pointer {addr:#x} is unmapped"
            );
            ensure!(visited.insert(addr), "wait-queue cycle at {addr:#x}");
            let node = Value::read(self.proc, waiter_ty, addr)
                .with_context(|| format!("failed to read the Waiter at {addr:#x}"))?;
            waiters.push(SemaphoreWaiter {
                addr,
                needed: self.walk(WalkRole::WaiterNeeded).read(node)?,
                waker: self.read_queued_waker(node)?,
            });
            cur = self
                .walk(WalkRole::WaiterNext)
                .walk(node)?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(anyhow::Error::from))
                .transpose()?;
        }
        waiters.reverse();
        Ok(waiters)
    }

    /// Decode the waker registered in a wait-queue node. Waiters keep
    /// theirs in an `UnsafeCell<Option<Waker>>`, whose `Some` payload
    /// peels through the `Waker` to the `RawWaker` pair.
    fn read_queued_waker(&self, node: Value<'b>) -> Result<QueuedWaker> {
        let Some(raw) = self.walk(WalkRole::WaiterWaker).walk(node)?.optional() else {
            return Ok(QueuedWaker::Unarmed);
        };
        self.raw_waker(raw)
    }

    /// Decode one `RawWaker`, wherever it was registered — a semaphore's
    /// wait queue, a timer entry's `AtomicWaker`. The two halves are read
    /// through the same recorded steps in either case, since the landing
    /// type is the same `RawWaker`.
    fn raw_waker(&self, raw: Value<'b>) -> Result<QueuedWaker> {
        let data: u64 = self.walk(WalkRole::WakerData).read(raw)?;
        let vtable: u64 = self.walk(WalkRole::WakerVtable).read(raw)?;
        self.task_waker(data, vtable)
    }

    /// Classify a `(data, vtable)` waker pair. Task wakers are recognized
    /// by their vtable: tokio builds them as `(data = the task's Header,
    /// vtable = &WAKER_VTABLE)`, and the bundle names that static — an
    /// address-equality join against the target's own symtab, never a
    /// guess about what the data word points at.
    fn task_waker(&self, data: u64, vtable: u64) -> Result<QueuedWaker> {
        if self.task_waker_vtable()? != Some(vtable) {
            return Ok(QueuedWaker::Other { vtable });
        }
        let (task_id, _) = self
            .header_task_ref(data)
            .context("failed to identify the task behind a registered waker")?;
        Ok(QueuedWaker::Task {
            addr: data,
            task_id,
        })
    }

    /// The target address of tokio's task `WAKER_VTABLE` static,
    /// resolved once through the target's symtab. The static may exist
    /// only as an `.llvm.<hash>`-suffixed internalized copy, like any
    /// other join symbol.
    fn task_waker_vtable(&self) -> Result<Option<u64>> {
        if let Some(cached) = self.waker_vtable.borrow().as_ref() {
            return cached.clone().map_err(anyhow::Error::msg);
        }
        let resolved: std::result::Result<Option<u64>, String> = (|| {
            let def = self
                .view
                .bundle()
                .statics
                .entries
                .get(&StaticRole::TaskWakerVtable)
                .ok_or_else(|| "bundle records no task WAKER_VTABLE static".to_owned())?;
            self.object_symbol(&def.symbol)
                .map(|symbol| symbol.map(|s| s.st_value))
                .map_err(|error| format!("{error:#}"))
        })();
        *self.waker_vtable.borrow_mut() = Some(resolved.clone());
        resolved.map_err(anyhow::Error::msg)
    }

    // -----------------------------------------------------------------------
    // Local-set discovery
    // -----------------------------------------------------------------------

    /// Classify a task entry by its recorded scheduler type — the `S`
    /// of its `Cell<T, S>`, resolved in the type table. Name-keyed and
    /// fail safe like the leaf keys: an unrecognized spelling is
    /// `Unknown`, never a guess.
    fn scheduler_kind(&self, entry: &TaskFutureEntry) -> SchedulerKind {
        let Some(ty) = self.view.ty(entry.scheduler) else {
            return SchedulerKind::Unknown;
        };
        let name = ty.name();
        if arc_of(name, "tokio::task::local::Shared") {
            SchedulerKind::LocalSet
        } else if name == "tokio::runtime::blocking::schedule::BlockingSchedule" {
            SchedulerKind::Blocking
        } else if arc_of(
            name,
            "tokio::runtime::scheduler::multi_thread::handle::Handle",
        ) {
            SchedulerKind::MultiThread
        } else if arc_of(name, "tokio::runtime::scheduler::current_thread::Handle") {
            SchedulerKind::CurrentThread
        } else {
            SchedulerKind::Unknown
        }
    }

    /// The task-table entry behind a bare Header pointer, via the
    /// vtable join — `None` when the future is unknown or ambiguous,
    /// never a guess.
    fn header_entry(&self, addr: u64) -> Result<Option<TaskEntryId>> {
        ensure!(
            self.mappings.contains_addr(addr),
            "task Header pointer {addr:#x} is unmapped"
        );
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let header = Value::read(self.proc, header_ty, addr)?;
        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
        let vtable = self.task_vtable(vtable_addr)?;
        match self.resolve_future(&vtable) {
            FutureInfo::Known(known) => Ok(Some(known.entry)),
            FutureInfo::Unknown { .. } | FutureInfo::Ambiguous { .. } => Ok(None),
        }
    }

    /// [`Context::scheduler_kind`] for a bare unlisted Header, as
    /// [`UnlistedTaskKind`] words it. `None` when the join cannot
    /// resolve the future or a read on the way fails — the
    /// classification is extra information, never worth an error.
    fn header_unlisted_kind(&self, addr: u64) -> Option<UnlistedTaskKind> {
        let entry_id = self.header_entry(addr).ok().flatten()?;
        match self.scheduler_kind(self.task_entry(entry_id)) {
            SchedulerKind::LocalSet => Some(UnlistedTaskKind::LocalSet),
            SchedulerKind::Blocking => Some(UnlistedTaskKind::Blocking),
            SchedulerKind::MultiThread => {
                Some(UnlistedTaskKind::OtherRuntime(RuntimeFlavor::MultiThread))
            }
            SchedulerKind::CurrentThread => {
                Some(UnlistedTaskKind::OtherRuntime(RuntimeFlavor::CurrentThread))
            }
            SchedulerKind::Unknown => None,
        }
    }

    /// Deterministic discovery of the task lists no thread's `Context`
    /// reaches — `LocalSet`s, and runtimes nothing is currently inside
    /// — and enumeration of everything they own into `list`.
    ///
    /// Route 3 reads each LWP's `task::local::CURRENT` anchor —
    /// populated only while a thread is mid-poll of a set. Route 1
    /// walks the enumerated tasks' await chains and follows every
    /// task-shaped pointer that lands outside the list — a
    /// `JoinHandle`'s target, an armed task waker in a walked waiter
    /// queue — through its cell's recorded scheduler, which says what
    /// owns it: an `Arc<task::local::Shared>` is a set's, an `Arc` of
    /// either flavor `Handle` a runtime's, and either way the list must
    /// claim the task that led there (its own id equal to the task's
    /// `Header.owner_id`) before it is admitted. Route 2 harvests the
    /// discovered runtimes' registries of parked tasks — the timer
    /// wheel, then the io driver's registrations — which hold a task's
    /// waker whatever list owns it, and so are the only route that
    /// reaches a set no enumerated task points at. Every route
    /// converges on the owner's address and dedups there.
    ///
    /// Each admitted list is then walked like one more shard and merged
    /// — including into further rounds of the sweep, since what it owns
    /// can point at the next hidden list, and a runtime it admits
    /// brings its own drivers to harvest.
    ///
    /// `runtimes` grows with what discovery finds; `excluded` names the
    /// handles it must leave alone, which is how a `--runtime`
    /// selection keeps meaning what it says. Failures degrade per
    /// candidate into `list.errors`; the returned sets are in admission
    /// order, and the group each task is stamped with is its owner's
    /// position in `runtimes`, or `runtimes.len()` plus its set's.
    pub fn discover_hidden_tasks(
        &self,
        lwps: &[LwpInfo],
        workers: &[Worker],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        excluded: &[u64],
        list: &mut TaskList,
    ) -> Vec<LocalSetRef<'b>> {
        let mut sets: Vec<LocalSetRef<'b>> = Vec::new();

        // The owner → LWP join table: each worker's own thread id, as
        // tokio's counter numbers it.
        let mut thread_ids: Vec<(u64, u32)> = Vec::new();
        for worker in workers {
            match self.worker_thread_id(worker) {
                Ok(Some(id)) => thread_ids.push((id, worker.tid)),
                Ok(None) => {}
                Err(e) => list.errors.push(e.context(format!(
                    "failed to read the thread id of LWP {}",
                    worker.tid
                ))),
            }
        }

        // Route 3 first: nearly free, and a TLS find carries the one
        // fact route 1 cannot recover — which LWP the set is entered on.
        match self.local_tls_probe(lwps) {
            Ok(found) => {
                for (tid, shared) in found {
                    self.admit_local_set(
                        shared,
                        None,
                        Some(tid),
                        DiscoveryRoute::Tls,
                        &thread_ids,
                        &mut sets,
                        &mut list.errors,
                    );
                }
            }
            Err(e) => list
                .errors
                .push(e.context("the local-set TLS probe failed")),
        }

        // Routes 1 and 2, to a fixed point: enumerate what was admitted,
        // produce more candidates from what was enumerated, admit what
        // they found. Both sides are monotone and bounded — owners dedup
        // by address, tasks by the lists' own cycle guards — so the loop
        // ends; the round cap is a backstop against nothing real.
        //
        // The chain sweep goes first, so a list an enumerated task
        // points at is credited to that edge rather than to whichever
        // of its members happens to hold a timer. The registry harvests
        // follow, each over the runtimes no earlier round harvested: a
        // registry's contents do not change as lists are enumerated,
        // but a runtime admitted from one brings drivers of its own.
        //
        // A set's tasks cannot be stamped as they are enumerated, since
        // their group sits above every runtime and discovery is still
        // free to find more; the blocks each set contributed are
        // recorded and stamped once the count is final.
        let listed = list.tasks.len();
        let mut walked = 0;
        let mut enumerated_runtimes = runtimes.len();
        let mut enumerated_sets = 0;
        let mut wheeled = 0;
        let mut ioed = 0;
        let mut local_blocks: Vec<(usize, std::ops::Range<usize>)> = Vec::new();
        for _round in 0..64 {
            while enumerated_runtimes < runtimes.len() {
                let runtime = &runtimes[enumerated_runtimes];
                match self
                    .find_shared(runtime)
                    .and_then(|shared| self.enumerate_tasks(shared))
                {
                    Ok(mut found) => {
                        for task in &mut found.tasks {
                            task.group = enumerated_runtimes;
                        }
                        list.tasks.append(&mut found.tasks);
                        list.errors.append(&mut found.errors);
                    }
                    Err(e) => list.errors.push(e.context(format!(
                        "failed to enumerate the runtime at {:#x}",
                        runtime.handle.addr
                    ))),
                }
                enumerated_runtimes += 1;
            }
            while enumerated_sets < sets.len() {
                let set = &sets[enumerated_sets];
                match self.enumerate_local_tasks(set) {
                    Ok(mut local) => {
                        let start = list.tasks.len();
                        list.tasks.append(&mut local.tasks);
                        list.errors.append(&mut local.errors);
                        local_blocks.push((enumerated_sets, start..list.tasks.len()));
                    }
                    Err(e) => list.errors.push(e.context(format!(
                        "failed to enumerate the local set at {:#x}",
                        set.shared.addr
                    ))),
                }
                enumerated_sets += 1;
            }
            let found = if walked < list.tasks.len() {
                let range = walked..list.tasks.len();
                walked = list.tasks.len();
                self.unlisted_task_pointers(list, range)
            } else if wheeled < runtimes.len() {
                let (found, errors) = self.wheel_task_pointers(&runtimes[wheeled..], list);
                wheeled = runtimes.len();
                list.errors.extend(errors);
                found
            } else if ioed < runtimes.len() {
                let (found, errors) = self.io_task_pointers(&runtimes[ioed..], list);
                ioed = runtimes.len();
                list.errors.extend(errors);
                found
            } else {
                break;
            };
            for (addr, route) in found {
                self.bootstrap_unlisted(
                    addr,
                    route,
                    excluded,
                    &thread_ids,
                    runtimes,
                    &mut sets,
                    &mut list.errors,
                );
            }
        }
        for (index, range) in local_blocks {
            let group = runtimes.len() + index;
            for task in &mut list.tasks[range] {
                task.group = group;
            }
        }
        if list.tasks.len() != listed {
            list.tasks
                .sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        }
        sets
    }

    /// The tokio thread id a worker's `Context` records — what a
    /// `LocalSet`'s recorded owner joins against. `None` when the row
    /// did not bind on this bundle or the thread has none assigned.
    fn worker_thread_id(&self, worker: &Worker) -> Result<Option<u64>> {
        let info = self.context_info(worker.context_addr)?;
        Ok(self
            .walk(WalkRole::ContextThreadId)
            .try_read::<Option<u64>>(info)?
            .flatten())
    }

    /// Route 3: each LWP's `task::local::CURRENT` anchor, resolved the
    /// way the runtime `CONTEXT` is — the bundle names the static, the
    /// target's symtab locates it, TLS resolution finds each thread's
    /// copy. The anchor holds a `Context` only while the thread is
    /// mid-poll of a set (or inside a user-held `enter` guard), so
    /// empty everywhere is the ordinary parked shape.
    fn local_tls_probe(&self, lwps: &[LwpInfo]) -> Result<Vec<(u32, Value<'b>)>> {
        // A bundle without the static, or whose rows did not bind,
        // probes nothing; those are recorded outcomes, not failures.
        let Some(def) = self
            .view
            .bundle()
            .statics
            .entries
            .get(&StaticRole::TlsLocalSetKey)
        else {
            return Ok(Vec::new());
        };
        let Some(local_data_ty) = self.walk_root_ty(WalkRole::LocalTlsCtx) else {
            return Ok(Vec::new());
        };
        let Some(sym) = self.object_symbol(&def.symbol)? else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for lwp in lwps {
            // LWPs the TLS model cannot walk are skipped the way worker
            // discovery skips them.
            let Ok(Some(addr)) = self.proc.tls_var_addr(&lwp.regs, &sym) else {
                continue;
            };
            if !self.mappings.contains_addr(addr) {
                continue;
            }
            let step = (|| -> Result<Option<Value<'b>>> {
                let data = Value::read(self.proc, local_data_ty, addr)?;
                let Some(ptr) = self
                    .walk(WalkRole::LocalTlsCtx)
                    .try_walk(data)?
                    .and_then(Walked::optional)
                else {
                    return Ok(None);
                };
                let inner = ptr.deref_ptr(self.proc)?;
                Ok(Some(self.walk(WalkRole::LocalCtxShared).walk_at(inner)?))
            })();
            match step {
                Ok(Some(shared)) => found.push((lwp.tid, shared)),
                Ok(None) => {}
                Err(e) => {
                    return Err(e.context(format!(
                        "failed to read the local-set anchor of LWP {}",
                        lwp.tid
                    )));
                }
            }
        }
        Ok(found)
    }

    /// The first recorded root type of a bound role — how a probe that
    /// constructs its own root value (a TLS payload) knows the layout
    /// to read it with.
    fn walk_root_ty(&self, role: WalkRole) -> Option<BundleType<'b>> {
        let binding = self.view.bundle().walks.entries.get(&role)?;
        if !matches!(binding.outcome, WalkOutcome::Bound { .. }) {
            return None;
        }
        self.view.ty(*binding.roots.first()?)
    }

    /// The task-Header pointers reachable from the chains of
    /// `list.tasks[range]` that no enumerated task claims: `JoinHandle`
    /// targets, and armed task wakers in walked waiter queues. Chain
    /// and stage failures are not reported here — the sweep is a
    /// discovery pass, and the analyses that own those chains report
    /// them.
    fn unlisted_task_pointers(
        &self,
        list: &TaskList,
        range: std::ops::Range<usize>,
    ) -> Vec<(u64, DiscoveryRoute)> {
        let mut found = Vec::new();
        for task in &list.tasks[range] {
            let Ok(TaskStage::Running(future)) = self.task_stage(task) else {
                continue;
            };
            let chain = self.await_chain(future);
            match self.wait_target(&chain, list) {
                Some(Ok(WaitTarget::Task {
                    addr,
                    listed: false,
                    ..
                })) => found.push((addr, DiscoveryRoute::JoinHandle)),
                Some(Ok(WaitTarget::Semaphore { waiters, .. })) => {
                    for waiter in waiters {
                        if let QueuedWaker::Task { addr, .. } = waiter.waker
                            && !list.contains(addr)
                        {
                            found.push((addr, DiscoveryRoute::QueuedWaker));
                        }
                    }
                }
                _ => {}
            }
        }
        found
    }

    /// Route 2: the task-Header pointers armed on timer entries parked
    /// in `runtimes`' own wheels that no enumerated task claims.
    ///
    /// The wheel is a registry of parked tasks whatever list owns them:
    /// every `tokio::time::Sleep` registers its `TimerShared` into it
    /// and arms the entry's `AtomicWaker` with the task's own waker, so
    /// a `LocalSet` member sleeping in a set nothing else points at is
    /// visible here and nowhere else. What identifies a waker as a
    /// task's is the same address-equality join on tokio's
    /// `WAKER_VTABLE` static that the wait-queue readers make; a waker
    /// that is not a task's, or a task that is already listed, is
    /// simply not a candidate.
    ///
    /// Failures degrade at the finest grain the walk allows: a runtime
    /// whose wheel cannot be reached costs its own wheel, a corrupt
    /// slot list costs the rest of that list, and everything else is
    /// still harvested.
    fn wheel_task_pointers(
        &self,
        runtimes: &[RuntimeRef<'b>],
        list: &TaskList,
    ) -> (Vec<(u64, DiscoveryRoute)>, Vec<anyhow::Error>) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        // Across the whole harvest: the same entry is in exactly one
        // slot, so a repeat is corrupt memory, not a second sighting.
        let mut visited = HashSet::default();
        for runtime in runtimes {
            if let Err(e) = self.harvest_wheel(runtime, list, &mut visited, &mut found, &mut errors)
            {
                errors.push(e.context(format!(
                    "failed to walk the timer wheel of the runtime at {:#x}",
                    runtime.handle.addr
                )));
            }
        }
        (found, errors)
    }

    /// Walk one runtime's wheel: six levels of 64 slots, each slot an
    /// intrusive list of `TimerShared`s. The levels and slots are plain
    /// arrays, read whole and iterated; only the lists are walked.
    fn harvest_wheel(
        &self,
        runtime: &RuntimeRef<'b>,
        list: &TaskList,
        visited: &mut HashSet<u64>,
        found: &mut Vec<(u64, DiscoveryRoute)>,
        errors: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
        // `driver.time` is an `Option`: a runtime built without the time
        // driver has no wheel, which is a runtime state, not a failure.
        let Some(levels) = self
            .walk(WalkRole::WheelLevels)
            .try_walk(runtime.handle)?
            .and_then(Walked::optional)
        else {
            return Ok(());
        };
        for level in levels.elements(self.proc)?.iter() {
            let slots = self.walk(WalkRole::LevelSlots).walk_at(level)?;
            for slot in slots.elements(self.proc)?.iter() {
                let Some(head) = self.walk(WalkRole::SlotHead).walk(slot)?.optional() else {
                    continue;
                };
                let addr = head.parse::<u64>(self.proc)?;
                let entry_ty = head
                    .ty
                    .pointer_target()
                    .ok_or_else(|| anyhow!("a wheel slot's head is not pointer-shaped"))?;
                if let Err(e) = self.walk_wheel_slot(addr, entry_ty, list, visited, found) {
                    errors.push(e.context(format!("failed to walk the wheel slot at {addr:#x}")));
                }
            }
        }
        Ok(())
    }

    /// Walk one slot's `TimerShared` list, collecting the task Headers
    /// its entries' wakers name.
    fn walk_wheel_slot(
        &self,
        head: u64,
        entry_ty: BundleType<'b>,
        list: &TaskList,
        visited: &mut HashSet<u64>,
        found: &mut Vec<(u64, DiscoveryRoute)>,
    ) -> Result<()> {
        let mut cur = Some(head);
        while let Some(addr) = cur {
            ensure!(
                self.mappings.contains_addr(addr),
                "timer-entry pointer {addr:#x} is unmapped"
            );
            ensure!(visited.insert(addr), "timer list cycle at {addr:#x}");
            let entry = Value::read(self.proc, entry_ty, addr)
                .with_context(|| format!("failed to read the TimerShared at {addr:#x}"))?;
            // An entry in the wheel with no waker registered has simply
            // not been polled since it was armed.
            if let Some(raw) = self
                .walk(WalkRole::TimerSharedWaker)
                .walk(entry)?
                .optional()
            {
                self.registry_candidate(raw, DiscoveryRoute::Wheel, list, found)?;
            }
            cur = self
                .walk(WalkRole::TimerSharedNext)
                .walk(entry)?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(anyhow::Error::from))
                .transpose()?;
        }
        Ok(())
    }

    /// Route 2's other registry: the task-Header pointers held by io
    /// resources registered with `runtimes`' own drivers that no
    /// enumerated task claims.
    ///
    /// The argument is the wheel's, for tasks waiting on a socket rather
    /// than on time: every io resource the runtime knows about is in the
    /// driver's registration list whatever list owns the task awaiting
    /// it, and awaiting readiness leaves the task's own waker on the
    /// resource. What identifies a waker as a task's is the same
    /// address-equality join on tokio's `WAKER_VTABLE` static every
    /// other reader makes.
    ///
    /// Failures degrade at the finest grain the walk allows: a runtime
    /// whose registrations cannot be reached costs its own driver, a
    /// resource whose waiters cannot be read costs that resource, and
    /// everything else is still harvested.
    pub(crate) fn io_task_pointers(
        &self,
        runtimes: &[RuntimeRef<'b>],
        list: &TaskList,
    ) -> (Vec<(u64, DiscoveryRoute)>, Vec<anyhow::Error>) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        // Across the whole harvest, for both node kinds: a registration
        // is in one driver's list and a waiter node in one resource's,
        // so a repeat is corrupt memory, not a second sighting.
        let mut visited = HashSet::default();
        for runtime in runtimes {
            if let Err(e) = self.harvest_io(runtime, list, &mut visited, &mut found, &mut errors) {
                errors.push(e.context(format!(
                    "failed to walk the io registrations of the runtime at {:#x}",
                    runtime.handle.addr
                )));
            }
        }
        (found, errors)
    }

    /// Walk one runtime's registration list, taking each resource's
    /// waiters as they come.
    fn harvest_io(
        &self,
        runtime: &RuntimeRef<'b>,
        list: &TaskList,
        visited: &mut HashSet<u64>,
        found: &mut Vec<(u64, DiscoveryRoute)>,
        errors: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
        // `driver.io` is the driver's flavor enum: a runtime built
        // without the io driver holds `Disabled` and registers nothing,
        // which is a runtime state, not a failure.
        let Some(head) = self
            .walk(WalkRole::IoRegistrations)
            .try_walk(runtime.handle)?
            .and_then(Walked::optional)
        else {
            return Ok(());
        };
        let io_ty = head
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("the io registration list's head is not pointer-shaped"))?;
        let mut cur = Some(head.parse::<u64>(self.proc)?);
        while let Some(addr) = cur {
            ensure!(
                self.mappings.contains_addr(addr),
                "io registration pointer {addr:#x} is unmapped"
            );
            ensure!(
                visited.insert(addr),
                "io registration list cycle at {addr:#x}"
            );
            let registration = Value::read(self.proc, io_ty, addr)
                .with_context(|| format!("failed to read the ScheduledIo at {addr:#x}"))?;
            if let Err(e) = self.harvest_io_waiters(registration, list, visited, found) {
                errors.push(e.context(format!(
                    "failed to walk the waiters of the io registration at {addr:#x}"
                )));
            }
            cur = self
                .walk(WalkRole::ScheduledIoNext)
                .walk(registration)?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(anyhow::Error::from))
                .transpose()?;
        }
        Ok(())
    }

    /// Everything parked on one io resource: the two direction slots,
    /// and the readiness list.
    ///
    /// The slots are where the `AsyncRead`/`AsyncWrite` paths leave a
    /// waker, and they are in no list at all — a harvest that walked
    /// only the list would miss the commoner of the two shapes.
    fn harvest_io_waiters(
        &self,
        registration: Value<'b>,
        list: &TaskList,
        visited: &mut HashSet<u64>,
        found: &mut Vec<(u64, DiscoveryRoute)>,
    ) -> Result<()> {
        let waiters = self
            .walk(WalkRole::ScheduledIoWaiters)
            .walk_at(registration)?;
        for role in [WalkRole::IoReaderWaker, WalkRole::IoWriterWaker] {
            // A direction nobody is awaiting holds no waker.
            if let Some(raw) = self.walk(role).walk(waiters)?.optional() {
                self.registry_candidate(raw, DiscoveryRoute::Io, list, found)?;
            }
        }
        let Some(head) = self.walk(WalkRole::IoWaiterHead).walk(waiters)?.optional() else {
            return Ok(());
        };
        let node_ty = head
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("an io waiter list's head is not pointer-shaped"))?;
        let mut cur = Some(head.parse::<u64>(self.proc)?);
        while let Some(addr) = cur {
            ensure!(
                self.mappings.contains_addr(addr),
                "io waiter pointer {addr:#x} is unmapped"
            );
            ensure!(visited.insert(addr), "io waiter list cycle at {addr:#x}");
            let node = Value::read(self.proc, node_ty, addr)
                .with_context(|| format!("failed to read the io Waiter at {addr:#x}"))?;
            // A node whose future has not been polled since it was
            // linked carries no waker yet.
            if let Some(raw) = self.walk(WalkRole::IoWaiterWaker).walk(node)?.optional() {
                self.registry_candidate(raw, DiscoveryRoute::Io, list, found)?;
            }
            cur = self
                .walk(WalkRole::IoWaiterNext)
                .walk(node)?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(anyhow::Error::from))
                .transpose()?;
        }
        Ok(())
    }

    /// One waker a registry holds, as a discovery candidate: a task's,
    /// and a task no list already claims. Anything else — a `block_on`
    /// thread's parker waker, a task the scheduler already owns — is
    /// simply not one.
    fn registry_candidate(
        &self,
        raw: Value<'b>,
        route: DiscoveryRoute,
        list: &TaskList,
        found: &mut Vec<(u64, DiscoveryRoute)>,
    ) -> Result<()> {
        if let QueuedWaker::Task { addr, .. } = self.raw_waker(raw)?
            && !list.contains(addr)
        {
            found.push((addr, route));
        }
        Ok(())
    }

    /// Route 1's tail: follow one unlisted Header home through its
    /// cell's scheduler, whatever that scheduler turns out to be. A
    /// task the bundle cannot classify — a `spawn_blocking` task, an
    /// unresolvable future — is the common, silent case; only a genuine
    /// read failure reports.
    #[allow(clippy::too_many_arguments)]
    fn bootstrap_unlisted(
        &self,
        addr: u64,
        route: DiscoveryRoute,
        excluded: &[u64],
        thread_ids: &[(u64, u32)],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        sets: &mut Vec<LocalSetRef<'b>>,
        errors: &mut Vec<anyhow::Error>,
    ) {
        let step = (|| -> Result<Option<(SchedulerKind, Value<'b>, u64)>> {
            ensure!(
                self.mappings.contains_addr(addr),
                "task Header pointer {addr:#x} is unmapped"
            );
            let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
            let header = Value::read(self.proc, header_ty, addr)?;
            let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
            let vtable = self.task_vtable(vtable_addr)?;
            let FutureInfo::Known(known) = self.resolve_future(&vtable) else {
                return Ok(None);
            };
            let entry = self.task_entry(known.entry);
            let kind = self.scheduler_kind(entry);
            if !matches!(
                kind,
                SchedulerKind::LocalSet | SchedulerKind::MultiThread | SchedulerKind::CurrentThread
            ) {
                return Ok(None);
            }
            let cell_ty =
                self.infra_ty(entry.cell, &format!("the Cell of {}", known.display_name))?;
            let cell = Value::read(self.proc, cell_ty, addr)?;
            let scheduler = self.walk(WalkRole::CellScheduler).walk_at(cell)?;
            let owner = self
                .arc_data(scheduler)
                .context("failed to follow the cell's scheduler Arc")?;
            let owner_id: Option<u64> = self.walk(WalkRole::HeaderOwnerId).read(header)?;
            let claim = owner_id
                .ok_or_else(|| anyhow!("the task at {addr:#x} records no owner_id to check"))?;
            Ok(Some((kind, owner, claim)))
        })();
        match step {
            Ok(Some((SchedulerKind::LocalSet, shared, claim))) => {
                self.admit_local_set(shared, Some(claim), None, route, thread_ids, sets, errors);
            }
            Ok(Some((SchedulerKind::MultiThread, handle, claim))) => self.admit_hidden_runtime(
                handle,
                RuntimeFlavor::MultiThread,
                claim,
                route,
                excluded,
                runtimes,
                errors,
            ),
            Ok(Some((SchedulerKind::CurrentThread, handle, claim))) => self.admit_hidden_runtime(
                handle,
                RuntimeFlavor::CurrentThread,
                claim,
                route,
                excluded,
                runtimes,
                errors,
            ),
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => errors.push(e.context(format!(
                "failed to follow the unlisted task at {addr:#x} home"
            ))),
        }
    }

    /// Admit a runtime handle route 1 reached from a task's own cell:
    /// dedup by handle address, then the decisive check — the
    /// scheduler's owned list must claim the very task that led there,
    /// exactly as a set's does.
    ///
    /// A handle already in `runtimes` is a runtime some thread's
    /// `Context` reached (or an earlier candidate of this loop), and one
    /// in `excluded` is a runtime the operator asked not to see; neither
    /// is news.
    #[allow(clippy::too_many_arguments)]
    fn admit_hidden_runtime(
        &self,
        handle: Value<'b>,
        flavor: RuntimeFlavor,
        claim: u64,
        route: DiscoveryRoute,
        excluded: &[u64],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        errors: &mut Vec<anyhow::Error>,
    ) {
        if runtimes.iter().any(|r| r.handle.addr == handle.addr) || excluded.contains(&handle.addr)
        {
            return;
        }
        let step = (|| -> Result<RuntimeRef<'b>> {
            let shared = self.walk(WalkRole::HandleShared).walk_at(handle)?;
            let owned_id: Option<u64> = self.walk(WalkRole::SchedulerOwnedId).try_read(shared)?;
            let owned_id = owned_id.ok_or_else(|| {
                anyhow!("the scheduler owned list's id did not bind against this target")
            })?;
            ensure!(
                claim == owned_id,
                "the runtime's owned-list id {owned_id} does not claim the task \
                 (owner_id {claim}) that led there"
            );
            Ok(RuntimeRef {
                flavor,
                handle,
                worker_tids: Vec::new(),
                route,
            })
        })();
        match step {
            Ok(runtime) => runtimes.push(runtime),
            Err(e) => errors.push(e.context(format!(
                "found a {flavor} runtime at {:#x} (via {route}) but could not read it",
                handle.addr
            ))),
        }
    }

    /// Admit a `Shared` some route reached: dedup by address, read the
    /// set's identity, and hold route 1's finds to the decisive check —
    /// the set must claim the very task that led there.
    #[allow(clippy::too_many_arguments)]
    fn admit_local_set(
        &self,
        shared: Value<'b>,
        claim: Option<u64>,
        tls_tid: Option<u32>,
        route: DiscoveryRoute,
        thread_ids: &[(u64, u32)],
        sets: &mut Vec<LocalSetRef<'b>>,
        errors: &mut Vec<anyhow::Error>,
    ) {
        if sets.iter().any(|set| set.shared.addr == shared.addr) {
            return;
        }
        let step = (|| -> Result<LocalSetRef<'b>> {
            let owned_id: u64 = self.walk(WalkRole::LocalOwnedId).read(shared)?;
            if let Some(claim) = claim {
                ensure!(
                    claim == owned_id,
                    "the set's owned-list id {owned_id} does not claim the task \
                     (owner_id {claim}) that led there"
                );
            }
            let owner: Option<u64> = self.walk(WalkRole::LocalSetOwner).try_read(shared)?;
            let owner_tid = tls_tid.or_else(|| {
                owner.and_then(|owner| {
                    thread_ids
                        .iter()
                        .find(|&&(id, _)| id == owner)
                        .map(|&(_, tid)| tid)
                })
            });
            Ok(LocalSetRef {
                shared,
                owned_id,
                owner,
                owner_tid,
                route,
            })
        })();
        match step {
            Ok(set) => sets.push(set),
            Err(e) => errors.push(e.context(format!(
                "found a local set at {:#x} (via {route}) but could not read it",
                shared.addr
            ))),
        }
    }

    /// Walk a discovered set's `LocalOwnedTasks` list — one more shard
    /// with a different root: the nodes are ordinary task Headers,
    /// linked through the same `Trailer.owned` pointers the scheduler's
    /// shards use. Every node must carry the set's `owned.id` as its
    /// `Header.owner_id`; a mismatch is reported and the task kept,
    /// since the list itself is the ground truth for membership.
    pub fn enumerate_local_tasks(&self, set: &LocalSetRef<'b>) -> Result<TaskList> {
        let mut tasks = Vec::new();
        let mut errors = Vec::new();
        let mut visited = HashSet::default();
        let what = format!("the local set at {:#x}", set.shared.addr);
        match self.walk(WalkRole::LocalOwnedHead).walk(set.shared)? {
            Walked::At(head) => {
                let head_addr = head
                    .parse::<u64>(self.proc)
                    .with_context(|| format!("failed to read the list head of {what}"))?;
                self.walk_owned_list(head_addr, &mut visited, &mut tasks, &mut errors, &what);
            }
            // An empty set.
            Walked::Inactive(_) | Walked::Null => {}
        }
        for task in &tasks {
            if task.owner_id != Some(set.owned_id) {
                errors.push(anyhow!(
                    "the task at {:#x} in {what} carries owner_id {}, not the set's {}",
                    task.addr.0,
                    task.owner_id
                        .map_or("<none>".to_owned(), |id| id.to_string()),
                    set.owned_id
                ));
            }
        }
        tasks.sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        Ok(TaskList { tasks, errors })
    }

    /// Cross an `Arc<T>` value to the `T` inside its `ArcInner`: the
    /// `ptr` member, the deref, the `data` member — the std layout the
    /// recorded discovery paths (`Context.handle`,
    /// `local::Context.shared`) spell the same way.
    ///
    /// Unlike those, this walks by value rather than by recorded steps,
    /// because the `Arc` it crosses is a *different type per task cell*
    /// — the `S` of `Cell<T, S>` — which one recorded binding cannot
    /// serve. Both hops therefore go through reify's peeling accessors,
    /// which see through the `NonNull` wrapper whether or not this
    /// build emitted it as its own type.
    fn arc_data(&self, arc: Value<'b>) -> Result<Value<'b>> {
        let inner = arc.member("ptr")?.deref_ptr(self.proc)?;
        Ok(inner.member("data")?)
    }

    // -----------------------------------------------------------------------
    // Off-path lock futures (RFD 609 futurelock)
    // -----------------------------------------------------------------------

    /// Scan a chain's frames for lock futures parked in locals, off the
    /// active poll path.
    ///
    /// The `__awaitee` spine is the only thing a suspended task will
    /// poll next; a `batch_semaphore::Acquire` reachable instead
    /// through some frame's saved locals belongs to a future the task
    /// stopped polling (an abandoned `select!` arm, typically). If
    /// that acquire is still queued — or worse, was already granted
    /// its permits — the task holds a place in line for a resource it
    /// can never take or release until the active await completes:
    /// the RFD 609 futurelock.
    ///
    /// Most locals are not futures; those are expected and skipped, as
    /// are trait objects whose concrete type is not in the bundle.
    /// Each local's own await chain is inspected, but the scan does
    /// not recurse into *its* locals.
    pub fn abandoned_acquires(&self, chain: &AwaitChain<'b>) -> Vec<AbandonedAcquire> {
        // The chain's own leaf acquire, when there is one: the same
        // future may also be reachable as a local (`&mut fut` in a
        // still-active select! arm), and that is not abandonment.
        let active_node = chain
            .frames
            .last()
            .filter(|_| matches!(chain.end, ChainEnd::Leaf))
            .filter(|f| {
                matches!(
                    leaf_kind(f.future.ty.name()),
                    Some(LeafKind::SemaphoreAcquire)
                )
            })
            .and_then(|f| {
                let node = self.walk(WalkRole::AcquireNode).walk_at(f.future).ok()?;
                Some(node.addr)
            });

        let mut found = Vec::new();
        for frame in &chain.frames {
            let Some(state) = &frame.state else { continue };
            let payload = state.payload;
            // The same positional slicing as the locals display: a
            // coroutine state may alias an upvar and a saved local.
            let mut seen = HashSet::default();
            for m in payload.ty.members() {
                if m.ty().size() == 0
                    || m.name().starts_with("__")
                    || !seen.insert((m.name(), m.offset()))
                {
                    continue;
                }
                let start = m.offset() as usize;
                let Some(bytes) = payload.bytes.get(start..start + m.ty().size() as usize) else {
                    continue;
                };
                let local = Value::new(m.ty(), payload.addr + m.offset(), bytes);
                let Some((future, owner, fields)) = self.local_acquire(local) else {
                    continue;
                };
                if Some(fields.node) == active_node || !fields.queued {
                    // On the poll path after all, or never enqueued:
                    // it holds nothing.
                    continue;
                }
                found.push(AbandonedAcquire {
                    frame: frame.future.ty.name().to_owned(),
                    state: state.name.to_owned(),
                    await_loc: state.await_loc.map(|(file, line)| (file.to_owned(), line)),
                    local: m.name().to_owned(),
                    future,
                    owner,
                    semaphore: fields.semaphore,
                    node: fields.node,
                    num_permits: fields.num_permits,
                    needed: fields.needed,
                });
            }
        }
        found
    }

    /// Interpret one local as a future and check whether its await
    /// chain bottoms out in a semaphore acquire.
    fn local_acquire(
        &self,
        local: Value<'b>,
    ) -> Option<(String, Option<&'static str>, AcquireFields)> {
        let peeled = local.peel();
        let root = if let Some(dp) = peeled.ty.dyn_pointer() {
            match self.resolve_dyn_future(peeled, &dp) {
                Ok(DynAwaitee::Resolved { future, .. }) => future,
                Ok(DynAwaitee::Unknown { .. } | DynAwaitee::Ambiguous { .. }) | Err(_) => {
                    return None;
                }
            }
        } else {
            local
        };
        let chain = self.await_chain(root);
        if !matches!(chain.end, ChainEnd::Leaf) {
            return None;
        }
        let leaf = chain.frames.last()?;
        if !matches!(
            leaf_kind(leaf.future.ty.name()),
            Some(LeafKind::SemaphoreAcquire)
        ) {
            return None;
        }
        let fields = self.read_acquire_fields(leaf.future).ok()?;
        let future = chain.frames.first()?.future.ty.name().to_owned();
        Some((future, semaphore_owner(&chain), fields))
    }

    /// The raw fields of a `batch_semaphore::Acquire`, read in place.
    fn read_acquire_fields(&self, acquire: Value<'b>) -> Result<AcquireFields> {
        Ok(AcquireFields {
            semaphore: self.walk(WalkRole::AcquireSemaphore).read(acquire)?,
            node: self.walk(WalkRole::AcquireNode).walk_at(acquire)?.addr,
            num_permits: self.walk(WalkRole::AcquireNumPermits).read(acquire)?,
            needed: self.walk(WalkRole::AcquireNeeded).read(acquire)?,
            queued: self.walk(WalkRole::AcquireQueued).read(acquire)?,
        })
    }
}

/// The raw fields of a `batch_semaphore::Acquire` future.
struct AcquireFields {
    /// Address of the contended `Semaphore`.
    semaphore: u64,
    /// Address of the `Waiter` node embedded in the acquire.
    node: u64,
    num_permits: u64,
    /// `Waiter.state`: permits still needed; 0 once fully granted.
    needed: u64,
    /// Whether the node was enqueued and has not since been dequeued
    /// by a completing poll or a drop. Stays stale-`true` after a
    /// grant until the future is polled again — which is exactly what
    /// makes an abandoned grant observable.
    queued: bool,
}

/// The normalized v0 key of every symbol, demangled across however many
/// threads the machine offers.
///
/// This demangles a debug binary's entire symtab — six figures of symbols,
/// with kilobyte-long names — which is the dominant cost of attaching to a
/// target whose fingerprint does not match exactly. The keys land in one
/// set, so the split carries no ordering to preserve.
///
/// Migrating this fan-out to the rayon pool was tested (2026-08-02) and
/// found slower: rayon's parallel reduce is a tree over every split,
/// whose extra merge levels cost +0.2 s of CPU on the nexus attach, and
/// reshaping to hand-sized chunks with a linear merge only reached
/// parity — the chunks are uniform enough that stealing has nothing to
/// level. Scoped threads stay.
fn normalized_key_set(symbols: &[SymbolBuf]) -> HashSet<String> {
    let workers = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let Some(chunk) = std::num::NonZeroUsize::new(symbols.len().div_ceil(workers)) else {
        return HashSet::default();
    };
    std::thread::scope(|scope| {
        let handles: Vec<_> = symbols
            .chunks(chunk.get())
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .filter_map(|s| normalized_v0_key(&s.name))
                        .collect::<HashSet<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("demangling does not panic"))
            .reduce(|mut set, chunk| {
                set.extend(chunk);
                set
            })
            .unwrap_or_default()
    })
}

/// A task vtable decoded from target memory (bundle layout, target values).
#[derive(Clone, Debug)]
struct TaskVtable {
    poll: u64,
    dealloc: Option<u64>,
    try_read_output: Option<u64>,
    drop_join_handle_slow: Option<u64>,
    drop_abort_handle: Option<u64>,
    shutdown: Option<u64>,
    trailer_offset: u64,
    id_offset: u64,
    spawn_location_offset: Option<u64>,
}

/// Where following one step of an await chain led: the next frame, or
/// the reason there is not one.
enum Follow<'b> {
    Next {
        future: Value<'b>,
        /// The dyn-vtable symbol that identified `future`, when it was
        /// not reached structurally.
        symbol: Option<String>,
    },
    Stop(ChainEnd),
}

/// The outcome of resolving one `dyn Future` awaitee.
enum DynAwaitee<'b> {
    /// The vtable joined: the concrete future, read from target memory,
    /// and the symbol that identified it.
    Resolved { future: Value<'b>, symbol: String },
    /// No vtable symbol joined the bundle's dyn-future table.
    Unknown { poll_symbol: Option<String> },
    /// The normalized symbol joined more than one concrete bundle type.
    Ambiguous {
        symbol: String,
        candidates: Vec<TypeCandidate>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testkit;

    use hansei_bundle::Bundle;
    use proc::snapshot::Snapshot;

    use std::sync::OnceLock;

    /// The `unordered` fixture pair: coroutines held plain and behind
    /// `Pin<Box<dyn Future>>`, a `FuturesUnordered`, and the tokio
    /// plumbing the predicates below pick from.
    fn unordered() -> &'static (Bundle, Snapshot) {
        static PAIR: OnceLock<(Bundle, Snapshot)> = OnceLock::new();
        PAIR.get_or_init(|| testkit::load_any("unordered"))
    }

    fn unordered_ctx() -> Context<'static, Snapshot> {
        let (bundle, snapshot) = unordered();
        testkit::context(bundle, snapshot)
    }

    /// The first bundle type satisfying `pred`, scanned in id order so
    /// one frozen fixture always yields the same type.
    fn find_ty<'b>(
        bundle: &'b Bundle,
        mut pred: impl FnMut(BundleType<'b>) -> bool,
    ) -> BundleType<'b> {
        let view = BundleView::new(bundle);
        (0..bundle.types.types.len() as u32)
            .filter_map(|i| view.ty(BundleTypeId(i)))
            .find(|ty| pred(*ty))
            .expect("the fixture bundle has such a type")
    }

    /// The `walk-shapes` pair, for the wrapper shapes the unordered
    /// fixture has no reason to carry.
    fn walk_shapes() -> &'static (Bundle, Snapshot) {
        static PAIR: OnceLock<(Bundle, Snapshot)> = OnceLock::new();
        PAIR.get_or_init(|| testkit::load_any("walk-shapes"))
    }

    /// The wrapper unwrap steps over zero-sized members: `WrapZ`'s only
    /// sized member is a future beside a `PhantomData`, and a filter
    /// that counts the marker sees two members and declines the whole
    /// stack.
    #[test]
    fn test_is_future_steps_over_zero_sized_members() {
        let (bundle, snapshot) = walk_shapes();
        let ctx = testkit::context(bundle, snapshot);
        let ty = find_ty(bundle, |t| t.name().starts_with("walk_shapes::WrapZ<"));
        assert!(!ctx.known_futures().contains(&ty.id()), "never polled");
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// A coroutine whose `poll` rustc inlined out of the symtab has no
    /// poll-table entry, and must still screen as a future on
    /// `is_coroutine` alone. Every debug-build fixture records every
    /// poll, so the documented condition — no symbol, no entry — is
    /// constructed here by taking the id out of the table.
    #[test]
    fn test_a_coroutine_off_the_poll_table_is_still_a_future() {
        let mut ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            t.is_coroutine() && leaf_kind(t.name()).is_none()
        });
        ctx.futures.remove(&ty.id());
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// The poll table alone is also enough: a hand-written future that
    /// is no coroutine and no named wait primitive screens on its
    /// recorded `poll`.
    #[test]
    fn test_a_poll_table_type_alone_is_a_future() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            ctx.known_futures().contains(&t.id())
                && !t.is_coroutine()
                && leaf_kind(t.name()).is_none()
                && t.dyn_pointer().is_none()
        });
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// Every coroutine is a future, named leaf or not: the screen's
    /// routes are alternatives, not conjuncts. Asserted over the whole
    /// bundle rather than one witness, because a single frame can be
    /// rescued through the unwrap loop (its sole member chains to a
    /// poll-table type) and hide a broken screen.
    #[test]
    fn test_every_coroutine_is_a_future() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let view = BundleView::new(bundle);
        let mut coroutines = 0;
        for i in 0..bundle.types.types.len() as u32 {
            let Some(t) = view.ty(BundleTypeId(i)) else {
                continue;
            };
            if t.is_coroutine() {
                coroutines += 1;
                assert!(ctx.is_future(t), "{}", t.name());
            }
        }
        assert!(coroutines > 0, "the fixture bundle has coroutines");
    }

    /// A wrapper that is not a future by any direct route answers by
    /// unwrapping its sole *sized* member — a filter that keeps ZSTs
    /// instead finds nothing to follow, and a step that never recurses
    /// never reaches the future inside. The witness is found by the
    /// unwrap contract itself, so it cannot silently degrade into a
    /// type the direct routes already accept.
    #[test]
    fn test_is_future_unwraps_the_sole_sized_member() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            if ctx.known_futures().contains(&t.id())
                || t.is_coroutine()
                || leaf_kind(t.name()).is_some()
                || t.dyn_pointer().is_some()
            {
                return false;
            }
            let mut sized = t.members().map(|m| m.ty()).filter(|m| m.size() > 0);
            match (sized.next(), sized.next()) {
                (Some(inner), None) => ctx.is_future(inner),
                _ => false,
            }
        });
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// Plain data is not a future, and neither is a multi-member
    /// container that merely holds them: the unwrap step follows a
    /// *sole* sized member, never guesses among several.
    #[test]
    fn test_is_future_declines_plain_data_and_containers() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let scalar = find_ty(bundle, |t| t.name() == "u32");
        assert!(!ctx.is_future(scalar));
        let set = find_ty(bundle, |t| {
            t.name()
                .starts_with("futures_util::stream::futures_unordered::FuturesUnordered<")
        });
        assert!(!ctx.is_future(set), "{}", set.name());
    }

    /// Where every hand-laid value is placed.
    const AT: u64 = 0x1000;

    /// The chain steps through a wrapper holding exactly one future,
    /// and the step lands at the member's own address. The witness is
    /// an enum variant payload whose sole future member sits at a
    /// nonzero offset, so a step that mis-adds the offset lands
    /// somewhere else and fails here rather than fabricating a frame.
    #[test]
    fn test_a_sole_inner_future_is_followed_at_its_member_offset() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            t.name().starts_with("core::option::Option<unordered::leaf")
                && t.name().ends_with("::Some")
        });
        let member = ty.members().next().expect("Some has a payload");
        assert!(member.offset() > 0, "the witness must not sit at zero");
        let bytes = vec![0u8; ty.size() as usize];
        let value = Value::new(ty, AT, &bytes);
        let (name, follow) = ctx
            .sole_inner_future(value)
            .expect("exactly one member is a future");
        assert_eq!(name, member.name());
        let Follow::Next { future, .. } = follow else {
            panic!("a by-value coroutine is followed, not stopped at");
        };
        assert_eq!(future.addr, AT + member.offset());
        assert_eq!(future.ty.id(), member.ty().id());
    }

    /// Two candidate futures and the rule declines: a combinator with
    /// several arms is a chain end, not a guess between them.
    #[test]
    fn test_two_candidate_futures_end_the_chain() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            t.name().starts_with("unordered::driver") && t.name().ends_with("::Suspend0")
        });
        let bytes = vec![0u8; ty.size() as usize];
        assert!(ctx.sole_inner_future(Value::new(ty, AT, &bytes)).is_none());
    }

    /// A buffer too short to hold the member's bytes declines rather
    /// than slicing out of range.
    #[test]
    fn test_a_short_buffer_declines_the_follow() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            t.name().starts_with("core::option::Option<unordered::leaf")
                && t.name().ends_with("::Some")
        });
        let bytes = vec![0u8; 1];
        assert!(ctx.sole_inner_future(Value::new(ty, AT, &bytes)).is_none());
    }
    /// The `local-set-io` fixture pair: a `LocalSet` parked on I/O,
    /// anchored both in the discovery statics and in its thread's TLS.
    fn local_set_io() -> &'static (Bundle, Snapshot) {
        static PAIR: OnceLock<(Bundle, Snapshot)> = OnceLock::new();
        PAIR.get_or_init(|| testkit::load_any("local-set-io"))
    }

    /// The vtable fallback of a task's extent — taken when the bundle
    /// has no Cell layout for the future — must still reach the
    /// trailer's end. Forced by handing the walk the same task with its
    /// future info erased, and pinned against the vtable spelling read
    /// here independently; the Cell route may exceed it only by the
    /// allocation's tail padding.
    #[test]
    fn test_an_unknown_futures_task_extent_reaches_the_trailers_end() {
        let ctx = unordered_ctx();
        let (_, snapshot) = unordered();
        let list = testkit::tasks(&ctx, snapshot);
        let known = list
            .tasks
            .iter()
            .find(|t| matches!(t.future, FutureInfo::Known(_)))
            .expect("the fixture has resolved tasks");
        let whole = ctx.task_extent(known).expect("the Cell route");
        // The Cell route is really the one that answered: the bundle's
        // Cell layout spans further than the vtable spelling below
        // reaches (the fixture driver's Cell carries tail padding), so
        // a walk shunted onto the fallback reports a different end.
        let FutureInfo::Known(k) = &known.future else {
            unreachable!()
        };
        let cell = ctx
            .view
            .ty(ctx.task_entry(k.entry).cell)
            .expect("the Cell layout is in the bundle");
        assert_eq!(whole.end - whole.start, cell.size());
        let erased = Task {
            addr: known.addr,
            state: known.state,
            owner_id: None,
            task_id: None,
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            group: 0,
        };
        let ext = ctx.task_extent(&erased).expect("the vtable route");
        assert_eq!(ext.start, known.addr.0);
        let header_ty = ctx
            .infra_ty(ctx.view.bundle().infra.header, "task Header")
            .unwrap();
        let header = Value::read(ctx.proc, header_ty, known.addr.0).unwrap();
        let vtable_addr: u64 = ctx.walk(WalkRole::HeaderVtable).read(header).unwrap();
        let vtable = ctx.task_vtable(vtable_addr).unwrap();
        let trailer_ty = ctx
            .infra_ty(ctx.view.bundle().infra.trailer, "task Trailer")
            .unwrap();
        assert_eq!(
            ext.end,
            known.addr.0 + vtable.trailer_offset + trailer_ty.size()
        );
        assert!(ext.end <= whole.end, "{ext:?} vs {whole:?}");
    }

    /// A bound walk role reports its recorded root type; the TLS probe
    /// reads the payload with it, so `None` here silently disables the
    /// whole route.
    #[test]
    fn test_walk_root_ty_reports_a_bound_roles_root() {
        let (bundle, snapshot) = local_set_io();
        let ctx = testkit::context(bundle, snapshot);
        let ty = ctx
            .walk_root_ty(WalkRole::LocalTlsCtx)
            .expect("the role is bound in the local-set-io bundle");
        assert!(ty.size() > 0);
    }

    /// A population discovery grew is re-sorted into task order; the
    /// enumerated prefix alone arrives sorted, so the gate that skips
    /// the sort when nothing was added must not skip it when
    /// something was.
    #[test]
    fn test_a_discovered_population_lists_in_task_order() {
        let (bundle, snapshot) = local_set_io();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let keys: Vec<_> = list
            .tasks
            .iter()
            .map(|t| (t.task_id.is_none(), t.task_id, t.addr.0))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}

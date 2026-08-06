// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bundle-based parsing of tokio runtime state (`HANSEI_V0_MANGLING_PLAN.md`
//! §9).
//!
//! Layouts come only from the bundle; addresses and bytes come only from the
//! target; the only thing that crosses between the two binaries is symbol
//! names (§2). Runtime discovery is the pthread-key flow (§3.0): the
//! bundle names the TLS-key static, the target's symtab locates it, and
//! its value indexes each LWP's fast-TSD slots to find that thread's
//! `tokio::runtime::context::Context`.

use super::{Lifecycle, Location, RawInstant, TaskAddr, TaskState};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use exegesis::bundle::{
    BundleType, BundleTypeId, BundleView, DynPointer, FutureKind, StaticRole, SymbolLookup,
    TaskEntryId, TaskFutureEntry, TypeDef, strip_build_prefix, strip_llvm_suffix,
};
use exegesis::symbols::normalized_v0_key;
use proc::{LwpInfo, Mappings, SymbolBuf, Target};
use reify::{ParseCtx, TypeInfo, TypeInfoRef};

use foldhash::{HashMap, HashSet};
use std::cell::RefCell;

use std::collections::BTreeMap;
use std::fmt;

/// Hard bound on await-chain depth: anything deeper indicates corrupt
/// memory (or a pathological program), and the walk must report it
/// rather than hang (§3.5).
const MAX_AWAIT_DEPTH: usize = 64;

/// Rust vtables place the drop-in-place glue in slot 0, size and align
/// in slots 1 and 2, and the trait's methods after; `Future`'s only
/// method is `poll`, so it is slot 3.
const VTABLE_SLOT_DROP: u64 = 0;
const VTABLE_SLOT_FUTURE_POLL: u64 = 3;

/// The leaf-future knowledge base (§3.6): the wait primitives hansei
/// can interpret, keyed by leaf type-name prefix. It grows one row (and
/// one reader fn) at a time, with no structural change.
///
/// The chain walker consults it too: a matching awaitee is a leaf even
/// when it peels to a pointer — a `JoinHandle` peels to the joined
/// task's `NonNull<Header>`, and following that would walk into another
/// task entirely.
const LEAF_FUTURES: &[(&str, LeafKind)] = &[
    ("tokio::time::sleep::Sleep", LeafKind::Sleep),
    (
        "tokio::runtime::task::join::JoinHandle<",
        LeafKind::JoinHandle,
    ),
    (
        "tokio::sync::batch_semaphore::Acquire",
        LeafKind::SemaphoreAcquire,
    ),
];

#[derive(Copy, Clone, Debug)]
pub(crate) enum LeafKind {
    Sleep,
    JoinHandle,
    SemaphoreAcquire,
}

pub(crate) fn leaf_kind(name: &str) -> Option<LeafKind> {
    LEAF_FUTURES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|(_, kind)| *kind)
}

/// Awaiter-frame prefixes naming the primitive whose semaphore an
/// `Acquire` leaf is queued on.
const SEMAPHORE_OWNERS: &[(&str, &str)] = &[
    ("tokio::sync::mutex::", "tokio::sync::Mutex"),
    ("tokio::sync::rwlock", "tokio::sync::RwLock"),
    ("tokio::sync::semaphore", "tokio::sync::Semaphore"),
];

/// The primitive wrapping an acquired semaphore, when the frame that
/// awaits the `Acquire` leaf names it.
fn semaphore_owner(chain: &AwaitChain<'_>) -> Option<&'static str> {
    chain.frames.iter().rev().nth(1).and_then(|frame| {
        let name = frame.future.ty.name();
        SEMAPHORE_OWNERS
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix))
            .map(|(_, owner)| *owner)
    })
}

/// Everything needed to interpret a target process through a loaded bundle.
pub struct Context<'b, T> {
    pub proc: &'b T,
    pub view: BundleView<'b>,
    pub mappings: Mappings,
    /// Target text address → mangled symtab name (`None` when the address
    /// resolves to no symbol). Mangled names are the join keys; demangling
    /// is display-only.
    symbols: RefCell<HashMap<u64, Option<String>>>,
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
}

impl<'b, T: Target> Context<'b, T> {
    pub fn new(proc: &'b T, view: BundleView<'b>) -> Result<Self> {
        let mappings = proc.mappings().context("failed to read target mappings")?;
        Ok(Self {
            proc,
            view,
            mappings,
            symbols: RefCell::new(HashMap::default()),
            object_symbols: RefCell::new(None),
            vtables: RefCell::new(HashMap::default()),
            waker_vtable: RefCell::new(None),
            stopped: RefCell::new(None),
        })
    }

    /// The target's monotonic clock at the moment it stopped: the latest lwp
    /// stop timestamp (`pr_tstamp`, which illumos stamps from the same
    /// `gethrtime` clock `Instant` reads). For a core that is the moment it
    /// was dumped; for a live target, the moment the grab halted it — either
    /// way, "now" as of everything else this session reads. `None` when no
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
        if let Some(cached) = self.symbols.borrow().get(&addr) {
            return cached.clone();
        }
        let name = self.proc.lookup_symbol_by_addr(addr).map(|s| s.name);
        self.symbols.borrow_mut().insert(addr, name.clone());
        name
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
    // Attach-time validation (§5.1)
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
    // Runtime discovery (§3.0)
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

    /// Probe every LWP for a live `Context` (§13.3: all LWPs, never thread
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
        let current_task_id = info
            .member("current_task_id")?
            .parse(self)
            .context("failed to parse Context.current_task_id")?;
        Ok(Worker {
            tid,
            context_addr,
            current_task_id,
        })
    }

    /// The thread-local `tokio::runtime::context::Context` at `addr`, as
    /// [`Context::find_workers`] located it.
    pub fn context_info(&self, addr: u64) -> Result<TypeInfo<'b, BundleType<'b>>> {
        let ty = self.infra_ty(
            self.view.bundle().infra.context,
            "tokio::runtime::context::Context",
        )?;
        TypeInfo::from_addr(self, ty, addr)
            .with_context(|| format!("failed to read Context at {addr:#x}"))
    }

    /// Navigate from the workers' `Context`s to the multi_thread
    /// scheduler's `Handle` (`Context.current.handle` →
    /// `Option<scheduler::Handle>` → `MultiThread(Arc<Handle>)` → deref →
    /// `.data`).
    ///
    /// The handle is the root of everything the runtime shares: the
    /// scheduler state under `shared`, the io/time/signal drivers under
    /// `driver`.
    pub fn find_handle(&self, workers: &[Worker]) -> Result<TypeInfo<'b, BundleType<'b>>> {
        let mut saw_other_scheduler = false;
        for worker in workers {
            let info = self.context_info(worker.context_addr)?;
            let handle = info.member("current")?.member("handle")?.member("value")?;
            let Some(some) = handle.try_select_variant("Some")? else {
                continue;
            };
            let Some(mt) = some.try_select_variant("MultiThread")? else {
                // current_thread is out of scope (§13.4).
                saw_other_scheduler = true;
                continue;
            };
            let inner = mt.deref_ptr(self)?; // ArcInner<multi_thread::Handle>
            return Ok(inner.member("data")?.to_owned());
        }
        if saw_other_scheduler {
            bail!("only MultiThread runtimes are supported, and none was found");
        }
        bail!("no worker thread has a runtime handle in its Context");
    }

    /// The scheduler state the workers share, from the runtime handle
    /// [`Context::find_handle`] reaches.
    pub fn find_shared(&self, workers: &[Worker]) -> Result<TypeInfo<'b, BundleType<'b>>> {
        let handle = self.find_handle(workers)?;
        let shared = handle.member("shared")?.to_owned();
        Ok(shared)
    }

    /// The scheduler context a worker thread is running under: the
    /// `multi_thread::worker::Context` its stack holds, reached through
    /// the scoped pointer in its thread-local `Context`.
    ///
    /// `None` when the thread is in the runtime without being inside the
    /// scheduler — the pointer is set only for the duration of a
    /// worker's run loop — or when it runs a scheduler hansei does not
    /// read.
    pub fn worker_context(&self, worker: &Worker) -> Result<Option<TypeInfo<'b, BundleType<'b>>>> {
        let info = self.context_info(worker.context_addr)?;
        // `Scoped` and the `Cell` inside it are single-member wrappers,
        // so the member lands straight on the pointer they hold. It is
        // null outside the run loop; anything else has to be readable,
        // so the deref is the strict one — an unreadable pointer is a
        // failure to report, not a thread to pass over.
        let scoped = info.member("scheduler")?;
        if scoped.parse::<u64, _>(self)? == 0 {
            return Ok(None);
        }
        let sched = scoped.deref_ptr(self)?;
        let Some(mt) = sched.as_ref().try_select_variant("MultiThread")? else {
            return Ok(None);
        };
        Ok(Some(mt.to_owned()))
    }

    /// Which worker of the scheduler a thread is running, as the
    /// scheduler numbers them, from the context
    /// [`Context::worker_context`] returned.
    pub fn worker_index(&self, worker_ctx: &TypeInfo<'b, BundleType<'b>>) -> Result<u64> {
        let worker = worker_ctx.member("worker")?.deref_ptr(self)?;
        Ok(worker.member("data")?.member("index")?.parse(self)?)
    }

    /// What every worker's parker says, in worker-index order.
    ///
    /// A parked worker's `Parker` is a stack local — the run loop moves
    /// it out of the `Core` before parking — so it is not reachable from
    /// the thread. The `Unparker` in the worker's `Remote` shares the
    /// same allocation, though, and that hangs off the shared scheduler
    /// state, so every worker's state word is readable from one place
    /// whether or not the thread holding it can be walked.
    pub fn park_states(&self, handle: &TypeInfo<'b, BundleType<'b>>) -> Result<ParkStates> {
        let shared = handle.member("shared")?;
        let remotes = shared.member("remotes")?;
        // The driver's lock lives under the parkers' own shared state,
        // which every `Inner` points at; the first one answers for all.
        let mut driver_held = None;
        let workers = remotes
            .boxed_slice_elements(self, |remote| {
                let arc = remote.member("unpark")?.deref_ptr(self)?;
                let inner = arc.member("data")?;
                if driver_held.is_none() {
                    let park_shared = inner.member("shared")?.deref_ptr(self)?;
                    // The parkers' `Shared` holds the driver's lock and
                    // nothing else, so reaching for it lands *past* it,
                    // on the lock — a single-member struct is peeled
                    // away by the member that names it. Take the lock
                    // however the member landed.
                    let shared = park_shared.member("data")?;
                    let lock = match shared.try_member("driver")? {
                        Some(lock) => lock,
                        None => shared,
                    };
                    driver_held = Some(lock.member("locked")?.parse(self)?);
                }
                Ok(ParkState::from_word(inner.member("state")?.parse(self)?))
            })
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
    pub fn blocking_pool(&self, handle: &TypeInfo<'b, BundleType<'b>>) -> Result<BlockingPool> {
        let arc = handle.member("blocking_spawner")?.deref_ptr(self)?;
        let metrics = arc.member("data")?.member("metrics")?;
        Ok(BlockingPool {
            threads: metrics.member("num_threads")?.parse(self)?,
            idle: metrics.member("num_idle_threads")?.parse(self)?,
            queued: metrics.member("queue_depth")?.parse(self)?,
        })
    }

    // -----------------------------------------------------------------------
    // Task enumeration (§3.1–§3.4)
    // -----------------------------------------------------------------------

    /// Walk `Shared.owned`'s sharded intrusive lists and parse every task.
    ///
    /// Corrupt memory degrades per shard: the failing shard contributes an
    /// error, the rest of the listing is unaffected (§11.5).
    pub fn enumerate_tasks(&self, shared: &TypeInfo<'b, BundleType<'b>>) -> Result<TaskList> {
        let list = shared.member("owned")?.member("list")?.to_owned();

        let mut tasks = Vec::new();
        let mut errors = Vec::new();
        // Guards against cycles from corrupt memory, across shards: the
        // same Header must never appear twice.
        let mut visited = HashSet::default();
        let mut shard = 0usize;

        list.as_ref()
            .member("lists")?
            .boxed_slice_elements(self, |elem| {
                let this_shard = shard;
                shard += 1;

                let head = elem.member("data")?.member("head")?;
                let head_addr = match head.try_select_variant("Some")? {
                    Some(ptr) => ptr.parse::<u64, _>(self)?,
                    None => return Ok(()),
                };

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
                            errors.push(e.context(format!(
                                "task walk failed in shard {this_shard} at {addr:#x}"
                            )));
                            break;
                        }
                    }
                }
                Ok(())
            })
            .context("failed to walk OwnedTasks shards")?;

        tasks.sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        Ok(TaskList { tasks, errors })
    }

    /// Parse one task from its `Header` address; returns the task and the
    /// next Header in the owned list (via `Trailer.owned`, §3.1).
    fn parse_task(&self, addr: u64) -> Result<(Task, Option<u64>)> {
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let info = TypeInfo::from_addr(self, header_ty, addr)
            .with_context(|| format!("failed to read task Header at {addr:#x}"))?;

        let state = TaskState(info.member("state")?.parse(self)?);
        let owner_id = info.member("owner_id")?.parse(self)?;

        let vtable_addr: u64 = info.member("vtable")?.parse(self)?;
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
        };
        Ok((task, next))
    }

    /// Decode a `task::raw::Vtable` from target memory using the bundle's
    /// layout — the struct is `#[repr(Rust)]`, so offsets must never be
    /// assumed from declaration order (§3.3).
    fn task_vtable(&self, vtable_addr: u64) -> Result<TaskVtable> {
        if let Some(vt) = self.vtables.borrow().get(&vtable_addr) {
            return Ok(vt.clone());
        }

        let ty = self.infra_ty(self.view.bundle().infra.vtable, "task Vtable")?;
        let info = TypeInfo::from_addr(self, ty, vtable_addr)?;
        let field = |name: &str| -> Result<Option<u64>> {
            match info.try_member(name)? {
                Some(m) => Ok(Some(m.parse(self)?)),
                None => Ok(None),
            }
        };
        let required = |name: &str| -> Result<u64> {
            field(name)?.ok_or_else(|| anyhow!("bundle Vtable layout has no {name:?} member"))
        };

        let vt = TaskVtable {
            poll: required("poll")?,
            dealloc: field("dealloc")?,
            try_read_output: field("try_read_output")?,
            drop_join_handle_slow: field("drop_join_handle_slow")?,
            drop_abort_handle: field("drop_abort_handle")?,
            shutdown: field("shutdown")?,
            trailer_offset: required("trailer_offset")?,
            id_offset: required("id_offset")?,
            // Only present under `tokio_unstable` + task instrumentation.
            spawn_location_offset: field("spawn_location_offset")?,
        };
        self.vtables.borrow_mut().insert(vtable_addr, vt.clone());
        Ok(vt)
    }

    /// The v0 pivot (§3.3): resolve the vtable's monomorphized fns via the
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
        let mut ambiguous: Option<(String, Vec<String>)> = None;
        for addr in candidates.into_iter().flatten() {
            let Some(symbol) = self.symbol_at(addr) else {
                continue;
            };
            let entry_id = match self.view.task_ids_for_symbol(&symbol) {
                SymbolLookup::Unique(id) => id,
                SymbolLookup::Ambiguous(ids) => {
                    let names = ids
                        .into_iter()
                        .filter_map(|id| self.view.bundle().tasks.entries.get(id.0 as usize))
                        .filter_map(|entry| self.view.str(entry.display_name))
                        .map(str::to_owned)
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

    /// Cheap bundle/target mismatch canary (§3.3): the offsets stored in the
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
        let Some(trailer) = cell.member("trailer") else {
            return Ok(());
        };
        ensure!(
            trailer.offset() == vt.trailer_offset,
            "bundle/target layout mismatch for {}: bundle Cell.trailer at {:#x}, \
             target vtable trailer_offset {:#x}",
            known.display_name,
            trailer.offset(),
            vt.trailer_offset
        );
        if let Some(core) = cell.member("core")
            && let Some(task_id) = core.ty().member("task_id")
        {
            let expected = core.offset() + task_id.offset();
            ensure!(
                expected == vt.id_offset,
                "bundle/target layout mismatch for {}: bundle Core.task_id at {:#x}, \
                 target vtable id_offset {:#x}",
                known.display_name,
                expected,
                vt.id_offset
            );
        }
        Ok(())
    }

    fn task_entry(&self, id: TaskEntryId) -> &'b TaskFutureEntry {
        // Ids handed out by task_entry_for_symbol always index the table.
        &self.view.bundle().tasks.entries[id.0 as usize]
    }

    /// Read a `core::panic::Location` from target memory. The strings live
    /// in the *target's* rodata; the bundle only supplies the layout.
    fn read_location(&self, loc_ptr: u64) -> Result<Location> {
        let ty = self.infra_ty(self.view.bundle().infra.location, "core::panic::Location")?;
        let info = TypeInfo::from_addr(self, ty, loc_ptr)
            .with_context(|| format!("failed to read Location at {loc_ptr:#x}"))?;
        let file_info = match info.try_member("filename")? {
            Some(m) => m,
            // Pre-rename std spells the field `file`.
            None => info.member("file")?,
        };
        // `file!()` records the path as rustc saw it on the build machine,
        // so a registry crate names itself in full. Cut it down the same way
        // extraction cuts a line-table path, or one file is spelled two ways
        // in one listing (`tasks` prints a task's spawn site beside its
        // future's declaration).
        let filename: String = file_info.parse(self)?;
        let line = info.member("line")?.parse(self)?;
        let col = info.member("col")?.parse(self)?;
        Ok(Location {
            filename: strip_build_prefix(&filename).into_owned(),
            line,
            col,
        })
    }

    /// Follow the owned-list link out of a task's `Trailer` (§3.1: the
    /// next/prev pointers live in `Trailer.owned`, not the Header).
    fn owned_next(&self, trailer_addr: u64) -> Result<Option<u64>> {
        let ty = self.infra_ty(self.view.bundle().infra.trailer, "task Trailer")?;
        let info = TypeInfo::from_addr(self, ty, trailer_addr)
            .with_context(|| format!("failed to read Trailer at {trailer_addr:#x}"))?;
        // Trailer.owned: linked_list::Pointers<Header>, which peels down to
        // its inner { prev, next } struct.
        let next = info
            .member("owned")?
            .member("next")?
            .try_select_variant("Some")?
            .map(|ptr| ptr.parse(self))
            .transpose()?;
        Ok(next)
    }

    // -----------------------------------------------------------------------
    // Task tracing (§3.4–§3.5)
    // -----------------------------------------------------------------------

    /// Decode a task's `Stage<T>` (§3.4): the future lives at
    /// `header_addr + offset(Cell.core) + offset(Core.stage)`, and the
    /// stage's discriminant says whether the state machine is resident.
    ///
    /// Requires the future type to have been resolved (§3.3); an unknown
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
                candidates.join(", ")
            ),
        };
        let entry = self.task_entry(known.entry);
        let cell_ty = self.infra_ty(entry.cell, &format!("the Cell of {}", known.display_name))?;
        let cell = TypeInfo::from_addr(self, cell_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Cell at {:?}", task.addr))?;
        // Cell.core.stage peels through CoreStage and the UnsafeCells down
        // to the Stage<T> enum.
        let stage = cell.member("core")?.member("stage")?;
        let (state, payload) = stage
            .active_variant()
            .context("failed to decode the task's Stage")?;
        match state {
            // The payload peels to its single sized member: T itself for
            // Running, Result<T::Output, JoinError> for Finished.
            "Running" => Ok(TaskStage::Running(payload.to_owned())),
            "Finished" => Ok(TaskStage::Finished(payload.to_owned())),
            "Consumed" => Ok(TaskStage::Consumed),
            other => bail!("unexpected Stage variant {other:?}"),
        }
    }

    /// Walk a resident future's await chain (§3.5), outermost future
    /// first.
    ///
    /// The walk never fails outright: whatever decoded cleanly is in
    /// [`AwaitChain::frames`], and [`AwaitChain::end`] says why it
    /// stopped. Corrupt memory is contained by the depth bound and an
    /// (address, type) cycle guard.
    pub fn await_chain(&self, root: TypeInfo<'b, BundleType<'b>>) -> AwaitChain<'b> {
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

            // A future that *is* a dyn wide pointer (a spawned
            // `Pin<Box<dyn Future>>`): resolve the concrete type through
            // its vtable before decoding anything.
            if let Some(dp) = cur.as_ref().peel().ty.dyn_pointer() {
                match self.resolve_dyn_future(&cur.as_ref().peel(), &dp) {
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

            // Decode the coroutine state. Non-enums are leaf futures:
            // sync primitives, I/O futures, combinator structs.
            let decoded = match cur.ty.active_variant(&cur.buf) {
                None => {
                    frames.push(AwaitFrame {
                        future: cur,
                        state: None,
                        dyn_symbol,
                    });
                    break ChainEnd::Leaf;
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
                    });
                    break ChainEnd::Error(err);
                }
            };

            // Coroutine variant members are numbered; their state names
            // live on the payload structs (§5.5). Ordinary enums (sync
            // primitives, combinators like MaybeDone) are leaves: an
            // await chain is linear, while a combinator may hold several
            // pending futures — per-combinator knowledge is §9 scope.
            let is_coroutine_state =
                !decoded.name.is_empty() && decoded.name.bytes().all(|b| b.is_ascii_digit());

            // Slice out the variant payload *without* peeling: its
            // members are the state's live locals.
            let start = decoded.offset as usize;
            let size = decoded.ty.size() as usize;
            let Some(bytes) = cur.buf.get(start..start + size) else {
                let err = anyhow!(
                    "variant payload {}..{} does not fit {} bytes of {}",
                    start,
                    start + size,
                    cur.buf.len(),
                    cur.ty.name(),
                );
                frames.push(AwaitFrame {
                    future: cur,
                    state: None,
                    dyn_symbol,
                });
                break ChainEnd::Error(err);
            };
            let payload = TypeInfoRef::new(decoded.ty, cur.addr + decoded.offset, bytes).to_owned();
            frames.push(AwaitFrame {
                future: cur,
                state: Some(FrameState {
                    name: decoded.state_name(),
                    await_loc: decoded.await_loc(),
                    payload,
                }),
                dyn_symbol: dyn_symbol.take(),
            });
            if !is_coroutine_state {
                break ChainEnd::Leaf;
            }

            // A suspended coroutine stores what it awaits in the
            // variant's `__awaitee` member; states that aren't waiting
            // (Unresumed, Returned, Panicked) have none.
            let payload = &frames.last().unwrap().state.as_ref().unwrap().payload;
            let Some(member) = payload.ty.member("__awaitee") else {
                break ChainEnd::Leaf;
            };
            let start = member.offset() as usize;
            let size = member.ty().size() as usize;
            let Some(bytes) = payload.buf.get(start..start + size) else {
                break ChainEnd::Error(anyhow!(
                    "__awaitee {}..{} does not fit {} bytes of {}",
                    start,
                    start + size,
                    payload.buf.len(),
                    payload.ty.name(),
                ));
            };
            let awaitee = TypeInfoRef::new(member.ty(), payload.addr + member.offset(), bytes);

            // Wrappers (Pin, mainly) hide what the pointer-shaped
            // awaitees really are; plain awaitees keep their own type so
            // the chain reports e.g. `oneshot::Receiver<u32>` rather than
            // whatever its innards peel down to.
            let peeled = awaitee.clone().peel();
            if let Some(dp) = peeled.ty.dyn_pointer() {
                // A boxed trait object: only its vtable knows the
                // concrete type (§3.5).
                match self.resolve_dyn_future(&peeled, &dp) {
                    Ok(DynAwaitee::Resolved { future, symbol }) => {
                        cur = future;
                        dyn_symbol = Some(symbol);
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
            } else if leaf_kind(awaitee.ty.name()).is_some() {
                // A recognized wait primitive is a leaf regardless of its
                // shape; [`Context::wait_target`] interprets it.
                cur = awaitee.to_owned();
            } else if peeled.ty.pointer_target().is_some() {
                // `(&mut fut).await`, `Box<fut>`: follow the thin pointer.
                match peeled.deref_ptr(self) {
                    Ok(info) => cur = info,
                    Err(e) => {
                        break ChainEnd::Error(
                            anyhow!(e).context("failed to follow an awaited pointer"),
                        );
                    }
                }
            } else {
                cur = awaitee.to_owned();
            }
        };

        AwaitChain { frames, end }
    }

    /// Resolve a `dyn Future` wide pointer (§3.5): read its data and
    /// vtable pointers from the already-read payload bytes, resolve the
    /// vtable's poll fn — or its drop glue, for polls internalized out of
    /// the symtab — through the *target's* symtab, and join the mangled
    /// symbol against the bundle's dyn-future table. Never guesses.
    fn resolve_dyn_future(
        &self,
        ptr: &TypeInfoRef<'_, 'b, BundleType<'b>>,
        dp: &DynPointer<'b>,
    ) -> Result<DynAwaitee<'b>> {
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
            match self.view.dyn_future_ids_for_symbol(&symbol) {
                SymbolLookup::Unique(id) => {
                    let ty = self.view.ty(id).expect("validated bundle type id");
                    let future = TypeInfo::from_addr(self, ty, data)
                        .with_context(|| format!("failed to read {} at {data:#x}", ty.name()))?;
                    return Ok(DynAwaitee::Resolved { future, symbol });
                }
                SymbolLookup::Ambiguous(ids) => {
                    let candidates = ids
                        .into_iter()
                        .filter_map(|id| self.view.ty(id))
                        .map(|ty| ty.name().to_owned())
                        .collect();
                    return Ok(DynAwaitee::Ambiguous { symbol, candidates });
                }
                SymbolLookup::Missing => {}
            }
        }
        Ok(DynAwaitee::Unknown { poll_symbol })
    }

    // -----------------------------------------------------------------------
    // The leaf-future knowledge base (§3.6)
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
            LeafKind::Sleep => self.read_sleep(&leaf.future),
            LeafKind::JoinHandle => self.read_join_handle(&leaf.future, list),
            LeafKind::SemaphoreAcquire => self.read_acquire(&leaf.future, chain),
        })
    }

    /// `tokio::time::Sleep`: the deadline its timer entry registered.
    fn read_sleep(&self, sleep: &TypeInfo<'b, BundleType<'b>>) -> Result<WaitTarget> {
        let entry = sleep.member("entry")?;
        let deadline = match entry.try_member("deadline")? {
            // Older tokios: `entry` is the TimerEntry itself.
            Some(deadline) => deadline,
            // tokio 1.52's `runtime::Timer` is an enum over the two
            // timer implementations (traditional wheel vs time_alt);
            // both variants carry the registered deadline.
            None => entry.active_variant()?.1.member("deadline")?,
        };
        // The deadline is tokio's Instant, which peels down to the std
        // Timespec on the target's monotonic clock.
        let tv_sec: i64 = deadline.member("tv_sec")?.parse(self)?;
        let tv_nsec: u32 = deadline.member("tv_nsec")?.parse(self)?;
        Ok(WaitTarget::Timer {
            deadline: RawInstant {
                tv_sec: tv_sec as u64,
                tv_nsec,
            },
            stopped: self.stopped_at(),
        })
    }

    /// A `JoinHandle<T>`: the task being awaited — a dependency edge
    /// between tasks (§3.6).
    fn read_join_handle(
        &self,
        handle: &TypeInfo<'b, BundleType<'b>>,
        list: &TaskList,
    ) -> Result<WaitTarget> {
        // JoinHandle.raw: RawTask, which peels to the NonNull<Header>.
        let addr: u64 = handle.member("raw")?.parse(self)?;
        let (task_id, state) = self
            .header_task_ref(addr)
            .context("failed to identify the joined task")?;
        Ok(WaitTarget::Task {
            addr,
            task_id,
            state,
            listed: list.contains(addr),
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
        let header = TypeInfo::from_addr(self, header_ty, addr)
            .with_context(|| format!("failed to read the task Header at {addr:#x}"))?;
        let state = TaskState(header.member("state")?.parse(self)?);
        let vtable_addr: u64 = header.member("vtable")?.parse(self)?;
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
        let header = TypeInfo::from_addr(self, header_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Header at {:?}", task.addr))?;
        let vtable_addr: u64 = header.member("vtable")?.parse(self)?;
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
    fn read_acquire(
        &self,
        acquire: &TypeInfo<'b, BundleType<'b>>,
        chain: &AwaitChain<'b>,
    ) -> Result<WaitTarget> {
        let semaphore = acquire.member("semaphore")?;
        let addr: u64 = semaphore.parse(self)?;
        let num_permits: u64 = acquire.member("num_permits")?.parse(self)?;
        let sem = semaphore
            .deref_ptr(self)
            .context("failed to read the Semaphore")?;
        // `permits` keeps the available count shifted above the CLOSED
        // bit.
        let raw: u64 = sem.member("permits")?.parse(self)?;
        let owner = semaphore_owner(chain);
        let waiters = self
            .semaphore_waiters(&sem)
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
    fn semaphore_waiters(
        &self,
        sem: &TypeInfo<'b, BundleType<'b>>,
    ) -> Result<Vec<SemaphoreWaiter>> {
        // Semaphore.waiters is a loom Mutex over the Waitlist; both the
        // parking_lot and std mutexes beneath it spell the payload
        // member `data`.
        let queue = sem.member("waiters")?.member("data")?.member("queue")?;
        let Some(head) = queue.member("head")?.try_select_variant("Some")? else {
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
        let mut cur = Some(head.parse::<u64, _>(self)?);
        while let Some(addr) = cur {
            ensure!(
                self.mappings.contains_addr(addr),
                "wait-queue pointer {addr:#x} is unmapped"
            );
            ensure!(visited.insert(addr), "wait-queue cycle at {addr:#x}");
            let node = TypeInfo::from_addr(self, waiter_ty, addr)
                .with_context(|| format!("failed to read the Waiter at {addr:#x}"))?;
            waiters.push(SemaphoreWaiter {
                addr,
                needed: node.member("state")?.parse(self)?,
                waker: self.read_queued_waker(&node)?,
            });
            cur = node
                .member("pointers")?
                .member("next")?
                .try_select_variant("Some")?
                .map(|ptr| ptr.parse(self))
                .transpose()?;
        }
        waiters.reverse();
        Ok(waiters)
    }

    /// Decode the waker registered in a wait-queue node. Task wakers are
    /// recognized by their vtable: tokio builds them as `(data = the
    /// task's Header, vtable = &WAKER_VTABLE)`, and the bundle names that
    /// static (§3.6).
    fn read_queued_waker(&self, node: &TypeInfo<'b, BundleType<'b>>) -> Result<QueuedWaker> {
        // Waiter.waker: UnsafeCell<Option<Waker>>; the Some payload
        // peels through the Waker to its RawWaker.
        let Some(raw) = node.member("waker")?.try_select_variant("Some")? else {
            return Ok(QueuedWaker::Unarmed);
        };
        let data: u64 = raw.member("data")?.parse(self)?;
        let vtable: u64 = raw.member("vtable")?.parse(self)?;
        if self.task_waker_vtable()? == Some(vtable) {
            let (task_id, _) = self
                .header_task_ref(data)
                .context("failed to identify the task behind a queued waker")?;
            Ok(QueuedWaker::Task {
                addr: data,
                task_id,
            })
        } else {
            Ok(QueuedWaker::Other { vtable })
        }
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
            .and_then(|f| f.future.member("node").ok().map(|node| node.addr));

        let mut found = Vec::new();
        for frame in &chain.frames {
            let Some(state) = &frame.state else { continue };
            let payload = state.payload.as_ref();
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
                let local = TypeInfoRef::new(m.ty(), payload.addr + m.offset(), bytes);
                let Some((future, owner, fields)) = self.local_acquire(&local) else {
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
        local: &TypeInfoRef<'_, 'b, BundleType<'b>>,
    ) -> Option<(String, Option<&'static str>, AcquireFields)> {
        let peeled = local.clone().peel();
        let root = if let Some(dp) = peeled.ty.dyn_pointer() {
            match self.resolve_dyn_future(&peeled, &dp) {
                Ok(DynAwaitee::Resolved { future, .. }) => future,
                Ok(DynAwaitee::Unknown { .. } | DynAwaitee::Ambiguous { .. }) | Err(_) => {
                    return None;
                }
            }
        } else {
            local.to_owned()
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
        let fields = self.read_acquire_fields(&leaf.future).ok()?;
        let future = chain.frames.first()?.future.ty.name().to_owned();
        Some((future, semaphore_owner(&chain), fields))
    }

    /// The raw fields of a `batch_semaphore::Acquire`, read in place.
    fn read_acquire_fields(&self, acquire: &TypeInfo<'b, BundleType<'b>>) -> Result<AcquireFields> {
        let node = acquire.member("node")?;
        Ok(AcquireFields {
            semaphore: acquire.member("semaphore")?.parse(self)?,
            node: node.addr,
            num_permits: acquire.member("num_permits")?.parse(self)?,
            needed: node.member("state")?.parse(self)?,
            queued: acquire.member("queued")?.parse(self)?,
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

impl<T: Target> ParseCtx for Context<'_, T> {
    type Target = T;

    fn proc(&self) -> &T {
        self.proc
    }
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

/// Result of resolving the bundle's symbol fingerprint against the target
/// (§5.1).
#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub total: usize,
    pub matched: usize,
    pub missing: Vec<String>,
}

impl Fingerprint {
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// A thread with a live `tokio::runtime::context::Context`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Worker {
    pub tid: u32,
    pub context_addr: u64,
    /// The task this thread is polling right now, if any.
    pub current_task_id: Option<u64>,
}

/// What every worker's parker says, and whether the io driver is held
/// at all; see [`Context::park_states`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ParkStates {
    /// One state per worker, in worker-index order.
    pub workers: Vec<ParkState>,
    /// Whether some thread holds the driver. A driver held with no
    /// worker parked in it is a thread polling it without parking —
    /// a zero-duration park, or one already notified out of its sleep.
    pub driver_held: bool,
}

impl ParkStates {
    /// The worker parked in the io driver, if one is. At most one can
    /// be: parking there means holding the driver's lock.
    pub fn in_driver(&self) -> Option<usize> {
        self.workers.iter().position(|s| *s == ParkState::Driver)
    }
}

/// A worker thread's park state, as its `Parker`'s state word records
/// it. The words are tokio's own constants, folded into its code at
/// compile time and so — as with [`TaskState`](super::TaskState)'s bits
/// — knowable only from its source.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ParkState {
    /// Not parked: in the run loop, or polling a task.
    Awake,
    /// Parked on the parker's own condvar, with no driver to park in
    /// because another worker holds it.
    Condvar,
    /// Parked *in* the driver: blocked in the system's readiness call
    /// on the whole runtime's behalf. There is no io thread in a
    /// multi_thread runtime — the driver rotates between workers — so
    /// this is whichever worker held it when the target stopped.
    Driver,
    /// Unparked but not yet awake: something called `unpark` and the
    /// worker has not consumed the notification. One parked in the
    /// driver stays blocked there until the readiness call returns.
    Notified,
    /// A word tokio does not define, which means its constants or this
    /// layout have moved.
    Unknown(u64),
}

impl ParkState {
    fn from_word(word: u64) -> Self {
        match word {
            0 => Self::Awake,
            1 => Self::Condvar,
            2 => Self::Driver,
            3 => Self::Notified,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ParkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Awake => f.write_str("awake"),
            Self::Condvar => f.write_str("parked"),
            Self::Driver => f.write_str("parked in the io driver"),
            Self::Notified => f.write_str("notified, waking"),
            Self::Unknown(word) => write!(f, "an unknown park state ({word})"),
        }
    }
}

/// The blocking pool's own counters; see [`Context::blocking_pool`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct BlockingPool {
    pub threads: u64,
    pub idle: u64,
    pub queued: u64,
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

/// The result of walking every owned-task shard.
#[derive(Debug)]
pub struct TaskList {
    /// Sorted by task id (tasks with no readable id last, by address).
    pub tasks: Vec<Task>,
    /// Per-shard walk failures; the shards that produced `tasks` are
    /// unaffected by these.
    pub errors: Vec<anyhow::Error>,
}

impl TaskList {
    /// Whether the walk enumerated a task whose Header is at `addr`. A
    /// live Header this returns false for belongs to something the
    /// scheduler's owned list never carries: a `spawn_blocking` task,
    /// or a task of some other runtime in the process.
    pub fn contains(&self, addr: u64) -> bool {
        self.tasks.iter().any(|t| t.addr.0 == addr)
    }
}

/// Every task's allocation, sorted by address, for resolving raw
/// pointers — a queued waker's data word, the `NonNull<Header>` inside
/// a `JoinHandle`, any address a value dump shows. Built by
/// [`Context::task_extents`].
#[derive(Debug)]
pub struct TaskExtents {
    /// `(start, end, index into the list this was built from)`.
    spans: Vec<(u64, u64, usize)>,
}

impl TaskExtents {
    /// The task whose allocation contains `addr`: its index in the
    /// [`TaskList`] this was built from, and the offset inside the
    /// allocation.
    pub fn locate(&self, addr: u64) -> Option<(usize, u64)> {
        let at = self.spans.partition_point(|&(start, _, _)| start <= addr);
        let &(start, end, index) = self.spans.get(at.checked_sub(1)?)?;
        (addr < end).then(|| (index, addr - start))
    }
}

/// One enumerated task.
#[derive(Debug)]
pub struct Task {
    pub addr: TaskAddr,
    pub state: TaskState,
    pub owner_id: Option<u64>,
    pub task_id: Option<u64>,
    /// Where the task was spawned, when the target records it
    /// (`tokio_unstable` task instrumentation).
    pub spawn_location: Option<Location>,
    pub future: FutureInfo,
}

/// The task's concrete future type, resolved via the symbol join — or not.
#[derive(Debug)]
pub enum FutureInfo {
    Known(KnownFuture),
    /// No vtable fn symbol matched the bundle's task table. The raw symbol
    /// is reported so the operator can see what the target called it;
    /// nothing is guessed.
    Unknown {
        poll_symbol: Option<String>,
    },
    /// Normalization joined the vtable functions to distinct task entries.
    Ambiguous {
        symbol: String,
        candidates: Vec<String>,
    },
}

/// A future resolved through the bundle's task join table.
#[derive(Debug)]
pub struct KnownFuture {
    pub entry: TaskEntryId,
    /// Demangled name of the future type (display only).
    pub display_name: String,
    pub kind: FutureKind,
    /// Source file/line where the future is defined (§5.5 provenance).
    pub decl: Option<(String, u32)>,
    /// The mangled vtable-fn symbol the join matched on.
    pub symbol: String,
}

/// A task's decoded `Stage<T>` (§3.4).
#[derive(Debug)]
pub enum TaskStage<'b> {
    /// The state machine is resident; walk it with
    /// [`Context::await_chain`].
    Running(TypeInfo<'b, BundleType<'b>>),
    /// `Result<T::Output, JoinError>`: the task returned, panicked, or
    /// was cancelled, and the output has not been consumed yet.
    Finished(TypeInfo<'b, BundleType<'b>>),
    /// The output was already taken through the join handle.
    Consumed,
}

/// The await chain of a resident future (§3.5), outermost future first.
#[derive(Debug)]
pub struct AwaitChain<'b> {
    pub frames: Vec<AwaitFrame<'b>>,
    /// Why the walk stopped; anything but [`ChainEnd::Leaf`] left the
    /// chain incomplete.
    pub end: ChainEnd,
}

impl AwaitChain<'_> {
    /// The type this chain bottoms out in — the future actually parked
    /// on, whether or not it is one of the primitives
    /// [`Context::wait_target`] decodes.
    ///
    /// `None` where the walk stopped short of a leaf, since the last
    /// frame it did reach is then a future awaiting something unread
    /// rather than the thing being waited on, and reporting it as the
    /// leaf would say the chain ended where it was merely cut off.
    pub fn leaf(&self) -> Option<&str> {
        match self.end {
            ChainEnd::Leaf => self.frames.last().map(|f| f.future.ty.name()),
            _ => None,
        }
    }
}

/// One future in an await chain.
#[derive(Debug)]
pub struct AwaitFrame<'b> {
    /// The future being polled at this depth.
    pub future: TypeInfo<'b, BundleType<'b>>,
    /// The decoded coroutine state; `None` for plain (leaf) futures.
    pub state: Option<FrameState<'b>>,
    /// The mangled symbol that identified this frame, when it was
    /// reached through a `dyn Future` vtable in target memory.
    pub dyn_symbol: Option<String>,
}

/// A coroutine frame's decoded state.
#[derive(Debug)]
pub struct FrameState<'b> {
    /// The human-readable state name (`Unresumed`, `Suspend0`, …).
    pub name: &'b str,
    /// The awaited expression's source location, when the debug info
    /// recorded it (§5.5).
    pub await_loc: Option<(&'b str, u32)>,
    /// The active variant's payload: the state's live locals, including
    /// compiler-generated `__…` slots and the `__awaitee` itself.
    pub payload: TypeInfo<'b, BundleType<'b>>,
}

/// Why an await-chain walk stopped.
#[derive(Debug)]
pub enum ChainEnd {
    /// Bottomed out normally: a non-coroutine leaf future, or a state
    /// with nothing awaited.
    Leaf,
    /// A `dyn Future` awaitee whose vtable symbols joined nothing in the
    /// bundle; the raw poll symbol is reported and nothing is guessed
    /// (§3.3).
    UnknownDyn {
        /// The `dyn Trait` spelling, for display.
        pointee: String,
        /// The mangled symbol the vtable's poll slot resolved to, if any.
        poll_symbol: Option<String>,
    },
    /// Normalization joined the vtable symbol to distinct concrete types.
    AmbiguousDyn {
        /// The `dyn Trait` spelling, for display.
        pointee: String,
        /// The target's raw mangled symbol.
        symbol: String,
        /// Concrete bundle type names sharing the normalized key.
        candidates: Vec<String>,
    },
    /// The depth bound was hit.
    DepthLimit,
    /// The same (address, type) pair reappeared.
    Cycle { addr: u64 },
    /// Reading or decoding below the last frame failed.
    Error(anyhow::Error),
}

/// What a leaf future is waiting on (§3.6).
#[derive(Clone, Debug)]
pub enum WaitTarget {
    /// `tokio::time::Sleep`: parked on the timer wheel until a deadline
    /// on the target's monotonic clock. `stopped` is the same clock at the
    /// moment the target stopped (the core was dumped, or the live grab
    /// halted it), when the lwps report one — the deadline relative to it is
    /// the wait remaining at that instant.
    Timer {
        deadline: RawInstant,
        stopped: Option<RawInstant>,
    },
    /// A `JoinHandle`: waiting for another task to finish — a
    /// dependency edge between tasks.
    Task {
        addr: u64,
        task_id: Option<u64>,
        /// The joined task's state word. A complete task has left the
        /// owned list (no listing shows it; the handle's reference is
        /// what keeps its Header alive), so the join is already
        /// satisfied and its awaiter merely unpolled.
        state: TaskState,
        /// Whether the enumerated task list contains the target. False
        /// with an incomplete state means the task is alive somewhere
        /// this session cannot list: the blocking pool, or another
        /// runtime.
        listed: bool,
    },
    /// `batch_semaphore::Acquire`: queued on the semaphore that backs
    /// tokio's Mutex, RwLock, and Semaphore.
    Semaphore {
        addr: u64,
        /// The wrapping primitive, when the awaiting frame names it.
        owner: Option<&'static str>,
        num_permits: u64,
        available: u64,
        closed: bool,
        /// The semaphore's wait queue, in wake order.
        waiters: Vec<SemaphoreWaiter>,
    },
}

/// The bucket a wait falls in: what a tally counts, without the
/// addresses and the wake queue a [`WaitTarget`] spells out for one
/// row. Small and `Copy`, so a census that finds a thousand futures
/// waiting on one contended semaphore does not carry a thousand copies
/// of its queue around to count them.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum WaitKind {
    /// The timer wheel. `past_due` says whether the deadline had
    /// already passed when the target stopped, and is `None` where the
    /// target stamps no stop time to compare against.
    Timer { past_due: Option<bool> },
    /// Another task, through its `JoinHandle`.
    Task,
    /// A semaphore, named by the primitive wrapping it where the frame
    /// awaiting it says which (`tokio::sync::Mutex`, …).
    Semaphore { owner: Option<&'static str> },
}

impl WaitTarget {
    /// This wait as a tally counts it.
    pub fn kind(&self) -> WaitKind {
        match self {
            Self::Timer { deadline, stopped } => WaitKind::Timer {
                past_due: stopped.map(|stopped| {
                    (deadline.tv_sec, deadline.tv_nsec) < (stopped.tv_sec, stopped.tv_nsec)
                }),
            },
            Self::Task { .. } => WaitKind::Task,
            Self::Semaphore { owner, .. } => WaitKind::Semaphore { owner: *owner },
        }
    }
}

/// One node in a semaphore's wait queue.
#[derive(Clone, Debug)]
pub struct SemaphoreWaiter {
    /// The `Waiter` node's address; it lives inside the suspended
    /// `Acquire` future itself.
    pub addr: u64,
    /// Permits this waiter still needs. A released permit is assigned
    /// here, so 0 means the waiter has been granted everything it asked
    /// for and merely awaits its next poll.
    pub needed: u64,
    /// Who waking this node schedules.
    pub waker: QueuedWaker,
}

/// A lock future parked in a suspended frame's locals, off the active
/// poll path, still queued on — or already granted — a semaphore
/// (RFD 609; see [`Context::abandoned_acquires`]).
#[derive(Clone, Debug)]
pub struct AbandonedAcquire {
    /// Type name of the frame whose locals hold the future.
    pub frame: String,
    /// The suspend state that frame is parked in, and the awaited
    /// expression it is suspended at, when recorded.
    pub state: String,
    pub await_loc: Option<(String, u32)>,
    /// The local's name in that frame.
    pub local: String,
    /// The held future's concrete type (dyn-resolved when boxed).
    pub future: String,
    /// The primitive wrapping the semaphore, when the future's own
    /// chain names it.
    pub owner: Option<&'static str>,
    /// Address of the contended `Semaphore`.
    pub semaphore: u64,
    /// The abandoned `Waiter` node (it appears in the semaphore's wake
    /// queue while still ungranted).
    pub node: u64,
    /// Permits the acquire asked for, and how many it still needs.
    pub num_permits: u64,
    pub needed: u64,
}

impl AbandonedAcquire {
    /// Whether the acquire was granted everything it asked for: the
    /// future holds the resource and, unpolled, can never release it.
    pub fn granted(&self) -> bool {
        self.needed == 0
    }
}

/// The waker registered in a wait-queue node.
#[derive(Clone, Debug)]
pub enum QueuedWaker {
    /// A tokio task waker: the wake edge points at this task.
    Task { addr: u64, task_id: Option<u64> },
    /// Not a task waker (a `block_on` thread, say) — or the
    /// `WAKER_VTABLE` static could not be resolved in the target.
    Other { vtable: u64 },
    /// No waker registered.
    Unarmed,
}

impl fmt::Display for WaitTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timer { deadline, stopped } => {
                // Relative to the stop instant when the lwps stamp one — the
                // wait remaining as of the moment the target was observed
                // (negative once the deadline has passed) — else the absolute
                // point, which is all there is to say.
                if let Some(stopped) = stopped {
                    let ns = |i: &RawInstant| i.tv_sec as i128 * 1_000_000_000 + i.tv_nsec as i128;
                    let delta = ns(deadline) - ns(stopped);
                    let sign = if delta < 0 { "-" } else { "" };
                    let delta = delta.unsigned_abs();
                    write!(
                        f,
                        "the timer: deadline {sign}{}.{:03}s",
                        delta / 1_000_000_000,
                        (delta % 1_000_000_000) / 1_000_000
                    )
                } else {
                    write!(
                        f,
                        "the timer: deadline {}.{:03}s on the target's monotonic clock",
                        deadline.tv_sec,
                        deadline.tv_nsec / 1_000_000
                    )
                }
            }
            Self::Task {
                task_id,
                addr,
                state,
                listed,
            } => {
                match task_id {
                    Some(id) => write!(f, "task {id} (JoinHandle)")?,
                    None => write!(f, "the task at {addr:#x} (JoinHandle)")?,
                }
                // Either way the listings cannot show it: complete
                // means off the owned list, alive only through this
                // handle; alive-but-unlisted means it runs somewhere
                // this session does not enumerate.
                if state.lifecycle() == Lifecycle::Complete {
                    write!(f, " — already complete, awaiting consumption")?;
                } else if !listed {
                    write!(
                        f,
                        " — {}, but not in the scheduler's owned tasks \
                         (a spawn_blocking task, or another runtime's)",
                        state.lifecycle()
                    )?;
                }
                Ok(())
            }
            Self::Semaphore {
                addr,
                owner,
                num_permits,
                available,
                closed,
                waiters,
            } => {
                match owner {
                    Some(owner) => write!(f, "a {owner} (semaphore {addr:#x})")?,
                    None => write!(f, "the semaphore at {addr:#x}")?,
                }
                let plural = if *num_permits == 1 { "" } else { "s" };
                write!(
                    f,
                    ": {num_permits} permit{plural} requested, {available} available"
                )?;
                if *closed {
                    write!(f, ", closed")?;
                }
                if !waiters.is_empty() {
                    write!(f, "; wake queue:")?;
                    for (i, w) in waiters.iter().enumerate() {
                        let sep = if i == 0 { " " } else { ", " };
                        match &w.waker {
                            QueuedWaker::Task {
                                task_id: Some(id), ..
                            } => write!(f, "{sep}task {id}")?,
                            QueuedWaker::Task {
                                addr,
                                task_id: None,
                            } => write!(f, "{sep}the task at {addr:#x}")?,
                            QueuedWaker::Other { .. } => write!(f, "{sep}a non-task waiter")?,
                            QueuedWaker::Unarmed => write!(f, "{sep}an unarmed waiter")?,
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// The outcome of resolving one `dyn Future` awaitee.
enum DynAwaitee<'b> {
    /// The vtable joined: the concrete future, read from target memory,
    /// and the symbol that identified it.
    Resolved {
        future: TypeInfo<'b, BundleType<'b>>,
        symbol: String,
    },
    /// No vtable symbol joined the bundle's dyn-future table.
    Unknown { poll_symbol: Option<String> },
    /// The normalized symbol joined more than one concrete bundle type.
    Ambiguous {
        symbol: String,
        candidates: Vec<String>,
    },
}

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

use super::Lifecycle;
pub use super::model::*;

use super::contract::{self, ContractReport, WalkPolicy, Walked};
use super::observe::{
    AcquireObservation, Consistency, IoFutureState, IoObservation, JoinObservation, Observed,
    QueueObservation, ReadContext, ReferenceSink, ReferenceSource, ResourceObservation, ScanBudget,
    ScanLimits, TimerObservation, TimerRegistrationState, ValueKey, WalkIssue, WalkIssueKind,
    issue_of, lock_consistency,
};
use super::semantics::SemanticIndex;
use super::{Location, RawInstant, TaskAddr, TaskState};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use hansei_bundle::symbols::normalized_v0_key;
use hansei_bundle::tokio::{semaphore, timer};
use hansei_bundle::{
    BundleType, BundleTypeId, BundleView, ContainerKind, DynPointer, FutureKind, IoOperationKind,
    ResourceKind, StaticRole, Step, StoragePolicy, SymbolLookup, TaskEntryId, TaskFutureEntry,
    TypeDef, TypeSemantics, WalkOutcome, WalkRole, strip_build_prefix, strip_llvm_suffix,
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

/// The io resource types the fd join recognizes: the fully-qualified
/// name a frame member (or its pointee) must bear, and the two walk
/// roles rooted at that type — the route to its `ScheduledIo` (the io
/// registry's join key) and to its fd.
const IO_RESOURCES: &[(&str, WalkRole, WalkRole)] = &[
    (
        "tokio::net::tcp::stream::TcpStream",
        WalkRole::TcpStreamShared,
        WalkRole::TcpStreamFd,
    ),
    (
        "tokio::net::tcp::listener::TcpListener",
        WalkRole::TcpListenerShared,
        WalkRole::TcpListenerFd,
    ),
    (
        "tokio::net::udp::UdpSocket",
        WalkRole::UdpSocketShared,
        WalkRole::UdpSocketFd,
    ),
    (
        "tokio::net::unix::stream::UnixStream",
        WalkRole::UnixStreamShared,
        WalkRole::UnixStreamFd,
    ),
    (
        "tokio::net::unix::listener::UnixListener",
        WalkRole::UnixListenerShared,
        WalkRole::UnixListenerFd,
    ),
    (
        "tokio::net::unix::datagram::socket::UnixDatagram",
        WalkRole::UnixDatagramShared,
        WalkRole::UnixDatagramFd,
    ),
];

/// Whether a blocking cell is the runtime's own machinery riding its
/// pool — a worker being launched — rather than target work. The
/// parameter names what the closure is: everything the runtime
/// spawns onto its own pool lives under `tokio::runtime::`.
fn runtime_internal_blocking(display_name: &str) -> bool {
    display_name.starts_with("tokio::runtime::blocking::task::BlockingTask<tokio::runtime::")
}

#[cfg(test)]
mod blocking_filter_tests {
    /// The pool lists target work and skips the runtime launching its
    /// own workers through itself — the one cell whose presence is
    /// capture timing rather than target state.
    #[test]
    fn test_runtime_internal_blocking_screens_on_the_parameter() {
        assert!(super::runtime_internal_blocking(
            "tokio::runtime::blocking::task::BlockingTask<\
             tokio::runtime::scheduler::multi_thread::worker::Launch::launch::{closure_env#0}>"
        ));
        assert!(!super::runtime_internal_blocking(
            "tokio::runtime::blocking::task::BlockingTask<\
             blocking_pool::main::{async_block#0}::{closure_env#0}>"
        ));
        // Only a blocking cell's spelling is screened at all.
        assert!(!super::runtime_internal_blocking(
            "tokio::runtime::whatever"
        ));
    }
}

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
    semantics: SemanticIndex,
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
        let semantics = SemanticIndex::new(
            view.bundle().types.types.len(),
            &view.bundle().semantics.types,
        )?;
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
            semantics,
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

    /// Borrow the bundle's independent type facts. Missing facts establish no
    /// semantic capability; lookup does not inspect names or display formats.
    pub fn type_semantics(&self, ty: BundleTypeId) -> Option<&TypeSemantics> {
        self.semantics
            .get(ty)
            .map(|index| &self.view.bundle().semantics.types[index])
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
            .ok_or_else(|| anyhow!("the tokio info has no type entry for {what}"))?;
        if matches!(ty.def(), TypeDef::Opaque { .. }) {
            bail!(
                "the tokio info has no layout for {what} \
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
                    "the tokio info records no TLS context static \
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
                // A live variant holding a null `Arc` is not a valid
                // state for a runtime. The most likely cause is that the
                // dumper failed to record the memory in this range,
                // causing it to be zeroed in the dump. This will be
                // parsed as an `Option<scheduler::Handle>` with a null
                // pointer in its `Arc`. So long as one thread was
                // correctly recorded we can still find the runtime,
                // so skip this thread and continue on.
                Some(Walked::Null) => {}
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
    /// [`Context::find_runtimes`] reached, the scheduler context
    /// [`Context::ct_worker_context`] returned for that thread, and the
    /// task id its thread-local `Context` carries ([`Worker::current_task_id`]).
    ///
    /// The core's whereabouts and the task id together are the state:
    /// the core is checked into the context's `RefCell` while the
    /// thread parks (driver taken out of it) and while it polls (driver
    /// still in it) — the root future when no task id is set, the task
    /// with that id otherwise — and held on the stack, unreadable from
    /// here, only between polls. See [`CtActivity`] for the table.
    pub fn ct_park_state(
        &self,
        handle: Value<'b>,
        ct_ctx: Value<'b>,
        current_task_id: Option<u64>,
    ) -> Result<CtParkState> {
        let woken = self.walk(WalkRole::CtSharedWoken).read(handle)?;
        let activity = match self.walk(WalkRole::CtWorkerCore).walk(ct_ctx)?.optional() {
            None => match current_task_id {
                None => CtActivity::BetweenPolls,
                Some(id) => CtActivity::DroppingTask(id),
            },
            Some(core) => match self.walk(WalkRole::CtCoreDriver).walk(core)? {
                Walked::At(_) => match current_task_id {
                    None => CtActivity::PollingBlockOn,
                    Some(id) => CtActivity::PollingTask(id),
                },
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
                // The runtime's own list is what led here, so the read
                // is held to nothing beyond the target's mappings.
                let header = self.read_task_header(TaskAddr(addr), &ReadContext::none())?;
                let next = self
                    .owned_next(addr + header.trailer_offset)
                    .context("failed to read Trailer.owned links")?;
                tasks.push(header.into_task());
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

    /// Decode a task from its `Header` address: everything the Header
    /// and the vtable it names establish, whoever handed the pointer
    /// over — an owned list, a `JoinHandle`, a registered waker, a
    /// blocking-pool queue entry. Nothing here reads the Trailer, so a
    /// handle to a task whose owned-list links are unreadable still
    /// identifies it; following the list is [`Context::walk_owned_list`]'s
    /// own step.
    ///
    /// `read` is what the Header's bytes are held to: a candidate in
    /// memory the allocator has taken back is refused before it is
    /// decoded into a task that is not there.
    pub fn read_task_header(
        &self,
        addr: TaskAddr,
        read: &ReadContext<'_>,
    ) -> Result<DecodedTaskHeader> {
        let identity = self.header_identity(addr.0, read)?;
        let vtable = &identity.vtable;

        let spawn_location = match vtable.spawn_location_offset {
            Some(off) => {
                let loc_ptr = self
                    .proc
                    .read_u64(addr.0 + off)
                    .map_err(|e| anyhow!(e).context("failed to read spawn location pointer"))?;
                Some(self.read_location(loc_ptr)?)
            }
            None => None,
        };

        let future = self.resolve_future(vtable);
        if let FutureInfo::Known(known) = &future {
            self.cross_check_offsets(vtable, known)?;
        }

        Ok(DecodedTaskHeader {
            addr,
            state: identity.state,
            owner_id: identity.owner_id,
            task_id: identity.task_id,
            spawn_location,
            vtable_addr: identity.vtable_addr,
            trailer_offset: vtable.trailer_offset,
            future,
        })
    }

    /// The first stage of [`Context::read_task_header`]: the Header's
    /// own words and the vtable they name, which is as far as the
    /// readers that only need a task's id and state go — a waker's
    /// data pointer is asked about tens of thousands of times on a
    /// production target, and neither the spawn location nor the
    /// future join is part of that answer.
    fn header_identity(&self, addr: u64, read: &ReadContext<'_>) -> Result<HeaderIdentity> {
        ensure!(
            self.mappings.contains_addr(addr),
            "task Header pointer {addr:#x} is unmapped"
        );
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        if let Some(refusal) = read.refusal(addr, header_ty.size()) {
            return Err(
                anyhow::Error::new(refusal).context(format!("the task Header at {addr:#x}"))
            );
        }
        let header = Value::read(self.proc, header_ty, addr)
            .with_context(|| format!("failed to read the task Header at {addr:#x}"))?;

        let state = TaskState(self.walk(WalkRole::HeaderState).read(header)?);
        let owner_id = self.walk(WalkRole::HeaderOwnerId).read(header)?;

        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;

        let id_addr = addr
            .checked_add(vtable.id_offset)
            .ok_or_else(|| anyhow!("{addr:#x} + {:#x} overflows", vtable.id_offset))?;
        let raw_id = self.proc.read_u64(id_addr).map_err(|e| {
            anyhow!(e).context(format!(
                "failed to read the task id at {addr:#x}+{:#x}",
                vtable.id_offset
            ))
        })?;
        // The id is a NonZeroU64; zero means we misread something.
        let task_id = (raw_id != 0).then_some(raw_id);

        Ok(HeaderIdentity {
            state,
            owner_id,
            task_id,
            vtable_addr,
            vtable,
        })
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
            "tokio-info/target layout mismatch for {}: recorded Cell.trailer at {:#x}, \
             target vtable trailer_offset {:#x}",
            known.display_name,
            trailer_offset,
            vt.trailer_offset
        );
        if let Some(id_offset) = self.walk(WalkRole::CellTaskId).member_offset(cell) {
            ensure!(
                id_offset == vt.id_offset,
                "tokio-info/target layout mismatch for {}: recorded Core.task_id at {:#x}, \
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

    /// Whether `addr` falls in any of the target's mapped regions —
    /// the cheap screen for an address argument before anything walks
    /// or scans for it.
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.mappings.contains_addr(addr)
    }

    /// The waker parked in a task's `Trailer`: armed by the first poll
    /// of a `JoinHandle` awaiting the task — task completion wakes it —
    /// and [`QueuedWaker::Unarmed`] where nothing has polled one. The
    /// Trailer's place is read from the task's own vtable, the way
    /// [`Context::task_extent`] places it.
    pub fn trailer_waker(&self, task: &Task) -> Result<QueuedWaker> {
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let header = Value::read(self.proc, header_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Header at {:?}", task.addr))?;
        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;
        let trailer_addr = task.addr.0 + vtable.trailer_offset;
        let ty = self.infra_ty(self.view.bundle().infra.trailer, "task Trailer")?;
        let trailer = Value::read(self.proc, ty, trailer_addr)
            .with_context(|| format!("failed to read Trailer at {trailer_addr:#x}"))?;
        let Some(raw) = self.walk(WalkRole::TrailerWaker).walk(trailer)?.optional() else {
            return Ok(QueuedWaker::Unarmed);
        };
        self.raw_waker(raw)
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
                bail!(
                    "the task's future type is not in the tokio info{sym}; nothing can be traced"
                );
            }
            FutureInfo::Ambiguous { symbol, candidates } => bail!(
                "the task's future symbol {symbol} is ambiguous: {}; nothing can be traced",
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
            let is_primitive = self.leaf_kind(cur.ty.id()).is_some();

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
        if self.leaf_kind(awaitee.ty.id()).is_none() && peeled.ty.pointer_target().is_some()
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
    /// Whether the bundle positively recognizes `id` as a future: a
    /// task entry, a recorded `poll`, a bound coroutine layout or a
    /// delegation names it, or a reviewed resource layout binds it (a
    /// `Sleep` is tokio's `Sleep` by its layout, and that is a future).
    /// Absence is not proof of the opposite — an inlined-away `poll`
    /// leaves no symbol, an unreviewed compiler no layout — which is why
    /// callers degrade rather than conclude.
    pub(crate) fn recognized_future(&self, id: BundleTypeId) -> bool {
        self.type_semantics(id)
            .is_some_and(|record| record.future.is_some() || record.resource.is_some())
    }

    /// Whether the bundle declares a type's storage unreadable: a
    /// compiler-storage candidate no reviewed convention bound, or a
    /// layout extraction could not keep. Such a value is stopped at,
    /// never scanned as whatever it is shaped like.
    pub(crate) fn storage_unavailable(&self, id: BundleTypeId) -> bool {
        self.type_semantics(id)
            .is_some_and(|record| matches!(record.storage, StoragePolicy::Unavailable(_)))
    }

    /// The container a type is bound as, if any.
    pub(crate) fn container_kind(&self, id: BundleTypeId) -> Option<ContainerKind> {
        self.type_semantics(id)?.container.as_ref().map(|c| c.kind)
    }

    /// The wait primitive a type is bound as — what [`Context::wait_target`]
    /// knows how to read. An io operation binding is a resource too, but
    /// no reader interprets it yet, so it is no leaf here.
    pub(crate) fn leaf_kind(&self, id: BundleTypeId) -> Option<LeafKind> {
        match self.type_semantics(id)?.resource.as_ref()?.kind {
            ResourceKind::Sleep => Some(LeafKind::Sleep),
            ResourceKind::JoinHandle => Some(LeafKind::JoinHandle),
            ResourceKind::SemaphoreAcquire => Some(LeafKind::SemaphoreAcquire),
            ResourceKind::IoOperation(_) => None,
        }
    }

    fn is_future(&self, ty: BundleType<'b>) -> bool {
        let mut ty = ty;
        for _ in 0..MAX_WRAPPER_DEPTH {
            if let Some(dp) = ty.dyn_pointer() {
                return contract::is_dyn_future_pointee(dp.pointee.name());
            }
            if self.recognized_future(ty.id()) {
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
        let kind = self.leaf_kind(leaf.future.ty.id())?;
        Some(match kind {
            LeafKind::Sleep => self.read_sleep(leaf.future),
            LeafKind::JoinHandle => self.read_join_handle(leaf.future, list),
            LeafKind::SemaphoreAcquire => self.read_acquire(leaf.future, chain),
        })
    }

    /// The fd of the io resource registered as `scheduled_io`, where a
    /// known resource type held in `frames` owns that registration —
    /// the `ScheduledIo` itself records no fd, so only a resource in
    /// the frames can name one. Enrichment only: every miss — no such
    /// member, an unreadable pointee, a walk the bundle did not bind —
    /// is a silent `None`, and the io row spells the address instead.
    pub fn io_resource_fd(&self, frames: &[Value<'b>], scheduled_io: u64) -> Option<i32> {
        for frame in frames {
            for member in frame.ty.members() {
                if member.ty().size() == 0 {
                    continue;
                }
                let value = self.resource_member(*frame, &member)?;
                let Some(value) = value else { continue };
                let Some(&(_, shared, fd)) = IO_RESOURCES
                    .iter()
                    .find(|(name, ..)| *name == value.ty.name())
                else {
                    continue;
                };
                let Ok(Some(Walked::At(owned))) = self.walk(shared).try_walk(value) else {
                    continue;
                };
                if owned.addr != scheduled_io {
                    continue;
                }
                return self.walk(fd).try_read::<i32>(value).ok().flatten();
            }
        }
        None
    }

    /// One frame member as a resource candidate: the member itself, or
    /// — for a reference member (`&mut UnixStream` in a `Read` future)
    /// — its pointee, read from the target. `Some(None)` is a member
    /// that is simply not a resource; the outer `Option` is never
    /// `None` (the signature rides `?` at the call site).
    #[allow(clippy::option_option)]
    fn resource_member(
        &self,
        frame: Value<'b>,
        member: &hansei_bundle::BundleMember<'b>,
    ) -> Option<Option<Value<'b>>> {
        let start = member.offset() as usize;
        let end = start + member.ty().size() as usize;
        let Some(bytes) = frame.bytes.get(start..end) else {
            return Some(None);
        };
        let value = Value::new(member.ty(), frame.addr + member.offset(), bytes);
        if IO_RESOURCES
            .iter()
            .any(|(name, ..)| *name == value.ty.name())
        {
            return Some(Some(value));
        }
        if let Some(target) = value.ty.pointer_target()
            && IO_RESOURCES.iter().any(|(name, ..)| *name == target.name())
            && let Ok(ptr) = value.parse::<u64>(self.proc)
            && self.mappings.contains_addr(ptr)
            && let Ok(pointee) = Value::read(self.proc, target, ptr)
        {
            return Some(Some(pointee));
        }
        Some(None)
    }

    /// `tokio::time::Sleep`: the deadline its timer entry registered.
    /// Where this tokio keeps it was the binder's business at
    /// extraction; the recorded steps already spell the route.
    fn read_sleep(&self, sleep: Value<'b>) -> Result<WaitTarget> {
        let deadline = self
            .sleep_deadline(sleep, &ReadContext::none())?
            .ok_or_else(|| anyhow!("the sleep's timer is of a flavor the walk does not read"))?;
        Ok(WaitTarget::Timer {
            deadline,
            stopped: self.stopped_at(),
        })
    }

    /// The deadline a `Sleep` caches, on the target's monotonic clock:
    /// the std `Timespec` inside tokio's `Instant`, wherever this
    /// tokio keeps it. `None` where the recorded route enters a timer
    /// flavor that is not the live one.
    fn sleep_deadline(
        &self,
        sleep: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<Option<RawInstant>> {
        let Some(deadline) = self
            .walk(WalkRole::SleepDeadline)
            .walk_with(read, sleep)?
            .optional()
        else {
            return Ok(None);
        };
        let tv_sec: i64 = self
            .walk(WalkRole::DeadlineTvSec)
            .read_with(read, deadline)?;
        let tv_nsec: u32 = self
            .walk(WalkRole::DeadlineTvNsec)
            .read_with(read, deadline)?;
        Ok(Some(RawInstant {
            tv_sec: tv_sec as u64,
            tv_nsec,
        }))
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
        let identity = self.header_identity(addr, &ReadContext::none())?;
        Ok((identity.task_id, identity.state))
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

    /// The address range of the task's resolved poll symbol: the
    /// symtab symbol covering the poll fn its vtable stores, as
    /// `st_value..st_value + st_size`. This is the anchor for joining
    /// a mid-poll task's native stack to its await chain — a native
    /// frame whose pc falls in this range is this task's poll, by the
    /// bundle's own task-join key rather than by any spelling. `None`
    /// when no symtab symbol covers the poll address, where a caller
    /// must refuse the join rather than guess. Note a task may have
    /// *resolved* through a sibling vtable fn ([`KnownFuture::symbol`]
    /// can be dealloc); the anchor is always the poll slot's symbol.
    ///
    /// A release build may emit `raw::poll` as a bare trampoline that
    /// tail-jumps into `Harness::poll` — a symbol far too small to
    /// hold a poll body, ending in an unconditional `jmp`. No return
    /// address can land inside such a symbol, so the range follows the
    /// jump (a bounded chain of them) to the symbol whose code
    /// actually runs the poll.
    pub fn poll_symbol_range(&self, task: &Task) -> Result<Option<std::ops::Range<u64>>> {
        let header_ty = self.infra_ty(self.view.bundle().infra.header, "task Header")?;
        let header = Value::read(self.proc, header_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Header at {:?}", task.addr))?;
        let vtable_addr: u64 = self.walk(WalkRole::HeaderVtable).read(header)?;
        let vtable = self
            .task_vtable(vtable_addr)
            .with_context(|| format!("failed to read task vtable at {vtable_addr:#x}"))?;
        let Some(mut sym) = self.proc.lookup_symbol_by_addr(vtable.poll) else {
            return Ok(None);
        };
        for _ in 0..4 {
            let target = self
                .proc
                .read_bytes(sym.st_value, sym.st_size)
                .ok()
                .and_then(|bytes| thunk_target(sym.st_value, bytes));
            match target.and_then(|t| self.proc.lookup_symbol_by_addr(t)) {
                Some(next) => sym = next,
                None => break,
            }
        }
        Ok(Some(sym.st_value..sym.st_value + sym.st_size))
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
            available: raw >> semaphore::PERMIT_SHIFT,
            closed: raw & semaphore::CLOSED != 0,
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
            waiters.push(self.queue_node(node, &ReadContext::none())?);
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

    /// One wait-queue node as a listing carries it: the permits it
    /// still needs and the waker it holds.
    fn queue_node(&self, node: Value<'b>, read: &ReadContext<'_>) -> Result<SemaphoreWaiter> {
        Ok(SemaphoreWaiter {
            addr: node.addr,
            needed: self.walk(WalkRole::WaiterNeeded).read_with(read, node)?,
            waker: self.read_queued_waker(node, read)?,
        })
    }

    /// Decode the waker registered in a wait-queue node. Waiters keep
    /// theirs in an `UnsafeCell<Option<Waker>>`, whose `Some` payload
    /// peels through the `Waker` to the `RawWaker` pair.
    fn read_queued_waker(&self, node: Value<'b>, read: &ReadContext<'_>) -> Result<QueuedWaker> {
        let Some(raw) = self
            .walk(WalkRole::WaiterWaker)
            .walk_with(read, node)?
            .optional()
        else {
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
                .ok_or_else(|| "the tokio info records no task WAKER_VTABLE static".to_owned())?;
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
        let identity = self.header_identity(addr, &ReadContext::none())?;
        match self.resolve_future(&identity.vtable) {
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
    /// takes every task-shaped pointer in the enumerated tasks'
    /// storage that lands outside the list — a `JoinHandle`'s target,
    /// a task waker queued on a semaphore or parked on an io
    /// registration the task holds, a `JoinSet` entry — through its
    /// cell's recorded scheduler, which says what owns it: an
    /// `Arc<task::local::Shared>` is a set's, an `Arc` of either
    /// flavor `Handle` a runtime's, and either way the list must claim
    /// the task that led there (its own id equal to the task's
    /// `Header.owner_id`) before it is admitted. Two inputs feed that
    /// route: the reference scan over each task's initialized storage
    /// ([`Context::scan_references`], under `read`'s allocator
    /// evidence), which finds a reference wherever it sits, and the
    /// older sweep over each task's await chain and diagnosed wait,
    /// which reaches what sits behind a boxed future the scan stops
    /// at. The chain sweep is a temporary input, kept only until
    /// explicit continuations give the scan that route, and it is
    /// credited first, so what both find is attributed as it always
    /// was. Route 2 harvests the discovered runtimes' registries of
    /// parked tasks — the timer wheel, then the io driver's
    /// registrations — which hold a task's waker whatever list owns
    /// it, and so are the only route that reaches a set no enumerated
    /// task points at. Every route converges on the owner's address
    /// and dedups there.
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
        read: &ReadContext<'_>,
    ) -> (Vec<LocalSetRef<'b>>, Registries) {
        self.discover_hidden_tasks_with(
            lwps,
            workers,
            runtimes,
            excluded,
            list,
            read,
            ScanLimits::default(),
        )
    }

    /// [`discover_hidden_tasks`] under explicit scan limits. The
    /// defaults are safety caps no healthy target reaches; a run that
    /// spends one says so in `list.errors` rather than trimming
    /// quietly, and this is how a test drives that report.
    ///
    /// [`discover_hidden_tasks`]: Context::discover_hidden_tasks
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn discover_hidden_tasks_with(
        &self,
        lwps: &[LwpInfo],
        workers: &[Worker],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        excluded: &[u64],
        list: &mut TaskList,
        read: &ReadContext<'_>,
        limits: ScanLimits,
    ) -> (Vec<LocalSetRef<'b>>, Registries) {
        let mut sets: Vec<LocalSetRef<'b>> = Vec::new();
        let mut registries = Registries::default();
        // One budget for the whole run: the scan's visit and referent
        // caps are per discovery, not per task.
        let mut budget = ScanBudget::new(limits);

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
        let mut pooled = 0;
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
                // The chain sweep first, so an owner both inputs reach
                // is credited to the edge it always was; then the scan,
                // whose finds past the sweep's are the ones only it
                // makes.
                let mut found = self.unlisted_task_pointers(list, range.clone());
                self.scanned_task_pointers(list, range, read, &mut budget, &mut found);
                found
            } else if wheeled < runtimes.len() {
                let (found, errors) =
                    self.wheel_task_pointers(&runtimes[wheeled..], list, &mut registries);
                wheeled = runtimes.len();
                list.errors.extend(errors);
                found
            } else if ioed < runtimes.len() {
                let (found, errors) =
                    self.io_task_pointers(&runtimes[ioed..], list, &mut registries);
                ioed = runtimes.len();
                list.errors.extend(errors);
                found
            } else if pooled < runtimes.len() {
                // The blocking pool's queue: the spawn_blocking cells
                // no task list carries, listed as rows of their own.
                // They bootstrap nothing — a blocking cell's scheduler
                // names no list — so the round yields no candidates.
                for (offset, runtime) in runtimes[pooled..].iter().enumerate() {
                    if let Err(e) = self.list_queued_blocking(runtime, pooled + offset, list) {
                        list.errors.push(e.context(format!(
                            "failed to walk the blocking queue of the runtime at {:#x}",
                            runtime.handle.addr
                        )));
                    }
                }
                pooled = runtimes.len();
                Vec::new()
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
                    list,
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
        // A spent budget is reported, never absorbed: the caps are
        // there to bound a corrupt or pathological target, and a
        // healthy one that reaches them is a fact to raise the cap on.
        if budget.inline_visits >= budget.limits.max_inline_visits {
            list.errors.push(anyhow!(
                "the reference scan spent its budget of {} inline visits; \
                 references past it were not followed",
                budget.limits.max_inline_visits
            ));
        }
        if budget.referent_expansions >= budget.limits.max_referent_expansions {
            list.errors.push(anyhow!(
                "the reference scan spent its budget of {} referent expansions; \
                 references past it were not followed",
                budget.limits.max_referent_expansions
            ));
        }
        (sets, registries)
    }

    /// Route 1's scan input: every task-Header pointer the reference
    /// scan finds in the storage of `list.tasks[range]` that no
    /// enumerated task claims, appended to `found` unless the chain
    /// sweep already named it. Scan issues are not reported here — a
    /// stop the scan cannot get past is a bounded loss of this input,
    /// and the chain sweep and the registry harvests still run — but
    /// the run-wide budget is `budget`'s, and its exhaustion is the
    /// sweep's to report.
    fn scanned_task_pointers(
        &self,
        list: &TaskList,
        range: std::ops::Range<usize>,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
        found: &mut Vec<(u64, DiscoveryRoute)>,
    ) {
        /// The sink feeding the candidate queue: a target outside the
        /// list, once, with the storage that referenced it as its
        /// route. Nothing else the scan reports is kept.
        struct Candidates<'l> {
            list: &'l TaskList,
            seen: HashSet<u64>,
            found: Vec<(u64, DiscoveryRoute)>,
        }

        impl ReferenceSink for Candidates<'_> {
            fn reference(
                &mut self,
                target: TaskAddr,
                source: ReferenceSource,
                _: Option<ValueKey>,
                _: Option<TaskAddr>,
                _: &[hansei_bundle::Step],
            ) {
                if !self.list.contains(target.0) && self.seen.insert(target.0) {
                    self.found.push((target.0, DiscoveryRoute::Scanned(source)));
                }
            }

            fn issue(&mut self, _: WalkIssue) {}
        }

        let mut sink = Candidates {
            list,
            seen: found.iter().map(|(addr, _)| *addr).collect(),
            found: Vec::new(),
        };
        for task in &list.tasks[range] {
            let Ok(TaskStage::Running(future)) = self.task_stage(task) else {
                continue;
            };
            let _ = self.scan_references(future, task.addr, read, budget, &mut sink);
        }
        found.append(&mut sink.found);
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
        registries: &mut Registries,
    ) -> (Vec<(u64, DiscoveryRoute)>, Vec<anyhow::Error>) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        // Across the whole harvest: the same entry is in exactly one
        // slot, so a repeat is corrupt memory, not a second sighting.
        let mut visited = HashSet::default();
        for runtime in runtimes {
            if let Err(e) = self.harvest_wheel(
                runtime,
                list,
                &mut visited,
                &mut found,
                &mut errors,
                registries,
            ) {
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
    #[allow(clippy::too_many_arguments)]
    fn harvest_wheel(
        &self,
        runtime: &RuntimeRef<'b>,
        list: &TaskList,
        visited: &mut HashSet<u64>,
        found: &mut Vec<(u64, DiscoveryRoute)>,
        errors: &mut Vec<anyhow::Error>,
        registries: &mut Registries,
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
                if let Err(e) =
                    self.walk_wheel_slot(addr, entry_ty, list, visited, found, registries)
                {
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
        registries: &mut Registries,
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
            let task = match self
                .walk(WalkRole::TimerSharedWaker)
                .walk(entry)?
                .optional()
            {
                Some(raw) => self.registry_waker(raw, DiscoveryRoute::Wheel, list, found)?,
                None => None,
            };
            // Enrichment beside the harvest's real business: a torn or
            // unbound word costs the state, never the entry.
            let state = self
                .walk(WalkRole::TimerSharedState)
                .try_read(entry)
                .ok()
                .flatten();
            registries.timers.push(TimerEntryInfo {
                entry: addr,
                state,
                task,
            });
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
        registries: &mut Registries,
    ) -> (Vec<(u64, DiscoveryRoute)>, Vec<anyhow::Error>) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        // Across the whole harvest, for both node kinds: a registration
        // is in one driver's list and a waiter node in one resource's,
        // so a repeat is corrupt memory, not a second sighting.
        let mut visited = HashSet::default();
        for runtime in runtimes {
            if let Err(e) = self.harvest_io(
                runtime,
                list,
                &mut visited,
                &mut found,
                &mut errors,
                registries,
            ) {
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
    #[allow(clippy::too_many_arguments)]
    fn harvest_io(
        &self,
        runtime: &RuntimeRef<'b>,
        list: &TaskList,
        visited: &mut HashSet<u64>,
        found: &mut Vec<(u64, DiscoveryRoute)>,
        errors: &mut Vec<anyhow::Error>,
        registries: &mut Registries,
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
            // Enrichment beside the harvest's real business: a torn or
            // unbound word costs the readiness or the guard's verdict,
            // never the resource.
            let mut resource = IoResourceInfo {
                addr,
                readiness: self
                    .walk(WalkRole::ScheduledIoReadiness)
                    .try_read(registration)
                    .ok()
                    .flatten(),
                consistency: self.io_guard(registration, &ReadContext::none()),
                waiters: Vec::new(),
            };
            if let Err(e) =
                self.harvest_io_waiters(registration, list, visited, found, &mut resource)
            {
                errors.push(e.context(format!(
                    "failed to walk the waiters of the io registration at {addr:#x}"
                )));
            }
            registries.io.push(resource);
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
        resource: &mut IoResourceInfo,
    ) -> Result<()> {
        let waiters = self
            .walk(WalkRole::ScheduledIoWaiters)
            .walk_at(registration)?;
        for (role, slot) in [
            (WalkRole::IoReaderWaker, IoSlot::Reader),
            (WalkRole::IoWriterWaker, IoSlot::Writer),
        ] {
            // A direction nobody is awaiting holds no waker.
            if let Some(raw) = self.walk(role).walk(waiters)?.optional() {
                let task = self.registry_waker(raw, DiscoveryRoute::Io, list, found)?;
                resource.waiters.push(IoWaiterInfo {
                    slot,
                    task,
                    node: None,
                    ready: None,
                });
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
                let task = self.registry_waker(raw, DiscoveryRoute::Io, list, found)?;
                let interest = self
                    .walk(WalkRole::IoWaiterInterest)
                    .try_read::<u64>(node)
                    .ok()
                    .flatten()
                    .map(Interest);
                // The node's identity and ready flag beside the waker:
                // a readiness await embeds exactly this node, and its
                // wake path sets the flag here. The flag's route is the
                // await's own row, rooted at the same `Waiter` type.
                let ready = self
                    .walk(WalkRole::ReadinessWaiterReady)
                    .try_read::<bool>(node)
                    .ok()
                    .flatten();
                resource.waiters.push(IoWaiterInfo {
                    slot: IoSlot::Listed { interest },
                    task,
                    node: Some(addr),
                    ready,
                });
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

    /// Decode one waker a registry holds and file its discovery
    /// candidate: a task's waker on a task no list claims is route 2's
    /// find. The task it names — listed or not — is returned either
    /// way, for the registries' retention; anything that is not a task
    /// waker (a `block_on` thread's parker waker, say) is `None`.
    fn registry_waker(
        &self,
        raw: Value<'b>,
        route: DiscoveryRoute,
        list: &TaskList,
        found: &mut Vec<(u64, DiscoveryRoute)>,
    ) -> Result<Option<u64>> {
        let QueuedWaker::Task { addr, .. } = self.raw_waker(raw)? else {
            return Ok(None);
        };
        if !list.contains(addr) {
            found.push((addr, route));
        }
        Ok(Some(addr))
    }

    /// The spawn_blocking cells parked in one runtime's pool queue,
    /// listed as rows under `group`. The queue is a `VecDeque` ring:
    /// the recorded element layout strides it, and each element's
    /// `UnownedTask` names the Header that identifies the cell.
    fn list_queued_blocking(
        &self,
        runtime: &RuntimeRef<'b>,
        group: usize,
        list: &mut TaskList,
    ) -> Result<()> {
        let Some(queue) = self
            .walk(WalkRole::BlockingQueue)
            .try_walk(runtime.handle)?
            .and_then(Walked::optional)
        else {
            return Ok(());
        };
        let len: u64 = self.walk(WalkRole::BlockingQueueLen).read(queue)?;
        if len == 0 {
            return Ok(());
        }
        let head: u64 = self.walk(WalkRole::BlockingQueueHead).read(queue)?;
        let cap: u64 = self.walk(WalkRole::BlockingQueueCap).read(queue)?;
        let buf: u64 = self.walk(WalkRole::BlockingQueueBuf).read(queue)?;
        ensure!(
            cap > 0 && len <= cap,
            "the blocking queue claims {len} of {cap} slots"
        );
        let elem = self
            .walk_root_ty(WalkRole::BlockingTaskHeader)
            .ok_or_else(|| anyhow!("the tokio info records no blocking pool Task layout"))?;
        for i in 0..len {
            let slot = (head + i) % cap;
            let addr = buf + slot * elem.size();
            let step = (|| -> Result<u64> {
                ensure!(
                    self.mappings.contains_addr(addr),
                    "queue slot {slot} at {addr:#x} is unmapped"
                );
                let value = Value::read(self.proc, elem, addr)?;
                self.walk(WalkRole::BlockingTaskHeader).read(value)
            })();
            match step {
                Ok(header) => self.list_blocking(header, group, list),
                Err(e) => list
                    .errors
                    .push(e.context(format!("failed to read blocking-queue slot {slot}"))),
            }
        }
        Ok(())
    }

    /// List one blocking cell as a row, wherever it was found: decode
    /// its Header like any task's and mark it. A complete cell is left
    /// to the join edge that found it — off the pool, alive only
    /// through its handle — and a listed one is already a row. The
    /// runtime's own cells are skipped: tokio launches its worker
    /// threads through the pool, and whether a capture catches one of
    /// those mid-launch is pure timing, not target work. A blocking
    /// cell is in no owned list, so its Trailer links are never read.
    fn list_blocking(&self, addr: u64, group: usize, list: &mut TaskList) {
        if list.contains(addr) {
            return;
        }
        match self.read_task_header(TaskAddr(addr), &ReadContext::none()) {
            Ok(header) => {
                let mut task = header.into_task();
                if task.state.lifecycle() == Lifecycle::Complete {
                    return;
                }
                if let FutureInfo::Known(known) = &task.future
                    && runtime_internal_blocking(&known.display_name)
                {
                    return;
                }
                task.blocking = true;
                task.group = group;
                list.tasks.push(task);
            }
            Err(e) => list
                .errors
                .push(e.context(format!("failed to list the blocking task at {addr:#x}"))),
        }
    }

    /// Route 1's tail: follow one unlisted Header home through its
    /// cell's scheduler, whatever that scheduler turns out to be. A
    /// blocking cell has no list to follow home and becomes a row of
    /// its own; a task the bundle cannot classify (an unresolvable
    /// future) is the common, silent case, and only a genuine read
    /// failure reports.
    #[allow(clippy::too_many_arguments)]
    fn bootstrap_unlisted(
        &self,
        addr: u64,
        route: DiscoveryRoute,
        excluded: &[u64],
        thread_ids: &[(u64, u32)],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        sets: &mut Vec<LocalSetRef<'b>>,
        list: &mut TaskList,
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
            // A blocking cell has no owner list to walk to; the header
            // itself is the whole find.
            if matches!(kind, SchedulerKind::Blocking) {
                return Ok(Some((kind, header, 0)));
            }
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
            Ok(Some((SchedulerKind::Blocking, ..))) => {
                self.list_blocking(addr, 0, list);
            }
            Ok(Some((SchedulerKind::LocalSet, shared, claim))) => {
                let errors = &mut list.errors;
                self.admit_local_set(shared, Some(claim), None, route, thread_ids, sets, errors);
            }
            Ok(Some((SchedulerKind::MultiThread, handle, claim))) => self.admit_hidden_runtime(
                handle,
                RuntimeFlavor::MultiThread,
                claim,
                route,
                excluded,
                runtimes,
                &mut list.errors,
            ),
            Ok(Some((SchedulerKind::CurrentThread, handle, claim))) => self.admit_hidden_runtime(
                handle,
                RuntimeFlavor::CurrentThread,
                claim,
                route,
                excluded,
                runtimes,
                &mut list.errors,
            ),
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => list.errors.push(e.context(format!(
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
                    self.leaf_kind(f.future.ty.id()),
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
            self.leaf_kind(leaf.future.ty.id()),
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

// ---------------------------------------------------------------------------
// Raw resource observations
// ---------------------------------------------------------------------------

impl<'b, T: Target> Context<'b, T> {
    /// What one resource value is, decoded through the roles its
    /// binding names and nothing else: the header a `JoinHandle`
    /// points at, an `Acquire`'s five words, a `Sleep`'s deadline and
    /// entry state, an io operation's registration. No task list is
    /// consulted and no wait is diagnosed — a join names a header that
    /// [`Context::read_task_header`] validates separately, an acquire
    /// names a semaphore whose queue [`Context::observe_semaphore_queue`]
    /// reads on demand — so discovery can consume a held handle before
    /// any list exists.
    ///
    /// A value with no resource binding observes as nothing, with
    /// nothing to report; a bound resource whose bytes do not decode
    /// observes as nothing with the reason.
    pub fn observe_resource(
        &self,
        value: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Observed<ResourceObservation> {
        let Some(kind) = self
            .type_semantics(value.ty.id())
            .and_then(|record| record.resource.as_ref())
            .map(|binding| binding.kind)
        else {
            return Observed::none();
        };
        let key = ValueKey::of(value);
        let observed = match kind {
            ResourceKind::JoinHandle => self
                .observe_join(value, read)
                .map(ResourceObservation::Join),
            ResourceKind::SemaphoreAcquire => self
                .observe_acquire(value, read)
                .map(ResourceObservation::Acquire),
            ResourceKind::Sleep => return self.observe_timer(value, read),
            ResourceKind::IoOperation(operation) => self
                .observe_io(value, operation, read)
                .map(ResourceObservation::Io),
        };
        match observed {
            Ok(observation) => Observed::of(observation),
            Err(e) => Observed::failed(issue_of(key, &e)),
        }
    }

    /// A `JoinHandle`: the task header its raw pointer names.
    fn observe_join(&self, handle: Value<'b>, read: &ReadContext<'_>) -> Result<JoinObservation> {
        let addr: u64 = self.walk(WalkRole::JoinHandleRaw).read_with(read, handle)?;
        ensure!(addr != 0, "the JoinHandle's task pointer is null");
        Ok(JoinObservation {
            handle: ValueKey::of(handle),
            header: TaskAddr(addr),
        })
    }

    /// An `Acquire`: its five raw words, read in place. The semaphore
    /// is keyed by the pointer's own pointee type, so the queue read
    /// under this key decodes with the layout this acquire was
    /// compiled against.
    fn observe_acquire(
        &self,
        acquire: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<AcquireObservation> {
        let semaphore = self
            .walk(WalkRole::AcquireSemaphore)
            .walk_at_with(read, acquire)?;
        let sem_ty = semaphore
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("Acquire.semaphore is not pointer-shaped"))?;
        let sem_addr: u64 = semaphore.parse(self.proc)?;
        let node = self
            .walk(WalkRole::AcquireNode)
            .walk_at_with(read, acquire)?;
        Ok(AcquireObservation {
            future: ValueKey::of(acquire),
            semaphore: ValueKey {
                addr: sem_addr,
                ty: sem_ty.id(),
            },
            node: node.addr,
            requested: self
                .walk(WalkRole::AcquireNumPermits)
                .read_with(read, acquire)?,
            needed: self
                .walk(WalkRole::AcquireNeeded)
                .read_with(read, acquire)?,
            queued: self
                .walk(WalkRole::AcquireQueued)
                .read_with(read, acquire)?,
            queue_position: None,
        })
    }

    /// A `Sleep`: the deadline it caches and where its timer entry is.
    /// Each half is read on its own, so a sleep whose entry word does
    /// not read still reports its deadline, with the failure beside it.
    fn observe_timer(
        &self,
        sleep: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Observed<ResourceObservation> {
        let key = ValueKey::of(sleep);
        let mut issues = Vec::new();
        let deadline = self.sleep_deadline(sleep, read).unwrap_or_else(|e| {
            issues.push(issue_of(key, &e));
            None
        });
        let state = self.timer_state(sleep, read).unwrap_or_else(|e| {
            issues.push(issue_of(key, &e));
            TimerRegistrationState::Unknown
        });
        Observed {
            value: Some(ResourceObservation::Timer(TimerObservation {
                future: key,
                deadline,
                state,
            })),
            issues,
        }
    }

    /// Where a `Sleep`'s timer entry is in the wheel's life: the
    /// entry's state word, decoded with the sentinels the wheel
    /// harvest reads, behind the `Some` that says the entry exists at
    /// all. A sleep never polled has no entry, and the route's guard
    /// says so; a timer of a flavor the route does not enter is an
    /// error rather than a state.
    fn timer_state(
        &self,
        sleep: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<TimerRegistrationState> {
        match self
            .walk(WalkRole::SleepTimerState)
            .walk_with(read, sleep)?
        {
            Walked::At(word) => {
                let raw: u64 = word.parse(self.proc)?;
                Ok(match raw {
                    timer::STATE_DEREGISTERED => TimerRegistrationState::Deregistered,
                    timer::STATE_PENDING_FIRE => TimerRegistrationState::PendingFire,
                    tick => TimerRegistrationState::Registered { tick },
                })
            }
            Walked::Inactive("Some") => Ok(TimerRegistrationState::NotRegistered),
            Walked::Inactive(variant) => {
                bail!("the sleep's timer is of a flavor the walk does not read (not {variant})")
            }
            Walked::Null => bail!("the sleep's timer entry is behind a null pointer"),
        }
    }

    /// A bounded io operation or a readiness await: the registration
    /// it belongs to, reached by the operation's own route — through
    /// the reader or writer a `Read`/`WriteAll` polls, or named
    /// outright by a `Readiness` — and what its own storage says.
    fn observe_io(
        &self,
        future: Value<'b>,
        operation: IoOperationKind,
        read: &ReadContext<'_>,
    ) -> Result<IoObservation> {
        let key = ValueKey::of(future);
        let (endpoint, length, shared, interest) = match operation {
            IoOperationKind::Read => (
                WalkRole::IoReadReader,
                WalkRole::IoReadBufLen,
                WalkRole::IoReadShared,
                Interest::READABLE,
            ),
            IoOperationKind::WriteAll => (
                WalkRole::IoWriteAllWriter,
                WalkRole::IoWriteAllBufLen,
                WalkRole::IoWriteAllShared,
                Interest::WRITABLE,
            ),
            IoOperationKind::Readiness => return self.observe_readiness(future, read),
        };
        // The reader is a `&mut` to the reviewed stream, and the
        // registration is reached through it: the one dereference,
        // held to `read`, then the stream's own route to its
        // `ScheduledIo`.
        let pointer = self.walk(endpoint).walk_at_with(read, future)?;
        let stream = contract::execute_steps(self, read, pointer, &[Step::Deref])
            .with_context(|| format!("walk path {}", endpoint.name()))?
            .at(endpoint.name())?;
        let scheduled_io = self.walk(shared).walk_at_with(read, stream)?;
        let remaining: u64 = self.walk(length).read_with(read, future)?;
        Ok(IoObservation {
            future: key,
            operation,
            scheduled_io: ValueKey::of(scheduled_io),
            interest,
            waiter_node: None,
            remaining: Some(remaining),
            readiness_state: None,
            waiter_ready: None,
        })
    }

    /// A `Readiness` await: the registration it names, its own state,
    /// and the `Waiter` node embedded in it — the exact list entry a
    /// pending wait must be found at, with the interest and ready flag
    /// the resource's wake path sets.
    fn observe_readiness(
        &self,
        future: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<IoObservation> {
        let pointer = self
            .walk(WalkRole::ReadinessScheduledIo)
            .walk_at_with(read, future)?;
        let io_ty = pointer
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("Readiness.scheduled_io is not pointer-shaped"))?;
        let io_addr: u64 = pointer.parse(self.proc)?;
        ensure!(io_addr != 0, "the Readiness's registration pointer is null");
        let state = self
            .walk(WalkRole::ReadinessState)
            .walk_at_with(read, future)?;
        let state = match state.ty.enumerator_name(state.bytes) {
            Some("Init") => IoFutureState::Init,
            Some("Waiting") => IoFutureState::Waiting,
            Some("Done") => IoFutureState::Done,
            _ => IoFutureState::Unknown(word_of(state.bytes)),
        };
        let waiter = self
            .walk(WalkRole::ReadinessWaiter)
            .walk_at_with(read, future)?;
        let interest: u64 = self
            .walk(WalkRole::ReadinessWaiterInterest)
            .read_with(read, waiter)?;
        let ready: bool = self
            .walk(WalkRole::ReadinessWaiterReady)
            .read_with(read, waiter)?;
        Ok(IoObservation {
            future: ValueKey::of(future),
            operation: IoOperationKind::Readiness,
            scheduled_io: ValueKey {
                addr: io_addr,
                ty: io_ty.id(),
            },
            interest: Interest(interest),
            waiter_node: Some(waiter.addr),
            remaining: None,
            readiness_state: Some(state),
            waiter_ready: Some(ready),
        })
    }

    /// Walk one semaphore's wait queue, on explicit demand: who its
    /// permits will wake, with the permit word, the closed flags and
    /// the guard's state read beside the list.
    ///
    /// tokio enqueues at the list head and wakes from the tail, so the
    /// walk runs newest-first and is reversed into wake order only
    /// when it reached the end: the prefix a failing walk found is
    /// kept as it was walked, since reversing it would place nodes
    /// that are not placed. Each node's dereference is charged to
    /// `budget` and held to `read`, and the first node that cannot be
    /// believed ends the walk with the reason.
    pub fn observe_semaphore_queue(
        &self,
        semaphore: ValueKey,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
    ) -> QueueObservation {
        let mut queue = QueueObservation {
            semaphore,
            waiters: Vec::new(),
            complete: false,
            consistency: Consistency::Unknown,
            closed: None,
            queue_closed: None,
            available: None,
            issues: Vec::new(),
        };
        if !budget.charge_referent() {
            queue.issues.push(spent(semaphore, budget));
            return queue;
        }
        let sem = match self.read_keyed(semaphore, read) {
            Ok(sem) => sem,
            Err(e) => {
                queue.issues.push(issue_of(semaphore, &e));
                return queue;
            }
        };
        // `permits` keeps the available count shifted above the CLOSED
        // bit.
        match self
            .walk(WalkRole::SemaphorePermits)
            .read_with::<u64>(read, sem)
        {
            Ok(raw) => {
                queue.closed = Some(raw & semaphore::CLOSED != 0);
                queue.available = Some(raw >> semaphore::PERMIT_SHIFT);
            }
            Err(e) => queue.issues.push(issue_of(semaphore, &e)),
        }
        match self
            .walk(WalkRole::SemaphoreClosed)
            .try_walk_with(read, sem)
        {
            Ok(Some(closed)) => match closed.at(WalkRole::SemaphoreClosed.name()) {
                Ok(closed) => match closed.parse::<bool>(self.proc) {
                    Ok(flag) => queue.queue_closed = Some(flag),
                    Err(e) => queue.issues.push(issue_of(semaphore, &anyhow!(e))),
                },
                Err(e) => queue.issues.push(issue_of(semaphore, &e)),
            },
            Ok(None) => {}
            Err(e) => queue.issues.push(issue_of(semaphore, &e)),
        }
        // The guard around the wait list: a queue read while its lock
        // is held is a queue mid-edit, whatever its links say.
        match self.walk(WalkRole::SemaphoreLock).try_walk_with(read, sem) {
            Ok(Some(Walked::At(lock))) => queue.consistency = lock_consistency(lock),
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => queue.issues.push(issue_of(semaphore, &e)),
        }

        match self.observe_queue_nodes(sem, read, budget, &mut queue.waiters) {
            Ok(()) => {
                queue.complete = true;
                queue.waiters.reverse();
            }
            Err(issue) => queue.issues.push(issue),
        }
        queue
    }

    /// The wait list of one semaphore, node by node in walk order,
    /// pushed as each is reached so a failing walk leaves its prefix.
    fn observe_queue_nodes(
        &self,
        sem: Value<'b>,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
        waiters: &mut Vec<SemaphoreWaiter>,
    ) -> std::result::Result<(), WalkIssue> {
        let at = ValueKey::of(sem);
        let head = self
            .walk(WalkRole::SemaphoreQueueHead)
            .walk_with(read, sem)
            .map_err(|e| issue_of(at, &e))?;
        let Some(head) = head.optional() else {
            return Ok(());
        };
        let waiter_ty = head.ty.pointer_target().ok_or_else(|| {
            WalkIssue::new(
                at,
                WalkIssueKind::InvalidLayout,
                "the wait-queue head is not pointer-shaped",
            )
        })?;
        let mut visited = HashSet::default();
        let mut cur = Some(
            head.parse::<u64>(self.proc)
                .map_err(|e| issue_of(at, &anyhow!(e)))?,
        );
        while let Some(addr) = cur {
            let key = ValueKey {
                addr,
                ty: waiter_ty.id(),
            };
            if !visited.insert(addr) {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::Cycle,
                    format!("wait-queue cycle at {addr:#x}"),
                ));
            }
            if waiters.len() >= budget.limits.max_children as usize {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::VisitLimit,
                    format!("the walk stopped at {} nodes", budget.limits.max_children),
                ));
            }
            if !budget.charge_referent() {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::VisitLimit,
                    format!(
                        "the referent budget ({}) is spent",
                        budget.limits.max_referent_expansions
                    ),
                ));
            }
            let node = self.read_keyed(key, read).map_err(|e| issue_of(key, &e))?;
            waiters.push(self.queue_node(node, read).map_err(|e| issue_of(key, &e))?);
            cur = self
                .walk(WalkRole::WaiterNext)
                .walk_with(read, node)
                .map_err(|e| issue_of(key, &e))?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(|e| issue_of(key, &anyhow!(e))))
                .transpose()?;
        }
        Ok(())
    }

    /// Everything parked on one io registration, read on demand from
    /// the `ScheduledIo` a resource observation named: the two direction
    /// slots and every node on the readiness list, armed or not, each
    /// with its identity. A list that could not be walked to its end
    /// keeps the nodes it reached, with the failure beside them.
    pub fn observe_io_registration(
        &self,
        registration: ValueKey,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
    ) -> Observed<IoResourceInfo> {
        if !budget.charge_referent() {
            return Observed::failed(spent(registration, budget));
        }
        let io = match self.read_keyed(registration, read) {
            Ok(io) => io,
            Err(e) => return Observed::failed(issue_of(registration, &e)),
        };
        let mut issues = Vec::new();
        let mut resource = IoResourceInfo {
            addr: registration.addr,
            readiness: self
                .walk(WalkRole::ScheduledIoReadiness)
                .try_read(io)
                .ok()
                .flatten(),
            consistency: self.io_guard(io, read),
            waiters: Vec::new(),
        };
        let waiters = match self
            .walk(WalkRole::ScheduledIoWaiters)
            .walk_at_with(read, io)
        {
            Ok(waiters) => waiters,
            Err(e) => {
                return Observed {
                    value: Some(resource),
                    issues: vec![issue_of(registration, &e)],
                };
            }
        };
        for (role, slot) in [
            (WalkRole::IoReaderWaker, IoSlot::Reader),
            (WalkRole::IoWriterWaker, IoSlot::Writer),
        ] {
            match self.walk(role).walk_with(read, waiters) {
                Ok(raw) => {
                    if let Some(raw) = raw.optional() {
                        match self.raw_waker(raw) {
                            Ok(waker) => resource.waiters.push(IoWaiterInfo {
                                slot,
                                task: waker.task(),
                                node: None,
                                ready: None,
                            }),
                            Err(e) => issues.push(issue_of(registration, &e)),
                        }
                    }
                }
                Err(e) => issues.push(issue_of(registration, &e)),
            }
        }
        if let Err(e) =
            self.observe_io_waiter_list(waiters, read, budget, &mut resource, &mut issues)
        {
            issues.push(e);
        }
        Observed {
            value: Some(resource),
            issues,
        }
    }

    /// Whether the guard around a registration's waiters read unlocked:
    /// `Unknown` where the row is unbound, lands on a representation
    /// the reader does not decode, or does not read.
    fn io_guard(&self, registration: Value<'b>, read: &ReadContext<'_>) -> Consistency {
        match self
            .walk(WalkRole::ScheduledIoLock)
            .try_walk_with(read, registration)
        {
            Ok(Some(Walked::At(lock))) => lock_consistency(lock),
            _ => Consistency::Unknown,
        }
    }

    /// The readiness list of one registration, node by node.
    fn observe_io_waiter_list(
        &self,
        waiters: Value<'b>,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
        resource: &mut IoResourceInfo,
        issues: &mut Vec<WalkIssue>,
    ) -> std::result::Result<(), WalkIssue> {
        let at = ValueKey::of(waiters);
        let head = self
            .walk(WalkRole::IoWaiterHead)
            .walk_with(read, waiters)
            .map_err(|e| issue_of(at, &e))?;
        let Some(head) = head.optional() else {
            return Ok(());
        };
        let node_ty = head.ty.pointer_target().ok_or_else(|| {
            WalkIssue::new(
                at,
                WalkIssueKind::InvalidLayout,
                "the io waiter list's head is not pointer-shaped",
            )
        })?;
        let mut visited = HashSet::default();
        let mut cur = Some(
            head.parse::<u64>(self.proc)
                .map_err(|e| issue_of(at, &anyhow!(e)))?,
        );
        while let Some(addr) = cur {
            let key = ValueKey {
                addr,
                ty: node_ty.id(),
            };
            if !visited.insert(addr) {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::Cycle,
                    format!("io waiter list cycle at {addr:#x}"),
                ));
            }
            // The set now holds this node too, so its size is one past
            // the nodes taken.
            if visited.len() > budget.limits.max_children as usize {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::VisitLimit,
                    format!("the walk stopped at {} nodes", budget.limits.max_children),
                ));
            }
            if !budget.charge_referent() {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::VisitLimit,
                    format!(
                        "the referent budget ({}) is spent",
                        budget.limits.max_referent_expansions
                    ),
                ));
            }
            let node = self.read_keyed(key, read).map_err(|e| issue_of(key, &e))?;
            // A node whose future has not been polled since it was
            // linked carries no waker yet; it is a node all the same.
            let task = match self.walk(WalkRole::IoWaiterWaker).walk_with(read, node) {
                Ok(raw) => match raw.optional() {
                    Some(raw) => match self.raw_waker(raw) {
                        Ok(waker) => waker.task(),
                        Err(e) => {
                            issues.push(issue_of(key, &e));
                            None
                        }
                    },
                    None => None,
                },
                Err(e) => {
                    issues.push(issue_of(key, &e));
                    None
                }
            };
            let interest = self
                .walk(WalkRole::IoWaiterInterest)
                .try_read::<u64>(node)
                .ok()
                .flatten()
                .map(Interest);
            let ready = self
                .walk(WalkRole::ReadinessWaiterReady)
                .try_read::<bool>(node)
                .ok()
                .flatten();
            resource.waiters.push(IoWaiterInfo {
                slot: IoSlot::Listed { interest },
                task,
                node: Some(addr),
                ready,
            });
            cur = self
                .walk(WalkRole::IoWaiterNext)
                .walk_with(read, node)
                .map_err(|e| issue_of(key, &e))?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(|e| issue_of(key, &anyhow!(e))))
                .transpose()?;
        }
        Ok(())
    }

    /// Read the value a key names, as its nominal type, held to `read`:
    /// the type must exist, the address must be mapped, and the
    /// allocator must permit the typed range.
    fn read_keyed(&self, key: ValueKey, read: &ReadContext<'_>) -> Result<Value<'b>> {
        let ty = self
            .view
            .ty(key.ty)
            .ok_or_else(|| anyhow!("type {} is not in the tokio info", key.ty.0))?;
        ensure!(
            self.mappings.contains_addr(key.addr),
            "the pointer {:#x} to {} is unmapped",
            key.addr,
            ty.name()
        );
        if let Some(refusal) = read.refusal(key.addr, ty.size()) {
            return Err(anyhow::Error::new(refusal).context(format!("reading {}", ty.name())));
        }
        Value::read(self.proc, ty, key.addr)
            .with_context(|| format!("failed to read {} at {:#x}", ty.name(), key.addr))
    }
}

/// The issue a read charged to a spent referent budget reports.
fn spent(at: ValueKey, budget: &ScanBudget) -> WalkIssue {
    WalkIssue::new(
        at,
        WalkIssueKind::VisitLimit,
        format!(
            "the referent budget ({}) is spent",
            budget.limits.max_referent_expansions
        ),
    )
}

/// The little-endian word `bytes` hold, for a raw value nothing names.
fn word_of(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    let n = bytes.len().min(8);
    word[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(word)
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

/// Where a trampoline's code continues: the target of the
/// unconditional `jmp rel32` a tail-call thunk ends in, or `None` for
/// any symbol that could hold a real function body. `addr` is where
/// `bytes` — the symbol's whole code — was read from.
///
/// The rule errs narrow, since following a jump out of a real poll
/// body would anchor the join on the wrong function: only a symbol too
/// small to be anything but a trampoline (nexus's `raw::poll` is ten
/// bytes: `push rbp; mov rbp, rsp; pop rbp; jmp Harness::poll`) whose
/// final five bytes decode as `e9 rel32` qualifies.
fn thunk_target(addr: u64, bytes: &[u8]) -> Option<u64> {
    /// The largest symbol treated as a trampoline. A prologue, its
    /// unwind, and the jump fit well inside this; no real poll body
    /// does.
    const THUNK_MAX: usize = 16;
    if bytes.len() > THUNK_MAX {
        return None;
    }
    let jmp = bytes.get(bytes.len().checked_sub(5)?..)?;
    if jmp[0] != 0xe9 {
        return None;
    }
    let rel = i32::from_le_bytes(jmp[1..5].try_into().unwrap());
    // rel32 is relative to the next instruction, which is the symbol's
    // end: the jump is its last five bytes.
    Some((addr + bytes.len() as u64).wrapping_add_signed(rel as i64))
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

/// What a task `Header` says of itself before anything is joined or
/// followed: [`Context::header_identity`]'s answer, the common prefix
/// of every header reader.
struct HeaderIdentity {
    state: TaskState,
    owner_id: Option<u64>,
    task_id: Option<u64>,
    vtable_addr: u64,
    vtable: TaskVtable,
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
    /// The symbol joined more than one concrete bundle type.
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

    #[test]
    fn test_type_semantics_borrows_records_without_changing_production_chains() {
        let (bundle, snapshot) = unordered();
        let ctx = testkit::context(bundle, snapshot);
        assert!(!bundle.semantics.types.is_empty());
        for record in &bundle.semantics.types {
            assert!(std::ptr::eq(ctx.type_semantics(record.ty).unwrap(), record));
        }
        assert!(ctx.type_semantics(BundleTypeId(u32::MAX)).is_none());
        let mut without = bundle.clone();
        without.semantics = Default::default();
        for entry in &mut without.tasks.entries {
            entry.scheduler_binding = None;
        }
        without.validate().unwrap();
        let other = testkit::context(&without, snapshot);
        let tasks = testkit::tasks(&ctx, snapshot);
        let mut compared = 0;
        for task in &tasks.tasks {
            if let TaskStage::Running(root) = ctx.task_stage(task).unwrap() {
                let TaskStage::Running(other_root) = other.task_stage(task).unwrap() else {
                    panic!("same resident task")
                };
                let actual = ctx.await_chain(root);
                let expected = other.await_chain(other_root);
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
                compared += 1;
            }
        }
        assert!(compared > 0);
    }

    #[test]
    fn test_exact_task_collision_can_resolve_through_a_vtable_sibling() {
        let (original, snapshot) = unordered();
        let mut bundle = original.clone();
        let first = TaskEntryId(0);
        let second = TaskEntryId(
            bundle
                .tasks
                .entries
                .iter()
                .position(|entry| entry.future != bundle.tasks.entries[0].future)
                .expect("the fixture contains distinct futures") as u32,
        );
        bundle
            .tasks
            .by_symbol
            .insert("shared_poll".into(), vec![first, second]);
        bundle
            .tasks
            .by_symbol
            .insert("unique_dealloc".into(), vec![second]);
        bundle.tasks.by_normalized_symbol =
            hansei_bundle::symbols::normalized_candidate_index(&bundle.tasks.by_symbol);
        bundle.validate().unwrap();
        let ctx = testkit::context(&bundle, snapshot);
        ctx.symbols
            .get_or(&1, || Some("shared_poll.llvm.123".to_owned()));
        ctx.symbols.get_or(&2, || Some("unique_dealloc".to_owned()));
        let mut vt = TaskVtable {
            poll: 1,
            dealloc: None,
            try_read_output: None,
            drop_join_handle_slow: None,
            drop_abort_handle: None,
            shutdown: None,
            trailer_offset: 0,
            id_offset: 0,
            spawn_location_offset: None,
        };
        for _ in 0..2 {
            let FutureInfo::Ambiguous { candidates, .. } = ctx.resolve_future(&vt) else {
                panic!("an exact collision cannot choose a task");
            };
            let types: Vec<_> = candidates.iter().map(|candidate| candidate.ty).collect();
            assert_eq!(
                types,
                vec![
                    bundle.tasks.entries[0].future,
                    bundle.tasks.entries[second.0 as usize].future
                ]
            );
        }
        vt.dealloc = Some(2);
        let FutureInfo::Known(future) = ctx.resolve_future(&vt) else {
            panic!("the unique sibling identifies the task");
        };
        assert_eq!(future.entry, second);
        assert_eq!(future.symbol, "unique_dealloc");
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
        assert!(!ctx.recognized_future(ty.id()), "no fact names the wrapper");
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// A coroutine whose `poll` rustc inlined out of the symtab has no
    /// poll symbol, and must still screen as a future on its bound
    /// layout's evidence alone. Every debug-build fixture records every
    /// poll, so the documented condition — no symbol — is constructed
    /// here by taking the poll evidence out of the record.
    #[test]
    fn test_a_coroutine_off_the_poll_table_is_still_a_future() {
        let (bundle, snapshot) = unordered();
        let mut bundle = bundle.clone();
        // A coroutine no task was spawned with, so once its poll symbol
        // is gone only the layout's evidence names it.
        let record = bundle
            .semantics
            .types
            .iter_mut()
            .find(|r| {
                r.coroutine.is_some()
                    && r.future.as_ref().is_some_and(|f| {
                        !f.evidence
                            .iter()
                            .any(|e| matches!(e, hansei_bundle::FutureEvidence::TaskEntry(_)))
                    })
            })
            .expect("the fixture bundle binds coroutine layouts");
        let ty = record.ty;
        let facts = record.future.as_mut().unwrap();
        // Its poll symbol and whatever parent delegated to it: only the
        // layout's own evidence stays.
        facts
            .evidence
            .retain(|e| matches!(e, hansei_bundle::FutureEvidence::Coroutine(_)));
        assert!(!facts.evidence.is_empty());
        bundle.validate().unwrap();
        let ctx = testkit::context(&bundle, snapshot);
        let ty = ctx.view.ty(ty).unwrap();
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// A recorded `poll` alone is also enough: a hand-written future
    /// that is no coroutine and no bound resource screens on it.
    #[test]
    fn test_a_poll_table_type_alone_is_a_future() {
        let ctx = unordered_ctx();
        let (bundle, _) = unordered();
        let ty = find_ty(bundle, |t| {
            ctx.type_semantics(t.id()).is_some_and(|r| {
                r.coroutine.is_none()
                    && r.resource.is_none()
                    && r.future.as_ref().is_some_and(|f| {
                        f.evidence
                            .iter()
                            .all(|e| matches!(e, hansei_bundle::FutureEvidence::PollSymbol(_)))
                    })
            }) && t.dyn_pointer().is_none()
        });
        assert!(ctx.is_future(ty), "{}", ty.name());
    }

    /// Every coroutine is a future, and every coroutine-shaped enum in
    /// the fixture has the bound layout that says so: the shape the
    /// runtime used to screen on is now a fact of the bundle. Asserted
    /// over the whole bundle rather than one witness, because a single
    /// frame can be rescued through the unwrap loop (its sole member
    /// chains to a recognized type) and hide a broken screen.
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
                assert!(
                    ctx.type_semantics(t.id())
                        .is_some_and(|r| r.coroutine.is_some()),
                    "{} has no bound layout",
                    t.name()
                );
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
            if ctx.recognized_future(t.id()) || t.dyn_pointer().is_some() {
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

    /// Storage the bundle declares unreadable is reported as such from
    /// the record, and nothing else: the fixtures bind every coroutine,
    /// so the unbound case is constructed by unbinding one — which also
    /// takes its identity with it, leaving a value the census stops at.
    #[test]
    fn test_unavailable_storage_is_read_from_the_record() {
        use hansei_bundle::{SemanticIssue, SemanticIssueKind, StoragePolicy};
        let (bundle, snapshot) = unordered();
        let ctx = testkit::context(bundle, snapshot);
        assert!(
            bundle
                .semantics
                .types
                .iter()
                .all(|r| !ctx.storage_unavailable(r.ty)),
            "the fixture bundle binds every candidate"
        );
        let mut bundle = bundle.clone();
        let record = bundle
            .semantics
            .types
            .iter_mut()
            .find(|r| r.coroutine.is_some())
            .expect("a bound coroutine");
        let ty = record.ty;
        record.coroutine = None;
        record.future = None;
        record.storage = StoragePolicy::Unavailable(SemanticIssue {
            kind: SemanticIssueKind::UnsupportedOrigin,
            detail: None,
        });
        // Unbinding it also unbinds its program, so nothing it delegated
        // to is proved a future by it any more: withdraw that evidence,
        // and the identity of anything it alone proved, transitively.
        let mut withdrawn = vec![ty];
        while let Some(parent) = withdrawn.pop() {
            for record in &mut bundle.semantics.types {
                let Some(facts) = &mut record.future else {
                    continue;
                };
                facts.evidence.retain(
                    |e| !matches!(e, hansei_bundle::FutureEvidence::DelegatedBy { parent: p } if *p == parent),
                );
                if facts.evidence.is_empty() {
                    record.future = None;
                    withdrawn.push(record.ty);
                }
            }
        }
        bundle.validate().unwrap();
        let ctx = testkit::context(&bundle, snapshot);
        assert!(ctx.storage_unavailable(ty));
        assert!(!ctx.recognized_future(ty));
        assert_eq!(
            crate::tokio::census::Recognize::recognize(&ctx, ty),
            crate::tokio::census::Recognized::Unavailable
        );
        assert!(!ctx.storage_unavailable(BundleTypeId(u32::MAX)));
    }

    /// Plain data is not a future, and neither is a multi-member
    /// container that merely holds them: the unwrap step follows a
    /// *sole* sized member, never guesses among several. A set bound as
    /// a container is a container, not a future.
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
        assert_eq!(
            ctx.container_kind(set.id()),
            Some(ContainerKind::FuturesUnordered)
        );
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

    fn sleep_join() -> &'static (Bundle, Snapshot) {
        static PAIR: OnceLock<(Bundle, Snapshot)> = OnceLock::new();
        PAIR.get_or_init(|| testkit::load_any("sleep-join"))
    }

    /// The listed task whose future's display name contains `name`.
    fn task_named<'a>(list: &'a TaskList, name: &str) -> &'a Task {
        list.tasks
            .iter()
            .find(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
            .unwrap_or_else(|| panic!("the fixture lists a task named {name}"))
    }

    /// A task's Header identifies it without its Trailer: with the
    /// Trailer's pages denied, the header decodes exactly as it did
    /// from the healthy capture while the owned-list link that lives
    /// there does not read — which is what lets a handle name a task
    /// whose list is unreadable, or that has left its list. And a
    /// Header the allocator has taken back is refused before it is
    /// decoded into a task.
    #[test]
    fn test_a_header_decodes_without_its_trailer_links() {
        use crate::testkit::corrupt::Corrupt;
        use crate::testkit::heap::FakeHeap;

        let (bundle, snapshot) = sleep_join();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let task = task_named(&list, "sleeper");
        let healthy = ctx
            .read_task_header(task.addr, &ReadContext::none())
            .unwrap();
        assert_eq!(healthy.task_id, task.task_id);
        assert_eq!(healthy.state, task.state);
        let trailer_ty = ctx
            .infra_ty(ctx.view.bundle().infra.trailer, "task Trailer")
            .unwrap();
        let trailer = task.addr.0 + healthy.trailer_offset;
        assert!(ctx.owned_next(trailer).is_ok());

        let torn = Corrupt::new(snapshot).deny(trailer..trailer + trailer_ty.size());
        let ctx = Context::new(&torn, BundleView::new(bundle)).unwrap();
        let header = ctx
            .read_task_header(task.addr, &ReadContext::none())
            .expect("the header does not need the trailer");
        assert_eq!(header.addr, healthy.addr);
        assert_eq!(header.task_id, healthy.task_id);
        assert_eq!(header.state, healthy.state);
        assert_eq!(header.owner_id, healthy.owner_id);
        assert_eq!(header.trailer_offset, healthy.trailer_offset);
        assert_eq!(header.vtable_addr, healthy.vtable_addr);
        let FutureInfo::Known(known) = &header.future else {
            panic!("the join resolves as before: {:?}", header.future);
        };
        assert!(known.display_name.contains("sleeper"));
        assert_eq!(
            ctx.header_task_ref(task.addr.0).unwrap(),
            (healthy.task_id, healthy.state)
        );
        let err = ctx.owned_next(trailer).unwrap_err();
        assert!(format!("{err:#}").contains("Trailer"), "{err:#}");

        let freed = FakeHeap::new().freed(task.addr.0..task.addr.0 + 8);
        let err = ctx
            .read_task_header(task.addr, &ReadContext::with_heap(&freed))
            .unwrap_err();
        assert!(format!("{err:#}").contains("taken back"), "{err:#}");
        assert_eq!(freed.counts(), (0, 0, 0));
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
            blocking: false,
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

    // -----------------------------------------------------------------
    // Raw resource observations
    // -----------------------------------------------------------------

    /// An address nothing in a small test program's address space
    /// reaches.
    const NOWHERE: u64 = 0xdead_beef_0000;

    fn futurelock() -> &'static (Bundle, Snapshot) {
        static PAIR: OnceLock<(Bundle, Snapshot)> = OnceLock::new();
        PAIR.get_or_init(|| testkit::load_any("futurelock"))
    }

    /// The leaf future of `task`'s chain: the value its chain bottoms
    /// out in, which the observers are asked about.
    fn leaf_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> Value<'a> {
        let TaskStage::Running(root) = ctx.task_stage(task).unwrap() else {
            panic!("the task's future is resident");
        };
        let chain = ctx.await_chain(root);
        assert!(matches!(chain.end, ChainEnd::Leaf), "{:?}", chain.end);
        chain.frames.last().unwrap().future
    }

    /// The listed task whose chain bottoms out in a value of a type
    /// named `leaf`.
    fn task_parked_on<'a, T: Target>(
        ctx: &Context<'a, T>,
        list: &'a TaskList,
        leaf: &str,
    ) -> (&'a Task, Value<'a>) {
        list.tasks
            .iter()
            .filter_map(|task| {
                let TaskStage::Running(root) = ctx.task_stage(task).ok()? else {
                    return None;
                };
                let chain = ctx.await_chain(root);
                let value = chain.frames.last()?.future;
                (matches!(chain.end, ChainEnd::Leaf) && value.ty.name().starts_with(leaf))
                    .then_some((task, value))
            })
            .next()
            .unwrap_or_else(|| panic!("a task is parked on a {leaf}"))
    }

    /// A `JoinHandle` observes as the header it names and nothing
    /// more: no task list is consulted, and a header that has since
    /// completed is still the observation — completion is the
    /// header's own fact, read separately.
    #[test]
    fn test_a_join_handle_observes_its_header_without_a_task_list() {
        use crate::testkit::corrupt::Corrupt;

        let (bundle, snapshot) = sleep_join();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let joiner = task_named(&list, "joiner");
        let sleeper = task_named(&list, "sleeper");
        let handle = leaf_of(&ctx, joiner);
        let observed = ctx.observe_resource(handle, &ReadContext::none());
        assert!(observed.issues.is_empty(), "{:?}", observed.issues);
        let Some(ResourceObservation::Join(join)) = observed.value else {
            panic!("a JoinHandle observes as a join: {:?}", observed.value);
        };
        assert_eq!(join.header, sleeper.addr);
        assert_eq!(join.handle, ValueKey::of(handle));
        let header = ctx
            .read_task_header(join.header, &ReadContext::none())
            .unwrap();
        assert_eq!(header.task_id, sleeper.task_id);
        assert_eq!(header.state.lifecycle(), Lifecycle::Idle);

        // The same handle over a capture where the sleeper has run to
        // completion: the observation is the same header, and the
        // header says complete.
        let header_ty = ctx
            .infra_ty(ctx.view.bundle().infra.header, "task Header")
            .unwrap();
        let state_at = ctx
            .walk(WalkRole::HeaderState)
            .member_offset(header_ty)
            .expect("Header.state is a member path");
        const COMPLETE: u64 = 0b0010;
        const REF_ONE: u64 = 1 << 6;
        let done = Corrupt::new(snapshot).patch(sleeper.addr.0 + state_at, REF_ONE | COMPLETE);
        let ctx = Context::new(&done, BundleView::new(bundle)).unwrap();
        let handle = leaf_of(&ctx, joiner);
        let observed = ctx.observe_resource(handle, &ReadContext::none());
        let Some(ResourceObservation::Join(join)) = observed.value else {
            panic!("still a join: {:?}", observed.value);
        };
        assert_eq!(join.header, sleeper.addr);
        let header = ctx
            .read_task_header(join.header, &ReadContext::none())
            .unwrap();
        assert_eq!(header.state.lifecycle(), Lifecycle::Complete);

        // A value with no resource binding is no observation and no
        // issue: the coroutine frame itself, say.
        let TaskStage::Running(root) = ctx.task_stage(joiner).unwrap() else {
            unreachable!()
        };
        let observed = ctx.observe_resource(root, &ReadContext::none());
        assert!(observed.value.is_none());
        assert!(observed.issues.is_empty());
    }

    /// A `Sleep` observes its cached deadline — the same instant the
    /// wait reader spells — and its entry registered in the wheel at a
    /// tick, the one the wheel harvest reads off the same entry.
    #[test]
    fn test_a_sleep_observes_its_deadline_and_registration() {
        let (bundle, snapshot) = sleep_join();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let sleeper = task_named(&list, "sleeper");
        let sleep = leaf_of(&ctx, sleeper);
        let observed = ctx.observe_resource(sleep, &ReadContext::none());
        let Some(ResourceObservation::Timer(timer)) = observed.value else {
            panic!("a Sleep observes as a timer: {:?}", observed.value);
        };
        assert_eq!(timer.future, ValueKey::of(sleep));
        let TaskStage::Running(root) = ctx.task_stage(sleeper).unwrap() else {
            unreachable!()
        };
        let chain = ctx.await_chain(root);
        let Some(Ok(WaitTarget::Timer { deadline, .. })) = ctx.wait_target(&chain, &list) else {
            panic!("the wait reader reads the same sleep");
        };
        assert_eq!(timer.deadline, Some(deadline));
        assert!(observed.issues.is_empty(), "{:?}", observed.issues);
        let TimerRegistrationState::Registered { tick } = timer.state else {
            panic!("parked in the wheel: {:?}", timer.state);
        };
        assert!(tick < timer::STATE_MIN_VALUE);
        // The wheel harvest read the same word off the same entry.
        let mut e = testkit::enumerate(&ctx, snapshot);
        e.discover(&ctx, &[]);
        let armed: Vec<u64> = e
            .registries
            .timers_of(sleeper.addr.0)
            .filter_map(|t| t.state)
            .collect();
        assert_eq!(armed, [tick]);

        // A sleep whose entry word says deregistered, and one never
        // polled — its guarded `Some` inactive — are each their own
        // state, never a tick.
        use crate::testkit::corrupt::Corrupt;
        let word = ctx.walk(WalkRole::SleepTimerState).walk_at(sleep).unwrap();
        let fired = Corrupt::new(snapshot).patch(word.addr, timer::STATE_DEREGISTERED);
        let ctx_fired = Context::new(&fired, BundleView::new(bundle)).unwrap();
        let sleep_fired = leaf_of(&ctx_fired, sleeper);
        let Some(ResourceObservation::Timer(timer)) = ctx_fired
            .observe_resource(sleep_fired, &ReadContext::none())
            .value
        else {
            unreachable!()
        };
        assert_eq!(timer.state, TimerRegistrationState::Deregistered);
        let pending = Corrupt::new(snapshot).patch(word.addr, timer::STATE_PENDING_FIRE);
        let ctx_pending = Context::new(&pending, BundleView::new(bundle)).unwrap();
        let sleep_pending = leaf_of(&ctx_pending, sleeper);
        let Some(ResourceObservation::Timer(timer)) = ctx_pending
            .observe_resource(sleep_pending, &ReadContext::none())
            .value
        else {
            unreachable!()
        };
        assert_eq!(timer.state, TimerRegistrationState::PendingFire);
    }

    /// An `Acquire` observes its five words with no queue read, and
    /// the semaphore's queue is read on demand: complete, quiescent
    /// under an unlocked guard, in the wake order the wait reader
    /// spells, holding the acquire's node exactly once — which is
    /// what places it.
    #[test]
    fn test_an_acquire_observes_its_words_and_the_queue_on_demand() {
        let (bundle, snapshot) = futurelock();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let (task, acquire) = task_parked_on(&ctx, &list, "tokio::sync::batch_semaphore::Acquire");
        let observed = ctx.observe_resource(acquire, &ReadContext::none());
        assert!(observed.issues.is_empty(), "{:?}", observed.issues);
        let Some(ResourceObservation::Acquire(acq)) = observed.value else {
            panic!("an Acquire observes as an acquire: {:?}", observed.value);
        };
        assert_eq!(acq.future, ValueKey::of(acquire));
        assert_eq!(acq.requested, 1);
        assert_eq!(acq.needed, 1);
        assert!(acq.queued);
        assert_eq!(acq.queue_position, None);
        let sem_ty = ctx.view.ty(acq.semaphore.ty).unwrap();
        assert_eq!(sem_ty.name(), "tokio::sync::batch_semaphore::Semaphore");
        let node_ty = ctx.walk(WalkRole::AcquireNode).walk_at(acquire).unwrap();
        assert_eq!(acq.node, node_ty.addr);

        let mut budget = ScanBudget::default();
        let queue = ctx.observe_semaphore_queue(acq.semaphore, &ReadContext::none(), &mut budget);
        assert!(queue.issues.is_empty(), "{:?}", queue.issues);
        assert!(queue.complete);
        assert_eq!(queue.consistency, Consistency::Quiescent);
        assert_eq!(queue.closed, Some(false));
        assert_eq!(queue.queue_closed, Some(false));
        // The background task holds the one permit.
        assert_eq!(queue.available, Some(0));
        assert!(queue.established());
        assert_eq!(
            queue.waiters.iter().filter(|w| w.addr == acq.node).count(),
            1
        );
        assert_eq!(queue.contains(acq.node), Some(true));
        assert_eq!(queue.contains(NOWHERE), Some(false));
        // The semaphore itself, then one node.
        assert_eq!(budget.referent_expansions, 1 + queue.waiters.len() as u64);
        // Every node's waker is this task's: the abandoned op1 box
        // and the awaited op2 were both polled by it.
        for waiter in &queue.waiters {
            assert_eq!(waiter.waker.task(), Some(task.addr.0), "{waiter:?}");
        }

        // The permits word decodes its count above the closed bit.
        {
            use crate::testkit::corrupt::Corrupt;
            let sem = ctx.read_keyed(acq.semaphore, &ReadContext::none()).unwrap();
            let permits = ctx.walk(WalkRole::SemaphorePermits).walk_at(sem).unwrap();
            for (word, available, closed) in [
                (
                    (3u64 << semaphore::PERMIT_SHIFT) | semaphore::CLOSED,
                    3,
                    true,
                ),
                (5 << semaphore::PERMIT_SHIFT, 5, false),
            ] {
                let patched = Corrupt::new(snapshot).patch(permits.addr, word);
                let ctx = Context::new(&patched, BundleView::new(bundle)).unwrap();
                let queue = ctx.observe_semaphore_queue(
                    acq.semaphore,
                    &ReadContext::none(),
                    &mut ScanBudget::default(),
                );
                assert_eq!(queue.available, Some(available), "word {word:#x}");
                assert_eq!(queue.closed, Some(closed), "word {word:#x}");
            }
        }

        // The same order and nodes the wait reader spells.
        let TaskStage::Running(root) = ctx.task_stage(task).unwrap() else {
            unreachable!()
        };
        let chain = ctx.await_chain(root);
        let Some(Ok(WaitTarget::Semaphore { waiters, .. })) = ctx.wait_target(&chain, &list) else {
            panic!("the wait reader reads the same semaphore");
        };
        let legacy: Vec<u64> = waiters.iter().map(|w| w.addr).collect();
        let observed: Vec<u64> = queue.waiters.iter().map(|w| w.addr).collect();
        assert_eq!(observed, legacy);
        assert_eq!(
            queue.position(acq.node),
            legacy.iter().position(|&a| a == acq.node)
        );
    }

    /// The queue's guard byte and the word linking its first node —
    /// the `Option<NonNull<Waiter>>` inside the node's pointers, at
    /// whatever it holds — for damaging them.
    fn queue_words<'a>(ctx: &Context<'a, Snapshot>, semaphore: ValueKey) -> (u64, u64, u64) {
        let sem = ctx.read_keyed(semaphore, &ReadContext::none()).unwrap();
        let lock = ctx.walk(WalkRole::SemaphoreLock).walk_at(sem).unwrap();
        assert_eq!(lock.ty.name(), "parking_lot::raw_mutex::RawMutex");
        let head = ctx.walk(WalkRole::SemaphoreQueueHead).walk_at(sem).unwrap();
        let first: u64 = head.parse(ctx.proc).unwrap();
        let node = Value::read(ctx.proc, head.ty.pointer_target().unwrap(), first).unwrap();
        // The recorded route enters `Some` on its way to the pointer;
        // the option itself is what the steps before that land on.
        let steps = &ctx.view.bundle().walks.entries[&WalkRole::WaiterNext].steps;
        let option = steps
            .iter()
            .position(|s| matches!(s, Step::Variant(_)))
            .expect("the link route enters Some");
        let Walked::At(next) =
            contract::execute_steps(ctx, &ReadContext::none(), node, &steps[..option]).unwrap()
        else {
            panic!("the option is reached");
        };
        (lock.addr, next.addr, first)
    }

    /// A queue read under a held guard, cut short, refused by the
    /// allocator, capped, or looped keeps the nodes it reached and
    /// places none of them: no position, and no claim that an unseen
    /// node is absent. The fixture's queue holds one node — op2's —
    /// behind the granted, abandoned op1, which has left the queue
    /// and so has no position in it.
    #[test]
    fn test_a_partial_or_mutating_queue_places_nothing() {
        use crate::testkit::corrupt::Corrupt;
        use crate::testkit::heap::FakeHeap;
        use crate::tokio::observe::ScanLimits;

        let (bundle, snapshot) = futurelock();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let (task, acquire) = task_parked_on(&ctx, &list, "tokio::sync::batch_semaphore::Acquire");
        let Some(ResourceObservation::Acquire(acq)) =
            ctx.observe_resource(acquire, &ReadContext::none()).value
        else {
            unreachable!()
        };
        let (lock_byte, first_next, first) = queue_words(&ctx, acq.semaphore);
        assert_eq!(first, acq.node);

        // The granted acquire left the queue: an established walk says
        // so, and places it nowhere.
        let TaskStage::Running(root) = ctx.task_stage(task).unwrap() else {
            unreachable!()
        };
        let chain = ctx.await_chain(root);
        let abandoned = ctx.abandoned_acquires(&chain);
        assert_eq!(abandoned.len(), 1, "{abandoned:?}");
        assert!(abandoned[0].granted());
        let granted = abandoned[0].node;
        let queue = ctx.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::none(),
            &mut ScanBudget::default(),
        );
        assert!(queue.established());
        assert_eq!(queue.waiters.len(), 1);
        assert_eq!(queue.position(first), Some(0));
        assert_eq!(queue.contains(granted), Some(false));
        assert_eq!(queue.position(granted), None);

        // Locked: everything reads, nothing is placed.
        let locked = Corrupt::new(snapshot).patch_byte(lock_byte, 0b01);
        let ctx_locked = Context::new(&locked, BundleView::new(bundle)).unwrap();
        let queue = ctx_locked.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::none(),
            &mut ScanBudget::default(),
        );
        assert!(queue.complete);
        assert_eq!(queue.consistency, Consistency::Mutating);
        assert!(queue.issues.is_empty(), "{:?}", queue.issues);
        assert_eq!(queue.waiters.len(), 1);
        assert_eq!(queue.position(first), None);
        assert_eq!(queue.contains(first), Some(true));
        assert_eq!(queue.contains(granted), None);

        // Cut: the node's link runs off the map, the prefix is kept,
        // and nothing beyond it is placed or declared absent.
        let cut = Corrupt::new(snapshot).patch(first_next, NOWHERE);
        let ctx_cut = Context::new(&cut, BundleView::new(bundle)).unwrap();
        let queue = ctx_cut.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::none(),
            &mut ScanBudget::default(),
        );
        assert!(!queue.complete);
        assert_eq!(queue.consistency, Consistency::Quiescent);
        let reached: Vec<u64> = queue.waiters.iter().map(|w| w.addr).collect();
        assert_eq!(reached, [first]);
        assert_eq!(queue.issues.len(), 1);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::ReadFailed);
        assert_eq!(queue.issues[0].at.addr, NOWHERE);
        assert_eq!(queue.position(first), None);
        assert_eq!(queue.contains(first), Some(true));
        assert_eq!(queue.contains(granted), None);

        // Looped: the node links back to itself.
        let looped = Corrupt::new(snapshot).patch(first_next, first);
        let ctx_looped = Context::new(&looped, BundleView::new(bundle)).unwrap();
        let queue = ctx_looped.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::none(),
            &mut ScanBudget::default(),
        );
        assert!(!queue.complete);
        assert_eq!(queue.issues.len(), 1);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::Cycle);
        assert_eq!(queue.waiters.len(), 1);

        // Refused: the node is in memory the allocator has taken
        // back, so it is not read and the walk ends before it.
        let node_ty = ctx.view.ty(queue.issues[0].at.ty).unwrap();
        let freed = FakeHeap::new().freed(first..first + node_ty.size());
        let mut budget = ScanBudget::default();
        let queue = ctx.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::with_heap(&freed),
            &mut budget,
        );
        assert!(!queue.complete);
        assert_eq!(queue.issues.len(), 1);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::Freed);
        assert_eq!(queue.issues[0].at.addr, first);
        assert!(queue.waiters.is_empty());
        assert_eq!(queue.contains(first), None);
        // Charged for the semaphore and for the node it was about to
        // read: the budget is charged before the read the allocator
        // then refused.
        assert_eq!(budget.referent_expansions, 2);
        assert_eq!(freed.counts(), (0, 0, 0));

        // A live block too short for the node refuses the same way.
        let short = FakeHeap::new().live(first..first + node_ty.size() - 1);
        let queue = ctx.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::with_heap(&short),
            &mut ScanBudget::default(),
        );
        assert_eq!(queue.issues.len(), 1);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::OutsideAllocation);

        // Capped: no node at all is what the walk may list.
        let mut budget = ScanBudget::new(ScanLimits {
            max_children: 0,
            ..ScanLimits::default()
        });
        let queue = ctx.observe_semaphore_queue(acq.semaphore, &ReadContext::none(), &mut budget);
        assert!(!queue.complete);
        assert_eq!(queue.issues.len(), 1);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::VisitLimit);
        assert!(queue.waiters.is_empty());

        // Or the referent budget is spent before the first node.
        let mut budget = ScanBudget::new(ScanLimits {
            max_referent_expansions: 0,
            ..ScanLimits::default()
        });
        let queue = ctx.observe_semaphore_queue(acq.semaphore, &ReadContext::none(), &mut budget);
        assert!(!queue.complete);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::VisitLimit);
        assert!(queue.waiters.is_empty());

        // And a semaphore the allocator has taken back observes as
        // nothing but the refusal.
        let sem_ty = ctx.view.ty(acq.semaphore.ty).unwrap();
        let gone = FakeHeap::new().freed(acq.semaphore.addr..acq.semaphore.addr + sem_ty.size());
        let queue = ctx.observe_semaphore_queue(
            acq.semaphore,
            &ReadContext::with_heap(&gone),
            &mut ScanBudget::default(),
        );
        assert!(!queue.complete);
        assert_eq!(queue.consistency, Consistency::Unknown);
        assert_eq!(queue.available, None);
        assert_eq!(queue.issues.len(), 1);
        assert_eq!(queue.issues[0].kind, WalkIssueKind::Freed);
    }

    /// Each bounded io operation observes the registration its own
    /// reader or writer reaches — the resource the registry harvest
    /// found the task's waker on — and a readiness await observes the
    /// exact node it embedded, which the registration read on demand
    /// lists with the same identity and ready flag. A custom reader
    /// over a socket observes as nothing.
    #[test]
    fn test_io_operations_observe_their_registrations() {
        let (bundle, snapshot) = local_set_io();
        let ctx = testkit::context(bundle, snapshot);
        let mut e = testkit::enumerate(&ctx, snapshot);
        e.discover(&ctx, &[]);
        let list = &e.list;
        let registered = |task: &Task| -> Vec<(u64, IoWaiterInfo)> {
            e.registries
                .io_of(task.addr.0)
                .map(|(res, waiter)| (res.addr, waiter.clone()))
                .collect()
        };

        // `Read<UnixStream>`: through `reader` to its `ScheduledIo`.
        for (name, remaining) in [("local_reader", 8), ("::reader", 16)] {
            let task = task_named(list, name);
            let read = leaf_of(&ctx, task);
            assert!(read.ty.name().starts_with("tokio::io::util::read::Read<"));
            let observed = ctx.observe_resource(read, &ReadContext::none());
            assert!(observed.issues.is_empty(), "{name}: {:?}", observed.issues);
            let Some(ResourceObservation::Io(io)) = observed.value else {
                panic!("{name}: a Read observes as io: {:?}", observed.value);
            };
            assert_eq!(io.operation, IoOperationKind::Read);
            assert_eq!(io.interest, Interest::READABLE);
            assert_eq!(io.remaining, Some(remaining));
            assert_eq!(io.waiter_node, None);
            assert_eq!(io.readiness_state, None);
            let parked = registered(task);
            assert_eq!(parked.len(), 1, "{name}: {parked:?}");
            assert_eq!(parked[0].0, io.scheduled_io.addr);
            assert_eq!(parked[0].1.slot, IoSlot::Reader);
            assert_eq!(
                ctx.view.ty(io.scheduled_io.ty).unwrap().name(),
                "tokio::runtime::io::scheduled_io::ScheduledIo"
            );
        }

        // `WriteAll<UnixStream>`: through `writer`.
        let writer = task_named(list, "local_writer");
        let write = leaf_of(&ctx, writer);
        let Some(ResourceObservation::Io(io)) =
            ctx.observe_resource(write, &ReadContext::none()).value
        else {
            panic!("a WriteAll observes as io");
        };
        assert_eq!(io.operation, IoOperationKind::WriteAll);
        assert_eq!(io.interest, Interest::WRITABLE);
        assert!(
            io.remaining.is_some_and(|n| n > 0 && n <= 64 * 1024),
            "{:?}",
            io.remaining
        );
        let parked = registered(writer);
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].0, io.scheduled_io.addr);
        assert_eq!(parked[0].1.slot, IoSlot::Writer);

        // `Readiness`: the registration it names outright, its state,
        // and its own node — which the registration lists.
        let watcher = task_named(list, "local_watcher");
        let readiness = leaf_of(&ctx, watcher);
        let observed = ctx.observe_resource(readiness, &ReadContext::none());
        assert!(observed.issues.is_empty(), "{:?}", observed.issues);
        let Some(ResourceObservation::Io(io)) = observed.value else {
            panic!("a Readiness observes as io: {:?}", observed.value);
        };
        assert_eq!(io.operation, IoOperationKind::Readiness);
        assert_eq!(io.interest, Interest::READABLE);
        assert_eq!(io.readiness_state, Some(IoFutureState::Waiting));
        assert_eq!(io.waiter_ready, Some(false));
        assert_eq!(io.remaining, None);
        let node = io.waiter_node.expect("a readiness await embeds its node");
        let parked = registered(watcher);
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].0, io.scheduled_io.addr);
        assert_eq!(parked[0].1.node, Some(node));
        assert_eq!(parked[0].1.ready, Some(false));
        assert_eq!(
            parked[0].1.slot,
            IoSlot::Listed {
                interest: Some(Interest::READABLE)
            }
        );

        let mut budget = ScanBudget::default();
        let registration =
            ctx.observe_io_registration(io.scheduled_io, &ReadContext::none(), &mut budget);
        assert!(registration.issues.is_empty(), "{:?}", registration.issues);
        let resource = registration.value.expect("the registration reads");
        assert_eq!(resource.addr, io.scheduled_io.addr);
        assert_eq!(resource.consistency, Consistency::Quiescent);
        assert_eq!(resource.waiters.len(), 1);
        // The harvest decoded the same guard.
        assert!(
            e.registries
                .io
                .iter()
                .all(|r| r.consistency == Consistency::Quiescent),
            "{:?}",
            e.registries.io
        );
        let listed = &resource.waiters[0];
        assert_eq!(listed.node, Some(node));
        assert_eq!(listed.ready, Some(false));
        assert_eq!(listed.task, Some(watcher.addr.0));
        assert_eq!(
            listed.slot,
            IoSlot::Listed {
                interest: Some(Interest::READABLE)
            }
        );
        // The registration itself, then its one node.
        assert_eq!(budget.referent_expansions, 2);

        // The child cap is exact: a cap of one lists the one node, a
        // cap of zero refuses it.
        {
            use crate::tokio::observe::ScanLimits;
            let capped = |max_children: u32| {
                let mut budget = ScanBudget::new(ScanLimits {
                    max_children,
                    ..ScanLimits::default()
                });
                ctx.observe_io_registration(io.scheduled_io, &ReadContext::none(), &mut budget)
            };
            let one = capped(1);
            assert!(one.issues.is_empty(), "{:?}", one.issues);
            assert_eq!(one.value.unwrap().waiters.len(), 1);
            let none = capped(0);
            assert_eq!(none.issues.len(), 1, "{:?}", none.issues);
            assert_eq!(none.issues[0].kind, WalkIssueKind::VisitLimit);
            assert_eq!(none.issues[0].at.addr, node);
            assert!(none.value.unwrap().waiters.is_empty());
        }

        // A registration whose list runs off the map keeps the slots
        // it read and says where the list failed.
        {
            use crate::testkit::corrupt::Corrupt;
            let io_value = ctx
                .read_keyed(io.scheduled_io, &ReadContext::none())
                .unwrap();
            let waiters = ctx
                .walk(WalkRole::ScheduledIoWaiters)
                .walk_at(io_value)
                .unwrap();
            let head = ctx.walk(WalkRole::IoWaiterHead).walk_at(waiters).unwrap();
            let cut = Corrupt::new(snapshot).patch(head.addr, NOWHERE);
            let ctx_cut = Context::new(&cut, BundleView::new(bundle)).unwrap();
            let registration = ctx_cut.observe_io_registration(
                io.scheduled_io,
                &ReadContext::none(),
                &mut ScanBudget::default(),
            );
            let resource = registration.value.expect("the registration itself reads");
            assert!(resource.waiters.is_empty());
            assert_eq!(registration.issues.len(), 1);
            assert_eq!(registration.issues[0].kind, WalkIssueKind::ReadFailed);
            assert_eq!(registration.issues[0].at.addr, NOWHERE);
        }

        // The await's own state word, as its enumeration spells it,
        // and a word no enumerator claims kept raw.
        {
            use crate::testkit::corrupt::Corrupt;
            let word = ctx
                .walk(WalkRole::ReadinessState)
                .walk_at(readiness)
                .unwrap();
            for (byte, expected) in [
                (0u8, IoFutureState::Init),
                (1, IoFutureState::Waiting),
                (2, IoFutureState::Done),
                (7, IoFutureState::Unknown(7)),
            ] {
                let patched = Corrupt::new(snapshot).patch_byte(word.addr, byte);
                let ctx = Context::new(&patched, BundleView::new(bundle)).unwrap();
                let readiness = leaf_of(&ctx, watcher);
                let Some(ResourceObservation::Io(io)) =
                    ctx.observe_resource(readiness, &ReadContext::none()).value
                else {
                    panic!("still a readiness await")
                };
                assert_eq!(io.readiness_state, Some(expected), "state byte {byte}");
            }
        }

        // `Read<Gated>` holds a socket and is not an operation on one.
        let gated = task_named(list, "local_gated_reader");
        let read = leaf_of(&ctx, gated);
        assert!(read.ty.name().contains("Gated"));
        let observed = ctx.observe_resource(read, &ReadContext::none());
        assert!(observed.value.is_none());
        assert!(observed.issues.is_empty());
        assert!(registered(gated).is_empty());
    }

    /// A read operation's route dereferences its reader, and that
    /// dereference is held to the allocator: a stream the allocator
    /// has taken back is refused before the registration is reached.
    #[test]
    fn test_an_io_route_is_held_to_the_allocator() {
        use crate::testkit::heap::FakeHeap;

        let (bundle, snapshot) = local_set_io();
        let ctx = testkit::context(bundle, snapshot);
        let list = testkit::tasks(&ctx, snapshot);
        let task = task_named(&list, "local_reader");
        let read = leaf_of(&ctx, task);
        let reader = ctx.walk(WalkRole::IoReadReader).walk_at(read).unwrap();
        let stream: u64 = reader.parse(ctx.proc).unwrap();
        let stream_ty = reader.ty.pointer_target().unwrap();
        let freed = FakeHeap::new().freed(stream..stream + stream_ty.size());
        let observed = ctx.observe_resource(read, &ReadContext::with_heap(&freed));
        assert!(observed.value.is_none());
        assert_eq!(observed.issues.len(), 1);
        assert_eq!(observed.issues[0].kind, WalkIssueKind::Freed);
        assert_eq!(observed.issues[0].at, ValueKey::of(read));
        let live = FakeHeap::new().live(stream..stream + stream_ty.size());
        let observed = ctx.observe_resource(read, &ReadContext::with_heap(&live));
        assert!(observed.issues.is_empty(), "{:?}", observed.issues);
        assert!(matches!(observed.value, Some(ResourceObservation::Io(_))));
    }

    /// Only a trampoline-sized symbol ending in `jmp rel32` yields a
    /// target — computed relative to the symbol's end — and everything
    /// that could hold a real body (a big symbol, a return, an
    /// indirect jump, bytes too short to hold a jump) yields none.
    #[test]
    fn test_a_thunk_target_follows_only_a_trailing_rel32_jump() {
        // nexus's `raw::poll` trampoline verbatim:
        // push rbp; mov rbp, rsp; pop rbp; jmp +0x2e98b6.
        let thunk = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xe9, 0xb6, 0x98, 0x2e, 0x00];
        assert_eq!(thunk_target(0xa16dd80, &thunk), Some(0xa457640));
        // A bare jump, and one jumping backwards to its own start.
        let back = [0xe9, 0xfb, 0xff, 0xff, 0xff];
        assert_eq!(thunk_target(0x1000, &back), Some(0x1000));
        // Too big to be a trampoline, even ending in the right bytes.
        let mut big = vec![0x90; 17];
        big[12..].copy_from_slice(&[0xe9, 0, 0, 0, 0]);
        assert_eq!(thunk_target(0x1000, &big), None);
        // The tail is not a rel32 jmp: a plain return, an indirect
        // (`ff 25`) jump.
        assert_eq!(thunk_target(0x1000, &[0x55, 0x5d, 0xc3]), None);
        assert_eq!(thunk_target(0x1000, &[0xff, 0x25, 0, 0, 0, 0]), None);
        // Too short to hold a jmp at all.
        assert_eq!(thunk_target(0x1000, &[0xe9, 0x00]), None);
        assert_eq!(thunk_target(0x1000, &[]), None);
        // The boundary: sixteen bytes — the largest trampoline — still
        // follows.
        let mut edge = vec![0x90; 11];
        edge.extend_from_slice(&[0xe9, 0, 0, 0, 0]);
        assert_eq!(thunk_target(0x1000, &edge), Some(0x1010));
    }

    /// The anchor range handed to the stack join is the symtab
    /// symbol covering the vtable's poll fn, as `st_value ..
    /// st_value + st_size` — recomputed here from the symbol itself,
    /// so a range computed any other way fails.
    #[test]
    fn test_poll_symbol_range_is_the_polls_symtab_extent() {
        let (_, snapshot) = unordered();
        let ctx = unordered_ctx();
        let list = testkit::tasks(&ctx, snapshot);
        let task = list.tasks.first().expect("the fixture owns tasks");
        let range = ctx
            .poll_symbol_range(task)
            .expect("the header and vtable read back")
            .expect("a symbol covers the poll fn");
        let sym = snapshot
            .lookup_symbol_by_addr(range.start)
            .expect("the range starts inside a symbol");
        assert_eq!(range, sym.st_value..sym.st_value + sym.st_size);
        assert!(range.start < range.end);
        // The v0 spelling of `task::raw::poll`, however the future
        // type parameter mangles.
        assert!(sym.name.contains("3raw4poll"), "{}", sym.name);
    }
}

/// Route 1's two inputs, side by side: the chain sweep and the
/// reference scan over the same enumerated storage.
#[cfg(test)]
mod discovery_scan_tests {
    use super::*;
    use crate::testkit;

    fn named<'l>(list: &'l TaskList, name: &str) -> &'l Task {
        list.tasks
            .iter()
            .find(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
            .unwrap_or_else(|| panic!("a task named {name}"))
    }

    /// The scan finds what the chain sweep finds: on the foreign-runtime
    /// pair the joiner's held `JoinHandle` names a task no enumerated
    /// list owns, and both inputs offer that Header — the sweep by the
    /// diagnosed wait, the scan by the reference's own kind. Offered
    /// after the sweep, the scan adds nothing the sweep already named;
    /// offered alone, it names the same task. In the rounds after
    /// admission the hidden runtime's own tasks are scanned in turn,
    /// and reference nothing outside the list.
    #[test]
    fn test_the_scan_offers_what_the_chain_sweep_offers() {
        for set in testkit::FIXTURE_SETS {
            let (bundle, snapshot) = testkit::load(set, "foreign-runtime");
            let ctx = testkit::context(&bundle, &snapshot);
            let mut e = testkit::enumerate(&ctx, &snapshot);
            let listed = e.list.tasks.len();
            let read = ReadContext::none();

            let swept = ctx.unlisted_task_pointers(&e.list, 0..listed);
            let mut alone = Vec::new();
            let mut budget = ScanBudget::default();
            ctx.scanned_task_pointers(&e.list, 0..listed, &read, &mut budget, &mut alone);
            let mut after = swept.clone();
            ctx.scanned_task_pointers(&e.list, 0..listed, &read, &mut budget, &mut after);
            assert!(budget.inline_visits > 0, "[{set}] the scan visited");

            e.discover(&ctx, &[]);
            let joined = named(&e.list, "foreign_runtime::joined").addr.0;
            assert!(
                swept.iter().any(|(addr, _)| *addr == joined),
                "[{set}] the sweep offers the joined task: {swept:?}"
            );
            assert_eq!(
                alone,
                vec![(joined, DiscoveryRoute::Scanned(ReferenceSource::JoinHandle))],
                "[{set}] the scan alone offers the joined task, once, by its kind"
            );
            assert_eq!(
                after, swept,
                "[{set}] after the sweep the scan adds nothing"
            );
            assert_eq!(
                DiscoveryRoute::Scanned(ReferenceSource::JoinHandle).to_string(),
                "a JoinHandle scanned in an enumerated task's storage"
            );

            // The later round: what the admitted runtime owns is scanned
            // as new storage, and references only what is listed.
            let mut later = Vec::new();
            let before = budget.inline_visits;
            ctx.scanned_task_pointers(
                &e.list,
                listed..e.list.tasks.len(),
                &read,
                &mut budget,
                &mut later,
            );
            assert!(
                e.list.tasks.len() > listed,
                "[{set}] discovery admitted tasks"
            );
            assert!(
                budget.inline_visits > before,
                "[{set}] the later round scanned"
            );
            assert!(later.is_empty(), "[{set}] {later:?}");
        }
    }

    /// A spent budget is reported, not absorbed: under a one-visit cap
    /// the sweep says so in the list's errors and still finds every
    /// owner through its other input, and under the defaults nothing
    /// is spent and nothing is said.
    #[test]
    fn test_a_spent_scan_budget_is_reported() {
        let (bundle, snapshot) = testkit::load_any("foreign-runtime");
        let ctx = testkit::context(&bundle, &snapshot);
        let discover = |limits: ScanLimits| {
            let mut e = testkit::enumerate(&ctx, &snapshot);
            let (sets, _) = ctx.discover_hidden_tasks_with(
                &e.lwps,
                &e.workers,
                &mut e.runtimes,
                &[],
                &mut e.list,
                &ReadContext::none(),
                limits,
            );
            (e.runtimes.len(), sets.len(), e.list)
        };
        let (runtimes, sets, list) = discover(ScanLimits::default());
        let budget: Vec<String> = list
            .errors
            .iter()
            .map(|e| e.to_string())
            .filter(|e| e.contains("reference scan spent"))
            .collect();
        assert!(budget.is_empty(), "{budget:?}");

        let capped = ScanLimits {
            max_inline_visits: 1,
            ..ScanLimits::default()
        };
        let (capped_runtimes, capped_sets, capped_list) = discover(capped);
        assert_eq!((capped_runtimes, capped_sets), (runtimes, sets));
        assert_eq!(capped_list.tasks.len(), list.tasks.len());
        let budget: Vec<String> = capped_list
            .errors
            .iter()
            .map(|e| e.to_string())
            .filter(|e| e.contains("reference scan spent"))
            .collect();
        assert_eq!(
            budget,
            ["the reference scan spent its budget of 1 inline visits; \
              references past it were not followed"]
        );
    }
}

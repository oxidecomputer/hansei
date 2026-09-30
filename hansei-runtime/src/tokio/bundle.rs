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
use super::discovery::{
    DiscoveryIssue, Observation, OwnerClaim, OwnerEvidence, TaskRecordId, TaskSource, list_claim,
};
use super::observe::{
    AcquireObservation, ChannelObservation, Consistency, HttpClientObservation,
    HttpConnObservation, HttpNegotiatingObservation, HttpReading, HttpRequestObservation,
    HttpServerObservation, HttpWriting, IoFutureState, IoObservation, JoinObservation, KeepAlive,
    NotifiedObservation, NotifiedState, NotifyObservation, Observed, OneshotObservation,
    QueueObservation, ReadContext, RecvObservation, ReferenceSink, ReferenceSource,
    ResourceObservation, ScanBudget, ScanLimits, SlotState, SocketReading, TaskReference,
    TimerObservation, TimerRegistrationState, ValueKey, WalkIssue, WalkIssueKind, issue_of,
    lock_consistency,
};
use super::semantics::SemanticIndex;
use super::work::{DiscoveryWorld, Registry, Roots, sweep};
use super::{Location, RawInstant, TaskAddr, TaskState};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use hansei_bundle::symbols::normalized_v0_key;
use hansei_bundle::tokio::{semaphore, timer};
use hansei_bundle::{
    AccessKind, BundleMember, BundleType, BundleTypeId, BundleView, ContainerKind, Continuation,
    DynStreamCase, DynStreamLayout, FutureKind, HashTableBinding, IoOperationKind, IoRouteStep,
    IoSocket, MemberRef, PollAction, PollProgram, ResourceKind, SchedulerClass, SelectBinding,
    StaticRole, Step, StoragePolicy, StreamPeerBinding, SymbolLookup, TaskEntryId, TaskFutureEntry,
    TlsStreamBinding, TypeClass, TypeDef, TypeSemantics, TypedPath, WalkOutcome, WalkRole,
    socket_roles, strip_build_prefix, strip_llvm_suffix,
};
use proc::{LwpInfo, Mappings, SymbolBuf, Target};
use reify::Value;

use foldhash::{HashMap, HashSet};
use std::cell::RefCell;

use std::collections::BTreeMap;

/// Hard bound on await-chain depth: anything deeper indicates corrupt
/// memory (or a pathological program), and the walk must report it
/// rather than hang.
pub(crate) const MAX_AWAIT_DEPTH: usize = 64;

/// Bound on the streams a route crosses to its socket, for a table that
/// was never validated; a validated one ends every route well short.
const MAX_IO_ROUTE: usize = 32;

/// Where a stream's route led: the streams crossed, outermost first,
/// the socket's registration and descriptor, and the TLS connection on
/// the way, where there was one.
pub(crate) struct FollowedRoute<'b> {
    pub(crate) streams: Vec<ValueKey>,
    pub(crate) scheduled_io: Value<'b>,
    pub(crate) fd: Option<i32>,
    pub(crate) tls: Option<Result<TlsReading, String>>,
    pub(crate) socket: IoSocket,
    pub(crate) peer: Option<Result<String, String>>,
}

/// Whether `addr` lies in `value`'s storage.
pub(crate) fn contains(value: Value<'_>, addr: u64) -> bool {
    addr >= value.addr && addr - value.addr < value.bytes.len() as u64
}

/// A watch channel's words, as both readers print them.
pub(crate) struct WatchWords {
    /// The `Shared`'s address: `data`'s offset into the `ArcInner`.
    pub addr: u64,
    pub version: u64,
    pub closed: bool,
    pub receivers: u64,
    pub senders: u64,
}

/// The watch channel behind `arc`, an `ArcInner<watch::Shared<T>>`
/// value, read through the roles rooted at it — `at` walks a role to
/// its value, `word` reads one as a u64 — when the `Notify` at
/// `notify` is one of its `notify_rx` array: the state word's version
/// and closed bit, and both handle counts. Shared by the wait
/// assessor's target and the attributor's reading, so the two never
/// disagree on a channel.
pub(crate) fn watch_words_of<'b>(
    arc: Value<'b>,
    notify: u64,
    at: &dyn Fn(WalkRole) -> Option<Value<'b>>,
    word: &dyn Fn(WalkRole) -> Option<u64>,
) -> Option<WatchWords> {
    use hansei_bundle::tokio::watch;
    if !contains(at(WalkRole::WatchSharedNotifyRx)?, notify) {
        return None;
    }
    let state = word(WalkRole::WatchSharedState)?;
    let data = arc.ty.member("data").map(|m| m.offset()).unwrap_or(0);
    Some(WatchWords {
        addr: arc.addr + data,
        version: state >> watch::VERSION_SHIFT,
        closed: state & watch::CLOSED != 0,
        receivers: word(WalkRole::WatchSharedRxCount)?,
        senders: word(WalkRole::WatchSharedTxCount)?,
    })
}

/// Whether an `Option<T>` value holds a `Some`, by its active variant;
/// `None` where the bytes decode to no variant or the type is not an
/// enum.
pub fn option_present(value: Value<'_>) -> Option<bool> {
    match value.ty.active_variant(value.bytes)?.ok()?.name {
        "Some" => Some(true),
        "None" => Some(false),
        _ => None,
    }
}

/// The io resources the fd join recognizes, as the two walk roles
/// rooted at each resource type — the route to its `ScheduledIo` (the
/// io registry's join key) and to its fd. A frame member (or its
/// pointee) is a resource when its type is one the first role roots at.
const IO_RESOURCES: &[(WalkRole, WalkRole)] = &[
    (WalkRole::TcpStreamShared, WalkRole::TcpStreamFd),
    (WalkRole::TcpListenerShared, WalkRole::TcpListenerFd),
    (WalkRole::UdpSocketShared, WalkRole::UdpSocketFd),
    (WalkRole::UnixStreamShared, WalkRole::UnixStreamFd),
    (WalkRole::UnixListenerShared, WalkRole::UnixListenerFd),
    (WalkRole::UnixDatagramShared, WalkRole::UnixDatagramFd),
];

/// One route's find, before the store takes it: a header some value
/// or registry named, or an entry of a runtime's blocking-pool queue.
/// Both are merged by [`Context::observe_candidate`], which decodes
/// the header once per address and bootstraps the owner a fresh
/// reference's cell records.
#[derive(Debug)]
pub(crate) enum Candidate {
    Reference {
        reference: TaskReference,
        route: DiscoveryRoute,
    },
    Queued {
        addr: u64,
        owner: OwnerKey,
        queue: ValueKey,
        entry: u64,
    },
}

impl Candidate {
    pub(crate) fn addr(&self) -> u64 {
        match self {
            Self::Reference { reference, .. } => reference.target.0,
            Self::Queued { addr, .. } => *addr,
        }
    }

    fn route(&self) -> DiscoveryRoute {
        match self {
            Self::Reference { route, .. } => *route,
            Self::Queued { .. } => DiscoveryRoute::BlockingQueue,
        }
    }
}

/// The primitive wrapping an acquired semaphore, when a frame above the
/// `Acquire` leaf is a future the bundle records acquiring for one.
///
/// The search runs up the chain rather than reading the frame directly
/// above the leaf: a wrapper the walk now follows (`Instrumented`, a
/// `Map`) can sit between `Mutex::lock`'s coroutine and the `Acquire` it
/// awaits, and a fixed offset would read that wrapper and report a
/// semaphore nobody owns.
pub(crate) fn semaphore_owner(chain: &AwaitChain<'_>) -> Option<&'static str> {
    chain
        .frames
        .iter()
        .rev()
        .skip(1)
        .find_map(|frame| frame.future.ty.acquires_for())
        .map(primitive_label)
}

/// A primitive's name as the records that carry it by value keep it:
/// the bundle's own string, kept once per distinct name for the life
/// of the process. Only a reviewed rule records one, so what is kept is
/// bounded by the rules' few names, not by the target.
fn primitive_label(name: &str) -> &'static str {
    static LABELS: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
    let mut labels = LABELS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(label) = labels.iter().find(|label| **label == name) {
        return label;
    }
    let label: &'static str = Box::leak(name.into());
    labels.push(label);
    label
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

    fn get(&self, key: &K) -> Option<V> {
        self.0.borrow().get(key).cloned()
    }

    fn insert(&self, key: K, value: V) {
        self.0.borrow_mut().insert(key, value);
    }
}

/// The longest request text a read takes as one: a URL or a path and
/// query past this many bytes is a length word that did not read as
/// the text's.
const MAX_REQUEST_TEXT: u64 = 64 * 1024;

/// A request's text: the `len` bytes at `ptr`, where they decode as
/// UTF-8. An empty text is a fact; a text past any sane request line
/// is a word that did not read as one.
pub(crate) fn read_request_text<T: proc::Target>(proc: &T, ptr: u64, len: u64) -> Option<String> {
    if len > MAX_REQUEST_TEXT {
        return None;
    }
    if len == 0 {
        return Some(String::new());
    }
    let bytes = proc.read_bytes(ptr, len).ok()?;
    String::from_utf8(bytes.to_vec()).ok()
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
    /// Whether a frame of the type can hold a request-bound local at
    /// all — any member of it, or of any state of it, binds one — so
    /// the chain scan lists locals only for the few types that can.
    request_holders: Memo<BundleTypeId, bool>,
    /// Memoized address of tokio's task `WAKER_VTABLE` static in the
    /// target, including a cached diagnostic when resolution is ambiguous.
    waker_vtable: RefCell<Option<std::result::Result<Vec<u64>, String>>>,
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
    /// Which release each of the target's crate hashes is, for a crate
    /// the target links at several releases (see [`super::pairing`]).
    /// Read on the first join that needs it: a target linking every
    /// crate once never does.
    pairing: std::cell::OnceCell<super::pairing::Pairing>,
    /// The candidate the pairing picks, per symbol: every in-flight
    /// request of a target meets the same few ambiguous joins.
    paired: Memo<String, Option<BundleTypeId>>,
    /// The tasks a `Notify`'s wait list names, per `Notify`: the
    /// reference scan meets the same few `Notify`s — a cancellation
    /// token's, with thousands of waiters — from thousands of tasks,
    /// and walks each list once for the target rather than once per
    /// task.
    notify_waiters: Memo<ValueKey, Vec<u64>>,
    /// Whether a value of the type can hold anything the reference scan
    /// reports ([`Context::reference_inert`]): the scan meets the same
    /// few hundred types in every in-flight request of a target, and
    /// decides each once.
    reference_inert: Memo<BundleTypeId, bool>,
    semantics: SemanticIndex,
    /// Records standing in for the bundle's own, for a test over a
    /// shape the production binders decline; empty outside the tests
    /// ([`Context::with_test_bindings`]).
    test_bindings: &'b [TypeSemantics],
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
            request_holders: Memo::default(),
            object_symbols: RefCell::new(None),
            vtables: RefCell::new(HashMap::default()),
            waker_vtable: RefCell::new(None),
            stopped: RefCell::new(None),
            task_lookups: Memo::default(),
            dyn_future_lookups: Memo::default(),
            pairing: std::cell::OnceCell::new(),
            paired: Memo::default(),
            notify_waiters: Memo::default(),
            reference_inert: Memo::default(),
            semantics,
            test_bindings: &[],
            contract,
        })
    }

    /// Attach with explicit continuation bindings, for a test over a
    /// hand-written shape the production binders decline: each record
    /// in `bindings` stands in for the bundle's own record of its type,
    /// and `rules` are appended to the bundle's rule table for the
    /// bindings to name. The bindings are validated the way the
    /// bundle's own are — paths, endpoints, state guards, rule kinds,
    /// evidence closure — over a copy of the bundle carrying them, and
    /// never reach the wire or a production context. `bindings` lives
    /// as long as the context, so the routes the chain borrows do.
    #[cfg(feature = "testkit")]
    pub fn with_test_bindings(
        proc: &'b T,
        view: BundleView<'b>,
        bindings: &'b [TypeSemantics],
        rules: &[hansei_bundle::SemanticRule],
    ) -> Result<Self> {
        let mut checked = view.bundle().clone();
        checked.semantics.rules.extend(rules.iter().cloned());
        for binding in bindings {
            match checked
                .semantics
                .types
                .binary_search_by_key(&binding.ty, |record| record.ty)
            {
                Ok(i) => checked.semantics.types[i] = binding.clone(),
                Err(i) => checked.semantics.types.insert(i, binding.clone()),
            }
        }
        checked
            .validate()
            .context("the test bindings do not validate")?;
        let mut ctx = Self::new(proc, view)?;
        ctx.test_bindings = bindings;
        Ok(ctx)
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
    /// The semantic index and the test bindings, for a walk that runs
    /// apart from this context's thread (the slot attribution).
    pub(super) fn semantic_parts(&self) -> (&SemanticIndex, &'b [TypeSemantics]) {
        (&self.semantics, self.test_bindings)
    }

    pub fn type_semantics(&self, ty: BundleTypeId) -> Option<&'b TypeSemantics> {
        if let Some(binding) = self.test_bindings.iter().find(|record| record.ty == ty) {
            return Some(binding);
        }
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
    pub(crate) fn stopped_at(&self) -> Option<RawInstant> {
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
    pub(crate) fn infra_ty(&self, id: BundleTypeId, what: &str) -> Result<BundleType<'b>> {
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
    pub(crate) fn symbol_at(&self, addr: u64) -> Option<String> {
        self.symbols.get_or(&addr, || {
            self.proc.lookup_symbol_by_addr(addr).map(|s| s.name)
        })
    }

    /// [`BundleView::task_ids_for_symbol`], answered from
    /// [`Context::task_lookups`] when the symbol has been asked before.
    pub(crate) fn task_ids_memoized(&self, symbol: &str) -> SymbolLookup<TaskEntryId> {
        self.task_lookups
            .get_or(symbol, || self.view.task_ids_for_symbol(symbol))
    }

    /// [`BundleView::dyn_future_ids_for_symbol`], answered from
    /// [`Context::dyn_future_lookups`] when the symbol has been asked
    /// before.
    pub(crate) fn dyn_future_ids_memoized(&self, symbol: &str) -> SymbolLookup<BundleTypeId> {
        self.dyn_future_lookups
            .get_or(symbol, || self.view.dyn_future_ids_for_symbol(symbol))
    }

    /// Of a join's `candidates`, the one of the release the target's
    /// crate hashes in `symbol` were paired with (see
    /// [`super::pairing::select`]). The candidates are what `symbol`
    /// resolves to, so the symbol alone keys the memo.
    pub(crate) fn paired_candidate(
        &self,
        symbol: &str,
        candidates: &[BundleTypeId],
    ) -> Option<BundleTypeId> {
        self.paired.get_or(symbol, || {
            let pairing = self.pairing.get_or_init(|| {
                super::pairing::pair(self.view.bundle(), self.proc, &self.mappings)
            });
            super::pairing::select(self.view.bundle(), pairing, symbol, candidates)
        })
    }

    /// Stand a known pairing in for the one the target's vtables would
    /// give, for a test over a fixture that links every crate once.
    #[cfg(test)]
    pub(crate) fn with_pairing(self, pairing: super::pairing::Pairing) -> Self {
        let _ = self.pairing.set(pairing);
        self
    }

    /// Every target address a named static resolves to: the exact name's
    /// alone when the symtab has it, else every distinct address the
    /// normalized v0 key's candidates sit at, sorted — for a join that
    /// accepts any copy of the static.
    fn object_symbol_addrs(&self, name: &str) -> Result<Vec<u64>> {
        if let Some(symbol) = self.proc.lookup_symbol_by_name(name) {
            return Ok(vec![symbol.st_value]);
        }
        let Some(key) = normalized_v0_key(name) else {
            return Ok(Vec::new());
        };
        self.index_object_symbols()?;
        let symbols = self.object_symbols.borrow();
        let mut addrs: Vec<u64> = symbols
            .as_ref()
            .unwrap()
            .get(&key)
            .into_iter()
            .flatten()
            .map(|symbol| symbol.st_value)
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        Ok(addrs)
    }

    /// Build the normalized-key index over the target's object symbols,
    /// once.
    fn index_object_symbols(&self) -> Result<()> {
        if self.object_symbols.borrow().is_none() {
            let mut index: HashMap<String, Vec<SymbolBuf>> = HashMap::default();
            for symbol in self.proc.object_symbols()? {
                if let Some(key) = normalized_v0_key(&symbol.name) {
                    index.entry(key).or_default().push(symbol);
                }
            }
            *self.object_symbols.borrow_mut() = Some(index);
        }
        Ok(())
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
                    owned_id: self.owned_list_id(handle)?,
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

    /// The id the global owned-list counter gave a runtime's list, from
    /// its handle: what every task it owns carries as `Header.owner_id`,
    /// and what a claim that this runtime owns a task is held to.
    /// `None` where the row did not bind against this target.
    fn owned_list_id(&self, handle: Value<'b>) -> Result<Option<u64>> {
        let shared = self.walk(WalkRole::HandleShared).walk_at(handle)?;
        self.walk(WalkRole::SchedulerOwnedId).try_read(shared)
    }

    /// Every discovered runtime's tasks, merged into one list with the
    /// per-runtime enumeration's own ordering applied across the whole.
    /// Each task's record names the runtime whose list links it, so a
    /// listing over the merge can still say which is whose.
    pub fn enumerate_all_tasks(&self, runtimes: &[RuntimeRef<'b>]) -> Result<TaskList> {
        let mut all = TaskList::default();
        for runtime in runtimes {
            let shared = self.find_shared(runtime)?;
            self.enumerate_owned(shared, runtime.owner_key(), runtime.owned_id, &mut all)?;
        }
        all.reproject(&[]);
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

    /// Walk `Shared.owned`'s sharded intrusive lists and file every task
    /// as one `owner`'s list links: a source for each and — where the
    /// list's id `owned_id` is known and is the task's own
    /// `Header.owner_id` — a validated owner claim. A list whose id did
    /// not bind links its members with no owner established, and says
    /// so once.
    ///
    /// Corrupt memory degrades per shard: the failing shard contributes an
    /// error, the rest of the listing is unaffected.
    fn enumerate_owned(
        &self,
        shared: Value<'b>,
        owner: OwnerKey,
        owned_id: Option<u64>,
        list: &mut TaskList,
    ) -> Result<()> {
        let lists = self.walk(WalkRole::OwnedLists).walk_at(shared)?;
        if owned_id.is_none() {
            list.errors.push(anyhow!(
                "the owned list of {owner} records no id this tokio info can read; \
                 the tasks it links are listed with no owner established"
            ));
        }

        // Guards against cycles from corrupt memory, across shards: the
        // same Header must never appear twice in one list walk. A
        // Header met again through another route is that route's
        // business, and the store's to reconcile.
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
                owner,
                owned_id,
                &mut visited,
                list,
                &format!("shard {this_shard}"),
            );
        }
        Ok(())
    }

    /// Walk one intrusive owned-task list from its head, filing every
    /// parsed task as `owner`'s. Corrupt memory degrades per list: the
    /// failing node contributes an error under `what`'s name, the rest
    /// of the caller's enumeration is unaffected. The caller owns the
    /// cycle guard, so lists that (corruptly) share a node are caught
    /// across calls.
    fn walk_owned_list(
        &self,
        head_addr: u64,
        owner: OwnerKey,
        owned_id: Option<u64>,
        visited: &mut HashSet<u64>,
        list: &mut TaskList,
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
                self.observe_listed(header, owner, head_addr, owned_id, list);
                Ok(next)
            })();
            match step {
                Ok(next) => cur = next,
                Err(e) => {
                    list.errors
                        .push(e.context(format!("task walk failed in {what} at {addr:#x}")));
                    break;
                }
            }
        }
    }

    /// File a task an owner's list links. The list is its source and
    /// — where the list's id is the task's `owner_id` — its owner. A
    /// task carrying some other id is linked here all the same, since
    /// the list is the ground truth for membership, but the owner it
    /// names is not established, and the mismatch is kept.
    fn observe_listed(
        &self,
        header: DecodedTaskHeader,
        owner: OwnerKey,
        head: u64,
        owned_id: Option<u64>,
        list: &mut TaskList,
    ) {
        let (claim, mismatch) = list_claim(owner, head, owned_id, &header);
        let kind = self.header_kind(&header);
        let effect = list.records.observe(
            header,
            Observation {
                source: TaskSource::OwnedList { owner, head },
                kind,
                claim,
            },
        );
        if let Some(mismatch) = mismatch {
            list.records.issue(effect.record, mismatch);
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
        let mut ambiguous: Option<(String, Vec<BundleTypeId>)> = None;
        for addr in candidates.into_iter().flatten() {
            let Some(symbol) = self.symbol_at(addr) else {
                continue;
            };
            let entry_id = match self.task_ids_memoized(&symbol) {
                SymbolLookup::Unique(id) => id,
                SymbolLookup::Ambiguous(ids) => {
                    let futures = ids
                        .into_iter()
                        .filter_map(|id| self.view.bundle().tasks.entries.get(id.0 as usize))
                        .map(|entry| entry.future)
                        .collect();
                    ambiguous.get_or_insert((symbol, futures));
                    continue;
                }
                SymbolLookup::Missing => continue,
            };
            let entry = &self.view.bundle().tasks.entries[entry_id.0 as usize];
            let provenance = self.view.provenance(entry_id);
            let decl = provenance
                .and_then(|p| p.decl)
                .and_then(|loc| Some((self.view.str(loc.file)?.to_owned(), loc.line)));
            let kind = provenance.map(|p| p.kind).unwrap_or(FutureKind::Manual);
            return FutureInfo::Known(KnownFuture {
                entry: entry_id,
                future: entry.future,
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
            known.name(self.view),
            trailer_offset,
            vt.trailer_offset
        );
        if let Some(id_offset) = self.walk(WalkRole::CellTaskId).member_offset(cell) {
            ensure!(
                id_offset == vt.id_offset,
                "tokio-info/target layout mismatch for {}: recorded Core.task_id at {:#x}, \
                 target vtable id_offset {:#x}",
                known.name(self.view),
                id_offset,
                vt.id_offset
            );
        }
        Ok(())
    }

    pub(crate) fn task_entry(&self, id: TaskEntryId) -> &'b TaskFutureEntry {
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
        Ok(self.trailer_waker_slot(task)?.0)
    }

    /// [`Context::trailer_waker`], with the address of the pair it
    /// decoded — the slot the waker sweep must find again.
    pub fn trailer_waker_slot(&self, task: &Task) -> Result<(QueuedWaker, Option<u64>)> {
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
            return Ok((QueuedWaker::Unarmed, None));
        };
        Ok((self.raw_waker(raw)?, Some(raw.addr)))
    }

    // -----------------------------------------------------------------------
    // Task tracing
    // -----------------------------------------------------------------------

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

    /// Whether a type is a supported owned pointer adapter that is not
    /// itself a future: a `Box<F>` over a future that is not `Unpin`,
    /// the `Box<dyn Future>` inside a pinned one. Its access binding
    /// records the route to what it holds ([`Context::access_referent`]).
    pub(crate) fn owned_adapter(&self, id: BundleTypeId) -> bool {
        self.type_semantics(id).is_some_and(|record| {
            record.future.is_none()
                && record.resource.is_none()
                && record
                    .access
                    .as_ref()
                    .is_some_and(|access| access.kind == AccessKind::Owned)
        })
    }

    /// Whether a type is a supported pointer adapter of either kind that
    /// is not itself a future — the owned ones above, and a `&mut F`
    /// borrowing a future kept elsewhere. What a frame *polls* through
    /// a borrow is still its branch, which is why the wait set follows
    /// both where the census follows only what a frame owns.
    pub(crate) fn any_adapter(&self, id: BundleTypeId) -> bool {
        self.type_semantics(id).is_some_and(|record| {
            record.future.is_none() && record.resource.is_none() && record.access.is_some()
        })
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

    /// The hash table a type keeps, where the bundle binds one whose
    /// buckets could hold something a scan reports: a table of plain
    /// data is not worth walking for what it cannot hold.
    pub(crate) fn scanned_table(&self, id: BundleTypeId) -> Option<&'b HashTableBinding> {
        let table = self.type_semantics(id)?.table.as_ref()?;
        let bucket = self.view.ty(table.bucket)?;
        (!self.reference_inert(bucket)).then_some(table)
    }

    /// Whether no value of `ty` can hold anything the reference scan
    /// reports: nothing in its inline storage — its members, every
    /// variant's payload — is a bound resource, container, pointer
    /// adapter, future or coroutine, storage the bundle declares
    /// unreadable, or an array of aggregates, and no hash table it
    /// keeps has buckets that could hold one. A pointer no adapter is
    /// bound for is a word the scan never follows, so it ends the
    /// question there. A fact of the type, remembered per type.
    ///
    /// A table's buckets live on the heap, so a type can reach itself
    /// through its own map (a trie's node keeping its children in a
    /// `HashMap<_, Node>`): the question is asked of every type the
    /// storage reaches, each once. A type met again adds nothing, and
    /// where the answer is yes it is yes for every type the walk met,
    /// which reach no further than the first.
    pub(crate) fn reference_inert(&self, ty: BundleType<'b>) -> bool {
        if let Some(known) = self.reference_inert.get(&ty.id()) {
            return known;
        }
        let mut seen = HashSet::default();
        let mut stack = vec![ty];
        let mut inert = true;
        while let Some(ty) = stack.pop() {
            if !seen.insert(ty.id()) {
                continue;
            }
            match self.reference_inert.get(&ty.id()) {
                Some(true) => continue,
                Some(false) => {
                    inert = false;
                    break;
                }
                None => {}
            }
            let record = self.type_semantics(ty.id());
            if record.is_some_and(|record| {
                record.resource.is_some()
                    || record.container.is_some()
                    || record.access.is_some()
                    || record.future.is_some()
                    || record.coroutine.is_some()
                    || matches!(record.storage, StoragePolicy::Unavailable(_))
            }) {
                inert = false;
                break;
            }
            if let Some(table) = record.and_then(|record| record.table.as_ref())
                && let Some(bucket) = self.view.ty(table.bucket)
            {
                stack.push(bucket);
            }
            match ty.classify() {
                TypeClass::Struct => stack.extend(
                    ty.members()
                        .map(|member| member.ty())
                        .filter(|member| member.size() != 0),
                ),
                TypeClass::RustEnum => stack.extend(ty.variants().map(|variant| variant.ty)),
                TypeClass::Array { element, .. } => {
                    if super::scan::holds_aggregates(element) {
                        inert = false;
                        break;
                    }
                }
                TypeClass::Union
                | TypeClass::Pointer { .. }
                | TypeClass::Integer { .. }
                | TypeClass::Float { .. }
                | TypeClass::CEnum
                | TypeClass::Opaque => {}
            }
        }
        if inert {
            for id in seen {
                self.reference_inert.insert(id, true);
            }
        } else {
            self.reference_inert.insert(ty.id(), false);
        }
        inert
    }

    /// The member a fan-out container keeps its entries in, as the
    /// bound route names it — what an entry of a map that is itself
    /// a chain frame is listed as held in. Asked only of a bundle that
    /// bound a fan-out container, and the validator holds every such
    /// binding to that route being bound at the container, so the
    /// route and its first member step are there by construction.
    pub(crate) fn fanout_storage_name(&self) -> &'b str {
        self.view
            .bundle()
            .walks
            .entries
            .get(&WalkRole::StreamMapEntries)
            .and_then(|binding| match binding.steps.first() {
                Some(Step::Member(MemberRef::Named(name))) => self.view.str(*name),
                _ => None,
            })
            .expect("a fan-out container's entries route is bound at it")
    }

    /// The `select!` branches a type polls, where the bundle bound it
    /// as the `PollFn` of a reviewed expansion.
    pub(crate) fn select_binding(&self, id: BundleTypeId) -> Option<&'b SelectBinding> {
        self.type_semantics(id)?.select.as_ref()
    }

    // -----------------------------------------------------------------------
    // The leaf-future knowledge base
    // -----------------------------------------------------------------------

    /// The fd of the io resource registered as `scheduled_io`, where a
    /// known resource type held in `frames` owns that registration —
    /// the `ScheduledIo` itself records no fd, so only a resource in
    /// the frames can name one. Enrichment only: every miss — no such
    /// member, an unreadable pointee, a walk the bundle did not bind —
    /// is a silent `None`, and the io row spells the address instead.
    pub fn io_resource_fd(&self, frames: &[Value<'b>], scheduled_io: u64) -> Option<i32> {
        let resource_of = |ty: BundleType<'b>| {
            IO_RESOURCES
                .iter()
                .find(|(shared, _)| self.view.walk_roots(*shared).contains(&ty.id()))
        };
        for value in self.frame_members(frames, &|ty| resource_of(ty).is_some()) {
            let Some(&(shared, fd)) = resource_of(value.ty) else {
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
        None
    }

    /// The watch channel whose receivers queue on the `Notify` at
    /// `notify`, where a `watch::Receiver` held in `frames` — by value,
    /// or by reference as `changed`'s `self` — points at its `Shared`:
    /// the `Shared`'s address and the words that describe the channel.
    /// Enrichment only, like the fd join: nothing is dereferenced but
    /// the `Shared` a receiver in the frames already names, and every
    /// miss is a silent `None`.
    pub fn watch_target(&self, frames: &[Value<'b>], notify: u64) -> Option<WaitTarget> {
        let receivers = self.view.walk_roots(WalkRole::WatchReceiverShared);
        let is_receiver = |ty: BundleType<'b>| receivers.contains(&ty.id());
        for receiver in self.frame_members(frames, &is_receiver) {
            let Ok(Some(Walked::At(ptr))) =
                self.walk(WalkRole::WatchReceiverShared).try_walk(receiver)
            else {
                continue;
            };
            let Some(arc_ty) = ptr.ty.pointer_target() else {
                continue;
            };
            let Ok(addr) = ptr.parse::<u64>(self.proc) else {
                continue;
            };
            if !self.mappings.contains_addr(addr) {
                continue;
            }
            let Ok(arc) = Value::read(self.proc, arc_ty, addr) else {
                continue;
            };
            if let Some(target) = self.watch_shared_target(arc, notify) {
                return Some(target);
            }
        }
        // `changed`'s own frame keeps nothing past its await; the
        // `changed_impl` below it holds `&Shared<T>`. The `ArcInner`
        // around that `Shared` is a type the shared-state roles root
        // at — the one whose `data` is this `Shared`'s type — and the
        // `Shared` sits at `data`'s offset into it.
        let arcs: Vec<(BundleType<'b>, BundleMember<'b>)> = self
            .view
            .walk_roots(WalkRole::WatchSharedState)
            .iter()
            .filter_map(|&root| {
                let arc_ty = self.view.ty(root)?;
                Some((arc_ty, arc_ty.member("data")?))
            })
            .collect();
        let is_shared = |ty: BundleType<'b>| arcs.iter().any(|(_, data)| data.ty().id() == ty.id());
        for shared in self.frame_members(frames, &is_shared) {
            for &(arc_ty, data) in &arcs {
                if data.ty().id() != shared.ty.id() {
                    continue;
                }
                let Some(addr) = shared.addr.checked_sub(data.offset()) else {
                    continue;
                };
                if let Ok(arc) = Value::read(self.proc, arc_ty, addr)
                    && let Some(target) = self.watch_shared_target(arc, notify)
                {
                    return Some(target);
                }
            }
        }
        None
    }

    /// The watch channel behind `arc`, an `ArcInner<watch::Shared<T>>`
    /// value, as a wait target — when the `Notify` at `notify` is one
    /// of its `notify_rx` array. Reads the state word and both handle
    /// counts from the value.
    pub fn watch_shared_target(&self, arc: Value<'b>, notify: u64) -> Option<WaitTarget> {
        let at = |role: WalkRole| match self.walk(role).try_walk(arc) {
            Ok(Some(Walked::At(value))) => Some(value),
            _ => None,
        };
        let word = |role: WalkRole| self.walk(role).try_read::<u64>(arc).ok().flatten();
        let words = watch_words_of(arc, notify, &at, &word)?;
        Some(WaitTarget::Watch {
            addr: words.addr,
            version: words.version,
            closed: words.closed,
            receivers: words.receivers,
            senders: words.senders,
        })
    }

    /// The values of the accepted types held in `frames`: each member
    /// whose type `accept`s, or — for a reference member (`&mut
    /// UnixStream` in a `Read` future, `&mut Receiver` in `changed`) —
    /// whose pointee does, read from the target.
    fn frame_members(
        &self,
        frames: &[Value<'b>],
        accept: &dyn Fn(BundleType<'b>) -> bool,
    ) -> Vec<Value<'b>> {
        let mut values = Vec::new();
        for frame in frames {
            for member in frame.ty.members() {
                if member.ty().size() == 0 {
                    continue;
                }
                let start = member.offset() as usize;
                let end = start + member.ty().size() as usize;
                let Some(bytes) = frame.bytes.get(start..end) else {
                    continue;
                };
                let value = Value::new(member.ty(), frame.addr + member.offset(), bytes);
                if accept(value.ty) {
                    values.push(value);
                } else if let Some(target) = value.ty.pointer_target()
                    && accept(target)
                    && let Ok(ptr) = value.parse::<u64>(self.proc)
                    && self.mappings.contains_addr(ptr)
                    && let Ok(pointee) = Value::read(self.proc, target, ptr)
                {
                    values.push(pointee);
                }
            }
        }
        values
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
        Ok(Some(self.timespec(deadline, read)?))
    }

    /// A std `Timespec` — the inside of every `Instant` tokio keeps —
    /// as a raw instant, through the two word readers `Sleep.deadline`
    /// declares: the same type wherever an instant is met.
    fn timespec(&self, timespec: Value<'b>, read: &ReadContext<'_>) -> Result<RawInstant> {
        let tv_sec: i64 = self
            .walk(WalkRole::DeadlineTvSec)
            .read_with(read, timespec)?;
        let tv_nsec: u32 = self
            .walk(WalkRole::DeadlineTvNsec)
            .read_with(read, timespec)?;
        Ok(RawInstant {
            tv_sec: tv_sec as u64,
            tv_nsec,
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

    /// One wait-queue node as a listing carries it: the permits it
    /// still needs and the waker it holds.
    fn queue_node(&self, node: Value<'b>, read: &ReadContext<'_>) -> Result<SemaphoreWaiter> {
        let (waker, waker_at) = self.read_queued_waker(node, read)?;
        Ok(SemaphoreWaiter {
            addr: node.addr,
            needed: self.walk(WalkRole::WaiterNeeded).read_with(read, node)?,
            waker,
            waker_at,
        })
    }

    /// Decode the waker registered in a wait-queue node, and where the
    /// pair sits. Waiters keep theirs in an `UnsafeCell<Option<Waker>>`,
    /// whose `Some` payload peels through the `Waker` to the `RawWaker`
    /// pair.
    fn read_queued_waker(
        &self,
        node: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<(QueuedWaker, Option<u64>)> {
        let Some(raw) = self
            .walk(WalkRole::WaiterWaker)
            .walk_with(read, node)?
            .optional()
        else {
            return Ok((QueuedWaker::Unarmed, None));
        };
        Ok((self.raw_waker(raw)?, Some(raw.addr)))
    }

    /// Decode one `RawWaker`, wherever it was registered — a semaphore's
    /// wait queue, a timer entry's `AtomicWaker`. The two halves are read
    /// through the same recorded steps in either case, since the landing
    /// type is the same `RawWaker`.
    pub(crate) fn raw_waker(&self, raw: Value<'b>) -> Result<QueuedWaker> {
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
        if !self.task_waker_vtables()?.contains(&vtable) {
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

    /// Every target address of tokio's task `WAKER_VTABLE` static,
    /// resolved once through the target's symtab and sorted. The static
    /// may exist only as `.llvm.<hash>`-suffixed internalized copies,
    /// like any other join symbol, and a build may carry several; a
    /// task waker's vtable word is any one of them. Empty where the
    /// symtab names none.
    pub fn task_waker_vtables(&self) -> Result<Vec<u64>> {
        if let Some(cached) = self.waker_vtable.borrow().as_ref() {
            return cached.clone().map_err(anyhow::Error::msg);
        }
        let resolved: std::result::Result<Vec<u64>, String> = (|| {
            let def = self
                .view
                .bundle()
                .statics
                .entries
                .get(&StaticRole::TaskWakerVtable)
                .ok_or_else(|| "the tokio info records no task WAKER_VTABLE static".to_owned())?;
            self.object_symbol_addrs(&def.symbol)
                .map_err(|error| format!("{error:#}"))
        })();
        *self.waker_vtable.borrow_mut() = Some(resolved.clone());
        resolved.map_err(anyhow::Error::msg)
    }

    // -----------------------------------------------------------------------
    // Local-set discovery
    // -----------------------------------------------------------------------

    /// The class the tokio info recorded for a task entry's scheduler
    /// `S` — bound at extraction against the reviewed scheduler
    /// layouts, never read off a type name here. `None` is a scheduler
    /// the extraction did not classify, which selects nothing.
    pub(crate) fn scheduler_class(&self, entry: &TaskFutureEntry) -> Option<SchedulerClass> {
        entry
            .scheduler_binding
            .as_ref()
            .map(|binding| binding.class)
    }

    /// The class of a decoded header's cell, through the vtable join:
    /// `None` when the future is unknown or ambiguous, never a guess.
    fn header_class(&self, header: &DecodedTaskHeader) -> Option<SchedulerClass> {
        let FutureInfo::Known(known) = &header.future else {
            return None;
        };
        self.scheduler_class(self.task_entry(known.entry))
    }

    /// The kind of task a decoded header heads, by its cell's recorded
    /// scheduler class — type-level evidence, which no owner needs to
    /// validate.
    pub(crate) fn header_kind(&self, header: &DecodedTaskHeader) -> Option<TaskKind> {
        self.header_class(header).map(|class| match class {
            SchedulerClass::Blocking => TaskKind::Blocking,
            SchedulerClass::MultiThread
            | SchedulerClass::CurrentThread
            | SchedulerClass::LocalSet => TaskKind::Async,
        })
    }

    /// [`Context::scheduler_class`] for a bare unlisted Header, as
    /// [`UnlistedTaskKind`] words it. `None` when the join cannot
    /// resolve the future, the class is unclassified, or a read on the
    /// way fails — the classification is extra information, never
    /// worth an error.
    pub(crate) fn header_unlisted_kind(&self, addr: u64) -> Option<UnlistedTaskKind> {
        let identity = self.header_identity(addr, &ReadContext::none()).ok()?;
        let FutureInfo::Known(known) = self.resolve_future(&identity.vtable) else {
            return None;
        };
        match self.scheduler_class(self.task_entry(known.entry))? {
            SchedulerClass::LocalSet => Some(UnlistedTaskKind::LocalSet),
            SchedulerClass::Blocking => Some(UnlistedTaskKind::Blocking),
            SchedulerClass::MultiThread => {
                Some(UnlistedTaskKind::OtherRuntime(RuntimeFlavor::MultiThread))
            }
            SchedulerClass::CurrentThread => {
                Some(UnlistedTaskKind::OtherRuntime(RuntimeFlavor::CurrentThread))
            }
        }
    }

    /// Deterministic discovery of the task lists no thread's `Context`
    /// reaches — `LocalSet`s, and runtimes nothing is currently inside
    /// — and enumeration of everything they own into `list`.
    ///
    /// Route 3 reads each LWP's `task::local::CURRENT` anchor —
    /// populated only while a thread is mid-poll of a set. Route 1
    /// takes every task-shaped pointer in the enumerated tasks'
    /// storage — a `JoinHandle`'s target, a task waker queued on a
    /// semaphore or parked on an io registration the task holds, a
    /// `JoinSet` entry — and files it as a reference to the task it
    /// names; a task no list claims is then followed home through
    /// its cell's recorded scheduler, which says what owns it: an
    /// `Arc<task::local::Shared>` is a set's, an `Arc` of either
    /// flavor `Handle` a runtime's, and either way the list must claim
    /// the task that led there (its own id equal to the task's
    /// `Header.owner_id`) before the record credits it. Its input is
    /// the reference scan over each task's initialized storage
    /// ([`Context::scan_references`], under `read`'s allocator
    /// evidence), which finds a reference wherever it sits — a held
    /// handle as much as an awaited one, behind the adapters whose
    /// routes the bundle records — without diagnosing what the holder
    /// waits on. Route 2 harvests the discovered runtimes' registries
    /// of parked tasks — the timer wheel, then the io driver's
    /// registrations — which hold a task's waker whatever list owns
    /// it, and so are the only route that reaches a set no enumerated
    /// task points at; and then each runtime's blocking-pool queue,
    /// whose entries are the `spawn_blocking` cells no list carries.
    /// Every route converges on the owner's address and dedups there.
    ///
    /// Each admitted list is then walked like one more shard and merged
    /// — and scanned in turn, since what it owns can point at the next
    /// hidden list, and a runtime it admits brings its own drivers to
    /// harvest. The routes run as one queue of work
    /// ([`sweep`](super::work::sweep)): each admitted owner is
    /// enumerated and harvested once, each resident record scanned
    /// once, each find validated once, under an explicit item cap whose
    /// frontier is reported rather than dropped.
    ///
    /// Every route contributes what it observed to `list.records`,
    /// one record per header ([`TaskStore::observe`]): a source, kind
    /// evidence, and the owner claim it validated, if any. Which
    /// route met a task first decides nothing about its row — a
    /// blocking cell met through a handle and then through its queue
    /// reads exactly as one met the other way round — and what the
    /// routes disagreed on stays a diagnostic in `list.errors`. The
    /// rows are rebuilt from the records when the sweep ends.
    ///
    /// `runtimes` grows with what discovery finds; `excluded` names the
    /// handles it must leave alone, which is how a `--runtime`
    /// selection keeps meaning what it says: an excluded runtime's
    /// population is never walked, and a task its list claims is not a
    /// row of the selection. Failures degrade per candidate into
    /// `list.errors`; the returned sets are in admission order.
    ///
    /// [`TaskStore::observe`]: super::discovery::TaskStore::observe
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
                    if sets.iter().any(|set| set.shared.addr == shared.addr) {
                        continue;
                    }
                    match self.read_local_set(shared, Some(tid), DiscoveryRoute::Tls, &thread_ids) {
                        Ok(set) => sets.push(set),
                        Err(e) => list.errors.push(e),
                    }
                }
            }
            Err(e) => list
                .errors
                .push(e.context("the local-set TLS probe failed")),
        }

        // Routes 1 and 2, to a fixed point: one queue of finite work
        // (`work::sweep`), seeded with the root runtimes' registries and
        // the TLS sets' lists, fed by what each item finds. What each
        // item does to the target is `Live`'s; the order the kinds run
        // in is the queue's; the cap and the frontier report are its.
        let roots = Roots {
            runtimes: runtimes.iter().map(RuntimeRef::owner_key).collect(),
            sets: sets.iter().map(LocalSetRef::owner_key).collect(),
        };
        let outcome = {
            let mut live = Live {
                ctx: self,
                runtimes,
                sets: &mut sets,
                registries: &mut registries,
                thread_ids: &thread_ids,
                excluded,
                read,
                wheel_visited: HashSet::default(),
                io_visited: HashSet::default(),
            };
            sweep(&mut live, list, &roots, excluded, limits)
        };
        // An owner reached only through a task an excluded runtime owns
        // is not in the selection: its rows are already out of scope,
        // and it is not a group either. Its records keep what they
        // established.
        let dropped: Vec<OwnerKey> = runtimes
            .iter()
            .map(RuntimeRef::owner_key)
            .chain(sets.iter().map(LocalSetRef::owner_key))
            .filter(|key| !outcome.reached.contains(key))
            .collect();
        runtimes.retain(|r| outcome.reached.contains(&r.owner_key()));
        sets.retain(|s| outcome.reached.contains(&s.owner_key()));
        list.reproject(excluded);
        // What the routes disagreed on, beside the rows: every standing
        // diagnostic of every record, in record order.
        let issues: Vec<String> = list.records.issues().map(ToString::to_string).collect();
        list.errors
            .extend(issues.into_iter().map(|issue| anyhow!(issue)));
        for owner in dropped {
            list.errors.push(anyhow!(
                "{owner} was reached only through tasks of an excluded runtime; \
                 its tasks are not rows of this selection"
            ));
        }
        // A spent budget is reported, never absorbed: the caps are
        // there to bound a corrupt or pathological target, and a
        // healthy one that reaches them is a fact to raise the cap on.
        let budget = &outcome.budget;
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
        if outcome.capped {
            list.errors.push(anyhow!(
                "discovery stopped at its cap of {} work items with {} left; \
                 the population past that is not listed",
                limits.max_work_items,
                outcome.remaining
            ));
        }
        (sets, registries)
    }

    /// Route 1's input: every reference the scan finds in the storage
    /// of the records `ids` name, each of which is marked scanned
    /// whatever the scan made of it. Scan issues are not reported here
    /// — a stop the scan cannot get past is a bounded loss of this
    /// input, and the registry harvests still run — but the run-wide
    /// budget is `budget`'s, and its exhaustion is the sweep's to
    /// report.
    fn scan_records(
        &self,
        ids: &[TaskRecordId],
        list: &mut TaskList,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
    ) -> Vec<Candidate> {
        /// The sink feeding the candidate queue: every reference, with
        /// the storage that held it as its route. Nothing else the
        /// scan reports is kept.
        struct Candidates(Vec<Candidate>);

        impl ReferenceSink for Candidates {
            fn reference(
                &mut self,
                target: TaskAddr,
                source: ReferenceSource,
                source_value: Option<ValueKey>,
                root_task: Option<TaskAddr>,
                path: &[hansei_bundle::Step],
            ) {
                self.0.push(Candidate::Reference {
                    reference: TaskReference {
                        target,
                        source,
                        source_value,
                        root_task,
                        path: path.to_vec(),
                    },
                    route: DiscoveryRoute::Scanned(source),
                });
            }

            fn issue(&mut self, _: WalkIssue) {}
        }

        let mut sink = Candidates(Vec::new());
        for &id in ids {
            list.records.mark_scanned(id);
            let task = list.records.record(id).task();
            let Ok(TaskStage::Running(future)) = self.task_root(&task, read) else {
                continue;
            };
            let _ = self.scan_references(future, task.addr, read, budget, &mut sink);
        }
        sink.0
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

    /// A type's name as the bundle records it, for a message: `<anon>`
    /// for one the bundle does not carry.
    pub fn type_name(&self, ty: BundleTypeId) -> &'b str {
        self.view.ty(ty).map_or("<anon>", |ty| ty.name())
    }

    /// The first recorded root type of a bound role — how a probe that
    /// constructs its own root value (a TLS payload) knows the layout
    /// to read it with.
    pub(crate) fn walk_root_ty(&self, role: WalkRole) -> Option<BundleType<'b>> {
        let binding = self.view.bundle().walks.entries.get(&role)?;
        if !matches!(binding.outcome, WalkOutcome::Bound { .. }) {
            return None;
        }
        self.view.ty(*binding.roots.first()?)
    }

    /// Route 2: every task-Header pointer armed on a timer entry parked
    /// in `runtimes`' own wheels, as a reference from the entry.
    ///
    /// The wheel is a registry of parked tasks whatever list owns them:
    /// every `tokio::time::Sleep` registers its `TimerShared` into it
    /// and arms the entry's `AtomicWaker` with the task's own waker, so
    /// a `LocalSet` member sleeping in a set nothing else points at is
    /// visible here and nowhere else. What identifies a waker as a
    /// task's is the same address-equality join on tokio's
    /// `WAKER_VTABLE` static that the wait-queue readers make; a waker
    /// that is not a task's is simply not a candidate.
    ///
    /// Failures degrade at the finest grain the walk allows: a runtime
    /// whose wheel cannot be reached costs its own wheel, a corrupt
    /// slot list costs the rest of that list, and everything else is
    /// still harvested.
    fn wheel_task_pointers(
        &self,
        runtimes: &[RuntimeRef<'b>],
        visited: &mut HashSet<u64>,
        registries: &mut Registries,
    ) -> (Vec<Candidate>, Vec<anyhow::Error>) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        // `visited` spans the whole run's harvests: the same entry is
        // in exactly one slot of one wheel, so a repeat is corrupt
        // memory, not a second sighting.
        for runtime in runtimes {
            if let Err(e) =
                self.harvest_wheel(runtime, visited, &mut found, &mut errors, registries)
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
        visited: &mut HashSet<u64>,
        found: &mut Vec<Candidate>,
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
        // The driver's epoch, read once per wheel: enrichment beside
        // the harvest, so an unbound or unreadable epoch costs every
        // entry its deadline and nothing else.
        let start = self
            .walk(WalkRole::TimeSourceStart)
            .try_walk(runtime.handle)
            .ok()
            .flatten()
            .and_then(Walked::optional)
            .and_then(|start| self.timespec(start, &ReadContext::none()).ok());
        registries.stopped = self.stopped_at();
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
                    self.walk_wheel_slot(addr, entry_ty, start, visited, found, registries)
                {
                    errors.push(e.context(format!("failed to walk the wheel slot at {addr:#x}")));
                }
            }
        }
        Ok(())
    }

    /// Walk one slot's `TimerShared` list, collecting the task Headers
    /// its entries' wakers name.
    #[allow(clippy::too_many_arguments)]
    fn walk_wheel_slot(
        &self,
        head: u64,
        entry_ty: BundleType<'b>,
        start: Option<RawInstant>,
        visited: &mut HashSet<u64>,
        found: &mut Vec<Candidate>,
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
            let (task, waker_at) = match self
                .walk(WalkRole::TimerSharedWaker)
                .walk(entry)?
                .optional()
            {
                Some(raw) => (
                    self.registry_waker(
                        raw,
                        entry,
                        ReferenceSource::TimerWaker,
                        DiscoveryRoute::Wheel,
                        found,
                    )?,
                    Some(raw.addr),
                ),
                None => (None, None),
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
                waker_at,
                deadline: match (start, state) {
                    (Some(start), Some(state)) => TimerEntryInfo::wheel_deadline(start, state),
                    _ => None,
                },
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

    /// Route 2's other registry: every task-Header pointer held by an
    /// io resource registered with `runtimes`' own drivers, as a
    /// reference from the resource.
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
        visited: &mut HashSet<u64>,
        registries: &mut Registries,
    ) -> (Vec<Candidate>, Vec<anyhow::Error>) {
        let mut found = Vec::new();
        let mut errors = Vec::new();
        // `visited` spans the whole run's harvests, for both node
        // kinds: a registration is in one driver's list and a waiter
        // node in one resource's, so a repeat is corrupt memory, not a
        // second sighting.
        for runtime in runtimes {
            if let Err(e) = self.harvest_io(runtime, visited, &mut found, &mut errors, registries) {
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
        visited: &mut HashSet<u64>,
        found: &mut Vec<Candidate>,
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
            if let Err(e) = self.harvest_io_waiters(registration, visited, found, &mut resource) {
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
        visited: &mut HashSet<u64>,
        found: &mut Vec<Candidate>,
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
                let task = self.registry_waker(
                    raw,
                    registration,
                    ReferenceSource::IoWaker,
                    DiscoveryRoute::Io,
                    found,
                )?;
                resource.waiters.push(IoWaiterInfo {
                    slot,
                    task,
                    waker_at: Some(raw.addr),
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
                let task = self.registry_waker(
                    raw,
                    node,
                    ReferenceSource::IoWaker,
                    DiscoveryRoute::Io,
                    found,
                )?;
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
                    waker_at: Some(raw.addr),
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
    /// candidate: a reference of kind `source` from `holder` — the
    /// entry or node the waker sits in — to the task it names, by
    /// `route`. The task's address is returned either way, for the
    /// registries' retention; anything that is not a task waker (a
    /// `block_on` thread's parker waker, say) is `None`.
    fn registry_waker(
        &self,
        raw: Value<'b>,
        holder: Value<'b>,
        source: ReferenceSource,
        route: DiscoveryRoute,
        found: &mut Vec<Candidate>,
    ) -> Result<Option<u64>> {
        let QueuedWaker::Task { addr, .. } = self.raw_waker(raw)? else {
            return Ok(None);
        };
        found.push(Candidate::Reference {
            reference: TaskReference {
                target: TaskAddr(addr),
                source,
                source_value: Some(ValueKey::of(holder)),
                root_task: None,
                path: Vec::new(),
            },
            route,
        });
        Ok(Some(addr))
    }

    /// The spawn_blocking cells parked in one runtime's pool queue, as
    /// candidates naming the queue and the runtime it belongs to. The
    /// queue is a `VecDeque` ring: the recorded element layout strides
    /// it, and each element's `UnownedTask` names the Header that
    /// identifies the cell.
    fn queued_blocking(
        &self,
        runtime: &RuntimeRef<'b>,
        found: &mut Vec<Candidate>,
        errors: &mut Vec<anyhow::Error>,
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
                Ok(header) => found.push(Candidate::Queued {
                    addr: header,
                    owner: runtime.owner_key(),
                    queue: ValueKey::of(queue),
                    entry: addr,
                }),
                Err(e) => {
                    errors.push(e.context(format!("failed to read blocking-queue slot {slot}")))
                }
            }
        }
        Ok(())
    }

    /// Take one candidate into the store.
    ///
    /// An address already decoded merges the source — and a queue
    /// entry's owner claim — without a second decode of the header. A
    /// new one is decoded under `read` (a candidate in memory the
    /// allocator has taken back is refused, not filed), filed with
    /// its cell's recorded scheduler class as kind evidence, and, for
    /// a scheduler-owned task, followed home through that scheduler
    /// to the owner it names — which must claim the task (its list id
    /// the task's `owner_id`) before the record credits it. A blocking
    /// cell has no list to follow home; the header is the whole find.
    /// A task the tokio info cannot classify (an unresolvable future)
    /// is a record with no kind and no owner, and only a genuine read
    /// failure reports.
    #[allow(clippy::too_many_arguments)]
    fn observe_candidate(
        &self,
        candidate: Candidate,
        excluded: &[u64],
        thread_ids: &[(u64, u32)],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        sets: &mut Vec<LocalSetRef<'b>>,
        list: &mut TaskList,
        read: &ReadContext<'_>,
    ) {
        let addr = candidate.addr();
        let route = candidate.route();
        let (source, claim) = match candidate {
            Candidate::Reference { reference, .. } => (TaskSource::Reference(reference), None),
            Candidate::Queued {
                owner,
                queue,
                entry,
                ..
            } => (
                TaskSource::BlockingQueue {
                    owner,
                    queue,
                    entry,
                },
                Some(OwnerClaim {
                    owner,
                    evidence: OwnerEvidence::BlockingQueue { queue, entry },
                }),
            ),
        };
        if let Some(id) = list.records.lookup(addr) {
            list.records.observe_at(
                id,
                Observation {
                    source,
                    kind: None,
                    claim,
                },
            );
            return;
        }
        let header = match self.read_task_header(TaskAddr(addr), read) {
            Ok(header) => header,
            Err(e) => {
                list.errors.push(e.context(format!(
                    "failed to decode the task at {addr:#x} that {route} named"
                )));
                return;
            }
        };
        let class = self.header_class(&header);
        let kind = self.header_kind(&header);
        let effect = list.records.observe(
            header,
            Observation {
                source,
                kind,
                claim,
            },
        );
        let Some(class) = class else {
            return;
        };
        if class == SchedulerClass::Blocking {
            return;
        }
        match self.cell_owner_claim(
            effect.record,
            class,
            route,
            excluded,
            thread_ids,
            runtimes,
            sets,
            list,
        ) {
            Ok(Some(claim)) => {
                list.records.claim(effect.record, claim);
            }
            Ok(None) => {}
            Err(e) => list.errors.push(e.context(format!(
                "failed to follow the task at {addr:#x} home through its scheduler"
            ))),
        }
    }

    /// Follow a fresh record home through its cell's recorded
    /// scheduler: the `Arc` the cell holds, crossed to the owner it
    /// points at, which is admitted (or already was) and must claim
    /// the task. The validated claim, or `None` with the mismatch
    /// filed on the record.
    #[allow(clippy::too_many_arguments)]
    fn cell_owner_claim(
        &self,
        id: TaskRecordId,
        class: SchedulerClass,
        route: DiscoveryRoute,
        excluded: &[u64],
        thread_ids: &[(u64, u32)],
        runtimes: &mut Vec<RuntimeRef<'b>>,
        sets: &mut Vec<LocalSetRef<'b>>,
        list: &mut TaskList,
    ) -> Result<Option<OwnerClaim>> {
        let header = &list.records.record(id).header;
        let addr = header.addr;
        let FutureInfo::Known(known) = &header.future else {
            return Ok(None);
        };
        let entry = self.task_entry(known.entry);
        let cell_ty = self.infra_ty(
            entry.cell,
            &format!("the Cell of {}", known.name(self.view)),
        )?;
        let owner_id = header
            .owner_id
            .ok_or_else(|| anyhow!("the task at {addr:?} records no owner_id to check"))?;
        let cell = Value::read(self.proc, cell_ty, addr.0)?;
        let scheduler = self.walk(WalkRole::CellScheduler).walk_at(cell)?;
        let owner = self
            .arc_data(scheduler)
            .context("failed to follow the cell's scheduler Arc")?;
        let validated = match class {
            SchedulerClass::LocalSet => {
                self.local_set_claim(owner, owner_id, addr, route, thread_ids, sets)?
            }
            SchedulerClass::MultiThread => self.runtime_claim(
                owner,
                RuntimeFlavor::MultiThread,
                owner_id,
                addr,
                route,
                excluded,
                runtimes,
            )?,
            SchedulerClass::CurrentThread => self.runtime_claim(
                owner,
                RuntimeFlavor::CurrentThread,
                owner_id,
                addr,
                route,
                excluded,
                runtimes,
            )?,
            SchedulerClass::Blocking => return Ok(None),
        };
        Ok(match validated {
            Ok(key) => Some(OwnerClaim {
                owner: key,
                evidence: OwnerEvidence::CellScheduler {
                    scheduler: ValueKey::of(owner),
                    owner_id,
                },
            }),
            Err(mismatch) => {
                list.records.issue(id, mismatch);
                None
            }
        })
    }

    /// The claim a task's cell makes on a runtime, held to the
    /// runtime's list claiming the task back: the key, or the mismatch
    /// to file. The runtime may be one a thread's `Context` reached,
    /// one an earlier candidate admitted, one the operator excluded —
    /// whose list id is read and whose population is not — or one this
    /// find admits, which it does only when the list claims the task.
    /// A runtime already known under the other flavor is keyed by the
    /// flavor this cell records: one address seen two ways is a
    /// conflict for the record, not a second runtime.
    #[allow(clippy::too_many_arguments)]
    fn runtime_claim(
        &self,
        handle: Value<'b>,
        flavor: RuntimeFlavor,
        owner_id: u64,
        addr: TaskAddr,
        route: DiscoveryRoute,
        excluded: &[u64],
        runtimes: &mut Vec<RuntimeRef<'b>>,
    ) -> Result<std::result::Result<OwnerKey, DiscoveryIssue>> {
        let key = OwnerKey::Runtime {
            flavor,
            handle: handle.addr,
        };
        let mismatch = |expected: u64| DiscoveryIssue::OwnerIdMismatch {
            addr,
            owner: key,
            expected,
            found: Some(owner_id),
        };
        let unbound = || anyhow!("the scheduler owned list's id did not bind against this target");
        let list_id = match runtimes.iter().find(|r| r.handle.addr == handle.addr) {
            Some(runtime) => runtime.owned_id,
            None if excluded.contains(&handle.addr) => self.owned_list_id(handle)?,
            None => {
                let step = (|| -> Result<std::result::Result<RuntimeRef<'b>, DiscoveryIssue>> {
                    let owned_id = self.owned_list_id(handle)?.ok_or_else(unbound)?;
                    if owned_id != owner_id {
                        return Ok(Err(mismatch(owned_id)));
                    }
                    Ok(Ok(RuntimeRef {
                        flavor,
                        handle,
                        owned_id: Some(owned_id),
                        worker_tids: Vec::new(),
                        route,
                    }))
                })();
                return match step {
                    Ok(Ok(runtime)) => {
                        runtimes.push(runtime);
                        Ok(Ok(key))
                    }
                    Ok(Err(mismatch)) => Ok(Err(mismatch)),
                    Err(e) => Err(e.context(format!(
                        "found a {flavor} runtime at {:#x} (via {route}) but could not read it",
                        handle.addr
                    ))),
                };
            }
        };
        let list_id = list_id.ok_or_else(unbound)?;
        Ok(match list_id == owner_id {
            true => Ok(key),
            false => Err(mismatch(list_id)),
        })
    }

    /// The claim a task's cell makes on a local set, held to the set's
    /// list claiming the task back — the set's sibling of
    /// [`Context::runtime_claim`]: a set already admitted is checked,
    /// a new one is read and admitted only when it claims the task.
    fn local_set_claim(
        &self,
        shared: Value<'b>,
        owner_id: u64,
        addr: TaskAddr,
        route: DiscoveryRoute,
        thread_ids: &[(u64, u32)],
        sets: &mut Vec<LocalSetRef<'b>>,
    ) -> Result<std::result::Result<OwnerKey, DiscoveryIssue>> {
        let key = OwnerKey::LocalSet {
            shared: shared.addr,
        };
        let mismatch = |expected: u64| DiscoveryIssue::OwnerIdMismatch {
            addr,
            owner: key,
            expected,
            found: Some(owner_id),
        };
        if let Some(set) = sets.iter().find(|set| set.shared.addr == shared.addr) {
            return Ok(match set.owned_id == owner_id {
                true => Ok(key),
                false => Err(mismatch(set.owned_id)),
            });
        }
        let set = self.read_local_set(shared, None, route, thread_ids)?;
        if set.owned_id != owner_id {
            return Ok(Err(mismatch(set.owned_id)));
        }
        sets.push(set);
        Ok(Ok(key))
    }

    /// Read a `Shared` some route reached as a set: its owned-list id,
    /// the thread it is pinned to, and the LWP that is — `tls_tid`
    /// where the TLS probe found it, else the worker whose thread id
    /// the set records.
    fn read_local_set(
        &self,
        shared: Value<'b>,
        tls_tid: Option<u32>,
        route: DiscoveryRoute,
        thread_ids: &[(u64, u32)],
    ) -> Result<LocalSetRef<'b>> {
        let step = (|| -> Result<LocalSetRef<'b>> {
            let owned_id: u64 = self.walk(WalkRole::LocalOwnedId).read(shared)?;
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
        step.map_err(|e| {
            e.context(format!(
                "found a local set at {:#x} (via {route}) but could not read it",
                shared.addr
            ))
        })
    }

    /// Walk a discovered set's `LocalOwnedTasks` list — one more shard
    /// with a different root: the nodes are ordinary task Headers,
    /// linked through the same `Trailer.owned` pointers the scheduler's
    /// shards use. Every node must carry the set's `owned.id` as its
    /// `Header.owner_id` to be credited to the set; a mismatch is kept
    /// on the record and the task listed all the same, since the list
    /// itself is the ground truth for membership.
    fn enumerate_local(&self, set: &LocalSetRef<'b>, list: &mut TaskList) -> Result<()> {
        let mut visited = HashSet::default();
        let what = format!("the local set at {:#x}", set.shared.addr);
        match self.walk(WalkRole::LocalOwnedHead).walk(set.shared)? {
            Walked::At(head) => {
                let head_addr = head
                    .parse::<u64>(self.proc)
                    .with_context(|| format!("failed to read the list head of {what}"))?;
                self.walk_owned_list(
                    head_addr,
                    set.owner_key(),
                    Some(set.owned_id),
                    &mut visited,
                    list,
                    &what,
                );
            }
            // An empty set.
            Walked::Inactive(_) | Walked::Null => {}
        }
        Ok(())
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
        let Some((record, kind)) = self
            .type_semantics(value.ty.id())
            .and_then(|record| Some((record, record.resource.as_ref()?.kind)))
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
            ResourceKind::MpscRecv => self
                .observe_recv(value, read)
                .map(ResourceObservation::Recv),
            ResourceKind::Notified => self
                .observe_notified(value, read)
                .map(ResourceObservation::Notified),
            ResourceKind::OneshotRecv => self
                .observe_oneshot(value, read)
                .map(ResourceObservation::Oneshot),
            // The dispatcher, with its words bound, or hyper-util's
            // version-choosing wrapper, which binds none.
            ResourceKind::HttpConn if record.http.is_some() => self
                .observe_http_conn(value, read)
                .map(|http| ResourceObservation::HttpConn(Box::new(http))),
            ResourceKind::HttpConn => self
                .observe_http_negotiating(record, value, read)
                .map(ResourceObservation::HttpNegotiating),
        };
        match observed {
            Ok(observation) => Observed::of(observation),
            Err(e) => Observed::failed(issue_of(key, &e)),
        }
    }

    /// hyper-util's version-choosing wrapper as the connection resource.
    /// It is one only in the state its program marks the primitive —
    /// reading a connection's first bytes — so the state the program
    /// matches on is read and held to that case: a wrapper that has
    /// chosen its version is not the connection, the one inside is.
    fn observe_http_negotiating(
        &self,
        record: &TypeSemantics,
        wrapper: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<HttpNegotiatingObservation> {
        let Some(Continuation::Bound {
            program: PollProgram::MatchVariant { state, cases },
            ..
        }) = record.future.as_ref().map(|facts| &facts.continuation)
        else {
            bail!(
                "{} binds the connection resource with no state to read it in",
                wrapper.ty.name()
            );
        };
        let state_value = self.route(wrapper, &state.steps, read)?;
        ensure!(
            state_value.ty.id() == state.target,
            "the state route landed on {} rather than its recorded type",
            state_value.ty.name()
        );
        let (active, _) = state_value.active_variant_raw()?;
        let negotiating = cases.iter().any(|case| {
            matches!(case.action, PollAction::Primitive)
                && self.view.str(case.variant) == Some(active)
        });
        ensure!(
            negotiating,
            "{} has chosen its version ({active}); the connection is the one inside",
            wrapper.ty.name()
        );
        Ok(HttpNegotiatingObservation {
            wrapper: ValueKey::of(wrapper),
        })
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

    /// A bounded receiver's `recv`: the channel behind the `Rx` its
    /// closure borrowed. The `Rx` is read through the borrow under
    /// `read`, and the channel is keyed by the `Chan`'s own nominal
    /// type, so the words read from it decode with the layout this
    /// receiver was compiled against.
    fn observe_recv(&self, poll_fn: Value<'b>, read: &ReadContext<'_>) -> Result<RecvObservation> {
        let rx = self
            .walk(WalkRole::MpscRecvRx)
            .walk_at_with(read, poll_fn)?;
        let rx_ty = rx
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("the recv closure's Rx capture is not pointer-shaped"))?;
        let rx_addr: u64 = rx.parse(self.proc)?;
        ensure!(rx_addr != 0, "the recv closure's Rx pointer is null");
        let rx = self.read_keyed(
            ValueKey {
                addr: rx_addr,
                ty: rx_ty.id(),
            },
            read,
        )?;
        let chan = self.walk(WalkRole::MpscRecvChan).walk_at_with(read, rx)?;
        Ok(RecvObservation {
            future: ValueKey::of(poll_fn),
            chan: ValueKey::of(chan),
        })
    }

    /// A `Notified`: the `Notify` it borrowed, its state, the count it
    /// was created at, and its embedded node's notification word, all
    /// read in place.
    fn observe_notified(
        &self,
        notified: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<NotifiedObservation> {
        let notify = self
            .walk(WalkRole::NotifiedNotify)
            .walk_at_with(read, notified)?;
        let notify_ty = notify
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("Notified.notify is not pointer-shaped"))?;
        let notify_addr: u64 = notify.parse(self.proc)?;
        ensure!(notify_addr != 0, "the Notified's Notify pointer is null");
        let state = self
            .walk(WalkRole::NotifiedState)
            .walk_at_with(read, notified)?;
        let state = match state.ty.enumerator_name(state.bytes) {
            Some("Init") => NotifiedState::Init,
            Some("Waiting") => NotifiedState::Waiting,
            Some("Done") => NotifiedState::Done,
            _ => NotifiedState::Unknown(word_of(state.bytes)),
        };
        let node = self
            .walk(WalkRole::NotifiedWaiter)
            .walk_at_with(read, notified)?;
        let notification: u64 = self
            .walk(WalkRole::NotifyWaiterNotification)
            .read_with(read, node)?;
        let calls: u64 = self
            .walk(WalkRole::NotifiedCalls)
            .read_with(read, notified)?;
        Ok(NotifiedObservation {
            future: ValueKey::of(notified),
            notify: ValueKey {
                addr: notify_addr,
                ty: notify_ty.id(),
            },
            state,
            node: node.addr,
            notification,
            calls,
        })
    }

    /// A `oneshot::Receiver`: the `ArcInner<Inner<T>>` its pointer
    /// names, read whole under `read`, and from it the state word, the
    /// value's presence and the receiver's task cell. The cell is read
    /// only where the state word says a waker is in it: a clear bit
    /// leaves `MaybeUninit` bytes nothing vouches for.
    pub fn observe_oneshot(
        &self,
        receiver: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<OneshotObservation> {
        self.observe_oneshot_arc(ValueKey::of(receiver), receiver, read)
    }

    /// The oneshot behind a `Receiver` value, keyed as `future`.
    fn observe_oneshot_arc(
        &self,
        future: ValueKey,
        receiver: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<OneshotObservation> {
        let ptr = self
            .walk(WalkRole::OneshotInner)
            .walk_at_with(read, receiver)?;
        let arc_ty = ptr
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("oneshot::Receiver.inner is not pointer-shaped"))?;
        let arc_addr: u64 = ptr.parse(self.proc)?;
        ensure!(arc_addr != 0, "the oneshot receiver's Arc pointer is null");
        let arc = ValueKey {
            addr: arc_addr,
            ty: arc_ty.id(),
        };
        let value = self.read_keyed(arc, read)?;
        self.observe_oneshot_inner(future, value, read)
    }

    /// The oneshot's words, from its `ArcInner<Inner<T>>` value.
    pub fn observe_oneshot_inner(
        &self,
        future: ValueKey,
        arc: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<OneshotObservation> {
        let word: u64 = self.walk(WalkRole::OneshotState).read_with(read, arc)?;
        let inner = arc.addr + arc.ty.member("data").map(|m| m.offset()).unwrap_or(0);
        let value_present = match self.walk(WalkRole::OneshotValue).try_walk_with(read, arc) {
            Ok(Some(Walked::At(value))) => option_present(value),
            _ => None,
        };
        let state = OneshotState {
            word,
            value_present,
        };
        // The cell's address is the `Inner`'s layout and reads nothing;
        // the waker in it is read only where the state word says one
        // is stored.
        let task = |role: WalkRole, set: bool| -> Result<(Option<QueuedWaker>, Option<u64>)> {
            let raw = match (self.walk(role).walk_with(read, arc), set) {
                (Ok(Walked::At(raw)), _) => raw,
                (Ok(_), _) | (Err(_), false) => return Ok((None, None)),
                (Err(e), true) => return Err(e),
            };
            let waker = if set {
                Some(self.raw_waker(raw)?)
            } else {
                None
            };
            Ok((waker, Some(raw.addr)))
        };
        let (rx_waker, rx_task_at) = task(WalkRole::OneshotRxTask, state.rx_task_set())?;
        let (tx_waker, tx_task_at) = task(WalkRole::OneshotTxTask, state.tx_task_set())?;
        Ok(OneshotObservation {
            future,
            arc: ValueKey::of(arc),
            inner,
            state,
            rx_waker,
            tx_waker,
            rx_task_at,
            tx_task_at,
        })
    }

    /// The oneshot behind a `Sender` value: the `ArcInner<Inner<T>>`
    /// its pointer names, read whole under `read`, and its words — for
    /// a connection's response callback, watched from the sending side.
    fn observe_oneshot_sender(
        &self,
        sender: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<OneshotObservation> {
        let ptr = self
            .walk(WalkRole::OneshotSenderInner)
            .walk_at_with(read, sender)?;
        let arc_ty = ptr
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("oneshot::Sender.inner is not pointer-shaped"))?;
        let arc_addr: u64 = ptr.parse(self.proc)?;
        ensure!(arc_addr != 0, "the oneshot sender's Arc pointer is null");
        let arc = self.read_keyed(
            ValueKey {
                addr: arc_addr,
                ty: arc_ty.id(),
            },
            read,
        )?;
        self.observe_oneshot_inner(ValueKey::of(sender), arc, read)
    }

    /// hyper's HTTP/1 `Dispatcher`: every word the connection verdict
    /// reads, each by the route its binding records from the
    /// dispatcher, and for a client the primitives its dispatch is
    /// parked on — the response callback's oneshot, read from the
    /// `Sender` the callback's active variant carries, and the channel
    /// behind the request receiver; for a server, whether a handler is
    /// in flight and whether the header-read timer is armed. A word
    /// whose route lands on an enumerator or variant the reviewed range
    /// does not have is kept as unknown, for the assessor to decline
    /// with; a framing or a method that does not read is left out,
    /// since the phase stands without it.
    fn observe_http_conn(
        &self,
        dispatcher: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<HttpConnObservation> {
        let binding = self
            .type_semantics(dispatcher.ty.id())
            .and_then(|record| record.http.as_ref())
            .ok_or_else(|| anyhow!("{} has no connection binding", dispatcher.ty.name()))?;
        let at = |path: &TypedPath| -> Result<Walked<'b>> {
            contract::execute_steps(self, read, dispatcher, &path.steps)
        };
        let word = |path: &TypedPath, what: &str| -> Result<Value<'b>> {
            let value = at(path)?.at(what)?;
            ensure!(
                value.ty.id() == path.target,
                "the {what} route landed on {} rather than its recorded type",
                value.ty.name()
            );
            Ok(value)
        };
        // The connection is the first member every state route enters.
        let conn = self
            .route(dispatcher, &binding.keep_alive.steps[..1], read)?
            .addr;
        let keep_alive = word(&binding.keep_alive, "keep-alive")?;
        let keep_alive = match keep_alive.ty.enumerator_name(keep_alive.bytes) {
            Some("Idle") => KeepAlive::Idle,
            Some("Busy") => KeepAlive::Busy,
            Some("Disabled") => KeepAlive::Disabled,
            other => KeepAlive::Unknown(other.unwrap_or("<unreadable>").to_owned()),
        };
        // A body's framing, from the codec's `kind` the variant carries;
        // `None` where that did not read.
        let framing = |path: &TypedPath| -> Option<BodyFraming> {
            let Ok(Walked::At(kind)) = at(path) else {
                return None;
            };
            let (name, payload) = kind.active_variant_raw().ok()?;
            body_framing(name, || payload.member("__0").ok()?.parse(self.proc).ok())
        };
        let reading = word(&binding.reading, "reading")?;
        let reading = match reading.active_variant_raw()?.0 {
            "Init" => HttpReading::Init,
            "Continue" => HttpReading::Continue(framing(&binding.read_continue_kind)),
            "Body" => HttpReading::Body(framing(&binding.read_body_kind)),
            "KeepAlive" => HttpReading::KeepAlive,
            "Closed" => HttpReading::Closed,
            other => HttpReading::Unknown(other.to_owned()),
        };
        let writing = word(&binding.writing, "writing")?;
        let writing = match writing.active_variant_raw()?.0 {
            "Init" => HttpWriting::Init,
            "Body" => HttpWriting::Body(framing(&binding.write_body_kind)),
            "KeepAlive" => HttpWriting::KeepAlive,
            "Closed" => HttpWriting::Closed,
            other => HttpWriting::Unknown(other.to_owned()),
        };
        // The method's name is its enum's variant, uppercased the way
        // the wire writes it; an extension method carries its text
        // elsewhere and is left unnamed.
        let method = match word(&binding.method, "method")?.active_variant_raw()?.0 {
            "Some" => match at(&binding.method_inner) {
                Ok(Walked::At(inner)) => inner
                    .active_variant_raw()
                    .ok()
                    .map(|(name, _)| name)
                    .filter(|name| !name.starts_with("Extension"))
                    .map(|name| name.to_ascii_uppercase()),
                _ => None,
            },
            _ => None,
        };
        let is_closing = word(&binding.is_closing, "closing flag")?;
        let is_closing = is_closing.bytes.first().is_some_and(|byte| *byte != 0);
        // The read buffer's two words, a fact beside the verdict: a
        // buffer that does not read leaves the verdict standing.
        let buffer_word = |path: &TypedPath, what: &str| -> Option<u64> {
            word(path, what).ok()?.parse::<u64>(self.proc).ok()
        };
        let read_buf = buffer_word(&binding.read_buf_len, "read buffer length")
            .zip(buffer_word(&binding.read_buf_cap, "read buffer capacity"));
        let client = match &binding.client {
            Some(client) => {
                let callback = match word(&client.callback, "callback")?.active_variant_raw()?.0 {
                    "Some" => {
                        let mut found = None;
                        for path in [&client.retry, &client.no_retry] {
                            if let Walked::At(sender) = at(path)? {
                                found = Some(self.observe_oneshot_sender(sender, read)?);
                                break;
                            }
                        }
                        found
                    }
                    _ => None,
                };
                // The receiver's route lands on the `Chan` behind its
                // `Arc`, keyed by the `Chan`'s own type so its words
                // decode with the layout this receiver was compiled
                // against; a null `Arc` is no channel to read.
                let receiver = word(&client.rx, "request receiver")?;
                let rx = self
                    .walk(WalkRole::MpscReceiverChan)
                    .walk_with(read, receiver)?
                    .optional()
                    .map(ValueKey::of);
                // The want pointer, a fact beside the verdict: a word
                // that does not read leaves the connection unnamed.
                let want = word(&client.want, "want handle")
                    .ok()
                    .and_then(|pointer| pointer.parse::<u64>(self.proc).ok())
                    .filter(|addr| *addr != 0);
                Some(HttpClientObservation { callback, rx, want })
            }
            None => None,
        };
        // The server's handler: `Some` behind the pinned box while one
        // runs. The timer flag is a byte.
        let server = match &binding.server {
            Some(server) => {
                let in_flight = word(&server.in_flight, "in-flight handler")?;
                let (variant, payload) = in_flight.active_variant_raw()?;
                let in_flight = variant == "Some";
                // The request the handler runs for: the pinned box the
                // option holds, walked as a held future is.
                let request = in_flight
                    .then(|| payload.member("__0").ok())
                    .flatten()
                    .and_then(|boxed| self.handler_request(boxed, read));
                let flag = word(
                    &server.header_read_timeout_running,
                    "header-read timer flag",
                )?;
                let header_read_timer_running = flag.bytes.first().is_some_and(|byte| *byte != 0);
                // The timeout and the timer, facts beside the verdict:
                // `None` where the server has none — the `Option`'s
                // variant is not the one the words sit in — or a word
                // did not read.
                let selected = |path: &TypedPath| match at(path) {
                    Ok(Walked::At(value)) => Some(value),
                    _ => None,
                };
                let header_read_timeout = selected(&server.header_read_timeout_secs)
                    .and_then(|secs| secs.parse::<u64>(self.proc).ok())
                    .zip(
                        selected(&server.header_read_timeout_nanos)
                            .and_then(|nanos| nanos.parse::<u32>(self.proc).ok())
                            .filter(|nanos| *nanos < 1_000_000_000),
                    )
                    .map(|(secs, nanos)| std::time::Duration::new(secs, nanos));
                // The timer's address, which is what tells its find
                // from any other timer the task holds.
                let header_read_timer = selected(&server.header_read_timer)
                    .and_then(|pointer| pointer.parse::<u64>(self.proc).ok())
                    .filter(|addr| *addr != 0);
                // The peer and the server's context, where a convention
                // routes to them: facts beside the verdict, like the
                // buffer.
                let service = server.service.as_ref();
                let peer = service
                    .and_then(|service| word(&service.peer, "peer address").ok())
                    .and_then(socket_addr_text);
                let context = service
                    .and_then(|service| self.view.ty(service.context))
                    .map(|ty| ty.name().to_string());
                Some(HttpServerObservation {
                    in_flight,
                    header_read_timer_running,
                    header_read_timeout,
                    header_read_timer,
                    peer,
                    context,
                    request,
                })
            }
            None => None,
        };
        // The socket under the connection, where its stream's route is
        // bound: a fact beside the verdict, which stands on the words.
        let stream = binding.stream.as_ref().map(|path| {
            (|| -> Result<SocketReading> {
                let stream = word(path, "stream")?;
                let FollowedRoute {
                    scheduled_io,
                    fd,
                    tls,
                    socket,
                    peer,
                    ..
                } = self.follow_io_route(stream, read)?;
                Ok(SocketReading {
                    scheduled_io: ValueKey::of(scheduled_io),
                    fd,
                    socket,
                    tls,
                    peer,
                })
            })()
            .map_err(|e| format!("{e:#}"))
        });
        Ok(HttpConnObservation {
            dispatcher: ValueKey::of(dispatcher),
            conn,
            role: binding.role,
            keep_alive,
            reading,
            writing,
            method,
            is_closing,
            read_buf,
            client,
            server,
            stream,
        })
    }

    /// What a server's in-flight handler is running for: the pinned box
    /// walked as a held future, and the request a frame of its chain
    /// holds. `None` where no frame does, as when a `dyn` box's pointee
    /// is not in the bundle.
    fn handler_request(
        &self,
        boxed: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Option<HttpRequestObservation> {
        let inspection = self.inspect_future(boxed, super::chain::InspectionMode::Held, read);
        self.chain_request(&inspection.chain, read)
    }

    /// The request a chain carries: the first frame that is itself a
    /// value a reviewed range keeps a request in, or holds one as a
    /// local — reqwest's in-flight request is the future the caller's
    /// chain runs into, a handler's request or request context is a
    /// local of its frame. `None` where no frame of the chain does.
    pub fn chain_request(
        &self,
        chain: &AwaitChain<'b>,
        read: &ReadContext<'_>,
    ) -> Option<HttpRequestObservation> {
        chain.frames.iter().find_map(|frame| {
            if self.keeps_request(frame.future.ty.id()) {
                return Some(self.observe_request(frame.future, read));
            }
            if !self.may_hold_request(frame.future.ty) {
                return None;
            }
            super::census::frame_locals(self, frame)
                .locals
                .into_iter()
                .find(|(_, local)| self.keeps_request(local.ty.id()))
                .map(|(_, local)| self.observe_request(local, read))
        })
    }

    /// Whether a frame of `ty` can hold a request as a local: a member
    /// of it, or of one of its states, is of a type that binds one. A
    /// fact of the type, remembered per type, since the chain scan asks
    /// it of every frame of every find on a target.
    fn may_hold_request(&self, ty: BundleType<'b>) -> bool {
        self.request_holders.get_or(&ty.id(), || {
            let member_keeps = |ty: BundleType<'b>| {
                ty.members()
                    .any(|member| self.keeps_request(member.ty().id()))
            };
            member_keeps(ty) || ty.variants().any(|variant| member_keeps(variant.ty))
        })
    }

    /// Whether a value of `ty` keeps a request's words.
    fn keeps_request(&self, ty: BundleTypeId) -> bool {
        self.type_semantics(ty)
            .is_some_and(|record| record.request.is_some())
    }

    /// The request a value keeps, read through its binding: the
    /// method's name is its enum's variant, uppercased the way the wire
    /// writes it, with an extension method left unnamed as the
    /// connection's is; the target's text is the bytes at the pointer
    /// the binding routes to, for the length beside it, where they
    /// decode as UTF-8. Each half reads on its own, so a text that does
    /// not read still leaves the method.
    pub fn observe_request(
        &self,
        value: Value<'b>,
        read: &ReadContext<'_>,
    ) -> HttpRequestObservation {
        let binding = self
            .type_semantics(value.ty.id())
            .and_then(|record| record.request.as_ref())
            .expect("a request is read only off a type that binds one");
        let at = |path: &TypedPath| -> Option<Value<'b>> {
            let landed = contract::execute_steps(self, read, value, &path.steps)
                .ok()?
                .optional()?;
            (landed.ty.id() == path.target).then_some(landed)
        };
        let method = at(&binding.method)
            .and_then(|inner| {
                inner
                    .active_variant_raw()
                    .ok()
                    .map(|(name, _)| name.to_owned())
            })
            .filter(|name| !name.starts_with("Extension"))
            .map(|name| name.to_ascii_uppercase());
        let text = at(&binding.target_ptr)
            .zip(at(&binding.target_len))
            .and_then(|(ptr, len)| {
                let ptr: u64 = ptr.parse(self.proc).ok()?;
                let len: u64 = len.parse(self.proc).ok()?;
                read_request_text(self.proc, ptr, len)
            });
        HttpRequestObservation {
            at: ValueKey::of(value),
            method,
            target: binding.target,
            text,
        }
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
    /// the stream its `&mut` names and that stream's route to its
    /// socket, or named outright by a `Readiness` — and what its own
    /// storage says.
    fn observe_io(
        &self,
        future: Value<'b>,
        operation: IoOperationKind,
        read: &ReadContext<'_>,
    ) -> Result<IoObservation> {
        // A handshake reads and writes as the protocol needs: which
        // direction it waits in is the slot its waker sits in, which
        // the assessor reads; the observation names both.
        let interest = match operation.writes() {
            Some(true) => Interest::WRITABLE,
            Some(false) => Interest::READABLE,
            None if operation == IoOperationKind::Handshake => {
                Interest::READABLE.union(Interest::WRITABLE)
            }
            None => return self.observe_readiness(future, read),
        };
        let binding = self
            .type_semantics(future.ty.id())
            .and_then(|record| record.io.as_ref())
            .ok_or_else(|| anyhow!("{} has no io operation binding", future.ty.name()))?;
        // The stream is behind the operation's `&mut`: the one
        // dereference, held to `read`, then the stream's own route.
        let stream = contract::execute_steps(self, read, future, &binding.stream.steps)
            .context("the operation's stream")?
            .at("the operation's stream")?;
        let FollowedRoute {
            streams: route,
            scheduled_io,
            fd,
            tls,
            socket,
            peer,
        } = self.follow_io_route(stream, read)?;
        let remaining = binding
            .remaining
            .as_ref()
            .map(|path| -> Result<u64> {
                let length = contract::execute_steps(self, read, future, &path.steps)
                    .context("the operation's buffer length")?
                    .at("the operation's buffer length")?;
                Ok(length.parse(self.proc)?)
            })
            .transpose()?;
        Ok(IoObservation {
            future: ValueKey::of(future),
            operation,
            scheduled_io: ValueKey::of(scheduled_io),
            interest,
            waiter_node: None,
            remaining,
            readiness_state: None,
            waiter_ready: None,
            route,
            fd,
            tls,
            socket: Some(socket),
            peer,
        })
    }

    /// Follow a stream's route to its socket: each routed type's
    /// forward, every pointer it crosses held to `read`, until a
    /// socket's roles reach its registration and its descriptor. The
    /// streams crossed come back outermost first, the socket last. The
    /// table's validation proves every route ends at a socket in fewer
    /// hops than it has records; the bound here only stops a table that
    /// was never validated.
    pub(crate) fn follow_io_route(
        &self,
        stream: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Result<FollowedRoute<'b>> {
        let mut current = stream;
        let mut route = Vec::new();
        let mut tls = None;
        let mut peer = None;
        while route.len() < MAX_IO_ROUTE {
            route.push(ValueKey::of(current));
            let record = self.type_semantics(current.ty.id());
            // A TLS stream on the way: its connection's words, read
            // where the route crosses it — never from a frame's copy.
            if tls.is_none()
                && let Some(binding) = record.and_then(|record| record.tls_stream.as_ref())
            {
                tls = Some(
                    self.observe_tls(current, binding, read)
                        .map_err(|e| format!("{e:#}")),
                );
            }
            // A stream that names its peer: the name's text.
            if peer.is_none()
                && let Some(binding) = record.and_then(|record| record.stream_peer.as_ref())
            {
                peer = Some(self.observe_peer(current, binding, read));
            }
            let step = record
                .and_then(|record| record.io_route.as_ref())
                .map(|binding| &binding.step)
                .ok_or_else(|| anyhow!("{} has no stream route", current.ty.name()))?;
            match step {
                IoRouteStep::Forward { inner } => {
                    current = contract::execute_steps(self, read, current, &inner.steps)
                        .with_context(|| format!("the route through {}", current.ty.name()))?
                        .at("the stream held")?;
                }
                // Exactly one case's variant is live; a value in a
                // variant with no case has no route.
                IoRouteStep::Match { cases } => {
                    let mut live = None;
                    for case in cases {
                        let walked = contract::execute_steps(self, read, current, &case.steps)
                            .with_context(|| format!("the route through {}", current.ty.name()))?;
                        if let Walked::At(inner) = walked {
                            live = Some(inner);
                            break;
                        }
                    }
                    current = live.ok_or_else(|| {
                        anyhow!("{}'s live variant has no stream route", current.ty.name())
                    })?;
                }
                IoRouteStep::Dyn {
                    pointer,
                    layout,
                    cases,
                } => {
                    current = self
                        .dyn_stream(current, pointer, layout, cases, read)
                        .with_context(|| {
                            format!("the stream trait object in {}", current.ty.name())
                        })?;
                }
                IoRouteStep::Socket(socket) => {
                    let [shared, fd] = socket_roles(*socket);
                    let scheduled_io = self.walk(shared).walk_at_with(read, current)?;
                    let fd = self.walk(fd).try_read::<i32>(current).ok().flatten();
                    return Ok(FollowedRoute {
                        streams: route,
                        scheduled_io,
                        fd,
                        tls,
                        socket: *socket,
                        peer,
                    });
                }
            }
        }
        bail!("the stream route runs past {MAX_IO_ROUTE} streams")
    }

    /// The stream behind a trait object: the wide pointer's two words by
    /// the recorded paths, then the case whose read symbol the vtable's
    /// read slot holds — the same symbol, or, where the target was built
    /// apart from the binary the bundle was read from, the same one
    /// under its hash-free key, the pairing of the target's own crate
    /// hashes choosing among releases — then the size and alignment the
    /// vtable records held to that case's layout, and the stream read
    /// whole under `read`. A symbol that names no case, or several the
    /// pairing does not settle, is no route.
    fn dyn_stream(
        &self,
        value: Value<'b>,
        pointer: &TypedPath,
        layout: &DynStreamLayout,
        cases: &[DynStreamCase],
        read: &ReadContext<'_>,
    ) -> Result<Value<'b>> {
        let wide = contract::execute_steps(self, read, value, &pointer.steps)?
            .at("the stream's trait object")?;
        ensure!(
            wide.ty.id() == pointer.target,
            "the trait object route landed on {} rather than its recorded type",
            wide.ty.name()
        );
        let word = |path: &TypedPath, what: &str| -> Result<u64> {
            let field = contract::execute_steps(self, read, wide, &path.steps)
                .with_context(|| format!("the {what} word"))?
                .at(what)?;
            Ok(field.parse::<u64>(self.proc)?)
        };
        let data = word(&layout.data, "data")?;
        let vtable = word(&layout.vtable, "vtable")?;
        ensure!(
            vtable != 0 && self.mappings.contains_addr(vtable),
            "stream vtable pointer {vtable:#x} is unmapped"
        );
        ensure!(data != 0, "stream data pointer is null");
        let slot = |slot: u32| -> Result<u64> {
            let addr = vtable
                .checked_add(u64::from(slot) * 8)
                .ok_or_else(|| anyhow!("vtable slot {slot} of {vtable:#x} overflows"))?;
            self.proc.read_u64(addr).map_err(|e| {
                anyhow!(e).context(format!("failed to read slot {slot} of vtable {vtable:#x}"))
            })
        };
        let read_fn = slot(layout.read_slot)?;
        let symbol = self
            .symbol_at(read_fn)
            .ok_or_else(|| anyhow!("no symbol at the vtable's read method {read_fn:#x}"))?;
        let exact = strip_llvm_suffix(&symbol);
        let key = normalized_v0_key(exact);
        let named = |matches: &dyn Fn(&str) -> bool| -> Vec<BundleTypeId> {
            let mut targets: Vec<BundleTypeId> = cases
                .iter()
                .filter(|case| self.view.str(case.symbol).is_some_and(matches))
                .map(|case| case.target)
                .collect();
            targets.sort();
            targets.dedup();
            targets
        };
        let mut targets = named(&|s| s == exact);
        if targets.is_empty()
            && let Some(key) = &key
        {
            targets = named(&|s| normalized_v0_key(s).as_ref() == Some(key));
        }
        let target = match targets.as_slice() {
            [] => bail!("the read method {symbol} names no stream the tokio info routes"),
            [one] => *one,
            several => self.paired_candidate(&symbol, several).ok_or_else(|| {
                anyhow!("the read method {symbol} names {} streams", several.len())
            })?,
        };
        let ty = self
            .view
            .ty(target)
            .ok_or_else(|| anyhow!("stream type {} is not in the tokio info", target.0))?;
        let size = slot(layout.size_slot)?;
        let align = slot(layout.align_slot)?;
        ensure!(
            size == ty.size(),
            "vtable {vtable:#x} records a size of {size} for {}, whose layout is {} bytes",
            ty.name(),
            ty.size()
        );
        ensure!(
            align != 0 && align.is_power_of_two() && data.is_multiple_of(align),
            "stream data pointer {data:#x} is not aligned to the vtable's {align}"
        );
        if let Some(refusal) = read.refusal(data, size) {
            return Err(anyhow::Error::new(refusal).context(format!("reading {}", ty.name())));
        }
        Value::read(self.proc, ty, data)
            .with_context(|| format!("failed to read {} at {data:#x}", ty.name()))
    }

    /// A stream's peer: the text its name's bytes hold, up to the NULs
    /// that pad them.
    fn observe_peer(
        &self,
        stream: Value<'b>,
        binding: &StreamPeerBinding,
        read: &ReadContext<'_>,
    ) -> Result<String, String> {
        let name = contract::execute_steps(self, read, stream, &binding.name.steps)
            .and_then(|walked| walked.at("the peer's name"))
            .map_err(|e| format!("{e:#}"))?;
        hansei_bundle::padded_text(name.bytes)
            .map(str::to_owned)
            .ok_or_else(|| "the peer's name is not UTF-8".to_owned())
    }

    /// A TLS stream's connection, read through the paths its binding
    /// records: the stream's own state variant, then the rustls
    /// connection's words by its session binding.
    fn observe_tls(
        &self,
        stream: Value<'b>,
        binding: &TlsStreamBinding,
        read: &ReadContext<'_>,
    ) -> Result<TlsReading> {
        let at = |root: Value<'b>, path: &TypedPath, what: &str| -> Result<Value<'b>> {
            let value = contract::execute_steps(self, read, root, &path.steps)
                .with_context(|| format!("the TLS {what}"))?
                .at(what)?;
            ensure!(
                value.ty.id() == path.target,
                "the TLS {what} route landed on {} rather than its recorded type",
                value.ty.name()
            );
            Ok(value)
        };
        // An enum's word: a C-like enum's enumerator, or the variant
        // that is live.
        let name = |value: Value<'b>, what: &str| -> Result<&'b str> {
            match value.ty.enumerator_name(value.bytes) {
                Some(name) => Ok(name),
                None => Ok(value
                    .active_variant_raw()
                    .with_context(|| format!("the TLS {what}"))?
                    .0),
            }
        };
        let stream_state = name(at(stream, &binding.state, "stream state")?, "stream state")?;
        let session = at(stream, &binding.session, "connection")?;
        let words = self
            .type_semantics(session.ty.id())
            .and_then(|record| record.tls_session.as_ref())
            .ok_or_else(|| anyhow!("{} has no session binding", session.ty.name()))?;
        let flag = |path: &TypedPath, what: &str| -> Result<bool> {
            Ok(at(session, path, what)?
                .bytes
                .first()
                .is_some_and(|b| *b != 0))
        };
        let seq = |path: &TypedPath, what: &str| -> Result<u64> {
            Ok(at(session, path, what)?.parse::<u64>(self.proc)?)
        };
        let failed = name(at(session, &words.state, "state")?, "state")? == "Err";
        let side = name(at(session, &words.side, "side")?, "side")?.to_owned();
        let version = match name(
            at(session, &words.negotiated_version, "negotiated version")?,
            "negotiated version",
        )? {
            "Some" => Some(name(at(session, &words.version, "version")?, "version")?.to_owned()),
            _ => None,
        };
        Ok(TlsReading {
            side,
            version,
            failed,
            may_send_application_data: flag(&words.may_send_application_data, "send flag")?,
            may_receive_application_data: flag(
                &words.may_receive_application_data,
                "receive flag",
            )?,
            has_sent_close_notify: flag(&words.has_sent_close_notify, "sent close_notify flag")?,
            has_received_close_notify: flag(
                &words.has_received_close_notify,
                "received close_notify flag",
            )?,
            has_seen_eof: flag(&words.has_seen_eof, "end-of-stream flag")?,
            sent_fatal_alert: flag(&words.sent_fatal_alert, "fatal alert flag")?,
            read_seq: seq(&words.read_seq, "read sequence")?,
            write_seq: seq(&words.write_seq, "write sequence")?,
            deframer: (
                seq(&words.deframer_used, "deframer's fill")?,
                seq(&words.deframer_len, "deframer's size")?,
            ),
            stream_state: stream_state.to_owned(),
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
            route: Vec::new(),
            fd: None,
            tls: None,
            socket: None,
            peer: None,
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

    /// Read one bounded mpsc channel, on explicit demand: every word
    /// the recv protocol reads, each on its own so one that fails to
    /// read costs itself and nothing else. The slot the receiver would
    /// pop is found the way `Rx::pop` finds it — the block chain walked
    /// from the head to the block holding the read index, then that
    /// block's ready word — each block's dereference charged to
    /// `budget` and held to `read`.
    pub fn observe_channel(
        &self,
        chan: ValueKey,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
    ) -> ChannelObservation {
        use hansei_bundle::tokio::semaphore;
        let mut channel = ChannelObservation {
            chan,
            senders: None,
            tail_position: None,
            index: None,
            rx_closed: None,
            slot: SlotState::Unknown,
            capacity: None,
            available: None,
            semaphore_closed: None,
            waker_state: None,
            waker: None,
            issues: Vec::new(),
        };
        if !budget.charge_referent() {
            channel.issues.push(spent(chan, budget));
            return channel;
        }
        let value = match self.read_keyed(chan, read) {
            Ok(value) => value,
            Err(e) => {
                channel.issues.push(issue_of(chan, &e));
                return channel;
            }
        };
        let word = |role: WalkRole, issues: &mut Vec<WalkIssue>| -> Option<u64> {
            match self.walk(role).read_with::<u64>(read, value) {
                Ok(word) => Some(word),
                Err(e) => {
                    issues.push(issue_of(chan, &e));
                    None
                }
            }
        };
        channel.senders = word(WalkRole::ChanTxCount, &mut channel.issues);
        channel.tail_position = word(WalkRole::ChanTailPosition, &mut channel.issues);
        channel.index = word(WalkRole::ChanRxIndex, &mut channel.issues);
        channel.waker_state = word(WalkRole::ChanRxWakerState, &mut channel.issues);
        match self
            .walk(WalkRole::ChanRxClosed)
            .read_with::<bool>(read, value)
        {
            Ok(closed) => channel.rx_closed = Some(closed),
            Err(e) => channel.issues.push(issue_of(chan, &e)),
        }
        // The bounded semaphore's words are enrichment: a build whose
        // member names moved costs the receiver-closed branch, not the wait.
        match self
            .walk(WalkRole::ChanSemaphoreBound)
            .try_read::<u64>(value)
        {
            Ok(bound) => channel.capacity = bound,
            Err(e) => channel.issues.push(issue_of(chan, &e)),
        }
        match self
            .walk(WalkRole::ChanSemaphorePermits)
            .try_read::<u64>(value)
        {
            Ok(Some(raw)) => {
                channel.semaphore_closed = Some(raw & semaphore::CLOSED != 0);
                channel.available = Some(raw >> semaphore::PERMIT_SHIFT);
            }
            Ok(None) => {}
            Err(e) => channel.issues.push(issue_of(chan, &e)),
        }
        match self.walk(WalkRole::ChanRxWaker).walk_with(read, value) {
            Ok(walked) => match walked.optional() {
                Some(raw) => match self.raw_waker(raw) {
                    Ok(waker) => channel.waker = Some(waker),
                    Err(e) => channel.issues.push(issue_of(chan, &e)),
                },
                None => channel.waker = Some(QueuedWaker::Unarmed),
            },
            Err(e) => channel.issues.push(issue_of(chan, &e)),
        }
        if let Some(index) = channel.index {
            match self.observe_slot(value, index, read, budget) {
                Ok(slot) => channel.slot = slot,
                Err(issue) => channel.issues.push(issue),
            }
        }
        channel
    }

    /// What `Rx::pop` would find at `index`: the block chain from the
    /// list's head to the block whose `start_index` is the index's,
    /// then that block's ready word — the slot's bit, else the senders'
    /// close marker, else nothing. A chain that ends first is nothing
    /// to read; one that loops or outruns the budget is an issue.
    fn observe_slot(
        &self,
        chan: Value<'b>,
        index: u64,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
    ) -> std::result::Result<SlotState, WalkIssue> {
        use hansei_bundle::tokio::mpsc;
        let at = ValueKey::of(chan);
        let head = self
            .walk(WalkRole::ChanRxHead)
            .walk_at_with(read, chan)
            .map_err(|e| issue_of(at, &e))?;
        let block_ty = head.ty.pointer_target().ok_or_else(|| {
            WalkIssue::new(
                at,
                WalkIssueKind::InvalidLayout,
                "the list head is not pointer-shaped",
            )
        })?;
        let mut cur: u64 = head
            .parse(self.proc)
            .map_err(|e| issue_of(at, &anyhow!(e)))?;
        let wanted = index & mpsc::BLOCK_MASK;
        let mut visited = HashSet::default();
        loop {
            if cur == 0 {
                return Ok(SlotState::NoBlock);
            }
            let key = ValueKey {
                addr: cur,
                ty: block_ty.id(),
            };
            if !visited.insert(cur) {
                return Err(WalkIssue::new(
                    key,
                    WalkIssueKind::Cycle,
                    format!("block-list cycle at {cur:#x}"),
                ));
            }
            if !budget.charge_referent() {
                return Err(spent(key, budget));
            }
            let block = self.read_keyed(key, read).map_err(|e| issue_of(key, &e))?;
            let start: u64 = self
                .walk(WalkRole::BlockStartIndex)
                .read_with(read, block)
                .map_err(|e| issue_of(key, &e))?;
            if start == wanted {
                let ready: u64 = self
                    .walk(WalkRole::BlockReadySlots)
                    .read_with(read, block)
                    .map_err(|e| issue_of(key, &e))?;
                let bit = 1u64 << (index & mpsc::SLOT_MASK);
                return Ok(if ready & bit != 0 {
                    SlotState::Value
                } else if ready & mpsc::TX_CLOSED != 0 {
                    SlotState::Closed
                } else {
                    SlotState::Empty
                });
            }
            cur = self
                .walk(WalkRole::BlockNext)
                .read_with(read, block)
                .map_err(|e| issue_of(key, &e))?;
        }
    }

    /// One `Notify`'s state word alone — what a description of a held
    /// `Notified` reads, since the list behind it may hold thousands.
    /// `None` where the value or the word did not read.
    pub fn notify_state(&self, notify: ValueKey, read: &ReadContext<'_>) -> Option<u64> {
        let value = self.read_keyed(notify, read).ok()?;
        self.walk(WalkRole::NotifyState)
            .read_with::<u64>(read, value)
            .ok()
    }

    /// Read one `Notify`, on explicit demand: its state word, the
    /// guard around its wait list, and the list itself, walked like a
    /// semaphore's queue — newest first, reversed into `notify_one`'s
    /// wake order only when it reached the end.
    pub fn observe_notify(
        &self,
        notify: ValueKey,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
    ) -> NotifyObservation {
        let mut observation = NotifyObservation {
            notify,
            state: None,
            waiters: Vec::new(),
            complete: false,
            consistency: Consistency::Unknown,
            issues: Vec::new(),
        };
        if !budget.charge_referent() {
            observation.issues.push(spent(notify, budget));
            return observation;
        }
        let value = match self.read_keyed(notify, read) {
            Ok(value) => value,
            Err(e) => {
                observation.issues.push(issue_of(notify, &e));
                return observation;
            }
        };
        match self
            .walk(WalkRole::NotifyState)
            .read_with::<u64>(read, value)
        {
            Ok(state) => observation.state = Some(state),
            Err(e) => observation.issues.push(issue_of(notify, &e)),
        }
        match self.walk(WalkRole::NotifyLock).try_walk_with(read, value) {
            Ok(Some(Walked::At(lock))) => observation.consistency = lock_consistency(lock),
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => observation.issues.push(issue_of(notify, &e)),
        }
        match self.observe_notify_nodes(value, read, budget, &mut observation.waiters) {
            Ok(()) => {
                observation.complete = true;
                observation.waiters.reverse();
            }
            Err(issue) => observation.issues.push(issue),
        }
        observation
    }

    /// The task headers a `Notify`'s wait list names, walked once per
    /// target: the list read on the first demand, its issues handed to
    /// that caller, and the tasks alone kept for every later one.
    pub fn notify_waiter_tasks(
        &self,
        notify: ValueKey,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
        issues: &mut Vec<WalkIssue>,
    ) -> Vec<u64> {
        self.notify_waiters.get_or(&notify, || {
            let list = self.observe_notify(notify, read, budget);
            issues.extend(list.issues);
            list.waiters.iter().filter_map(|w| w.waker.task()).collect()
        })
    }

    /// The wait list of one `Notify`, node by node in walk order,
    /// pushed as each is reached so a failing walk leaves its prefix.
    fn observe_notify_nodes(
        &self,
        notify: Value<'b>,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
        waiters: &mut Vec<NotifyWaiter>,
    ) -> std::result::Result<(), WalkIssue> {
        let at = ValueKey::of(notify);
        let head = self
            .walk(WalkRole::NotifyQueueHead)
            .walk_with(read, notify)
            .map_err(|e| issue_of(at, &e))?;
        let Some(head) = head.optional() else {
            return Ok(());
        };
        let waiter_ty = head.ty.pointer_target().ok_or_else(|| {
            WalkIssue::new(
                at,
                WalkIssueKind::InvalidLayout,
                "the wait-list head is not pointer-shaped",
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
                    format!("wait-list cycle at {addr:#x}"),
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
                return Err(spent(key, budget));
            }
            let node = self.read_keyed(key, read).map_err(|e| issue_of(key, &e))?;
            waiters.push(
                self.notify_node(node, read)
                    .map_err(|e| issue_of(key, &e))?,
            );
            cur = self
                .walk(WalkRole::NotifyWaiterNext)
                .walk_with(read, node)
                .map_err(|e| issue_of(key, &e))?
                .optional()
                .map(|ptr| ptr.parse(self.proc).map_err(|e| issue_of(key, &anyhow!(e))))
                .transpose()?;
        }
        Ok(())
    }

    /// One `Notify` wait-list node: its notification word and the
    /// waker it holds.
    fn notify_node(&self, node: Value<'b>, read: &ReadContext<'_>) -> Result<NotifyWaiter> {
        let waker = match self
            .walk(WalkRole::NotifyWaiterWaker)
            .walk_with(read, node)?
            .optional()
        {
            Some(raw) => self.raw_waker(raw)?,
            None => QueuedWaker::Unarmed,
        };
        Ok(NotifyWaiter {
            addr: node.addr,
            notification: self
                .walk(WalkRole::NotifyWaiterNotification)
                .read_with(read, node)?,
            waker,
        })
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
                                waker_at: Some(raw.addr),
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
            let (task, waker_at) = match self.walk(WalkRole::IoWaiterWaker).walk_with(read, node) {
                Ok(raw) => match raw.optional() {
                    Some(raw) => match self.raw_waker(raw) {
                        Ok(waker) => (waker.task(), Some(raw.addr)),
                        Err(e) => {
                            issues.push(issue_of(key, &e));
                            (None, None)
                        }
                    },
                    None => (None, None),
                },
                Err(e) => {
                    issues.push(issue_of(key, &e));
                    (None, None)
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
                waker_at,
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
    pub(crate) fn read_keyed(&self, key: ValueKey, read: &ReadContext<'_>) -> Result<Value<'b>> {
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

/// A body's framing, from the codec's `Kind` variant hyper's decoder or
/// encoder carries and — for a `Content-Length` body — the bytes still
/// to go, read on demand. The decoder's `Eof` and the encoder's
/// `CloseDelimited` are one framing: the body ends with the connection.
/// A variant the reviewed range does not have is no framing.
/// A `core::net::SocketAddr` as std spells it — `192.0.2.1:80`,
/// `[2001:db8::1]:80`, the scope after a `%` when nonzero — read off the
/// enum's active variant: `V4`/`V6`, whose payload holds the address
/// struct with its `ip.octets` array, `port` word and, for v6, `scope_id`.
/// `None` where any of those did not read.
fn socket_addr_text(addr: Value<'_>) -> Option<String> {
    let (variant, payload) = addr.active_variant_raw().ok()?;
    let inner = payload.member("__0").ok()?;
    let word = |name: &str| -> Option<u64> {
        let bytes = inner.member(name).ok()?.bytes;
        match bytes.len() {
            2 => Some(u64::from(u16::from_le_bytes(bytes.try_into().ok()?))),
            4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
            _ => None,
        }
    };
    let octets = inner.member("ip").ok()?.member("octets").ok()?.bytes;
    let scope_id = match variant {
        "V6" => Some(word("scope_id")?),
        _ => None,
    };
    spell_socket_addr(variant, octets, word("port")?, scope_id)
}

/// The spelling itself: `V4` with four octets as `a.b.c.d:port`, `V6`
/// with sixteen as `[addr]:port`, the scope after a `%` when it is
/// set; another variant or count is no address.
fn spell_socket_addr(
    variant: &str,
    octets: &[u8],
    port: u64,
    scope_id: Option<u64>,
) -> Option<String> {
    match variant {
        "V4" => {
            let octets: [u8; 4] = octets.try_into().ok()?;
            Some(format!("{}:{port}", std::net::Ipv4Addr::from(octets)))
        }
        "V6" => {
            let octets: [u8; 16] = octets.try_into().ok()?;
            let scope = match scope_id? {
                0 => String::new(),
                scope => format!("%{scope}"),
            };
            Some(format!(
                "[{}{scope}]:{port}",
                std::net::Ipv6Addr::from(octets)
            ))
        }
        _ => None,
    }
}

fn body_framing(variant: &str, remaining: impl FnOnce() -> Option<u64>) -> Option<BodyFraming> {
    match variant {
        "Length" => Some(BodyFraming::Length {
            remaining: remaining()?,
        }),
        "Chunked" => Some(BodyFraming::Chunked),
        "Eof" | "CloseDelimited" => Some(BodyFraming::CloseDelimited),
        _ => None,
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

#[cfg(test)]
mod tests {
    /// A primitive's name is kept once: the same name is the same
    /// string whichever bundle it came from, and another name another.
    #[test]
    fn test_a_primitive_label_is_kept_once_per_name() {
        let one = super::primitive_label(&String::from("tokio::sync::Mutex"));
        let again = super::primitive_label(&String::from("tokio::sync::Mutex"));
        assert_eq!(one, "tokio::sync::Mutex");
        assert!(std::ptr::eq(one, again));
        let other = super::primitive_label("tokio::sync::RwLock");
        assert_eq!(other, "tokio::sync::RwLock");
        assert!(!std::ptr::eq(one, other));
    }

    /// A request's text is its bytes up to the limit, the limit
    /// included: an empty text is one, a longer one or bytes that are
    /// not UTF-8 are none.
    #[test]
    fn test_a_request_text_reads_up_to_the_limit() {
        use crate::testkit::fake::FakeTarget;
        let base = 0x1000;
        // The limit written out, not read back off the constant.
        let limit: u64 = 64 * 1024;
        let target = FakeTarget {
            base,
            bytes: vec![b'a'; limit as usize + 1],
            has_symbol: false,
            seam: None,
        };
        let text = super::read_request_text(&target, base, limit);
        assert_eq!(text.map(|t| t.len() as u64), Some(limit));
        assert_eq!(super::read_request_text(&target, base, limit + 1), None);
        assert_eq!(
            super::read_request_text(&target, base, 0).as_deref(),
            Some("")
        );
        let invalid = FakeTarget {
            base,
            bytes: vec![0xff; 4],
            has_symbol: false,
            seam: None,
        };
        assert_eq!(super::read_request_text(&invalid, base, 4), None);
    }

    /// A socket address spells as std does, from the enum's active
    /// variant: the v4 form bare, the v6 form bracketed with its scope
    /// only when set, and a variant or an octet count that is neither
    /// is no address.
    #[test]
    fn test_a_socket_address_spells_as_std_does() {
        assert_eq!(
            spell_socket_addr("V4", &[127, 0, 0, 1], 8080, None).as_deref(),
            Some("127.0.0.1:8080")
        );
        let v6 = [
            0xfd, 0, 0x11, 0x22, 0x33, 0x44, 0x01, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0x25,
        ];
        assert_eq!(
            spell_socket_addr("V6", &v6, 57400, Some(0)).as_deref(),
            Some("[fd00:1122:3344:10d::25]:57400")
        );
        assert_eq!(
            spell_socket_addr("V6", &v6, 57400, Some(3)).as_deref(),
            Some("[fd00:1122:3344:10d::25%3]:57400")
        );
        assert_eq!(spell_socket_addr("V6", &v6, 1, None), None);
        assert_eq!(spell_socket_addr("V4", &v6, 1, None), None);
        assert_eq!(spell_socket_addr("V6", &[1, 2, 3, 4], 1, Some(0)), None);
        assert_eq!(spell_socket_addr("Other", &[1, 2, 3, 4], 1, None), None);
    }

    /// The same read off values of the fixture's own `SocketAddr` type:
    /// the peer the server's service captured — a loopback v4 address
    /// and the port the client connected from — and a v6 value laid
    /// down by hand at the type's own offsets, with and without a
    /// scope, so both variants read through the value's members.
    #[test]
    fn test_a_socket_address_reads_off_the_enum() {
        use crate::testkit::{self, load_any};
        let (bundle, snapshot) = load_any("http-conns");
        let ctx = testkit::context(&bundle, &snapshot);
        let e = testkit::enumerate(&ctx, &snapshot);
        // The peer the service captured, reached through the server
        // dispatcher's frame on a connection that has chosen HTTP/1.
        let read = ReadContext::none();
        let peer = e
            .list
            .tasks
            .iter()
            .filter(|t| {
                matches!(&t.future, FutureInfo::Known(known) if known.name(ctx.view).contains("http_conns::serve"))
            })
            .find_map(|serve| {
                let inspection = ctx.inspect_task(serve, &read).ok()??;
                let dispatcher = inspection.chain.frames.iter().find(|f| {
                    f.future
                        .ty
                        .name()
                        .contains("Dispatcher<hyper::proto::h1::dispatch::Server<")
                })?;
                // `member` peels the one-member `ServiceFn` to the
                // closure it wraps, whose capture is the peer.
                dispatcher
                    .future
                    .member("dispatch")
                    .ok()?
                    .member("service")
                    .ok()?
                    .member("peer")
                    .ok()
            })
            .expect("an HTTP/1 server connection holding its peer");
        let text = socket_addr_text(peer).expect("the peer reads");
        let (ip, port) = text.split_once(':').unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert!(port.parse::<u16>().unwrap() > 1024, "{text}");

        let ty = ctx
            .view
            .find_by_name("core::net::socket_addr::SocketAddr")
            .find(|t| t.variant("V6").is_some())
            .expect("the address enum");
        let (payload, at) = ty.variant("V6").unwrap();
        let inner = payload.member("__0").unwrap();
        let v6 = inner.ty();
        let base = (at + inner.offset()) as usize;
        let offset = |name: &str| base + v6.member(name).unwrap().offset() as usize;
        let mut bytes = vec![0u8; ty.size() as usize];
        // The discriminant: `V6`'s value at the enum's discriminant word.
        let discr = ty.variant_shape().unwrap().discr.as_ref().unwrap();
        let v6_index = ty
            .variant_shape()
            .unwrap()
            .variants
            .iter()
            .position(|v| bundle.strings.get(v.name) == Some("V6"))
            .unwrap();
        let discr_value = match &ty.variant_shape().unwrap().variants[v6_index].discr_values {
            Some(hansei_bundle::DiscrValues(values)) => match values[0] {
                hansei_bundle::DiscrValue::Value(v) => v as u64,
                _ => panic!("a ranged discriminant"),
            },
            None => panic!("no discriminant value"),
        };
        let discr_size = ctx.view.ty(discr.ty).unwrap().size() as usize;
        bytes[discr.offset as usize..discr.offset as usize + discr_size]
            .copy_from_slice(&discr_value.to_le_bytes()[..discr_size]);
        let ip = offset("ip");
        bytes[ip..ip + 16].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let port = offset("port");
        bytes[port..port + 2].copy_from_slice(&443u16.to_le_bytes());
        let value = reify::Value::new(ty, 0x1000, &bytes);
        assert_eq!(socket_addr_text(value).as_deref(), Some("[fe80::1]:443"));
        let scope = offset("scope_id");
        bytes[scope..scope + 4].copy_from_slice(&7u32.to_le_bytes());
        let value = reify::Value::new(ty, 0x1000, &bytes);
        assert_eq!(socket_addr_text(value).as_deref(), Some("[fe80::1%7]:443"));
    }

    use super::*;

    use crate::testkit;
    use crate::tokio::Lifecycle;
    use crate::tokio::assess::AssessmentPass;
    use crate::tokio::bundle::Registries;
    use crate::tokio::chain::FutureInspection;

    use hansei_bundle::Bundle;
    use proc::snapshot::Snapshot;

    use std::sync::OnceLock;

    /// The body framing each codec variant names, and the count only a
    /// `Length` body reads — the rows the fixture never parks in.
    #[test]
    fn test_body_framing_names_each_codec_variant() {
        let never = || panic!("only a Length body reads its count");
        assert_eq!(
            body_framing("Length", || Some(1234)),
            Some(BodyFraming::Length { remaining: 1234 })
        );
        assert_eq!(body_framing("Length", || None), None);
        assert_eq!(body_framing("Chunked", never), Some(BodyFraming::Chunked));
        assert_eq!(
            body_framing("Eof", never),
            Some(BodyFraming::CloseDelimited)
        );
        assert_eq!(
            body_framing("CloseDelimited", never),
            Some(BodyFraming::CloseDelimited)
        );
        assert_eq!(body_framing("Trailers", never), None);
    }

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
            assert_eq!(
                candidates,
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
    fn task_named<'a>(list: &'a TaskList, view: BundleView<'_>, name: &str) -> &'a Task {
        list.tasks
            .iter()
            .find(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(view).contains(name)))
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
        let task = task_named(&list, ctx.view, "sleeper");
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
        assert!(known.name(ctx.view).contains("sleeper"));
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
            kind: TaskKind::Unknown,
            owner: OwnerResolution::Unknown,
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

    /// A listed task's own chain, walked by its programs.
    fn chain_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> AwaitChain<'a> {
        inspection_of(ctx, task).chain
    }

    /// A listed task's own inspection, walked by its programs.
    fn inspection_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> FutureInspection<'a> {
        ctx.inspect_task(task, &ReadContext::none())
            .unwrap()
            .expect("the task's future is resident")
    }

    /// The primitive `task`'s chain ends in, which the observers are
    /// asked about.
    fn leaf_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> Value<'a> {
        let chain = chain_of(ctx, task);
        chain
            .primitive_leaf()
            .unwrap_or_else(|| panic!("the chain ends in a primitive: {:?}", chain.end))
    }

    /// The listed task whose chain ends in a primitive of a type named
    /// `leaf`.
    fn task_parked_on<'a, T: Target>(
        ctx: &Context<'a, T>,
        list: &'a TaskList,
        leaf: &str,
    ) -> (&'a Task, Value<'a>) {
        list.tasks
            .iter()
            .filter_map(|task| {
                let value = chain_of(ctx, task).primitive_leaf()?;
                value.ty.name().starts_with(leaf).then_some((task, value))
            })
            .next()
            .unwrap_or_else(|| panic!("a task is parked on a {leaf}"))
    }

    /// The target an observation describes, read under no protocol.
    fn described<'a, T: Target>(ctx: &Context<'a, T>, list: &TaskList, task: &Task) -> WaitTarget {
        let inspection = inspection_of(ctx, task);
        let observation = inspection
            .primitive
            .value
            .as_ref()
            .expect("a primitive observed");
        let mut pass = AssessmentPass::new();
        ctx.observed_target(
            &mut pass,
            observation,
            &inspection.chain,
            list,
            &ReadContext::none(),
        )
        .expect("the observation describes")
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
        let joiner = task_named(&list, ctx.view, "joiner");
        let sleeper = task_named(&list, ctx.view, "sleeper");
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
        let TaskStage::Running(root) = ctx.task_root(joiner, &ReadContext::none()).unwrap() else {
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
        let sleeper = task_named(&list, ctx.view, "sleeper");
        let sleep = leaf_of(&ctx, sleeper);
        let observed = ctx.observe_resource(sleep, &ReadContext::none());
        let Some(ResourceObservation::Timer(timer)) = observed.value else {
            panic!("a Sleep observes as a timer: {:?}", observed.value);
        };
        assert_eq!(timer.future, ValueKey::of(sleep));
        let WaitTarget::Timer { deadline, .. } = described(&ctx, &list, sleeper) else {
            panic!("the description spells the same sleep");
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

        // The same order and nodes the description spells.
        let WaitTarget::Semaphore { waiters, .. } = described(&ctx, &list, task) else {
            panic!("the description spells the same semaphore");
        };
        let spelled: Vec<u64> = waiters.iter().map(|w| w.addr).collect();
        let observed: Vec<u64> = queue.waiters.iter().map(|w| w.addr).collect();
        assert_eq!(observed, spelled);
        assert_eq!(
            queue.position(acq.node),
            spelled.iter().position(|&a| a == acq.node)
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
        let (_, acquire) = task_parked_on(&ctx, &list, "tokio::sync::batch_semaphore::Acquire");
        let Some(ResourceObservation::Acquire(acq)) =
            ctx.observe_resource(acquire, &ReadContext::none()).value
        else {
            unreachable!()
        };
        let (lock_byte, first_next, first) = queue_words(&ctx, acq.semaphore);
        assert_eq!(first, acq.node);

        // The granted acquire left the queue: an established walk says
        // so, and places it nowhere.
        let analysis =
            crate::tokio::graph::analyze(&ctx, &list, &Registries::default(), &ReadContext::none());
        let [barrier] = analysis.barriers.as_slice() else {
            panic!("one barrier: {:?}", analysis.barriers);
        };
        assert!(barrier.granted());
        let granted = barrier.acquire.node;
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
            let task = task_named(list, ctx.view, name);
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
        let writer = task_named(list, ctx.view, "local_writer");
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
        let watcher = task_named(list, ctx.view, "local_watcher");
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

        // `Read<Gated>` holds a socket and is not an operation on one:
        // the chain ends at it with its continuation unknown, and it
        // observes as nothing.
        let gated = task_named(list, ctx.view, "local_gated_reader");
        let chain = chain_of(&ctx, gated);
        assert!(
            matches!(chain.end, ChainEnd::UnknownContinuation { .. }),
            "{:?}",
            chain.end
        );
        let read = chain.frames.last().unwrap().future;
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
        let task = task_named(&list, ctx.view, "local_reader");
        let read = leaf_of(&ctx, task);
        // The operation's `&mut`: its stream path short of the final
        // dereference.
        let binding = ctx
            .type_semantics(read.ty.id())
            .and_then(|record| record.io.as_ref())
            .expect("a read over a socket binds its stream");
        let (deref, to_pointer) = binding.stream.steps.split_last().unwrap();
        assert_eq!(deref, &Step::Deref);
        let reader = contract::execute_steps(&ctx, &ReadContext::none(), read, to_pointer)
            .unwrap()
            .at("reader")
            .unwrap();
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

    fn armed_select() -> &'static (Bundle, Snapshot) {
        static PAIR: OnceLock<(Bundle, Snapshot)> = OnceLock::new();
        PAIR.get_or_init(|| testkit::load_any("armed-select"))
    }

    /// A frame member is sliced at its own offset and size: the value
    /// handed on carries exactly the member's bytes, at the member's
    /// address.
    #[test]
    fn test_frame_members_slice_each_member_at_its_offset() {
        let (bundle, snapshot) = sleep_join();
        let ctx = testkit::context(bundle, snapshot);
        // Any struct with a sized, non-pointer member well past its
        // start (past 8, so offset and size cannot coincide).
        let (frame_ty, member) = (0..bundle.types.types.len() as u32)
            .filter_map(|i| ctx.view.ty(hansei_bundle::BundleTypeId(i)))
            .filter(|ty| matches!(ty.classify(), hansei_bundle::TypeClass::Struct))
            .find_map(|ty| {
                let m = ty.members().find(|m| {
                    m.offset() >= 8 && m.ty().size() > 0 && m.ty().pointer_target().is_none()
                })?;
                Some((ty, m))
            })
            .expect("a struct with a sized member past its start");
        let wanted = member.ty().name().to_string();
        let accept = |ty: BundleType<'_>| ty.id() == member.ty().id();
        let bytes = vec![0xab_u8; frame_ty.size() as usize];
        let base = 0x7000_0000;
        let frame = Value::new(frame_ty, base, &bytes);
        let values = ctx.frame_members(&[frame], &accept);
        assert!(
            values.iter().any(|v| v.addr == base + member.offset()),
            "{wanted} at {:#x} in {}: {:?}",
            member.offset(),
            frame_ty.name(),
            values.iter().map(|v| v.addr).collect::<Vec<_>>()
        );
        for v in &values {
            assert_eq!(v.bytes.len() as u64, v.ty.size(), "{}", v.ty.name());
        }
    }

    /// A `Notify`'s state is read from its word, whatever it says: one
    /// patched to `notified` with two `notify_waiters` calls above the
    /// bits reads back as exactly that.
    #[test]
    fn test_notify_state_reads_the_word() {
        use crate::testkit::corrupt::Corrupt;
        use hansei_bundle::tokio::notify;
        let (bundle, snapshot) = armed_select();
        let ctx = testkit::context(bundle, snapshot);
        let notify_ty = ctx
            .view
            .find_by_name("tokio::sync::notify::Notify")
            .next()
            .expect("the fixture's bundle carries Notify");
        // Somewhere readable to lay one: the first task's header.
        let list = testkit::tasks(&ctx, snapshot);
        let addr = list.tasks[0].addr.0;
        let key = ValueKey {
            addr,
            ty: notify_ty.id(),
        };
        let read = ReadContext::none();
        let value = ctx.read_keyed(key, &read).expect("a Notify-shaped read");
        let Ok(Some(Walked::At(state))) = ctx.walk(WalkRole::NotifyState).try_walk(value) else {
            panic!("the state role walks");
        };
        let word = notify::NOTIFIED | (2 << notify::CALLS_SHIFT);
        let patched = Corrupt::new(snapshot).patch(state.addr, word);
        let ctx = Context::new(&patched, BundleView::new(bundle)).unwrap();
        assert_eq!(ctx.notify_state(key, &read), Some(word));
    }
}

/// Route 1's input: the reference scan over the enumerated storage.
#[cfg(test)]
mod discovery_scan_tests {
    use super::*;
    use crate::testkit;

    fn named<'l>(list: &'l TaskList, view: BundleView<'_>, name: &str) -> &'l Task {
        list.tasks
            .iter()
            .find(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(view).contains(name)))
            .unwrap_or_else(|| panic!("a task named {name}"))
    }

    /// The scan offers the owner a held handle names: on the
    /// foreign-runtime pair the joiner's `JoinHandle` names a task no
    /// enumerated list owns, and the scan offers that Header, by the
    /// reference's own kind, with no wait diagnosed. After admission
    /// the hidden runtime's own tasks are scanned in turn, and
    /// reference nothing outside the list.
    #[test]
    fn test_the_scan_offers_the_referenced_owner() {
        for set in testkit::FIXTURE_SETS {
            let (bundle, snapshot) = testkit::load(set, "foreign-runtime");
            let ctx = testkit::context(&bundle, &snapshot);
            let mut e = testkit::enumerate(&ctx, &snapshot);
            let listed = e.list.tasks.len();
            let read = ReadContext::none();

            let ids: Vec<TaskRecordId> = e.list.records.records().map(|(id, _)| id).collect();
            let mut budget = ScanBudget::default();
            let found = ctx.scan_records(&ids, &mut e.list, &read, &mut budget);
            assert!(budget.inline_visits > 0, "[{set}] the scan visited");
            let alone: Vec<(u64, DiscoveryRoute)> = found
                .iter()
                .filter(|c| !e.list.contains(c.addr()))
                .map(|c| (c.addr(), c.route()))
                .collect();

            // The scan above marked every record scanned, so the
            // sweep is driven over a fresh enumeration.
            let mut e = testkit::enumerate(&ctx, &snapshot);
            e.discover(&ctx, &[]);
            let joined = named(&e.list, ctx.view, "foreign_runtime::joined").addr.0;
            assert_eq!(
                alone,
                vec![(joined, DiscoveryRoute::Scanned(ReferenceSource::JoinHandle))],
                "[{set}] the scan offers the joined task, once, by its kind"
            );
            assert_eq!(
                DiscoveryRoute::Scanned(ReferenceSource::JoinHandle).to_string(),
                "a JoinHandle scanned in an enumerated task's storage"
            );

            // The later scans: what the admitted runtime owns was
            // scanned as new storage, and references only what is
            // listed — walked again here to look at what it offers.
            let hidden = e.runtimes[1].owner_key();
            let later_ids: Vec<TaskRecordId> = e
                .list
                .records
                .records()
                .filter(|(_, r)| r.owner().known() == Some(hidden))
                .map(|(id, _)| id)
                .collect();
            assert!(
                e.list.tasks.len() > listed && !later_ids.is_empty(),
                "[{set}] discovery admitted tasks"
            );
            let before = budget.inline_visits;
            let later = ctx.scan_records(&later_ids, &mut e.list, &read, &mut budget);
            assert!(
                budget.inline_visits > before,
                "[{set}] the later scans read storage"
            );
            let outside: Vec<u64> = later
                .iter()
                .map(Candidate::addr)
                .filter(|addr| !e.list.contains(*addr))
                .collect();
            assert!(outside.is_empty(), "[{set}] {outside:x?}");
        }
    }

    /// A spent budget is reported, not absorbed: under a one-visit cap
    /// the scan reaches no handle, the hidden runtime stays hidden, and
    /// the list's errors say the budget was spent; under the defaults
    /// nothing is spent and nothing is said.
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
        assert!(
            runtimes > capped_runtimes,
            "{runtimes} vs {capped_runtimes}"
        );
        assert!(sets > capped_sets, "{sets} vs {capped_sets}");
        assert!(list.tasks.len() > capped_list.tasks.len());
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

/// The target as the discovery sweep sees it: what each item of work
/// does to memory, over the session's owner vectors and registries.
/// [`work::sweep`] decides what runs and in which order; this decides
/// what each run reads, and files what it found and what failed into
/// the list, the way the rounds it replaced did.
///
/// [`work::sweep`]: super::work::sweep
struct Live<'a, 'r, 'b, T: Target> {
    ctx: &'a Context<'b, T>,
    runtimes: &'a mut Vec<RuntimeRef<'b>>,
    sets: &'a mut Vec<LocalSetRef<'b>>,
    registries: &'a mut Registries,
    thread_ids: &'a [(u64, u32)],
    excluded: &'a [u64],
    read: &'a ReadContext<'r>,
    /// The wheel and io harvests' cycle guards, spanning every
    /// runtime's harvest of the run.
    wheel_visited: HashSet<u64>,
    io_visited: HashSet<u64>,
}

impl<'b, T: Target> Live<'_, '_, 'b, T> {
    fn runtime(&self, owner: OwnerKey) -> Option<RuntimeRef<'b>> {
        let OwnerKey::Runtime { handle, .. } = owner else {
            return None;
        };
        self.runtimes
            .iter()
            .find(|r| r.handle.addr == handle)
            .cloned()
    }
}

impl<'b, T: Target> DiscoveryWorld for Live<'_, '_, 'b, T> {
    fn enumerate(&mut self, owner: OwnerKey, list: &mut TaskList) {
        match owner {
            OwnerKey::Runtime { handle, .. } => {
                let Some(runtime) = self.runtime(owner) else {
                    list.errors
                        .push(anyhow!("{owner} was scheduled but never admitted"));
                    return;
                };
                if let Err(e) = self.ctx.find_shared(&runtime).and_then(|shared| {
                    self.ctx
                        .enumerate_owned(shared, owner, runtime.owned_id, list)
                }) {
                    list.errors
                        .push(e.context(format!("failed to enumerate the runtime at {handle:#x}")));
                }
            }
            OwnerKey::LocalSet { shared } => {
                let Some(set) = self.sets.iter().find(|s| s.shared.addr == shared).cloned() else {
                    list.errors
                        .push(anyhow!("{owner} was scheduled but never admitted"));
                    return;
                };
                if let Err(e) = self.ctx.enumerate_local(&set, list) {
                    list.errors.push(
                        e.context(format!("failed to enumerate the local set at {shared:#x}")),
                    );
                }
            }
        }
    }

    fn scan(
        &mut self,
        id: TaskRecordId,
        list: &mut TaskList,
        budget: &mut ScanBudget,
    ) -> Vec<Candidate> {
        self.ctx.scan_records(&[id], list, self.read, budget)
    }

    fn harvest(
        &mut self,
        owner: OwnerKey,
        registry: Registry,
        list: &mut TaskList,
    ) -> Vec<Candidate> {
        // Only a runtime has registries, and only an admitted one is
        // scheduled; a set here is nothing to read.
        let Some(runtime) = self.runtime(owner) else {
            return Vec::new();
        };
        let runtimes = std::slice::from_ref(&runtime);
        match registry {
            Registry::Timers => {
                let (found, errors) = self.ctx.wheel_task_pointers(
                    runtimes,
                    &mut self.wheel_visited,
                    self.registries,
                );
                list.errors.extend(errors);
                found
            }
            Registry::Io => {
                let (found, errors) =
                    self.ctx
                        .io_task_pointers(runtimes, &mut self.io_visited, self.registries);
                list.errors.extend(errors);
                found
            }
            Registry::BlockingQueue => {
                let mut found = Vec::new();
                if let Err(e) = self
                    .ctx
                    .queued_blocking(&runtime, &mut found, &mut list.errors)
                {
                    list.errors.push(e.context(format!(
                        "failed to walk the blocking queue of the runtime at {:#x}",
                        runtime.handle.addr
                    )));
                }
                found
            }
        }
    }

    fn validate(&mut self, candidate: Candidate, list: &mut TaskList) -> Vec<OwnerKey> {
        let (had_runtimes, had_sets) = (self.runtimes.len(), self.sets.len());
        self.ctx.observe_candidate(
            candidate,
            self.excluded,
            self.thread_ids,
            self.runtimes,
            self.sets,
            list,
            self.read,
        );
        self.runtimes[had_runtimes..]
            .iter()
            .map(RuntimeRef::owner_key)
            .chain(self.sets[had_sets..].iter().map(LocalSetRef::owner_key))
            .collect()
    }
}

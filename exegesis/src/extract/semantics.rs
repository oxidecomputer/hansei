// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sparse identity seeds, the library-layout bindings, and the reviewed
//! poll programs. Compiler candidates retain an unavailable storage
//! boundary until a reviewed defining-origin convention can bind them;
//! Tokio and futures-util resource, container and scheduler facts bind
//! from the walk contract's own roots, so each is a layout fact about the
//! exact type it names.
//!
//! A poll program is emitted only under a reviewed rule — a compiler
//! coroutine's suspended states, the four std pointer adapters, tracing's
//! `Instrumented` — whose origin and layout both check out on this
//! binary, and only for a type that is positively a future: a task's
//! root, a `Future::poll` self type, a bound coroutine, or the static
//! delegate of a parent whose own program is bound. That closure is a
//! least fixed point over the emitted programs; nothing about a
//! wrapper's shape, member count or drop glue seeds it.

use super::emitter::Emitter;
use super::passes::{members_of, state_name};
use super::paths::OwnedLoc;
use super::sweep::PollSource;
use crate::TypeId;
use crate::bundle::names::coroutine_kind;
use crate::bundle::origin::{git_origin, registry_origin};
use crate::bundle::{
    AccessBinding, AccessKind, AcquiresForBinding, BundleTypeId, ConnectedBinding,
    ContainerBinding, ContainerKind, Continuation, CoroutineLayout, CoroutinePhase, CoroutineState,
    DynFutureLayout, DynStreamCase, DynStreamLayout, ExtraCase, FarEndBinding, FarEndState,
    FutureEvidence, FutureFacts, FutureTarget, HashTableBinding, HttpClientBinding,
    HttpConnBinding, HttpPoolBinding, HttpRequestBinding, HttpRequestTarget, HttpRole,
    HttpServerBinding, HttpServiceBinding, IoOperationBinding, IoOperationKind, IoRouteBinding,
    IoRouteStep, IoSocket, LayoutSelection, LockBinding, LockWord, MemberRef, PollAction, PollCase,
    PollProgram, RefcountBinding, ResourceBinding, ResourceKind, SchedulerBinding, SchedulerClass,
    SelectBinding, Selector, SemanticIssue, SemanticIssueKind, SemanticOrigin, SemanticOriginId,
    SemanticRule, SemanticRuleId, SemanticRuleKind, SemanticTable, SendableBinding,
    SourceFileEvidence, SourceLoc, Step, StoragePolicy, StrRef, StreamPeerBinding, StringInterner,
    TaskEntryId, TaskFutureEntry, TlsSessionBinding, TlsStreamBinding, TypeDef, TypeSemantics,
    TypeTable, TypedPath, WalkOutcome, WalkRole, WalksTable, container_roles, container_routes,
    required_resource_roles, required_resource_routes, scheduler_role, semantic_path_target,
    socket_roles,
};
use crate::detect::Family;
use crate::detect::adapters::{
    self, H1Role, HashTableLayout, HttpDispatcherLayout, HttpRequestKind, HttpRequestLayout,
    InstrumentedLayout, Pointee, PointerDecline, SelectLayout, StdAdapter, WidePointer, hash_table,
    hyper_h1, hyper_pool, request,
};
use crate::detect::semantics::{
    DROPSHOT_HANDLER_V0_17_0, DROPSHOT_SERVER_V0_17_0, EXTRA_INNER_SET_SLOT,
    FUTURES_UTIL_ADAPTERS_V0_3_30, GitConvention, HASHBROWN_TABLE_V0_12_3, HTTP_REQUEST_V1_0_0,
    HYPER_H1_CONN_V1_6_0, HYPER_RUSTLS_STREAM_V0_27_0, HYPER_UTIL_AUTO_CONN_V0_1_10,
    HYPER_UTIL_CONNECTED_V0_1_10, HYPER_UTIL_IO_V0_1_10, HYPER_UTIL_POOL_V0_1_16,
    HYPER_UTIL_RESPONSE_V0_1_10, HYPER_UTIL_TOKIO_SLEEP_V0_1_10, LibraryConvention,
    PARKING_LOT_RAW_MUTEX_V0_11_0, REQWEST_CONN_READ_SLOT, REQWEST_CONN_V0_12_14,
    REQWEST_COOKIE_V0_12_24, REQWEST_PENDING_REQUEST_V0_12_0, RUSTLS_SESSION_V0_23_23,
    RustcConvention, SPROCKETS_TLS_CLIENT_D2B68E4, SPROCKETS_TLS_SERVER_D2B68E4,
    SPROCKETS_TLS_STREAM_D2B68E4, TOKIO_INTERVAL_TICK_V1_47, TOKIO_RUSTLS_HANDSHAKE_V0_26_0,
    TOKIO_RUSTLS_STREAM_V0_26_0, TOKIO_SELECT_V1_47, TOKIO_STREAM_MAP_V0_1_14,
    TOKIO_STREAM_WATCH_V0_1_14, TOKIO_UTIL_REUSABLE_BOX_V0_7_11, TOWER_RETRY_V0_5_2,
    TRACING_INSTRUMENTED_V0_1_40, library_convention, rustc_core_pending_convention,
    rustc_coroutine_convention, rustc_dyn_future_abi_convention, rustc_std_adapter_convention,
    rustc_std_futex_mutex_convention, rustc_std_refcount_convention, tokio_acquire_owner,
    tokio_state_protocol,
};

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What the defining units of a compiler-storage candidate said about
/// the convention its layout follows, decided where the reader's origins
/// are at hand and carried to the binder by bundle id.
#[derive(Clone, Debug)]
pub(super) enum CompilerVerdict {
    /// Every defining unit's producer falls inside one reviewed range.
    Supported {
        /// The canonical definition's producer, as the origin records it.
        producer: String,
        convention: &'static RustcConvention,
    },
    /// Why no convention applies: the reader's decline, spelled out.
    Declined(String),
}

/// Which reviewed compiler convention a verdict is asked under: each is
/// a separate review of a separate fact, over the same defining units.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum Reviewed {
    Coroutine,
    StdAdapters,
    DynFutureAbi,
    CorePending,
    StdRefcount,
    StdFutexMutex,
}

impl Reviewed {
    /// The convention selector the verdict runs a producer through.
    pub(super) fn select(self, producer: &str) -> Option<&'static RustcConvention> {
        match self {
            Reviewed::Coroutine => rustc_coroutine_convention(producer),
            Reviewed::StdAdapters => rustc_std_adapter_convention(producer),
            Reviewed::DynFutureAbi => rustc_dyn_future_abi_convention(producer),
            Reviewed::CorePending => rustc_core_pending_convention(producer),
            Reviewed::StdRefcount => rustc_std_refcount_convention(producer),
            Reviewed::StdFutexMutex => rustc_std_futex_mutex_convention(producer),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AdapterKind {
    Box,
    MutRef,
    PinBox,
    PinMutRef,
}

impl AdapterKind {
    fn poll_rule(self) -> SemanticRuleKind {
        match self {
            AdapterKind::Box => SemanticRuleKind::StdBoxPoll,
            AdapterKind::MutRef => SemanticRuleKind::StdMutRefPoll,
            AdapterKind::PinBox => SemanticRuleKind::StdPinBoxPoll,
            AdapterKind::PinMutRef => SemanticRuleKind::StdPinMutRefPoll,
        }
    }

    fn access_rule(self) -> SemanticRuleKind {
        match self {
            AdapterKind::Box => SemanticRuleKind::StdBoxAccess,
            AdapterKind::MutRef => SemanticRuleKind::StdMutRefAccess,
            AdapterKind::PinBox => SemanticRuleKind::StdPinBoxAccess,
            AdapterKind::PinMutRef => SemanticRuleKind::StdPinMutRefAccess,
        }
    }

    fn access(self) -> AccessKind {
        match self {
            AdapterKind::Box | AdapterKind::PinBox => AccessKind::Owned,
            AdapterKind::MutRef | AdapterKind::PinMutRef => AccessKind::Borrowed,
        }
    }
}

/// A wide pointer to a trait object, by bundle id: the struct, its two
/// members and their types, the trait object, whether that object is a
/// bare `dyn Future`, and the verdict on the vtable ABI the struct's
/// defining units were compiled under.
#[derive(Clone, Debug)]
struct DynSeed {
    wide: BundleTypeId,
    pointer: String,
    vtable: String,
    data_ptr: BundleTypeId,
    vtable_ptr: BundleTypeId,
    trait_ty: BundleTypeId,
    future_trait: bool,
    abi: CompilerVerdict,
}

#[derive(Clone, Debug)]
enum PointeeSeed {
    Sized(BundleTypeId),
    Dyn(DynSeed),
}

/// A std adapter as the raw screen saw it, carried by bundle id: the
/// kind, the `Pin` member and its `Ptr` where there is one, what it
/// points at, and the verdict on the adapter convention.
#[derive(Clone, Debug)]
struct AdapterSeed {
    kind: AdapterKind,
    pin: Option<(String, BundleTypeId)>,
    pointee: PointeeSeed,
    compiler: CompilerVerdict,
}

#[derive(Clone, Debug)]
struct InstrumentedSeed {
    inner: String,
    future: BundleTypeId,
}

/// A reviewed third-party wrapper as its screen saw it, by bundle id.
/// The layout is the screen's. Which crate owns it is the kind's, and
/// so is what proves the rule: a sole-member forwarder binds on the
/// layout alone, and every other seed on the origin its poll or method
/// declarations name.
#[derive(Clone, Debug)]
enum LibrarySeed {
    /// futures-util's `map::Map` enum: the incomplete variant and the
    /// member inside it, the complete variant, and the mapped future.
    Map {
        incomplete: String,
        future_member: String,
        complete: String,
        future: BundleTypeId,
    },
    /// The public `Map` newtype the `delegate_all!` macro builds.
    MapWrapper(String, BundleTypeId),
    /// `MapErr`, another such newtype.
    MapErr(String, BundleTypeId),
    /// `IntoFuture`.
    IntoFuture(String, BundleTypeId),
    /// hyper-util's `TokioSleep` over `tokio::time::Sleep`.
    TokioSleep(String, BundleTypeId),
    /// tokio's `Coop<F>` over the `F` it budgets.
    Coop(String, BundleTypeId),
    /// futures-util's `Next<'_, St>`: the `&mut St` member and the
    /// stream it targets — a stream, which the route names without
    /// proving it a future.
    Next(String, BundleTypeId),
    /// tokio-stream's `WatchStream<T>` over the `ReusableBoxFuture` it
    /// owns: a storage route, not a future.
    WatchStream(String, BundleTypeId),
    /// tokio-util's `ReusableBoxFuture<'_, T>` over its pinned box: a
    /// storage route to the trait object inside.
    ReusableBox {
        boxed: String,
        pin: (String, BundleTypeId),
        dyn_: DynSeed,
    },
    /// The `PollFn` tokio's `Interval::tick` awaits: the member holding
    /// the closure, the closure's one capture and the `Interval` it
    /// references, the interval's member holding its pinned box and
    /// that box — and where the closure environment was declared, the
    /// origin the rule is read off, as the `select!`'s is.
    IntervalTick {
        closure: String,
        interval_ref: String,
        interval: BundleTypeId,
        delay: String,
        boxed: BundleTypeId,
        source: Option<PollSource>,
    },
    /// futures-util's `Pending<T>`, the future `futures::future::pending()`
    /// returns: `poll` returns `Poll::Pending` and does nothing else.
    /// The layout is the whole of the evidence — a zero-sized future
    /// over a `PhantomData<T>` holds nothing to poll and cannot produce
    /// a `T` — and it has to be: its poll is a constant every build
    /// inlines away, and neither it nor the constructor leaves a
    /// declaration in the DWARF to read a version off. So the seed
    /// carries nothing but the fact.
    Pending,
    /// hyper's `Connection` of either side — `client::conn::http1`'s
    /// over the dispatcher in its `inner`, `server::conn::http1`'s over
    /// the one in its `conn` — which its poll forwards to.
    HyperConnection(String, BundleTypeId),
    /// tokio-rustls's `Connect`, `Accept` or their fallible twins: the
    /// member holding the `MidHandshake` its poll forwards to.
    TokioRustlsHandshake(String, BundleTypeId),
    /// hyper's `UpgradeableConnection` of either side: the member
    /// holding the `Option<Connection>`, the option, the connection's
    /// member holding the dispatcher, and the dispatcher its poll
    /// reaches through `Some`'s connection.
    HyperUpgradeable {
        inner: String,
        option: BundleTypeId,
        dispatcher_member: String,
        dispatcher: BundleTypeId,
    },
    /// hyper-util's `server::conn::auto::UpgradeableConnection<I, S,
    /// E>`: the member holding its state, the state enum, and under
    /// its `H1` the member holding hyper's server-side upgradeable
    /// connection and that connection.
    HyperUtilAuto {
        state: String,
        state_ty: BundleTypeId,
        h1_conn: String,
        h1: BundleTypeId,
    },
    /// futures-util's `Either<A, B>`: each variant's name and the future
    /// its `__0` holds.
    Either {
        left: (String, BundleTypeId),
        right: (String, BundleTypeId),
    },
    /// tower's retry `ResponseFuture`: the member holding its state, the
    /// state enum, the variant and member holding the service's future
    /// and the policy's, and the state holding neither.
    TowerRetry {
        state: String,
        state_ty: BundleTypeId,
        called: (String, String, BundleTypeId),
        waiting: (String, String, BundleTypeId),
        retrying: String,
    },
    /// reqwest's cookie layer's `ResponseFuture` over the service's
    /// future in `future`.
    ReqwestCookie(String, BundleTypeId),
    /// hyper-util's legacy `ResponseFuture`: its `SyncWrapper` member,
    /// the wrapper's one member, and the pinned box it holds.
    HyperUtilResponse {
        inner: String,
        wrapped: String,
        boxed: BundleTypeId,
    },
}

impl LibrarySeed {
    fn rule_kind(&self) -> SemanticRuleKind {
        match self {
            LibrarySeed::Either { .. } => SemanticRuleKind::FuturesUtilEither,
            LibrarySeed::TowerRetry { .. } => SemanticRuleKind::TowerRetry,
            LibrarySeed::ReqwestCookie(..) => SemanticRuleKind::ReqwestCookie,
            LibrarySeed::HyperUtilResponse { .. } => SemanticRuleKind::HyperUtilResponseFuture,
            LibrarySeed::Pending => SemanticRuleKind::FuturesUtilPending,
            LibrarySeed::HyperConnection(..) | LibrarySeed::HyperUpgradeable { .. } => {
                SemanticRuleKind::HyperH1Conn
            }
            LibrarySeed::HyperUtilAuto { .. } => SemanticRuleKind::HyperUtilAutoConn,
            LibrarySeed::TokioRustlsHandshake(..) => SemanticRuleKind::TokioRustlsHandshake,
            LibrarySeed::Map { .. } | LibrarySeed::MapWrapper(..) => {
                SemanticRuleKind::FuturesUtilMap
            }
            LibrarySeed::MapErr(..) => SemanticRuleKind::FuturesUtilMapErr,
            LibrarySeed::IntoFuture(..) => SemanticRuleKind::FuturesUtilIntoFuture,
            LibrarySeed::TokioSleep(..) => SemanticRuleKind::HyperUtilTokioSleep,
            LibrarySeed::Coop(..) => SemanticRuleKind::TokioCoop,
            LibrarySeed::Next(..) => SemanticRuleKind::FuturesUtilNext,
            LibrarySeed::WatchStream(..) => SemanticRuleKind::TokioStreamWatchStream,
            LibrarySeed::ReusableBox { .. } => SemanticRuleKind::TokioUtilReusableBox,
            LibrarySeed::IntervalTick { .. } => SemanticRuleKind::TokioIntervalTick,
        }
    }

    /// The crate whose reviewed implementation the rule runs, and the
    /// convention its version has to fall inside. Not asked of a seed
    /// that binds on its layout.
    fn convention(&self) -> &'static LibraryConvention {
        match self {
            LibrarySeed::TokioSleep(..) => &HYPER_UTIL_TOKIO_SLEEP_V0_1_10,
            LibrarySeed::HyperConnection(..) | LibrarySeed::HyperUpgradeable { .. } => {
                &HYPER_H1_CONN_V1_6_0
            }
            LibrarySeed::HyperUtilAuto { .. } => &HYPER_UTIL_AUTO_CONN_V0_1_10,
            LibrarySeed::TokioRustlsHandshake(..) => &TOKIO_RUSTLS_HANDSHAKE_V0_26_0,
            LibrarySeed::HyperUtilResponse { .. } => &HYPER_UTIL_RESPONSE_V0_1_10,
            LibrarySeed::TowerRetry { .. } => &TOWER_RETRY_V0_5_2,
            LibrarySeed::ReqwestCookie(..) => &REQWEST_COOKIE_V0_12_24,
            LibrarySeed::WatchStream(..) => &TOKIO_STREAM_WATCH_V0_1_14,
            LibrarySeed::ReusableBox { .. } => &TOKIO_UTIL_REUSABLE_BOX_V0_7_11,
            LibrarySeed::IntervalTick { .. } => &TOKIO_INTERVAL_TICK_V1_47,
            _ => &FUTURES_UTIL_ADAPTERS_V0_3_30,
        }
    }

    /// The declarations the rule's origin is read off, and what they
    /// declare: a `poll` for a wrapper, the type's own methods for a
    /// storage route, and the closure for the tick's `PollFn` — whose
    /// `poll` is core's and names no tokio file, so the closure
    /// environment's declaration is the one record of where the body it
    /// runs was written.
    fn origin_sources<'s>(
        &'s self,
        seed: &'s Seed,
    ) -> (Cow<'s, BTreeSet<PollSource>>, &'static str) {
        match self {
            LibrarySeed::IntervalTick { source, .. } => {
                (Cow::Owned(source.iter().cloned().collect()), "closure")
            }
            _ if self.origin_is_the_type() => (Cow::Borrowed(&seed.type_sources), "method"),
            _ => (Cow::Borrowed(&seed.poll_sources), "poll"),
        }
    }

    /// Whether the rule's origin is the type's own method declarations
    /// rather than a `poll`'s: the two storage routes are no futures
    /// and have no poll to be declared anywhere.
    fn origin_is_the_type(&self) -> bool {
        matches!(
            self,
            LibrarySeed::WatchStream(..) | LibrarySeed::ReusableBox { .. }
        )
    }

    /// Whether the type gets a record on the strength of its screen
    /// alone: a route that is polled through and never polled — a
    /// stream over the box it owns — is never proved a future by
    /// anything, and a declined origin has nowhere else to be recorded.
    fn records_on_its_screen(&self) -> bool {
        matches!(
            self,
            LibrarySeed::WatchStream(..) | LibrarySeed::ReusableBox { .. }
        )
    }

    /// Whether the layout the screen proved is the whole of the rule's
    /// evidence. A wrapper whose one member is the future its own
    /// template parameter names can poll that member or nothing: there
    /// is nothing else in it to wait on, so the delegation is read off
    /// the layout and needs no declaration to say which implementation
    /// forwards it. That matters because a `poll` the optimizer folded
    /// into an identical instantiation's leaves no declaration at all,
    /// and a rule whose evidence came and went with the fold would bind
    /// or decline by build. The map's state machine, the `select!`
    /// mask and the box's refill keep the origin proof: their behavior
    /// is read from the source, not the layout. hyper-util's sleep is
    /// the same shape as these but keeps the proof too, for want of a
    /// hyper-util layout origin to file it under. `Pending` is the
    /// extreme case: nothing in it to poll at all, and no declaration
    /// left in any build to read a proof from.
    fn origin_is_the_layout(&self) -> bool {
        matches!(
            self,
            LibrarySeed::Coop(..)
                | LibrarySeed::MapWrapper(..)
                | LibrarySeed::MapErr(..)
                | LibrarySeed::IntoFuture(..)
                | LibrarySeed::Pending
        )
    }
}

/// A `select!`'s `PollFn` as its screen saw it, by bundle id: the
/// closure and its two captures, what each points at, the tuple's
/// members in branch order, and where the closure environment was
/// declared — the origin the rule is read off.
#[derive(Clone, Debug)]
struct SelectSeed {
    closure: String,
    mask: String,
    mask_word: BundleTypeId,
    futures: String,
    tuple: BundleTypeId,
    branches: Vec<(String, BundleTypeId)>,
    source: Option<PollSource>,
    /// Where each branch's arm is written, parallel to `branches`.
    arms: Vec<ArmSite>,
}

/// What a closure environment's body function says about it: where the
/// closure was declared, joined the way a poll declaration's file is so
/// the same registry-path check applies, and — for a `select!`'s — the
/// arms that body recorded, each keyed by its branch's canonical future
/// type. One lookup answers both.
pub(super) struct EnvFacts {
    pub(super) source: Option<PollSource>,
    pub(super) arms: Vec<(TypeId, Vec<OwnedLoc>)>,
}

/// What the join found for one branch of a `select!`: the source line
/// its arm's pattern is written on, read from the closure the macro
/// polls the branches in, where the arm binds a name and the join could
/// settle which arm is the branch's.
#[derive(Clone, Debug)]
enum ArmSite {
    /// The arm's pattern binds, and every binding agrees on where.
    Written(OwnedLoc),
    /// The arm's pattern binds nothing — `_ = …`, `Ok(()) = …` — the
    /// ordinary shape, and no defect: rustc records no scope for it.
    Unbound,
    /// Something the join could not settle, with the reason: the
    /// branch's type shared with another branch or another arm, no
    /// arm of its type at all, or bindings on different lines.
    Declined(Decline),
}

/// hyper's HTTP/1 `Dispatcher` as its screen saw it, by bundle id: the
/// role, and the type every route of the connection binding lands on.
/// The member names are the reviewed layout's ([`hyper_h1`]); the
/// binder holds each route to the final table and to these targets.
#[derive(Clone, Debug)]
struct HttpSeed {
    role: H1Role,
    keep_alive: BundleTypeId,
    reading: BundleTypeId,
    writing: BundleTypeId,
    method: BundleTypeId,
    method_inner: BundleTypeId,
    read_continue_kind: BundleTypeId,
    read_body_kind: BundleTypeId,
    write_body_kind: BundleTypeId,
    is_closing: BundleTypeId,
    client: Option<HttpClientSeed>,
    server: Option<HttpServerSeed>,
}

#[derive(Clone, Debug)]
struct HttpClientSeed {
    callback: BundleTypeId,
    retry: BundleTypeId,
    no_retry: BundleTypeId,
    rx: BundleTypeId,
    want: BundleTypeId,
}

/// The server dispatch by bundle id: the handler's pinned box — the
/// `Pin`'s member holding the `Box`, the box, and the `Option` behind
/// it — the header-read timer's flag, the two words of the timeout it
/// is armed for, and the timer's own box: the `Pin`'s member, the
/// `Box`'s data pointer member, and that pointer.
#[derive(Clone, Debug)]
struct HttpServerSeed {
    in_flight_member: String,
    in_flight_box: BundleTypeId,
    in_flight: BundleTypeId,
    header_read_timeout_running: BundleTypeId,
    header_read_timeout_secs: BundleTypeId,
    header_read_timeout_nanos: BundleTypeId,
    header_read_timer_pin: String,
    header_read_timer_pointer: String,
    header_read_timer: BundleTypeId,
    /// What the service keeps, where the screen recognized the service:
    /// the peer address's type, the context type, and the service's
    /// own method declarations, which are what its crate's version is
    /// read off.
    service: Option<HttpServiceSeed>,
}

#[derive(Clone, Debug)]
struct HttpServiceSeed {
    peer: BundleTypeId,
    context: BundleTypeId,
    sources: BTreeSet<PollSource>,
}

/// A type keeping a request's words as its screen saw it, by bundle
/// id: which crate's type, the method's enum, the two words of the
/// target's text, and — for the two that are no future — the type's
/// own method declarations, which its crate's version is read off. A
/// future's version comes off its `poll` like any other's.
#[derive(Clone, Debug)]
struct RequestSeed {
    kind: HttpRequestKind,
    method_inner: BundleTypeId,
    target_ptr: BundleTypeId,
    target_len: BundleTypeId,
    sources: BTreeSet<PollSource>,
}

/// A hash table as its screen saw it, by bundle id: which of the four
/// types holds it, the types of the three words the walk reads and of a
/// bucket, and the declarations of hashbrown's own map inside it, which
/// the hashbrown release is read off.
#[derive(Clone, Debug)]
struct TableSeed {
    kind: adapters::HashTableKind,
    bucket_mask: BundleTypeId,
    ctrl: BundleTypeId,
    items: BundleTypeId,
    bucket: BundleTypeId,
    sources: BTreeSet<PollSource>,
}

/// hyper-util's pool as its screen saw it, by bundle id: the reaper's
/// routes — the pool's strong count, its idle map and that map's
/// bucket, the key text and the idle list from the bucket, the list's
/// element and its sender's `want` pointer — or a checkout's key text
/// and `want` pointer; and the type's own method declarations, which
/// hyper-util's version is read off.
#[derive(Clone, Debug)]
enum PoolSeed {
    Reaper {
        strong: BundleTypeId,
        idle: BundleTypeId,
        bucket: BundleTypeId,
        key_ptr: BundleTypeId,
        key_len: BundleTypeId,
        entries_ptr: BundleTypeId,
        entries_len: BundleTypeId,
        entry: BundleTypeId,
        want: BundleTypeId,
        /// The `PoolClient`'s `conn_info`, where its type was emitted.
        conn_info: Option<BundleTypeId>,
        sources: BTreeSet<PollSource>,
    },
    Checkout {
        key_ptr: BundleTypeId,
        key_len: BundleTypeId,
        want: BundleTypeId,
        conn_info: Option<BundleTypeId>,
        sources: BTreeSet<PollSource>,
    },
}

/// The screen's reaper layout by bundle id. `None` when a type it names
/// was not emitted.
fn pool_reaper_seed(
    layout: adapters::PoolReaperLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    sources: BTreeSet<PollSource>,
) -> Option<PoolSeed> {
    Some(PoolSeed::Reaper {
        strong: bundle_id(layout.strong)?,
        idle: bundle_id(layout.idle)?,
        bucket: bundle_id(layout.bucket)?,
        key_ptr: bundle_id(layout.key_ptr)?,
        key_len: bundle_id(layout.key_len)?,
        entries_ptr: bundle_id(layout.entries_ptr)?,
        entries_len: bundle_id(layout.entries_len)?,
        entry: bundle_id(layout.entry)?,
        want: bundle_id(layout.want)?,
        conn_info: layout.conn_info.and_then(&bundle_id),
        sources,
    })
}

/// The screen's checkout layout by bundle id.
fn pool_checkout_seed(
    layout: adapters::PoolCheckoutLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    sources: BTreeSet<PollSource>,
) -> Option<PoolSeed> {
    Some(PoolSeed::Checkout {
        key_ptr: bundle_id(layout.key_ptr)?,
        key_len: bundle_id(layout.key_len)?,
        want: bundle_id(layout.want)?,
        conn_info: layout.conn_info.and_then(&bundle_id),
        sources,
    })
}

/// The screen's table layout by bundle id. `None` when a type it names
/// was not emitted: the bucket is reached only through a `PhantomData`,
/// so it is in the table only where the display program reserved it.
fn table_seed(
    layout: HashTableLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    sources: BTreeSet<PollSource>,
) -> Option<TableSeed> {
    Some(TableSeed {
        kind: layout.kind,
        bucket_mask: bundle_id(layout.bucket_mask)?,
        ctrl: bundle_id(layout.ctrl)?,
        items: bundle_id(layout.items)?,
        bucket: bundle_id(layout.bucket)?,
        sources,
    })
}

#[derive(Default)]
pub(super) struct Seed {
    polls: BTreeSet<String>,
    poll_sources: BTreeSet<PollSource>,
    coroutine_candidate: bool,
    compiler: Option<CompilerVerdict>,
    resource: Option<ResourceKind>,
    container: Option<ContainerKind>,
    adapter: Option<AdapterSeed>,
    /// Why the std adapter screen declined a type of an adapter's
    /// shape: a `Box` or `&mut` whose definitions name several targets.
    /// The continuation's reason where the type earns a record.
    adapter_declined: Option<Decline>,
    instrumented: Option<InstrumentedSeed>,
    library: Option<LibrarySeed>,
    select: Option<SelectSeed>,
    /// hyper's HTTP/1 dispatcher, where the type is one: the resource
    /// whose words are the connection's verdict.
    http: Option<HttpSeed>,
    /// A type keeping a request's words, where the type is one: a fact
    /// read wherever a chain or a frame holds a value of it.
    request: Option<RequestSeed>,
    /// A hash table, where the type is one: a fact read wherever a value
    /// of it is scanned as storage.
    table: Option<TableSeed>,
    /// hyper-util's pool reaper or checkout, where the type is one: a
    /// fact read wherever a frame holds a value of it.
    pool: Option<PoolSeed>,
    /// One of tokio's forwarding streams or sockets, where the type is
    /// one: the route a read or a write through it takes, which binds
    /// only where it ends at a socket.
    io_route: Option<IoRouteSeed>,
    /// One of tokio's io operation futures, where the type is one: a
    /// resource only over a stream whose route ends at a socket.
    io_op: Option<IoOpSeed>,
    /// rustls's connection state, where the type is it: the type's own
    /// method declarations, which its release is read off.
    tls_session: Option<BTreeSet<PollSource>>,
    /// Whether the type is tokio-rustls's `MidHandshake`: an io operation
    /// over the stream it handshakes on, whose origin is its `poll`.
    handshake: bool,
    /// The linkage names of the type's `hyper::rt::Read::poll_read`, by
    /// which a stream trait object's vtable names it.
    read_symbols: BTreeSet<String>,
    /// The linkage names of the type's hyper-util `ExtraInner::set`, by
    /// which a `Connected`'s extras vtable names it.
    extra_symbols: BTreeSet<String>,
    /// hyper-util's `Connected`, where the type is it.
    connected: Option<ConnectedSeed>,
    /// A reviewed handshake's coroutine, where the type is one: the
    /// convention its body's file is reviewed under, and where that
    /// body was declared.
    far_end: Option<(&'static FarEndRule, Option<PollSource>)>,
    /// A refcounted allocation's header, where the type is one: the
    /// member its value sits in, and the verdict on its defining units.
    refcount: Option<(&'static str, CompilerVerdict)>,
    /// A raw lock of a reviewed implementation, where the type is one.
    lock: Option<LockSeed>,
    /// core's `Pending<T>` as its screen saw it: the compiler verdict on
    /// its defining units, which is the whole of the rule's origin. The
    /// layout is the screen's; there is no member to route through.
    pending: Option<CompilerVerdict>,
    /// Where the type's own methods were declared, for a library rule
    /// whose origin is the type rather than a `poll` (a `WatchStream`
    /// has none, nor does the `StreamMap` container); empty otherwise.
    type_sources: BTreeSet<PollSource>,
}

impl Seed {
    /// Whether the seed alone puts a record in the table: identity,
    /// storage or a library binding, as opposed to an adapter or
    /// wrapper screen that only matters once something proves the type
    /// a future or its pointee interesting.
    fn is_own_record(&self) -> bool {
        !self.polls.is_empty()
            || self.coroutine_candidate
            || self.resource.is_some()
            || self.container.is_some()
            || self.select.is_some()
            || self.http.is_some()
            || self.request.is_some()
            || self.table.is_some()
            || self.pool.is_some()
            || self.connected.is_some()
            || self.io_op.is_some()
            || self.handshake
            || self.refcount.is_some()
            || self.lock.is_some()
    }
}

/// hyper-util's `Connected` as its screen saw it, by bundle id: the
/// types its routes land on — the boxed trait object last — and the
/// type's own method declarations, which its version is read off.
#[derive(Clone, Debug)]
struct ConnectedSeed {
    alpn: BundleTypeId,
    is_proxied: BundleTypeId,
    extra: BundleTypeId,
    sources: BTreeSet<PollSource>,
}

/// A stream's route as its name announced it: the hops to the stream
/// it holds, or the socket it is — or a third-party stream's reviewed
/// route, with the type's method declarations its origin is read from.
#[derive(Clone, Debug)]
enum IoRouteSeed {
    Forward(&'static [Hop<'static>]),
    Socket(IoSocket),
    Delegated {
        stream: &'static DelegatedStream,
        sources: BTreeSet<PollSource>,
    },
}

/// A third-party stream whose every read and write is another's: the
/// name its instantiations start with, the rule it binds under, the
/// review its origin is checked against, and the route.
#[derive(Debug)]
struct DelegatedStream {
    key: &'static str,
    kind: SemanticRuleKind,
    review: Review,
    route: DelegatedRoute,
    /// Where the stream holds a rustls connection: the hops to it and
    /// to the stream's own state.
    tls: Option<TlsHops>,
    /// Where the stream names its peer: the hops to the NUL-padded
    /// bytes of its name.
    peer: Option<&'static [Hop<'static>]>,
}

#[derive(Debug)]
struct TlsHops {
    session: &'static [Hop<'static>],
    state: &'static [Hop<'static>],
}

/// tokio-rustls's client and server streams hold their connection as
/// `session`, a `ClientConnection` or `ServerConnection` newtype over
/// rustls's `ConnectionCommon` in `inner`, and their shutdown state as
/// `state`, a `TlsState`.
const TOKIO_RUSTLS_SESSION: TlsHops = TlsHops {
    session: &[Hop::Member("session"), Hop::Member("inner")],
    state: &[Hop::Member("state")],
};

/// Which kind of review a third-party stream's origin is checked
/// against: a registry release's range, or a git revision list.
#[derive(Debug)]
enum Review {
    Release(&'static LibraryConvention),
    Git(&'static GitConvention),
}

#[derive(Debug)]
enum DelegatedRoute {
    /// The hops to the stream held.
    Forward(&'static [Hop<'static>]),
    /// The variants whose one payload is the stream, by name.
    Match(&'static [&'static str]),
    /// The hops to a box of a stream trait object, and the vtable slot
    /// the trait's read method sits in.
    Dyn(&'static [Hop<'static>], u32),
}

/// A route as planned: a step the bundle records as it is, or a trait
/// object's, whose ABI rule and case symbols are interned only when the
/// record is emitted.
#[derive(Clone, Debug)]
enum PlannedStep {
    Fixed(IoRouteStep),
    Dyn {
        pointer: TypedPath,
        data: TypedPath,
        vtable: TypedPath,
        abi: RuleKey,
        read_slot: u32,
        /// Every routed stream a read symbol names, with the symbol.
        cases: Vec<(String, BundleTypeId)>,
    },
}

/// The third-party streams whose routes are reviewed (see each
/// convention for the review): tokio-rustls's enum and its client and
/// server streams, sprockets-tls's stream over the enum, hyper-util's
/// io adapters, dropshot's TLS connection, reqwest's connection and its
/// wrappers, and hyper-rustls's maybe-TLS stream.
const IO_DELEGATIONS: [DelegatedStream; 11] = [
    DelegatedStream {
        key: "tokio_rustls::TlsStream<",
        kind: SemanticRuleKind::TokioRustlsStream,
        review: Review::Release(&TOKIO_RUSTLS_STREAM_V0_26_0),
        route: DelegatedRoute::Match(&["Client", "Server"]),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "tokio_rustls::client::TlsStream<",
        kind: SemanticRuleKind::TokioRustlsStream,
        review: Review::Release(&TOKIO_RUSTLS_STREAM_V0_26_0),
        route: DelegatedRoute::Forward(&[Hop::Member("io")]),
        tls: Some(TOKIO_RUSTLS_SESSION),
        peer: None,
    },
    DelegatedStream {
        key: "tokio_rustls::server::TlsStream<",
        kind: SemanticRuleKind::TokioRustlsStream,
        review: Review::Release(&TOKIO_RUSTLS_STREAM_V0_26_0),
        route: DelegatedRoute::Forward(&[Hop::Member("io")]),
        tls: Some(TOKIO_RUSTLS_SESSION),
        peer: None,
    },
    DelegatedStream {
        key: "sprockets_tls::Stream<",
        kind: SemanticRuleKind::SprocketsTlsStream,
        review: Review::Git(&SPROCKETS_TLS_STREAM_D2B68E4),
        route: DelegatedRoute::Forward(&[Hop::Member("inner")]),
        tls: None,
        // The platform id the attestation verified, a
        // `dice_mfg_msgs::PlatformId` newtype over its bytes.
        peer: Some(&[Hop::Member("platform_id"), Hop::Member("__0")]),
    },
    DelegatedStream {
        key: "hyper_util::rt::tokio::TokioIo<",
        kind: SemanticRuleKind::HyperUtilStream,
        review: Review::Release(&HYPER_UTIL_IO_V0_1_10),
        route: DelegatedRoute::Forward(&[Hop::Member("inner")]),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "hyper_util::common::rewind::Rewind<",
        kind: SemanticRuleKind::HyperUtilStream,
        review: Review::Release(&HYPER_UTIL_IO_V0_1_10),
        route: DelegatedRoute::Forward(&[Hop::Member("inner")]),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "reqwest::connect::sealed::Conn",
        kind: SemanticRuleKind::ReqwestConn,
        review: Review::Release(&REQWEST_CONN_V0_12_14),
        route: DelegatedRoute::Dyn(&[Hop::Member("inner")], REQWEST_CONN_READ_SLOT),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "reqwest::connect::rustls_tls_conn::RustlsTlsConn<",
        kind: SemanticRuleKind::ReqwestConn,
        review: Review::Release(&REQWEST_CONN_V0_12_14),
        route: DelegatedRoute::Forward(&[Hop::Member("inner")]),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "reqwest::connect::verbose::Verbose<",
        kind: SemanticRuleKind::ReqwestConn,
        review: Review::Release(&REQWEST_CONN_V0_12_14),
        route: DelegatedRoute::Forward(&[Hop::Member("inner")]),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "hyper_rustls::stream::MaybeHttpsStream<",
        kind: SemanticRuleKind::HyperRustlsStream,
        review: Review::Release(&HYPER_RUSTLS_STREAM_V0_27_0),
        route: DelegatedRoute::Match(&["Http", "Https"]),
        tls: None,
        peer: None,
    },
    DelegatedStream {
        key: "dropshot::server::TlsConn",
        kind: SemanticRuleKind::DropshotTlsConn,
        review: Review::Release(&DROPSHOT_SERVER_V0_17_0),
        route: DelegatedRoute::Forward(&[Hop::Member("stream")]),
        tls: None,
        peer: None,
    },
];

/// tokio-rustls's handshake newtypes, by the names their instantiations
/// start with: in the crate root through 0.26.2, beside each side's
/// stream from 0.26.3.
const TOKIO_RUSTLS_HANDSHAKES: [&str; 8] = [
    "tokio_rustls::Connect<",
    "tokio_rustls::Accept<",
    "tokio_rustls::FallibleConnect<",
    "tokio_rustls::FallibleAccept<",
    "tokio_rustls::client::Connect<",
    "tokio_rustls::server::Accept<",
    "tokio_rustls::client::FallibleConnect<",
    "tokio_rustls::server::FallibleAccept<",
];

/// rustls's connection state, by the name every instantiation starts
/// with.
const RUSTLS_CONNECTION: &str = "rustls::conn::ConnectionCommon<";

/// tokio-rustls's handshake in progress, by the same.
const MID_HANDSHAKE: &str = "tokio_rustls::common::handshake::MidHandshake<";

/// The third-party stream a name announces, if its route is reviewed.
fn io_delegation(name: &str) -> Option<&'static DelegatedStream> {
    IO_DELEGATIONS
        .iter()
        .find(|stream| names_type(stream.key, name))
}

/// A reviewed handshake whose frame keeps the TLS stream it sets up as
/// a local beside what it knows of the far end: its coroutine, named by
/// the module and the async fn below some `{impl#N}`, the review of the
/// file its body is declared in, and the locals that review read.
#[derive(Debug)]
pub(super) struct FarEndRule {
    module: &'static str,
    function: &'static str,
    review: &'static GitConvention,
    stream: &'static str,
    /// The local holding the far end's `SocketAddr`, where one does.
    addr: Option<&'static str>,
    /// The hops from the state to the bytes of the far end's name.
    name: &'static [&'static str],
}

/// The member rustc keeps a suspended coroutine's awaited future in.
const AWAITEE: &str = "__awaitee";

/// sprockets-tls's two handshakes (see each convention for the review):
/// the client's keeps no address, the server's the accepted socket's.
const FAR_END_RULES: [FarEndRule; 2] = [
    FarEndRule {
        module: "sprockets_tls::client::",
        function: "connect_with_config::{async_fn_env#0}",
        review: &SPROCKETS_TLS_CLIENT_D2B68E4,
        stream: "stream",
        addr: None,
        name: &["tq_platform_id", "__0"],
    },
    FarEndRule {
        module: "sprockets_tls::server::",
        function: "handshake::{async_fn_env#0}",
        review: &SPROCKETS_TLS_SERVER_D2B68E4,
        stream: "stream",
        addr: Some("addr"),
        name: &["tq_platform_id", "__0"],
    },
];

/// The handshake a coroutine's name announces: `module`, one
/// `{impl#N}`, then the async fn's environment.
fn far_end_rule(name: &str) -> Option<&'static FarEndRule> {
    FAR_END_RULES.iter().find(|rule| {
        name.strip_prefix(rule.module)
            .and_then(|rest| rest.strip_prefix("{impl#"))
            .and_then(|rest| rest.split_once("}::"))
            .is_some_and(|(index, function)| {
                !index.is_empty()
                    && index.bytes().all(|b| b.is_ascii_digit())
                    && function == rule.function
            })
    })
}

/// An io operation future as its name announced it: which operation,
/// the member holding the `&mut` it polls, and whether it holds the
/// byte slice whose length says when it completes.
#[derive(Clone, Copy, Debug)]
struct IoOpSeed {
    kind: IoOperationKind,
    pointer: &'static str,
    sliced: bool,
}

/// tokio's io operation futures, by the name every instantiation of
/// each starts with: the member holding the `&mut` it polls, and
/// whether its `buf` is a byte slice. A write's slice is a completion
/// witness — an exhausted one returns before polling — and a read's is
/// recorded with it; the others hold a `ReadBuf` or a generic buffer.
const IO_OPERATIONS: [(&str, IoOperationKind, &str, bool); 8] = [
    (
        "tokio::io::util::read::Read<",
        IoOperationKind::Read,
        "reader",
        true,
    ),
    (
        "tokio::io::util::read_exact::ReadExact<",
        IoOperationKind::ReadExact,
        "reader",
        false,
    ),
    (
        "tokio::io::util::read_buf::ReadBuf<",
        IoOperationKind::ReadBuf,
        "reader",
        false,
    ),
    (
        "tokio::io::util::write::Write<",
        IoOperationKind::Write,
        "writer",
        true,
    ),
    (
        "tokio::io::util::write_all::WriteAll<",
        IoOperationKind::WriteAll,
        "writer",
        true,
    ),
    (
        "tokio::io::util::write_buf::WriteBuf<",
        IoOperationKind::WriteBuf,
        "writer",
        false,
    ),
    (
        "tokio::io::util::flush::Flush<",
        IoOperationKind::Flush,
        "a",
        false,
    ),
    (
        "tokio::io::util::shutdown::Shutdown<",
        IoOperationKind::Shutdown,
        "a",
        false,
    ),
];

/// `io::split`'s halves share the stream behind an `Arc`, under std's
/// mutex, which a half locks only while one of its polls runs.
const SPLIT_HALF: [Hop<'static>; 8] = [
    Hop::Member("inner"),
    Hop::Member("ptr"),
    Hop::Member("pointer"),
    Hop::Deref,
    Hop::Member("data"),
    Hop::Member("stream"),
    Hop::Member("data"),
    Hop::Member("value"),
];
/// A socket's owned halves share it behind an `Arc`.
const OWNED_HALF: [Hop<'static>; 5] = [
    Hop::Member("inner"),
    Hop::Member("ptr"),
    Hop::Member("pointer"),
    Hop::Deref,
    Hop::Member("data"),
];
/// A socket's borrowed halves hold a reference to it.
const BORROWED_HALF: [Hop<'static>; 2] = [Hop::Member("__0"), Hop::Deref];
/// The buffered wrappers hold the stream by value.
const BUFFERED: [Hop<'static>; 1] = [Hop::Member("inner")];

/// tokio's streams whose every read and write goes to the stream they
/// hold (tokio 1.47 through 1.53, `io/split.rs`, `net/tcp/split.rs`,
/// `net/tcp/split_owned.rs`, their `net/unix` twins, and
/// `io/util/buf_{reader,writer,stream}.rs`, the same layout across the
/// range): by name — a generic's prefix, or the whole name of a type
/// generic over a lifetime only, which the name omits — and the hops
/// to the stream held. A buffered wrapper serves a read from its buffer
/// and takes a write into it without touching the stream; it reaches
/// the stream only when the buffer cannot, so a pending poll through
/// one is always the stream's.
const IO_FORWARDS: [(&str, &[Hop<'static>]); 13] = [
    ("tokio::io::split::ReadHalf<", &SPLIT_HALF),
    ("tokio::io::split::WriteHalf<", &SPLIT_HALF),
    ("tokio::net::tcp::split_owned::OwnedReadHalf", &OWNED_HALF),
    ("tokio::net::tcp::split_owned::OwnedWriteHalf", &OWNED_HALF),
    ("tokio::net::unix::split_owned::OwnedReadHalf", &OWNED_HALF),
    ("tokio::net::unix::split_owned::OwnedWriteHalf", &OWNED_HALF),
    ("tokio::net::tcp::split::ReadHalf", &BORROWED_HALF),
    ("tokio::net::tcp::split::WriteHalf", &BORROWED_HALF),
    ("tokio::net::unix::split::ReadHalf", &BORROWED_HALF),
    ("tokio::net::unix::split::WriteHalf", &BORROWED_HALF),
    ("tokio::io::util::buf_reader::BufReader<", &BUFFERED),
    ("tokio::io::util::buf_writer::BufWriter<", &BUFFERED),
    ("tokio::io::util::buf_stream::BufStream<", &BUFFERED),
];

/// The sockets a route ends at: each registers with the io driver, and
/// its `poll_read`/`poll_write` park in the registration's direction
/// slots and nowhere else.
const IO_SOCKETS: [(&str, IoSocket); 2] = [
    ("tokio::net::tcp::stream::TcpStream", IoSocket::TcpStream),
    ("tokio::net::unix::stream::UnixStream", IoSocket::UnixStream),
];

/// Whether `name` is a type `key` names: every instantiation of a
/// generic whose key ends in `<` — the instantiation itself, whose
/// arguments close the name, not a variant's payload type named below
/// it (`TlsStream<T>::Client`) — or the one type an exact key names.
fn names_type(key: &str, name: &str) -> bool {
    if key.ends_with('<') {
        name.strip_prefix(key).is_some_and(|args| {
            super::sweep::angle_close(args).map(|at| at + 1) == Some(args.len())
        })
    } else {
        name == key
    }
}

/// The route a stream's name announces, if it is one of tokio's.
fn io_route_seed(name: &str) -> Option<IoRouteSeed> {
    if let Some(&(_, hops)) = IO_FORWARDS.iter().find(|(key, _)| names_type(key, name)) {
        return Some(IoRouteSeed::Forward(hops));
    }
    IO_SOCKETS
        .iter()
        .find(|(key, _)| names_type(key, name))
        .map(|&(_, socket)| IoRouteSeed::Socket(socket))
}

/// The operation an io future's name announces, if it is one of tokio's.
fn io_op_seed(name: &str) -> Option<IoOpSeed> {
    IO_OPERATIONS
        .iter()
        .find(|(key, ..)| names_type(key, name))
        .map(|&(_, kind, pointer, sliced)| IoOpSeed {
            kind,
            pointer,
            sliced,
        })
}

/// A raw lock as its screen saw it: whose implementation it is, which
/// is what its origin is read from.
pub(super) enum LockSeed {
    /// std's futex mutex: the verdict on its defining units.
    StdFutex(CompilerVerdict),
    /// parking_lot's raw mutex: where its methods were declared.
    ParkingLot(BTreeSet<PollSource>),
}

pub(super) type SemanticSeeds = BTreeMap<BundleTypeId, Seed>;

/// What the library bindings dispatch on: the bound walk contract, and
/// the tokio version and family every versioned row answered from.
pub(super) struct Library<'a> {
    pub(super) walks: &'a WalksTable,
    pub(super) tokio_version: Option<&'a semver::Version>,
    pub(super) family: Family,
}

/// A wide pointer as the binder carries it, by bundle id, with the
/// verdict on the vtable ABI its defining units were compiled under.
fn dyn_seed(
    w: WidePointer,
    verdict: &mut impl FnMut(TypeId, Reviewed) -> CompilerVerdict,
    bundle_id: &impl Fn(TypeId) -> Option<BundleTypeId>,
) -> Option<DynSeed> {
    Some(DynSeed {
        abi: verdict(w.wide, Reviewed::DynFutureAbi),
        future_trait: w.future_trait,
        wide: bundle_id(w.wide)?,
        pointer: w.pointer,
        vtable: w.vtable,
        data_ptr: bundle_id(w.data_ptr)?,
        vtable_ptr: bundle_id(w.vtable_ptr)?,
        trait_ty: bundle_id(w.trait_ty)?,
    })
}

/// The reviewed third-party wrapper `raw` is, if it is one. The name
/// picks the screen — a definition path is where a crate's own type
/// lives — and the screen decides, over the type's own declaration.
/// `dyn_seed` carries a wide pointer a screen found to the binder,
/// with its ABI verdict.
fn library_seed(
    reader: &crate::DwReader<'_>,
    raw: TypeId,
    name: &str,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    mut dyn_seed: impl FnMut(WidePointer) -> Option<DynSeed>,
    env_source: &impl Fn(TypeId) -> Option<PollSource>,
) -> Option<LibrarySeed> {
    let forward = |layout: Option<adapters::ForwardLayout>| {
        let layout = layout?;
        Some((layout.member, bundle_id(layout.inner)?))
    };
    if name.starts_with("futures_util::future::future::map::Map<") {
        let layout = adapters::futures_util_map(reader, raw)?;
        Some(LibrarySeed::Map {
            incomplete: layout.incomplete,
            future_member: layout.future_member,
            complete: layout.complete,
            future: bundle_id(layout.future)?,
        })
    } else if name.starts_with("futures_util::future::future::Map<") {
        let (member, inner) = forward(adapters::futures_util_map_wrapper(reader, raw))?;
        Some(LibrarySeed::MapWrapper(member, inner))
    } else if name.starts_with("futures_util::future::try_future::MapErr<") {
        let (member, inner) = forward(adapters::futures_util_map_err(reader, raw))?;
        Some(LibrarySeed::MapErr(member, inner))
    } else if name.starts_with("futures_util::future::try_future::into_future::IntoFuture<") {
        let (member, inner) = forward(adapters::futures_util_into_future(reader, raw))?;
        Some(LibrarySeed::IntoFuture(member, inner))
    } else if name == "hyper_util::rt::tokio::TokioSleep" {
        let (member, inner) = forward(adapters::hyper_util_tokio_sleep(reader, raw))?;
        Some(LibrarySeed::TokioSleep(member, inner))
    } else if name.starts_with("tokio::task::coop::Coop<") {
        let (member, inner) = forward(adapters::tokio_coop(reader, raw))?;
        Some(LibrarySeed::Coop(member, inner))
    } else if name.starts_with("futures_util::stream::stream::next::Next<") {
        let layout = adapters::futures_util_next(reader, raw)?;
        Some(LibrarySeed::Next(layout.stream, bundle_id(layout.target)?))
    } else if name.starts_with("tokio_stream::wrappers::watch::WatchStream<") {
        let (member, inner) = forward(adapters::tokio_stream_watch_stream(reader, raw))?;
        Some(LibrarySeed::WatchStream(member, inner))
    } else if name.starts_with("futures_util::future::pending::Pending<") {
        adapters::futures_util_pending(reader, raw).then_some(LibrarySeed::Pending)
    } else if name.starts_with("tokio_util::sync::reusable_box::ReusableBoxFuture<") {
        let layout = adapters::tokio_util_reusable_box(reader, raw)?;
        Some(LibrarySeed::ReusableBox {
            boxed: layout.boxed,
            pin: (layout.pin.0, bundle_id(layout.pin.1)?),
            dyn_: dyn_seed(layout.wide)?,
        })
    } else if name.starts_with("core::future::poll_fn::PollFn<") {
        // The `select!` screen ran first on this name; a `PollFn` it
        // declined may be the tick's.
        let layout = adapters::tokio_interval_tick(reader, raw)?;
        Some(LibrarySeed::IntervalTick {
            closure: layout.closure,
            interval_ref: layout.interval_ref,
            interval: bundle_id(layout.interval)?,
            delay: layout.delay,
            boxed: bundle_id(layout.boxed)?,
            source: env_source(layout.env),
        })
    } else if TOKIO_RUSTLS_HANDSHAKES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        let (member, inner) = forward(adapters::tokio_rustls_handshake(reader, raw))?;
        Some(LibrarySeed::TokioRustlsHandshake(member, inner))
    } else if name.starts_with("hyper::client::conn::http1::Connection<") {
        let (member, inner) = forward(adapters::hyper_h1_client_connection(reader, raw))?;
        Some(LibrarySeed::HyperConnection(member, inner))
    } else if name.starts_with("hyper::server::conn::http1::Connection<") {
        let (member, inner) = forward(adapters::hyper_h1_server_connection(reader, raw))?;
        Some(LibrarySeed::HyperConnection(member, inner))
    } else if name.starts_with("hyper::client::conn::http1::upgrades::UpgradeableConnection<")
        || name.starts_with("hyper::server::conn::http1::UpgradeableConnection<")
    {
        let layout = if name.starts_with("hyper::client::") {
            adapters::hyper_h1_client_upgradeable(reader, raw)?
        } else {
            adapters::hyper_h1_server_upgradeable(reader, raw)?
        };
        Some(LibrarySeed::HyperUpgradeable {
            inner: layout.inner,
            option: bundle_id(layout.option)?,
            dispatcher_member: layout.dispatcher_member,
            dispatcher: bundle_id(layout.dispatcher)?,
        })
    } else if name.starts_with("hyper_util::server::conn::auto::UpgradeableConnection<") {
        let layout = adapters::hyper_util_auto_upgradeable(reader, raw)?;
        Some(LibrarySeed::HyperUtilAuto {
            state: layout.state,
            state_ty: bundle_id(layout.state_ty)?,
            h1_conn: layout.h1_conn,
            h1: bundle_id(layout.h1)?,
        })
    } else if name.starts_with("futures_util::future::either::Either<") {
        let layout = adapters::futures_util_either(reader, raw)?;
        Some(LibrarySeed::Either {
            left: (layout.left.0, bundle_id(layout.left.1)?),
            right: (layout.right.0, bundle_id(layout.right.1)?),
        })
    } else if name.starts_with("tower::retry::future::ResponseFuture<") {
        let layout = adapters::tower_retry_response_future(reader, raw)?;
        let (called, called_member, called_ty) = layout.called;
        let (waiting, waiting_member, waiting_ty) = layout.waiting;
        Some(LibrarySeed::TowerRetry {
            state: layout.state,
            state_ty: bundle_id(layout.state_ty)?,
            called: (called, called_member, bundle_id(called_ty)?),
            waiting: (waiting, waiting_member, bundle_id(waiting_ty)?),
            retrying: layout.retrying,
        })
    } else if name.starts_with("reqwest::cookie::service::ResponseFuture<") {
        let (member, inner) = forward(adapters::reqwest_cookie_response_future(reader, raw))?;
        Some(LibrarySeed::ReqwestCookie(member, inner))
    } else if name == "hyper_util::client::legacy::client::ResponseFuture" {
        let layout = adapters::hyper_util_response_future(reader, raw)?;
        Some(LibrarySeed::HyperUtilResponse {
            inner: layout.inner,
            wrapped: layout.wrapped,
            boxed: bundle_id(layout.boxed)?,
        })
    } else {
        None
    }
}

/// The screen's dispatcher layout by bundle id. `None` when any type
/// it names was not emitted: a word the table does not carry cannot be
/// a recorded route.
fn http_seed(
    layout: HttpDispatcherLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    type_sources: impl Fn(TypeId) -> BTreeSet<PollSource>,
) -> Option<HttpSeed> {
    let client = match layout.client {
        Some(client) => Some(HttpClientSeed {
            callback: bundle_id(client.callback)?,
            retry: bundle_id(client.retry)?,
            no_retry: bundle_id(client.no_retry)?,
            rx: bundle_id(client.rx)?,
            want: bundle_id(client.want)?,
        }),
        None => None,
    };
    let server = match layout.server {
        Some(server) => Some(HttpServerSeed {
            in_flight_member: server.in_flight_member,
            in_flight_box: bundle_id(server.in_flight_box)?,
            in_flight: bundle_id(server.in_flight)?,
            header_read_timeout_running: bundle_id(server.header_read_timeout_running)?,
            header_read_timeout_secs: bundle_id(server.header_read_timeout_secs)?,
            header_read_timeout_nanos: bundle_id(server.header_read_timeout_nanos)?,
            header_read_timer_pin: server.header_read_timer_pin,
            header_read_timer_pointer: server.header_read_timer_pointer,
            header_read_timer: bundle_id(server.header_read_timer)?,
            // A service the table does not carry the types of is no
            // recorded route; the binding stands without it.
            service: server.dropshot.and_then(|dropshot| {
                Some(HttpServiceSeed {
                    peer: bundle_id(dropshot.remote_addr)?,
                    context: bundle_id(dropshot.context)?,
                    sources: type_sources(server.service),
                })
            }),
        }),
        None => None,
    };
    Some(HttpSeed {
        role: layout.role,
        keep_alive: bundle_id(layout.keep_alive)?,
        reading: bundle_id(layout.reading)?,
        writing: bundle_id(layout.writing)?,
        method: bundle_id(layout.method)?,
        method_inner: bundle_id(layout.method_inner)?,
        read_continue_kind: bundle_id(layout.read_continue_kind)?,
        read_body_kind: bundle_id(layout.read_body_kind)?,
        write_body_kind: bundle_id(layout.write_body_kind)?,
        is_closing: bundle_id(layout.is_closing)?,
        client,
        server,
    })
}

/// The screen's request layout by bundle id, with the declarations its
/// crate's version is read off. `None` when a type it names was not
/// emitted: a word the table does not carry cannot be a recorded route.
fn request_seed(
    layout: HttpRequestLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    sources: BTreeSet<PollSource>,
) -> Option<RequestSeed> {
    Some(RequestSeed {
        kind: layout.kind,
        method_inner: bundle_id(layout.method_inner)?,
        target_ptr: bundle_id(layout.target_ptr)?,
        target_len: bundle_id(layout.target_len)?,
        sources,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "one table per join the sweep feeds the seeds"
)]
pub(super) fn collect_semantic_seeds(
    em: &Emitter<'_>,
    polls: &BTreeMap<TypeId, BTreeSet<String>>,
    stream_reads: &BTreeMap<TypeId, BTreeSet<String>>,
    extra_sets: &BTreeMap<TypeId, BTreeSet<String>>,
    poll_sources: &BTreeMap<TypeId, BTreeSet<PollSource>>,
    coroutines: &BTreeSet<TypeId>,
    mut verdict: impl FnMut(TypeId, Reviewed) -> CompilerVerdict,
    env: impl Fn(TypeId) -> EnvFacts,
    type_sources: impl Fn(TypeId) -> BTreeSet<PollSource>,
) -> SemanticSeeds {
    let env_source = |ty: TypeId| env(ty).source;
    let mut seeds = SemanticSeeds::new();
    let reader = em.reader;
    let bundle_id = |raw: TypeId| em.bundle_id_of(raw);
    for (raw, name) in em.emitted_named() {
        let Some(ty) = bundle_id(raw) else {
            continue;
        };
        let canonical = reader
            .canonical_type(raw)
            .and_then(|t| t.name())
            .map(|n| reader.strings.get(n))
            .unwrap_or_default();
        let candidate =
            coroutines.contains(&raw) || crate::bundle::names::is_coroutine_candidate(canonical);
        if candidate {
            let seed = seeds.entry(ty).or_default();
            seed.coroutine_candidate = true;
            seed.compiler = Some(verdict(raw, Reviewed::Coroutine));
            // A reviewed handshake's frame, whose origin is the file its
            // body was declared in.
            if let Some(rule) = far_end_rule(name) {
                seed.far_end = Some((rule, env_source(raw)));
            }
        }
        // The adapter and wrapper screens run on the shapes their names
        // announce; the screen decides, the name only saves the walk.
        if name.starts_with("core::pin::Pin<")
            || name.starts_with("alloc::boxed::Box<")
            || name.starts_with("&mut ")
        {
            let screened = adapters::std_adapter_screen(reader, raw);
            if let Ok(adapter) = screened {
                let compiler = verdict(raw, Reviewed::StdAdapters);
                let mut pointee = |pointee: Pointee| -> Option<PointeeSeed> {
                    Some(match pointee {
                        Pointee::Sized(f) => PointeeSeed::Sized(bundle_id(f)?),
                        Pointee::Dyn(w) => PointeeSeed::Dyn(dyn_seed(w, &mut verdict, &bundle_id)?),
                    })
                };
                let seed = match adapter {
                    StdAdapter::Box(p) => pointee(p).map(|pointee| AdapterSeed {
                        kind: AdapterKind::Box,
                        pin: None,
                        pointee,
                        compiler,
                    }),
                    StdAdapter::MutRef(p) => pointee(p).map(|pointee| AdapterSeed {
                        kind: AdapterKind::MutRef,
                        pin: None,
                        pointee,
                        compiler,
                    }),
                    StdAdapter::PinBox {
                        member,
                        boxed,
                        pointee: p,
                    } => pointee(p)
                        .zip(bundle_id(boxed))
                        .map(|(pointee, boxed)| AdapterSeed {
                            kind: AdapterKind::PinBox,
                            pin: Some((member, boxed)),
                            pointee,
                            compiler,
                        }),
                    StdAdapter::PinMutRef {
                        member,
                        reference,
                        pointee: p,
                    } => pointee(p)
                        .zip(bundle_id(reference))
                        .map(|(pointee, reference)| AdapterSeed {
                            kind: AdapterKind::PinMutRef,
                            pin: Some((member, reference)),
                            pointee,
                            compiler,
                        }),
                };
                if let Some(seed) = seed {
                    seeds.entry(ty).or_default().adapter = Some(seed);
                }
            } else if let Err(PointerDecline::Disagree { targets }) = screened {
                // The one pointer type stands over several pointees: a
                // collapse the identity partition did not split. Nothing
                // else will claim the type, so the reason is recorded
                // where its continuation would have been.
                seeds.entry(ty).or_default().adapter_declined = Some((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("the pointer's definitions name {targets} targets"),
                ));
            }
        } else if name.starts_with("tracing::instrument::Instrumented<")
            && let Some(InstrumentedLayout { inner, future }) = adapters::instrumented(reader, raw)
            && let Some(future) = bundle_id(future)
        {
            seeds.entry(ty).or_default().instrumented = Some(InstrumentedSeed { inner, future });
        } else if name.starts_with("core::future::poll_fn::PollFn<")
            && let Some(layout) = adapters::tokio_select(reader, raw)
            && let Some(seed) = select_seed(layout, bundle_id, &env)
        {
            seeds.entry(ty).or_default().select = Some(seed);
        } else if name.starts_with("core::future::pending::Pending<")
            && adapters::core_pending(reader, raw)
        {
            seeds.entry(ty).or_default().pending = Some(verdict(raw, Reviewed::CorePending));
        } else if name.starts_with("hyper::proto::h1::dispatch::Dispatcher<")
            && let Some(layout) = adapters::hyper_h1_dispatcher(reader, raw)
            && let Some(seed) = http_seed(layout, bundle_id, &type_sources)
        {
            seeds.entry(ty).or_default().http = Some(seed);
        } else if let Some(value) = refcount_value(name) {
            seeds.entry(ty).or_default().refcount =
                Some((value, verdict(raw, Reviewed::StdRefcount)));
        } else if name == "std::sys::sync::mutex::futex::Mutex" {
            seeds.entry(ty).or_default().lock =
                Some(LockSeed::StdFutex(verdict(raw, Reviewed::StdFutexMutex)));
        } else if name == "parking_lot::raw_mutex::RawMutex" {
            seeds.entry(ty).or_default().lock = Some(LockSeed::ParkingLot(type_sources(raw)));
        } else if name.starts_with("reqwest::async_impl::client::PendingRequest")
            && let Some(layout) = adapters::reqwest_pending_request(reader, raw)
            && let Some(seed) = request_seed(layout, bundle_id, BTreeSet::new())
        {
            seeds.entry(ty).or_default().request = Some(seed);
        } else if name.starts_with("http::request::Request<")
            && let Some(layout) = adapters::http_request(reader, raw)
            && let Some(seed) = request_seed(layout, bundle_id, type_sources(raw))
        {
            seeds.entry(ty).or_default().request = Some(seed);
        } else if name.starts_with("dropshot::handler::RequestContext<")
            && let Some(layout) = adapters::dropshot_request_context(reader, raw)
            && let Some(seed) = request_seed(layout, bundle_id, type_sources(raw))
        {
            seeds.entry(ty).or_default().request = Some(seed);
        } else if name.starts_with("hyper_util::client::legacy::pool::IdleTask<")
            && let Some(layout) = adapters::hyper_util_pool_reaper(reader, raw)
            && let Some(seed) = pool_reaper_seed(layout, bundle_id, type_sources(raw))
        {
            seeds.entry(ty).or_default().pool = Some(seed);
        } else if name.starts_with("hyper_util::client::legacy::pool::Pooled<")
            && let Some(layout) = adapters::hyper_util_pool_checkout(reader, raw)
            && let Some(seed) = pool_checkout_seed(layout, bundle_id, type_sources(raw))
        {
            seeds.entry(ty).or_default().pool = Some(seed);
        } else if name == "hyper_util::client::legacy::connect::Connected"
            && let Some(layout) = adapters::hyper_util_connected(reader, raw)
            && let (Some(alpn), Some(is_proxied), Some(extra)) = (
                bundle_id(layout.alpn),
                bundle_id(layout.is_proxied),
                bundle_id(layout.extra),
            )
        {
            seeds.entry(ty).or_default().connected = Some(ConnectedSeed {
                alpn,
                is_proxied,
                extra,
                sources: type_sources(raw),
            });
        } else if let Some(route) = io_route_seed(name) {
            seeds.entry(ty).or_default().io_route = Some(route);
        } else if let Some(stream) = io_delegation(name) {
            seeds.entry(ty).or_default().io_route = Some(IoRouteSeed::Delegated {
                stream,
                sources: type_sources(raw),
            });
        } else if names_type(MID_HANDSHAKE, name) {
            seeds.entry(ty).or_default().handshake = true;
        } else if names_type(RUSTLS_CONNECTION, name) {
            seeds.entry(ty).or_default().tls_session = Some(type_sources(raw));
        } else if let Some(op) = io_op_seed(name) {
            seeds.entry(ty).or_default().io_op = Some(op);
        } else if let Some(library) = library_seed(
            reader,
            raw,
            name,
            bundle_id,
            |w| dyn_seed(w, &mut verdict, &bundle_id),
            &env_source,
        ) {
            let seed = seeds.entry(ty).or_default();
            if library.origin_is_the_type() {
                seed.type_sources = type_sources(raw);
            }
            seed.library = Some(library);
        } else if HASH_TABLES.iter().any(|prefix| name.starts_with(prefix))
            && let Some(layout) = adapters::hash_table(reader, raw)
        {
            // The release is hashbrown's, so it is read off hashbrown's
            // map — the one type all four hold — and not off a
            // wrapper std declares, nor off the `RawTable`, whose name
            // std's vendored copy and a registry release share.
            let sources = type_sources(layout.map);
            if let Some(seed) = table_seed(layout, bundle_id, sources) {
                seeds.entry(ty).or_default().table = Some(seed);
            }
        } else if name.starts_with(STREAM_MAP) {
            // The map's layout is the walk contract's to bind, by the
            // roles rooted at its name; its origin is the type's own
            // method declarations, gathered here where the DWARF is
            // still open and read when the container binds.
            seeds.entry(ty).or_default().type_sources = type_sources(raw);
        }
    }
    // A stream's read symbols, for the trait objects that name it; only
    // an emitted type can be a case.
    for (raw, symbols) in stream_reads {
        if let Some(ty) = bundle_id(*raw) {
            seeds
                .entry(ty)
                .or_default()
                .read_symbols
                .extend(symbols.iter().cloned());
        }
    }
    // An extra's `set` symbols, for the `Connected` extras vtable that
    // names it, likewise.
    for (raw, symbols) in extra_sets {
        if let Some(ty) = bundle_id(*raw) {
            seeds
                .entry(ty)
                .or_default()
                .extra_symbols
                .extend(symbols.iter().cloned());
        }
    }
    for (raw, symbols) in polls {
        // Poll roots have already been emitted through the dynamic table.
        if let Some(ty) = bundle_id(*raw) {
            let seed = seeds.entry(ty).or_default();
            seed.polls.extend(symbols.iter().cloned());
            if let Some(sources) = poll_sources.get(raw) {
                seed.poll_sources.extend(sources.iter().cloned());
            }
        }
    }
    seeds
}

/// The screen's `select!` layout by bundle id, with the closure
/// environment's declaration site and each branch's arm. `None` when
/// any type it names was not emitted: a branch future the table does
/// not carry cannot be a recorded route.
fn select_seed(
    layout: SelectLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    env: &impl Fn(TypeId) -> EnvFacts,
) -> Option<SelectSeed> {
    let EnvFacts { source, arms } = env(layout.env);
    let arms = join_arms(&layout.branches, &arms);
    let branches = layout
        .branches
        .iter()
        .map(|(member, future)| Some((member.clone(), bundle_id(*future)?)))
        .collect::<Option<Vec<_>>>()?;
    Some(SelectSeed {
        closure: layout.closure,
        mask: layout.mask,
        mask_word: bundle_id(layout.mask_word)?,
        futures: layout.futures,
        tuple: bundle_id(layout.tuple)?,
        branches,
        source,
        arms,
    })
}

/// Pair each tuple member with the arm of its future type, from the
/// arms the closure the macro polls the branches in recorded: each an
/// anchor's pointee, canonical like the members, and the arm's pattern
/// bindings. Type is the only key there is — the macro's scopes carry
/// no branch index, and their order is the compiler's — so a type that
/// appears twice on either side settles nothing: with two members of
/// one type and one arm, the arm belongs to either, and a wrong line
/// would be worse than none. Bindings that disagree on where they are
/// settle nothing for the same reason; an arm that binds nothing is
/// simply unbound.
fn join_arms(branches: &[(String, TypeId)], arms: &[(TypeId, Vec<OwnedLoc>)]) -> Vec<ArmSite> {
    branches
        .iter()
        .enumerate()
        .map(|(i, (_, future))| {
            let members = branches.iter().filter(|(_, t)| t == future).count();
            let of_type: Vec<&Vec<OwnedLoc>> = arms
                .iter()
                .filter(|(t, _)| t == future)
                .map(|(_, bindings)| bindings)
                .collect();
            if members > 1 || of_type.len() > 1 {
                return ArmSite::Declined((
                    SemanticIssueKind::AmbiguousLayout,
                    format!(
                        "branch {i}'s future type is shared: {members} tuple members, {} arms",
                        of_type.len()
                    ),
                ));
            }
            let [bindings] = of_type.as_slice() else {
                return ArmSite::Declined((
                    SemanticIssueKind::MissingLayout,
                    format!("no arm of branch {i}'s future type in the closure"),
                ));
            };
            let mut sites = bindings
                .iter()
                .filter(|b| b.file.is_some() && b.line.is_some());
            let Some(first) = sites.next() else {
                return ArmSite::Unbound;
            };
            let same = |a: &OwnedLoc, b: &OwnedLoc| {
                a.file == b.file && a.dir == b.dir && a.comp_dir == b.comp_dir && a.line == b.line
            };
            if let Some(other) = sites.find(|b| !same(first, b)) {
                return ArmSite::Declined((
                    SemanticIssueKind::AmbiguousLayout,
                    format!(
                        "branch {i}'s bindings disagree: line {} and line {}",
                        first.line.unwrap_or_default(),
                        other.line.unwrap_or_default()
                    ),
                ));
            }
            ArmSite::Written(first.clone())
        })
        .collect()
}

/// The resources the walk contract binds, in the every-kind order the
/// bindings are attempted in, which is also the order their rules are
/// numbered: a bundle's rule ids depend on which kinds bound, never on
/// the order types were met. An io operation over a stream is bound by
/// its route instead ([`plan_io`]).
const RESOURCE_KINDS: [(ResourceKind, SemanticRuleKind); 7] = [
    (ResourceKind::Sleep, SemanticRuleKind::TokioSleep),
    (ResourceKind::JoinHandle, SemanticRuleKind::TokioJoinHandle),
    (
        ResourceKind::SemaphoreAcquire,
        SemanticRuleKind::TokioAcquire,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::Readiness),
        SemanticRuleKind::TokioIoOperation,
    ),
    (ResourceKind::MpscRecv, SemanticRuleKind::TokioMpscRecv),
    (ResourceKind::Notified, SemanticRuleKind::TokioNotified),
    (
        ResourceKind::OneshotRecv,
        SemanticRuleKind::TokioOneshotRecv,
    ),
];

/// The layout rule a tokio resource binds under.
fn resource_rule(kind: ResourceKind) -> SemanticRuleKind {
    match kind {
        ResourceKind::IoOperation(IoOperationKind::Handshake) => {
            SemanticRuleKind::TokioRustlsHandshake
        }
        ResourceKind::IoOperation(_) => SemanticRuleKind::TokioIoOperation,
        kind => RESOURCE_KINDS
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, rule)| *rule)
            .expect("every walk-bound resource kind has a rule"),
    }
}

const CONTAINER_KINDS: [(ContainerKind, SemanticRuleKind); 3] = [
    (ContainerKind::JoinSet, SemanticRuleKind::TokioJoinSet),
    (
        ContainerKind::FuturesUnordered,
        SemanticRuleKind::FuturesUnordered,
    ),
    (
        ContainerKind::StreamMap,
        SemanticRuleKind::TokioStreamStreamMap,
    ),
];

/// The by-value type every tokio-stream `StreamMap` is recognized as:
/// the walk contract's leaf key, whose roles bound at a type are what
/// seed the container.
const STREAM_MAP: &str = "tokio_stream::stream_map::StreamMap<";

/// The names a hash table is screened under: hashbrown's map and set,
/// and std's wrappers of each.
const HASH_TABLES: [&str; 4] = [
    "hashbrown::map::HashMap<",
    "hashbrown::set::HashSet<",
    "std::collections::hash::map::HashMap<",
    "std::collections::hash::set::HashSet<",
];

/// The rule a container binds under. The two tokio and futures-util
/// sets bind under the bundle's one layout origin for their library;
/// the map is a third-party type whose layout the contract binds by
/// name alone, so its rule is read off the type's own method
/// declarations like a stream route's, and declines the same ways.
fn container_rule(kind: ContainerKind, seed: &Seed) -> Result<RuleKey, Decline> {
    let rule_kind = CONTAINER_KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, rule)| *rule)
        .expect("every container kind has a rule");
    match kind {
        ContainerKind::JoinSet | ContainerKind::FuturesUnordered => Ok(RuleKey::Library(rule_kind)),
        ContainerKind::StreamMap => {
            let origin =
                delegation_origin(&seed.type_sources, &TOKIO_STREAM_MAP_V0_1_14, "method")?;
            Ok(RuleKey::Delegation {
                kind: rule_kind,
                origin,
            })
        }
    }
}

const SCHEDULER_CLASSES: [(SchedulerClass, SemanticRuleKind); 4] = [
    (
        SchedulerClass::MultiThread,
        SemanticRuleKind::TokioMultiThreadScheduler,
    ),
    (
        SchedulerClass::CurrentThread,
        SemanticRuleKind::TokioCurrentThreadScheduler,
    ),
    (
        SchedulerClass::LocalSet,
        SemanticRuleKind::TokioLocalScheduler,
    ),
    (
        SchedulerClass::Blocking,
        SemanticRuleKind::TokioBlockingScheduler,
    ),
];

/// The types every one of `roles` bound at, provided every chained
/// `route` below them bound too: a binding's roots are the set its
/// spelling resolved against, so a role broken for any root is broken
/// for all, and the intersection is the roots the whole route holds for.
fn bound_roots(
    walks: &WalksTable,
    roles: &[WalkRole],
    routes: &[WalkRole],
) -> BTreeSet<BundleTypeId> {
    let bound = |role: &WalkRole| {
        walks
            .entries
            .get(role)
            .is_some_and(|binding| matches!(binding.outcome, WalkOutcome::Bound { .. }))
    };
    if !routes.iter().all(bound) {
        return BTreeSet::new();
    }
    let mut roots: Option<BTreeSet<BundleTypeId>> = None;
    for role in roles {
        let bound: BTreeSet<BundleTypeId> = match walks.entries.get(role) {
            Some(binding) if matches!(binding.outcome, WalkOutcome::Bound { .. }) => {
                binding.roots.iter().copied().collect()
            }
            _ => BTreeSet::new(),
        };
        roots = Some(match roots {
            Some(roots) => &roots & &bound,
            None => bound,
        });
    }
    roots.unwrap_or_default()
}

/// A third-party delegation origin as the binder established it: the
/// crate and version the declaration path spells, the family that
/// version selected, the anchored path, and whatever checksums the file
/// tables carried for the implementing file.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct DelegationOrigin {
    package: &'static str,
    version: String,
    family: &'static str,
    source: String,
    files: Vec<(String, [u8; 16])>,
}

/// A git delegation origin as the binder established it: the crate the
/// review names, the repository and abbreviated revision the checkout
/// path records, the family, the anchored path, and whatever checksums
/// the file tables carried.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct GitDelegationOrigin {
    package: &'static str,
    repository: String,
    revision: String,
    family: &'static str,
    source: String,
    files: Vec<(String, [u8; 16])>,
}

/// A rule as a plan names it, before ids exist: enough to intern the
/// origin and the rule once each, in the order the records are emitted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum RuleKey {
    /// A tokio or futures-util layout rule under the bundle's one
    /// origin for that library.
    Library(SemanticRuleKind),
    /// A compiler rule under the origin of one producer and one
    /// reviewed family: two producers inside one range are two origins,
    /// and two families over one producer are two as well.
    Rustc {
        kind: SemanticRuleKind,
        producer: String,
        family: &'static str,
    },
    Delegation {
        kind: SemanticRuleKind,
        origin: DelegationOrigin,
    },
    GitDelegation {
        kind: SemanticRuleKind,
        origin: GitDelegationOrigin,
    },
    /// A layout rule over a release its declarations named, under the
    /// origin of that package, release and reviewed family.
    Layout {
        kind: SemanticRuleKind,
        package: &'static str,
        version: String,
        family: &'static str,
    },
}

/// The origins and rules a bundle applied, interned on first use in
/// record order.
struct Rules {
    origins: Vec<SemanticOrigin>,
    rules: Vec<SemanticRule>,
    by_key: BTreeMap<RuleKey, SemanticRuleId>,
    tokio: Option<SemanticOriginId>,
    futures_util: Option<SemanticOriginId>,
    rustc: BTreeMap<(String, &'static str), SemanticOriginId>,
    delegation: BTreeMap<DelegationOrigin, SemanticOriginId>,
    git: BTreeMap<GitDelegationOrigin, SemanticOriginId>,
    layout: BTreeMap<(&'static str, String, &'static str), SemanticOriginId>,
}

impl Rules {
    fn new() -> Self {
        Rules {
            origins: Vec::new(),
            rules: Vec::new(),
            by_key: BTreeMap::new(),
            tokio: None,
            futures_util: None,
            rustc: BTreeMap::new(),
            delegation: BTreeMap::new(),
            git: BTreeMap::new(),
            layout: BTreeMap::new(),
        }
    }

    fn push_origin(&mut self, origin: SemanticOrigin) -> SemanticOriginId {
        let id = SemanticOriginId(u32::try_from(self.origins.len()).expect("origin overflow"));
        self.origins.push(origin);
        id
    }

    fn library_origin(
        &mut self,
        kind: SemanticRuleKind,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> SemanticOriginId {
        let futures_util = matches!(
            kind,
            SemanticRuleKind::FuturesUnordered
                | SemanticRuleKind::FuturesUtilMap
                | SemanticRuleKind::FuturesUtilMapErr
                | SemanticRuleKind::FuturesUtilIntoFuture
                | SemanticRuleKind::FuturesUtilPending
        );
        let (slot, origin) = if futures_util {
            // The set walker's layout has held across every futures-util
            // release the fixtures cover, and no version is recovered for
            // it: its rows are unversioned, and the origin says so. The
            // sole-member forwarders bound on their layout are filed
            // under the same origin, being read off nothing else.
            let origin = SemanticOrigin::LibraryLayout {
                package: strings.intern("futures-util"),
                version: None,
                family: strings.intern("unversioned"),
                selection: LayoutSelection::VersionUnknown,
            };
            (&mut self.futures_util, origin)
        } else {
            let origin = SemanticOrigin::LibraryLayout {
                package: strings.intern("tokio"),
                version: library
                    .tokio_version
                    .map(|version| strings.intern(&version.to_string())),
                family: strings.intern(library.family.name()),
                selection: Family::layout_selection(library.tokio_version),
            };
            (&mut self.tokio, origin)
        };
        if let Some(id) = *slot {
            return id;
        }
        let id = SemanticOriginId(u32::try_from(self.origins.len()).expect("origin overflow"));
        self.origins.push(origin);
        *slot = Some(id);
        id
    }

    /// The rule a key names, interned on first use with its origin.
    fn rule(
        &mut self,
        key: &RuleKey,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> SemanticRuleId {
        if let Some(id) = self.by_key.get(key) {
            return *id;
        }
        let (kind, origin) = match key {
            RuleKey::Library(kind) => (*kind, self.library_origin(*kind, strings, library)),
            RuleKey::Rustc {
                kind,
                producer,
                family,
            } => {
                let origin = match self.rustc.get(&(producer.clone(), *family)) {
                    Some(id) => *id,
                    None => {
                        let id = self.push_origin(SemanticOrigin::Rustc {
                            producer: strings.intern(producer),
                            family: strings.intern(family),
                        });
                        self.rustc.insert((producer.clone(), family), id);
                        id
                    }
                };
                (*kind, origin)
            }
            RuleKey::Delegation { kind, origin } => {
                let id = match self.delegation.get(origin) {
                    Some(id) => *id,
                    None => {
                        let id = self.push_origin(SemanticOrigin::LibraryDelegation {
                            package: strings.intern(origin.package),
                            version: strings.intern(&origin.version),
                            family: strings.intern(origin.family),
                            source: strings.intern(&origin.source),
                            files: origin
                                .files
                                .iter()
                                .map(|(file, md5)| SourceFileEvidence {
                                    file: strings.intern(file),
                                    md5: *md5,
                                })
                                .collect(),
                        });
                        self.delegation.insert(origin.clone(), id);
                        id
                    }
                };
                (*kind, id)
            }
            RuleKey::GitDelegation { kind, origin } => {
                let id = match self.git.get(origin) {
                    Some(id) => *id,
                    None => {
                        let id = self.push_origin(SemanticOrigin::GitDelegation {
                            package: strings.intern(origin.package),
                            repository: strings.intern(&origin.repository),
                            revision: strings.intern(&origin.revision),
                            family: strings.intern(origin.family),
                            source: strings.intern(&origin.source),
                            files: origin
                                .files
                                .iter()
                                .map(|(file, md5)| SourceFileEvidence {
                                    file: strings.intern(file),
                                    md5: *md5,
                                })
                                .collect(),
                        });
                        self.git.insert(origin.clone(), id);
                        id
                    }
                };
                (*kind, id)
            }
            RuleKey::Layout {
                kind,
                package,
                version,
                family,
            } => {
                let slot = (*package, version.clone(), *family);
                let id = match self.layout.get(&slot) {
                    Some(id) => *id,
                    None => {
                        // Only a release inside the reviewed range is
                        // planned under a layout key.
                        let id = self.push_origin(SemanticOrigin::LibraryLayout {
                            package: strings.intern(package),
                            version: Some(strings.intern(version)),
                            family: strings.intern(family),
                            selection: LayoutSelection::ReviewedRange,
                        });
                        self.layout.insert(slot, id);
                        id
                    }
                };
                (*kind, id)
            }
        };
        let id = SemanticRuleId(u32::try_from(self.rules.len()).expect("rule overflow"));
        self.rules.push(SemanticRule {
            kind,
            revision: 1,
            origin,
        });
        self.by_key.insert(key.clone(), id);
        id
    }
}

/// Where a planned delegation lands, before the dyn ABI rule has an id.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Value(TypedPath),
    Dynamic {
        pointer: TypedPath,
        data: TypedPath,
        vtable: TypedPath,
        trait_ty: BundleTypeId,
        /// Whether the reviewed ABI settles where the poll sits, which
        /// it does for a bare `dyn Future` and no other trait.
        future_trait: bool,
        /// Boxed: the key is several times the size of the paths, and
        /// most targets are values.
        abi: Box<RuleKey>,
    },
}

impl Target {
    /// The static type a delegation proves a future, if it names one.
    fn static_child(&self) -> Option<BundleTypeId> {
        match self {
            Target::Value(path) => Some(path.target),
            Target::Dynamic { .. } => None,
        }
    }

    fn into_future_target(
        self,
        rules: &mut Rules,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> FutureTarget {
        match self {
            Target::Value(path) => FutureTarget::Value(path),
            Target::Dynamic {
                pointer,
                data,
                vtable,
                trait_ty,
                future_trait,
                abi,
            } => FutureTarget::Dynamic {
                pointer,
                layout: DynFutureLayout {
                    abi: rules.rule(&abi, strings, library),
                    data,
                    vtable,
                    trait_ty,
                    drop_slot: 0,
                    size_slot: 1,
                    align_slot: 2,
                    poll_slot: future_trait.then_some(3),
                },
            },
        }
    }
}

/// One coroutine state's planned action.
#[derive(Clone, Debug)]
enum CaseAction {
    Unresumed,
    Returned,
    Panicked,
    Delegate(Box<Target>),
    /// The state in which the type is itself the resource: its poll
    /// registers on what the resource names and forwards to nothing.
    Primitive,
    Unknown(SemanticIssue),
}

/// A program as planned: its rule, and either one action or a case per
/// coroutine state. Every path in it has been held to the validator's
/// rule over the final table already.
#[derive(Clone, Debug)]
struct Plan {
    rule: RuleKey,
    /// The poll program, for a type that is a future. A storage route
    /// that is polled through and never polled itself — a stream over
    /// the box it owns — plans none, and has only its access.
    program: Option<Delegation>,
    /// The storage access the same route establishes, for an adapter.
    access: Option<(RuleKey, AccessKind, Target)>,
    /// Whether the program's delegate is thereby a future: a poll
    /// forwarded to a poll proves it, a poll that runs the delegate's
    /// `poll_next` names a stream and proves nothing.
    delegate_is_future: bool,
    /// The resource the type is in the state its program marks
    /// [`CaseAction::Primitive`]: hyper-util's version-choosing wrapper
    /// is the connection while it reads the first bytes, under the
    /// program's own rule as its protocol.
    resource: Option<ResourceKind>,
}

/// A `select!` binding as planned: its rule, the three routes held
/// to the final table, and where each branch's arm is written.
#[derive(Clone, Debug)]
struct SelectPlan {
    rule: RuleKey,
    mask: TypedPath,
    futures: TypedPath,
    branches: Vec<TypedPath>,
    arms: Vec<Option<SourceLoc>>,
}

#[derive(Clone, Debug)]
enum Delegation {
    Direct {
        target: Target,
        exclusive: bool,
    },
    /// One action per state of an enum the reviewed implementation
    /// matches on: a compiler coroutine's states, futures-util's
    /// two-state `Map`, or the `Option` a hyper connection wrapper
    /// holds its connection in. `state` is the route from the future
    /// to that enum — empty where the future is the enum itself.
    Match {
        state: TypedPath,
        cases: Vec<(StrRef, CaseAction)>,
    },
    /// The reviewed poll returns `Pending` and does nothing else: no
    /// delegate, no state, nothing to route to.
    NeverReady,
}

impl Plan {
    fn static_children(&self) -> Vec<BundleTypeId> {
        if !self.delegate_is_future {
            return Vec::new();
        }
        match &self.program {
            None => Vec::new(),
            Some(Delegation::Direct { target, .. }) => target.static_child().into_iter().collect(),
            Some(Delegation::Match { cases, .. }) => cases
                .iter()
                .filter_map(|(_, action)| match action {
                    CaseAction::Delegate(target) => target.static_child(),
                    _ => None,
                })
                .collect(),
            Some(Delegation::NeverReady) => Vec::new(),
        }
    }
}

type Decline = (SemanticIssueKind, String);

/// A record in the making: everything decided about one type before the
/// rules are numbered.
#[derive(Default)]
struct Draft {
    storage: Option<StoragePolicy>,
    coroutine: Option<CoroutineLayout>,
    coroutine_rule: Option<RuleKey>,
    /// The rule naming which kind of coroutine a compiler candidate
    /// is, where its verdict supports one.
    coroutine_kind: Option<RuleKey>,
    /// The primitive the future acquires a batch semaphore for, where
    /// it is one of an owner's that reaches an acquire.
    acquires_for: Option<&'static str>,
    issues: Vec<Decline>,
    evidence: BTreeSet<FutureEvidence>,
    resource: Option<ResourceKind>,
    /// The container the type is bound as, with the rule it binds
    /// under — decided with the seed in hand, since the map's rule is
    /// an origin read off the seed's sources.
    container: Option<(ContainerKind, RuleKey)>,
    plan: Option<Plan>,
    /// Why no program was planned, when a reviewed shape was screened
    /// and declined: the continuation's reason, over the bare `NoRule`.
    decline: Option<Decline>,
    /// The type an adapter's storage leads to, for deciding whether an
    /// adapter with no future evidence still earns a record.
    pointee: Option<BundleTypeId>,
    /// The `select!` branches this `PollFn` polls, where it is one.
    select: Option<SelectPlan>,
    /// The connection words this dispatcher's poll drives, where it is
    /// hyper's under a reviewed range.
    http: Option<HttpPlan>,
    /// The request's words this value keeps, where its type is one a
    /// reviewed range says does.
    request: Option<RequestPlan>,
    /// The hash table this value keeps, where its type is one a
    /// reviewed range lays out.
    table: Option<TablePlan>,
    /// The pooled connections this value names, where its type is a
    /// hyper-util pool's reaper or checkout under a reviewed range.
    pool: Option<PoolPlan>,
    /// A pooled connection's info, where the type is hyper-util's
    /// `Connected` under a reviewed range.
    connected: Option<ConnectedPlan>,
    /// The route a read or write through a value of the type takes,
    /// where it ends at a socket.
    io_route: Option<(RuleKey, PlannedStep)>,
    /// The stream an io operation polls, where it is one over a routed
    /// stream.
    io: Option<IoOpPlan>,
    /// A rustls connection's words, where they bind.
    tls_session: Option<TlsSessionPlan>,
    /// A routed TLS stream's connection and state, where they bind.
    tls_stream: Option<(TypedPath, TypedPath)>,
    /// A routed stream's peer name, where it binds.
    stream_peer: Option<TypedPath>,
    /// What a handshake's frame keeps of the far end, where it binds.
    far_end: Option<FarEndPlan>,
    /// The header's value member, with the rule it binds under.
    refcount: Option<(RuleKey, MemberRef)>,
    /// The lock's word, with the rule it binds under.
    lock: Option<(RuleKey, LockWord)>,
    own_record: bool,
}

impl Draft {
    /// Whether the type is positively a future: something proved it
    /// one, or its storage is a bound coroutine's — which is proof in
    /// itself, ahead of the rule number that spells it as evidence.
    fn is_future(&self) -> bool {
        !self.evidence.is_empty() || self.coroutine.is_some()
    }
}

/// Run after type demotion and coroutine member pruning, while strings can
/// still be interned. Identity survives an opaque executable layout; the
/// library bindings attach to the exact types the walk contract bound
/// its routes at, and a task entry's scheduler class to the entry whose
/// `S` the class's route bound at.
pub(super) fn bind_semantics(
    mut seeds: SemanticSeeds,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
    tasks: &mut [TaskFutureEntry],
    library: &Library<'_>,
) -> SemanticTable {
    let mut rules = Rules::new();
    let mut drafts: BTreeMap<BundleTypeId, Draft> = BTreeMap::new();
    for (i, task) in tasks.iter().enumerate() {
        seeds.entry(task.future).or_default();
        drafts
            .entry(task.future)
            .or_default()
            .evidence
            .insert(FutureEvidence::TaskEntry(TaskEntryId(
                u32::try_from(i).expect("task table overflow"),
            )));
    }
    for (kind, _) in RESOURCE_KINDS {
        for ty in bound_roots(
            library.walks,
            required_resource_roles(kind),
            required_resource_routes(kind),
        ) {
            seeds.entry(ty).or_default().resource = Some(kind);
        }
    }
    for (kind, _) in CONTAINER_KINDS {
        for ty in bound_roots(library.walks, container_roles(kind), container_routes(kind)) {
            seeds.entry(ty).or_default().container = Some(kind);
        }
    }
    // The stream routes, over every seed at once: an operation is a
    // resource exactly where its stream's route ends at a socket.
    let io = plan_io(&seeds, types, names, strings, library.walks);
    for (&ty, op) in &io.operations {
        seeds.entry(ty).or_default().resource = Some(ResourceKind::IoOperation(op.kind));
    }

    // Every extra a `Connected`'s vtable may name: the types whose `set`
    // the sweep found.
    let extras: Vec<(BundleTypeId, BTreeSet<String>)> = seeds
        .iter()
        .filter(|(_, seed)| !seed.extra_symbols.is_empty())
        .map(|(&ty, seed)| (ty, seed.extra_symbols.clone()))
        .collect();

    // Phase A: decide storage, layout and the candidate program of every
    // seed, without numbering anything.
    for (&ty, seed) in &seeds {
        let draft = drafts.entry(ty).or_default();
        draft.own_record = seed.is_own_record() || !draft.evidence.is_empty();
        for symbol in &seed.polls {
            draft
                .evidence
                .insert(FutureEvidence::PollSymbol(strings.intern(symbol)));
        }
        if seed.coroutine_candidate {
            draft.coroutine_kind = coroutine_kind_rule(ty, seed, names);
        }
        let storage = if seed.coroutine_candidate {
            // A compiler candidate reads its states only under a reviewed
            // convention that its every defining unit supports and whose
            // shape this enum then actually has; anything less leaves the
            // storage unavailable, with the reason beside it.
            match bind_coroutine(ty, seed, types, names, strings) {
                Ok((rule, layout)) => {
                    draft.plan = Some(coroutine_plan(ty, &rule, &layout, types, strings));
                    draft.coroutine = Some(layout);
                    draft.coroutine_rule = Some(rule);
                    StoragePolicy::CoroutineStates
                }
                Err(decline) => {
                    draft.issues.push(decline.clone());
                    StoragePolicy::Unavailable(SemanticIssue {
                        kind: decline.0,
                        detail: Some(strings.intern(&decline.1)),
                    })
                }
            }
        } else if matches!(types.get(ty), Some(TypeDef::Opaque { .. })) {
            StoragePolicy::Unavailable(SemanticIssue {
                kind: SemanticIssueKind::MissingLayout,
                detail: None,
            })
        } else {
            StoragePolicy::DeclaredMembers
        };
        // A capability needs readable storage; a route cannot have bound
        // at a type without it, so this only guards the record's shape.
        let readable = matches!(storage, StoragePolicy::DeclaredMembers);
        draft.resource = seed.resource.filter(|_| readable);
        // A stream's route is a record of its own wherever it ends at a
        // socket, since a reader follows it type by type (Phase C); one
        // that runs off every reviewed route says why beside whatever
        // record the type has. An operation over no routed stream is no
        // resource, and that is its continuation's reason.
        if readable {
            if let Some(step) = io.routes.get(&ty) {
                draft.io_route = Some(step.clone());
            }
            if let Some(decline) = io.route_declines.get(&ty) {
                draft.issues.push(decline.clone());
            }
            draft.io = io.operations.get(&ty).cloned();
            draft.tls_session = io.sessions.get(&ty).cloned();
            draft.tls_stream = io.tls_streams.get(&ty).cloned();
            draft.stream_peer = io.peers.get(&ty).cloned();
            if let Some(decline) = io.tls_declines.get(&ty) {
                draft.issues.push(decline.clone());
            }
            if let Some(decline) = io.operation_declines.get(&ty) {
                draft.decline = Some(decline.clone());
            }
        }
        // A container whose rule declines — the map declared off the
        // registry, or at an unreviewed version — keeps its record and
        // says why, and is walked by no contract.
        draft.container =
            seed.container
                .filter(|_| readable)
                .and_then(|kind| match container_rule(kind, seed) {
                    Ok(rule) => Some((kind, rule)),
                    Err(decline) => {
                        draft.issues.push(decline);
                        None
                    }
                });
        if readable && draft.plan.is_none() {
            if let Some(adapter) = &seed.adapter {
                match plan_adapter(ty, adapter, types, strings) {
                    Ok(plan) => {
                        draft.pointee = adapter_pointee(adapter);
                        draft.plan = Some(plan);
                    }
                    Err(decline) => draft.decline = Some(decline),
                }
            } else if let Some(decline) = &seed.adapter_declined {
                draft.decline = Some(decline.clone());
            } else if let Some(instrumented) = &seed.instrumented {
                match plan_instrumented(ty, instrumented, seed, types, names, strings) {
                    Ok(plan) => draft.plan = Some(plan),
                    Err(decline) => draft.decline = Some(decline),
                }
            } else if let Some(verdict) = &seed.pending {
                // The terminal is a program like any other: it needs a
                // future to be about, so a `Pending` nothing proves a
                // future — a member of a type with no plan — plans one
                // and never emits it.
                match plan_pending(verdict) {
                    Ok(plan) => draft.plan = Some(plan),
                    Err(decline) => draft.decline = Some(decline),
                }
            } else if let Some(library) = &seed.library {
                // A route that is polled through and never polled — a
                // stream over the box it owns — is a record on the
                // strength of its screen alone: nothing will ever prove
                // it a future, and a declined origin has nowhere else
                // to be recorded.
                draft.own_record |= library.records_on_its_screen();
                match plan_library(ty, library, seed, types, strings) {
                    Ok(plan) => draft.plan = Some(plan),
                    Err(decline) => draft.decline = Some(decline),
                }
            }
        }
        // The select binding is a fact beside the continuation, not a
        // program: the `PollFn` still polls nothing any rule follows.
        // An arm the join could not place is an issue beside a binding
        // that stands; a layout the plan could not read is no binding.
        if readable && let Some(select) = &seed.select {
            match plan_select(ty, select, types, strings) {
                Ok((plan, mut declined)) => {
                    draft.issues.append(&mut declined);
                    draft.select = Some(plan);
                }
                Err(decline) => draft.issues.push(decline),
            }
        }
        // The dispatcher is the connection resource: its words are a
        // fact beside its continuation, which the resource makes the
        // primitive boundary. A declined origin or a moved layout is
        // the continuation's reason, as any other declined shape's.
        if readable && let Some(http) = &seed.http {
            match plan_http(ty, http, &seed.poll_sources, types, strings) {
                Ok(mut plan) => {
                    draft.issues.extend(plan.peer_declined.take());
                    // The stream hyper's buffered io holds, where its
                    // route ends at a socket: what the connection reads
                    // and writes, beside the words its state keeps. One
                    // with no reviewed route says why, and the words
                    // stand without it.
                    match hop_landing(
                        types,
                        strings,
                        ty,
                        &[
                            Hop::Member(hyper_h1::CONN),
                            Hop::Member(hyper_h1::IO),
                            Hop::Member(hyper_h1::IO),
                        ],
                    ) {
                        Ok(stream) if io.routes.contains_key(&stream.target) => {
                            plan.stream = Some(stream);
                        }
                        Ok(stream) => draft.issues.push((
                            SemanticIssueKind::NoRule,
                            format!(
                                "the stream it reads, {}, has no reviewed route to a socket",
                                type_label(names, stream.target)
                            ),
                        )),
                        Err(decline) => draft.issues.push(decline),
                    }
                    draft.http = Some(plan);
                }
                Err(decline) => draft.decline = Some(decline),
            }
        }
        // The request's words are a fact beside whatever else the record
        // says, and route through nothing the type polls: a declined
        // origin or a moved layout is an issue beside the record, not
        // the continuation's reason.
        if readable && let Some(request) = &seed.request {
            match plan_request(ty, request, &seed.poll_sources, types, strings) {
                Ok(plan) => draft.request = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        // And what a handshake's frame keeps of the far end, over the
        // coroutine's own states: a fact beside its layout, and an issue
        // beside the record where the review or a state declines.
        if matches!(storage, StoragePolicy::CoroutineStates)
            && let Some((rule, source)) = &seed.far_end
        {
            // The TLS streams the io plans keep are all routed ones.
            let tls_stream = |ty: BundleTypeId| io.tls_streams.contains_key(&ty);
            // A handshake the state awaits: tokio-rustls's `Accept` or
            // `Connect` at a reviewed release, polling its one member,
            // whose handshake holds the stream as its io operation's.
            let awaited = |awaitee: BundleTypeId| -> Option<(Vec<Step>, BundleTypeId)> {
                let awaited_seed = seeds.get(&awaitee)?;
                let Some(library @ LibrarySeed::TokioRustlsHandshake(member, inner)) =
                    &awaited_seed.library
                else {
                    return None;
                };
                let (sources, declared_by) = library.origin_sources(awaited_seed);
                delegation_origin(&sources, library.convention(), declared_by).ok()?;
                let handshake = io
                    .operations
                    .get(inner)
                    .filter(|op| op.kind == IoOperationKind::Handshake)?;
                let (mut steps, landed) =
                    hop_steps(types, strings, awaitee, &[Hop::Member(member)]).ok()?;
                (landed == *inner).then_some(())?;
                steps.extend(handshake.stream.steps.iter().copied());
                Some((steps, handshake.stream.target))
            };
            match plan_far_end(
                ty,
                rule,
                source.as_ref(),
                &tls_stream,
                &awaited,
                types,
                strings,
            ) {
                Ok(plan) => draft.far_end = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        // Likewise the table: what a scan reads a map's entries through,
        // and an issue beside the record where it declines.
        if readable && let Some(table) = &seed.table {
            match plan_table(ty, table, types, strings) {
                Ok(plan) => draft.table = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        // And the pool: what names a pooled connection, beside the record.
        if readable && let Some(pool) = &seed.pool {
            match plan_pool(ty, pool, types, strings) {
                Ok(plan) => draft.pool = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        // And the info the pool keeps beside each sender.
        if readable && let Some(connected) = &seed.connected {
            match plan_connected(ty, connected, &seeds, &extras, types, names, strings) {
                Ok(plan) => draft.connected = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        // A header's value and a lock's word are facts beside the
        // record, read wherever a path or a wait list reaches a value
        // of the type; an origin or a layout the review did not cover
        // is an issue beside the record.
        if readable && let Some((value, verdict)) = &seed.refcount {
            match plan_refcount(ty, value, verdict, types, strings) {
                Ok(plan) => draft.refcount = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        if readable && let Some(lock) = &seed.lock {
            match plan_lock(ty, lock, types, strings) {
                Ok(plan) => draft.lock = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        draft.storage = Some(storage);
    }

    // Phase B: the least fixed point over the bound delegations. A type
    // that is positively a future and has a planned program proves each
    // static delegate a future; a delegate so proved runs its own plan,
    // if it has one. An adapter with no evidence proves nothing. A
    // bound coroutine is a future by its storage alone — its own
    // evidence is numbered only at emit time, so the seed asks the
    // draft, not the evidence set.
    let mut queue: VecDeque<BundleTypeId> = drafts
        .iter()
        .filter(|(_, d)| d.is_future() && d.plan.is_some())
        .map(|(&ty, _)| ty)
        .collect();
    while let Some(parent) = queue.pop_front() {
        let children = drafts[&parent]
            .plan
            .as_ref()
            .map(Plan::static_children)
            .unwrap_or_default();
        for child in children {
            let draft = drafts.entry(child).or_default();
            let was_future = draft.is_future();
            draft
                .evidence
                .insert(FutureEvidence::DelegatedBy { parent });
            if !was_future && draft.plan.is_some() {
                queue.push_back(child);
            }
        }
    }

    // The primitive an acquire is made for: a coroutine of an owner's
    // module whose bound chain reaches a semaphore acquire. The module
    // names the primitive; the chain is what says the future acquires
    // at all — a bounded sender's `closed` lies in the same module and
    // waits on no permit.
    let acquires: BTreeSet<BundleTypeId> = drafts
        .iter()
        .filter(|(_, d)| d.resource == Some(ResourceKind::SemaphoreAcquire))
        .map(|(&ty, _)| ty)
        .collect();
    let owned: Vec<(BundleTypeId, &'static str)> = seeds
        .iter()
        .filter(|(_, seed)| seed.coroutine_candidate)
        .filter_map(|(&ty, _)| {
            let name = names.get(ty.0 as usize)?.as_deref()?;
            let primitive = tokio_acquire_owner(name, library.tokio_version)?;
            reaches_any(ty, &drafts, &acquires).then_some((ty, primitive))
        })
        .collect();
    for (ty, primitive) in owned {
        drafts.entry(ty).or_default().acquires_for = Some(primitive);
    }

    // Phase C: which drafts become records. A seed with identity,
    // storage or a library binding always does; a future does; an
    // adapter whose storage leads to a record does, so that discovery
    // can follow the owned route to it. A stream's route makes a record
    // too, but one discovery has no business following: a pointer to a
    // stream is no adapter, whatever its type's route says; nor is a
    // pointer to a TLS connection.
    let mut discovered: BTreeSet<BundleTypeId> = drafts
        .iter()
        .filter(|(_, d)| d.own_record || !d.evidence.is_empty())
        .map(|(&ty, _)| ty)
        .collect();
    loop {
        let more: Vec<BundleTypeId> = drafts
            .iter()
            .filter(|(ty, d)| {
                !discovered.contains(ty)
                    && d.plan.as_ref().is_some_and(|p| p.access.is_some())
                    && d.pointee.is_some_and(|p| discovered.contains(&p))
            })
            .map(|(&ty, _)| ty)
            .collect();
        if more.is_empty() {
            break;
        }
        discovered.extend(more);
    }
    let included: BTreeSet<BundleTypeId> = drafts
        .iter()
        .filter(|(ty, d)| {
            discovered.contains(ty)
                || d.io_route.is_some()
                || d.tls_session.is_some()
                || d.tls_stream.is_some()
        })
        .map(|(&ty, _)| ty)
        .collect();
    // A pool's route to a connection's info stands only where that info
    // binds.
    let connected: BTreeSet<BundleTypeId> = included
        .iter()
        .filter(|ty| drafts[ty].connected.is_some())
        .copied()
        .collect();
    let info = |path: Option<TypedPath>| path.filter(|path| connected.contains(&path.target));

    // Phase D: number the rules in record order and emit.
    let issue = |kind| SemanticIssue { kind, detail: None };
    let mut records = Vec::with_capacity(included.len());
    for ty in included {
        let draft = drafts.remove(&ty).expect("included drafts exist");
        let storage = draft.storage.unwrap_or_else(|| {
            // A type that entered through a delegation alone: its storage
            // is whatever its layout says, like any other seed.
            if matches!(types.get(ty), Some(TypeDef::Opaque { .. })) {
                StoragePolicy::Unavailable(issue(SemanticIssueKind::MissingLayout))
            } else if names
                .get(ty.0 as usize)
                .and_then(|n| n.as_deref())
                .is_some_and(crate::bundle::names::is_coroutine_candidate)
            {
                StoragePolicy::Unavailable(SemanticIssue {
                    kind: SemanticIssueKind::UnsupportedOrigin,
                    detail: Some(strings.intern("no defining unit recorded")),
                })
            } else {
                StoragePolicy::DeclaredMembers
            }
        });
        let readable = matches!(storage, StoragePolicy::DeclaredMembers);
        let resource = draft.resource.map(|kind| {
            let rule_kind = resource_rule(kind);
            // The layout rule binds under whatever family was selected;
            // the state protocol only inside its reviewed range, which
            // the one tokio origin's selection records — so a guessed
            // family observes and never assesses. Each reviewed
            // primitive polls nothing else while pending, which is the
            // exclusive-pending guarantee the barrier proof needs.
            // tokio's own under its one origin; an operation of another
            // crate's under the rule its plan read the origin of.
            let rule = match draft.io.as_ref().and_then(|io| io.rule.as_ref()) {
                Some(key) => rules.rule(key, strings, library),
                None => rules.rule(&RuleKey::Library(rule_kind), strings, library),
            };
            // A handshake's protocol is its own rule, as a connection's
            // is: tokio-rustls's origin binds only inside the reviewed
            // range, and a pending `MidHandshake` polls its stream and
            // nothing else.
            let state_rule = if kind == ResourceKind::IoOperation(IoOperationKind::Handshake) {
                Some(rule)
            } else {
                tokio_state_protocol(kind, library.tokio_version)
                    .filter(|_| {
                        Family::layout_selection(library.tokio_version)
                            == LayoutSelection::ReviewedRange
                    })
                    .map(|protocol| rules.rule(&RuleKey::Library(protocol.kind), strings, library))
            };
            ResourceBinding {
                rule,
                kind,
                state_rule,
                exclusive_pending: state_rule.is_some(),
            }
        });
        // The connection resource binds under the hyper rule its
        // delegation origin selected, which is also its protocol: the
        // reviewed range is what says what the words mean. A pending
        // client dispatcher has registered its waker on the socket and
        // on its dispatch primitive and polls nothing outside itself,
        // which is the exclusive-pending guarantee; a server dispatcher
        // polls the handler it holds while a request is in flight,
        // which awaits whatever the application wrote, so it carries
        // no such guarantee.
        let http = draft.http.filter(|_| readable).map(|plan| {
            let rule = rules.rule(&plan.rule, strings, library);
            (
                ResourceBinding {
                    rule,
                    kind: ResourceKind::HttpConn,
                    state_rule: Some(rule),
                    exclusive_pending: plan.role == HttpRole::Client,
                },
                HttpConnBinding {
                    rule,
                    role: plan.role,
                    keep_alive: plan.keep_alive,
                    reading: plan.reading,
                    writing: plan.writing,
                    method: plan.method,
                    method_inner: plan.method_inner,
                    read_continue_kind: plan.read_continue_kind,
                    read_body_kind: plan.read_body_kind,
                    write_body_kind: plan.write_body_kind,
                    is_closing: plan.is_closing,
                    stream: plan.stream,
                    client: plan.client,
                    server: plan.server.map(|server| HttpServerBinding {
                        in_flight: server.in_flight,
                        header_read_timeout_running: server.header_read_timeout_running,
                        header_read_timeout_secs: server.header_read_timeout_secs,
                        header_read_timeout_nanos: server.header_read_timeout_nanos,
                        header_read_timer: server.header_read_timer,
                        service: server.service.map(|service| HttpServiceBinding {
                            rule: rules.rule(&service.key, strings, library),
                            peer: service.peer,
                            context: service.context,
                            local_addr: service.local_addr,
                            tls_acceptor: service.tls_acceptor,
                        }),
                    }),
                },
            )
        });
        let (resource, http) = match http {
            Some((resource_binding, http)) => (resource.or(Some(resource_binding)), Some(http)),
            None => (resource, None),
        };
        // A program whose state marks the type itself the resource —
        // hyper-util's wrapper reading a connection's first bytes —
        // binds the resource under the program's rule, which is also
        // its protocol: the reviewed poll registers on the socket read
        // alone in that state. The program stays the continuation,
        // since it is what selects the state, and the resource is bound
        // once the program is, below: like any program it needs a
        // future to be about.
        let plan_resource = draft
            .plan
            .as_ref()
            .filter(|_| readable)
            .and_then(|plan| plan.resource.map(|kind| (kind, plan.rule.clone())));
        let mut resource = resource;
        let container = draft.container.map(|(kind, rule)| ContainerBinding {
            rule: rules.rule(&rule, strings, library),
            kind,
            wakers: kind.wakers(),
        });
        let coroutine = draft.coroutine.map(|layout| CoroutineLayout {
            rule: rules.rule(
                draft
                    .coroutine_rule
                    .as_ref()
                    .expect("a coroutine layout has its rule"),
                strings,
                library,
            ),
            states: layout.states,
        });
        let mut evidence: Vec<FutureEvidence> = draft.evidence.into_iter().collect();
        if let Some(layout) = &coroutine {
            evidence.push(FutureEvidence::Coroutine(layout.rule));
            evidence.sort();
        }
        let mut issues: Vec<SemanticIssue> = draft
            .issues
            .iter()
            .map(|(kind, detail)| SemanticIssue {
                kind: *kind,
                detail: Some(strings.intern(detail)),
            })
            .collect();
        let mut access = None;
        // A program is a fact about polling, so it needs a future to be
        // about: an adapter nothing proves a future keeps its storage
        // access and no continuation, and numbers no poll rule. One
        // recorded only for its stream route keeps no access either.
        let program = match draft.plan.filter(|_| readable || coroutine.is_some()) {
            Some(plan) => {
                if let Some((access_rule, kind, target)) =
                    plan.access.filter(|_| discovered.contains(&ty))
                {
                    access = Some(AccessBinding {
                        rule: rules.rule(&access_rule, strings, library),
                        kind,
                        target: target.into_future_target(&mut rules, strings, library),
                    });
                }
                if evidence.is_empty() {
                    None
                } else if let Some(program) = plan.program {
                    let rule = rules.rule(&plan.rule, strings, library);
                    let program = match program {
                        Delegation::Direct { target, exclusive } => {
                            PollProgram::Direct(PollAction::Delegate {
                                target: target.into_future_target(&mut rules, strings, library),
                                exclusive,
                            })
                        }
                        Delegation::NeverReady => PollProgram::Direct(PollAction::NeverReady),
                        Delegation::Match { state, cases } => PollProgram::MatchVariant {
                            state,
                            cases: cases
                                .into_iter()
                                .map(|(variant, action)| PollCase {
                                    variant,
                                    action: match action {
                                        CaseAction::Unresumed => PollAction::Unresumed,
                                        CaseAction::Returned => PollAction::Returned,
                                        CaseAction::Panicked => PollAction::Panicked,
                                        CaseAction::Primitive => PollAction::Primitive,
                                        CaseAction::Delegate(target) => PollAction::Delegate {
                                            target: target
                                                .into_future_target(&mut rules, strings, library),
                                            exclusive: true,
                                        },
                                        CaseAction::Unknown(issue) => PollAction::Unknown(issue),
                                    },
                                })
                                .collect(),
                        },
                    };
                    Some((rule, program))
                } else {
                    // Proved a future by something, yet a route with no
                    // program: its continuation stays unknown, its
                    // access beside it.
                    None
                }
            }
            None => None,
        };
        let program_is_the_resource = match (plan_resource, &program) {
            (Some((kind, rule)), Some((program_rule, _))) => {
                debug_assert!(
                    resource.is_none(),
                    "a program's resource beside a walk-bound one"
                );
                let rule = rules.rule(&rule, strings, library);
                debug_assert_eq!(rule, *program_rule);
                resource = Some(ResourceBinding {
                    rule,
                    kind,
                    state_rule: Some(rule),
                    exclusive_pending: true,
                });
                true
            }
            _ => false,
        };
        // A resource that is positively a future polls its own state and
        // nothing else: its continuation is the primitive boundary. What
        // that state means — ready, pending, closed — is the state
        // rule's to say, and none is bound here. A program that made
        // its type the resource is the boundary itself, in the state
        // it marks.
        let continuation = match (&resource, program) {
            (Some(resource), _) if !program_is_the_resource => Continuation::Bound {
                rule: resource.rule,
                program: PollProgram::Direct(PollAction::Primitive),
            },
            (_, Some((rule, program))) => Continuation::Bound { rule, program },
            (Some(_), None) => unreachable!("a program marked its type the resource"),
            (None, None) => match &draft.decline {
                Some((kind, detail)) => {
                    let detail = strings.intern(detail);
                    issues.push(SemanticIssue {
                        kind: *kind,
                        detail: Some(detail),
                    });
                    Continuation::Unknown(SemanticIssue {
                        kind: *kind,
                        detail: Some(detail),
                    })
                }
                None => Continuation::Unknown(issue(SemanticIssueKind::NoRule)),
            },
        };
        let select = draft.select.filter(|_| readable).map(|plan| SelectBinding {
            rule: rules.rule(&plan.rule, strings, library),
            mask: plan.mask,
            futures: plan.futures,
            branches: plan.branches,
            arms: plan.arms,
        });
        let request = draft
            .request
            .filter(|_| readable)
            .map(|plan| HttpRequestBinding {
                rule: rules.rule(&plan.rule, strings, library),
                method: plan.method,
                target: plan.target,
                target_ptr: plan.target_ptr,
                target_len: plan.target_len,
            });
        let table = draft
            .table
            .filter(|_| readable)
            .map(|plan| HashTableBinding {
                rule: rules.rule(&plan.rule, strings, library),
                bucket_mask: plan.bucket_mask,
                ctrl: plan.ctrl,
                items: plan.items,
                bucket: plan.bucket,
            });
        let pool = draft.pool.filter(|_| readable).map(|plan| match plan {
            PoolPlan::Reaper {
                rule,
                strong,
                idle,
                key_ptr,
                key_len,
                entries_ptr,
                entries_len,
                entry,
                want,
                conn_info,
            } => HttpPoolBinding::Reaper {
                rule: rules.rule(&rule, strings, library),
                strong,
                idle,
                key_ptr,
                key_len,
                entries_ptr,
                entries_len,
                entry,
                want,
                conn_info: info(conn_info),
            },
            PoolPlan::Checkout {
                rule,
                key_ptr,
                key_len,
                want,
                conn_info,
            } => HttpPoolBinding::Checkout {
                rule: rules.rule(&rule, strings, library),
                key_ptr,
                key_len,
                want,
                conn_info: info(conn_info),
            },
        });
        let connected = draft
            .connected
            .filter(|_| readable)
            .map(|plan| ConnectedBinding {
                rule: rules.rule(&plan.rule, strings, library),
                alpn: plan.alpn,
                is_proxied: plan.is_proxied,
                extra: plan.extra,
                layout: DynStreamLayout {
                    abi: rules.rule(&plan.abi, strings, library),
                    data: plan.data,
                    vtable: plan.vtable,
                    size_slot: 1,
                    align_slot: 2,
                    read_slot: EXTRA_INNER_SET_SLOT,
                },
                cases: plan
                    .cases
                    .into_iter()
                    .map(|case| ExtraCase {
                        symbol: strings.intern(&case.symbol),
                        target: case.target,
                        remote_addr: case.remote_addr,
                        local_addr: case.local_addr,
                        next: case.next,
                    })
                    .collect(),
            });
        // An operation's stream is reached under the operation's own
        // rule, beside the resource it is; a stream's route under the
        // rule of whoever implements the stream.
        let io = draft
            .io
            .filter(|_| readable)
            .zip(resource.as_ref())
            .map(|(plan, resource)| IoOperationBinding {
                rule: resource.rule,
                stream: plan.stream,
                remaining: plan.remaining,
            });
        // A TLS stream's words bind under its route's rule: the review
        // that routes it is the one that names its members.
        let tls_stream = draft
            .tls_stream
            .zip(draft.io_route.as_ref())
            .filter(|_| readable)
            .map(|((session, state), (rule, _))| TlsStreamBinding {
                rule: rules.rule(rule, strings, library),
                session,
                state,
            });
        let stream_peer = draft
            .stream_peer
            .zip(draft.io_route.as_ref())
            .filter(|_| readable)
            .map(|(name, (rule, _))| StreamPeerBinding {
                rule: rules.rule(rule, strings, library),
                name,
            });
        let far_end = draft.far_end.map(|plan| FarEndBinding {
            rule: rules.rule(&plan.rule, strings, library),
            states: plan.states,
        });
        let io_route = draft
            .io_route
            .filter(|_| readable)
            .map(|(rule, step)| IoRouteBinding {
                rule: rules.rule(&rule, strings, library),
                step: match step {
                    PlannedStep::Fixed(step) => step,
                    PlannedStep::Dyn {
                        pointer,
                        data,
                        vtable,
                        abi,
                        read_slot,
                        cases,
                    } => IoRouteStep::Dyn {
                        pointer,
                        layout: DynStreamLayout {
                            abi: rules.rule(&abi, strings, library),
                            data,
                            vtable,
                            size_slot: 1,
                            align_slot: 2,
                            read_slot,
                        },
                        cases: cases
                            .into_iter()
                            .map(|(symbol, target)| DynStreamCase {
                                symbol: strings.intern(&symbol),
                                target,
                            })
                            .collect(),
                    },
                },
            });
        let tls_session = draft
            .tls_session
            .filter(|_| readable)
            .map(|plan| TlsSessionBinding {
                rule: rules.rule(&plan.rule, strings, library),
                state: plan.state,
                side: plan.side,
                negotiated_version: plan.negotiated_version,
                version: plan.version,
                may_send_application_data: plan.may_send_application_data,
                may_receive_application_data: plan.may_receive_application_data,
                has_sent_close_notify: plan.has_sent_close_notify,
                has_received_close_notify: plan.has_received_close_notify,
                has_seen_eof: plan.has_seen_eof,
                sent_fatal_alert: plan.sent_fatal_alert,
                read_seq: plan.read_seq,
                write_seq: plan.write_seq,
                sendable: plan.sendable,
                received: plan.received,
                handshake_kind: plan.handshake_kind,
                suites: plan.suites,
                alpn_ptr: plan.alpn.as_ref().map(|(ptr, _)| ptr.clone()),
                alpn_len: plan.alpn.map(|(_, len)| len),
                peer_certificates: plan.peer_certificates,
            });
        records.push(TypeSemantics {
            ty,
            storage,
            future: (!evidence.is_empty()).then_some(FutureFacts {
                evidence,
                continuation,
            }),
            coroutine,
            access,
            resource,
            container,
            select,
            http,
            request,
            table,
            pool,
            connected,
            io_route,
            io,
            tls_session,
            tls_stream,
            stream_peer,
            far_end,
            refcount: draft.refcount.map(|(rule, value)| RefcountBinding {
                rule: rules.rule(&rule, strings, library),
                value,
            }),
            lock: draft.lock.map(|(rule, word)| LockBinding {
                rule: rules.rule(&rule, strings, library),
                word,
            }),
            acquires_for: draft.acquires_for.map(|primitive| AcquiresForBinding {
                rule: rules.rule(
                    &RuleKey::Library(SemanticRuleKind::TokioAcquireOwner),
                    strings,
                    library,
                ),
                primitive: strings.intern(primitive),
            }),
            coroutine_kind: draft
                .coroutine_kind
                .as_ref()
                .map(|key| rules.rule(key, strings, library)),
            issues,
        });
    }
    for task in tasks.iter_mut() {
        let mut classes = SCHEDULER_CLASSES.iter().filter(|(class, _)| {
            bound_roots(library.walks, &[scheduler_role(*class)], &[]).contains(&task.scheduler)
        });
        // Exactly one class may claim an entry's S; the roots are exact
        // types, so two claiming the same one is a table bug, and the
        // entry is left unknown rather than guessed.
        task.scheduler_binding = match (classes.next(), classes.next()) {
            (Some((class, rule_kind)), None) => Some(SchedulerBinding {
                class: *class,
                rule: rules.rule(&RuleKey::Library(*rule_kind), strings, library),
            }),
            _ => None,
        };
    }
    SemanticTable {
        origins: rules.origins,
        rules: rules.rules,
        types: records,
    }
}

fn adapter_pointee(adapter: &AdapterSeed) -> Option<BundleTypeId> {
    match &adapter.pointee {
        PointeeSeed::Sized(f) => Some(*f),
        PointeeSeed::Dyn(_) => None,
    }
}

/// Hold a planned path to the validator's own rule over the final table:
/// named members only, in bounds, landing on exactly the type claimed.
fn checked_path(
    types: &TypeTable,
    root: BundleTypeId,
    steps: Vec<Step>,
    target: BundleTypeId,
) -> Result<TypedPath, Decline> {
    match semantic_path_target(types, root, &Selector(steps.clone())) {
        Ok(landed) if landed == target => Ok(TypedPath { steps, target }),
        Ok(_) => Err((
            SemanticIssueKind::MissingLayout,
            "the route lands on another type than declared".to_owned(),
        )),
        Err(e) => Err((SemanticIssueKind::MissingLayout, e.to_string())),
    }
}

/// The unique member of `ty` named `name`, with its type.
fn member_named(
    types: &TypeTable,
    strings: &StringInterner,
    ty: BundleTypeId,
    name: &str,
) -> Option<(StrRef, BundleTypeId, u64)> {
    let mut found = members_of(types, ty)
        .iter()
        .filter(|m| strings.get(m.name) == Some(name));
    let member = found.next()?;
    found
        .next()
        .is_none()
        .then_some((member.name, member.ty, member.offset))
}

fn supported(verdict: &CompilerVerdict) -> Result<(&str, &'static RustcConvention), Decline> {
    match verdict {
        CompilerVerdict::Supported {
            producer,
            convention,
        } => Ok((producer, convention)),
        CompilerVerdict::Declined(detail) => {
            Err((SemanticIssueKind::UnsupportedOrigin, detail.clone()))
        }
    }
}

/// Plan core's `Pending<T>`: the compiler verdict on its defining units
/// is the whole of the evidence — the layout was the screen's, and the
/// reviewed poll routes to nothing — so the plan is the terminal under
/// the compiler rule, or the verdict's decline.
fn plan_pending(verdict: &CompilerVerdict) -> Result<Plan, Decline> {
    let (producer, convention) = supported(verdict)?;
    Ok(Plan {
        rule: RuleKey::Rustc {
            kind: SemanticRuleKind::CorePending,
            producer: producer.to_owned(),
            family: convention.family,
        },
        program: Some(Delegation::NeverReady),
        access: None,
        delegate_is_future: false,
        resource: None,
    })
}

/// Plan a std adapter's delegation: the compiler verdict on its
/// defining units, then the route the screen described held to the
/// final table — the `Pin` member that is its `Ptr`, the thin pointer
/// whose pointee is the declared `F`, or the wide pointer whose data
/// and vtable words are where the screen found them.
fn plan_adapter(
    ty: BundleTypeId,
    adapter: &AdapterSeed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<Plan, Decline> {
    let (producer, convention) = supported(&adapter.compiler)?;
    let rule = |kind| RuleKey::Rustc {
        kind,
        producer: producer.to_owned(),
        family: convention.family,
    };
    let mut steps = Vec::new();
    let mut current = ty;
    if let Some((member, ptr)) = &adapter.pin {
        let Some(TypeDef::Struct { members, .. }) = types.get(ty) else {
            return Err((
                SemanticIssueKind::MissingLayout,
                "Pin is not a struct in the final table".to_owned(),
            ));
        };
        let (name, member_ty, offset) = member_named(types, strings, ty, member).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("Pin has no unique member {member:?}"),
        ))?;
        if members.len() != 1 || member_ty != *ptr || offset != 0 {
            return Err((
                SemanticIssueKind::MissingLayout,
                "Pin's member is not its declared pointer".to_owned(),
            ));
        }
        steps.push(Step::Member(MemberRef::Named(name)));
        current = *ptr;
    }
    let target = match &adapter.pointee {
        PointeeSeed::Sized(f) => {
            if !matches!(types.get(current), Some(TypeDef::Pointer { target, .. }) if target == f) {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the adapter's pointer does not target its declared future".to_owned(),
                ));
            }
            steps.push(Step::Deref);
            Target::Value(checked_path(types, ty, steps, *f)?)
        }
        PointeeSeed::Dyn(d) => dynamic_target(ty, steps, current, d, types, strings)?,
    };
    Ok(Plan {
        rule: rule(adapter.kind.poll_rule()),
        access: Some((
            rule(adapter.kind.access_rule()),
            adapter.kind.access(),
            target.clone(),
        )),
        program: Some(Delegation::Direct {
            target,
            exclusive: true,
        }),
        delegate_is_future: true,
        resource: None,
    })
}

/// The dynamic target a wide pointer plans: `steps` from `ty` to the
/// wide pointer `current`, which has to be the one the screen saw,
/// held to the final table; inside it the two words the screen named,
/// each pointer-sized, the data word targeting the zero-sized trait
/// object; and the ABI rule its defining units were compiled under.
fn dynamic_target(
    ty: BundleTypeId,
    steps: Vec<Step>,
    current: BundleTypeId,
    d: &DynSeed,
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<Target, Decline> {
    let (abi_producer, abi) = supported(&d.abi)?;
    if current != d.wide {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the adapter's wide pointer is not the one screened".to_owned(),
        ));
    }
    let (pointer, data_ptr, _) = member_named(types, strings, d.wide, &d.pointer).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        "no unique data pointer member".to_owned(),
    ))?;
    let (vtable, vtable_ptr, _) = member_named(types, strings, d.wide, &d.vtable).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        "no unique vtable member".to_owned(),
    ))?;
    let wide_shape = data_ptr == d.data_ptr
        && vtable_ptr == d.vtable_ptr
        && matches!(types.get(d.data_ptr), Some(TypeDef::Pointer { target, .. }) if *target == d.trait_ty)
        && matches!(
            types.get(d.trait_ty),
            Some(TypeDef::Struct { size: 0, members, .. }) if members.is_empty()
        )
        && types.size_of(d.data_ptr) == Some(crate::bundle::POINTER_SIZE)
        && types.size_of(d.vtable_ptr) == Some(crate::bundle::POINTER_SIZE);
    if !wide_shape {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the wide pointer's words or trait object moved in the final table".to_owned(),
        ));
    }
    Ok(Target::Dynamic {
        pointer: checked_path(types, ty, steps, d.wide)?,
        data: checked_path(
            types,
            d.wide,
            vec![Step::Member(MemberRef::Named(pointer))],
            d.data_ptr,
        )?,
        vtable: checked_path(
            types,
            d.wide,
            vec![Step::Member(MemberRef::Named(vtable))],
            d.vtable_ptr,
        )?,
        trait_ty: d.trait_ty,
        future_trait: d.future_trait,
        abi: Box::new(RuleKey::Rustc {
            kind: SemanticRuleKind::DynFutureAbi,
            producer: abi_producer.to_owned(),
            family: abi.family,
        }),
    })
}

/// Plan a reviewed third-party wrapper's delegation: the origin first —
/// every declaration of its `poll` on a cargo registry path naming the
/// convention's crate at a version inside its reviewed range, or of
/// the type's own methods where the type is a storage route with no
/// poll — then the route the screen described, held to the final
/// table. Each of these implementations polls its delegate and nothing
/// else, so all of them forward exclusively; the two storage routes
/// plan no program at all, only the access their one member is.
fn plan_library(
    ty: BundleTypeId,
    seed_layout: &LibrarySeed,
    seed: &Seed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<Plan, Decline> {
    let rule = if seed_layout.origin_is_the_layout() {
        // The forward below is the proof: a sole member of the declared
        // type, under the crate's layout origin.
        RuleKey::Library(seed_layout.rule_kind())
    } else {
        let (sources, declared_by) = seed_layout.origin_sources(seed);
        let origin = delegation_origin(&sources, seed_layout.convention(), declared_by)?;
        RuleKey::Delegation {
            kind: seed_layout.rule_kind(),
            origin,
        }
    };
    // A wrapper's route is its one member; the map's is the member
    // inside its incomplete state, and the state is what selects it.
    let forward = |member: &str, inner: BundleTypeId, strings: &mut StringInterner| {
        let (name, member_ty, _) = member_named(types, strings, ty, member).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("no unique member {member:?}"),
        ))?;
        if member_ty != inner {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{member} holds another type than the screen declared"),
            ));
        }
        checked_path(types, ty, vec![Step::Member(MemberRef::Named(name))], inner)
    };
    let program = match seed_layout {
        LibrarySeed::Map {
            incomplete,
            future_member,
            complete,
            future,
        } => {
            let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Map is not an enum in the final table".to_owned(),
                ));
            };
            let variant = |name: &str| {
                shape
                    .variants
                    .iter()
                    .find(|v| strings.get(v.name) == Some(name))
                    .map(|v| (v.name, v.payload.ty))
            };
            let (incomplete_name, payload) = variant(incomplete).ok_or((
                SemanticIssueKind::MissingLayout,
                format!("Map has no {incomplete} state in the final table"),
            ))?;
            let (complete_name, _) = variant(complete).ok_or((
                SemanticIssueKind::MissingLayout,
                format!("Map has no {complete} state in the final table"),
            ))?;
            if shape.variants.len() != 2 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Map has states beyond the two reviewed ones".to_owned(),
                ));
            }
            let (member, member_ty, _) = member_named(types, strings, payload, future_member)
                .ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("Map's {incomplete} state has no unique member {future_member:?}"),
                ))?;
            if member_ty != *future {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{future_member} holds another type than the screen declared"),
                ));
            }
            let path = checked_path(
                types,
                ty,
                vec![
                    Step::Variant(incomplete_name),
                    Step::Member(MemberRef::Named(member)),
                ],
                *future,
            )?;
            Delegation::Match {
                state: TypedPath {
                    steps: Vec::new(),
                    target: ty,
                },
                cases: vec![
                    (
                        incomplete_name,
                        CaseAction::Delegate(Box::new(Target::Value(path))),
                    ),
                    // Polling a completed map panics, so this state is
                    // where its output was already produced.
                    (complete_name, CaseAction::Returned),
                ],
            }
        }
        LibrarySeed::MapWrapper(member, inner)
        | LibrarySeed::MapErr(member, inner)
        | LibrarySeed::IntoFuture(member, inner)
        | LibrarySeed::TokioSleep(member, inner)
        | LibrarySeed::ReqwestCookie(member, inner)
        | LibrarySeed::Coop(member, inner) => Delegation::Direct {
            target: Target::Value(forward(member, *inner, strings)?),
            exclusive: true,
        },
        // `Either` polls the side its variant says it holds.
        LibrarySeed::Either { left, right } => {
            let side = |(variant, future): &(String, BundleTypeId)| -> Result<_, Decline> {
                let path = hop_route(
                    types,
                    strings,
                    ty,
                    &[Hop::Variant(variant), Hop::Member("__0")],
                    *future,
                )?;
                let Some(&Step::Variant(name)) = path.steps.first() else {
                    unreachable!("the route starts at the variant");
                };
                Ok((name, CaseAction::Delegate(Box::new(Target::Value(path)))))
            };
            Delegation::Match {
                state: TypedPath {
                    steps: Vec::new(),
                    target: ty,
                },
                cases: vec![side(left)?, side(right)?],
            }
        }
        // The retry polls the future its state holds; retrying, it polls
        // the service's readiness, which it keeps no future of.
        LibrarySeed::TowerRetry {
            state,
            state_ty,
            called,
            waiting,
            retrying,
        } => {
            let unread =
                strings.intern("retrying, the retry polls its service's readiness, not a future");
            let retrying_name = match types.get(*state_ty) {
                Some(TypeDef::Enum { shape, .. }) => shape
                    .variants
                    .iter()
                    .find(|v| strings.get(v.name) == Some(retrying.as_str()))
                    .map(|v| v.name),
                _ => None,
            }
            .ok_or((
                SemanticIssueKind::MissingLayout,
                format!("the retry's state has no {retrying} variant in the final table"),
            ))?;
            let state_path = hop_route(types, strings, ty, &[Hop::Member(state)], *state_ty)?;
            let holding =
                |(variant, member, future): &(String, String, BundleTypeId)| -> Result<_, Decline> {
                    let path = hop_route(
                        types,
                        strings,
                        ty,
                        &[
                            Hop::Member(state),
                            Hop::Variant(variant),
                            Hop::Member(member),
                        ],
                        *future,
                    )?;
                    let Some(&Step::Variant(name)) = path.steps.get(1) else {
                        unreachable!("the route selects the variant under the state");
                    };
                    Ok((name, CaseAction::Delegate(Box::new(Target::Value(path)))))
                };
            Delegation::Match {
                state: state_path,
                cases: vec![
                    holding(called)?,
                    holding(waiting)?,
                    (
                        retrying_name,
                        CaseAction::Unknown(SemanticIssue {
                            kind: SemanticIssueKind::UnsupportedState,
                            detail: Some(unread),
                        }),
                    ),
                ],
            }
        }
        // hyper-util's response future polls the box its wrapper lends;
        // crossing the box is the box's own std record's business.
        LibrarySeed::HyperUtilResponse {
            inner,
            wrapped,
            boxed,
        } => Delegation::Direct {
            target: Target::Value(hop_route(
                types,
                strings,
                ty,
                &[Hop::Member(inner), Hop::Member(wrapped)],
                *boxed,
            )?),
            exclusive: true,
        },
        // The terminal: nothing in the layout to poll, so the plan is
        // the never-ready program under the crate's layout rule and
        // nothing else — the same shape as core's, under a library
        // origin instead of the compiler's.
        LibrarySeed::Pending => {
            return Ok(Plan {
                rule,
                program: Some(Delegation::NeverReady),
                access: None,
                delegate_is_future: false,
                resource: None,
            });
        }
        // `Next` polls through its `&mut St`: the route dereferences the
        // reference to the stream itself, whose own record says what
        // polling it polls. A stream is no future, so the delegate is
        // named and not proved.
        LibrarySeed::Next(member, stream) => {
            let (name, member_ty, _) = member_named(types, strings, ty, member).ok_or((
                SemanticIssueKind::AmbiguousLayout,
                format!("no unique member {member:?}"),
            ))?;
            if !matches!(types.get(member_ty), Some(TypeDef::Pointer { target, .. }) if target == stream)
            {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{member} is not a reference to the declared stream"),
                ));
            }
            let path = checked_path(
                types,
                ty,
                vec![Step::Member(MemberRef::Named(name)), Step::Deref],
                *stream,
            )?;
            return Ok(Plan {
                rule,
                program: Some(Delegation::Direct {
                    target: Target::Value(path),
                    exclusive: true,
                }),
                access: None,
                delegate_is_future: false,
                resource: None,
            });
        }
        // The stream owns the box it polls through, and is polled
        // through itself: an access and no program.
        LibrarySeed::WatchStream(member, inner) => {
            let path = forward(member, *inner, strings)?;
            return Ok(Plan {
                rule: rule.clone(),
                program: None,
                access: Some((rule, AccessKind::Owned, Target::Value(path))),
                delegate_is_future: true,
                resource: None,
            });
        }
        // The box's every poll is the trait object's: the route runs
        // through `boxed` and the `Pin`'s one member to the wide
        // pointer, which the dyn join resolves.
        LibrarySeed::ReusableBox { boxed, pin, dyn_ } => {
            let (boxed_name, pin_ty, _) = member_named(types, strings, ty, boxed).ok_or((
                SemanticIssueKind::AmbiguousLayout,
                format!("no unique member {boxed:?}"),
            ))?;
            let Some(TypeDef::Struct { members, .. }) = types.get(pin_ty) else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Pin is not a struct in the final table".to_owned(),
                ));
            };
            let (pin_name, box_ty, offset) =
                member_named(types, strings, pin_ty, &pin.0).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("Pin has no unique member {:?}", pin.0),
                ))?;
            if members.len() != 1 || box_ty != pin.1 || offset != 0 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Pin's member is not its declared pointer".to_owned(),
                ));
            }
            let steps = vec![
                Step::Member(MemberRef::Named(boxed_name)),
                Step::Member(MemberRef::Named(pin_name)),
            ];
            let target = dynamic_target(ty, steps, box_ty, dyn_, types, strings)?;
            return Ok(Plan {
                rule: rule.clone(),
                program: None,
                access: Some((rule, AccessKind::Owned, target)),
                delegate_is_future: true,
                resource: None,
            });
        }
        // hyper's connection, either side, polls the dispatcher in its
        // one member and acts on its output alone.
        LibrarySeed::HyperConnection(member, inner) => Delegation::Direct {
            target: Target::Value(forward(member, *inner, strings)?),
            exclusive: true,
        },
        // `Connect` and `Accept` poll the handshake they hold and
        // nothing else.
        LibrarySeed::TokioRustlsHandshake(member, inner) => Delegation::Direct {
            target: Target::Value(forward(member, *inner, strings)?),
            exclusive: true,
        },
        // The upgradeable connection polls the dispatcher inside the
        // connection its `inner` holds — `inner.as_mut().unwrap().inner`
        // on the client, `.conn` on the server — and nothing else while
        // that is pending; the `None` state, which only `into_parts` or
        // a completed upgrade leaves behind, is not a state a parked
        // connection is in (the client's poll panics on it, the
        // server's returns at once), so it gets no action.
        LibrarySeed::HyperUpgradeable {
            inner,
            option,
            dispatcher_member,
            dispatcher,
        } => {
            let (inner_name, inner_ty, _) = member_named(types, strings, ty, inner).ok_or((
                SemanticIssueKind::AmbiguousLayout,
                format!("no unique member {inner:?}"),
            ))?;
            if inner_ty != *option {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{inner} holds another type than the screen declared"),
                ));
            }
            let Some(TypeDef::Enum { shape, .. }) = types.get(*option) else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the connection's Option is not an enum in the final table".to_owned(),
                ));
            };
            let variant = |name: &str| {
                shape
                    .variants
                    .iter()
                    .find(|v| strings.get(v.name) == Some(name))
                    .map(|v| (v.name, v.payload.ty))
            };
            let (some, payload) = variant(hyper_h1::SOME).ok_or((
                SemanticIssueKind::MissingLayout,
                "the connection's Option has no Some state".to_owned(),
            ))?;
            let (none, _) = variant("None").ok_or((
                SemanticIssueKind::MissingLayout,
                "the connection's Option has no None state".to_owned(),
            ))?;
            if shape.variants.len() != 2 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the connection's Option has states beyond the two reviewed ones".to_owned(),
                ));
            }
            let (payload_name, connection, _) =
                member_named(types, strings, payload, hyper_h1::PAYLOAD).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    "the connection's Some state has no unique payload member".to_owned(),
                ))?;
            let (dispatcher_name, dispatcher_ty, _) =
                member_named(types, strings, connection, dispatcher_member).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("the connection has no unique member {dispatcher_member}"),
                ))?;
            if dispatcher_ty != *dispatcher {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the connection's inner is not the dispatcher the screen declared".to_owned(),
                ));
            }
            let state = checked_path(
                types,
                ty,
                vec![Step::Member(MemberRef::Named(inner_name))],
                *option,
            )?;
            let path = checked_path(
                types,
                ty,
                vec![
                    Step::Member(MemberRef::Named(inner_name)),
                    Step::Variant(some),
                    Step::Member(MemberRef::Named(payload_name)),
                    Step::Member(MemberRef::Named(dispatcher_name)),
                ],
                *dispatcher,
            )?;
            let taken = strings.intern("the connection was taken for an upgrade");
            Delegation::Match {
                state,
                cases: vec![
                    (some, CaseAction::Delegate(Box::new(Target::Value(path)))),
                    (
                        none,
                        CaseAction::Unknown(SemanticIssue {
                            kind: SemanticIssueKind::UnsupportedState,
                            detail: Some(taken),
                        }),
                    ),
                ],
            }
        }
        // hyper-util's version-choosing wrapper matches on its state:
        // reading the first bytes, it polls the read of the socket and
        // registers on nothing else, so the wrapper is the connection
        // resource in that state and its own rule the protocol; once
        // HTTP/1 it polls hyper's upgradeable connection in `conn` and
        // acts only on its output; HTTP/2 is not read. The enum has
        // exactly those three states in the reviewed range — a build
        // that drops one behind a feature is another layout.
        LibrarySeed::HyperUtilAuto {
            state,
            state_ty,
            h1_conn,
            h1,
        } => {
            let (state_name, actual_ty, _) = member_named(types, strings, ty, state).ok_or((
                SemanticIssueKind::AmbiguousLayout,
                format!("no unique member {state:?}"),
            ))?;
            if actual_ty != *state_ty {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{state} holds another type than the screen declared"),
                ));
            }
            let Some(TypeDef::Enum { shape, .. }) = types.get(*state_ty) else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the wrapper's state is not an enum in the final table".to_owned(),
                ));
            };
            let variant = |name: &str| {
                shape
                    .variants
                    .iter()
                    .find(|v| strings.get(v.name) == Some(name))
                    .map(|v| (v.name, v.payload.ty))
                    .ok_or((
                        SemanticIssueKind::MissingLayout,
                        format!("the wrapper's state has no {name} variant"),
                    ))
            };
            let (read_version, _) = variant(hyper_h1::READ_VERSION)?;
            let (h1_name, h1_payload) = variant(hyper_h1::H1)?;
            let (h2, _) = variant(hyper_h1::H2)?;
            if shape.variants.len() != 3 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the wrapper's state has states beyond the three reviewed ones".to_owned(),
                ));
            }
            let (conn_name, conn_ty, _) =
                member_named(types, strings, h1_payload, h1_conn).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("the HTTP/1 state has no unique member {h1_conn}"),
                ))?;
            if conn_ty != *h1 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{h1_conn} holds another type than the screen declared"),
                ));
            }
            let state_path = checked_path(
                types,
                ty,
                vec![Step::Member(MemberRef::Named(state_name))],
                *state_ty,
            )?;
            let path = checked_path(
                types,
                ty,
                vec![
                    Step::Member(MemberRef::Named(state_name)),
                    Step::Variant(h1_name),
                    Step::Member(MemberRef::Named(conn_name)),
                ],
                *h1,
            )?;
            let unread = strings.intern("an HTTP/2 connection is not read");
            Delegation::Match {
                state: state_path,
                cases: vec![
                    (read_version, CaseAction::Primitive),
                    (h1_name, CaseAction::Delegate(Box::new(Target::Value(path)))),
                    (
                        h2,
                        CaseAction::Unknown(SemanticIssue {
                            kind: SemanticIssueKind::UnsupportedState,
                            detail: Some(unread),
                        }),
                    ),
                ],
            }
        }
        // The tick's closure runs `self.poll_tick(cx)`, and `poll_tick`
        // is `ready!(Pin::new(&mut self.delay).poll(cx))` before
        // anything else: pending, the `PollFn` polls the pinned box in
        // `delay` and nothing else, so the forward is exclusive. The
        // route runs through the closure's one capture to the interval
        // and lands on the box, not the `Sleep` behind it: crossing the
        // box is the box's own std record's business.
        LibrarySeed::IntervalTick {
            closure,
            interval_ref,
            interval,
            delay,
            boxed,
            ..
        } => {
            let member = |strings: &mut StringInterner, parent: BundleTypeId, name: &str| {
                member_named(types, strings, parent, name).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("no unique member {name:?}"),
                ))
            };
            let (closure_name, env, _) = member(strings, ty, closure)?;
            let (capture_name, capture_ty, _) = member(strings, env, interval_ref)?;
            if !matches!(types.get(capture_ty), Some(TypeDef::Pointer { target, .. }) if target == interval)
            {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{interval_ref} is not a reference to the declared interval"),
                ));
            }
            let (delay_name, delay_ty, _) = member(strings, *interval, delay)?;
            if delay_ty != *boxed {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{delay} holds another type than the screen declared"),
                ));
            }
            let path = checked_path(
                types,
                ty,
                vec![
                    Step::Member(MemberRef::Named(closure_name)),
                    Step::Member(MemberRef::Named(capture_name)),
                    Step::Deref,
                    Step::Member(MemberRef::Named(delay_name)),
                ],
                *boxed,
            )?;
            Delegation::Direct {
                target: Target::Value(path),
                exclusive: true,
            }
        }
    };
    Ok(Plan {
        rule,
        program: Some(program),
        access: None,
        delegate_is_future: true,
        resource: matches!(seed_layout, LibrarySeed::HyperUtilAuto { .. })
            .then_some(ResourceKind::HttpConn),
    })
}

/// An HTTP/1 connection binding as planned: its rule, and every route
/// held to the final table.
#[derive(Clone, Debug)]
struct HttpPlan {
    rule: RuleKey,
    role: HttpRole,
    keep_alive: TypedPath,
    reading: TypedPath,
    writing: TypedPath,
    method: TypedPath,
    method_inner: TypedPath,
    read_continue_kind: TypedPath,
    read_body_kind: TypedPath,
    write_body_kind: TypedPath,
    is_closing: TypedPath,
    client: Option<HttpClientBinding>,
    server: Option<HttpServerPlan>,
    /// The stream the connection reads and writes, where its type's
    /// route ends at a socket; set once the routes are known.
    stream: Option<TypedPath>,
    /// Why the peer was not routed, where the service was recognized
    /// and its crate's origin declined: a fact beside the binding, not
    /// a reason to decline it.
    peer_declined: Option<Decline>,
}

/// The server dispatch's routes with the service's.
#[derive(Clone, Debug)]
struct HttpServerPlan {
    in_flight: TypedPath,
    header_read_timeout_running: TypedPath,
    header_read_timeout_secs: TypedPath,
    header_read_timeout_nanos: TypedPath,
    header_read_timer: TypedPath,
    service: Option<HttpServicePlan>,
}

/// What the service keeps — the peer's route, the context type, and
/// the routes into the server's shared state where they bound — under
/// the key its rule is interned by once the plan is bound.
#[derive(Clone, Debug)]
struct HttpServicePlan {
    key: RuleKey,
    peer: TypedPath,
    context: BundleTypeId,
    local_addr: Option<TypedPath>,
    tls_acceptor: Option<TypedPath>,
}

/// Plan hyper's dispatcher as the connection resource: the origin first
/// — every declaration of its `poll` in hyper's `proto/h1/dispatch.rs`
/// on a cargo registry path at a version inside the reviewed range —
/// then each route the screen described, held to the final table by
/// the reviewed layout's member and variant names, landing on the type
/// the screen saw. The client's callback routes run through the
/// `Option` and the `Callback` enum's two variants to the oneshot
/// sender each holds; the read reports the variant inactive where the
/// callback is `None` or the other variant.
fn plan_http(
    ty: BundleTypeId,
    seed: &HttpSeed,
    sources: &BTreeSet<PollSource>,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<HttpPlan, Decline> {
    use hyper_h1::*;
    let origin = delegation_origin(sources, &HYPER_H1_CONN_V1_6_0, "poll")?;
    let rule = RuleKey::Delegation {
        kind: SemanticRuleKind::HyperH1Conn,
        origin,
    };
    let member = |strings: &mut StringInterner, parent: BundleTypeId, name: &str| {
        member_named(types, strings, parent, name).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("no unique member {name:?}"),
        ))
    };
    let variant = |strings: &mut StringInterner, parent: BundleTypeId, name: &str| {
        let Some(TypeDef::Enum { shape, .. }) = types.get(parent) else {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("no enum to select {name} from in the final table"),
            ));
        };
        shape
            .variants
            .iter()
            .find(|v| strings.get(v.name) == Some(name))
            .map(|v| (v.name, v.payload.ty))
            .ok_or((
                SemanticIssueKind::MissingLayout,
                format!("no variant {name} in the final table"),
            ))
    };
    // A route as a run of members and variants from the dispatcher,
    // each level checked as it is entered, then held whole to the
    // declared target.
    let route = |strings: &mut StringInterner,
                 names: &[(bool, &str)],
                 target: BundleTypeId|
     -> Result<TypedPath, Decline> {
        let mut steps = Vec::with_capacity(names.len());
        let mut current = ty;
        for &(is_variant, name) in names {
            if is_variant {
                let (name, payload) = variant(strings, current, name)?;
                steps.push(Step::Variant(name));
                current = payload;
            } else {
                let (name, member_ty, _) = member(strings, current, name)?;
                steps.push(Step::Member(MemberRef::Named(name)));
                current = member_ty;
            }
        }
        checked_path(types, ty, steps, target)
    };
    const M: bool = false;
    const V: bool = true;
    let word = |strings: &mut StringInterner, name: &str, target| {
        route(strings, &[(M, CONN), (M, STATE), (M, name)], target)
    };
    let keep_alive = word(strings, KEEP_ALIVE, seed.keep_alive)?;
    let reading = word(strings, READING, seed.reading)?;
    let writing = word(strings, WRITING, seed.writing)?;
    let method = word(strings, METHOD, seed.method)?;
    // The words inside a word: the method's enum through the option
    // and the newtype, the body framing through the variant carrying
    // the codec to its `kind`.
    let method_inner = route(
        strings,
        &[
            (M, CONN),
            (M, STATE),
            (M, METHOD),
            (V, SOME),
            (M, PAYLOAD),
            (M, PAYLOAD),
        ],
        seed.method_inner,
    )?;
    let framing = |strings: &mut StringInterner, word: &str, variant: &str, target| {
        route(
            strings,
            &[
                (M, CONN),
                (M, STATE),
                (M, word),
                (V, variant),
                (M, PAYLOAD),
                (M, KIND),
            ],
            target,
        )
    };
    let read_continue_kind = framing(strings, READING, CONTINUE, seed.read_continue_kind)?;
    let read_body_kind = framing(strings, READING, BODY, seed.read_body_kind)?;
    let write_body_kind = framing(strings, WRITING, BODY, seed.write_body_kind)?;
    let is_closing = route(strings, &[(M, IS_CLOSING)], seed.is_closing)?;
    let mut peer_declined = None;
    let client = match &seed.client {
        Some(client) => {
            let callback = route(strings, &[(M, DISPATCH), (M, CALLBACK)], client.callback)?;
            let sender = |strings: &mut StringInterner, variant: &str, target| {
                route(
                    strings,
                    &[
                        (M, DISPATCH),
                        (M, CALLBACK),
                        (V, SOME),
                        (M, PAYLOAD),
                        (V, variant),
                        (M, PAYLOAD),
                        (V, SOME),
                        (M, PAYLOAD),
                    ],
                    target,
                )
            };
            Some(HttpClientBinding {
                callback,
                retry: sender(strings, RETRY, client.retry)?,
                no_retry: sender(strings, NO_RETRY, client.no_retry)?,
                rx: route(strings, &[(M, DISPATCH), (M, RX), (M, INNER)], client.rx)?,
                want: route(
                    strings,
                    &[(M, DISPATCH), (M, RX)]
                        .into_iter()
                        .chain(TAKER_PTR.map(|name| (M, name)))
                        .collect::<Vec<_>>(),
                    client.want,
                )?,
            })
        }
        None => None,
    };
    // The server's handler sits behind a pinned box: the route runs
    // through the `Pin`'s member to the `Box` and dereferences it to
    // the `Option`, each level held to what the screen declared.
    let server = match &seed.server {
        Some(server) => {
            let (dispatch_name, dispatch_ty, _) = member(strings, ty, DISPATCH)?;
            let (in_flight_name, pin_ty, _) = member(strings, dispatch_ty, IN_FLIGHT)?;
            let (pointer_name, box_ty, _) = member(strings, pin_ty, &server.in_flight_member)?;
            if box_ty != server.in_flight_box {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!(
                        "{} holds another type than the screen declared",
                        server.in_flight_member
                    ),
                ));
            }
            if !matches!(types.get(box_ty), Some(TypeDef::Pointer { target, .. }) if *target == server.in_flight)
            {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the handler's box does not target the declared option".to_owned(),
                ));
            }
            let in_flight = checked_path(
                types,
                ty,
                vec![
                    Step::Member(MemberRef::Named(dispatch_name)),
                    Step::Member(MemberRef::Named(in_flight_name)),
                    Step::Member(MemberRef::Named(pointer_name)),
                    Step::Deref,
                ],
                server.in_flight,
            )?;
            // The service under its own crate's rule: the service's
            // method declarations say which dropshot, and a version
            // outside the reviewed range leaves the binding without a
            // peer or a context rather than without a verdict.
            let service = match &server.service {
                Some(service) => match method_origin(&service.sources, &DROPSHOT_SERVER_V0_17_0) {
                    Ok(origin) => {
                        let peer = route(
                            strings,
                            &[(M, DISPATCH), (M, SERVICE), (M, REMOTE_ADDR)],
                            service.peer,
                        )?;
                        // The state every connection the server accepted
                        // shares, behind the handler's `Arc`: where it
                        // does not bind, the peer and the context stand
                        // without it.
                        let state = |field: &'static str| {
                            hop_landing(
                                types,
                                strings,
                                ty,
                                &[
                                    Hop::Member(DISPATCH),
                                    Hop::Member(SERVICE),
                                    Hop::Member(SERVER),
                                    Hop::Member(PTR),
                                    Hop::Member(POINTER),
                                    Hop::Deref,
                                    Hop::Member(DATA),
                                    Hop::Member(field),
                                ],
                            )
                            .ok()
                        };
                        Some(HttpServicePlan {
                            key: RuleKey::Delegation {
                                kind: SemanticRuleKind::DropshotRequestHandler,
                                origin,
                            },
                            peer,
                            context: service.context,
                            local_addr: landing_on(state(LOCAL_ADDR), service.peer),
                            tls_acceptor: state(TLS_ACCEPTOR).filter(|path| {
                                matches!(types.get(path.target), Some(TypeDef::Enum { .. }))
                            }),
                        })
                    }
                    Err(declined) => {
                        peer_declined = Some(declined);
                        None
                    }
                },
                None => None,
            };
            // The timeout's two words, through the `Option` and std's
            // `Duration` — `nanos` through its `Nanoseconds` newtype.
            let timeout_word = |strings: &mut StringInterner, word: &[(bool, &str)], target| {
                let mut names = vec![
                    (M, CONN),
                    (M, STATE),
                    (M, HEADER_READ_TIMEOUT),
                    (V, SOME),
                    (M, PAYLOAD),
                ];
                names.extend_from_slice(word);
                route(strings, &names, target)
            };
            Some(HttpServerPlan {
                in_flight,
                header_read_timeout_running: word(
                    strings,
                    HEADER_READ_TIMEOUT_RUNNING,
                    server.header_read_timeout_running,
                )?,
                header_read_timeout_secs: timeout_word(
                    strings,
                    &[(M, SECS)],
                    server.header_read_timeout_secs,
                )?,
                header_read_timeout_nanos: timeout_word(
                    strings,
                    &[(M, NANOS), (M, PAYLOAD)],
                    server.header_read_timeout_nanos,
                )?,
                // The timer's address: through the `Option` and the
                // `Pin` to the data pointer of the `Box` it holds.
                header_read_timer: route(
                    strings,
                    &[
                        (M, CONN),
                        (M, STATE),
                        (M, HEADER_READ_TIMEOUT_FUT),
                        (V, SOME),
                        (M, PAYLOAD),
                        (M, &server.header_read_timer_pin),
                        (M, &server.header_read_timer_pointer),
                    ],
                    server.header_read_timer,
                )?,
                service,
            })
        }
        None => None,
    };
    Ok(HttpPlan {
        rule,
        role: match seed.role {
            H1Role::Client => HttpRole::Client,
            H1Role::Server => HttpRole::Server,
        },
        keep_alive,
        reading,
        writing,
        method,
        method_inner,
        read_continue_kind,
        read_body_kind,
        write_body_kind,
        is_closing,
        client,
        server,
        stream: None,
        peer_declined,
    })
}

/// A request binding as planned: its rule, and every route held to
/// the final table.
#[derive(Clone, Debug)]
struct RequestPlan {
    rule: RuleKey,
    target: HttpRequestTarget,
    method: TypedPath,
    target_ptr: TypedPath,
    target_len: TypedPath,
}

/// A route as a run of members from `root`, each level checked as it
/// is entered, then held whole to the declared target.
fn member_route(
    types: &TypeTable,
    strings: &mut StringInterner,
    root: BundleTypeId,
    names: &[&str],
    target: BundleTypeId,
) -> Result<TypedPath, Decline> {
    let mut steps = Vec::with_capacity(names.len());
    let mut current = root;
    for name in names {
        let (name, member_ty, _) = member_named(types, strings, current, name).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("no unique member {name:?}"),
        ))?;
        steps.push(Step::Member(MemberRef::Named(name)));
        current = member_ty;
    }
    checked_path(types, root, steps, target)
}

/// Plan a request binding: the origin first — a future's `poll`
/// declarations, or the type's own method declarations for the two
/// request records that are no future, on a cargo registry path at a
/// version inside the crate's reviewed range — then the three routes
/// the screen described, by the reviewed layout's member names, held to
/// the final table and landing on the types the screen saw. The target
/// text's two words come out of one holder: the `Bytes` view of a
/// server's path, or the `String` of a client's URL through std's
/// vector and raw buffer, crossed by name under the request's own rule
/// as the connection binding crosses into the buffer it reads.
fn plan_request(
    ty: BundleTypeId,
    seed: &RequestSeed,
    poll_sources: &BTreeSet<PollSource>,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<RequestPlan, Decline> {
    use request::*;
    let (convention, kind, declared_by, sources) = match seed.kind {
        HttpRequestKind::ReqwestPendingRequest => (
            &REQWEST_PENDING_REQUEST_V0_12_0,
            SemanticRuleKind::ReqwestPendingRequest,
            "poll",
            poll_sources,
        ),
        HttpRequestKind::HttpRequest => (
            &HTTP_REQUEST_V1_0_0,
            SemanticRuleKind::HttpRequest,
            "method",
            &seed.sources,
        ),
        HttpRequestKind::DropshotRequestContext => (
            &DROPSHOT_HANDLER_V0_17_0,
            SemanticRuleKind::DropshotRequestContext,
            "method",
            &seed.sources,
        ),
    };
    let origin = match declared_by {
        "method" => method_origin(sources, convention)?,
        _ => delegation_origin(sources, convention, declared_by)?,
    };
    let rule = RuleKey::Delegation { kind, origin };
    fn under(prefix: &[&'static str], rest: &[&'static str]) -> Vec<&'static str> {
        prefix.iter().chain(rest).copied().collect()
    }
    let (target, method, ptr, len) = match seed.kind {
        HttpRequestKind::ReqwestPendingRequest => (
            HttpRequestTarget::Url,
            vec![METHOD, PAYLOAD],
            under(&[URL, SERIALIZATION], &STRING_PTR),
            under(&[URL, SERIALIZATION], &STRING_LEN),
        ),
        HttpRequestKind::HttpRequest => (
            HttpRequestTarget::PathAndQuery,
            vec![HEAD, METHOD, PAYLOAD],
            under(&[HEAD], &PATH_PTR),
            under(&[HEAD], &PATH_LEN),
        ),
        HttpRequestKind::DropshotRequestContext => (
            HttpRequestTarget::PathAndQuery,
            vec![REQUEST, METHOD, PAYLOAD],
            under(&[REQUEST], &PATH_PTR),
            under(&[REQUEST], &PATH_LEN),
        ),
    };
    Ok(RequestPlan {
        rule,
        target,
        method: member_route(types, strings, ty, &method, seed.method_inner)?,
        target_ptr: member_route(types, strings, ty, &ptr, seed.target_ptr)?,
        target_len: member_route(types, strings, ty, &len, seed.target_len)?,
    })
}

/// Where the toolchain's own copies of the crates std depends on are
/// compiled from, each in a `<crate>-<version>` directory, as a line
/// table records it.
const TOOLCHAIN_DEPS: &str = "/rust/deps/";

struct TablePlan {
    rule: RuleKey,
    bucket_mask: TypedPath,
    ctrl: TypedPath,
    items: TypedPath,
    bucket: BundleTypeId,
}

/// Plan a hash table's binding: the hashbrown release first, read off
/// the declarations of hashbrown's map, then the three routes to the
/// table's words by the member names the reviewed layout declares, held
/// to the final table and landing on the types the screen saw.
fn plan_table(
    ty: BundleTypeId,
    seed: &TableSeed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<TablePlan, Decline> {
    use hash_table::{BUCKET_MASK, CTRL, ITEMS, POINTER, TABLE};
    let convention = &HASHBROWN_TABLE_V0_12_3;
    let version = layout_release(&seed.sources, convention)?;
    let rule = RuleKey::Layout {
        kind: SemanticRuleKind::HashbrownTable,
        package: convention.package,
        version,
        family: convention.family,
    };
    let words = |word: &[&'static str]| -> Vec<&'static str> {
        seed.kind
            .outer()
            .iter()
            .chain(&[TABLE, TABLE])
            .chain(word)
            .copied()
            .collect()
    };
    Ok(TablePlan {
        rule,
        bucket_mask: member_route(types, strings, ty, &words(&[BUCKET_MASK]), seed.bucket_mask)?,
        ctrl: member_route(types, strings, ty, &words(&[CTRL, POINTER]), seed.ctrl)?,
        items: member_route(types, strings, ty, &words(&[ITEMS]), seed.items)?,
        bucket: seed.bucket,
    })
}

/// A crate release some reviewed rule declined over because no review
/// covers it: a registry release outside the reviewed range, or a git
/// checkout at a revision the review did not read. Extraction warns of
/// each one a record's issue names; the issue itself says which type
/// the rule declined at.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum UnreviewedRelease {
    Version {
        package: &'static str,
        version: semver::Version,
        /// Whether the release is newer than the range, not older.
        newer: bool,
        range: String,
    },
    Revision {
        package: &'static str,
        revision: String,
    },
}

impl UnreviewedRelease {
    fn outside(
        convention: &LibraryConvention,
        version: &semver::Version,
        side: LayoutSelection,
    ) -> Self {
        UnreviewedRelease::Version {
            package: convention.package,
            version: version.clone(),
            newer: side != LayoutSelection::BelowFloor,
            range: convention.releases.range_for(version),
        }
    }
}

impl std::fmt::Display for UnreviewedRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnreviewedRelease::Version {
                package,
                version,
                newer,
                range,
            } => {
                let side = if *newer { "newer" } else { "older" };
                write!(
                    f,
                    "{package} {version} is {side} than the supported version range: {range}"
                )
            }
            UnreviewedRelease::Revision { package, revision } => {
                write!(
                    f,
                    "{package} revision {revision} is not a reviewed revision"
                )
            }
        }
    }
}

/// Every unreviewed release a table's records name a rule declining
/// over, with the families that declined.
pub type UnreviewedReleases = BTreeMap<UnreviewedRelease, BTreeSet<&'static str>>;

/// The releases the origin gates refuse while [`capture`](refusals::capture)
/// runs.
///
/// The sink is thread-local rather than a reporter threaded through
/// every planner, for the reason [`crate::detect::trace`]'s is: binding
/// is single-threaded, and a parameter only the extraction's warning
/// reads would spread across every plan's signature. Each refusal keeps
/// the detail its decline carries, so the warning can keep only the
/// refusals some record kept.
mod refusals {
    use super::UnreviewedRelease;

    use std::cell::RefCell;

    pub(super) struct Refusal {
        pub(super) detail: String,
        pub(super) family: &'static str,
        pub(super) release: UnreviewedRelease,
    }

    thread_local! {
        static SINK: RefCell<Option<Vec<Refusal>>> = const { RefCell::new(None) };
    }

    /// Add one refusal to those being collected, if any.
    pub(super) fn note(refusal: Refusal) {
        SINK.with_borrow_mut(|sink| {
            if let Some(refusals) = sink {
                refusals.push(refusal);
            }
        });
    }

    /// Run `f` with refusals collected, returning them alongside `f`'s
    /// result.
    pub(super) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<Refusal>) {
        SINK.with_borrow_mut(|sink| *sink = Some(Vec::new()));
        let out = f();
        let refused = SINK.with_borrow_mut(Option::take).unwrap_or_default();
        (out, refused)
    }
}

/// A gate's decline over a release no review covers, noted for the
/// extraction's warning.
fn refuse(family: &'static str, release: UnreviewedRelease, detail: String) -> Decline {
    refusals::note(refusals::Refusal {
        detail: detail.clone(),
        family,
        release,
    });
    (SemanticIssueKind::UnsupportedOrigin, detail)
}

/// [`bind_semantics`], with every unreviewed release the table names a
/// rule declining over: one a gate refused whose decline some record
/// keeps among its issues. A refusal no record keeps cost the bundle
/// nothing, and is not reported.
pub(super) fn bind_semantics_noting_releases(
    seeds: SemanticSeeds,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
    tasks: &mut [TaskFutureEntry],
    library: &Library<'_>,
) -> (SemanticTable, UnreviewedReleases) {
    let (table, refused) =
        refusals::capture(|| bind_semantics(seeds, types, names, strings, tasks, library));
    let recorded: BTreeSet<&str> = table
        .types
        .iter()
        .flat_map(|record| &record.issues)
        .filter(|issue| issue.kind == SemanticIssueKind::UnsupportedOrigin)
        .filter_map(|issue| strings.get(issue.detail?))
        .collect();
    let mut releases = UnreviewedReleases::new();
    for refusal in refused {
        if recorded.contains(refusal.detail.as_str()) {
            releases
                .entry(refusal.release)
                .or_default()
                .insert(refusal.family);
        }
    }
    (table, releases)
}

/// The release a layout rule's type was declared in — hashbrown's map,
/// rustls's connection: a cargo registry release, or the one the
/// toolchain vendors for std. A declaration in another crate — a trait
/// some other crate implements on the type — says nothing about which
/// release laid it out and is set aside.
/// Where every release named is inside the reviewed range the binding
/// holds for each, and the origin names the newest, as a delegation's
/// does; where one is outside, or none is named at all, there is no
/// binding.
fn layout_release(
    sources: &BTreeSet<PollSource>,
    convention: &'static LibraryConvention,
) -> Result<String, Decline> {
    let decline = |detail: String| (SemanticIssueKind::UnsupportedOrigin, detail);
    let package = convention.package;
    let mut releases: BTreeSet<semver::Version> = BTreeSet::new();
    for source in sources {
        let release = match registry_origin(&source.path) {
            Some(origin) => Some((origin.package, origin.version)),
            None if source.path.contains(TOOLCHAIN_DEPS) => {
                super::paths::crate_version_of(&source.path)
            }
            None => None,
        };
        let Some((named, version)) = release else {
            continue;
        };
        if named != package {
            continue;
        }
        if let Some(md5) = &source.md5
            && !convention.reviewed_checksum(md5)
        {
            return Err(decline(format!(
                "{} has checksum {}, not a reviewed revision of {}",
                source.path,
                hex(md5),
                convention.family
            )));
        }
        releases.insert(version);
    }
    let Some(newest) = releases.last() else {
        return Err(decline(match sources.first() {
            None => format!("no method declaration records which {package} release this is"),
            Some(source) => format!(
                "declared in {}, which names no {package} release",
                source.path
            ),
        }));
    };
    if let Some((version, side)) = releases.iter().find_map(|version| {
        library_convention(convention, version)
            .err()
            .map(|s| (version, s))
    }) {
        let word = match side {
            LayoutSelection::BelowFloor => "below",
            _ => "above",
        };
        return Err(refuse(
            convention.family,
            UnreviewedRelease::outside(convention, version, side),
            format!(
                "{package} {version} is {word} the reviewed range {}",
                convention.releases.range_for(version)
            ),
        ));
    }
    Ok(newest.to_string())
}

/// One level of a route a review names: a member, a variant, or the
/// pointee of the pointer the route stands on.
#[derive(Clone, Copy, Debug)]
enum Hop<'a> {
    Member(&'a str),
    Variant(&'a str),
    Deref,
}

/// A second address a layout keeps, where it lands on the type of the
/// first: a server's listening address beside the peer it accepted, a
/// pooled connection's local address beside its remote one. One that
/// lands elsewhere is not the address the review read.
fn landing_on(address: Option<TypedPath>, ty: BundleTypeId) -> Option<TypedPath> {
    address.filter(|path| path.target == ty)
}

/// A route from `root` as a run of hops, each level checked in the final
/// table as it is entered, then held whole to the declared target.
fn hop_route(
    types: &TypeTable,
    strings: &StringInterner,
    root: BundleTypeId,
    hops: &[Hop<'_>],
    target: BundleTypeId,
) -> Result<TypedPath, Decline> {
    let (steps, _) = hop_steps(types, strings, root, hops)?;
    checked_path(types, root, steps, target)
}

/// A route from `root` as a run of hops, checked like [`hop_route`]'s,
/// landing on whatever type the last hop enters.
fn hop_landing(
    types: &TypeTable,
    strings: &StringInterner,
    root: BundleTypeId,
    hops: &[Hop<'_>],
) -> Result<TypedPath, Decline> {
    let (steps, landed) = hop_steps(types, strings, root, hops)?;
    checked_path(types, root, steps, landed)
}

/// The steps a run of hops takes from `root`, each level checked in the
/// final table as it is entered, and the type the last one enters.
fn hop_steps(
    types: &TypeTable,
    strings: &StringInterner,
    root: BundleTypeId,
    hops: &[Hop<'_>],
) -> Result<(Vec<Step>, BundleTypeId), Decline> {
    let mut steps = Vec::with_capacity(hops.len());
    let mut current = root;
    for hop in hops {
        match *hop {
            Hop::Member(name) => {
                let (name, member_ty, _) = member_named(types, strings, current, name).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("no unique member {name:?}"),
                ))?;
                steps.push(Step::Member(MemberRef::Named(name)));
                current = member_ty;
            }
            Hop::Variant(name) => {
                let Some(TypeDef::Enum { shape, .. }) = types.get(current) else {
                    return Err((
                        SemanticIssueKind::MissingLayout,
                        format!("no enum to select {name} from in the final table"),
                    ));
                };
                let variant = shape
                    .variants
                    .iter()
                    .find(|v| strings.get(v.name) == Some(name))
                    .ok_or((
                        SemanticIssueKind::MissingLayout,
                        format!("no variant {name} in the final table"),
                    ))?;
                steps.push(Step::Variant(variant.name));
                current = variant.payload.ty;
            }
            Hop::Deref => {
                let Some(TypeDef::Pointer { target, .. }) = types.get(current) else {
                    return Err((
                        SemanticIssueKind::MissingLayout,
                        "no pointer to follow in the final table".to_owned(),
                    ));
                };
                steps.push(Step::Deref);
                current = *target;
            }
        }
    }
    Ok((steps, current))
}

/// The io routes and operations a table binds, planned over every seed
/// at once: an operation binds only over a stream whose route ends at a
/// socket, and whether one does is a fact about the routes of every
/// type it forwards through.
struct IoPlans {
    /// Every route that ends at a socket, by the type it starts at, with
    /// the rule it binds under.
    routes: BTreeMap<BundleTypeId, (RuleKey, PlannedStep)>,
    /// Every operation over such a stream.
    operations: BTreeMap<BundleTypeId, IoOpPlan>,
    /// Why a screened stream's route did not bind: an issue beside its
    /// record, where it has one.
    route_declines: BTreeMap<BundleTypeId, Decline>,
    /// Why a screened operation did not bind: its continuation's reason.
    operation_declines: BTreeMap<BundleTypeId, Decline>,
    /// Every rustls connection whose words bind.
    sessions: BTreeMap<BundleTypeId, TlsSessionPlan>,
    /// Every routed TLS stream whose connection is such a one: the
    /// paths to the connection and to the stream's state.
    tls_streams: BTreeMap<BundleTypeId, (TypedPath, TypedPath)>,
    /// Every routed stream that names its peer: the path to the name.
    peers: BTreeMap<BundleTypeId, TypedPath>,
    /// Why a screened connection's words, or a routed stream's TLS
    /// layer or peer, did not bind: an issue beside its record.
    tls_declines: BTreeMap<BundleTypeId, Decline>,
}

/// rustls's connection words, each a run of member names from the
/// connection landing on a type of the shape its reading takes.
#[derive(Clone, Debug)]
struct TlsSessionPlan {
    rule: RuleKey,
    state: TypedPath,
    side: TypedPath,
    negotiated_version: TypedPath,
    version: TypedPath,
    may_send_application_data: TypedPath,
    may_receive_application_data: TypedPath,
    has_sent_close_notify: TypedPath,
    has_received_close_notify: TypedPath,
    has_seen_eof: TypedPath,
    sent_fatal_alert: TypedPath,
    read_seq: TypedPath,
    write_seq: TypedPath,
    sendable: SendableBinding,
    received: Option<SendableBinding>,
    handshake_kind: Option<TypedPath>,
    suites: Vec<TypedPath>,
    alpn: Option<(TypedPath, TypedPath)>,
    peer_certificates: Option<TypedPath>,
}

/// The ring rustls keeps its outgoing records in, as std names it, and
/// the record it holds.
const SENDABLE_RING: &str =
    "alloc::collections::vec_deque::VecDeque<alloc::vec::Vec<u8, alloc::alloc::Global>, ";
const SENDABLE_RECORD: &str = "alloc::vec::Vec<u8, alloc::alloc::Global>";

/// Plan a rustls connection's words: the release first, read off the
/// type's declarations and inside the reviewed range, then each word
/// by the reviewed layout's member names, held to the shape the
/// reading takes — the state a `Result`, the version an `Option` over
/// an enum, the side a C-like enum, the flags single bytes and the
/// sequence counts unsigned words; the outgoing records' ring by std's
/// member names, its storage a pointer, its record `Vec<u8>` by name.
fn plan_tls_session(
    ty: BundleTypeId,
    sources: &BTreeSet<PollSource>,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<TlsSessionPlan, Decline> {
    use Hop::{Member, Variant};
    let convention = &RUSTLS_SESSION_V0_23_23;
    let version = layout_release(sources, convention)?;
    let rule = RuleKey::Layout {
        kind: SemanticRuleKind::RustlsSession,
        package: convention.package,
        version,
        family: convention.family,
    };
    let shape = |path: TypedPath, ok: bool, what: &str| {
        if ok {
            Ok(path)
        } else {
            Err((
                SemanticIssueKind::MissingLayout,
                format!("its {what} has another shape in the final table"),
            ))
        }
    };
    let variants = |target: BundleTypeId| -> BTreeSet<&str> {
        match types.get(target) {
            Some(TypeDef::Enum { shape, .. }) => shape
                .variants
                .iter()
                .filter_map(|v| strings.get(v.name))
                .collect(),
            _ => BTreeSet::new(),
        }
    };
    let is_word = |target: BundleTypeId| {
        matches!(
            types.get(target),
            Some(TypeDef::Base {
                encoding: crate::bundle::Encoding::Unsigned,
                size: 8,
                ..
            })
        )
    };
    let common = |name: &str| {
        hop_landing(
            types,
            strings,
            ty,
            &[Member("core"), Member("common_state"), Member(name)],
        )
    };
    let flag = |name: &str| {
        let path = common(name)?;
        let ok = types.size_of(path.target) == Some(1);
        shape(path, ok, name)
    };
    let count = |hops: &[Hop<'_>], name: &str| {
        let path = hop_landing(types, strings, ty, hops)?;
        let ok = matches!(
            types.get(path.target),
            Some(TypeDef::Base {
                encoding: crate::bundle::Encoding::Unsigned,
                size: 8,
                ..
            })
        );
        shape(path, ok, name)
    };
    let seq = |name: &str| {
        count(
            &[
                Member("core"),
                Member("common_state"),
                Member("record_layer"),
                Member(name),
            ],
            name,
        )
    };
    let state = hop_landing(types, strings, ty, &[Member("core"), Member("state")])?;
    let ok = variants(state.target) == BTreeSet::from(["Ok", "Err"]);
    let state = shape(state, ok, "state")?;
    let side = common("side")?;
    let ok = matches!(types.get(side.target), Some(TypeDef::CEnum { .. }));
    let side = shape(side, ok, "side")?;
    let negotiated_version = common("negotiated_version")?;
    let ok = variants(negotiated_version.target) == BTreeSet::from(["None", "Some"]);
    let negotiated_version = shape(negotiated_version, ok, "negotiated version")?;
    let version = hop_landing(
        types,
        strings,
        ty,
        &[
            Member("core"),
            Member("common_state"),
            Member("negotiated_version"),
            Variant("Some"),
            Member("__0"),
        ],
    )?;
    let ok = !variants(version.target).is_empty();
    let version = shape(version, ok, "version")?;
    // The words beside the verdict, each standing on its own: one whose
    // layout does not hold is left out, and the rest bind without it.
    let state_word = |tail: &[Hop<'_>]| {
        let mut hops = vec![Member("core"), Member("common_state")];
        hops.extend_from_slice(tail);
        hop_landing(types, strings, ty, &hops).ok()
    };
    let handshake_kind = state_word(&[Member("handshake_kind"), Variant("Some"), Member("__0")])
        .filter(|path| matches!(types.get(path.target), Some(TypeDef::CEnum { .. })));
    let suites = ["Tls12", "Tls13"]
        .into_iter()
        .filter_map(|variant| {
            state_word(&[
                Member("suite"),
                Variant("Some"),
                Member("__0"),
                Variant(variant),
                Member("__0"),
                Hop::Deref,
                Member("common"),
                Member("suite"),
            ])
        })
        .filter(|path| {
            matches!(
                types.get(path.target),
                Some(TypeDef::Enum { .. } | TypeDef::CEnum { .. })
            )
        })
        .collect();
    // `ProtocolName` over `PayloadU8` over the `Vec<u8>` of its text.
    let alpn_vec = [
        Member("alpn_protocol"),
        Variant("Some"),
        Member("__0"),
        Member("__0"),
        Member("__0"),
    ];
    let vec_word = |tail: &[Hop<'static>]| {
        let mut hops = alpn_vec.to_vec();
        hops.extend_from_slice(tail);
        state_word(&hops)
    };
    let alpn = vec_word(&[
        Member("buf"),
        Member("inner"),
        Member("ptr"),
        Member("pointer"),
        Member("pointer"),
    ])
    .filter(|ptr| matches!(types.get(ptr.target), Some(TypeDef::Pointer { .. })))
    .zip(vec_word(&[Member("len")]).filter(|len| is_word(len.target)));
    let peer_certificates = state_word(&[
        Member("peer_certificates"),
        Variant("Some"),
        Member("__0"),
        Member("__0"),
        Member("len"),
    ])
    .filter(|len| is_word(len.target));
    Ok(TlsSessionPlan {
        rule,
        state,
        side,
        negotiated_version,
        version,
        may_send_application_data: flag("may_send_application_data")?,
        may_receive_application_data: flag("may_receive_application_data")?,
        has_sent_close_notify: flag("has_sent_close_notify")?,
        has_received_close_notify: flag("has_received_close_notify")?,
        has_seen_eof: flag("has_seen_eof")?,
        sent_fatal_alert: flag("sent_fatal_alert")?,
        read_seq: seq("read_seq")?,
        write_seq: seq("write_seq")?,
        sendable: plan_sendable(ty, "sendable_tls", &count, types, names, strings)?,
        received: plan_sendable(ty, "received_plaintext", &count, types, names, strings).ok(),
        handshake_kind,
        suites,
        alpn,
        peer_certificates,
    })
}

/// A session word's plan: the hops from the connection to an unsigned
/// word, and what the decline calls it.
type WordPlan<'a> = dyn Fn(&[Hop<'_>], &str) -> Result<TypedPath, Decline> + 'a;

/// One of rustls's record buffers, `core.common_state.<field>`: the
/// outgoing records `sendable_tls`, or the decrypted ones not yet read,
/// `received_plaintext` — each a `ChunkVecBuffer` over a
/// `VecDeque<Vec<u8>>`. The ring's head and
/// capacity are words the standard library wraps in a newtype
/// (`WrappedIndex`, `UsizeNoHighBit`) in some releases and not in
/// others, which the toolchain decides, not rustls: each is the word
/// itself or its newtype's `__0`.
fn plan_sendable(
    ty: BundleTypeId,
    field: &'static str,
    count: &WordPlan<'_>,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<SendableBinding, Decline> {
    use Hop::Member;
    let at = |tail: &[Hop<'static>]| -> Vec<Hop<'static>> {
        let mut hops = vec![Member("core"), Member("common_state"), Member(field)];
        hops.extend_from_slice(tail);
        hops
    };
    let wrapped = |tail: &[Hop<'static>], what: &str| {
        let hops = at(tail);
        count(&hops, what).or_else(|first| {
            let mut inside = hops.clone();
            inside.push(Member("__0"));
            count(&inside, what).map_err(|_| first)
        })
    };
    let missing = |what: &str| (SemanticIssueKind::MissingLayout, what.to_owned());
    let ring = hop_landing(types, strings, ty, &at(&[Member("chunks")]))?;
    let ring_name = names.get(ring.target.0 as usize).cloned().flatten();
    if !ring_name.is_some_and(|name| name.starts_with(SENDABLE_RING)) {
        return Err(missing("its outgoing records are not a ring of Vec<u8>"));
    }
    let buf = hop_landing(
        types,
        strings,
        ty,
        &at(&[
            Member("chunks"),
            Member("buf"),
            Member("inner"),
            Member("ptr"),
            Member("pointer"),
            Member("pointer"),
        ]),
    )?;
    if !matches!(types.get(buf.target), Some(TypeDef::Pointer { .. })) {
        return Err(missing("its outgoing records' storage is no pointer"));
    }
    let mut records = names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.as_deref() == Some(SENDABLE_RECORD))
        .map(|(at, _)| BundleTypeId(at as u32));
    let (Some(record), None) = (records.next(), records.next()) else {
        return Err(missing("no one Vec<u8> in the final table"));
    };
    let record_len = hop_landing(types, strings, record, &[Member("len")])?;
    if !matches!(
        types.get(record_len.target),
        Some(TypeDef::Base {
            encoding: crate::bundle::Encoding::Unsigned,
            size: 8,
            ..
        })
    ) {
        return Err(missing("its outgoing record's length is no word"));
    }
    Ok(SendableBinding {
        prefix_used: count(&at(&[Member("prefix_used")]), "sent prefix")?,
        head: wrapped(&[Member("chunks"), Member("head")], "ring's head")?,
        len: wrapped(&[Member("chunks"), Member("len")], "ring's length")?,
        buf,
        cap: wrapped(
            &[
                Member("chunks"),
                Member("buf"),
                Member("inner"),
                Member("cap"),
            ],
            "ring's capacity",
        )?,
        record,
        record_len,
    })
}

/// A routed stream's peer: the path to its name, an array of bytes.
fn plan_stream_peer(
    ty: BundleTypeId,
    hops: &[Hop<'_>],
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<TypedPath, Decline> {
    let name = hop_landing(types, strings, ty, hops)?;
    let bytes = match types.get(name.target) {
        Some(&TypeDef::Array { elem, count }) => {
            count > 0
                && matches!(
                    types.get(elem),
                    Some(TypeDef::Base {
                        encoding: crate::bundle::Encoding::Unsigned,
                        size: 1,
                        ..
                    })
                )
        }
        _ => false,
    };
    if bytes {
        Ok(name)
    } else {
        Err((
            SemanticIssueKind::MissingLayout,
            "its peer's name is not an array of bytes in the final table".to_owned(),
        ))
    }
}

/// What a handshake's frame keeps of the far end, by state.
#[derive(Clone, Debug)]
struct FarEndPlan {
    rule: RuleKey,
    states: Vec<FarEndState>,
}

/// Plan a reviewed handshake's far end: the origin first — the file its
/// body was declared in, at a reviewed revision — then every state of
/// the coroutine that holds the stream local, landing on a routed TLS
/// stream, with the rule's address and name beside it where the state
/// keeps them: a path that ends early drops what nothing after it
/// reads, and the name is held only from the certificates on. A state
/// still awaiting the TLS handshake holds no stream local — the socket
/// went into the handshake future — so its stream is the one that
/// future holds: `awaited` gives the hops from the awaitee's type to
/// it, where the awaitee is a handshake a review covers. An address
/// the state does keep that is no enum declines the whole, as a stream
/// that is no routed TLS stream does: the layout is not the one
/// reviewed.
fn plan_far_end(
    ty: BundleTypeId,
    rule: &FarEndRule,
    source: Option<&PollSource>,
    tls_stream: &impl Fn(BundleTypeId) -> bool,
    awaited: &impl Fn(BundleTypeId) -> Option<(Vec<Step>, BundleTypeId)>,
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<FarEndPlan, Decline> {
    use Hop::{Member, Variant};
    let sources = source.into_iter().cloned().collect();
    let origin = git_delegation_origin(&sources, rule.review, "async fn body")?;
    let key = RuleKey::GitDelegation {
        kind: SemanticRuleKind::SprocketsHandshake,
        origin,
    };
    let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the coroutine is no enum in the final table".to_owned(),
        ));
    };
    let mut states = Vec::new();
    for variant in &shape.variants {
        let Some(state) = strings.get(variant.name) else {
            continue;
        };
        let stream = match hop_landing(types, strings, ty, &[Variant(state), Member(rule.stream)]) {
            Ok(stream) => stream,
            Err(_) => {
                let Ok(awaitee) =
                    hop_landing(types, strings, ty, &[Variant(state), Member(AWAITEE)])
                else {
                    continue;
                };
                let Some((hops, target)) = awaited(awaitee.target) else {
                    continue;
                };
                let mut steps = awaitee.steps;
                steps.extend(hops);
                checked_path(types, ty, steps, target)?
            }
        };
        if !tls_stream(stream.target) {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{state}'s {} is no routed TLS stream", rule.stream),
            ));
        }
        let addr = rule
            .addr
            .and_then(|addr| hop_landing(types, strings, ty, &[Variant(state), Member(addr)]).ok());
        if let Some(addr) = &addr
            && !matches!(types.get(addr.target), Some(TypeDef::Enum { .. }))
        {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{state}'s address is no enum in the final table"),
            ));
        }
        let mut hops = vec![Variant(state)];
        hops.extend(rule.name.iter().map(|&name| Member(name)));
        let name = plan_stream_peer(ty, &hops, types, strings).ok();
        states.push(FarEndState { stream, addr, name });
    }
    if states.is_empty() {
        return Err((
            SemanticIssueKind::MissingLayout,
            format!("no state holds its {}", rule.stream),
        ));
    }
    Ok(FarEndPlan { rule: key, states })
}

/// A routed stream's TLS layer: the paths to the connection it holds,
/// which has to be one whose words bind, and to its own state, an
/// enum.
fn plan_tls_stream(
    ty: BundleTypeId,
    hops: &TlsHops,
    sessions: &BTreeMap<BundleTypeId, TlsSessionPlan>,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<(TypedPath, TypedPath), Decline> {
    let session = hop_landing(types, strings, ty, hops.session)?;
    if !sessions.contains_key(&session.target) {
        return Err((
            SemanticIssueKind::NoRule,
            format!(
                "its connection, {}, has no reviewed session layout",
                type_label(names, session.target)
            ),
        ));
    }
    let state = hop_landing(types, strings, ty, hops.state)?;
    if !matches!(
        types.get(state.target),
        Some(TypeDef::Enum { .. } | TypeDef::CEnum { .. })
    ) {
        return Err((
            SemanticIssueKind::MissingLayout,
            "its state is not an enum in the final table".to_owned(),
        ));
    }
    Ok((session, state))
}

#[derive(Clone, Debug)]
struct IoOpPlan {
    kind: IoOperationKind,
    stream: TypedPath,
    remaining: Option<TypedPath>,
    /// The rule an operation of another crate binds under; tokio's
    /// bind under tokio's one origin.
    rule: Option<RuleKey>,
}

/// Plan every stream's route and every operation over one. A stream's
/// route is its seed's hops to the stream it holds, or its socket's
/// roles bound at its own type, or a reviewed third-party stream's
/// route once its origin checks out; a `Box` or `&mut` whose screen saw
/// a sized pointee forwards to it, by tokio's impls for both. Only the
/// routes that end at a socket are kept — a forward counts once the
/// type it lands on does, a match once any case's does, keeping just
/// those cases — so an operation's stream is routed exactly when a
/// reader following its route reaches a registration.
fn plan_io(
    seeds: &SemanticSeeds,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
    walks: &WalksTable,
) -> IoPlans {
    let mut sessions = BTreeMap::new();
    let mut tls_declines = BTreeMap::new();
    for (&ty, seed) in seeds {
        if let Some(sources) = &seed.tls_session {
            match plan_tls_session(ty, sources, types, names, strings) {
                Ok(plan) => {
                    sessions.insert(ty, plan);
                }
                Err(decline) => {
                    tls_declines.insert(ty, decline);
                }
            }
        }
    }
    let tokio = || RuleKey::Library(SemanticRuleKind::TokioIoRoute);
    let mut planned: BTreeMap<BundleTypeId, (RuleKey, PlannedStep)> = BTreeMap::new();
    let mut route_declines = BTreeMap::new();
    let fixed = |step| PlannedStep::Fixed(step);
    for (&ty, seed) in seeds {
        let step = match (&seed.io_route, &seed.adapter) {
            (Some(IoRouteSeed::Forward(hops)), _) => hop_landing(types, strings, ty, hops)
                .map(|inner| (tokio(), fixed(IoRouteStep::Forward { inner }))),
            (Some(IoRouteSeed::Socket(socket)), _) => {
                if bound_roots(walks, &socket_roles(*socket), &[]).contains(&ty) {
                    Ok((tokio(), fixed(IoRouteStep::Socket(*socket))))
                } else {
                    Err((
                        SemanticIssueKind::MissingLayout,
                        "the socket's registration and descriptor routes are not bound".to_owned(),
                    ))
                }
            }
            (Some(IoRouteSeed::Delegated { stream, sources }), _) => {
                delegated_route(ty, stream, sources, seeds, types, strings)
            }
            (
                None,
                Some(AdapterSeed {
                    kind: AdapterKind::Box | AdapterKind::MutRef,
                    pin: None,
                    pointee: PointeeSeed::Sized(pointee),
                    ..
                }),
            ) => hop_route(types, strings, ty, &[Hop::Deref], *pointee)
                .map(|inner| (tokio(), fixed(IoRouteStep::Forward { inner }))),
            _ => continue,
        };
        match step {
            Ok(step) => {
                planned.insert(ty, step);
            }
            Err(decline) => {
                route_declines.insert(ty, decline);
            }
        }
    }
    // The streams a trait object's read slot can name: every type with
    // a read method's symbol.
    let readers: Vec<BundleTypeId> = seeds
        .iter()
        .filter(|(_, seed)| !seed.read_symbols.is_empty())
        .map(|(&ty, _)| ty)
        .collect();
    let mut routed = BTreeSet::new();
    loop {
        let before = routed.len();
        for (&ty, (_, step)) in &planned {
            let ends = match step {
                PlannedStep::Fixed(IoRouteStep::Socket(_)) => true,
                PlannedStep::Fixed(IoRouteStep::Forward { inner }) => {
                    routed.contains(&inner.target)
                }
                PlannedStep::Fixed(IoRouteStep::Match { cases }) => {
                    cases.iter().any(|case| routed.contains(&case.target))
                }
                PlannedStep::Fixed(IoRouteStep::Dyn { .. }) => {
                    unreachable!("a trait object's step is planned as one")
                }
                PlannedStep::Dyn { .. } => readers.iter().any(|ty| routed.contains(ty)),
            };
            if ends {
                routed.insert(ty);
            }
        }
        if routed.len() == before {
            break;
        }
    }
    // A match keeps the cases that end at a socket: a value in any
    // other variant has no route, which a reader finds by its variant.
    // A trait object's cases are every routed stream a read symbol
    // names: a stream in no case has no route, which a reader finds by
    // the symbol its vtable holds.
    let routes = planned
        .iter()
        .filter(|(ty, _)| routed.contains(*ty))
        .map(|(&ty, (rule, step))| {
            let step = match step {
                PlannedStep::Fixed(IoRouteStep::Match { cases }) => {
                    PlannedStep::Fixed(IoRouteStep::Match {
                        cases: cases
                            .iter()
                            .filter(|case| routed.contains(&case.target))
                            .cloned()
                            .collect(),
                    })
                }
                PlannedStep::Dyn {
                    pointer,
                    data,
                    vtable,
                    abi,
                    read_slot,
                    ..
                } => PlannedStep::Dyn {
                    pointer: pointer.clone(),
                    data: data.clone(),
                    vtable: vtable.clone(),
                    abi: abi.clone(),
                    read_slot: *read_slot,
                    cases: readers
                        .iter()
                        .filter(|reader| routed.contains(*reader) && **reader != ty)
                        .flat_map(|&reader| {
                            seeds[&reader]
                                .read_symbols
                                .iter()
                                .map(move |symbol| (symbol.clone(), reader))
                        })
                        .collect(),
                },
                step => step.clone(),
            };
            (ty, (rule.clone(), step))
        })
        .collect();
    // A screened stream whose route runs off every reviewed one says
    // so; a `Box` or a reference over anything else is no stream at
    // all, and says nothing.
    for (&ty, (_, step)) in &planned {
        if !routed.contains(&ty) && seeds.get(&ty).is_some_and(|s| s.io_route.is_some()) {
            let detail = match step {
                PlannedStep::Fixed(IoRouteStep::Forward { inner }) => format!(
                    "the stream it holds, {}, has no reviewed route to a socket",
                    type_label(names, inner.target)
                ),
                PlannedStep::Fixed(IoRouteStep::Match { .. }) => {
                    "no variant's stream has a reviewed route to a socket".to_owned()
                }
                PlannedStep::Dyn { .. } => {
                    "no stream its trait object can hold has a reviewed route to a socket"
                        .to_owned()
                }
                PlannedStep::Fixed(IoRouteStep::Socket(_) | IoRouteStep::Dyn { .. }) => {
                    unreachable!("every socket route is kept, and no dyn step is fixed")
                }
            };
            route_declines.insert(ty, (SemanticIssueKind::NoRule, detail));
        }
    }

    let mut operations = BTreeMap::new();
    let mut operation_declines = BTreeMap::new();
    for (&ty, seed) in seeds {
        let planned = match (seed.io_op, seed.handshake) {
            (Some(op), _) => plan_io_operation(ty, op, &routes, types, names, strings),
            (None, true) => plan_handshake(ty, &seed.poll_sources, &routes, types, names, strings),
            (None, false) => continue,
        };
        match planned {
            Ok(plan) => {
                operations.insert(ty, plan);
            }
            Err(decline) => {
                operation_declines.insert(ty, decline);
            }
        }
    }
    // A routed stream that holds a rustls connection: its TLS layer,
    // where the connection's words bind.
    // And one that names its peer: the name, where it is bytes.
    let mut tls_streams = BTreeMap::new();
    let mut peers = BTreeMap::new();
    for (&ty, seed) in seeds {
        let Some(IoRouteSeed::Delegated { stream, .. }) = &seed.io_route else {
            continue;
        };
        if !routes.contains_key(&ty) {
            continue;
        }
        if let Some(hops) = &stream.tls {
            match plan_tls_stream(ty, hops, &sessions, types, names, strings) {
                Ok(paths) => {
                    tls_streams.insert(ty, paths);
                }
                Err(decline) => {
                    tls_declines.insert(ty, decline);
                }
            }
        }
        if let Some(hops) = stream.peer {
            match plan_stream_peer(ty, hops, types, strings) {
                Ok(name) => {
                    peers.insert(ty, name);
                }
                Err(decline) => {
                    tls_declines.insert(ty, decline);
                }
            }
        }
    }
    IoPlans {
        routes,
        operations,
        route_declines,
        operation_declines,
        sessions,
        tls_streams,
        peers,
        tls_declines,
    }
}

/// A type's own method declarations: the ones `own` places in its
/// crate. A foreign trait implemented on the type — reqwest converting
/// its request into http's, or giving tokio-rustls's client stream its
/// TLS-info trait — is declared in the implementing crate's file and
/// says nothing about which release declared the type. Where nothing
/// is left the whole set is kept, so the decline's reason names what
/// was found.
fn own_declarations(
    sources: &BTreeSet<PollSource>,
    own: impl Fn(&str) -> bool,
) -> Cow<'_, BTreeSet<PollSource>> {
    let owned: BTreeSet<PollSource> = sources
        .iter()
        .filter(|source| own(&source.path))
        .cloned()
        .collect();
    if owned.is_empty() {
        Cow::Borrowed(sources)
    } else {
        Cow::Owned(owned)
    }
}

/// The origin a type's own method declarations establish under a
/// release's review: those [`own_declarations`] places in the
/// convention's crate, held to [`delegation_origin`]. A generic impl
/// another crate writes for every type of a shape — hyper's
/// `HttpService` for every `Service` — counts as the type's own impl
/// once its self type resolves, and is declared in that crate.
fn method_origin(
    sources: &BTreeSet<PollSource>,
    convention: &'static LibraryConvention,
) -> Result<DelegationOrigin, Decline> {
    let sources = own_declarations(sources, |path| {
        registry_origin(path).is_some_and(|origin| origin.package == convention.package)
    });
    delegation_origin(&sources, convention, "method")
}

/// A reviewed third-party stream's route: its origin first — the
/// type's own method declarations, checked against the review — then
/// the reviewed route's hops, held to the final table. A match's cases
/// are each its variant's one payload.
fn delegated_route(
    ty: BundleTypeId,
    stream: &DelegatedStream,
    sources: &BTreeSet<PollSource>,
    seeds: &SemanticSeeds,
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<(RuleKey, PlannedStep), Decline> {
    let kind = stream.kind;
    let rule = match stream.review {
        Review::Release(convention) => RuleKey::Delegation {
            kind,
            origin: method_origin(sources, convention)?,
        },
        Review::Git(convention) => {
            let sources = own_declarations(sources, |path| {
                git_origin(path).is_some_and(|origin| origin.repository == convention.repository)
            });
            RuleKey::GitDelegation {
                kind,
                origin: git_delegation_origin(&sources, convention, "method")?,
            }
        }
    };
    let step = match stream.route {
        DelegatedRoute::Forward(hops) => PlannedStep::Fixed(IoRouteStep::Forward {
            inner: hop_landing(types, strings, ty, hops)?,
        }),
        // A box of a trait object the std adapter screen saw, read
        // under the compiler's rule for its header; its cases are the
        // routed streams, known once every route is.
        DelegatedRoute::Dyn(hops, read_slot) => {
            let (steps, wide) = hop_steps(types, strings, ty, hops)?;
            let Some(AdapterSeed {
                kind: AdapterKind::Box,
                pin: None,
                pointee: PointeeSeed::Dyn(dyn_seed),
                ..
            }) = seeds.get(&wide).and_then(|seed| seed.adapter.as_ref())
            else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!(
                        "its stream, type {}, is no boxed trait object the screen saw",
                        wide.0
                    ),
                ));
            };
            let Target::Dynamic {
                pointer,
                data,
                vtable,
                abi,
                ..
            } = dynamic_target(ty, steps, wide, dyn_seed, types, strings)?
            else {
                unreachable!("a dynamic target is dynamic");
            };
            PlannedStep::Dyn {
                pointer,
                data,
                vtable,
                abi: *abi,
                read_slot,
                cases: Vec::new(),
            }
        }
        DelegatedRoute::Match(variants) => PlannedStep::Fixed(IoRouteStep::Match {
            cases: variants
                .iter()
                .map(|variant| {
                    hop_landing(
                        types,
                        strings,
                        ty,
                        &[Hop::Variant(variant), Hop::Member("__0")],
                    )
                })
                .collect::<Result<_, _>>()?,
        }),
    };
    Ok((rule, step))
}

/// An operation over a routed stream: its `&mut` crossed to the stream,
/// which must be routed, and its slice's length where it holds one.
fn plan_io_operation(
    ty: BundleTypeId,
    op: IoOpSeed,
    routes: &BTreeMap<BundleTypeId, (RuleKey, PlannedStep)>,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<IoOpPlan, Decline> {
    let (_, pointer, _) = member_named(types, strings, ty, op.pointer).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        format!("no unique member {:?}", op.pointer),
    ))?;
    let Some(&TypeDef::Pointer { target, .. }) = types.get(pointer) else {
        return Err((
            SemanticIssueKind::MissingLayout,
            format!("its {} is not a pointer", op.pointer),
        ));
    };
    if !routes.contains_key(&target) {
        return Err((
            SemanticIssueKind::NoRule,
            format!(
                "the stream it polls, {}, has no reviewed route to a socket",
                type_label(names, target)
            ),
        ));
    }
    let stream = hop_route(
        types,
        strings,
        ty,
        &[Hop::Member(op.pointer), Hop::Deref],
        target,
    )?;
    let remaining = if op.sliced {
        let length = hop_landing(
            types,
            strings,
            ty,
            &[Hop::Member("buf"), Hop::Member("length")],
        )?;
        if !matches!(
            types.get(length.target),
            Some(TypeDef::Base {
                encoding: crate::bundle::Encoding::Unsigned,
                size: 8,
                ..
            })
        ) {
            return Err((
                SemanticIssueKind::MissingLayout,
                "its buffer's length is not an unsigned word".to_owned(),
            ));
        }
        Some(length)
    } else {
        None
    };
    Ok(IoOpPlan {
        kind: op.kind,
        stream,
        remaining,
        rule: None,
    })
}

/// tokio-rustls's handshake as an operation over its stream: the origin
/// first — every declaration of its `poll` in tokio-rustls, inside the
/// reviewed range — then the path through the `Handshaking` variant to
/// the stream it holds, which has to be routed. In any other state it
/// holds no stream to wait on, which the reader finds by its variant.
fn plan_handshake(
    ty: BundleTypeId,
    sources: &BTreeSet<PollSource>,
    routes: &BTreeMap<BundleTypeId, (RuleKey, PlannedStep)>,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<IoOpPlan, Decline> {
    let origin = delegation_origin(sources, &TOKIO_RUSTLS_HANDSHAKE_V0_26_0, "poll")?;
    let stream = hop_landing(
        types,
        strings,
        ty,
        &[Hop::Variant("Handshaking"), Hop::Member("__0")],
    )?;
    if !routes.contains_key(&stream.target) {
        return Err((
            SemanticIssueKind::NoRule,
            format!(
                "the stream it handshakes over, {}, has no reviewed route to a socket",
                type_label(names, stream.target)
            ),
        ));
    }
    Ok(IoOpPlan {
        kind: IoOperationKind::Handshake,
        stream,
        remaining: None,
        rule: Some(RuleKey::Delegation {
            kind: SemanticRuleKind::TokioRustlsHandshake,
            origin,
        }),
    })
}

/// A type's name for a decline's text, or its id where it has none.
fn type_label(names: &[Option<String>], ty: BundleTypeId) -> String {
    names
        .get(ty.0 as usize)
        .and_then(Option::as_deref)
        .map_or_else(|| format!("type {}", ty.0), str::to_owned)
}

enum PoolPlan {
    Reaper {
        rule: RuleKey,
        strong: TypedPath,
        idle: TypedPath,
        key_ptr: TypedPath,
        key_len: TypedPath,
        entries_ptr: TypedPath,
        entries_len: TypedPath,
        entry: BundleTypeId,
        want: TypedPath,
        conn_info: Option<TypedPath>,
    },
    Checkout {
        rule: RuleKey,
        key_ptr: TypedPath,
        key_len: TypedPath,
        want: TypedPath,
        conn_info: Option<TypedPath>,
    },
}

/// Plan a pool binding: the origin first — the type's own method
/// declarations in hyper-util, at a version inside the reviewed range —
/// then the routes the screen described, by the reviewed layout's
/// member names, held to the final table and landing on the types the
/// screen saw. A reaper's routes start at the reaper, then at a bucket
/// of its idle map and at an element of a bucket's list; a checkout's
/// start at the checkout.
fn plan_pool(
    ty: BundleTypeId,
    seed: &PoolSeed,
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<PoolPlan, Decline> {
    use Hop::{Deref, Member, Variant};
    use hyper_pool::*;
    let (PoolSeed::Reaper { sources, .. } | PoolSeed::Checkout { sources, .. }) = seed;
    let convention = &HYPER_UTIL_POOL_V0_1_16;
    // A trait another crate implements on the type is declared in that
    // crate's file, and says nothing about which hyper-util this is.
    let own: BTreeSet<PollSource> = sources
        .iter()
        .filter(|source| {
            registry_origin(&source.path).is_some_and(|origin| origin.package == convention.package)
        })
        .cloned()
        .collect();
    let sources = if own.is_empty() { sources } else { &own };
    let origin = delegation_origin(sources, convention, "method")?;
    let rule = RuleKey::Delegation {
        kind: SemanticRuleKind::HyperUtilPool,
        origin,
    };
    let route =
        |root, hops: &[&[Hop<'_>]], target| hop_route(types, strings, root, &hops.concat(), target);
    let giver: Vec<Hop<'_>> = GIVER_PTR.iter().map(|name| Member(name)).collect();
    // The sender behind a `PoolClient`: `tx`'s `Http1`, down to its giver.
    let client_want = [Member(TX), Variant(HTTP1)];
    // The connection's info beside the sender: a fact the key and the
    // sender stand without, so a route that does not hold leaves none.
    let conn_info = |root, client: &[Hop<'_>], target: &Option<BundleTypeId>| {
        target.and_then(|target| {
            route(
                root,
                &[client, &[Member(adapters::hyper_connected::CONN_INFO)]],
                target,
            )
            .ok()
        })
    };
    match seed {
        PoolSeed::Reaper {
            strong,
            idle,
            bucket,
            key_ptr,
            key_len,
            entries_ptr,
            entries_len,
            entry,
            want,
            conn_info: info,
            ..
        } => {
            let pool = [
                Member(POOL),
                Member(PAYLOAD),
                Variant(SOME),
                Member(PAYLOAD),
                Member(PTR),
                Member(POINTER),
                Deref,
            ];
            // The bucket is `((Scheme, Authority), Vec<Idle<T>>)`.
            let key = [
                Member(PAYLOAD),
                Member(AUTHORITY),
                Member(DATA),
                Member(BYTES),
            ];
            let list = [Member(AUTHORITY)];
            let vec_ptr: Vec<Hop<'_>> = VEC_PTR.iter().map(|name| Member(name)).collect();
            Ok(PoolPlan::Reaper {
                rule,
                strong: route(ty, &[&pool, &[Member(STRONG)]], *strong)?,
                idle: route(
                    ty,
                    &[
                        &pool,
                        &[Member(DATA), Member(DATA), Member(VALUE), Member(IDLE)],
                    ],
                    *idle,
                )?,
                key_ptr: route(*bucket, &[&key, &[Member(PTR)]], *key_ptr)?,
                key_len: route(*bucket, &[&key, &[Member(LEN)]], *key_len)?,
                entries_ptr: route(*bucket, &[&list, &vec_ptr], *entries_ptr)?,
                entries_len: route(*bucket, &[&list, &[Member(LEN)]], *entries_len)?,
                entry: *entry,
                want: route(*entry, &[&[Member(VALUE)], &client_want, &giver], *want)?,
                conn_info: conn_info(*entry, &[Member(VALUE)], info),
            })
        }
        PoolSeed::Checkout {
            key_ptr,
            key_len,
            want,
            conn_info: info,
            ..
        } => {
            let key = [Member(KEY), Member(AUTHORITY), Member(DATA), Member(BYTES)];
            let client = [Member(VALUE), Variant(SOME), Member(PAYLOAD)];
            Ok(PoolPlan::Checkout {
                rule,
                key_ptr: route(ty, &[&key, &[Member(PTR)]], *key_ptr)?,
                key_len: route(ty, &[&key, &[Member(LEN)]], *key_len)?,
                want: route(ty, &[&client, &client_want, &giver], *want)?,
                conn_info: conn_info(ty, &client, info),
            })
        }
    }
}

/// `Connected`'s binding as planned, with its rules unnumbered and each
/// case's symbol not yet interned.
#[derive(Clone, Debug)]
struct ConnectedPlan {
    rule: RuleKey,
    alpn: TypedPath,
    is_proxied: TypedPath,
    extra: TypedPath,
    data: TypedPath,
    vtable: TypedPath,
    abi: RuleKey,
    cases: Vec<ExtraCasePlan>,
}

#[derive(Clone, Debug)]
struct ExtraCasePlan {
    symbol: String,
    target: BundleTypeId,
    remote_addr: Option<TypedPath>,
    local_addr: Option<TypedPath>,
    next: Option<TypedPath>,
}

/// Plan hyper-util's `Connected`: the origin first — the type's own
/// method declarations in hyper-util, at a version inside the reviewed
/// range — then its two words and the box of its extras, read under
/// the compiler's rule for a trait object's header, and a case for
/// every extra whose `set` the sweep found: an envelope of one value
/// at `__0`, or a chain of a value at `__1` over the box of the extras
/// before it at `__0`. A value that is `HttpInfo` binds its two
/// addresses, each landing on one address enum; a case whose layout
/// does not hold is left out, and its symbol then names no extra.
fn plan_connected(
    ty: BundleTypeId,
    seed: &ConnectedSeed,
    seeds: &SemanticSeeds,
    extras: &[(BundleTypeId, BTreeSet<String>)],
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<ConnectedPlan, Decline> {
    use Hop::{Member, Variant};
    use adapters::hyper_connected::*;
    let origin = method_origin(&seed.sources, &HYPER_UTIL_CONNECTED_V0_1_10)?;
    let rule = RuleKey::Delegation {
        kind: SemanticRuleKind::HyperUtilConnected,
        origin,
    };
    let alpn = hop_route(types, strings, ty, &[Member(ALPN)], seed.alpn)?;
    let is_proxied = hop_route(types, strings, ty, &[Member(IS_PROXIED)], seed.is_proxied)?;
    let (steps, wide) = hop_steps(
        types,
        strings,
        ty,
        &[
            Member(EXTRA),
            Variant(SOME),
            Member(PAYLOAD),
            Member(PAYLOAD),
        ],
    )?;
    if wide != seed.extra {
        return Err((
            SemanticIssueKind::MissingLayout,
            "its extras' box is not the one screened".to_owned(),
        ));
    }
    let Some(AdapterSeed {
        kind: AdapterKind::Box,
        pin: None,
        pointee: PointeeSeed::Dyn(dyn_seed),
        ..
    }) = seeds.get(&wide).and_then(|seed| seed.adapter.as_ref())
    else {
        return Err((
            SemanticIssueKind::MissingLayout,
            "its extras are no boxed trait object the screen saw".to_owned(),
        ));
    };
    let Target::Dynamic {
        pointer: extra,
        data,
        vtable,
        abi,
        ..
    } = dynamic_target(ty, steps, wide, dyn_seed, types, strings)?
    else {
        unreachable!("a dynamic target is dynamic");
    };
    let named = |target: BundleTypeId| names.get(target.0 as usize).and_then(|n| n.as_deref());
    let mut cases = Vec::new();
    for (target, symbols) in extras {
        let Some(name) = named(*target) else {
            continue;
        };
        let (value, next) = if name.starts_with(ENVELOPE) {
            (PAYLOAD, None)
        } else if name.starts_with(CHAIN) {
            match hop_route(types, strings, *target, &[Member(PAYLOAD)], wide) {
                Ok(next) => (CHAINED, Some(next)),
                Err(_) => continue,
            }
        } else {
            continue;
        };
        let Ok(held) = hop_landing(types, strings, *target, &[Member(value)]) else {
            continue;
        };
        let address = |field: &'static str| {
            hop_landing(types, strings, *target, &[Member(value), Member(field)])
                .ok()
                .filter(|path| matches!(types.get(path.target), Some(TypeDef::Enum { .. })))
        };
        let (remote_addr, local_addr) = match named(held.target) {
            Some(HTTP_INFO) => {
                let Some(remote) = address(REMOTE_ADDR) else {
                    continue;
                };
                let Some(local) = landing_on(address(LOCAL_ADDR), remote.target) else {
                    continue;
                };
                (Some(remote), Some(local))
            }
            _ => (None, None),
        };
        for symbol in symbols {
            cases.push(ExtraCasePlan {
                symbol: symbol.clone(),
                target: *target,
                remote_addr: remote_addr.clone(),
                local_addr: local_addr.clone(),
                next: next.clone(),
            });
        }
    }
    Ok(ConnectedPlan {
        rule,
        alpn,
        is_proxied,
        extra,
        data,
        vtable,
        abi: *abi,
        cases,
    })
}

/// Plan a `select!`'s binding: the origin first — the closure
/// environment declared in tokio's `src/macros/select.rs` on a cargo
/// registry path at a version inside the reviewed range — then the two
/// routes through the closure's references and one per tuple member,
/// each held to the final table. The mask word has to be the unsigned
/// integer the screen saw, of a width tokio-macros emits, with room
/// for every branch.
fn plan_select(
    ty: BundleTypeId,
    seed: &SelectSeed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<(SelectPlan, Vec<Decline>), Decline> {
    let Some(source) = &seed.source else {
        return Err((
            SemanticIssueKind::UnsupportedOrigin,
            "the closure environment records no declaration site".to_owned(),
        ));
    };
    let origin = delegation_origin(
        &BTreeSet::from([source.clone()]),
        &TOKIO_SELECT_V1_47,
        "closure",
    )?;
    let rule = RuleKey::Delegation {
        kind: SemanticRuleKind::TokioSelect,
        origin,
    };
    let member = |strings: &mut StringInterner, parent: BundleTypeId, name: &str| {
        member_named(types, strings, parent, name).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("no unique member {name:?}"),
        ))
    };
    // Both captures: the `PollFn`'s closure, the closure's reference,
    // then what it points at.
    let (closure, env, _) = member(strings, ty, &seed.closure)?;
    let capture = |strings: &mut StringInterner, name: &str, target| {
        let (name, _, _) = member(strings, env, name)?;
        checked_path(
            types,
            ty,
            vec![
                Step::Member(MemberRef::Named(closure)),
                Step::Member(MemberRef::Named(name)),
                Step::Deref,
            ],
            target,
        )
    };
    let mask = capture(strings, &seed.mask, seed.mask_word)?;
    if !matches!(
        types.get(seed.mask_word),
        Some(TypeDef::Base {
            encoding: crate::Encoding::Unsigned,
            size: 1 | 2 | 4 | 8,
            ..
        })
    ) {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the mask is not an unsigned word in the final table".to_owned(),
        ));
    }
    let futures = capture(strings, &seed.futures, seed.tuple)?;
    let mut branches = Vec::with_capacity(seed.branches.len());
    for (name, future) in &seed.branches {
        let (name, member_ty, _) = member(strings, seed.tuple, name)?;
        if member_ty != *future {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!(
                    "{} holds another type than the screen declared",
                    strings.get(name).unwrap_or_default()
                ),
            ));
        }
        branches.push(checked_path(
            types,
            seed.tuple,
            vec![Step::Member(MemberRef::Named(name))],
            *future,
        )?);
    }
    if branches.is_empty() {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the tuple has no members".to_owned(),
        ));
    }
    if seed.arms.len() != branches.len() {
        return Err((
            SemanticIssueKind::MissingLayout,
            format!(
                "{} arms were joined for {} branches",
                seed.arms.len(),
                branches.len()
            ),
        ));
    }
    // Each written arm's path is cut the way every other source path
    // in the bundle is; a declined one is an issue beside the binding.
    let mut declined = Vec::new();
    let arms = seed
        .arms
        .iter()
        .map(|arm| match arm {
            ArmSite::Written(loc) => loc.bundle_loc(strings),
            ArmSite::Unbound => None,
            ArmSite::Declined(decline) => {
                declined.push(decline.clone());
                None
            }
        })
        .collect();
    Ok((
        SelectPlan {
            rule,
            mask,
            futures,
            branches,
            arms,
        },
        declined,
    ))
}

/// Plan `Instrumented<F>`'s delegation: the origin first — every
/// declaration of its `poll` on a cargo registry path naming `tracing`
/// at one version inside the reviewed range, any checksum the file
/// tables carried among the reviewed revisions — then the storage
/// route, `inner` and whatever std wrappers hold `F` inside it, held to
/// the final table. The forwarded poll runs the span's subscriber
/// callbacks around it, so the delegation is not exclusive.
fn plan_instrumented(
    ty: BundleTypeId,
    layout: &InstrumentedSeed,
    seed: &Seed,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
) -> Result<Plan, Decline> {
    let origin = delegation_origin(&seed.poll_sources, &TRACING_INSTRUMENTED_V0_1_40, "poll")?;
    let (name, inner_ty, _) = member_named(types, strings, ty, &layout.inner).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        format!("Instrumented has no unique member {:?}", layout.inner),
    ))?;
    let mut steps = vec![Step::Member(MemberRef::Named(name))];
    let mut current = inner_ty;
    // `inner` is `ManuallyDrop<F>`, which std currently lays out as
    // `{ value: MaybeDangling<F> }` over `{ __0: F }`: each a transparent
    // wrapper with one member at offset zero, entered by name, and
    // nothing else is.
    const WRAPPERS: [&str; 2] = [
        "core::mem::manually_drop::ManuallyDrop<",
        "core::mem::maybe_dangling::MaybeDangling<",
    ];
    for _ in 0..WRAPPERS.len() {
        if current == layout.future {
            break;
        }
        let name = names
            .get(current.0 as usize)
            .and_then(|n| n.as_deref())
            .unwrap_or_default();
        if !WRAPPERS.iter().any(|w| name.starts_with(w)) {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("inner holds {name:?}, not a reviewed std wrapper of the future"),
            ));
        }
        let [member] = members_of(types, current) else {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{name} is not a one-member wrapper"),
            ));
        };
        if member.offset != 0 {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{name}'s member is not at offset zero"),
            ));
        }
        steps.push(Step::Member(MemberRef::Named(member.name)));
        current = member.ty;
    }
    if current != layout.future {
        return Err((
            SemanticIssueKind::MissingLayout,
            "inner does not reach the declared future through reviewed wrappers".to_owned(),
        ));
    }
    let path = checked_path(types, ty, steps, layout.future)?;
    Ok(Plan {
        rule: RuleKey::Delegation {
            kind: SemanticRuleKind::TracingInstrumented,
            origin,
        },
        program: Some(Delegation::Direct {
            target: Target::Value(path),
            exclusive: false,
        }),
        access: None,
        delegate_is_future: true,
        resource: None,
    })
}

/// The origin an instantiation's poll declarations establish for a
/// reviewed third-party implementation. Every declaration has to lie on
/// a cargo registry path naming the convention's crate; they have to
/// agree on one such path; its version has to fall inside the reviewed
/// range; and a checksum, where a file table carried one, has to be a
/// reviewed revision. No declaration at all is no origin: the
/// implementation may be inlined away, but then nothing says which one
/// it was.
fn delegation_origin(
    sources: &BTreeSet<PollSource>,
    convention: &'static LibraryConvention,
    declared_by: &str,
) -> Result<DelegationOrigin, Decline> {
    let decline = |detail: String| (SemanticIssueKind::UnsupportedOrigin, detail);
    let package = convention.package;
    if sources.is_empty() {
        return Err(decline(format!(
            "no {declared_by} declaration records where this instantiation's implementation lives"
        )));
    }
    let mut declared: Vec<(String, semver::Version)> = Vec::new();
    let mut files: Vec<(String, [u8; 16])> = Vec::new();
    for source in sources {
        let Some(origin) = registry_origin(&source.path) else {
            return Err(decline(format!(
                "declared in {}, which is not a cargo registry path",
                source.path
            )));
        };
        if origin.package != package {
            return Err(decline(format!(
                "declared in {}, which is not the {package} crate",
                source.path
            )));
        }
        if !declared.iter().any(|(path, _)| path == origin.path) {
            declared.push((origin.path.to_owned(), origin.version));
        }
        if let Some(md5) = source.md5 {
            files.push((origin.path.to_owned(), md5));
        }
    }
    // Several files of one release declare one type where its impls
    // sit apart — `TokioIo`'s io impls beside its `Connection` impl —
    // and the review read each of them; a file it did not read is a
    // type it did not describe. Such a release counts once, under its
    // first file.
    declared.sort();
    let mut releases: Vec<(String, semver::Version)> = Vec::new();
    for (path, version) in declared {
        match releases.last() {
            Some((first, last)) if *last == version => {
                let reviewed = |path: &str| {
                    registry_origin(path).is_some_and(|origin| {
                        convention
                            .checksums
                            .iter()
                            .any(|(file, _)| *file == origin.file)
                    })
                };
                if !(reviewed(first) && reviewed(&path)) {
                    return Err(decline(format!("declared in both {first} and {path}")));
                }
            }
            _ => releases.push((path, version)),
        }
    }
    let mut declared = releases;
    // A target linking two releases of one crate — two reqwests, each
    // with its own copy of the type — declares the type in both, and
    // the layouts are one type here only because they are identical.
    // Where every release declared is inside the reviewed range the
    // binding holds for each of them, and the origin names the newest;
    // a release outside it is the decline it would be alone.
    declared.sort_by(|a, b| a.1.cmp(&b.1));
    let (source, version) = match declared.as_slice() {
        [] => unreachable!("at least one source"),
        [one] => one.clone(),
        [first, .., last] => {
            let mut versions: Vec<&semver::Version> = declared.iter().map(|(_, v)| v).collect();
            versions.dedup();
            if versions.len() != declared.len() {
                return Err(decline(format!(
                    "declared in both {} and {}",
                    first.0, last.0
                )));
            }
            if let Some((outside, side)) = declared
                .iter()
                .find_map(|(_, v)| library_convention(convention, v).err().map(|s| (v, s)))
            {
                return Err(refuse(
                    convention.family,
                    UnreviewedRelease::outside(convention, outside, side),
                    format!(
                        "declared in both {} and {}, and {outside} is outside the reviewed range {}",
                        first.0,
                        last.0,
                        convention.releases.range_for(outside)
                    ),
                ));
            }
            last.clone()
        }
    };
    let convention = match library_convention(convention, &version) {
        Ok(convention) => convention,
        Err(side) => {
            let word = match side {
                LayoutSelection::BelowFloor => "below",
                _ => "above",
            };
            return Err(refuse(
                convention.family,
                UnreviewedRelease::outside(convention, &version, side),
                format!(
                    "{package} {version} is {word} the reviewed range {}",
                    convention.releases.range_for(&version)
                ),
            ));
        }
    };
    files.sort();
    files.dedup();
    for (file, md5) in &files {
        if !convention.reviewed_checksum(md5) {
            return Err(decline(format!(
                "{file} has checksum {}, not a reviewed revision of {}",
                hex(md5),
                convention.family
            )));
        }
    }
    Ok(DelegationOrigin {
        package: convention.package,
        version: version.to_string(),
        family: convention.family,
        source,
        files,
    })
}

/// The origin a type's declarations establish for a reviewed
/// implementation fetched from git. Every declaration has to lie on a
/// cargo git checkout path of the convention's repository, in its
/// implementing file; they have to agree on one such path; its revision
/// has to name exactly one reviewed revision; and a checksum, where a
/// file table carried one, has to be that revision's. As with a
/// release, no declaration at all is no origin.
fn git_delegation_origin(
    sources: &BTreeSet<PollSource>,
    convention: &'static GitConvention,
    declared_by: &str,
) -> Result<GitDelegationOrigin, Decline> {
    let decline = |detail: String| (SemanticIssueKind::UnsupportedOrigin, detail);
    let mut declared: Option<(String, String, String)> = None;
    let mut files: Vec<(String, [u8; 16])> = Vec::new();
    if sources.is_empty() {
        return Err(decline(format!(
            "no {declared_by} declaration records where this instantiation's implementation lives"
        )));
    }
    for source in sources {
        let Some(origin) = git_origin(&source.path) else {
            return Err(decline(format!(
                "declared in {}, which is not a cargo git checkout path",
                source.path
            )));
        };
        if origin.repository != convention.repository || origin.file != convention.file {
            return Err(decline(format!(
                "declared in {}, which is not {} in the {} repository",
                source.path, convention.file, convention.repository
            )));
        }
        match &declared {
            None => {
                declared = Some((
                    origin.path.to_owned(),
                    origin.repository.to_owned(),
                    origin.revision.to_owned(),
                ))
            }
            Some((path, ..)) if path == origin.path => {}
            Some((path, ..)) => {
                return Err(decline(format!(
                    "declared in both {path} and {}",
                    origin.path
                )));
            }
        }
        if let Some(md5) = source.md5 {
            files.push((origin.path.to_owned(), md5));
        }
    }
    let (source, repository, revision) = declared.expect("at least one source");
    let Some((_, reviewed)) = convention.reviewed_revision(&revision) else {
        return Err(refuse(
            convention.family,
            UnreviewedRelease::Revision {
                package: convention.package,
                revision: revision.clone(),
            },
            format!(
                "{} revision {revision} is not a reviewed revision of {}",
                convention.repository, convention.family
            ),
        ));
    };
    files.sort();
    files.dedup();
    for (file, md5) in &files {
        if md5 != reviewed {
            return Err(decline(format!(
                "{file} has checksum {}, not revision {revision}'s",
                hex(md5)
            )));
        }
    }
    Ok(GitDelegationOrigin {
        package: convention.package,
        repository,
        revision,
        family: convention.family,
        source,
        files,
    })
}

fn hex(md5: &[u8; 16]) -> String {
    md5.iter().map(|b| format!("{b:02x}")).collect()
}

/// The program a bound coroutine layout spells: one case per state, a
/// suspended state delegating to its `__awaitee` — the one member the
/// convention names as the future being awaited — and to nothing else.
/// A suspended state without one keeps an unknown case: the layout is
/// still read, the continuation not guessed.
fn coroutine_plan(
    ty: BundleTypeId,
    rule: &RuleKey,
    layout: &CoroutineLayout,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Plan {
    let awaitee = strings.intern(AWAITEE);
    let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
        unreachable!("a bound coroutine is an enum");
    };
    let cases = layout
        .states
        .iter()
        .map(|state| {
            let action = match state.stage {
                CoroutinePhase::Unresumed => CaseAction::Unresumed,
                CoroutinePhase::Returned => CaseAction::Returned,
                CoroutinePhase::Panicked => CaseAction::Panicked,
                CoroutinePhase::Unknown => CaseAction::Unknown(SemanticIssue {
                    kind: SemanticIssueKind::UnsupportedState,
                    detail: None,
                }),
                CoroutinePhase::Suspended => {
                    let payload = shape
                        .variants
                        .iter()
                        .find(|v| v.name == state.variant)
                        .map(|v| v.payload.ty);
                    let member = payload.and_then(|payload| {
                        let mut found = members_of(types, payload)
                            .iter()
                            .filter(|m| m.name == awaitee);
                        let member = found.next()?;
                        (found.next().is_none() && state.locals.contains(&awaitee))
                            .then_some(member.ty)
                    });
                    match member {
                        Some(target) => match checked_path(
                            types,
                            ty,
                            vec![
                                Step::Variant(state.variant),
                                Step::Member(MemberRef::Named(awaitee)),
                            ],
                            target,
                        ) {
                            Ok(path) => CaseAction::Delegate(Box::new(Target::Value(path))),
                            Err((kind, detail)) => CaseAction::Unknown(SemanticIssue {
                                kind,
                                detail: Some(strings.intern(&detail)),
                            }),
                        },
                        None => CaseAction::Unknown(SemanticIssue {
                            kind: SemanticIssueKind::MissingLayout,
                            detail: Some(strings.intern("the suspended state lists no __awaitee")),
                        }),
                    }
                }
            };
            (state.variant, action)
        })
        .collect();
    Plan {
        rule: rule.clone(),
        program: Some(Delegation::Match {
            state: TypedPath {
                steps: Vec::new(),
                target: ty,
            },
            cases,
        }),
        access: None,
        delegate_is_future: true,
        resource: None,
    }
}

/// The stage rustc's variant numbering assigns, and the payload name it
/// carries: the convention the reviewed range was checked for.
fn expected_state(index: usize) -> (CoroutinePhase, String) {
    match index {
        0 => (CoroutinePhase::Unresumed, "Unresumed".to_owned()),
        1 => (CoroutinePhase::Returned, "Returned".to_owned()),
        2 => (CoroutinePhase::Panicked, "Panicked".to_owned()),
        n => (CoroutinePhase::Suspended, format!("Suspend{}", n - 3)),
    }
}

/// Whether a planned chain from `root` reaches one of `targets`
/// through the static children the plans delegate to, however deep —
/// the chain being bounded by the plans themselves, and each type
/// walked once.
fn reaches_any(
    root: BundleTypeId,
    drafts: &BTreeMap<BundleTypeId, Draft>,
    targets: &BTreeSet<BundleTypeId>,
) -> bool {
    let mut seen = BTreeSet::from([root]);
    let mut queue = VecDeque::from([root]);
    while let Some(ty) = queue.pop_front() {
        let Some(plan) = drafts.get(&ty).and_then(|d| d.plan.as_ref()) else {
            continue;
        };
        for child in plan.static_children() {
            if targets.contains(&child) {
                return true;
            }
            if seen.insert(child) {
                queue.push_back(child);
            }
        }
    }
    false
}

/// Plan a refcount header's binding: the compiler verdict on its
/// defining units, then the reviewed layout — the two counts first,
/// `strong` at the start, and the named value member after them.
fn plan_refcount(
    ty: BundleTypeId,
    value: &str,
    verdict: &CompilerVerdict,
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<(RuleKey, MemberRef), Decline> {
    let (producer, convention) = supported(verdict)?;
    let layout = |detail: &str| (SemanticIssueKind::MissingLayout, detail.to_owned());
    let (_, _, strong) =
        member_named(types, strings, ty, "strong").ok_or_else(|| layout("no strong count"))?;
    let (_, _, weak) =
        member_named(types, strings, ty, "weak").ok_or_else(|| layout("no weak count"))?;
    let (name, _, at) = member_named(types, strings, ty, value)
        .ok_or_else(|| layout(&format!("no unique {value} member")))?;
    if strong != 0 || at <= weak {
        return Err(layout("the value does not follow the counts"));
    }
    Ok((
        RuleKey::Rustc {
            kind: SemanticRuleKind::StdRefcountHeader,
            producer: producer.to_owned(),
            family: convention.family,
        },
        MemberRef::Named(name),
    ))
}

/// Plan a raw lock's binding: the origin — the compiler verdict on
/// std's mutex, parking_lot's method declarations on a cargo registry
/// path inside the reviewed range — then the one state word the
/// reviewed implementation keeps, at the start of the lock, with the
/// bits that say it is held: all of std's futex word, parking_lot's
/// low bit.
fn plan_lock(
    ty: BundleTypeId,
    seed: &LockSeed,
    types: &TypeTable,
    strings: &StringInterner,
) -> Result<(RuleKey, LockWord), Decline> {
    let (rule, member, mask) = match seed {
        LockSeed::StdFutex(verdict) => {
            let (producer, convention) = supported(verdict)?;
            let rule = RuleKey::Rustc {
                kind: SemanticRuleKind::StdFutexMutex,
                producer: producer.to_owned(),
                family: convention.family,
            };
            (rule, "futex", None)
        }
        LockSeed::ParkingLot(sources) => {
            let origin = delegation_origin(sources, &PARKING_LOT_RAW_MUTEX_V0_11_0, "method")?;
            let rule = RuleKey::Delegation {
                kind: SemanticRuleKind::ParkingLotRawMutex,
                origin,
            };
            (rule, "state", Some(0b01))
        }
    };
    let layout = |detail: String| (SemanticIssueKind::MissingLayout, detail);
    let (_, word_ty, offset) = member_named(types, strings, ty, member)
        .ok_or_else(|| layout(format!("no unique {member} member")))?;
    let size = match types.get(word_ty) {
        Some(TypeDef::Base { size, .. } | TypeDef::Struct { size, .. }) => *size,
        _ => return Err(layout(format!("{member} is no word"))),
    };
    if offset != 0 || members_of(types, ty).len() != 1 || !matches!(size, 1 | 2 | 4 | 8) {
        return Err(layout(format!("{member} is not the lock's one word")));
    }
    let bits = size * 8;
    let whole = if bits == 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    };
    Ok((
        rule,
        LockWord {
            offset,
            size: size as u8,
            locked_mask: mask.unwrap_or(whole),
        },
    ))
}

/// The member a refcounted allocation's header keeps its value in,
/// where `name` is one of std's two headers: an `Arc`'s `ArcInner<T>`
/// keeps it in `data`, an `Rc`'s `RcInner<T>` in `value`.
fn refcount_value(name: &str) -> Option<&'static str> {
    if name.starts_with("alloc::sync::ArcInner<") {
        Some("data")
    } else if name.starts_with("alloc::rc::RcInner<") {
        Some("value")
    } else {
        None
    }
}

/// The rule saying which kind of coroutine a compiler candidate is —
/// an async fn's, block's or closure's environment, as its generated
/// name says — under the verdict on its defining units. A producer no
/// reviewed convention covers names nothing, and neither does a
/// candidate of a kind with no rule.
fn coroutine_kind_rule(ty: BundleTypeId, seed: &Seed, names: &[Option<String>]) -> Option<RuleKey> {
    let Some(CompilerVerdict::Supported {
        producer,
        convention,
    }) = &seed.compiler
    else {
        return None;
    };
    let name = names.get(ty.0 as usize)?.as_deref()?;
    let kind = match coroutine_kind(name)? {
        "async fn" => SemanticRuleKind::RustcAsyncFn,
        "async block" => SemanticRuleKind::RustcAsyncBlock,
        "async closure" => SemanticRuleKind::RustcAsyncClosure,
        _ => return None,
    };
    Some(RuleKey::Rustc {
        kind,
        producer: producer.clone(),
        family: convention.family,
    })
}

/// Bind a compiler candidate's states under its reviewed convention, or
/// say why not. The verdict on its defining units comes first; the enum
/// is then held to the convention's exact shape — numbered variants in
/// stage order, payload names to match, terminal states emptied — and
/// each state's members are classed: an `Unresumed`'s are its arguments,
/// a suspended state's are the locals live across its await, except
/// that an async block's captures, which the state kept whether or not
/// the body has moved them out, are uncertain.
fn bind_coroutine(
    ty: BundleTypeId,
    seed: &Seed,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
) -> Result<(RuleKey, CoroutineLayout), Decline> {
    let (producer, convention) = match &seed.compiler {
        Some(CompilerVerdict::Supported {
            producer,
            convention,
        }) => (producer, *convention),
        Some(CompilerVerdict::Declined(detail)) => {
            return Err((SemanticIssueKind::UnsupportedOrigin, detail.clone()));
        }
        None => {
            return Err((
                SemanticIssueKind::UnsupportedOrigin,
                "no defining unit recorded".to_owned(),
            ));
        }
    };
    let name = names
        .get(ty.0 as usize)
        .and_then(|n| n.as_deref())
        .unwrap_or_default();
    let kind = match coroutine_kind(name) {
        Some("async fn") => SemanticRuleKind::RustcAsyncFn,
        Some("async block") => SemanticRuleKind::RustcAsyncBlock,
        _ => {
            return Err((
                SemanticIssueKind::NoRule,
                "only async fn and async block environments have a reviewed rule".to_owned(),
            ));
        }
    };
    let states = coroutine_states(
        ty,
        kind == SemanticRuleKind::RustcAsyncBlock,
        types,
        names,
        strings,
    )?;
    let rule = RuleKey::Rustc {
        kind,
        producer: producer.clone(),
        family: convention.family,
    };
    Ok((
        rule,
        CoroutineLayout {
            // Numbered when the record is emitted.
            rule: SemanticRuleId(u32::MAX),
            states,
        },
    ))
}

/// Hold the final enum to the convention's shape and class each state's
/// members. `strings` is read only, for the variant keys.
fn coroutine_states(
    ty: BundleTypeId,
    is_block: bool,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<Vec<CoroutineState>, Decline> {
    let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the environment is not an enum".to_owned(),
        ));
    };
    if shape.variants.len() < 3 {
        return Err((
            SemanticIssueKind::UnsupportedState,
            format!(
                "{} variants, fewer than the three fixed stages",
                shape.variants.len()
            ),
        ));
    }
    let unresumed: BTreeSet<(StrRef, BundleTypeId, u64)> =
        members_of(types, shape.variants[0].payload.ty)
            .iter()
            .map(|m| (m.name, m.ty, m.offset))
            .collect();
    let mut states = Vec::with_capacity(shape.variants.len());
    for (index, variant) in shape.variants.iter().enumerate() {
        let key = strings.get(variant.name).unwrap_or_default();
        if key != index.to_string() {
            return Err((
                SemanticIssueKind::UnsupportedState,
                format!("variant {index} is keyed {key:?}, not by its position"),
            ));
        }
        let (stage, expected) = expected_state(index);
        let actual = state_name(names, variant.payload.ty).unwrap_or_default();
        if actual != expected {
            return Err((
                SemanticIssueKind::UnsupportedState,
                format!("variant {index} is {actual:?}, not {expected:?}"),
            ));
        }
        if !matches!(types.get(variant.payload.ty), Some(TypeDef::Struct { .. })) {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{expected} is not a struct"),
            ));
        }
        let members = members_of(types, variant.payload.ty);
        let mut seen = BTreeSet::new();
        for member in members {
            if !seen.insert(member.name) {
                return Err((
                    SemanticIssueKind::AmbiguousLayout,
                    format!(
                        "{expected} lists {:?} twice",
                        strings.get(member.name).unwrap_or_default()
                    ),
                ));
            }
        }
        let (locals, uncertain_locals): (Vec<StrRef>, Vec<StrRef>) = match stage {
            CoroutinePhase::Returned | CoroutinePhase::Panicked => {
                if !members.is_empty() {
                    return Err((
                        SemanticIssueKind::UnsupportedState,
                        format!("{expected} still lists {} members", members.len()),
                    ));
                }
                (Vec::new(), Vec::new())
            }
            CoroutinePhase::Unresumed => (members.iter().map(|m| m.name).collect(), Vec::new()),
            CoroutinePhase::Suspended => {
                let (captures, live): (Vec<_>, Vec<_>) = members
                    .iter()
                    .partition(|m| is_block && unresumed.contains(&(m.name, m.ty, m.offset)));
                (
                    live.into_iter().map(|m| m.name).collect(),
                    captures.into_iter().map(|m| m.name).collect(),
                )
            }
            CoroutinePhase::Unknown => unreachable!("expected_state never says unknown"),
        };
        states.push(CoroutineState {
            variant: variant.name,
            stage,
            locals,
            uncertain_locals,
        });
    }
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{MemberDef, VariantDef, VariantShape, WalkBinding};
    use crate::detect::semantics::{RUSTC_DYN_FUTURE_ABI_V1_97, RUSTC_STD_ADAPTERS_V1_97};

    /// A dispatcher screened as the connection resource is a record on
    /// that alone, as a tokio resource or a `select!` is: the binding
    /// is a fact worth a record whether or not a poll declaration
    /// survived to prove the type a future.
    #[test]
    fn test_a_screened_dispatcher_is_its_own_record() {
        let id = BundleTypeId(7);
        let seed = Seed {
            http: Some(HttpSeed {
                role: H1Role::Client,
                keep_alive: id,
                reading: id,
                writing: id,
                method: id,
                method_inner: id,
                read_continue_kind: id,
                read_body_kind: id,
                write_body_kind: id,
                is_closing: id,
                client: None,
                server: None,
            }),
            ..Seed::default()
        };
        assert!(seed.is_own_record());
        assert!(!Seed::default().is_own_record());
    }

    /// Each hyper seed runs under the convention that reviewed its
    /// crate: the connection wrappers under hyper's, the
    /// version-choosing wrapper under hyper-util's own — not the sleep's,
    /// which is another file of the same crate.
    #[test]
    fn test_hyper_seeds_name_their_conventions() {
        let id = BundleTypeId(7);
        let auto = LibrarySeed::HyperUtilAuto {
            state: "state".to_owned(),
            state_ty: id,
            h1_conn: "conn".to_owned(),
            h1: id,
        };
        assert_eq!(
            auto.convention().family,
            HYPER_UTIL_AUTO_CONN_V0_1_10.family
        );
        assert_eq!(auto.rule_kind(), SemanticRuleKind::HyperUtilAutoConn);
        let connection = LibrarySeed::HyperConnection("conn".to_owned(), id);
        assert_eq!(connection.convention().family, HYPER_H1_CONN_V1_6_0.family);
        assert_eq!(connection.rule_kind(), SemanticRuleKind::HyperH1Conn);
        let upgradeable = LibrarySeed::HyperUpgradeable {
            inner: "inner".to_owned(),
            option: id,
            dispatcher_member: "conn".to_owned(),
            dispatcher: id,
        };
        assert_eq!(upgradeable.convention().family, HYPER_H1_CONN_V1_6_0.family);
        assert_eq!(upgradeable.rule_kind(), SemanticRuleKind::HyperH1Conn);
        assert_ne!(
            HYPER_UTIL_AUTO_CONN_V0_1_10.family,
            HYPER_UTIL_TOKIO_SLEEP_V0_1_10.family
        );
    }

    fn binding(roots: &[u32], bound: bool) -> WalkBinding {
        WalkBinding {
            roots: if bound {
                roots.iter().map(|&r| BundleTypeId(r)).collect()
            } else {
                Vec::new()
            },
            steps: Vec::new(),
            outcome: if bound {
                WalkOutcome::Bound {
                    spelling: 0,
                    spellings: 1,
                    note: None,
                }
            } else {
                WalkOutcome::Absent {
                    reason: "none".to_owned(),
                }
            },
        }
    }

    fn ids(roots: &[u32]) -> BTreeSet<BundleTypeId> {
        roots.iter().map(|&r| BundleTypeId(r)).collect()
    }

    /// A kind binds at the types every one of its roles bound at — the
    /// intersection, never the union — and at none when a role is
    /// unbound or a chained route below them is.
    #[test]
    fn test_bound_roots_intersects_roles_and_requires_every_route() {
        use WalkRole::*;
        let mut walks = WalksTable::default();
        walks
            .entries
            .insert(SleepDeadline, binding(&[1, 2, 3], true));
        walks
            .entries
            .insert(JoinHandleRaw, binding(&[2, 3, 4], true));
        walks.entries.insert(TcpStreamShared, binding(&[9], true));
        walks.entries.insert(UnixStreamShared, binding(&[], false));
        assert_eq!(
            bound_roots(&walks, &[SleepDeadline, JoinHandleRaw], &[]),
            ids(&[2, 3])
        );
        assert_eq!(bound_roots(&walks, &[SleepDeadline], &[]), ids(&[1, 2, 3]));
        // A route only has to be bound; it roots elsewhere.
        assert_eq!(
            bound_roots(&walks, &[SleepDeadline], &[TcpStreamShared]),
            ids(&[1, 2, 3])
        );
        // An entry that recorded roots but no `Bound` outcome — which
        // the bundle validator forbids, so only a hand-built table has
        // one — binds nothing either: the outcome decides, not the list.
        let mut stale = binding(&[1, 2], true);
        stale.outcome = WalkOutcome::Broken {
            errors: vec!["moved".to_owned()],
        };
        walks.entries.insert(AcquireQueued, stale);
        assert!(bound_roots(&walks, &[AcquireQueued], &[]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline], &[AcquireQueued]).is_empty());
        // An unbound route, an unbound role, or a role never recorded
        // binds nothing.
        assert!(bound_roots(&walks, &[SleepDeadline], &[UnixStreamShared]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline, UnixStreamShared], &[]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline, AcquireNode], &[]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline], &[AcquireNode]).is_empty());
    }

    /// A coroutine env spelled the way rustc does: numbered variants whose
    /// payload structs carry the state names, with the member sets the
    /// state pass leaves behind.
    struct Env {
        types: TypeTable,
        names: Vec<Option<String>>,
        strings: StringInterner,
        env: BundleTypeId,
    }

    fn env(kind: &str, states: &[(&str, &[&str])], keys: &[&str]) -> Env {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = vec![Some("u32".to_owned())];
        let mut types = vec![TypeDef::Base {
            name: strings.intern("u32"),
            size: 4,
            encoding: crate::Encoding::Unsigned,
        }];
        let env_name = format!("app::work::{{{kind}_env#0}}");
        let mut variants = Vec::new();
        for (index, (state, members)) in states.iter().enumerate() {
            let payload = BundleTypeId(types.len() as u32);
            let name = format!("{env_name}::{state}");
            types.push(TypeDef::Struct {
                name: strings.intern(&name),
                size: 32,
                members: members
                    .iter()
                    .enumerate()
                    .map(|(i, m)| MemberDef {
                        name: strings.intern(m),
                        ty: BundleTypeId(0),
                        // A repeated name at a distinct slot is the
                        // shadowed-local case; the same name at the same
                        // slot is what the capture check keys on.
                        offset: 4 * i as u64,
                    })
                    .collect(),
            });
            names.push(Some(name));
            let key = strings.intern(keys.get(index).copied().unwrap_or(&index.to_string()));
            variants.push(VariantDef {
                name: key,
                discr_values: None,
                payload: MemberDef {
                    name: key,
                    ty: payload,
                    offset: 0,
                },
                decl: None,
                await_site: None,
            });
        }
        let env = BundleTypeId(types.len() as u32);
        types.push(TypeDef::Enum {
            name: strings.intern(&env_name),
            size: 32,
            shape: VariantShape {
                discr: None,
                variants,
            },
        });
        names.push(Some(env_name));
        Env {
            types: TypeTable {
                types,
                ..Default::default()
            },
            names,
            strings,
            env,
        }
    }

    fn render(e: &Env, states: &[CoroutineState]) -> Vec<String> {
        let s = |r| e.strings.get(r).unwrap();
        states
            .iter()
            .map(|st| {
                format!(
                    "{}:{:?}[{}]({})",
                    s(st.variant),
                    st.stage,
                    st.locals
                        .iter()
                        .map(|&n| s(n))
                        .collect::<Vec<_>>()
                        .join(","),
                    st.uncertain_locals
                        .iter()
                        .map(|&n| s(n))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect()
    }

    const FN: &[(&str, &[&str])] = &[
        ("Unresumed", &["arg"]),
        ("Returned", &[]),
        ("Panicked", &[]),
        ("Suspend0", &["local", "__awaitee"]),
        ("Suspend1", &["__awaitee"]),
    ];

    #[test]
    fn test_async_fn_states_class_arguments_and_live_locals() {
        let e = env("async_fn", FN, &[]);
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(
            render(&e, &states),
            [
                "0:Unresumed[arg]()",
                "1:Returned[]()",
                "2:Panicked[]()",
                "3:Suspended[local,__awaitee]()",
                "4:Suspended[__awaitee]()",
            ]
        );
    }

    /// An async block's suspended states keep its captures at the slot
    /// `Unresumed` lists them at; those are uncertain, everything else is
    /// live. The same name at another slot is a distinct local.
    #[test]
    fn test_async_block_captures_are_uncertain_only_at_their_unresumed_slot() {
        let e = env(
            "async_block",
            &[
                ("Unresumed", &["cap", "other"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["cap", "__awaitee", "other"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, true, &e.types, &e.names, &e.strings).unwrap();
        // `cap` sits at slot 0 in both; `other` moved from slot 4 to 8.
        assert_eq!(render(&e, &states)[3], "3:Suspended[__awaitee,other](cap)");
        // The same shape as an async fn admits every member as live: its
        // arguments were already stripped from the suspended states.
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(render(&e, &states)[3], "3:Suspended[cap,__awaitee,other]()");
    }

    #[test]
    fn test_coroutine_shape_declines_name_each_departure_from_the_convention() {
        let decline = |e: &Env| {
            coroutine_states(e.env, false, &e.types, &e.names, &e.strings)
                .unwrap_err()
                .0
        };
        // Variants keyed by anything but their position.
        let e = env("async_fn", FN, &["0", "1", "2", "Suspend0", "4"]);
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // States out of the fixed order.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Panicked", &[]),
                ("Returned", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // Suspend numbering that skips.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend1", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // A terminal state still listing storage.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &["arg"]),
                ("Panicked", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // A shadowed local listed twice in one state: which is which is
        // not knowable by name, so the whole type declines.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["x", "__awaitee", "x"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::AmbiguousLayout);
        // Too few variants for the three fixed stages.
        let e = env("async_fn", &[("Unresumed", &[]), ("Returned", &[])], &[]);
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // Not an enum at all.
        let mut e = env("async_fn", FN, &[]);
        e.types.types[e.env.0 as usize] = TypeDef::Opaque {
            name: e.strings.intern("app::work::{async_fn_env#0}"),
            size: Some(32),
        };
        assert_eq!(decline(&e), SemanticIssueKind::MissingLayout);
    }

    const PRODUCER: &str = "clang LLVM (rustc version 1.98.0 (88d9e12ae 2026-08-18))";

    fn supported(convention: &'static RustcConvention) -> CompilerVerdict {
        CompilerVerdict::Supported {
            producer: PRODUCER.to_owned(),
            convention,
        }
    }

    /// A final type table with a future `app::Fut` (id 1), a `dyn Future`
    /// (2) with its data (3) and vtable (5) pointers, a sized box (6), a
    /// reference (7), a wide box (8), and `Pin`s over the box (9) and the
    /// wide box (10).
    struct Adapters {
        types: TypeTable,
        names: Vec<Option<String>>,
        strings: StringInterner,
    }

    fn adapters() -> Adapters {
        let mut strings = StringInterner::new();
        let mut names = Vec::new();
        let mut types = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let usize_t = add(
            "usize",
            TypeDef::Base {
                name: strings.intern("usize"),
                size: 8,
                encoding: crate::Encoding::Unsigned,
            },
        );
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 16,
                members: vec![MemberDef {
                    name: strings.intern("state"),
                    ty: usize_t,
                    offset: 0,
                }],
            },
        );
        let dyn_name = "(dyn core::future::future::Future<Output=()> + core::marker::Send)";
        let dyn_t = add(
            dyn_name,
            TypeDef::Struct {
                name: strings.intern(dyn_name),
                size: 0,
                members: Vec::new(),
            },
        );
        let data = add(
            "*const dyn",
            TypeDef::Pointer {
                name: None,
                target: dyn_t,
            },
        );
        let slots = add(
            "[usize; 4]",
            TypeDef::Array {
                elem: usize_t,
                count: 4,
            },
        );
        let vtable = add(
            "&[usize; 4]",
            TypeDef::Pointer {
                name: Some(strings.intern("&[usize; 4]")),
                target: slots,
            },
        );
        let boxed = add(
            "alloc::boxed::Box<app::Fut, alloc::alloc::Global>",
            TypeDef::Pointer {
                name: Some(strings.intern("alloc::boxed::Box<app::Fut, alloc::alloc::Global>")),
                target: fut,
            },
        );
        let reference = add(
            "&mut app::Fut",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut app::Fut")),
                target: fut,
            },
        );
        let wide_name = "alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global>";
        let wide = add(
            wide_name,
            TypeDef::Struct {
                name: strings.intern(wide_name),
                size: 16,
                members: vec![
                    MemberDef {
                        name: strings.intern("pointer"),
                        ty: data,
                        offset: 0,
                    },
                    MemberDef {
                        name: strings.intern("vtable"),
                        ty: vtable,
                        offset: 8,
                    },
                ],
            },
        );
        for (name, inner) in [
            (
                "core::pin::Pin<alloc::boxed::Box<app::Fut, alloc::alloc::Global>>",
                boxed,
            ),
            (
                "core::pin::Pin<alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global>>",
                wide,
            ),
        ] {
            let size = if inner == wide { 16 } else { 8 };
            add(
                name,
                TypeDef::Struct {
                    name: strings.intern(name),
                    size,
                    members: vec![MemberDef {
                        name: strings.intern("pointer"),
                        ty: inner,
                        offset: 0,
                    }],
                },
            );
        }
        let box_ref = add(
            "alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>",
            TypeDef::Pointer {
                name: Some(
                    strings.intern("alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>"),
                ),
                target: reference,
            },
        );
        add(
            "core::pin::Pin<alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>>",
            TypeDef::Struct {
                name: strings.intern(
                    "core::pin::Pin<alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>>",
                ),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("pointer"),
                    ty: box_ref,
                    offset: 0,
                }],
            },
        );
        // tokio-util's box over the pinned wide pointer, for the
        // storage route whose target is the trait object.
        add(
            "tokio_util::sync::reusable_box::ReusableBoxFuture<()>",
            TypeDef::Struct {
                name: strings.intern("tokio_util::sync::reusable_box::ReusableBoxFuture<()>"),
                size: 16,
                members: vec![MemberDef {
                    name: strings.intern("boxed"),
                    ty: PIN_WIDE,
                    offset: 0,
                }],
            },
        );
        Adapters {
            types: TypeTable {
                types,
                ..Default::default()
            },
            names,
            strings,
        }
    }

    const FUT: BundleTypeId = BundleTypeId(1);
    const DYN: BundleTypeId = BundleTypeId(2);
    const DATA: BundleTypeId = BundleTypeId(3);
    const VTABLE: BundleTypeId = BundleTypeId(5);
    const BOX: BundleTypeId = BundleTypeId(6);
    const REF: BundleTypeId = BundleTypeId(7);
    const WIDE: BundleTypeId = BundleTypeId(8);
    const PIN_BOX: BundleTypeId = BundleTypeId(9);
    const PIN_WIDE: BundleTypeId = BundleTypeId(10);
    const BOX_REF: BundleTypeId = BundleTypeId(11);
    const PIN_BOX_REF: BundleTypeId = BundleTypeId(12);
    const REUSABLE: BundleTypeId = BundleTypeId(13);

    fn dyn_seed() -> DynSeed {
        DynSeed {
            wide: WIDE,
            pointer: "pointer".into(),
            vtable: "vtable".into(),
            data_ptr: DATA,
            vtable_ptr: VTABLE,
            trait_ty: DYN,
            future_trait: true,
            abi: supported(&RUSTC_DYN_FUTURE_ABI_V1_97),
        }
    }

    fn seed(
        kind: AdapterKind,
        pin: Option<(&str, BundleTypeId)>,
        pointee: PointeeSeed,
    ) -> AdapterSeed {
        AdapterSeed {
            kind,
            pin: pin.map(|(m, p)| (m.to_owned(), p)),
            pointee,
            compiler: supported(&RUSTC_STD_ADAPTERS_V1_97),
        }
    }

    fn steps_of(a: &Adapters, target: &Target) -> String {
        let s = |r: StrRef| a.strings.get(r).unwrap().to_owned();
        let render = |p: &TypedPath| {
            p.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => s(*n),
                    Step::Deref => "*".to_owned(),
                    Step::Variant(n) => format!("::{}", s(*n)),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
                + &format!(" -> {}", a.names[p.target.0 as usize].as_deref().unwrap())
        };
        match target {
            Target::Value(p) => render(p),
            Target::Dynamic {
                pointer,
                data,
                vtable,
                ..
            } => format!(
                "dyn {} [{} | {}]",
                render(pointer),
                render(data),
                render(vtable)
            ),
        }
    }

    /// Each adapter's route is the one std declares — the `Pin` member,
    /// then the thin pointer's dereference or the wide pointer's two
    /// words — held to the final table, and the same route is the
    /// adapter's storage access.
    #[test]
    fn test_adapter_plans_follow_the_declared_route() {
        let mut a = adapters();
        let cases = [
            (
                BOX,
                seed(AdapterKind::Box, None, PointeeSeed::Sized(FUT)),
                "* -> app::Fut",
                SemanticRuleKind::StdBoxPoll,
                AccessKind::Owned,
            ),
            (
                REF,
                seed(AdapterKind::MutRef, None, PointeeSeed::Sized(FUT)),
                "* -> app::Fut",
                SemanticRuleKind::StdMutRefPoll,
                AccessKind::Borrowed,
            ),
            (
                PIN_BOX,
                seed(
                    AdapterKind::PinBox,
                    Some(("pointer", BOX)),
                    PointeeSeed::Sized(FUT),
                ),
                "pointer.* -> app::Fut",
                SemanticRuleKind::StdPinBoxPoll,
                AccessKind::Owned,
            ),
            (
                PIN_WIDE,
                seed(
                    AdapterKind::PinBox,
                    Some(("pointer", WIDE)),
                    PointeeSeed::Dyn(dyn_seed()),
                ),
                "dyn pointer -> alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global> [pointer -> *const dyn | vtable -> &[usize; 4]]",
                SemanticRuleKind::StdPinBoxPoll,
                AccessKind::Owned,
            ),
        ];
        for (ty, seed, expected, rule, access) in cases {
            let plan = plan_adapter(ty, &seed, &a.types, &mut a.strings)
                .unwrap_or_else(|e| panic!("{expected}: {e:?}"));
            let Delegation::Direct { target, exclusive } = plan.program.as_ref().unwrap() else {
                panic!("adapters delegate directly");
            };
            assert!(exclusive, "{expected}");
            assert_eq!(steps_of(&a, target), expected);
            assert!(matches!(&plan.rule, RuleKey::Rustc { kind, family, .. }
                if *kind == rule && *family == "rustc-std-adapters-1.97"));
            let (_, kind, access_target) = plan.access.as_ref().unwrap();
            assert_eq!(*kind, access);
            assert_eq!(access_target, target);
            if let Target::Dynamic { abi, .. } = target {
                assert!(
                    matches!(abi.as_ref(), RuleKey::Rustc { kind: SemanticRuleKind::DynFutureAbi, family, .. }
                    if *family == "rustc-dyn-future-abi-1.97")
                );
            }
        }
    }

    /// futures-util's `Pending<T>`: the never-ready terminal under the
    /// crate's layout rule, whatever the seed says about declarations —
    /// none survive in any build, and the layout is the whole proof.
    #[test]
    fn test_the_futures_util_pending_rule_binds_on_its_layout() {
        let mut strings = StringInterner::new();
        let types = TypeTable {
            types: vec![TypeDef::Struct {
                name: strings.intern("futures_util::future::pending::Pending<u32>"),
                size: 0,
                members: Vec::new(),
            }],
            ..Default::default()
        };
        let plan = plan_library(
            BundleTypeId(0),
            &LibrarySeed::Pending,
            &Seed::default(),
            &types,
            &mut strings,
        )
        .unwrap();
        assert!(
            matches!(
                plan.rule,
                RuleKey::Library(SemanticRuleKind::FuturesUtilPending)
            ),
            "{:?}",
            plan.rule
        );
        assert!(matches!(plan.program, Some(Delegation::NeverReady)));
        assert!(plan.access.is_none());
        assert!(!plan.delegate_is_future);
    }

    /// A container's rule: the two sets under their library's one
    /// layout origin, whatever the seed says; the map under
    /// tokio-stream's delegation origin read off the type's own method
    /// declarations, declining — with no container — where those are
    /// missing, off the registry, another crate's, or at a version on
    /// either side of the reviewed range.
    #[test]
    fn test_the_map_container_rule_reads_the_type_origin() {
        let typed = |path: &str| Seed {
            type_sources: BTreeSet::from([source(path, None)]),
            ..Seed::default()
        };
        let registry = |package: &str, version: &str| {
            typed(&format!(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 {package}-{version}/src/stream_map.rs"
            ))
        };
        for kind in [ContainerKind::JoinSet, ContainerKind::FuturesUnordered] {
            let rule = container_rule(kind, &Seed::default()).unwrap();
            assert!(matches!(rule, RuleKey::Library(_)), "{kind:?}: {rule:?}");
        }
        let rule = container_rule(
            ContainerKind::StreamMap,
            &registry("tokio-stream", "0.1.19"),
        )
        .unwrap();
        assert!(
            matches!(&rule, RuleKey::Delegation { kind: SemanticRuleKind::TokioStreamStreamMap, origin }
            if origin.package == "tokio-stream" && origin.version == "0.1.19"
                && origin.family == TOKIO_STREAM_MAP_V0_1_14.family),
            "{rule:?}"
        );
        let reviewed = TOKIO_STREAM_MAP_V0_1_14.checksums[4].1;
        let checked = Seed {
            type_sources: BTreeSet::from([source(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 tokio-stream-0.1.19/src/stream_map.rs",
                Some(reviewed),
            )]),
            ..Seed::default()
        };
        assert!(container_rule(ContainerKind::StreamMap, &checked).is_ok());
        for (seed, expected) in [
            (Seed::default(), "no method declaration"),
            (
                typed("/build/vendor/tokio-stream-0.1.19/src/stream_map.rs"),
                "not a cargo registry path",
            ),
            (
                registry("tokio-util", "0.7.19"),
                "not the tokio-stream crate",
            ),
            (
                registry("tokio-stream", "0.1.13"),
                "below the reviewed range",
            ),
            (
                registry("tokio-stream", "0.1.20"),
                "above the reviewed range",
            ),
            (
                Seed {
                    type_sources: BTreeSet::from([source(
                        "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                         tokio-stream-0.1.19/src/stream_map.rs",
                        Some([9; 16]),
                    )]),
                    ..Seed::default()
                },
                "not a reviewed revision",
            ),
        ] {
            let (kind, detail) = container_rule(ContainerKind::StreamMap, &seed).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{detail}");
        }
    }

    /// A table's hashbrown release is read off its map's declarations:
    /// a registry release, or the one the toolchain vendors for std.
    /// Another crate's declaration on the map names nothing and is set
    /// aside; releases on both paths bind together where each is
    /// reviewed, as the newest; and one outside the range, a checksum
    /// that is no reviewed file's, or no release named at all, declines.
    #[test]
    fn test_a_table_release_is_read_off_either_hashbrown_path() {
        let registry = |package: &str, version: &str| {
            source(
                &format!(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     {package}-{version}/src/map.rs"
                ),
                None,
            )
        };
        let vendored =
            |version: &str| source(&format!("/rust/deps/hashbrown-{version}/src/map.rs"), None);
        let release = |sources: &[PollSource]| {
            layout_release(&sources.iter().cloned().collect(), &HASHBROWN_TABLE_V0_12_3)
        };
        assert_eq!(
            release(&[registry("hashbrown", "0.15.5")]).unwrap(),
            "0.15.5"
        );
        assert_eq!(release(&[vendored("0.17.1")]).unwrap(), "0.17.1");
        assert_eq!(
            release(&[
                vendored("0.17.1"),
                registry("hashbrown", "0.14.5"),
                registry("serde", "1.0.228"),
            ])
            .unwrap(),
            "0.17.1"
        );
        for (sources, expected) in [
            (vec![], "no method declaration"),
            (
                vec![registry("serde", "1.0.228")],
                "names no hashbrown release",
            ),
            (
                vec![source("/build/vendor/hashbrown-0.15.5/src/map.rs", None)],
                "names no hashbrown release",
            ),
            (
                vec![vendored("0.12.2")],
                "0.12.2 is below the reviewed range",
            ),
            (
                vec![vendored("0.17.1"), registry("hashbrown", "0.18.0")],
                "0.18.0 is above the reviewed range",
            ),
            (
                vec![source(
                    "/rust/deps/hashbrown-0.17.1/src/map.rs",
                    Some([9; 16]),
                )],
                "not a reviewed revision",
            ),
        ] {
            let (kind, detail) = release(&sources).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{expected}: {detail}");
        }
    }

    /// tokio-util's box plans an owned access and no program: the route
    /// runs through `boxed` and the `Pin`'s member to the wide pointer,
    /// whose two words the dyn join reads, under the tokio-util origin
    /// read off the type's own method declarations. A `Pin` whose
    /// member is not the box the screen saw declines on the layout; no
    /// method declaration, or one off the registry, declines before it.
    #[test]
    fn test_the_reusable_box_plans_an_owned_dynamic_access() {
        let mut a = adapters();
        let typed = |path: &str| Seed {
            type_sources: BTreeSet::from([source(path, None)]),
            ..Seed::default()
        };
        let registry = typed(
            "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
             tokio-util-0.7.19/src/sync/reusable_box.rs",
        );
        let layout = |pin| LibrarySeed::ReusableBox {
            boxed: "boxed".into(),
            pin: ("pointer".into(), pin),
            dyn_: dyn_seed(),
        };
        let plan =
            plan_library(REUSABLE, &layout(WIDE), &registry, &a.types, &mut a.strings).unwrap();
        assert!(
            plan.program.is_none(),
            "a storage route polls nothing itself"
        );
        assert!(plan.delegate_is_future);
        let (rule, kind, target) = plan.access.as_ref().unwrap();
        assert_eq!(*kind, AccessKind::Owned);
        assert!(
            matches!(rule, RuleKey::Delegation { kind: SemanticRuleKind::TokioUtilReusableBox, origin }
            if origin.package == "tokio-util" && origin.version == "0.7.19"
                && origin.family == TOKIO_UTIL_REUSABLE_BOX_V0_7_11.family)
        );
        assert_eq!(&plan.rule, rule);
        assert_eq!(
            steps_of(&a, target),
            "dyn boxed.pointer -> alloc::boxed::Box<(dyn core::future::future::Future<Output=()> \
             + core::marker::Send), alloc::alloc::Global> [pointer -> *const dyn | vtable -> \
             &[usize; 4]]"
        );
        let (kind, detail) =
            plan_library(REUSABLE, &layout(BOX), &registry, &a.types, &mut a.strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("Pin's member"), "{detail}");
        for (seed, expected) in [
            (Seed::default(), "no method declaration"),
            (
                typed("/build/vendor/tokio-util-0.7.19/src/sync/reusable_box.rs"),
                "not a cargo registry path",
            ),
            (
                typed(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     tokio-util-0.7.20/src/sync/reusable_box.rs",
                ),
                "above the reviewed range",
            ),
        ] {
            let (kind, detail) =
                plan_library(REUSABLE, &layout(WIDE), &seed, &a.types, &mut a.strings).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{detail}");
        }
    }

    /// `Pending` plans the terminal under the compiler rule, on the
    /// verdict alone: no route, no access, no delegate to prove a
    /// future; and a verdict outside the reviewed range is the decline
    /// with its reason.
    #[test]
    fn test_pending_plans_the_terminal_on_the_compiler_verdict_alone() {
        use crate::detect::semantics::RUSTC_CORE_PENDING_V1_97;
        let plan = plan_pending(&supported(&RUSTC_CORE_PENDING_V1_97)).unwrap();
        assert_eq!(
            plan.rule,
            RuleKey::Rustc {
                kind: SemanticRuleKind::CorePending,
                producer: PRODUCER.to_owned(),
                family: RUSTC_CORE_PENDING_V1_97.family,
            }
        );
        assert!(matches!(plan.program, Some(Delegation::NeverReady)));
        assert!(plan.access.is_none());
        assert!(!plan.delegate_is_future);
        assert!(plan.static_children().is_empty());
        let (kind, detail) =
            plan_pending(&CompilerVerdict::Declined("rustc 2.999".into())).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
        assert_eq!(detail, "rustc 2.999");
    }

    /// A route that the final table does not bear out declines with the
    /// reason, as does an adapter compiled outside the reviewed range or
    /// a wide pointer whose ABI was.
    #[test]
    fn test_adapter_plans_decline_layout_and_origin_departures() {
        let mut a = adapters();
        let kind_of = |result: Result<Plan, Decline>| result.unwrap_err().0;
        // The declared pointee is not what the pointer targets.
        let s = seed(AdapterKind::Box, None, PointeeSeed::Sized(DYN));
        assert_eq!(
            kind_of(plan_adapter(BOX, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::MissingLayout
        );
        // Pin's member is not its declared pointer.
        let s = seed(
            AdapterKind::PinBox,
            Some(("pointer", REF)),
            PointeeSeed::Sized(FUT),
        );
        assert_eq!(
            kind_of(plan_adapter(PIN_BOX, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::MissingLayout
        );
        // The wide pointer's trait object grew a member.
        let mut grown = adapters();
        if let TypeDef::Struct { members, .. } = &mut grown.types.types[DYN.0 as usize] {
            members.push(MemberDef {
                name: grown.strings.intern("x"),
                ty: BundleTypeId(0),
                offset: 0,
            });
        }
        let s = seed(AdapterKind::Box, None, PointeeSeed::Dyn(dyn_seed()));
        assert_eq!(
            kind_of(plan_adapter(WIDE, &s, &grown.types, &mut grown.strings)),
            SemanticIssueKind::MissingLayout
        );
        // Outside the reviewed toolchains, on either review.
        let mut s = seed(AdapterKind::Box, None, PointeeSeed::Sized(FUT));
        s.compiler = CompilerVerdict::Declined("rustc 2.999".into());
        assert_eq!(
            kind_of(plan_adapter(BOX, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::UnsupportedOrigin
        );
        let mut d = dyn_seed();
        d.abi = CompilerVerdict::Declined("rustc 2.999".into());
        let s = seed(AdapterKind::Box, None, PointeeSeed::Dyn(d));
        assert_eq!(
            kind_of(plan_adapter(WIDE, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::UnsupportedOrigin
        );
        // The supported case still plans, so the declines above were
        // the departures and not the fixture.
        let s = seed(AdapterKind::Box, None, PointeeSeed::Dyn(dyn_seed()));
        plan_adapter(WIDE, &s, &a.types, &mut a.strings).unwrap();
    }

    fn source(path: &str, md5: Option<[u8; 16]>) -> PollSource {
        PollSource {
            path: path.to_owned(),
            md5,
        }
    }

    /// A request's origin is read from its own crate's method
    /// declarations where it has any, but a method-declared type with
    /// none keeps what it has, so the decline names it; and a
    /// poll-declared one is never narrowed to its own crate.
    #[test]
    fn test_a_request_origin_keeps_foreign_declarations_to_decline_on() {
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let reqwest = format!("{ROOT}/reqwest-0.13.2/src/async_impl/request.rs");
        let tokio = format!("{ROOT}/tokio-1.52.4/src/runtime/task/core.rs");
        let seed = |kind, sources| RequestSeed {
            kind,
            method_inner: BundleTypeId(1),
            target_ptr: BundleTypeId(2),
            target_len: BundleTypeId(3),
            sources,
        };
        let decline = |seed: &RequestSeed, polls: &BTreeSet<PollSource>| {
            let mut strings = StringInterner::new();
            plan_request(
                BundleTypeId(0),
                seed,
                polls,
                &TypeTable::default(),
                &mut strings,
            )
            .map(|_| ())
            .unwrap_err()
            .1
        };
        // http's `Request` with only reqwest's conversion declared on it.
        let request = seed(
            HttpRequestKind::HttpRequest,
            BTreeSet::from([source(&reqwest, None)]),
        );
        let why = decline(&request, &BTreeSet::new());
        assert!(why.contains("which is not the http crate"), "{why}");
        // reqwest's `PendingRequest` whose polls include another crate's.
        let pending = seed(HttpRequestKind::ReqwestPendingRequest, BTreeSet::new());
        let polls = BTreeSet::from([source(&reqwest, None), source(&tokio, None)]);
        let why = decline(&pending, &polls);
        assert!(why.contains("which is not the reqwest crate"), "{why}");
    }

    /// A type's own method declarations decide its origin, whatever
    /// another crate implements for every type of its shape: dropshot's
    /// request handler, whose one out-of-line method on a real target
    /// is hyper's blanket `HttpService::call`, binds where a dropshot
    /// declaration survives beside it, and declines naming hyper's file
    /// where none does. Held to every declaration, the pair declines.
    #[test]
    fn test_a_blanket_impl_leaves_the_types_own_origin() {
        let dropshot = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/dropshot-0.17.1/src/server.rs";
        let hyper = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-1.10.1/src/service/http.rs";
        let both = BTreeSet::from([source(dropshot, None), source(hyper, None)]);
        let origin = method_origin(&both, &DROPSHOT_SERVER_V0_17_0).unwrap();
        assert_eq!(origin.package, "dropshot");
        assert_eq!(origin.version, "0.17.1");
        assert!(origin.source.ends_with("dropshot-0.17.1/src/server.rs"));
        let (kind, why) = method_origin(
            &BTreeSet::from([source(hyper, None)]),
            &DROPSHOT_SERVER_V0_17_0,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
        assert!(
            why.contains("hyper-1.10.1/src/service/http.rs, which is not the dropshot crate"),
            "{why}"
        );
        assert!(delegation_origin(&both, &DROPSHOT_SERVER_V0_17_0, "method").is_err());
    }

    /// A second address binds only where it lands on the first's type:
    /// another type, or no address at all, binds nothing.
    #[test]
    fn test_a_second_address_lands_on_the_firsts_type() {
        let at = |target| {
            Some(TypedPath {
                steps: Vec::new(),
                target: BundleTypeId(target),
            })
        };
        assert_eq!(landing_on(at(4), BundleTypeId(4)), at(4));
        assert_eq!(landing_on(at(5), BundleTypeId(4)), None);
        assert_eq!(landing_on(None, BundleTypeId(4)), None);
    }

    const REGISTRY: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs";

    /// The origin is what every poll declaration agrees on: a registry
    /// path naming tracing at a reviewed version, with any checksum a
    /// reviewed one. Each departure declines and says which.
    #[test]
    fn test_instrumented_origin_reads_the_registry_path() {
        let reviewed = crate::detect::semantics::TRACING_INSTRUMENTED_V0_1_40.checksums[0].1;
        let origin = delegation_origin(
            &BTreeSet::from([source(REGISTRY, None)]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        assert_eq!(
            origin,
            DelegationOrigin {
                package: "tracing",
                version: "0.1.40".into(),
                family: "tracing-instrumented-0.1.40",
                source:
                    "registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs"
                        .into(),
                files: Vec::new(),
            }
        );
        // A type declared under one release names that release, with
        // nothing to break a tie against: on a target linking two
        // releases whose layouts differ, each release's type has its
        // own poll declaration, and each origin is exact.
        let own = delegation_origin(
            &BTreeSet::from([source(
                "/home/u/.cargo/registry/src/idx/tracing-0.1.41/src/instrument.rs",
                None,
            )]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        assert_eq!(own.version, "0.1.41");
        assert!(own.source.ends_with("tracing-0.1.41/src/instrument.rs"));
        // A checksum the table carried is recorded when reviewed.
        let origin = delegation_origin(
            &BTreeSet::from([source(REGISTRY, Some(reviewed))]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        assert_eq!(origin.files.len(), 1);
        assert_eq!(origin.files[0].1, reviewed);
        // Two declarations on the same path agree.
        delegation_origin(
            &BTreeSet::from([source(REGISTRY, None), source(REGISTRY, Some(reviewed))]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        let declined = |sources: &[PollSource]| {
            let (kind, detail) = delegation_origin(
                &sources.iter().cloned().collect(),
                &TRACING_INSTRUMENTED_V0_1_40,
                "poll",
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            detail
        };
        assert!(declined(&[]).contains("no poll declaration"));
        assert!(
            declined(&[source(
                "/build/vendor/tracing-0.1.40/src/instrument.rs",
                None
            )])
            .contains("not a cargo registry path")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/git/checkouts/tracing-1a2b3c4d5e6f7a8b/0123abc/tracing/src/instrument.rs",
                None
            )])
            .contains("not a cargo registry path")
        );
        assert!(
            declined(&[source("/home/u/tracing/src/instrument.rs", None)])
                .contains("not a cargo registry path")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/tracing-core-0.1.40/src/instrument.rs",
                None
            )])
            .contains("not the tracing crate")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/tracing-0.1.39/src/instrument.rs",
                None
            )])
            .contains("0.1.39 is below the reviewed range 0.1.40-0.1.44")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/tracing-0.1.45/src/instrument.rs",
                None
            )])
            .contains("0.1.45 is above the reviewed range 0.1.40-0.1.44")
        );
        // Two releases declaring the type, both reviewed, agree on the
        // newest: a target linking both has one type for their one
        // layout. A release outside the range declines the pair.
        let both = delegation_origin(
            &BTreeSet::from([
                source(REGISTRY, None),
                source(
                    "/home/u/.cargo/registry/src/idx/tracing-0.1.41/src/instrument.rs",
                    None,
                ),
            ]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        assert_eq!(both.version, "0.1.41");
        assert!(both.source.ends_with("tracing-0.1.41/src/instrument.rs"));
        assert!(
            declined(&[
                source(REGISTRY, None),
                source(
                    "/home/u/.cargo/registry/src/idx/tracing-0.1.45/src/instrument.rs",
                    None
                ),
            ])
            .contains("0.1.45 is outside the reviewed range 0.1.40-0.1.44")
        );
        let mismatch = declined(&[source(REGISTRY, Some([0xab; 16]))]);
        assert!(
            mismatch.contains(&format!(
                "has checksum {}, not a reviewed revision of tracing-instrumented-0.1.40",
                "ab".repeat(16)
            )),
            "{mismatch}"
        );
    }

    /// Which screen a type is offered to is decided by where it is
    /// defined, and the name that routes it is the exact one each
    /// crate's own type has. A type under a name no rule claims is
    /// offered to none, and a screen that refuses leaves no seed.
    #[test]
    fn test_library_seeds_route_by_the_definition_path() {
        use crate::raw_types::{NsId, RawMember, RawStruct, RawType};
        use gimli::UnitSectionOffset;

        let mut reader = crate::DwReader::default();
        let ns = |reader: &mut crate::DwReader<'static>, path: &'static str| -> NsId {
            let mut at = None;
            for segment in path.split("::") {
                let name = reader.strings.intern(segment);
                at = Some(reader.namespaces.insert(at, name));
            }
            at.expect("a namespace path has segments")
        };
        let sleep_mod = ns(&mut reader, "tokio::time::sleep");
        let rt = ns(&mut reader, "hyper_util::rt::tokio");
        let into_mod = ns(&mut reader, "futures_util::future::try_future::into_future");
        let coop_mod = ns(&mut reader, "tokio::task::coop");
        let id = |offset: usize| TypeId(UnitSectionOffset(offset));
        let (sleep, tokio_sleep, into, fut, coop) = (id(1), id(2), id(3), id(4), id(5));
        let strukt = |reader: &mut crate::DwReader<'static>,
                      at: TypeId,
                      namespace: NsId,
                      name: &'static str,
                      member: Option<(&'static str, TypeId)>,
                      param: Option<(&'static str, TypeId)>| {
            let name = Some(reader.strings.intern(name));
            let members = member
                .map(|(name, type_id)| RawMember {
                    name: Some(reader.strings.intern(name)),
                    offset: 0,
                    type_id,
                    source_loc: None,
                })
                .into_iter()
                .collect();
            let template_params = param
                .map(|(name, type_id)| crate::raw_types::RawGenericParameter {
                    name: Some(reader.strings.intern(name)),
                    type_id,
                })
                .into_iter()
                .collect();
            reader.types.insert(
                at,
                RawType::Struct(RawStruct {
                    name,
                    namespace: Some(namespace),
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        };
        strukt(&mut reader, sleep, sleep_mod, "Sleep", None, None);
        strukt(&mut reader, fut, sleep_mod, "Fut", None, None);
        strukt(
            &mut reader,
            tokio_sleep,
            rt,
            "TokioSleep",
            Some(("inner", sleep)),
            None,
        );
        strukt(
            &mut reader,
            into,
            into_mod,
            "IntoFuture<tokio::time::sleep::Fut>",
            Some(("future", fut)),
            Some(("Fut", fut)),
        );
        strukt(
            &mut reader,
            coop,
            coop_mod,
            "Coop<tokio::time::sleep::Fut>",
            Some(("fut", fut)),
            Some(("F", fut)),
        );
        // The stream routes: `Next<St>` over a `&mut St`, and a
        // `WatchStream` whose `inner` is tokio-util's box by that
        // type's own declaration.
        let next_mod = ns(&mut reader, "futures_util::stream::stream::next");
        let watch_mod = ns(&mut reader, "tokio_stream::wrappers::watch");
        let reusable_mod = ns(&mut reader, "tokio_util::sync::reusable_box");
        let (st, ref_st, next, reusable, watch) = (id(6), id(7), id(8), id(9), id(10));
        strukt(&mut reader, st, sleep_mod, "St", None, None);
        reader.types.insert(
            ref_st,
            RawType::Pointer(crate::raw_types::RawPointer {
                name: Some(reader.strings.intern("&mut tokio::time::sleep::St")),
                target_type_id: st,
            }),
        );
        strukt(
            &mut reader,
            next,
            next_mod,
            "Next<tokio::time::sleep::St>",
            Some(("stream", ref_st)),
            Some(("St", st)),
        );
        strukt(
            &mut reader,
            reusable,
            reusable_mod,
            "ReusableBoxFuture<()>",
            Some(("boxed", fut)),
            None,
        );
        strukt(
            &mut reader,
            watch,
            watch_mod,
            "WatchStream<u32>",
            Some(("inner", reusable)),
            Some(("T", fut)),
        );
        // The tick's `PollFn`: the closure declared under tokio's
        // `tick`, its one capture referencing the `Interval`, and the
        // interval's `delay` a pinned box over tokio's `Sleep`.
        let tick_mod = ns(
            &mut reader,
            "tokio::time::interval::{impl#2}::tick::{async_fn#0}",
        );
        let interval_mod = ns(&mut reader, "tokio::time::interval");
        let pin_mod = ns(&mut reader, "core::pin");
        let poll_fn_mod = ns(&mut reader, "core::future::poll_fn");
        let (sleep_box, pin, interval, interval_ref, env, tick, select_env, select) = (
            id(20),
            id(21),
            id(22),
            id(23),
            id(24),
            id(25),
            id(26),
            id(27),
        );
        reader.types.insert(
            sleep_box,
            RawType::Pointer(crate::raw_types::RawPointer {
                name: Some(
                    reader.strings.intern(
                        "alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>",
                    ),
                ),
                target_type_id: sleep,
            }),
        );
        strukt(
            &mut reader,
            pin,
            pin_mod,
            "Pin<alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>>",
            Some(("pointer", sleep_box)),
            Some(("Ptr", sleep_box)),
        );
        strukt(
            &mut reader,
            interval,
            interval_mod,
            "Interval",
            Some(("delay", pin)),
            None,
        );
        reader.types.insert(
            interval_ref,
            RawType::Pointer(crate::raw_types::RawPointer {
                name: Some(
                    reader
                        .strings
                        .intern("&mut tokio::time::interval::Interval"),
                ),
                target_type_id: interval,
            }),
        );
        strukt(
            &mut reader,
            env,
            tick_mod,
            "{closure_env#0}",
            Some(("_ref__self", interval_ref)),
            None,
        );
        strukt(
            &mut reader,
            tick,
            poll_fn_mod,
            "PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>",
            Some(("f", env)),
            Some(("F", env)),
        );
        // A `PollFn` over some other closure — a user's, with a capture
        // of another name — reaches the tick screen and is refused.
        strukt(
            &mut reader,
            select_env,
            sleep_mod,
            "{closure_env#0}",
            Some(("_ref__disabled", interval_ref)),
            None,
        );
        strukt(
            &mut reader,
            select,
            poll_fn_mod,
            "PollFn<tokio::time::sleep::{closure_env#0}>",
            Some(("f", select_env)),
            Some(("F", select_env)),
        );
        let bundle_id = |raw: TypeId| Some(BundleTypeId(raw.0.0 as u32));
        let seed =
            |raw, name: &str| library_seed(&reader, raw, name, bundle_id, |_| None, &|_| None);
        let tick_name = "core::future::poll_fn::PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>";
        assert!(matches!(
            seed(tick, tick_name),
            Some(LibrarySeed::IntervalTick { closure, interval_ref, interval: i, delay, boxed, source: None })
                if closure == "f" && interval_ref == "_ref__self" && i == bundle_id(interval).unwrap()
                    && delay == "delay" && boxed == bundle_id(pin).unwrap()
        ));
        // The closure environment's declaration site rides along, read
        // off the environment the screen found.
        let declared = source("/home/u/tokio/src/time/interval.rs", None);
        let with_source = library_seed(&reader, tick, tick_name, bundle_id, |_| None, &|raw| {
            (raw == env).then(|| declared.clone())
        });
        assert!(matches!(
            with_source,
            Some(LibrarySeed::IntervalTick { source: Some(s), .. }) if s == declared
        ));
        assert!(
            seed(
                select,
                "core::future::poll_fn::PollFn<tokio::time::sleep::{closure_env#0}>"
            )
            .is_none()
        );
        assert!(matches!(
            seed(next, "futures_util::stream::stream::next::Next<tokio::time::sleep::St>"),
            Some(LibrarySeed::Next(member, target)) if member == "stream" && target == bundle_id(st).unwrap()
        ));
        assert!(matches!(
            seed(watch, "tokio_stream::wrappers::watch::WatchStream<u32>"),
            Some(LibrarySeed::WatchStream(member, inner)) if member == "inner" && inner == bundle_id(reusable).unwrap()
        ));
        // The box's screen needs a pinned wide pointer, which this
        // table does not carry: the name reaches the screen, the
        // screen refuses.
        assert!(
            seed(
                reusable,
                "tokio_util::sync::reusable_box::ReusableBoxFuture<()>"
            )
            .is_none()
        );
        assert!(matches!(
            seed(tokio_sleep, "hyper_util::rt::tokio::TokioSleep"),
            Some(LibrarySeed::TokioSleep(member, _)) if member == "inner"
        ));
        assert!(matches!(
            seed(coop, "tokio::task::coop::Coop<tokio::time::sleep::Fut>"),
            Some(LibrarySeed::Coop(member, _)) if member == "fut"
        ));
        assert!(matches!(
            seed(
                into,
                "futures_util::future::try_future::into_future::IntoFuture<tokio::time::sleep::Fut>"
            ),
            Some(LibrarySeed::IntoFuture(member, _)) if member == "future"
        ));
        // The name is the route: the same layout under any other name
        // reaches no screen, and a name whose screen refuses seeds
        // nothing either.
        for (raw, name) in [
            (tokio_sleep, "hyper_util::rt::tokio::TokioSleeper"),
            (tokio_sleep, "TokioSleep"),
            (tokio_sleep, "app::TokioSleep"),
            (sleep, "hyper_util::rt::tokio::TokioSleep"),
            (
                sleep,
                "futures_util::future::try_future::into_future::IntoFuture<x>",
            ),
            (coop, "tokio::task::Coop<tokio::time::sleep::Fut>"),
            (fut, "tokio::task::coop::Coop<tokio::time::sleep::Fut>"),
            (
                tick,
                "app::PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>",
            ),
            (
                env,
                "core::future::poll_fn::PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>",
            ),
            (
                next,
                "tokio_stream::StreamExt::next::Next<tokio::time::sleep::St>",
            ),
            (watch, "tokio_stream::wrappers::WatchStream<u32>"),
            (
                st,
                "futures_util::stream::stream::next::Next<tokio::time::sleep::St>",
            ),
        ] {
            assert!(seed(raw, name).is_none(), "{name}");
        }
    }

    /// Each reviewed third-party convention reads its origin off the
    /// registry path its own `poll` was declared on, and every
    /// departure declines with the reason: a tree that is not the
    /// registry's, another crate's, a version outside the range, two
    /// declarations disagreeing, or a checksum that is not a reviewed
    /// revision.
    #[test]
    fn test_every_delegation_origin_is_read_off_its_registry_path() {
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        for (convention, version, file, other) in [
            (
                &FUTURES_UTIL_ADAPTERS_V0_3_30,
                "0.3.33",
                "src/future/future/map.rs",
                "futures-core",
            ),
            (
                &HYPER_UTIL_TOKIO_SLEEP_V0_1_10,
                "0.1.20",
                "src/rt/tokio.rs",
                "hyper",
            ),
            (
                &TOKIO_STREAM_WATCH_V0_1_14,
                "0.1.19",
                "src/wrappers/watch.rs",
                "tokio",
            ),
            (
                &TOKIO_UTIL_REUSABLE_BOX_V0_7_11,
                "0.7.19",
                "src/sync/reusable_box.rs",
                "tokio",
            ),
            (
                &TOKIO_INTERVAL_TICK_V1_47,
                "1.52.4",
                "src/time/interval.rs",
                "tokio-util",
            ),
            (
                &TOKIO_RUSTLS_STREAM_V0_26_0,
                "0.26.4",
                "src/client.rs",
                "rustls",
            ),
        ] {
            let package = convention.package;
            let at = |version: &str| format!("{ROOT}/{package}-{version}/{file}");
            let origin = delegation_origin(
                &BTreeSet::from([source(&at(version), None)]),
                convention,
                "poll",
            )
            .unwrap();
            assert_eq!(
                origin,
                DelegationOrigin {
                    package,
                    version: version.to_owned(),
                    family: convention.family,
                    source: at(version)
                        .strip_prefix("/home/u/.cargo/")
                        .unwrap()
                        .to_owned(),
                    files: Vec::new(),
                }
            );
            let reviewed = convention.checksums[0].1;
            let origin = delegation_origin(
                &BTreeSet::from([source(&at(version), Some(reviewed))]),
                convention,
                "poll",
            )
            .unwrap();
            assert_eq!(origin.files.len(), 1);
            let declined = |sources: &[PollSource]| {
                let (kind, detail) =
                    delegation_origin(&sources.iter().cloned().collect(), convention, "poll")
                        .unwrap_err();
                assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
                detail
            };
            assert!(declined(&[]).contains("no poll declaration"));
            for path in [
                format!("/build/vendor/{package}-{version}/{file}"),
                format!("/home/u/.cargo/git/checkouts/{package}-1a2b3c4d5e6f7a8b/0123abc/{file}"),
                format!("/home/u/{package}/{file}"),
            ] {
                assert!(
                    declined(&[source(&path, None)]).contains("not a cargo registry path"),
                    "{path}"
                );
            }
            assert!(
                declined(&[source(&format!("{ROOT}/{other}-{version}/{file}"), None)])
                    .contains(&format!("not the {package} crate"))
            );
            // The release just below the floor: the previous patch, or
            // the previous minor where the floor is a `.0`.
            let (a, b, c) = convention.releases.floor();
            let below = match c {
                0 => format!("{a}.{}.0", b - 1),
                c => format!("{a}.{b}.{}", c - 1),
            };
            let (x, y, z) = convention.releases.ceiling();
            let above = format!("{x}.{y}.{}", z + 1);
            assert!(
                declined(&[source(&at(&below), None)])
                    .contains(&format!("{package} {below} is below the reviewed range"))
            );
            assert!(
                declined(&[source(&at(&above), None)])
                    .contains(&format!("{package} {above} is above the reviewed range"))
            );
            assert!(
                declined(&[
                    source(&at(version), None),
                    source(&format!("{ROOT}/{package}-{version}/src/other.rs"), None),
                ])
                .contains("declared in both")
            );
            assert!(
                declined(&[source(&at(version), Some([0xab; 16]))])
                    .contains("not a reviewed revision of")
            );
        }
    }

    /// A type whose impls sit in several files of one release is one
    /// declaration where the review read every file, named by the
    /// first; a file the review did not read declines. Two releases
    /// still bind together where both are inside the range, as before.
    #[test]
    fn test_one_release_may_declare_a_type_in_its_reviewed_files() {
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let convention = &HYPER_UTIL_IO_V0_1_10;
        let at = |version: &str, file: &str| {
            source(&format!("{ROOT}/hyper-util-{version}/{file}"), None)
        };
        let origin = |sources: &[PollSource]| {
            delegation_origin(&sources.iter().cloned().collect(), convention, "method")
        };
        let both = origin(&[
            at("0.1.20", "src/rt/tokio.rs"),
            at("0.1.20", "src/client/legacy/connect/http.rs"),
        ])
        .unwrap();
        assert_eq!(both.version, "0.1.20");
        assert!(
            both.source
                .ends_with("hyper-util-0.1.20/src/client/legacy/connect/http.rs"),
            "{}",
            both.source
        );
        let (kind, detail) = origin(&[
            at("0.1.20", "src/rt/tokio.rs"),
            at("0.1.20", "src/other.rs"),
        ])
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
        assert!(detail.contains("declared in both"), "{detail}");
        let two = origin(&[
            at("0.1.19", "src/rt/tokio.rs"),
            at("0.1.20", "src/rt/tokio.rs"),
            at("0.1.20", "src/common/rewind.rs"),
        ])
        .unwrap();
        assert_eq!(two.version, "0.1.20");
        assert!(
            origin(&[
                at("0.1.20", "src/rt/tokio.rs"),
                at("0.1.21", "src/rt/tokio.rs")
            ])
            .unwrap_err()
            .1
            .contains("outside the reviewed range")
        );
    }

    /// A git origin is read off a checkout path of the convention's
    /// repository, in its implementing file, at a revision the review
    /// lists — by any abbreviation cargo writes — and corroborated by
    /// that revision's checksum where the line table carries one. Every
    /// departure declines with the reason.
    #[test]
    fn test_a_git_origin_names_a_reviewed_revision_of_its_file() {
        const CHECKOUT: &str = "/home/u/.cargo/git/checkouts/sprockets-882d17aeeb0cb343";
        let convention = &SPROCKETS_TLS_STREAM_D2B68E4;
        let at = |revision: &str| format!("{CHECKOUT}/{revision}/tls/src/lib.rs");
        let origin = |sources: &[PollSource]| {
            git_delegation_origin(&sources.iter().cloned().collect(), convention, "method")
        };
        let (_, reviewed) = convention.revisions[2];
        assert_eq!(
            origin(&[source(&at("a233079"), Some(reviewed))]).unwrap(),
            GitDelegationOrigin {
                package: "sprockets-tls",
                repository: "sprockets".to_owned(),
                revision: "a233079".to_owned(),
                family: convention.family,
                source: at("a233079")
                    .strip_prefix("/home/u/.cargo/")
                    .unwrap()
                    .to_owned(),
                files: vec![(
                    at("a233079")
                        .strip_prefix("/home/u/.cargo/")
                        .unwrap()
                        .to_owned(),
                    reviewed
                )],
            }
        );
        // Every reviewed revision, by a longer abbreviation too.
        for (revision, _) in convention.revisions {
            assert!(origin(&[source(&at(&revision[..7]), None)]).is_ok());
            assert!(origin(&[source(&at(&revision[..12]), None)]).is_ok());
        }
        let declined = |sources: &[PollSource]| {
            let (kind, detail) = origin(sources).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            detail
        };
        assert!(declined(&[]).contains("no method declaration"));
        assert!(
            declined(&[source(&at("0123abc"), None)])
                .contains("sprockets revision 0123abc is not a reviewed revision")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/sprockets-tls-0.1.0/src/lib.rs",
                None
            )])
            .contains("not a cargo git checkout path")
        );
        assert!(
            declined(&[source(
                &format!("{CHECKOUT}/a233079/tls/src/client.rs"),
                None
            )])
            .contains("which is not tls/src/lib.rs in the sprockets repository")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/git/checkouts/sprocket-882d17aeeb0cb343/a233079/tls/src/lib.rs",
                None
            )])
            .contains("in the sprockets repository")
        );
        assert!(
            declined(&[source(&at("a233079"), None), source(&at("68a4b3b"), None)])
                .contains("declared in both")
        );
        // Two declarations in the one file, one of them checksummed,
        // are one origin, and the checksum still holds it.
        let twice = origin(&[
            source(&at("a233079"), None),
            source(&at("a233079"), Some(reviewed)),
        ])
        .unwrap();
        assert_eq!(twice.revision, "a233079");
        assert_eq!(twice.files.len(), 1);
        assert!(
            declined(&[source(&at("a233079"), Some(convention.revisions[0].1))])
                .contains("not revision a233079's")
        );
    }

    /// A third-party stream's origin is read off the declarations in
    /// its own crate or checkout: a foreign trait implemented on it —
    /// reqwest's TLS-info trait on tokio-rustls's client stream — is
    /// passed over where the stream's own declarations are present, and
    /// is the decline's reason where they are not. An origin that holds
    /// goes on to the layout, which the empty table here does not have.
    #[test]
    fn test_a_stream_origin_passes_over_foreign_declarations() {
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let reqwest = source(&format!("{ROOT}/reqwest-0.13.2/src/connect.rs"), None);
        let checkout = "/home/u/.cargo/git/checkouts/sprockets-882d17aeeb0cb343/a233079";
        let strings = StringInterner::new();
        let route = |key: &str, sources: &[&PollSource]| {
            let stream = io_delegation(key).unwrap();
            let sources = sources.iter().copied().cloned().collect();
            delegated_route(
                BundleTypeId(0),
                stream,
                &sources,
                &SemanticSeeds::new(),
                &TypeTable::default(),
                &strings,
            )
            .map(|_| ())
            .unwrap_err()
        };
        for (key, own) in [
            (
                "tokio_rustls::client::TlsStream<u8>",
                source(&format!("{ROOT}/tokio-rustls-0.26.4/src/client.rs"), None),
            ),
            (
                "sprockets_tls::Stream<u8>",
                source(&format!("{checkout}/tls/src/lib.rs"), None),
            ),
        ] {
            let (kind, detail) = route(key, &[&own, &reqwest]);
            assert!(detail.contains("no unique member"), "{key}: {detail}");
            assert_ne!(
                kind,
                SemanticIssueKind::UnsupportedOrigin,
                "{key}: {detail}"
            );
            let (kind, detail) = route(key, &[&reqwest]);
            assert_eq!(
                kind,
                SemanticIssueKind::UnsupportedOrigin,
                "{key}: {detail}"
            );
            assert!(detail.contains("reqwest-0.13.2"), "{key}: {detail}");
        }
    }

    /// A generic's key names each instantiation whole, never a
    /// variant's payload type named below one.
    #[test]
    fn test_a_generic_key_names_only_whole_instantiations() {
        let key = "tokio_rustls::TlsStream<";
        let tcp = "tokio_rustls::TlsStream<tokio::net::tcp::stream::TcpStream>";
        assert!(names_type(key, tcp));
        assert!(names_type(key, "tokio_rustls::TlsStream<a::B<c::D>>"));
        assert!(!names_type(key, &format!("{tcp}::Client")));
        assert!(!names_type(key, "tokio_rustls::TlsStream<"));
        assert!(!names_type(key, "tokio_rustls::TlsStreamX<u8>"));
        assert!(names_type("a::B", "a::B"));
        assert!(!names_type("a::B", "a::B<u8>"));
    }

    /// The reviewed wrappers plan one exclusive forward each — through
    /// the member their implementation polls — and `Map` plans a case
    /// per state: its incomplete one delegates into the future it holds,
    /// its complete one has already returned. A member holding another
    /// type than the screen declared plans nothing.
    #[test]
    fn test_the_reviewed_wrappers_plan_one_forward_each() {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = Vec::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 8,
                members: Vec::new(),
            },
        );
        let sleep = add(
            "tokio::time::sleep::Sleep",
            TypeDef::Struct {
                name: strings.intern("tokio::time::sleep::Sleep"),
                size: 8,
                members: Vec::new(),
            },
        );
        let one = |strings: &mut StringInterner, name: &str, member: &str, ty| TypeDef::Struct {
            name: strings.intern(name),
            size: 8,
            members: vec![MemberDef {
                name: strings.intern(member),
                ty,
                offset: 0,
            }],
        };
        let tokio_sleep = {
            let def = one(
                &mut strings,
                "hyper_util::rt::tokio::TokioSleep",
                "inner",
                sleep,
            );
            add("hyper_util::rt::tokio::TokioSleep", def)
        };
        let coop = {
            let def = one(
                &mut strings,
                "tokio::task::coop::Coop<app::Fut>",
                "fut",
                fut,
            );
            add("tokio::task::coop::Coop<app::Fut>", def)
        };
        let into = {
            let def = one(
                &mut strings,
                "futures_util::future::try_future::into_future::IntoFuture<app::Fut>",
                "future",
                fut,
            );
            add(
                "futures_util::future::try_future::into_future::IntoFuture<app::Fut>",
                def,
            )
        };
        let incomplete = add(
            "map::Map::Incomplete",
            TypeDef::Struct {
                name: strings.intern("map::Map::Incomplete"),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("future"),
                    ty: fut,
                    offset: 0,
                }],
            },
        );
        let complete = add(
            "map::Map::Complete",
            TypeDef::Struct {
                name: strings.intern("map::Map::Complete"),
                size: 0,
                members: Vec::new(),
            },
        );
        let variant = |strings: &mut StringInterner, name: &str, ty| VariantDef {
            name: strings.intern(name),
            discr_values: None,
            payload: MemberDef {
                name: strings.intern(name),
                ty,
                offset: 0,
            },
            decl: None,
            await_site: None,
        };
        let map = {
            let variants = vec![
                variant(&mut strings, "Incomplete", incomplete),
                variant(&mut strings, "Complete", complete),
            ];
            let def = TypeDef::Enum {
                name: strings.intern("futures_util::future::future::map::Map<app::Fut, app::Fn>"),
                size: 16,
                shape: VariantShape {
                    discr: None,
                    variants,
                },
            };
            add(
                "futures_util::future::future::map::Map<app::Fut, app::Fn>",
                def,
            )
        };
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let registry = |package: &str, version: &str, file: &str| Seed {
            poll_sources: BTreeSet::from([source(
                &format!(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     {package}-{version}/{file}"
                ),
                None,
            )]),
            ..Seed::default()
        };
        let futures_util = registry("futures-util", "0.3.33", "src/lib.rs");
        let hyper_util = registry("hyper-util", "0.1.20", "src/rt/tokio.rs");
        // No declaration at all: what a `poll` the optimizer folded
        // into another instantiation's leaves behind.
        let unproven = Seed::default();
        let render = |strings: &StringInterner, path: &TypedPath| {
            path.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => strings.get(*n).unwrap().to_owned(),
                    Step::Variant(n) => format!("::{}", strings.get(*n).unwrap()),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        // hyper-util's sleep is proved by its poll's origin; a
        // sole-member forwarder by its layout alone, under the crate's
        // layout origin, with nothing declared anywhere.
        for (ty, seed_layout, seed, expected, target, rule) in [
            (
                tokio_sleep,
                LibrarySeed::TokioSleep("inner".into(), sleep),
                &hyper_util,
                "inner",
                sleep,
                None,
            ),
            (
                into,
                LibrarySeed::IntoFuture("future".into(), fut),
                &unproven,
                "future",
                fut,
                Some(RuleKey::Library(SemanticRuleKind::FuturesUtilIntoFuture)),
            ),
            (
                coop,
                LibrarySeed::Coop("fut".into(), fut),
                &unproven,
                "fut",
                fut,
                Some(RuleKey::Library(SemanticRuleKind::TokioCoop)),
            ),
        ] {
            let plan = plan_library(ty, &seed_layout, seed, &types, &mut strings).unwrap();
            match rule {
                Some(rule) => assert_eq!(plan.rule, rule),
                None => assert!(
                    matches!(
                        plan.rule,
                        RuleKey::Delegation {
                            kind: SemanticRuleKind::HyperUtilTokioSleep,
                            ..
                        }
                    ),
                    "{:?}",
                    plan.rule
                ),
            }
            let Delegation::Direct {
                target: t,
                exclusive,
            } = plan.program.as_ref().unwrap()
            else {
                panic!("a wrapper forwards directly");
            };
            assert!(exclusive, "a reviewed forward polls its delegate alone");
            let Target::Value(path) = t else {
                panic!("a wrapper forwards to a value");
            };
            assert_eq!(render(&strings, path), expected);
            assert_eq!(path.target, target);
            assert!(plan.access.is_none(), "a wrapper is not a pointer");
        }
        // The map's two states, and the one member the incomplete one
        // polls.
        let layout = LibrarySeed::Map {
            incomplete: "Incomplete".into(),
            future_member: "future".into(),
            complete: "Complete".into(),
            future: fut,
        };
        let plan = plan_library(map, &layout, &futures_util, &types, &mut strings).unwrap();
        let Delegation::Match { cases, .. } = plan.program.as_ref().unwrap() else {
            panic!("a map matches its state");
        };
        let [
            (incomplete_name, CaseAction::Delegate(target)),
            (_, CaseAction::Returned),
        ] = cases.as_slice()
        else {
            panic!("the incomplete state delegates and the complete one has returned");
        };
        assert_eq!(strings.get(*incomplete_name), Some("Incomplete"));
        let Target::Value(path) = target.as_ref() else {
            panic!("a map delegates to a value");
        };
        assert_eq!(render(&strings, path), "::Incomplete.future");
        assert_eq!(path.target, fut);
        // A member the screen's declared type no longer matches.
        let wrong = LibrarySeed::TokioSleep("inner".into(), fut);
        let (kind, detail) =
            plan_library(tokio_sleep, &wrong, &hyper_util, &types, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(
            detail.contains("another type than the screen declared"),
            "{detail}"
        );
        // And an origin no review covers stops before the layout.
        let vendored = Seed {
            poll_sources: BTreeSet::from([source(
                "/build/vendor/hyper-util-0.1.20/src/rt/tokio.rs",
                None,
            )]),
            ..Seed::default()
        };
        let (kind, _) = plan_library(
            tokio_sleep,
            &LibrarySeed::TokioSleep("inner".into(), sleep),
            &vendored,
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);

        // The stream routes. `Next` forwards through its `&mut` to the
        // stream itself — a dereference on the route — exclusively,
        // and proves the stream nothing; a `WatchStream` is an owned
        // access into its box and no program, under an origin read off
        // the type's own methods rather than a poll it does not have.
        let mut types = types.types;
        let mut add = |_name: &str, def: TypeDef| {
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let st = add(
            "app::St",
            TypeDef::Struct {
                name: strings.intern("app::St"),
                size: 8,
                members: Vec::new(),
            },
        );
        let ref_st = add(
            "&mut app::St",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut app::St")),
                target: st,
            },
        );
        let next = {
            let def = one(
                &mut strings,
                "futures_util::stream::stream::next::Next<app::St>",
                "stream",
                ref_st,
            );
            add("futures_util::stream::stream::next::Next<app::St>", def)
        };
        let by_value = {
            let def = one(
                &mut strings,
                "futures_util::stream::stream::next::Next<app::St>",
                "stream",
                st,
            );
            add("futures_util::stream::stream::next::Next<app::St>", def)
        };
        let watch = {
            let def = one(
                &mut strings,
                "tokio_stream::wrappers::watch::WatchStream<u32>",
                "inner",
                sleep,
            );
            add("tokio_stream::wrappers::watch::WatchStream<u32>", def)
        };
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let plan = plan_library(
            next,
            &LibrarySeed::Next("stream".into(), st),
            &registry("futures-util", "0.3.33", "src/stream/stream/next.rs"),
            &types,
            &mut strings,
        )
        .unwrap();
        let Some(Delegation::Direct { target, exclusive }) = &plan.program else {
            panic!("`Next` forwards directly");
        };
        assert!(exclusive, "`Next` polls its stream alone");
        let Target::Value(path) = target else {
            panic!("`Next` forwards to a value");
        };
        assert_eq!(render(&strings, path), "stream.Deref");
        assert_eq!(path.target, st);
        assert!(plan.access.is_none());
        assert!(!plan.delegate_is_future, "a stream is proved nothing");
        let (kind, detail) = plan_library(
            by_value,
            &LibrarySeed::Next("stream".into(), st),
            &registry("futures-util", "0.3.33", "src/stream/stream/next.rs"),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("not a reference"), "{detail}");
        let typed = |path: &str| Seed {
            type_sources: BTreeSet::from([source(path, None)]),
            ..Seed::default()
        };
        let plan = plan_library(
            watch,
            &LibrarySeed::WatchStream("inner".into(), sleep),
            &typed(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 tokio-stream-0.1.19/src/wrappers/watch.rs",
            ),
            &types,
            &mut strings,
        )
        .unwrap();
        assert!(
            plan.program.is_none(),
            "a storage route polls nothing itself"
        );
        let (rule, kind, target) = plan.access.as_ref().unwrap();
        assert_eq!(*kind, AccessKind::Owned);
        assert_eq!(rule, &plan.rule);
        assert!(
            matches!(rule, RuleKey::Delegation { kind: SemanticRuleKind::TokioStreamWatchStream, origin }
            if origin.package == "tokio-stream" && origin.version == "0.1.19")
        );
        let Target::Value(path) = target else {
            panic!("the stream's access is a value route");
        };
        assert_eq!(render(&strings, path), "inner");
        assert_eq!(path.target, sleep);
        // The stream's poll sources are nobody's evidence: only its
        // own methods' declarations count, and none is a decline of
        // its own kind.
        for (seed, expected) in [
            (
                registry("tokio-stream", "0.1.19", "src/wrappers/watch.rs"),
                "no method declaration",
            ),
            (
                typed("/build/vendor/tokio-stream-0.1.19/src/wrappers/watch.rs"),
                "not a cargo registry path",
            ),
            (
                typed(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     tokio-stream-0.1.13/src/wrappers/watch.rs",
                ),
                "below the reviewed range",
            ),
        ] {
            let (kind, detail) = plan_library(
                watch,
                &LibrarySeed::WatchStream("inner".into(), sleep),
                &seed,
                &types,
                &mut strings,
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{detail}");
        }
    }

    /// A `select!` plan: the origin off the closure's declaration file,
    /// then the two capture routes and one per tuple member, each held
    /// to the final table. A closure declared outside the registry, in
    /// another crate or at an unreviewed version declines before the
    /// layout; a mask that is not an unsigned word, a tuple member
    /// holding another type than the screen saw, or a member missing
    /// from the table decline on the layout.
    #[test]
    fn test_the_select_plan_reads_the_captures_and_the_tuple() {
        let mut strings = StringInterner::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            let _ = name;
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let u8_t = add(
            "u8",
            TypeDef::Base {
                name: strings.intern("u8"),
                size: 1,
                encoding: crate::Encoding::Unsigned,
            },
        );
        let i8_t = add(
            "i8",
            TypeDef::Base {
                name: strings.intern("i8"),
                size: 1,
                encoding: crate::Encoding::Signed,
            },
        );
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 8,
                members: Vec::new(),
            },
        );
        let other = add(
            "app::Other",
            TypeDef::Struct {
                name: strings.intern("app::Other"),
                size: 8,
                members: Vec::new(),
            },
        );
        let member = |strings: &mut StringInterner, name: &str, ty, offset| MemberDef {
            name: strings.intern(name),
            ty,
            offset,
        };
        let first = member(&mut strings, "__0", fut, 0);
        let second = member(&mut strings, "__1", other, 8);
        let tuple = add(
            "(app::Fut, app::Other)",
            TypeDef::Struct {
                name: strings.intern("(app::Fut, app::Other)"),
                size: 16,
                members: vec![first, second],
            },
        );
        let mask_ref = add(
            "&mut u8",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut u8")),
                target: u8_t,
            },
        );
        let signed_ref = add(
            "&mut i8",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut i8")),
                target: i8_t,
            },
        );
        let tuple_ref = add(
            "&mut (app::Fut, app::Other)",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut (app::Fut, app::Other)")),
                target: tuple,
            },
        );
        let disabled = member(&mut strings, "_ref__disabled", mask_ref, 0);
        let futures = member(&mut strings, "_ref__futures", tuple_ref, 8);
        let env = add(
            "app::run::{async_fn#0}::{closure_env#1}",
            TypeDef::Struct {
                name: strings.intern("app::run::{async_fn#0}::{closure_env#1}"),
                size: 16,
                members: vec![disabled, futures.clone()],
            },
        );
        let signed_env = add(
            "app::run::{async_fn#0}::{closure_env#2}",
            TypeDef::Struct {
                name: strings.intern("app::run::{async_fn#0}::{closure_env#2}"),
                size: 16,
                members: vec![
                    member(&mut strings, "_ref__disabled", signed_ref, 0),
                    futures,
                ],
            },
        );
        let f = member(&mut strings, "f", env, 0);
        let poll_fn = add(
            "core::future::poll_fn::PollFn<…#1>",
            TypeDef::Struct {
                name: strings.intern("core::future::poll_fn::PollFn<…#1>"),
                size: 16,
                members: vec![f],
            },
        );
        let signed_poll_fn = add(
            "core::future::poll_fn::PollFn<…#2>",
            TypeDef::Struct {
                name: strings.intern("core::future::poll_fn::PollFn<…#2>"),
                size: 16,
                members: vec![member(&mut strings, "f", signed_env, 0)],
            },
        );
        let types = TypeTable {
            types,
            ..Default::default()
        };
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let seed = |mask_word, branches: Vec<(&str, BundleTypeId)>, path: &str| SelectSeed {
            closure: "f".into(),
            mask: "_ref__disabled".into(),
            mask_word,
            futures: "_ref__futures".into(),
            tuple,
            arms: vec![ArmSite::Unbound; branches.len()],
            branches: branches
                .into_iter()
                .map(|(m, t)| (m.to_owned(), t))
                .collect(),
            source: (!path.is_empty()).then(|| source(path, None)),
        };
        let reviewed = format!("{ROOT}/tokio-1.52.4/src/macros/select.rs");
        let render = |strings: &StringInterner, path: &TypedPath| {
            path.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => strings.get(*n).unwrap().to_owned(),
                    Step::Deref => "*".to_owned(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        let (plan, declined) = plan_select(
            poll_fn,
            &seed(u8_t, vec![("__0", fut), ("__1", other)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap();
        assert!(declined.is_empty(), "{declined:?}");
        assert_eq!(plan.arms, [None, None]);
        let RuleKey::Delegation { kind, origin } = &plan.rule else {
            panic!("{:?}", plan.rule);
        };
        assert_eq!(*kind, SemanticRuleKind::TokioSelect);
        assert_eq!(origin.package, "tokio");
        assert_eq!(origin.version, "1.52.4");
        assert_eq!(origin.family, TOKIO_SELECT_V1_47.family);
        assert_eq!(render(&strings, &plan.mask), "f._ref__disabled.*");
        assert_eq!(plan.mask.target, u8_t);
        assert_eq!(render(&strings, &plan.futures), "f._ref__futures.*");
        assert_eq!(plan.futures.target, tuple);
        assert_eq!(
            plan.branches
                .iter()
                .map(|b| (render(&strings, b), b.target))
                .collect::<Vec<_>>(),
            [("__0".to_owned(), fut), ("__1".to_owned(), other)]
        );
        // The origin: no declaration site, a vendored tree, another
        // crate's registry path, and a version past the review.
        for (path, expected) in [
            ("", "no declaration site"),
            (
                "/build/vendor/tokio-1.52.4/src/macros/select.rs",
                "not a cargo registry path",
            ),
            (
                &format!("{ROOT}/tokio-util-0.7.12/src/macros/select.rs"),
                "not the tokio crate",
            ),
            (
                &format!("{ROOT}/tokio-1.54.0/src/macros/select.rs"),
                "above the reviewed range",
            ),
            (
                &format!("{ROOT}/tokio-1.46.1/src/macros/select.rs"),
                "below the reviewed range",
            ),
        ] {
            let (kind, detail) = plan_select(
                poll_fn,
                &seed(u8_t, vec![("__0", fut)], path),
                &types,
                &mut strings,
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{path}");
            assert!(detail.contains(expected), "{path}: {detail}");
        }
        // The layout: a signed mask, a member holding another type, a
        // member the table does not have.
        let (kind, detail) = plan_select(
            signed_poll_fn,
            &seed(i8_t, vec![("__0", fut)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("not an unsigned word"), "{detail}");
        let (kind, detail) = plan_select(
            poll_fn,
            &seed(u8_t, vec![("__0", other)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("another type than the screen"), "{detail}");
        let (kind, detail) = plan_select(
            poll_fn,
            &seed(u8_t, vec![("__2", fut)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::AmbiguousLayout);
        assert!(detail.contains("no unique member"), "{detail}");
        // The arms: a written one is interned with its path cut like
        // every other, a declined one is handed back as an issue with
        // no arm, and the join's list has to pair with the branches.
        let mut with_arms = seed(u8_t, vec![("__0", fut), ("__1", other)], &reviewed);
        with_arms.arms = vec![
            ArmSite::Written(OwnedLoc {
                file: Some("src/pool.rs".to_owned()),
                dir: Some(format!("{ROOT}/qorb-0.4.1")),
                comp_dir: None,
                line: Some(286),
            }),
            ArmSite::Declined((
                SemanticIssueKind::AmbiguousLayout,
                "branch 1's future type is shared".to_owned(),
            )),
        ];
        let (plan, declined) = plan_select(poll_fn, &with_arms, &types, &mut strings).unwrap();
        let [Some(written), None] = plan.arms.as_slice() else {
            panic!("{:?}", plan.arms);
        };
        assert_eq!(strings.get(written.file), Some("qorb-0.4.1/src/pool.rs"));
        assert_eq!(written.line, 286);
        assert_eq!(
            declined,
            [(
                SemanticIssueKind::AmbiguousLayout,
                "branch 1's future type is shared".to_owned()
            )]
        );
        with_arms.arms.pop();
        let (kind, detail) = plan_select(poll_fn, &with_arms, &types, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(
            detail.contains("1 arms were joined for 2 branches"),
            "{detail}"
        );
    }

    /// The join pairs a branch with the arm of its type and nothing
    /// else: a type on one side twice settles nothing for anything of
    /// that type, an arm with no arm of its type is missing, an arm
    /// whose pattern binds nothing is unbound, and bindings that do
    /// not agree settle nothing either.
    #[test]
    fn test_select_arms_join_by_type_alone() {
        use gimli::UnitSectionOffset;
        let id = |offset: usize| TypeId(UnitSectionOffset(offset));
        let loc = |line: u64| OwnedLoc {
            file: Some("src/pool.rs".to_owned()),
            dir: None,
            comp_dir: None,
            line: Some(line),
        };
        let branches = |types: &[usize]| -> Vec<(String, TypeId)> {
            types
                .iter()
                .enumerate()
                .map(|(i, &t)| (format!("__{i}"), id(t)))
                .collect()
        };
        let kinds = |sites: &[ArmSite]| -> Vec<String> {
            sites
                .iter()
                .map(|site| match site {
                    ArmSite::Written(loc) => format!("written {}", loc.line.unwrap()),
                    ArmSite::Unbound => "unbound".to_owned(),
                    ArmSite::Declined((kind, detail)) => format!("declined {kind:?}: {detail}"),
                })
                .collect()
        };
        // Five branches of five types: bound, unbound, bound twice on
        // one line, absent from the closure, bound on two lines.
        let arms = vec![
            (id(1), vec![loc(286)]),
            (id(2), vec![]),
            (id(3), vec![loc(332), loc(332)]),
            (id(5), vec![loc(10), loc(11)]),
        ];
        assert_eq!(
            kinds(&join_arms(&branches(&[1, 2, 3, 4, 5]), &arms)),
            [
                "written 286",
                "unbound",
                "written 332",
                "declined MissingLayout: no arm of branch 3's future type in the closure",
                "declined AmbiguousLayout: branch 4's bindings disagree: line 10 and line 11",
            ]
        );
        // A binding without both coordinates is no site: not a
        // disagreement beside one that has them, not a site on its own.
        let bare = OwnedLoc {
            file: None,
            dir: None,
            comp_dir: None,
            line: None,
        };
        let file_only = OwnedLoc {
            line: None,
            ..loc(0)
        };
        let line_only = OwnedLoc {
            file: None,
            ..loc(300)
        };
        for half in [bare, file_only, line_only] {
            assert_eq!(
                kinds(&join_arms(
                    &branches(&[1]),
                    &[(id(1), vec![half.clone(), loc(286)])]
                )),
                ["written 286"],
                "{half:?}"
            );
            assert_eq!(
                kinds(&join_arms(&branches(&[1]), &[(id(1), vec![half.clone()])])),
                ["unbound"],
                "{half:?}"
            );
        }
        // The type shared on either side: two members and two arms, two
        // members and one arm, one member and two arms.
        assert_eq!(
            kinds(&join_arms(
                &branches(&[1, 1]),
                &[(id(1), vec![loc(33)]), (id(1), vec![loc(34)])]
            )),
            [
                "declined AmbiguousLayout: branch 0's future type is shared: 2 tuple members, 2 arms",
                "declined AmbiguousLayout: branch 1's future type is shared: 2 tuple members, 2 arms",
            ]
        );
        assert_eq!(
            kinds(&join_arms(&branches(&[1, 1]), &[(id(1), vec![loc(33)])])),
            [
                "declined AmbiguousLayout: branch 0's future type is shared: 2 tuple members, 1 arms",
                "declined AmbiguousLayout: branch 1's future type is shared: 2 tuple members, 1 arms",
            ]
        );
        assert_eq!(
            kinds(&join_arms(
                &branches(&[1, 2]),
                &[
                    (id(1), vec![loc(33)]),
                    (id(1), vec![loc(34)]),
                    (id(2), vec![loc(40)])
                ]
            )),
            [
                "declined AmbiguousLayout: branch 0's future type is shared: 1 tuple members, 2 arms",
                "written 40",
            ]
        );
    }

    /// The tick's plan: the origin off the closure's declaration file
    /// — `interval.rs` on a registry path at a reviewed version — then
    /// one exclusive forward through the closure's capture to the
    /// interval's pinned box, held to the final table. A closure with
    /// no declaration site, one declared outside the registry, in
    /// another crate, at an unreviewed version or revision declines
    /// before the layout; a capture that is not a reference to the
    /// interval, a `delay` holding another type than the screen saw,
    /// or a member missing from the table decline on the layout.
    #[test]
    fn test_the_tick_plan_routes_through_the_capture_to_the_box() {
        let mut strings = StringInterner::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let mut add = |def: TypeDef| {
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let plain = |strings: &mut StringInterner, name: &str, size| TypeDef::Struct {
            name: strings.intern(name),
            size,
            members: Vec::new(),
        };
        let member = |strings: &mut StringInterner, name: &str, ty, offset| MemberDef {
            name: strings.intern(name),
            ty,
            offset,
        };
        let sleep = add(plain(&mut strings, "tokio::time::sleep::Sleep", 112));
        let duration = add(plain(&mut strings, "core::time::Duration", 16));
        let sleep_box = add(TypeDef::Pointer {
            name: Some(
                strings
                    .intern("alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>"),
            ),
            target: sleep,
        });
        let pointer = member(&mut strings, "pointer", sleep_box, 0);
        let pin = add(TypeDef::Struct {
            name: strings
                .intern("core::pin::Pin<alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>>"),
            size: 8,
            members: vec![pointer],
        });
        let period = member(&mut strings, "period", duration, 0);
        let delay = member(&mut strings, "delay", pin, 16);
        let interval = add(TypeDef::Struct {
            name: strings.intern("tokio::time::interval::Interval"),
            size: 32,
            members: vec![period.clone(), delay],
        });
        // An interval whose `delay` is the bare box, not the pin.
        let bare = member(&mut strings, "delay", sleep_box, 16);
        let bare_interval = add(TypeDef::Struct {
            name: strings.intern("tokio::time::interval::Interval"),
            size: 32,
            members: vec![period, bare],
        });
        let interval_ref = add(TypeDef::Pointer {
            name: Some(strings.intern("&mut tokio::time::interval::Interval")),
            target: interval,
        });
        let bare_ref = add(TypeDef::Pointer {
            name: Some(strings.intern("&mut tokio::time::interval::Interval")),
            target: bare_interval,
        });
        let env_named = "tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}";
        let env = add(TypeDef::Struct {
            name: strings.intern(env_named),
            size: 8,
            members: vec![member(&mut strings, "_ref__self", interval_ref, 0)],
        });
        // A capture holding the interval by value, and one referencing
        // the bare-box interval.
        let by_value = add(TypeDef::Struct {
            name: strings.intern(env_named),
            size: 32,
            members: vec![member(&mut strings, "_ref__self", interval, 0)],
        });
        let to_bare = add(TypeDef::Struct {
            name: strings.intern(env_named),
            size: 8,
            members: vec![member(&mut strings, "_ref__self", bare_ref, 0)],
        });
        let poll_fn_named = "core::future::poll_fn::PollFn<…tick…>";
        let poll_fn = add(TypeDef::Struct {
            name: strings.intern(poll_fn_named),
            size: 8,
            members: vec![member(&mut strings, "f", env, 0)],
        });
        let over_value = add(TypeDef::Struct {
            name: strings.intern(poll_fn_named),
            size: 32,
            members: vec![member(&mut strings, "f", by_value, 0)],
        });
        let over_bare = add(TypeDef::Struct {
            name: strings.intern(poll_fn_named),
            size: 8,
            members: vec![member(&mut strings, "f", to_bare, 0)],
        });
        let types = TypeTable {
            types,
            ..Default::default()
        };
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let layout = |interval, boxed, path: &str, md5| LibrarySeed::IntervalTick {
            closure: "f".into(),
            interval_ref: "_ref__self".into(),
            interval,
            delay: "delay".into(),
            boxed,
            source: (!path.is_empty()).then(|| source(path, md5)),
        };
        let reviewed = format!("{ROOT}/tokio-1.52.4/src/time/interval.rs");
        let render = |strings: &StringInterner, path: &TypedPath| {
            path.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => strings.get(*n).unwrap().to_owned(),
                    Step::Deref => "*".to_owned(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        // The seed's own poll sources are nobody's evidence here: the
        // `PollFn`'s poll is core's, and the closure's declaration is
        // the origin.
        let unproven = Seed {
            poll_sources: BTreeSet::from([source(
                "/rustc/abc/library/core/src/future/poll_fn.rs",
                None,
            )]),
            ..Seed::default()
        };
        let checksum = TOKIO_INTERVAL_TICK_V1_47.checksums[1].1;
        for md5 in [None, Some(checksum)] {
            let plan = plan_library(
                poll_fn,
                &layout(interval, pin, &reviewed, md5),
                &unproven,
                &types,
                &mut strings,
            )
            .unwrap();
            let RuleKey::Delegation { kind, origin } = &plan.rule else {
                panic!("{:?}", plan.rule);
            };
            assert_eq!(*kind, SemanticRuleKind::TokioIntervalTick);
            assert_eq!(origin.package, "tokio");
            assert_eq!(origin.version, "1.52.4");
            assert_eq!(origin.family, TOKIO_INTERVAL_TICK_V1_47.family);
            assert_eq!(origin.files.len(), usize::from(md5.is_some()));
            let Some(Delegation::Direct {
                target: Target::Value(path),
                exclusive,
            }) = &plan.program
            else {
                panic!("{:?}", plan.program);
            };
            assert!(exclusive, "pending, the tick polls its box alone");
            assert_eq!(render(&strings, path), "f._ref__self.*.delay");
            assert_eq!(path.target, pin);
            assert!(plan.access.is_none(), "the tick is a future, not a pointer");
            assert!(plan.delegate_is_future, "the pinned box is a future");
        }
        // The origin: no declaration site, a vendored tree, another
        // crate's registry path, a version on either side of the
        // review, and a revision of `interval.rs` nobody reviewed.
        for (path, md5, expected) in [
            ("", None, "no closure declaration"),
            (
                "/build/vendor/tokio-1.52.4/src/time/interval.rs",
                None,
                "not a cargo registry path",
            ),
            (
                &format!("{ROOT}/tokio-util-0.7.12/src/time/interval.rs"),
                None,
                "not the tokio crate",
            ),
            (
                &format!("{ROOT}/tokio-1.53.2/src/time/interval.rs"),
                None,
                "above the reviewed range",
            ),
            (
                &format!("{ROOT}/tokio-1.46.1/src/time/interval.rs"),
                None,
                "below the reviewed range",
            ),
            (
                &reviewed,
                Some([0xab; 16]),
                "not a reviewed revision of tokio-interval-tick-1.47",
            ),
        ] {
            let (kind, detail) = plan_library(
                poll_fn,
                &layout(interval, pin, path, md5),
                &unproven,
                &types,
                &mut strings,
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{path}");
            assert!(detail.contains(expected), "{path}: {detail}");
        }
        // The layout: a capture holding the interval by value, a
        // `delay` that is not the box the screen saw, and members the
        // table does not have.
        let (kind, detail) = plan_library(
            over_value,
            &layout(interval, pin, &reviewed, None),
            &unproven,
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(
            detail.contains("not a reference to the declared interval"),
            "{detail}"
        );
        let (kind, detail) = plan_library(
            over_bare,
            &layout(bare_interval, pin, &reviewed, None),
            &unproven,
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("another type than the screen"), "{detail}");
        let renamed = |closure: &str, interval_ref: &str, delay: &str| LibrarySeed::IntervalTick {
            closure: closure.into(),
            interval_ref: interval_ref.into(),
            interval,
            delay: delay.into(),
            boxed: pin,
            source: Some(source(&reviewed, None)),
        };
        for seed in [
            renamed("closure", "_ref__self", "delay"),
            renamed("f", "_ref__interval", "delay"),
            renamed("f", "_ref__self", "sleep"),
        ] {
            let (kind, detail) =
                plan_library(poll_fn, &seed, &unproven, &types, &mut strings).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::AmbiguousLayout, "{seed:?}");
            assert!(detail.contains("no unique member"), "{detail}");
        }
    }

    /// A route is held to the type it claims to land on: the same steps
    /// declared for another endpoint decline, and so do steps the table
    /// cannot walk at all.
    #[test]
    fn test_checked_paths_land_on_the_declared_target() {
        let mut a = adapters();
        let pointer = a.strings.intern("pointer");
        let steps = vec![Step::Member(MemberRef::Named(pointer)), Step::Deref];
        let path = checked_path(&a.types, PIN_BOX, steps.clone(), FUT).unwrap();
        assert_eq!(path.target, FUT);
        let (kind, detail) = checked_path(&a.types, PIN_BOX, steps.clone(), DYN).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("another type than declared"), "{detail}");
        let (kind, _) = checked_path(&a.types, FUT, steps, FUT).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
    }

    /// An adapter whose storage the bundle cannot read plans nothing: no
    /// route is attempted through an opaque type, so its record carries
    /// no layout decline, only the storage boundary.
    #[test]
    fn test_an_adapter_over_unavailable_storage_plans_nothing() {
        let mut a = adapters();
        a.types.types[PIN_BOX.0 as usize] = TypeDef::Opaque {
            name: a
                .strings
                .intern("core::pin::Pin<alloc::boxed::Box<app::Fut, alloc::alloc::Global>>"),
            size: Some(8),
        };
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            PIN_BOX,
            Seed {
                adapter: Some(seed(
                    AdapterKind::PinBox,
                    Some(("pointer", BOX)),
                    PointeeSeed::Sized(FUT),
                )),
                ..Default::default()
            },
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = table.types.iter().find(|r| r.ty == PIN_BOX).unwrap();
        assert!(matches!(
            record.storage,
            StoragePolicy::Unavailable(SemanticIssue {
                kind: SemanticIssueKind::MissingLayout,
                ..
            })
        ));
        assert!(record.issues.is_empty(), "{:?}", record.issues);
        assert!(matches!(
            record.future.as_ref().unwrap().continuation,
            Continuation::Unknown(SemanticIssue {
                kind: SemanticIssueKind::NoRule,
                ..
            })
        ));
        assert!(record.access.is_none());
        assert!(table.rules.is_empty());
    }

    /// An unreviewed release is reported where a record keeps the
    /// decline it caused, and only there: a stream map tokio-stream
    /// 0.1.20 declares records its container rule's decline, so the
    /// release and its family are named; a rustls 0.24.0 session on an
    /// opaque type is refused too, but nothing reads that type, no
    /// record keeps the decline, and the release goes unreported.
    #[test]
    fn test_an_unreviewed_release_is_reported_where_a_record_keeps_its_decline() {
        let mut strings = StringInterner::new();
        let mut names = Vec::new();
        let mut types = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let map_name = "tokio_stream::stream_map::StreamMap<u8, u8>";
        let map = add(
            map_name,
            TypeDef::Struct {
                name: strings.intern(map_name),
                size: 24,
                members: Vec::new(),
            },
        );
        let session_name = "rustls::conn::ConnectionCommon<u8>";
        let session = add(
            session_name,
            TypeDef::Opaque {
                name: strings.intern(session_name),
                size: Some(8),
            },
        );
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let registry = |package: &str| {
            source(
                &format!(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     {package}/src/lib.rs"
                ),
                None,
            )
        };
        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            map,
            Seed {
                container: Some(ContainerKind::StreamMap),
                type_sources: BTreeSet::from([registry("tokio-stream-0.1.20")]),
                ..Default::default()
            },
        );
        seeds.insert(
            session,
            Seed {
                tls_session: Some(BTreeSet::from([registry("rustls-0.24.0")])),
                ..Default::default()
            },
        );
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let (table, releases) =
            bind_semantics_noting_releases(seeds, &types, &names, &mut strings, &mut [], &library);
        let record = table.types.iter().find(|r| r.ty == map).unwrap();
        let [issue] = record.issues.as_slice() else {
            panic!("one issue: {:?}", record.issues)
        };
        assert_eq!(
            strings.get(issue.detail.unwrap()),
            Some("tokio-stream 0.1.20 is above the reviewed range 0.1.14-0.1.19")
        );
        let reported: Vec<(String, Vec<&str>)> = releases
            .iter()
            .map(|(release, families)| (release.to_string(), families.iter().copied().collect()))
            .collect();
        assert_eq!(
            reported,
            [(
                "tokio-stream 0.1.20 is newer than the supported version range: 0.1.14-0.1.19"
                    .to_owned(),
                vec![TOKIO_STREAM_MAP_V0_1_14.family]
            )]
        );
    }

    /// Each origin gate notes the release it refuses, saying which side
    /// of the range a version falls on or which revision is unread, and
    /// notes nothing for a release it binds or a decline that names no
    /// release; nothing is noted outside a capture.
    #[test]
    fn test_the_origin_gates_note_each_refused_release() {
        let at = |path: &str| BTreeSet::from([source(path, None)]);
        let registry = |dir: &str, file: &str| {
            at(&format!(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/{dir}/{file}"
            ))
        };
        let refused = |gate: &dyn Fn() -> bool| {
            let (declined, refusals) = refusals::capture(gate);
            assert!(declined, "the gate declines");
            refusals
                .into_iter()
                .map(|r| (r.family, r.release.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            refused(&|| layout_release(
                &registry("rustls-0.23.22", "src/conn.rs"),
                &RUSTLS_SESSION_V0_23_23
            )
            .is_err()),
            [(
                RUSTLS_SESSION_V0_23_23.family,
                "rustls 0.23.22 is older than the supported version range: 0.23.23-0.23.45"
                    .to_owned()
            )]
        );
        assert_eq!(
            refused(&|| delegation_origin(
                &registry("tracing-0.1.45", "src/instrument.rs"),
                &TRACING_INSTRUMENTED_V0_1_40,
                "poll"
            )
            .is_err()),
            [(
                TRACING_INSTRUMENTED_V0_1_40.family,
                "tracing 0.1.45 is newer than the supported version range: 0.1.40-0.1.44"
                    .to_owned()
            )]
        );
        let mut both = registry("parking_lot-0.10.2", "src/raw_mutex.rs");
        both.extend(registry("parking_lot-0.12.5", "src/raw_mutex.rs"));
        assert_eq!(
            refused(
                &|| delegation_origin(&both, &PARKING_LOT_RAW_MUTEX_V0_11_0, "method").is_err()
            ),
            [(
                PARKING_LOT_RAW_MUTEX_V0_11_0.family,
                "parking_lot 0.10.2 is older than the supported version range: 0.11.0-0.12.5"
                    .to_owned()
            )]
        );
        assert_eq!(
            refused(&|| git_delegation_origin(
                &at(
                    "/home/u/.cargo/git/checkouts/sprockets-882d17aeeb0cb343/0123abc/tls/src/lib.rs"
                ),
                &SPROCKETS_TLS_STREAM_D2B68E4,
                "method"
            )
            .is_err()),
            [(
                SPROCKETS_TLS_STREAM_D2B68E4.family,
                "sprockets-tls revision 0123abc is not a reviewed revision".to_owned()
            )]
        );
        // A decline that names no release notes nothing, and neither
        // does a release that binds.
        assert!(
            refused(&|| layout_release(&BTreeSet::new(), &RUSTLS_SESSION_V0_23_23).is_err())
                .is_empty()
        );
        let (bound, refusals) = refusals::capture(|| {
            layout_release(
                &registry("rustls-0.23.41", "src/conn.rs"),
                &RUSTLS_SESSION_V0_23_23,
            )
        });
        assert_eq!(bound.unwrap(), "0.23.41");
        assert!(refusals.is_empty());
        // Outside a capture a refusal is dropped, not kept for the next.
        let _ = layout_release(
            &registry("rustls-0.24.0", "src/conn.rs"),
            &RUSTLS_SESSION_V0_23_23,
        );
        let ((), refusals) = refusals::capture(|| ());
        assert!(refusals.is_empty());
    }

    /// A `Pin<Box<F>>` whose box's definitions name several `F`s is no
    /// adapter, and the record it earns as a task's future says so in
    /// its continuation, over the bare `NoRule`.
    #[test]
    fn test_a_disagreeing_box_records_its_reason() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            PIN_BOX,
            Seed {
                adapter_declined: Some((
                    SemanticIssueKind::AmbiguousLayout,
                    "the pointer's definitions name 2 targets".to_owned(),
                )),
                ..Default::default()
            },
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = table.types.iter().find(|r| r.ty == PIN_BOX).unwrap();
        let Continuation::Unknown(issue) = &record.future.as_ref().unwrap().continuation else {
            panic!("the box's continuation is unknown");
        };
        assert_eq!(issue.kind, SemanticIssueKind::AmbiguousLayout);
        assert_eq!(
            issue.detail,
            Some(a.strings.intern("the pointer's definitions name 2 targets"))
        );
        assert_eq!(record.issues.len(), 1, "{:?}", record.issues);
        assert!(record.access.is_none());
        assert!(table.rules.is_empty());
    }

    /// Evidence crosses every bound hop: the pin over a box over a
    /// reference proves the reference a future, whose own rule then
    /// proves the future it points at.
    #[test]
    fn test_evidence_closes_transitively_over_two_hops() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            PIN_BOX_REF,
            Seed {
                adapter: Some(seed(
                    AdapterKind::PinBox,
                    Some(("pointer", BOX_REF)),
                    PointeeSeed::Sized(REF),
                )),
                ..Default::default()
            },
        );
        seeds.insert(
            REF,
            Seed {
                adapter: Some(seed(AdapterKind::MutRef, None, PointeeSeed::Sized(FUT))),
                ..Default::default()
            },
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX_REF,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let evidence = |ty: BundleTypeId| {
            table
                .types
                .iter()
                .find(|r| r.ty == ty)
                .and_then(|r| r.future.as_ref())
                .map(|f| f.evidence.clone())
        };
        assert_eq!(
            evidence(REF),
            Some(vec![FutureEvidence::DelegatedBy {
                parent: PIN_BOX_REF
            }])
        );
        assert_eq!(
            evidence(FUT),
            Some(vec![FutureEvidence::DelegatedBy { parent: REF }])
        );
        let bound = |ty: BundleTypeId| {
            matches!(
                table
                    .types
                    .iter()
                    .find(|r| r.ty == ty)
                    .unwrap()
                    .future
                    .as_ref()
                    .unwrap()
                    .continuation,
                Continuation::Bound { .. }
            )
        };
        assert!(bound(PIN_BOX_REF) && bound(REF) && !bound(FUT));
    }

    /// Two coroutines awaiting each other — async recursion through a
    /// box, as the type graph sees it — close in one pass: each proves
    /// the other, and the fixed point stops where the evidence stops
    /// changing.
    #[test]
    fn test_evidence_closes_over_a_delegation_cycle() {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = Vec::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let u32_t = strings.intern("u32");
        names.push(Some("u32".into()));
        types.push(TypeDef::Base {
            name: u32_t,
            size: 4,
            encoding: crate::Encoding::Unsigned,
        });
        // Each env: 4 payloads then the enum, so A's enum is id 5 and
        // B's is id 10; Suspend0 of each awaits the other's enum.
        const A_ENUM: BundleTypeId = BundleTypeId(5);
        const B_ENUM: BundleTypeId = BundleTypeId(10);
        for (env_name, awaitee) in [
            ("app::a::{async_fn_env#0}", B_ENUM),
            ("app::b::{async_fn_env#0}", A_ENUM),
        ] {
            let mut variants = Vec::new();
            for (index, state) in ["Unresumed", "Returned", "Panicked", "Suspend0"]
                .into_iter()
                .enumerate()
            {
                let payload = BundleTypeId(types.len() as u32);
                let name = format!("{env_name}::{state}");
                let members = if state == "Suspend0" {
                    vec![MemberDef {
                        name: strings.intern("__awaitee"),
                        ty: awaitee,
                        offset: 0,
                    }]
                } else {
                    Vec::new()
                };
                types.push(TypeDef::Struct {
                    name: strings.intern(&name),
                    size: 8,
                    members,
                });
                names.push(Some(name));
                let key = strings.intern(&index.to_string());
                variants.push(VariantDef {
                    name: key,
                    discr_values: None,
                    payload: MemberDef {
                        name: key,
                        ty: payload,
                        offset: 0,
                    },
                    decl: None,
                    await_site: None,
                });
            }
            names.push(Some(env_name.into()));
            types.push(TypeDef::Enum {
                name: strings.intern(env_name),
                size: 8,
                shape: VariantShape {
                    discr: None,
                    variants,
                },
            });
        }
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        for env in [A_ENUM, B_ENUM] {
            seeds.insert(
                env,
                Seed {
                    coroutine_candidate: true,
                    compiler: Some(supported(&crate::detect::semantics::RUSTC_COROUTINE_V1_97)),
                    ..Default::default()
                },
            );
        }
        let mut tasks = vec![TaskFutureEntry {
            future: A_ENUM,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: strings.intern("task"),
        }];
        let table = bind_semantics(seeds, &types, &names, &mut strings, &mut tasks, &library);
        let record = |ty: BundleTypeId| table.types.iter().find(|r| r.ty == ty).unwrap();
        let rule = record(A_ENUM).coroutine.as_ref().unwrap().rule;
        assert_eq!(
            record(A_ENUM).future.as_ref().unwrap().evidence,
            [
                FutureEvidence::TaskEntry(TaskEntryId(0)),
                FutureEvidence::Coroutine(rule),
                FutureEvidence::DelegatedBy { parent: B_ENUM },
            ]
        );
        assert_eq!(
            record(B_ENUM).future.as_ref().unwrap().evidence,
            [
                FutureEvidence::Coroutine(rule),
                FutureEvidence::DelegatedBy { parent: A_ENUM },
            ]
        );
        for env in [A_ENUM, B_ENUM] {
            assert!(matches!(
                record(env).future.as_ref().unwrap().continuation,
                Continuation::Bound {
                    program: PollProgram::MatchVariant { .. },
                    ..
                }
            ));
        }
    }

    /// `inner` reaches the future through std's `ManuallyDrop` and
    /// `MaybeDangling` wrappers by name, each a one-member struct at
    /// offset zero; anything else in the way declines.
    #[test]
    fn test_instrumented_plan_enters_only_the_reviewed_wrappers() {
        let mut strings = StringInterner::new();
        let mut names = Vec::new();
        let mut types = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 8,
                members: Vec::new(),
            },
        );
        let dangling = add(
            "core::mem::maybe_dangling::MaybeDangling<app::Fut>",
            TypeDef::Struct {
                name: strings.intern("core::mem::maybe_dangling::MaybeDangling<app::Fut>"),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("__0"),
                    ty: fut,
                    offset: 0,
                }],
            },
        );
        let manually = add(
            "core::mem::manually_drop::ManuallyDrop<app::Fut>",
            TypeDef::Struct {
                name: strings.intern("core::mem::manually_drop::ManuallyDrop<app::Fut>"),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("value"),
                    ty: dangling,
                    offset: 0,
                }],
            },
        );
        let span = add(
            "tracing::span::Span",
            TypeDef::Struct {
                name: strings.intern("tracing::span::Span"),
                size: 40,
                members: Vec::new(),
            },
        );
        let inst = add(
            "tracing::instrument::Instrumented<app::Fut>",
            TypeDef::Struct {
                name: strings.intern("tracing::instrument::Instrumented<app::Fut>"),
                size: 48,
                members: vec![
                    MemberDef {
                        name: strings.intern("span"),
                        ty: span,
                        offset: 0,
                    },
                    MemberDef {
                        name: strings.intern("inner"),
                        ty: manually,
                        offset: 40,
                    },
                ],
            },
        );
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let layout = InstrumentedSeed {
            inner: "inner".into(),
            future: fut,
        };
        let seed = Seed {
            poll_sources: BTreeSet::from([source(REGISTRY, None)]),
            ..Default::default()
        };
        let plan = plan_instrumented(inst, &layout, &seed, &types, &names, &mut strings).unwrap();
        let Delegation::Direct { target, exclusive } = plan.program.as_ref().unwrap() else {
            panic!("direct")
        };
        assert!(
            !exclusive,
            "a span's callbacks are not reviewed control flow"
        );
        assert!(plan.access.is_none());
        let s = |r: StrRef| strings.get(r).unwrap().to_owned();
        let Target::Value(path) = target else {
            panic!("static")
        };
        let spelled: Vec<String> = path
            .steps
            .iter()
            .map(|step| match step {
                Step::Member(MemberRef::Named(n)) => s(*n),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(spelled, ["inner", "value", "__0"]);
        assert_eq!(path.target, fut);
        assert!(
            matches!(&plan.rule, RuleKey::Delegation { kind: SemanticRuleKind::TracingInstrumented, origin }
            if origin.family == "tracing-instrumented-0.1.40" && origin.version == "0.1.40")
        );
        // A wrapper that is not one of the two, or one that grew a
        // member, stops the route.
        let mut other = types.clone();
        if let TypeDef::Struct { name, .. } = &mut other.types[dangling.0 as usize] {
            *name = strings.intern("app::Cell<app::Fut>");
        }
        let mut other_names = names.clone();
        other_names[dangling.0 as usize] = Some("app::Cell<app::Fut>".into());
        let (kind, detail) =
            plan_instrumented(inst, &layout, &seed, &other, &other_names, &mut strings)
                .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("not a reviewed std wrapper"), "{detail}");
        let mut grown = types.clone();
        if let TypeDef::Struct { members, .. } = &mut grown.types[manually.0 as usize] {
            members.push(MemberDef {
                name: strings.intern("extra"),
                ty: fut,
                offset: 0,
            });
        }
        let (kind, _) =
            plan_instrumented(inst, &layout, &seed, &grown, &names, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        // And an unsupported origin never reaches the layout.
        let seed = Seed::default();
        let (kind, _) =
            plan_instrumented(inst, &layout, &seed, &types, &names, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
    }

    /// Evidence closes over bound delegations from seeded types only: a
    /// task root's `Pin<Box<F>>` proves `F` a future, whose own program
    /// then proves its delegate; a `Pin<Box<G>>` nothing points at
    /// proves nothing, and appears only as the owned route to a `G`
    /// that has a record of its own.
    #[test]
    fn test_evidence_closes_over_seeded_delegations_only() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        let boxed = |pin: Option<(&str, BundleTypeId)>, kind, pointee| Seed {
            adapter: Some(seed(kind, pin, pointee)),
            ..Default::default()
        };
        // A task root: Pin<Box<Fut>> over the sized box over Fut.
        seeds.insert(
            PIN_BOX,
            boxed(
                Some(("pointer", BOX)),
                AdapterKind::PinBox,
                PointeeSeed::Sized(FUT),
            ),
        );
        seeds.insert(BOX, boxed(None, AdapterKind::Box, PointeeSeed::Sized(FUT)));
        // A reference nothing points at, over the same future.
        seeds.insert(
            REF,
            boxed(None, AdapterKind::MutRef, PointeeSeed::Sized(FUT)),
        );
        // A wide box nothing points at: no static child, no record.
        seeds.insert(
            WIDE,
            boxed(None, AdapterKind::Box, PointeeSeed::Dyn(dyn_seed())),
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = |ty: BundleTypeId| table.types.iter().find(|r| r.ty == ty);
        let evidence = |ty: BundleTypeId| {
            record(ty)
                .and_then(|r| r.future.as_ref())
                .map(|f| f.evidence.clone())
        };
        assert_eq!(
            evidence(PIN_BOX),
            Some(vec![FutureEvidence::TaskEntry(TaskEntryId(0))])
        );
        // Pin<Box<Fut>> delegates to Fut directly; the box's own record
        // is the owned route to a future that has one.
        assert_eq!(
            evidence(FUT),
            Some(vec![FutureEvidence::DelegatedBy { parent: PIN_BOX }])
        );
        assert!(matches!(
            record(FUT).unwrap().future.as_ref().unwrap().continuation,
            Continuation::Unknown(SemanticIssue {
                kind: SemanticIssueKind::NoRule,
                ..
            })
        ));
        assert_eq!(evidence(BOX), None);
        assert!(record(BOX).unwrap().access.is_some());
        assert_eq!(evidence(REF), None);
        assert!(record(REF).unwrap().access.is_some());
        assert!(record(WIDE).is_none());
        // The rules: the pin's poll and access, the box's and the
        // reference's access, each once, under one rustc origin.
        let kinds: BTreeSet<SemanticRuleKind> = table.rules.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            BTreeSet::from([
                SemanticRuleKind::StdPinBoxPoll,
                SemanticRuleKind::StdPinBoxAccess,
                SemanticRuleKind::StdBoxAccess,
                SemanticRuleKind::StdMutRefAccess,
            ])
        );
        assert_eq!(table.origins.len(), 1);
        assert!(matches!(table.origins[0], SemanticOrigin::Rustc { .. }));
        let Continuation::Bound { program, .. } = &record(PIN_BOX)
            .unwrap()
            .future
            .as_ref()
            .unwrap()
            .continuation
        else {
            panic!("the root's program is bound")
        };
        assert!(matches!(
            program,
            PollProgram::Direct(PollAction::Delegate {
                target: FutureTarget::Value(TypedPath { target: FUT, .. }),
                exclusive: true,
            })
        ));
    }

    /// A bound coroutine seeds the fixed point by its storage alone: a
    /// block nothing delegates to statically — one reached only through
    /// a dyn hop at runtime — still proves the pinned wide box its
    /// suspended state awaits a future, so the box carries a record the
    /// chain can cross and the scan can enter. Before this was so, the
    /// box had no record at all: its evidence was empty when the queue
    /// was seeded, and the coroutine's own evidence is numbered only
    /// at emit time.
    #[test]
    fn test_a_bound_coroutine_seeds_its_awaitee_without_evidence_of_its_own() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        // The env, appended to the adapter table: four payloads then
        // the enum, its Suspend0 awaiting the wide pin.
        let env_name = "app::dynamic::{async_block_env#0}";
        let base = a.types.types.len() as u32;
        let mut variants = Vec::new();
        for (index, state) in ["Unresumed", "Returned", "Panicked", "Suspend0"]
            .into_iter()
            .enumerate()
        {
            let payload = BundleTypeId(a.types.types.len() as u32);
            let name = format!("{env_name}::{state}");
            let members = if state == "Suspend0" {
                vec![MemberDef {
                    name: a.strings.intern("__awaitee"),
                    ty: PIN_WIDE,
                    offset: 0,
                }]
            } else {
                Vec::new()
            };
            a.types.types.push(TypeDef::Struct {
                name: a.strings.intern(&name),
                size: 16,
                members,
            });
            a.names.push(Some(name));
            let key = a.strings.intern(&index.to_string());
            variants.push(VariantDef {
                name: key,
                discr_values: None,
                payload: MemberDef {
                    name: key,
                    ty: payload,
                    offset: 0,
                },
                decl: None,
                await_site: None,
            });
        }
        let env = BundleTypeId(base + 4);
        a.types.types.push(TypeDef::Enum {
            name: a.strings.intern(env_name),
            size: 16,
            shape: VariantShape {
                discr: None,
                variants,
            },
        });
        a.names.push(Some(env_name.to_owned()));

        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            env,
            Seed {
                coroutine_candidate: true,
                compiler: Some(supported(&crate::detect::semantics::RUSTC_COROUTINE_V1_97)),
                ..Default::default()
            },
        );
        seeds.insert(
            PIN_WIDE,
            Seed {
                adapter: Some(seed(
                    AdapterKind::PinBox,
                    Some(("pointer", WIDE)),
                    PointeeSeed::Dyn(dyn_seed()),
                )),
                ..Default::default()
            },
        );
        // No task entry and no poll symbol anywhere: the block is a
        // future only by being a bound coroutine.
        let mut tasks = Vec::new();
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = |ty: BundleTypeId| table.types.iter().find(|r| r.ty == ty);
        let rule = record(env).unwrap().coroutine.as_ref().unwrap().rule;
        assert_eq!(
            record(env).unwrap().future.as_ref().unwrap().evidence,
            [FutureEvidence::Coroutine(rule)]
        );
        let pin = record(PIN_WIDE).expect("the awaited pin has a record");
        assert_eq!(
            pin.future.as_ref().unwrap().evidence,
            [FutureEvidence::DelegatedBy { parent: env }]
        );
        assert!(matches!(
            pin.future.as_ref().unwrap().continuation,
            Continuation::Bound {
                program: PollProgram::Direct(PollAction::Delegate {
                    target: FutureTarget::Dynamic { .. },
                    exclusive: true,
                }),
                ..
            }
        ));
        assert!(pin.access.is_some(), "the owned route into the box");
    }

    /// A bound coroutine's program matches its states: the fixed three
    /// and, per suspended state, a delegation to the listed `__awaitee`
    /// or an unknown case where none is listed.
    #[test]
    fn test_coroutine_plan_delegates_only_to_a_listed_awaitee() {
        let mut e = env(
            "async_fn",
            &[
                ("Unresumed", &["arg"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["local", "__awaitee"]),
                ("Suspend1", &["local"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        let layout = CoroutineLayout {
            rule: SemanticRuleId(u32::MAX),
            states,
        };
        let rule = RuleKey::Rustc {
            kind: SemanticRuleKind::RustcAsyncFn,
            producer: PRODUCER.into(),
            family: "rustc-coroutine-1.97",
        };
        let plan = coroutine_plan(e.env, &rule, &layout, &e.types, &mut e.strings);
        let Delegation::Match { cases, .. } = plan.program.as_ref().unwrap() else {
            panic!("coroutine")
        };
        let spelled: Vec<String> = cases
            .iter()
            .map(|(variant, action)| {
                let s = e.strings.get(*variant).unwrap();
                match action {
                    CaseAction::Unresumed => format!("{s}:unresumed"),
                    CaseAction::Returned => format!("{s}:returned"),
                    CaseAction::Panicked => format!("{s}:panicked"),
                    CaseAction::Delegate(target) => match target.as_ref() {
                        Target::Value(p) => {
                            format!("{s}:delegate {} steps -> {}", p.steps.len(), p.target.0)
                        }
                        Target::Dynamic { .. } => format!("{s}:dyn"),
                    },
                    CaseAction::Primitive => format!("{s}:primitive"),
                    CaseAction::Unknown(i) => format!("{s}:unknown {:?}", i.kind),
                }
            })
            .collect();
        assert_eq!(
            spelled,
            [
                "0:unresumed",
                "1:returned",
                "2:panicked",
                "3:delegate 2 steps -> 0",
                "4:unknown MissingLayout",
            ]
        );
        assert_eq!(plan.static_children(), [BundleTypeId(0)]);
        // An `__awaitee` the convention lists as uncertain — an async
        // block's capture at the slot its `Unresumed` state keeps it at —
        // is not a delegate: stale bytes are not a future being polled.
        let mut e = env(
            "async_block",
            &[
                ("Unresumed", &["__awaitee"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, true, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(render(&e, &states)[3], "3:Suspended[](__awaitee)");
        let layout = CoroutineLayout {
            rule: SemanticRuleId(u32::MAX),
            states,
        };
        let plan = coroutine_plan(e.env, &rule, &layout, &e.types, &mut e.strings);
        let Delegation::Match { cases, .. } = plan.program.as_ref().unwrap() else {
            panic!("coroutine")
        };
        assert!(matches!(
            cases[3].1,
            CaseAction::Unknown(SemanticIssue {
                kind: SemanticIssueKind::MissingLayout,
                ..
            })
        ));
        assert!(plan.static_children().is_empty());
    }

    /// A struct named `name` of unsigned members, each `(name, size,
    /// offset)`, as the last type of `types`; its id.
    fn words(
        types: &mut TypeTable,
        strings: &mut StringInterner,
        name: &str,
        members: &[(&str, u64, u64)],
    ) -> BundleTypeId {
        let base = |size: u64, strings: &mut StringInterner| TypeDef::Base {
            name: strings.intern(&format!("u{}", size * 8)),
            size,
            encoding: crate::bundle::Encoding::Unsigned,
        };
        let members = members
            .iter()
            .map(|&(member, size, offset)| {
                let ty = BundleTypeId(types.types.len() as u32);
                types.types.push(base(size, strings));
                MemberDef {
                    name: strings.intern(member),
                    ty,
                    offset,
                }
            })
            .collect();
        let size = 24;
        types.types.push(TypeDef::Struct {
            name: strings.intern(name),
            size,
            members,
        });
        BundleTypeId(types.types.len() as u32 - 1)
    }

    /// A refcount header binds its value only past both counts, with
    /// `strong` at its start: a header whose counts or value sit
    /// otherwise, or whose verdict declined, binds nothing.
    #[test]
    fn test_a_refcount_value_follows_the_counts() {
        use crate::detect::semantics::RUSTC_STD_REFCOUNT_V1_97;
        let verdict = CompilerVerdict::Supported {
            producer: "rustc 1.97.1".to_owned(),
            convention: &RUSTC_STD_REFCOUNT_V1_97,
        };
        let plan = |members: &[(&str, u64, u64)]| {
            let (mut types, mut strings) = (TypeTable::default(), StringInterner::new());
            let ty = words(
                &mut types,
                &mut strings,
                "alloc::sync::ArcInner<u64>",
                members,
            );
            plan_refcount(ty, "data", &verdict, &types, &strings)
        };
        let (rule, value) = plan(&[("strong", 8, 0), ("weak", 8, 8), ("data", 8, 16)]).unwrap();
        assert!(
            matches!(
                rule,
                RuleKey::Rustc {
                    kind: SemanticRuleKind::StdRefcountHeader,
                    ..
                }
            ),
            "{rule:?}"
        );
        assert!(matches!(value, MemberRef::Named(_)), "{value:?}");
        for members in [
            // The counts swapped: the value still follows both.
            [("weak", 8, 0), ("strong", 8, 8), ("data", 8, 16)],
            // `strong` first, but the value between the counts.
            [("strong", 8, 0), ("data", 8, 8), ("weak", 8, 16)],
        ] {
            let (kind, detail) = plan(&members).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::MissingLayout, "{members:?}");
            assert_eq!(
                detail, "the value does not follow the counts",
                "{members:?}"
            );
        }
        let (mut types, mut strings) = (TypeTable::default(), StringInterner::new());
        let ty = words(&mut types, &mut strings, "alloc::sync::ArcInner<u64>", &[]);
        let declined = CompilerVerdict::Declined("no reviewed producer".to_owned());
        let (kind, _) = plan_refcount(ty, "data", &declined, &types, &strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
    }

    /// A stream's peer binds only where its name is an array of bytes
    /// with room for one: an empty array, an array of wider or signed
    /// elements, or no array at all binds nothing.
    #[test]
    fn test_a_peer_name_is_a_nonempty_byte_array() {
        use crate::bundle::Encoding::{self, Signed, Unsigned};
        let plan = |count: u64, size: u64, encoding: Encoding, array: bool| {
            let (mut types, mut strings) = (TypeTable::default(), StringInterner::new());
            let elem = BundleTypeId(types.types.len() as u32);
            types.types.push(TypeDef::Base {
                name: strings.intern("elem"),
                size,
                encoding,
            });
            let name = BundleTypeId(types.types.len() as u32);
            types.types.push(if array {
                TypeDef::Array { elem, count }
            } else {
                TypeDef::Base {
                    name: strings.intern("u64"),
                    size: 8,
                    encoding: Unsigned,
                }
            });
            types.types.push(TypeDef::Struct {
                name: strings.intern("sprockets_tls::Stream"),
                size: 64,
                members: vec![MemberDef {
                    name: strings.intern("platform_id"),
                    ty: name,
                    offset: 0,
                }],
            });
            let stream = BundleTypeId(types.types.len() as u32 - 1);
            plan_stream_peer(stream, &[Hop::Member("platform_id")], &types, &strings)
                .map(|path| path.target == name)
        };
        assert_eq!(plan(32, 1, Unsigned, true), Ok(true));
        assert_eq!(plan(1, 1, Unsigned, true), Ok(true));
        for (count, size, encoding, array) in [
            (0, 1, Unsigned, true),
            (32, 2, Unsigned, true),
            (32, 1, Signed, true),
            (32, 1, Unsigned, false),
        ] {
            let (kind, _) = plan(count, size, encoding, array)
                .expect_err(&format!("{count} {size} {encoding:?} {array}"));
            assert_eq!(kind, SemanticIssueKind::MissingLayout);
        }
    }

    /// A handshake is screened by its module, one `{impl#N}`, and the
    /// async fn's own environment: the client's and the server's, under
    /// the review of each one's file, and nothing named near them.
    #[test]
    fn test_a_far_end_rule_screens_the_two_handshakes() {
        let client =
            far_end_rule("sprockets_tls::client::{impl#2}::connect_with_config::{async_fn_env#0}")
                .unwrap();
        assert_eq!(client.review.file, "tls/src/client.rs");
        assert_eq!(client.addr, None);
        let server =
            far_end_rule("sprockets_tls::server::{impl#13}::handshake::{async_fn_env#0}").unwrap();
        assert_eq!(server.review.file, "tls/src/server.rs");
        assert_eq!(server.addr, Some("addr"));
        for name in [
            "sprockets_tls::client::{impl#2}::connect::{async_fn_env#0}",
            "sprockets_tls::client::{impl#}::connect_with_config::{async_fn_env#0}",
            "sprockets_tls::client::{impl#x}::connect_with_config::{async_fn_env#0}",
            "sprockets_tls::client::connect_with_config::{async_fn_env#0}",
            "sprockets_tls::client::{impl#2}::handshake::{async_fn_env#0}",
            "sprockets_tls::server::{impl#1}::handshake::{async_fn_env#1}",
            "sprockets_tls::server::{impl#1}::handshake::{async_fn_env#0}::Suspend0",
            "sprockets_tls::server::{impl#1}::{impl#2}::handshake::{async_fn_env#0}",
            "sprockets_tls_x::server::{impl#1}::handshake::{async_fn_env#0}",
        ] {
            assert!(far_end_rule(name).is_none(), "{name}");
        }
    }

    /// A handshake's far end binds every state holding the stream — as a
    /// local, or inside the handshake future the state awaits — with
    /// the address and the name where the state keeps them, under the
    /// review of the file its body was declared in; a stream that is no
    /// routed TLS stream, an address that is no enum, or no state with
    /// the stream binds nothing, and neither does an unreviewed body.
    #[test]
    fn test_a_far_end_binds_the_states_that_hold_the_stream() {
        use crate::bundle::Encoding::Unsigned;
        const CHECKOUT: &str =
            "/home/u/.cargo/git/checkouts/sprockets-882d17aeeb0cb343/a233079/tls/src";
        let rule =
            far_end_rule("sprockets_tls::server::{impl#1}::handshake::{async_fn_env#0}").unwrap();
        let reviewed = source(
            &format!("{CHECKOUT}/server.rs"),
            Some(rule.review.revisions[2].1),
        );
        // The coroutine: an unresumed state with nothing, one with the
        // stream and both facts, and one with the stream alone — the
        // branch that returns early, whose address nothing reads.
        let plan = |addr_is_enum: bool, holds: bool, source: Option<&PollSource>| {
            let (mut types, mut strings) = (TypeTable::default(), StringInterner::new());
            let push = |types: &mut TypeTable, def| {
                types.types.push(def);
                BundleTypeId(types.types.len() as u32 - 1)
            };
            let u8_t = push(
                &mut types,
                TypeDef::Base {
                    name: strings.intern("u8"),
                    size: 1,
                    encoding: Unsigned,
                },
            );
            let stream = push(
                &mut types,
                TypeDef::Struct {
                    name: strings.intern("tokio_rustls::server::TlsStream<T>"),
                    size: 8,
                    members: Vec::new(),
                },
            );
            let v6 = strings.intern("V6");
            let addr = push(
                &mut types,
                match addr_is_enum {
                    true => TypeDef::Enum {
                        name: strings.intern("core::net::socket_addr::SocketAddr"),
                        size: 1,
                        shape: VariantShape {
                            discr: None,
                            variants: vec![VariantDef {
                                name: v6,
                                discr_values: None,
                                payload: MemberDef {
                                    name: v6,
                                    ty: u8_t,
                                    offset: 0,
                                },
                                decl: None,
                                await_site: None,
                            }],
                        },
                    },
                    false => TypeDef::Base {
                        name: strings.intern("u64"),
                        size: 8,
                        encoding: Unsigned,
                    },
                },
            );
            let bytes = push(
                &mut types,
                TypeDef::Array {
                    elem: u8_t,
                    count: 32,
                },
            );
            let id = push(
                &mut types,
                TypeDef::Struct {
                    name: strings.intern("dice_mfg_msgs::PlatformId"),
                    size: 32,
                    members: vec![MemberDef {
                        name: strings.intern("__0"),
                        ty: bytes,
                        offset: 0,
                    }],
                },
            );
            let local = |strings: &mut StringInterner, name: &str, ty, offset| MemberDef {
                name: strings.intern(name),
                ty,
                offset,
            };
            let suspend = strings.intern("Suspend");
            let state = |types: &mut TypeTable, members: Vec<MemberDef>| {
                push(
                    types,
                    TypeDef::Struct {
                        name: suspend,
                        size: 64,
                        members,
                    },
                )
            };
            let unresumed = state(&mut types, Vec::new());
            let full = match holds {
                true => vec![
                    local(&mut strings, "stream", stream, 0),
                    local(&mut strings, "addr", addr, 8),
                    local(&mut strings, "tq_platform_id", id, 16),
                ],
                false => Vec::new(),
            };
            let full = state(&mut types, full);
            let early = match holds {
                true => vec![local(&mut strings, "stream", stream, 0)],
                false => Vec::new(),
            };
            let early = state(&mut types, early);
            // A handshake in flight — tokio-rustls's `Accept` over its
            // `MidHandshake`, holding the stream in `Handshaking` — and
            // a state awaiting it beside the address, then one awaiting
            // something no handshake is.
            let (zero, handshaking) = (strings.intern("__0"), strings.intern("Handshaking"));
            let holding = push(
                &mut types,
                TypeDef::Struct {
                    name: handshaking,
                    size: 8,
                    members: vec![MemberDef {
                        name: zero,
                        ty: stream,
                        offset: 0,
                    }],
                },
            );
            let mid = push(
                &mut types,
                TypeDef::Enum {
                    name: strings.intern("tokio_rustls::common::handshake::MidHandshake<T>"),
                    size: 8,
                    shape: VariantShape {
                        discr: None,
                        variants: vec![VariantDef {
                            name: handshaking,
                            discr_values: None,
                            payload: MemberDef {
                                name: handshaking,
                                ty: holding,
                                offset: 0,
                            },
                            decl: None,
                            await_site: None,
                        }],
                    },
                },
            );
            let accept = push(
                &mut types,
                TypeDef::Struct {
                    name: strings.intern("tokio_rustls::server::Accept<T>"),
                    size: 8,
                    members: vec![MemberDef {
                        name: zero,
                        ty: mid,
                        offset: 0,
                    }],
                },
            );
            let awaiting = match holds {
                true => vec![
                    local(&mut strings, "addr", addr, 8),
                    local(&mut strings, "__awaitee", accept, 16),
                ],
                false => Vec::new(),
            };
            let awaiting = state(&mut types, awaiting);
            let elsewhere = match holds {
                true => vec![local(&mut strings, "__awaitee", u8_t, 16)],
                false => Vec::new(),
            };
            let elsewhere = state(&mut types, elsewhere);
            let into_stream = vec![
                Step::Member(MemberRef::Named(zero)),
                Step::Variant(handshaking),
                Step::Member(MemberRef::Named(zero)),
            ];
            let variants = [
                ("Unresumed", unresumed),
                ("Suspend0", full),
                ("Suspend1", early),
                ("Suspend2", awaiting),
                ("Suspend3", elsewhere),
            ]
            .map(|(name, ty)| {
                let name = strings.intern(name);
                VariantDef {
                    name,
                    discr_values: None,
                    payload: MemberDef {
                        name,
                        ty,
                        offset: 0,
                    },
                    decl: None,
                    await_site: None,
                }
            })
            .to_vec();
            let coroutine = push(
                &mut types,
                TypeDef::Enum {
                    name: strings
                        .intern("sprockets_tls::server::{impl#1}::handshake::{async_fn_env#0}"),
                    size: 64,
                    shape: VariantShape {
                        discr: None,
                        variants,
                    },
                },
            );
            plan_far_end(
                coroutine,
                rule,
                source,
                &|ty| ty == stream,
                &|ty| (ty == accept).then(|| (into_stream.clone(), stream)),
                &types,
                &strings,
            )
            .map(|plan| {
                let text = |path: &TypedPath| {
                    path.steps
                        .iter()
                        .map(|step| match step {
                            Step::Variant(name) | Step::Member(MemberRef::Named(name)) => {
                                strings.get(*name).unwrap().to_owned()
                            }
                            _ => "?".to_owned(),
                        })
                        .collect::<Vec<_>>()
                        .join(".")
                };
                assert!(matches!(
                    plan.rule,
                    RuleKey::GitDelegation {
                        kind: SemanticRuleKind::SprocketsHandshake,
                        ..
                    }
                ));
                plan.states
                    .iter()
                    .map(|state| {
                        (
                            text(&state.stream),
                            state.addr.as_ref().map(text),
                            state.name.as_ref().map(text),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        };
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(
            plan(true, true, Some(&reviewed)).unwrap(),
            [
                (
                    "Suspend0.stream".to_owned(),
                    some("Suspend0.addr"),
                    some("Suspend0.tq_platform_id.__0")
                ),
                ("Suspend1.stream".to_owned(), None, None),
                (
                    "Suspend2.__awaitee.__0.Handshaking.__0".to_owned(),
                    some("Suspend2.addr"),
                    None
                ),
            ]
        );
        let declined = |result: Result<_, Decline>| result.unwrap_err();
        let (kind, detail) = declined(plan(false, true, Some(&reviewed)));
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert_eq!(detail, "Suspend0's address is no enum in the final table");
        let (kind, detail) = declined(plan(true, false, Some(&reviewed)));
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert_eq!(detail, "no state holds its stream");
        let (kind, detail) = declined(plan(true, true, None));
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
        assert!(detail.contains("no async fn body declaration"), "{detail}");
        let client = source(
            &format!("{CHECKOUT}/client.rs"),
            Some(rule.review.revisions[2].1),
        );
        let (kind, detail) = declined(plan(true, true, Some(&client)));
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
        assert!(detail.contains("not tls/src/server.rs"), "{detail}");
        // The client's checksum on the server's file is no revision's.
        let mismatched = source(
            &format!("{CHECKOUT}/server.rs"),
            Some(SPROCKETS_TLS_CLIENT_D2B68E4.revisions[2].1),
        );
        let (kind, detail) = declined(plan(true, true, Some(&mismatched)));
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
        assert!(detail.contains("not revision a233079's"), "{detail}");
    }

    /// A lock binds the one word it is — a whole integer at its start,
    /// and nothing beside it — held when any of std's futex bits is set;
    /// a word elsewhere, a word with company, or a word of no integer's
    /// size binds nothing.
    #[test]
    fn test_a_lock_word_is_the_whole_lock() {
        use crate::detect::semantics::RUSTC_STD_FUTEX_MUTEX_V1_97;
        let seed = LockSeed::StdFutex(CompilerVerdict::Supported {
            producer: "rustc 1.97.1".to_owned(),
            convention: &RUSTC_STD_FUTEX_MUTEX_V1_97,
        });
        let name = "std::sys::sync::mutex::futex::Mutex";
        let plan = |members: &[(&str, u64, u64)]| {
            let (mut types, mut strings) = (TypeTable::default(), StringInterner::new());
            let ty = words(&mut types, &mut strings, name, members);
            plan_lock(ty, &seed, &types, &strings)
        };
        let (_, word) = plan(&[("futex", 4, 0)]).unwrap();
        assert_eq!(
            word,
            LockWord {
                offset: 0,
                size: 4,
                locked_mask: 0xffff_ffff
            }
        );
        for members in [
            // The one word, but not at the lock's start.
            &[("futex", 4, 4)][..],
            // At the start, but with a second member beside it.
            &[("futex", 4, 0), ("poison", 1, 4)],
            // Alone at the start, but three bytes wide.
            &[("futex", 3, 0)],
        ] {
            let (kind, detail) = plan(members).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::MissingLayout, "{members:?}");
            assert_eq!(detail, "futex is not the lock's one word", "{members:?}");
        }
    }

    /// An io operation's seed, or a handshake's, puts its record in
    /// the table by itself — a build that inlined the operation's
    /// `poll` leaves no declaration to do it.
    #[test]
    fn test_an_io_operation_or_a_handshake_alone_is_its_own_record() {
        assert!(!Seed::default().is_own_record());
        let operation = Seed {
            io_op: Some(IoOpSeed {
                kind: IoOperationKind::Read,
                pointer: "reader",
                sliced: true,
            }),
            ..Seed::default()
        };
        assert!(operation.is_own_record());
        let handshake = Seed {
            handshake: true,
            ..Seed::default()
        };
        assert!(handshake.is_own_record());
    }

    /// Each kind of coroutine environment binds under its own rule, the
    /// async closure's included; a coroutine of no async kind, and any
    /// candidate whose verdict declined, binds under none.
    #[test]
    fn test_each_coroutine_kind_has_its_rule() {
        let seed = Seed {
            compiler: Some(CompilerVerdict::Supported {
                producer: "rustc 1.97.1".to_owned(),
                convention: &crate::detect::semantics::RUSTC_COROUTINE_V1_97,
            }),
            ..Seed::default()
        };
        let kind_of = |name: &str, seed: &Seed| match coroutine_kind_rule(
            BundleTypeId(0),
            seed,
            &[Some(name.to_owned())],
        ) {
            Some(RuleKey::Rustc { kind, .. }) => Some(kind),
            other => {
                assert!(other.is_none(), "{name}: {other:?}");
                None
            }
        };
        for (name, kind) in [
            ("app::run::{async_fn_env#0}", SemanticRuleKind::RustcAsyncFn),
            (
                "app::main::{async_block_env#1}",
                SemanticRuleKind::RustcAsyncBlock,
            ),
            (
                "app::main::{async_closure_env#0}",
                SemanticRuleKind::RustcAsyncClosure,
            ),
        ] {
            assert_eq!(kind_of(name, &seed), Some(kind), "{name}");
        }
        assert_eq!(kind_of("app::gen::{coroutine_env#0}", &seed), None);
        let declined = Seed {
            compiler: Some(CompilerVerdict::Declined("no reviewed producer".to_owned())),
            ..Seed::default()
        };
        assert_eq!(kind_of("app::run::{async_fn_env#0}", &declined), None);
    }
}

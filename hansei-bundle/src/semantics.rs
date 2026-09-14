// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Independent identity, storage, and polling facts. Absence of a capability
//! is unknown; it does not establish that a value contains nothing of interest.

use crate::{BundleTypeId, Step, StrRef, TaskEntryId};

use serde::{Deserialize, Serialize};

pub(crate) mod check;

pub use check::{
    container_roles, container_routes, required_resource_roles, required_resource_routes,
    scheduler_role,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct SemanticRuleId(pub u32);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct SemanticOriginId(pub u32);

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SemanticTable {
    pub origins: Vec<SemanticOrigin>,
    pub rules: Vec<SemanticRule>,
    /// Sparse records, strictly ordered by type id.
    pub types: Vec<TypeSemantics>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TypeSemantics {
    pub ty: BundleTypeId,
    pub storage: StoragePolicy,
    pub future: Option<FutureFacts>,
    pub coroutine: Option<CoroutineLayout>,
    pub access: Option<AccessBinding>,
    pub resource: Option<ResourceBinding>,
    pub container: Option<ContainerBinding>,
    /// The branches this future polls in turn, where it is the
    /// `PollFn` a reviewed `select!` expansion parks in.
    pub select: Option<SelectBinding>,
    pub issues: Vec<SemanticIssue>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum StoragePolicy {
    DeclaredMembers,
    CoroutineStates,
    Unavailable(SemanticIssue),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FutureFacts {
    pub evidence: Vec<FutureEvidence>,
    pub continuation: Continuation,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum FutureEvidence {
    TaskEntry(TaskEntryId),
    /// Canonical linkage key, never a display-demangled name or drop glue.
    PollSymbol(StrRef),
    Coroutine(SemanticRuleId),
    DelegatedBy {
        parent: BundleTypeId,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Continuation {
    Unknown(SemanticIssue),
    Bound {
        rule: SemanticRuleId,
        program: PollProgram,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PollProgram {
    Direct(PollAction),
    MatchVariant {
        state: TypedPath,
        cases: Vec<PollCase>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PollCase {
    pub variant: StrRef,
    pub action: PollAction,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PollAction {
    /// Exclusivity needs a reviewed control-flow guarantee in addition to
    /// the ordinary forwarding rule. A single path does not establish it.
    Delegate {
        target: FutureTarget,
        exclusive: bool,
    },
    Primitive,
    Unresumed,
    Returned,
    Panicked,
    /// The reviewed implementation returns `Poll::Pending` without
    /// touching its `Context`: it registers no waker, polls nothing,
    /// and no poll of it ever returns `Ready`. A terminal about
    /// readiness, not waking — a spurious or stale wake still
    /// schedules the task, which polls this and parks again. Legal
    /// only as a whole program, never as a state's case: no reviewed
    /// matcher has a state that means this.
    NeverReady,
    Unknown(SemanticIssue),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TypedPath {
    /// Literal, name-addressed steps from the nominal future root. Case
    /// actions also start at that root, not at the selected payload.
    pub steps: Vec<Step>,
    pub target: BundleTypeId,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FutureTarget {
    Value(TypedPath),
    Dynamic {
        pointer: TypedPath,
        layout: DynFutureLayout,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DynFutureLayout {
    pub abi: SemanticRuleId,
    /// Paths relative to the wide-pointer value, not the future root.
    pub data: TypedPath,
    pub vtable: TypedPath,
    pub trait_ty: BundleTypeId,
    pub drop_slot: u32,
    pub size_slot: u32,
    pub align_slot: u32,
    /// Where `Future::poll` sits, when the reviewed ABI places it: the
    /// trait object is a bare `dyn Future`, whose one method is the
    /// poll. A trait object of another trait that has `Future` as a
    /// supertrait carries a poll too, but which slot holds it depends
    /// on that trait's own declaration order, which no reviewed
    /// convention covers — the slot is then `None` and identity comes
    /// from the drop glue alone.
    pub poll_slot: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoroutineLayout {
    pub rule: SemanticRuleId,
    pub states: Vec<CoroutineState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoroutineState {
    pub variant: StrRef,
    pub stage: CoroutinePhase,
    pub locals: Vec<StrRef>,
    pub uncertain_locals: Vec<StrRef>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CoroutinePhase {
    Unresumed,
    Suspended,
    Returned,
    Panicked,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AccessBinding {
    pub rule: SemanticRuleId,
    pub kind: AccessKind,
    pub target: FutureTarget,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AccessKind {
    Owned,
    Borrowed,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResourceBinding {
    pub rule: SemanticRuleId,
    pub kind: ResourceKind,
    pub state_rule: Option<SemanticRuleId>,
    pub exclusive_pending: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ResourceKind {
    Sleep,
    JoinHandle,
    SemaphoreAcquire,
    IoOperation(IoOperationKind),
    /// The bounded mpsc `Receiver::recv` future: the `PollFn` its
    /// `async fn` awaits, whose closure holds the receiver's `Rx`.
    MpscRecv,
    /// `tokio::sync::notify::Notified`, the borrowed form.
    Notified,
    /// `tokio::sync::oneshot::Receiver<T>`, which is its own future:
    /// its `poll` reads the shared `Inner`'s state word.
    OneshotRecv,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IoOperationKind {
    Read,
    WriteAll,
    Readiness,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ContainerBinding {
    pub rule: SemanticRuleId,
    pub kind: ContainerKind,
    /// Whose waker the container hands its children; fixed by the
    /// kind ([`ContainerKind::wakers`]) and recorded beside it so a
    /// consumer reads the fact it dispatches on rather than
    /// re-deriving it.
    pub wakers: ContainerWakers,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ContainerKind {
    JoinSet,
    FuturesUnordered,
    /// tokio-stream's `StreamMap<K, V>`: a `Vec<(K, V)>` of streams
    /// polled in turn with the polling task's own context, every
    /// pending one keeping its registration.
    StreamMap,
}

/// Whose waker a container's children are polled with.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ContainerWakers {
    /// The container's own per-child waker (`FuturesUnordered`,
    /// `JoinSet`): a child's registration names the container, and
    /// the task polling the container is woken through it.
    Own,
    /// The polling task's context, forwarded unchanged (`StreamMap`):
    /// every child's registration names the task itself.
    Forwarded,
}

impl ContainerKind {
    /// How the kind polls its children; the reviewed implementation's
    /// business, not the target's.
    pub fn wakers(self) -> ContainerWakers {
        match self {
            ContainerKind::JoinSet | ContainerKind::FuturesUnordered => ContainerWakers::Own,
            ContainerKind::StreamMap => ContainerWakers::Forwarded,
        }
    }
}

/// A `select!` as tokio's macro lays it out around the `PollFn` it
/// awaits: the closure borrows the branch mask and the tuple of branch
/// futures from the enclosing frame, and polls each tuple member whose
/// bit in the mask is clear. Member `i` of the tuple is branch `i` in
/// source order; bit `i` set means that branch is disabled — by a
/// false precondition before the first poll, or by a completed output
/// that missed its pattern — and is polled no more. Which of the two
/// set it is not recorded anywhere in memory.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SelectBinding {
    pub rule: SemanticRuleId,
    /// From the future root to the mask word itself, through the
    /// closure's reference: an unsigned integer of 1, 2, 4 or 8 bytes,
    /// the width tokio-macros picks by branch count.
    pub mask: TypedPath,
    /// From the future root to the tuple of branch futures, through the
    /// closure's reference.
    pub futures: TypedPath,
    /// Branch `i`, as a path from the tuple: its member `__i` and the
    /// future type that member holds.
    pub branches: Vec<TypedPath>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SemanticRule {
    pub kind: SemanticRuleKind,
    pub revision: u32,
    pub origin: SemanticOriginId,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum SemanticRuleKind {
    RustcAsyncFn,
    RustcAsyncBlock,
    DynFutureAbi,
    StdBoxAccess,
    StdMutRefAccess,
    StdPinBoxAccess,
    StdPinMutRefAccess,
    StdBoxPoll,
    StdMutRefPoll,
    StdPinBoxPoll,
    StdPinMutRefPoll,
    TokioSleep,
    TokioJoinHandle,
    TokioAcquire,
    TokioJoinSet,
    TokioSleepState,
    TokioJoinHandleState,
    TokioAcquireState,
    TokioIoOperation,
    TokioIoState,
    TokioMultiThreadScheduler,
    TokioCurrentThreadScheduler,
    TokioLocalScheduler,
    TokioBlockingScheduler,
    FuturesUnordered,
    TracingInstrumented,
    TokioMpscRecv,
    TokioMpscRecvState,
    TokioNotified,
    TokioNotifiedState,
    /// futures-util's `map` combinator: the public `delegate_all!`
    /// newtype and the `map::Map` enum it forwards into.
    FuturesUtilMap,
    /// futures-util's `map_err`: a `delegate_all!` newtype over a `Map`.
    FuturesUtilMapErr,
    /// futures-util's `into_future`.
    FuturesUtilIntoFuture,
    /// hyper-util's `TokioSleep`, the newtype that gives
    /// `tokio::time::Sleep` an `Unpin` trait object.
    HyperUtilTokioSleep,
    TokioOneshotRecv,
    TokioOneshotRecvState,
    /// tokio's `select!` expansion: the `PollFn` closure that borrows
    /// the branch mask and the tuple of branch futures.
    TokioSelect,
    /// tokio's `task::coop::Coop<F>`, the cooperative-budget wrapper
    /// `cooperative()` puts around a leaf future: its poll spends a
    /// budget unit, then polls `fut` and nothing else.
    TokioCoop,
    /// futures-util's `stream::Next<'_, St>`, the `StreamExt::next`
    /// future: `{ stream: &mut St }`, whose poll is the stream's
    /// `poll_next` and nothing else. Its delegate is a stream, so the
    /// route proves nothing about it being a future.
    FuturesUtilNext,
    /// tokio-stream's `WatchStream<T>`: an access binding, not a
    /// future — polling the stream polls the one `ReusableBoxFuture`
    /// it owns.
    TokioStreamWatchStream,
    /// tokio-util's `ReusableBoxFuture<'_, T>`: an access binding
    /// through `boxed`, the `Pin<Box<dyn Future>>` its every poll
    /// forwards to.
    TokioUtilReusableBox,
    /// tokio-stream's `StreamMap<K, V>`: a container binding over its
    /// `entries`, each polled with the polling task's own context.
    TokioStreamStreamMap,
    /// tokio's `Interval::tick`: the `PollFn` over the closure the
    /// async fn awaits, whose pending path polls the `Pin<Box<Sleep>>`
    /// in the interval's `delay` and nothing else. The route runs
    /// through the closure's capture to the interval and lands on
    /// the box; its std record crosses to the `Sleep`.
    TokioIntervalTick,
    /// core's `future::pending::Pending<T>`, the future
    /// `std::future::pending()` returns: `poll` returns `Poll::Pending`
    /// and does nothing else. A compiler-origin rule, since the source
    /// it reviews ships with the toolchain.
    CorePending,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum SemanticOrigin {
    Rustc {
        producer: StrRef,
        family: StrRef,
    },
    LibraryLayout {
        package: StrRef,
        version: Option<StrRef>,
        family: StrRef,
        selection: LayoutSelection,
    },
    /// A third-party implementation a reviewed delegation rule forwards
    /// through, identified the way its family was selected: the crate
    /// and version its declaration file's cargo registry path spells.
    LibraryDelegation {
        package: StrRef,
        version: StrRef,
        /// The reviewed implementation family the version selected.
        family: StrRef,
        /// The declaration file the origin was read from, cut to its
        /// `registry/src/` tail (see [`crate::origin::registry_origin`]).
        source: StrRef,
        /// Line-table checksums corroborating the reviewed revision, when
        /// the unit's file table carried any. rustc's DWARF 4 builds carry
        /// none, and the list is then empty: the registry path is the
        /// evidence the rule runs on, a checksum a check on top of it.
        files: Vec<SourceFileEvidence>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LayoutSelection {
    ReviewedRange,
    BelowFloor,
    AboveReviewedRange,
    VersionUnknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SourceFileEvidence {
    pub file: StrRef,
    pub md5: [u8; 16],
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SemanticIssue {
    pub kind: SemanticIssueKind,
    pub detail: Option<StrRef>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum SemanticIssueKind {
    NoRule,
    UnsupportedOrigin,
    MissingLayout,
    AmbiguousLayout,
    UnsupportedState,
    MultipleChildren,
    PossiblyUninitialized,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum SchedulerClass {
    MultiThread,
    CurrentThread,
    LocalSet,
    Blocking,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SchedulerBinding {
    pub class: SchedulerClass,
    pub rule: SemanticRuleId,
}

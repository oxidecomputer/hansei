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
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ContainerKind {
    JoinSet,
    FuturesUnordered,
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

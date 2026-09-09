// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a task's inspection means: the one interpretation of a chain
//! and a resource observation as a wait, and the conditional polling
//! barrier an exclusive chain proves about a future a task holds.
//!
//! An assessment is made in a fixed order. The task's state word comes
//! first: a complete task waits on nothing, a running or queued one is
//! runnable, and no saved resource state overrides either. Then the
//! chain's end: a terminal coroutine state is its own answer, a chain
//! cut short or ending in an unknown continuation is unknown with that
//! cause, and only a chain ending in a bound primitive goes on to the
//! resource. There the resource's reviewed state protocol — the
//! bundle's `state_rule` — is required before any word it holds is
//! read as ready or as a wait; a layout binding alone observes and
//! never assesses. Under a protocol, the observation is held to the
//! exact conditions the protocol reviewed: a fully granted acquire is
//! ready, a queued one waits only if the quiescent queue holds its node
//! once with this task's waker on it, a socket operation waits only if
//! no readiness the direction wants has been delivered, the resource
//! is not shut down, and this task's waker sits in the direction's
//! slot. Anything the protocol cannot account for is unknown, with the
//! reason, and the raw observation is kept beside it.
//!
//! What an assessment is not: a claim that the task can never receive
//! another poll (a cooperative-budget wake may be deferred outside the
//! state word), or a claim about any task but this one. A verified wait
//! is the saved resource dependency this task's own storage records,
//! and the type boundary around [`VerifiedWait`] is what keeps every
//! consumer from turning a weaker relation into one.

use super::bundle::{
    AwaitChain, ChainEnd, Context, IoResourceInfo, IoSlot, QueuedWaker, Task, TaskKind, TaskList,
    WaitTarget, semaphore_owner,
};
use super::chain::{FutureInspection, InspectionMode};
use super::observe::{
    AcquireObservation, Consistency, IoFutureState, IoObservation, JoinObservation, Observed,
    QueueObservation, ReadContext, ResourceObservation, ScanBudget, TimerObservation,
    TimerRegistrationState, ValueKey,
};
use super::{Lifecycle, TaskAddr, TaskState};

use hansei_bundle::{AccessKind, FutureTarget, IoOperationKind, SemanticIssueKind, Step};
use proc::Target;

use foldhash::{HashMap, HashSet};

/// The one interpretation of a task's inspection.
#[derive(Debug)]
pub enum WaitAssessment {
    /// The task is not waiting: it is complete, or its root has run to
    /// a terminal state.
    NotWaiting(NotWaitingReason),
    /// The task can be polled without any resource's help: it is in a
    /// run queue, or mid-poll right now.
    Runnable(RunnableReason),
    /// The root has never been polled. Its storage holds arguments and
    /// awaits nothing; whether the scheduler has enqueued it is the
    /// state word's business, not this one's.
    Unresumed,
    /// The resource the chain ends in has already given what was asked
    /// of it; the task merely awaits its next poll.
    ResourceReady(ReadyReason),
    /// The saved resource dependency the task's storage records, held
    /// to the resource's reviewed protocol.
    Waiting(VerifiedWait),
    /// No definite answer, for the reason given. The inspection still
    /// carries whatever was read.
    Unknown(WaitUnknownReason),
}

impl WaitAssessment {
    /// The verified wait, when this is one.
    pub fn verified(&self) -> Option<&VerifiedWait> {
        match self {
            WaitAssessment::Waiting(wait) => Some(wait),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NotWaitingReason {
    Complete,
    Returned,
    Panicked,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RunnableReason {
    /// `NOTIFIED`: pushed into a run queue.
    Scheduled,
    /// `RUNNING`: mid-poll on some thread.
    ActivePoll,
}

/// What a ready resource has already done.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ReadyReason {
    /// The joined task is complete; its output awaits the next poll.
    JoinComplete,
    /// The acquire has been assigned every permit it asked for.
    PermitsGranted,
    /// The semaphore is closed; the next poll returns the error.
    SemaphoreClosed,
    /// Readiness the operation wants has been delivered. An attempt
    /// may follow; nothing here says it completes.
    IoReady,
    /// The io driver has shut the resource down.
    IoShutdown,
    /// The readiness await's own node has been notified.
    IoNotified,
    /// The timer entry has fired and awaits the poll that reads it.
    TimerFired,
    /// The driver has marked the entry to fire; the wake is on its way.
    TimerPendingFire,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WaitUnknownReason {
    /// The chain does not end in a primitive: a continuation no rule
    /// establishes, an unresolved trait object, a cut.
    Continuation,
    /// The primitive, or a structure its protocol reads, could not be
    /// read.
    ResourceUnreadable,
    /// The resource has no reviewed state protocol, or what its
    /// protocol reads is not in a state the protocol vouches for — a
    /// queue read under its lock, a waker slot that is not a task's.
    ResourceStateUnproven,
    /// The task's state word and its storage disagree about lifecycle.
    Lifecycle,
    /// The task's kind is in conflict; reserved for the reconciliation
    /// of task evidence, which nothing here produces yet.
    TaskKind,
    /// What was read contradicts the protocol: a node absent from the
    /// queue it should be in, another task's waker where this one's
    /// should be, permits free beside a nonempty queue.
    ConflictingEvidence,
}

/// A definite wait: the resource dependency the task's own storage
/// records, verified under the resource's reviewed protocol. Built only
/// by the assessor, so an unvalidated target cannot become one.
#[derive(Clone, Debug)]
pub struct VerifiedWait {
    target: WaitTarget,
    primitive: ValueKey,
    queue_position: Option<usize>,
}

impl VerifiedWait {
    /// The structured target, as the wait-target renderers spell it.
    pub fn target(&self) -> &WaitTarget {
        &self.target
    }

    /// The primitive the wait was read from.
    pub fn primitive(&self) -> ValueKey {
        self.primitive
    }

    /// For a semaphore wait, the node's place in wake order — the
    /// waiters at greater positions are the only ones it precedes.
    pub fn queue_position(&self) -> Option<usize> {
        self.queue_position
    }

    /// The target, given up to a consumer that renders it.
    pub fn into_target(self) -> WaitTarget {
        self.target
    }

    /// A verified wait laid out by hand, for a listing test over a
    /// population no fixture holds. Test-only: production construction
    /// is the assessor's alone.
    #[cfg(feature = "testkit")]
    pub fn testkit(target: WaitTarget, queue_position: Option<usize>) -> Self {
        VerifiedWait {
            target,
            primitive: ValueKey {
                addr: 0,
                ty: hansei_bundle::BundleTypeId(0),
            },
            queue_position,
        }
    }
}

/// Why a continuation is not established, in words a listing prints.
pub fn continuation_reason(reason: SemanticIssueKind) -> &'static str {
    use SemanticIssueKind::*;
    match reason {
        NoRule => "no reviewed rule covers its implementation",
        UnsupportedOrigin => "its implementation's origin is not reviewed",
        MissingLayout => "its layout is not in the tokio info",
        AmbiguousLayout => "its layout is ambiguous",
        UnsupportedState => "its state is one no rule covers",
        MultipleChildren => "it polls more than one future",
        PossiblyUninitialized => "its storage may not be initialized",
    }
}

/// A chain's end as an owned, compact status: what a task row keeps
/// after the chain itself is dropped.
#[derive(Clone, Debug)]
pub enum ContinuationStatus {
    Primitive,
    Unresumed,
    Returned,
    Panicked,
    ActivePoll,
    Unknown {
        at: ValueKey,
        reason: SemanticIssueKind,
    },
    Incomplete {
        reason: IncompleteReason,
        /// The error's rendering, kept only for an error end.
        detail: Option<String>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IncompleteReason {
    UnknownDyn,
    AmbiguousDyn,
    DepthLimit,
    Cycle,
    Error,
    /// No chain was walked: the task's future type is not known, or
    /// its stage holds no resident future.
    NoRoot,
}

impl ContinuationStatus {
    /// The projection of a chain's end, by exhaustive match.
    pub fn of(end: &ChainEnd) -> Self {
        match end {
            ChainEnd::Primitive => ContinuationStatus::Primitive,
            ChainEnd::Unresumed => ContinuationStatus::Unresumed,
            ChainEnd::Returned => ContinuationStatus::Returned,
            ChainEnd::Panicked => ContinuationStatus::Panicked,
            ChainEnd::ActivePoll => ContinuationStatus::ActivePoll,
            ChainEnd::UnknownContinuation { at, reason } => ContinuationStatus::Unknown {
                at: *at,
                reason: *reason,
            },
            ChainEnd::UnknownDyn { .. } => ContinuationStatus::Incomplete {
                reason: IncompleteReason::UnknownDyn,
                detail: None,
            },
            ChainEnd::AmbiguousDyn { .. } => ContinuationStatus::Incomplete {
                reason: IncompleteReason::AmbiguousDyn,
                detail: None,
            },
            ChainEnd::DepthLimit => ContinuationStatus::Incomplete {
                reason: IncompleteReason::DepthLimit,
                detail: None,
            },
            ChainEnd::Cycle { .. } => ContinuationStatus::Incomplete {
                reason: IncompleteReason::Cycle,
                detail: None,
            },
            ChainEnd::Error(e) => ContinuationStatus::Incomplete {
                reason: IncompleteReason::Error,
                detail: Some(format!("{e:#}")),
            },
        }
    }
}

/// The assessed task's own facts: its identity, state word and kind.
/// Read off a listed task or a decoded header alike.
#[derive(Copy, Clone, Debug)]
pub struct TaskFacts {
    pub addr: TaskAddr,
    pub task_id: Option<u64>,
    pub state: TaskState,
    /// What discovery established the task to be — a kind in
    /// conflict prevents the diagnoses that depend on one.
    pub kind: TaskKind,
}

impl From<&Task> for TaskFacts {
    fn from(task: &Task) -> Self {
        TaskFacts {
            addr: task.addr,
            task_id: task.task_id,
            state: task.state,
            kind: task.kind,
        }
    }
}

/// One assessment, with what the protocol read that decided or
/// declined it, in words.
#[derive(Debug)]
pub struct Assessed {
    pub assessment: WaitAssessment,
    pub notes: Vec<String>,
}

impl Assessed {
    fn unknown(reason: WaitUnknownReason, note: impl Into<String>) -> Self {
        Assessed {
            assessment: WaitAssessment::Unknown(reason),
            notes: vec![note.into()],
        }
    }

    fn of(assessment: WaitAssessment) -> Self {
        Assessed {
            assessment,
            notes: Vec::new(),
        }
    }
}

/// The observations one analysis pass shares: each semaphore's queue
/// and each io registration read once, whoever asks. An observation
/// that came back incomplete stays incomplete on reuse.
pub struct AssessmentPass {
    queues: HashMap<ValueKey, QueueObservation>,
    registrations: HashMap<ValueKey, Observed<IoResourceInfo>>,
    pub budget: ScanBudget,
}

impl Default for AssessmentPass {
    fn default() -> Self {
        Self::new()
    }
}

impl AssessmentPass {
    pub fn new() -> Self {
        AssessmentPass {
            queues: HashMap::default(),
            registrations: HashMap::default(),
            budget: ScanBudget::default(),
        }
    }

    /// The queue of `semaphore`, read on first demand.
    pub fn queue<'b, T: Target>(
        &mut self,
        ctx: &Context<'b, T>,
        semaphore: ValueKey,
        read: &ReadContext<'_>,
    ) -> &QueueObservation {
        if !self.queues.contains_key(&semaphore) {
            let queue = ctx.observe_semaphore_queue(semaphore, read, &mut self.budget);
            self.queues.insert(semaphore, queue);
        }
        &self.queues[&semaphore]
    }

    /// The registration at `scheduled_io`, read on first demand.
    pub fn registration<'b, T: Target>(
        &mut self,
        ctx: &Context<'b, T>,
        scheduled_io: ValueKey,
        read: &ReadContext<'_>,
    ) -> &Observed<IoResourceInfo> {
        if !self.registrations.contains_key(&scheduled_io) {
            let registration = ctx.observe_io_registration(scheduled_io, read, &mut self.budget);
            self.registrations.insert(scheduled_io, registration);
        }
        &self.registrations[&scheduled_io]
    }
}

/// tokio's `Ready` bits, as the readiness word's low half packs them.
mod ready {
    pub const READABLE: u64 = 0b1;
    pub const WRITABLE: u64 = 0b10;
    pub const READ_CLOSED: u64 = 0b100;
    pub const WRITE_CLOSED: u64 = 0b1000;
    /// The delivered `Ready` set occupies the low sixteen bits.
    pub const MASK: u64 = 0xffff;
    /// The shutdown flag sits above the sixteen readiness bits and the
    /// fifteen tick bits.
    pub const SHUTDOWN: u64 = 1 << 31;

    /// The readiness a direction's mask accepts: the bit itself or its
    /// closed counterpart, as `Direction::mask` spells it.
    pub fn direction_mask(interest: u64) -> u64 {
        let mut mask = interest;
        if interest & READABLE != 0 {
            mask |= READ_CLOSED;
        }
        if interest & WRITABLE != 0 {
            mask |= WRITE_CLOSED;
        }
        mask
    }
}

impl<'b, T: Target> Context<'b, T> {
    /// Assess one task's inspection. `list` says whether a joined task
    /// is one any listing shows, for the target's rendering; the join
    /// itself is verified from the joined header, not from the list.
    pub fn assess_wait(
        &self,
        pass: &mut AssessmentPass,
        inspection: &FutureInspection<'b>,
        task: &TaskFacts,
        list: &TaskList,
        read: &ReadContext<'_>,
    ) -> Assessed {
        match task.state.lifecycle() {
            Lifecycle::Complete => {
                return Assessed::of(WaitAssessment::NotWaiting(NotWaitingReason::Complete));
            }
            Lifecycle::Running => {
                return Assessed::of(WaitAssessment::Runnable(RunnableReason::ActivePoll));
            }
            Lifecycle::Queued => {
                return Assessed::of(WaitAssessment::Runnable(RunnableReason::Scheduled));
            }
            Lifecycle::Idle => {}
        }
        // A task claimed as both a scheduler-owned task and a blocking
        // cell is neither for the purpose of a wait: what its storage
        // holds is read, but no wait is diagnosed from it.
        if task.kind == TaskKind::Conflict {
            return Assessed::unknown(
                WaitUnknownReason::TaskKind,
                "the task's kind is in conflict: it was claimed as both a scheduler-owned \
                 task and a blocking cell",
            );
        }
        let chain = &inspection.chain;
        match &chain.end {
            ChainEnd::Returned => {
                return Assessed::of(WaitAssessment::NotWaiting(NotWaitingReason::Returned));
            }
            ChainEnd::Panicked => {
                return Assessed::of(WaitAssessment::NotWaiting(NotWaitingReason::Panicked));
            }
            ChainEnd::Unresumed => return Assessed::of(WaitAssessment::Unresumed),
            ChainEnd::ActivePoll => {
                return Assessed::unknown(
                    WaitUnknownReason::Lifecycle,
                    "the chain was walked as mid-poll, but the state word reads idle",
                );
            }
            ChainEnd::Primitive => {}
            ChainEnd::UnknownContinuation { reason, .. } => {
                let last = chain
                    .frames
                    .last()
                    .map(|f| f.future.ty.name())
                    .unwrap_or("the root");
                return Assessed::unknown(
                    WaitUnknownReason::Continuation,
                    format!(
                        "what {last} polls is not established: {}",
                        continuation_reason(*reason)
                    ),
                );
            }
            ChainEnd::UnknownDyn { .. }
            | ChainEnd::AmbiguousDyn { .. }
            | ChainEnd::DepthLimit
            | ChainEnd::Cycle { .. }
            | ChainEnd::Error(_) => {
                return Assessed::unknown(
                    WaitUnknownReason::Continuation,
                    format!("the chain is incomplete: {:?}", chain.end),
                );
            }
        }
        let Some(leaf) = chain.primitive_leaf() else {
            return Assessed::unknown(WaitUnknownReason::Continuation, "no primitive frame");
        };
        let Some(observation) = &inspection.primitive.value else {
            let mut assessed = Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                "the primitive observed nothing",
            );
            assessed
                .notes
                .extend(inspection.primitive.issues.iter().map(|issue| {
                    format!(
                        "{:?}: {}",
                        issue.kind,
                        issue.detail.as_deref().unwrap_or("")
                    )
                }));
            return assessed;
        };
        let binding = self
            .type_semantics(leaf.ty.id())
            .and_then(|record| record.resource.as_ref());
        if binding.is_none_or(|binding| binding.state_rule.is_none()) {
            return Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                format!(
                    "{} has no reviewed state protocol on this tokio",
                    leaf.ty.name()
                ),
            );
        }
        let primitive = ValueKey::of(leaf);
        match observation {
            ResourceObservation::Join(join) => self.assess_join(join, task, list, primitive, read),
            ResourceObservation::Acquire(acquire) => {
                self.assess_acquire(pass, acquire, task, chain, primitive, read)
            }
            ResourceObservation::Io(io) => self.assess_io(pass, io, task, chain, primitive, read),
            ResourceObservation::Timer(timer) => self.assess_timer(timer, primitive),
        }
    }

    /// The join protocol: the joined header's `COMPLETE` bit says the
    /// output is there; short of that, the handle's poll stored this
    /// task's waker in the joined trailer, or it did not park here.
    fn assess_join(
        &self,
        join: &JoinObservation,
        task: &TaskFacts,
        list: &TaskList,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        let header = match self.read_task_header(join.header, read) {
            Ok(header) => header,
            Err(e) => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    format!("the joined task's header did not read: {e:#}"),
                );
            }
        };
        let state = header.state;
        if state.is_complete() {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::JoinComplete));
        }
        if !state.is_join_interested() {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "the joined task records no join interest, yet a handle awaits it",
            );
        }
        if !state.is_join_waker_set() {
            return Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                "the joined task holds no join waker: the handle's poll may not have \
                 reached it (a deferred wake can be pending)",
            );
        }
        let addr = join.header.0;
        let task_id = header.task_id;
        let listed = list.contains(addr);
        let kind = if listed {
            None
        } else {
            self.header_unlisted_kind(addr)
        };
        match self.trailer_waker(&header.into_task()) {
            Ok(QueuedWaker::Task { addr: waker, .. }) if waker == task.addr.0 => {
                Assessed::of(WaitAssessment::Waiting(VerifiedWait {
                    target: WaitTarget::Task {
                        addr,
                        task_id,
                        state,
                        listed,
                        kind,
                    },
                    primitive,
                    queue_position: None,
                }))
            }
            Ok(QueuedWaker::Task { addr: other, .. }) => Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!("the joined task's waker names the task at {other:#x}, not this one"),
            ),
            Ok(QueuedWaker::Other { vtable }) => Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                format!("the joined task's waker is not a task's (vtable {vtable:#x})"),
            ),
            Ok(QueuedWaker::Unarmed) => Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                "the joined task's waker slot is empty though its state says one is set",
            ),
            Err(e) => Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                format!("the joined task's trailer did not read: {e:#}"),
            ),
        }
    }

    /// The acquire protocol: closed means the next poll errors, a zero
    /// counter means granted whole, and a wait needs the queued bit,
    /// an open semaphore with no free permits, and the node found once
    /// in a complete quiescent queue with this task's waker on it.
    fn assess_acquire(
        &self,
        pass: &mut AssessmentPass,
        acquire: &AcquireObservation,
        task: &TaskFacts,
        chain: &AwaitChain<'b>,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        if acquire.needed > acquire.requested {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!(
                    "the node needs {} permits of {} requested",
                    acquire.needed, acquire.requested
                ),
            );
        }
        let queue = pass.queue(self, acquire.semaphore, read);
        if queue.closed == Some(true) || queue.queue_closed == Some(true) {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::SemaphoreClosed));
        }
        if acquire.needed == 0 {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::PermitsGranted));
        }
        if !acquire.queued {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "the acquire still needs permits but was never queued",
            );
        }
        let (Some(closed), Some(available)) = (queue.closed, queue.available) else {
            return Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                "the semaphore's permit word did not read",
            );
        };
        debug_assert!(!closed);
        if !queue.established() {
            let why = match queue.consistency {
                Consistency::Mutating => "its lock is held".to_owned(),
                Consistency::Unknown => "its guard could not be decoded".to_owned(),
                Consistency::Quiescent => format!(
                    "the walk stopped short: {}",
                    queue
                        .issues
                        .iter()
                        .map(|issue| issue.detail.clone().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            };
            return Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                format!("the wait queue is not a quiescent snapshot: {why}"),
            );
        }
        if queue.contains(acquire.node) != Some(true) {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!(
                    "the node at {:#x} is not in the semaphore's queue",
                    acquire.node
                ),
            );
        }
        if queue
            .waiters
            .iter()
            .filter(|waiter| waiter.addr == acquire.node)
            .count()
            != 1
        {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "the node appears more than once in the queue",
            );
        }
        let waiter = queue
            .waiters
            .iter()
            .find(|waiter| waiter.addr == acquire.node)
            .expect("contained once");
        if waiter.needed != acquire.needed {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!(
                    "the queue read the node needing {} permits, the future {}",
                    waiter.needed, acquire.needed
                ),
            );
        }
        match &waiter.waker {
            QueuedWaker::Task { addr, .. } if *addr == task.addr.0 => {}
            QueuedWaker::Task { addr, .. } => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    format!("the node's waker names the task at {addr:#x}, not this one"),
                );
            }
            QueuedWaker::Other { vtable } => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the node's waker is not a task's (vtable {vtable:#x})"),
                );
            }
            QueuedWaker::Unarmed => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    "the queued node holds no waker",
                );
            }
        }
        if available > 0 {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!("{available} permits are free beside a nonempty queue"),
            );
        }
        let queue_position = queue.position(acquire.node);
        Assessed::of(WaitAssessment::Waiting(VerifiedWait {
            target: WaitTarget::Semaphore {
                addr: acquire.semaphore.addr,
                owner: semaphore_owner(chain),
                num_permits: acquire.requested,
                available,
                closed: false,
                waiters: queue.waiters.clone(),
            },
            primitive,
            queue_position,
        }))
    }

    /// The io protocol: shutdown or delivered readiness the operation
    /// wants means ready; a wait needs a quiescent registration with
    /// this task's waker in the direction's slot — or, for a readiness
    /// await, its own node listed with this task's waker, its interest,
    /// and its ready flag clear.
    fn assess_io(
        &self,
        pass: &mut AssessmentPass,
        io: &IoObservation,
        task: &TaskFacts,
        chain: &AwaitChain<'b>,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        if io.operation == IoOperationKind::WriteAll && io.remaining == Some(0) {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "an exhausted write completes without parking",
            );
        }
        match (io.operation, io.readiness_state) {
            (IoOperationKind::Readiness, Some(IoFutureState::Init)) => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    "a readiness await in its initial state has not parked",
                );
            }
            (IoOperationKind::Readiness, Some(IoFutureState::Done)) => {
                return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::IoNotified));
            }
            (IoOperationKind::Readiness, Some(IoFutureState::Unknown(word))) => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the readiness await's state word {word:#x} names no state"),
                );
            }
            (IoOperationKind::Readiness, None) => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    "the readiness await's state did not read",
                );
            }
            _ => {}
        }
        if io.waiter_ready == Some(true) {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::IoNotified));
        }
        let registration = pass.registration(self, io.scheduled_io, read);
        let Some(resource) = &registration.value else {
            return Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                "the registration did not read",
            );
        };
        let Some(word) = resource.readiness else {
            return Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                "the registration's readiness word did not read",
            );
        };
        if word & ready::SHUTDOWN != 0 {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::IoShutdown));
        }
        if word & ready::MASK & ready::direction_mask(io.interest.0) != 0 {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::IoReady));
        }
        if resource.consistency != Consistency::Quiescent {
            return Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                match resource.consistency {
                    Consistency::Mutating => "the registration's waiters are locked",
                    _ => "the registration's guard could not be decoded",
                },
            );
        }
        let target = WaitTarget::Io {
            addr: io.scheduled_io.addr,
            fd: self.io_resource_fd(&payloads(chain), io.scheduled_io.addr),
            interest: Some(io.interest),
        };
        let waiting = || {
            Assessed::of(WaitAssessment::Waiting(VerifiedWait {
                target,
                primitive,
                queue_position: None,
            }))
        };
        match io.operation {
            IoOperationKind::Read | IoOperationKind::WriteAll => {
                let slot = if io.operation == IoOperationKind::Read {
                    IoSlot::Reader
                } else {
                    IoSlot::Writer
                };
                let Some(waiter) = resource.waiters.iter().find(|w| w.slot == slot) else {
                    return Assessed::unknown(
                        WaitUnknownReason::ConflictingEvidence,
                        format!("no waker is parked in the {slot:?} slot"),
                    );
                };
                match waiter.task {
                    Some(addr) if addr == task.addr.0 => waiting(),
                    Some(addr) => Assessed::unknown(
                        WaitUnknownReason::ConflictingEvidence,
                        format!("the {slot:?} slot holds the task at {addr:#x}, not this one"),
                    ),
                    None => Assessed::unknown(
                        WaitUnknownReason::ResourceStateUnproven,
                        format!("the {slot:?} slot's waker is not a task's"),
                    ),
                }
            }
            IoOperationKind::Readiness => {
                let Some(node) = io.waiter_node else {
                    return Assessed::unknown(
                        WaitUnknownReason::ResourceUnreadable,
                        "the readiness await's node did not read",
                    );
                };
                let Some(waiter) = resource.waiters.iter().find(|w| w.node == Some(node)) else {
                    return Assessed::unknown(
                        WaitUnknownReason::ConflictingEvidence,
                        format!("the await's node at {node:#x} is not on the registration's list"),
                    );
                };
                if waiter.ready == Some(true) {
                    return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::IoNotified));
                }
                if let IoSlot::Listed {
                    interest: Some(interest),
                } = waiter.slot
                    && interest != io.interest
                {
                    return Assessed::unknown(
                        WaitUnknownReason::ConflictingEvidence,
                        format!(
                            "the listed node's interest ({interest}) is not the await's ({})",
                            io.interest
                        ),
                    );
                }
                match waiter.task {
                    Some(addr) if addr == task.addr.0 => waiting(),
                    Some(addr) => Assessed::unknown(
                        WaitUnknownReason::ConflictingEvidence,
                        format!("the listed node holds the task at {addr:#x}, not this one"),
                    ),
                    None => Assessed::unknown(
                        WaitUnknownReason::ResourceStateUnproven,
                        "the listed node's waker is not a task's",
                    ),
                }
            }
        }
    }

    /// The timer protocol: a word below the sentinels is the tick the
    /// entry sits in the wheel for; the sentinels say it has fired or
    /// is about to. The entry's waker is the wheel's to report, so the
    /// registration alone carries the wait.
    fn assess_timer(&self, timer: &TimerObservation, primitive: ValueKey) -> Assessed {
        match timer.state {
            TimerRegistrationState::Registered { .. } => {
                let Some(deadline) = timer.deadline else {
                    return Assessed::unknown(
                        WaitUnknownReason::ResourceUnreadable,
                        "the sleep's deadline did not read",
                    );
                };
                Assessed::of(WaitAssessment::Waiting(VerifiedWait {
                    target: WaitTarget::Timer {
                        deadline,
                        stopped: self.stopped_at(),
                    },
                    primitive,
                    queue_position: None,
                }))
            }
            TimerRegistrationState::PendingFire => {
                Assessed::of(WaitAssessment::ResourceReady(ReadyReason::TimerPendingFire))
            }
            TimerRegistrationState::Deregistered => {
                Assessed::of(WaitAssessment::ResourceReady(ReadyReason::TimerFired))
            }
            TimerRegistrationState::NotRegistered => Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "the chain is suspended on a sleep that has never been polled",
            ),
            TimerRegistrationState::Unknown => Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                "the sleep's entry state could not be observed",
            ),
        }
    }
}

impl<'b, T: Target> Context<'b, T> {
    /// The structured target an observation names, read under no
    /// protocol: what a listing prints beside a future parked on a
    /// resource, whether or not the resource's protocol vouches for a
    /// wait — a description of the resource, never a verified
    /// dependency. `None` where the words that would spell it did not
    /// read. The joined header, the semaphore's queue and the timer's
    /// deadline are read the way the assessor reads them, the queue
    /// once per pass.
    pub fn observed_target(
        &self,
        pass: &mut AssessmentPass,
        observation: &ResourceObservation,
        chain: &AwaitChain<'b>,
        list: &TaskList,
        read: &ReadContext<'_>,
    ) -> Option<WaitTarget> {
        match observation {
            ResourceObservation::Join(join) => {
                let header = self.read_task_header(join.header, read).ok()?;
                let addr = join.header.0;
                let listed = list.contains(addr);
                let kind = if listed {
                    None
                } else {
                    self.header_unlisted_kind(addr)
                };
                Some(WaitTarget::Task {
                    addr,
                    task_id: header.task_id,
                    state: header.state,
                    listed,
                    kind,
                })
            }
            ResourceObservation::Acquire(acquire) => {
                let queue = pass.queue(self, acquire.semaphore, read);
                // The queue prints only where the walk established its
                // order: a prefix in walk order is not a wake queue.
                let waiters = if queue.established() {
                    queue.waiters.clone()
                } else {
                    Vec::new()
                };
                Some(WaitTarget::Semaphore {
                    addr: acquire.semaphore.addr,
                    owner: semaphore_owner(chain),
                    num_permits: acquire.requested,
                    available: queue.available?,
                    closed: queue.closed?,
                    waiters,
                })
            }
            ResourceObservation::Io(io) => Some(WaitTarget::Io {
                addr: io.scheduled_io.addr,
                fd: self.io_resource_fd(&payloads(chain), io.scheduled_io.addr),
                interest: Some(io.interest),
            }),
            ResourceObservation::Timer(timer) => Some(WaitTarget::Timer {
                deadline: timer.deadline?,
                stopped: self.stopped_at(),
            }),
        }
    }
}

/// Each frame's live storage — its state's payload, or the future
/// itself where it keeps no state — the values a resource held in the
/// frames is looked for in.
fn payloads<'b>(chain: &AwaitChain<'b>) -> Vec<reify::Value<'b>> {
    chain
        .frames
        .iter()
        .map(|frame| match &frame.state {
            Some(state) => state.payload,
            None => frame.future,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Conditional polling barriers
// ---------------------------------------------------------------------------

/// One edge of an owner's chain, copied out of it: the identities and
/// flags a barrier's evidence rests on, with the route copied from
/// the bundle rather than borrowed from the chain — a barrier is rare
/// and outlives the chain it was proved from.
#[derive(Clone, Debug)]
pub struct BarrierEdge {
    pub from: u32,
    pub to: u32,
    pub exclusive: bool,
    pub source: ValueKey,
    pub target: ValueKey,
    pub selected: FutureTarget,
}

/// What an exclusive chain proves about an acquire a task holds off
/// it: within this task's validated poll path, the candidate cannot be
/// polled before the chain's terminal completes. A conditional
/// statement — not that it will never be polled, not that nobody else
/// can drive or drop it, not that anyone queued behind its reservation
/// depends on this task.
#[derive(Clone, Debug)]
pub struct PollingBarrier {
    /// The task whose chain holds the candidate, and its id where the
    /// target records one.
    pub holder: TaskAddr,
    pub holder_id: Option<u64>,
    /// The on-chain coroutine frame holding it — its index from the
    /// root, its type — and that frame's state.
    pub frame: usize,
    pub frame_type: String,
    pub state: String,
    pub await_loc: Option<(String, u32)>,
    /// The local, by name, and its identity.
    pub local: String,
    pub candidate: ValueKey,
    /// The held future's own type, past its adapters.
    pub future: String,
    /// The primitive wrapping the semaphore, when the held chain names
    /// it.
    pub owner: Option<&'static str>,
    /// The acquire's observation, with its queue position filled from
    /// the pass's queue where the queue was established.
    pub acquire: AcquireObservation,
    /// The owner chain's terminal, whose completion is the condition:
    /// its identity, and its type for the diagnosis to name.
    pub primitive: ValueKey,
    pub terminal: String,
    pub edges: Vec<BarrierEdge>,
}

impl PollingBarrier {
    /// Whether the held acquire was granted whole: it holds the
    /// permits, and its reservation is the resource itself.
    pub fn granted(&self) -> bool {
        self.acquire.needed == 0
    }
}

impl<'b, T: Target> Context<'b, T> {
    /// The polling barriers `inspection` establishes for `task`: one per
    /// acquire found in an on-chain coroutine's initialized locals,
    /// reached through owned storage, off every chain referent, still
    /// queued or granted — given an idle owner, a complete chain of
    /// exclusive edges, and a terminal whose reviewed protocol excludes
    /// other polling while pending. Anything short of that is no
    /// barrier, silently: the candidates are still there to inspect.
    pub fn polling_barriers(
        &self,
        pass: &mut AssessmentPass,
        inspection: &FutureInspection<'b>,
        task: &TaskFacts,
        read: &ReadContext<'_>,
    ) -> Vec<PollingBarrier> {
        let chain = &inspection.chain;
        if task.state.lifecycle() != Lifecycle::Idle || !chain.all_exclusive() {
            return Vec::new();
        }
        let Some(terminal) = chain.primitive_leaf() else {
            return Vec::new();
        };
        let exclusive_pending = self
            .type_semantics(terminal.ty.id())
            .and_then(|record| record.resource.as_ref())
            .is_some_and(|binding| binding.state_rule.is_some() && binding.exclusive_pending);
        if !exclusive_pending {
            return Vec::new();
        }
        let primitive = ValueKey::of(terminal);
        let referents: HashSet<ValueKey> = chain.referents().collect();
        let edges: Vec<BarrierEdge> = chain
            .edges
            .iter()
            .map(|edge| BarrierEdge {
                from: edge.from,
                to: edge.to,
                exclusive: edge.exclusive,
                source: edge.source,
                target: edge.target,
                selected: edge.selected.clone(),
            })
            .collect();
        let mut barriers = Vec::new();
        for (index, frame) in chain.frames.iter().enumerate() {
            let Some(state) = &frame.state else { continue };
            let Some(layout) = self
                .type_semantics(frame.future.ty.id())
                .and_then(|record| record.coroutine.as_ref())
            else {
                continue;
            };
            // The layout's states are keyed by variant, the frame's
            // state by its display name: decode the key again.
            let Some(Ok(active)) = frame.future.ty.active_variant(frame.future.bytes) else {
                continue;
            };
            let Some(coroutine_state) = layout
                .states
                .iter()
                .find(|s| self.view.str(s.variant) == Some(active.name))
            else {
                continue;
            };
            for &name in &coroutine_state.locals {
                let steps = [
                    Step::Variant(coroutine_state.variant),
                    Step::Member(hansei_bundle::MemberRef::Named(name)),
                ];
                let Ok(super::contract::Walked::At(local)) =
                    super::contract::execute_steps(self, read, frame.future, &steps)
                else {
                    continue;
                };
                if referents.contains(&ValueKey::of(local)) {
                    continue;
                }
                if self
                    .type_semantics(local.ty.id())
                    .is_none_or(|record| record.future.is_none())
                {
                    continue;
                }
                let held = self.inspect_future(local, InspectionMode::Held, read);
                if !matches!(held.chain.end, ChainEnd::Primitive) {
                    continue;
                }
                // An alias of a chain referent is on the chain, whatever
                // route reached it; a borrowed route proves no ownership.
                if held.chain.referents().any(|key| referents.contains(&key)) {
                    continue;
                }
                let borrowed = held.chain.edges.iter().any(|edge| {
                    self.type_semantics(edge.source.ty)
                        .and_then(|record| record.access.as_ref())
                        .is_some_and(|access| access.kind == AccessKind::Borrowed)
                });
                if borrowed {
                    continue;
                }
                let Some(ResourceObservation::Acquire(mut acquire)) = held.primitive.value else {
                    continue;
                };
                if !acquire.queued {
                    continue;
                }
                let queue = pass.queue(self, acquire.semaphore, read);
                if queue.established() {
                    acquire.queue_position = queue.position(acquire.node);
                }
                let future = held
                    .chain
                    .frames
                    .iter()
                    .find(|f| {
                        self.type_semantics(f.future.ty.id())
                            .is_none_or(|record| record.access.is_none())
                    })
                    .unwrap_or(&held.chain.frames[0])
                    .future
                    .ty
                    .name()
                    .to_owned();
                barriers.push(PollingBarrier {
                    holder: task.addr,
                    holder_id: task.task_id,
                    frame: index,
                    frame_type: frame.future.ty.name().to_owned(),
                    state: state.name.to_owned(),
                    await_loc: state.await_loc.map(|(file, line)| (file.to_owned(), line)),
                    local: self.view.str(name).unwrap_or("<bad strref>").to_owned(),
                    candidate: ValueKey::of(local),
                    future,
                    owner: semaphore_owner(&held.chain),
                    acquire,
                    primitive,
                    terminal: terminal.ty.name().to_owned(),
                    edges: edges.clone(),
                });
            }
        }
        barriers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::corrupt::Corrupt;
    use crate::testkit::{self, load_any};
    use crate::tokio::bundle::FutureInfo;
    use crate::tokio::graph::{self, TaskWait};

    use hansei_bundle::tokio::timer;
    use hansei_bundle::{BundleView, WalkRole};
    use proc::snapshot::Snapshot;
    use reify::Value;

    const RUNNING: u64 = 0b0001;
    const COMPLETE: u64 = 0b0010;
    const NOTIFIED: u64 = 0b0100;
    const JOIN_WAKER: u64 = 0b10_000;
    const STATE_BITS: u64 = 0b111111;

    fn task_named<'a>(list: &'a TaskList, name: &str) -> &'a Task {
        let hits: Vec<&Task> = list
            .tasks
            .iter()
            .filter(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
            .collect();
        assert_eq!(hits.len(), 1, "one task named {name}: {hits:?}");
        hits[0]
    }

    /// The assessed rows of a target, by task address.
    fn assessed<T: Target>(
        ctx: &Context<'_, T>,
        target: &T,
    ) -> (TaskList, Vec<TaskWait>, Vec<PollingBarrier>) {
        let list = testkit::tasks(ctx, target);
        let analysis = graph::analyze(ctx, &list, &ReadContext::none());
        assert!(analysis.errors.is_empty(), "{:?}", analysis.errors);
        (list, analysis.waits, analysis.barriers)
    }

    fn row<'r>(rows: &'r [TaskWait], task: &Task) -> &'r TaskWait {
        rows.iter().find(|r| r.task.addr == task.addr).unwrap()
    }

    /// The address of a task's state word.
    fn state_word<T: Target>(ctx: &Context<'_, T>, task: &Task) -> u64 {
        let header_ty = ctx
            .infra_ty(ctx.view.bundle().infra.header, "task Header")
            .unwrap();
        task.addr.0
            + ctx
                .walk(WalkRole::HeaderState)
                .member_offset(header_ty)
                .expect("Header.state is a member path")
    }

    /// A target where `task`'s state word carries `bits` in place of
    /// its lifecycle bits, the reference count kept.
    fn with_state<'a>(
        snapshot: &'a Snapshot,
        ctx: &Context<'_, Snapshot>,
        task: &Task,
        bits: u64,
    ) -> Corrupt<'a> {
        Corrupt::new(snapshot).patch(state_word(ctx, task), (task.state.0 & !STATE_BITS) | bits)
    }

    fn primitive_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> Value<'a> {
        ctx.inspect_task(task, &ReadContext::none())
            .unwrap()
            .expect("resident")
            .chain
            .primitive_leaf()
            .expect("a primitive end")
    }

    /// The precedence's first two steps, on the joiner: the state word
    /// decides before anything is read. Complete waits on nothing,
    /// notified is runnable, running is mid-poll — and the chain of a
    /// running task keeps only its root.
    #[test]
    fn test_the_state_word_decides_before_the_chain_is_read() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let joiner = task_named(&list, "joiner");
        for (bits, expected) in [
            (COMPLETE, "NotWaiting(Complete)"),
            (NOTIFIED, "Runnable(Scheduled)"),
            (RUNNING, "Runnable(ActivePoll)"),
        ] {
            let patched = with_state(&snapshot, &ctx, joiner, bits);
            let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
            let (list, rows, _) = assessed(&ctx, &patched);
            let row = row(&rows, task_named(&list, "joiner"));
            assert_eq!(format!("{:?}", row.assessment), expected, "{bits:#b}");
            match bits {
                COMPLETE => {
                    assert!(matches!(
                        row.continuation,
                        ContinuationStatus::Incomplete {
                            reason: IncompleteReason::NoRoot,
                            ..
                        }
                    ));
                    assert_eq!(row.depth, 0);
                }
                RUNNING => {
                    assert!(matches!(row.continuation, ContinuationStatus::ActivePoll));
                    assert_eq!(row.depth, 1);
                    assert!(row.observation.is_none());
                }
                _ => {
                    // The chain is still walked and observed; the
                    // state word merely outranks what it says.
                    assert!(matches!(row.continuation, ContinuationStatus::Primitive));
                    assert!(row.observation.is_some());
                }
            }
        }
    }

    /// The join protocol on the fixture: the joiner waits on the
    /// sleeper, whose trailer holds the joiner's waker; a complete
    /// sleeper is a ready join; a sleeper whose state says no waker is
    /// stored proves nothing; a trailer naming another task is a
    /// contradiction.
    #[test]
    fn test_the_join_protocol_reads_the_joined_header_and_trailer() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, barriers) = assessed(&ctx, &snapshot);
        assert!(barriers.is_empty());
        let joiner = task_named(&list, "joiner");
        let sleeper = task_named(&list, "sleeper");
        let joined = row(&rows, joiner);
        let WaitAssessment::Waiting(wait) = &joined.assessment else {
            panic!(
                "the joiner waits: {:?} {:?}",
                joined.assessment, joined.notes
            );
        };
        let WaitTarget::Task {
            addr, listed, kind, ..
        } = wait.target()
        else {
            panic!("on a task: {:?}", wait.target());
        };
        assert_eq!(*addr, sleeper.addr.0);
        assert!(listed);
        assert!(kind.is_none());
        assert_eq!(wait.primitive().ty, primitive_of(&ctx, joiner).ty.id());
        assert!(matches!(joined.continuation, ContinuationStatus::Primitive));
        assert!(matches!(
            joined.observation,
            Some(ResourceObservation::Join(_))
        ));
        assert_eq!(joined.depth, 2);
        assert!(joined.site.is_some());

        // The sleeper complete: the join is ready, not a wait.
        let done = with_state(
            &snapshot,
            &ctx,
            sleeper,
            sleeper.state.0 & STATE_BITS | COMPLETE,
        );
        let ctx2 = Context::new(&done, BundleView::new(&bundle)).unwrap();
        let (list2, rows2, _) = assessed(&ctx2, &done);
        assert!(matches!(
            row(&rows2, task_named(&list2, "joiner")).assessment,
            WaitAssessment::ResourceReady(ReadyReason::JoinComplete)
        ));

        // No join waker stored: the handle's poll may not have reached
        // the header, and nothing is proved.
        let unset = with_state(
            &snapshot,
            &ctx,
            sleeper,
            sleeper.state.0 & STATE_BITS & !JOIN_WAKER,
        );
        let ctx3 = Context::new(&unset, BundleView::new(&bundle)).unwrap();
        let (list3, rows3, _) = assessed(&ctx3, &unset);
        let row3 = row(&rows3, task_named(&list3, "joiner"));
        assert!(
            matches!(
                row3.assessment,
                WaitAssessment::Unknown(WaitUnknownReason::ResourceStateUnproven)
            ),
            "{:?}",
            row3.assessment
        );
        assert!(row3.notes[0].contains("no join waker"), "{:?}", row3.notes);
        assert!(row3.observation.is_some(), "the observation is kept");

        // The trailer's waker naming some other task: a contradiction.
        let header = ctx
            .read_task_header(sleeper.addr, &ReadContext::none())
            .unwrap();
        let trailer_ty = ctx
            .infra_ty(ctx.view.bundle().infra.trailer, "task Trailer")
            .unwrap();
        let trailer = Value::read(
            &snapshot,
            trailer_ty,
            sleeper.addr.0 + header.trailer_offset,
        )
        .unwrap();
        let raw = ctx
            .walk(WalkRole::TrailerWaker)
            .walk(trailer)
            .unwrap()
            .optional()
            .expect("the joiner armed the sleeper's trailer");
        let data = ctx.walk(WalkRole::WakerData).walk_at(raw).unwrap();
        assert_eq!(
            u64::from_le_bytes(data.bytes.try_into().unwrap()),
            joiner.addr.0
        );
        let other = Corrupt::new(&snapshot).patch(data.addr, sleeper.addr.0);
        let ctx4 = Context::new(&other, BundleView::new(&bundle)).unwrap();
        let (list4, rows4, _) = assessed(&ctx4, &other);
        let row4 = row(&rows4, task_named(&list4, "joiner"));
        assert!(matches!(
            row4.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::ConflictingEvidence)
        ));
        assert!(row4.notes[0].contains("not this one"), "{:?}", row4.notes);
    }

    /// The timer protocol: a registered entry is the wait, the
    /// sentinels are the wake on its way or already delivered.
    #[test]
    fn test_the_timer_protocol_reads_the_entrys_sentinels() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, _) = assessed(&ctx, &snapshot);
        let sleeper = task_named(&list, "sleeper");
        let slept = row(&rows, sleeper);
        let WaitAssessment::Waiting(wait) = &slept.assessment else {
            panic!(
                "the sleeper waits: {:?} {:?}",
                slept.assessment, slept.notes
            );
        };
        assert!(matches!(wait.target(), WaitTarget::Timer { .. }));
        assert_eq!(wait.queue_position(), None);
        let sleep = primitive_of(&ctx, sleeper);
        let word = ctx.walk(WalkRole::SleepTimerState).walk_at(sleep).unwrap();
        for (sentinel, expected) in [
            (timer::STATE_DEREGISTERED, ReadyReason::TimerFired),
            (timer::STATE_PENDING_FIRE, ReadyReason::TimerPendingFire),
        ] {
            let patched = Corrupt::new(&snapshot).patch(word.addr, sentinel);
            let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
            let (list, rows, _) = assessed(&ctx, &patched);
            let row = row(&rows, task_named(&list, "sleeper"));
            assert!(
                matches!(row.assessment, WaitAssessment::ResourceReady(reason) if reason == expected),
                "{sentinel:#x}: {:?}",
                row.assessment
            );
        }
    }

    /// The queue's guard byte and its head word, for freezing the
    /// critical-section and empty-queue states.
    fn queue_words(ctx: &Context<'_, Snapshot>, semaphore: ValueKey) -> (u64, u64, u64) {
        let sem = ctx.read_keyed(semaphore, &ReadContext::none()).unwrap();
        let lock = ctx.walk(WalkRole::SemaphoreLock).walk_at(sem).unwrap();
        let permits = ctx.walk(WalkRole::SemaphorePermits).walk_at(sem).unwrap();
        let steps = &ctx.view.bundle().walks.entries[&WalkRole::SemaphoreQueueHead].steps;
        let option = steps
            .iter()
            .position(|s| matches!(s, Step::Variant(_)))
            .expect("the head route enters Some");
        let crate::tokio::contract::Walked::At(head) =
            crate::tokio::contract::execute_steps(ctx, &ReadContext::none(), sem, &steps[..option])
                .unwrap()
        else {
            panic!("the option is reached");
        };
        (lock.addr, permits.addr, head.addr)
    }

    /// The acquire protocol on the futurelock fixture: op2's task waits
    /// on the mutex, first in a one-node queue, with the granted op1
    /// held off its chain as a conditional polling barrier. Then each
    /// window the protocol distinguishes, frozen by hand: permits
    /// granted before the wake is consumed, the semaphore closed, the
    /// node never queued, the queue read under its lock, the node gone
    /// from an empty queue, and permits free beside a waiter.
    #[test]
    fn test_the_acquire_protocol_and_the_polling_barrier() {
        let (bundle, snapshot) = load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, barriers) = assessed(&ctx, &snapshot);
        let holder = list
            .tasks
            .iter()
            .find(|t| {
                matches!(
                    row(&rows, t).observation,
                    Some(ResourceObservation::Acquire(_))
                )
            })
            .expect("a task parked on an acquire");
        let parked = row(&rows, holder);
        let WaitAssessment::Waiting(wait) = &parked.assessment else {
            panic!("op2 waits: {:?} {:?}", parked.assessment, parked.notes);
        };
        let WaitTarget::Semaphore {
            owner,
            num_permits,
            available,
            closed,
            waiters,
            ..
        } = wait.target()
        else {
            panic!("on a semaphore: {:?}", wait.target());
        };
        assert_eq!(*owner, Some("tokio::sync::Mutex"));
        assert_eq!((*num_permits, *available, *closed), (1, 0, false));
        assert_eq!(waiters.len(), 1);
        assert_eq!(wait.queue_position(), Some(0));
        let Some(ResourceObservation::Acquire(op2)) = &parked.observation else {
            unreachable!()
        };
        assert_eq!((op2.requested, op2.needed, op2.queued), (1, 1, true));

        // The barrier: future1 in do_stuff's frame, granted whole and
        // removed from the queue, unpollable until op2's acquire ends.
        assert_eq!(barriers.len(), 1, "{barriers:#?}");
        let barrier = &barriers[0];
        assert_eq!(barrier.holder, holder.addr);
        assert_eq!(barrier.local, "future1");
        assert!(
            barrier.future.contains("do_async_thing"),
            "{}",
            barrier.future
        );
        assert_eq!(barrier.owner, Some("tokio::sync::Mutex"));
        assert!(barrier.granted());
        assert!(barrier.acquire.queued);
        assert_eq!(barrier.acquire.queue_position, None);
        assert_eq!(barrier.acquire.semaphore, op2.semaphore);
        assert_ne!(barrier.acquire.node, op2.node);
        assert_eq!(barrier.primitive, wait.primitive());
        assert!(barrier.edges.iter().all(|e| e.exclusive));
        assert_eq!(barrier.edges.len(), parked.depth - 1);
        assert!(barrier.state.starts_with("Suspend"), "{}", barrier.state);
        assert!(barrier.await_loc.is_some());

        let acquire = primitive_of(&ctx, holder);
        let needed = ctx.walk(WalkRole::AcquireNeeded).walk_at(acquire).unwrap();
        let queued = ctx.walk(WalkRole::AcquireQueued).walk_at(acquire).unwrap();
        let (lock, permits, head) = queue_words(&ctx, op2.semaphore);
        let cases: Vec<(&str, Corrupt<'_>, &str)> = vec![
            (
                "granted before the wake is consumed",
                Corrupt::new(&snapshot).patch(needed.addr, 0),
                "ResourceReady(PermitsGranted)",
            ),
            (
                "closed",
                Corrupt::new(&snapshot).patch(permits, hansei_bundle::tokio::semaphore::CLOSED),
                "ResourceReady(SemaphoreClosed)",
            ),
            (
                "never queued",
                Corrupt::new(&snapshot).patch_byte(queued.addr, 0),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "read under its lock",
                Corrupt::new(&snapshot).patch_byte(lock, 0b01),
                "Unknown(ResourceStateUnproven)",
            ),
            (
                "absent from an empty queue",
                Corrupt::new(&snapshot).patch(head, 0),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "permits free beside a waiter",
                Corrupt::new(&snapshot).patch(permits, 2 << 1),
                "Unknown(ConflictingEvidence)",
            ),
        ];
        for (what, patched, expected) in cases {
            let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
            let (list, rows, _) = assessed(&ctx, &patched);
            let holder = list.tasks.iter().find(|t| t.addr == holder.addr).unwrap();
            let row = row(&rows, holder);
            assert_eq!(
                format!("{:?}", row.assessment),
                expected,
                "{what}: {:?}",
                row.notes
            );
            assert!(row.observation.is_some(), "{what}: the observation is kept");
        }

        // The barrier's own acquire never queued: it holds nothing, and
        // no barrier is made of it. Its owner's wait is untouched.
        let candidate = Value::read(
            &snapshot,
            ctx.view.ty(barrier.acquire.future.ty).unwrap(),
            barrier.acquire.future.addr,
        )
        .unwrap();
        let held_queued = ctx
            .walk(WalkRole::AcquireQueued)
            .walk_at(candidate)
            .unwrap();
        let patched = Corrupt::new(&snapshot).patch_byte(held_queued.addr, 0);
        let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list, rows, barriers) = assessed(&ctx, &patched);
        assert!(barriers.is_empty(), "{barriers:#?}");
        let holder = list.tasks.iter().find(|t| t.addr == holder.addr).unwrap();
        assert!(matches!(
            row(&rows, holder).assessment,
            WaitAssessment::Waiting(_)
        ));
    }

    /// A chain that ends short of a primitive — a `Notified`, which no
    /// rule covers — assesses unknown and proves no barrier, however
    /// plainly a granted acquire sits in the frame: the walk-shapes
    /// abandoner holds one by value, and its chain does not qualify.
    #[test]
    fn test_an_unknown_chain_proves_no_wait_and_no_barrier() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, barriers) = assessed(&ctx, &snapshot);
        let abandoner = row(&rows, task_named(&list, "abandoner"));
        assert!(matches!(
            abandoner.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::Continuation)
        ));
        assert!(matches!(
            abandoner.continuation,
            ContinuationStatus::Unknown {
                reason: SemanticIssueKind::NoRule,
                ..
            }
        ));
        assert!(abandoner.observation.is_none());
        assert!(
            barriers.iter().all(|b| b.holder != abandoner.task.addr),
            "{barriers:#?}"
        );
        // The victim, parked on the same mutex, does wait.
        let victim = row(&rows, task_named(&list, "victim"));
        assert!(
            matches!(victim.assessment, WaitAssessment::Waiting(_)),
            "{:?} {:?}",
            victim.assessment,
            victim.notes
        );
    }

    /// The io protocol on the io fixture: a reader parked in the reader
    /// slot, a writer in the writer slot, a readiness await on its own
    /// listed node, and the fixture's own reader unknown. Then the
    /// windows: readiness delivered, the resource shut down, another
    /// task's waker in the slot, the node notified, the registration
    /// locked, an exhausted write.
    #[test]
    fn test_the_io_protocol_reads_the_registration_and_the_slots() {
        let (bundle, snapshot) = load_any("local-set-io");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, barriers) = assessed(&ctx, &snapshot);
        assert!(barriers.is_empty());
        let expect_io = |name: &str, interest: crate::tokio::bundle::Interest| {
            let task = task_named(&list, name);
            let r = row(&rows, task);
            let WaitAssessment::Waiting(wait) = &r.assessment else {
                panic!("{name} waits: {:?} {:?}", r.assessment, r.notes);
            };
            let WaitTarget::Io {
                addr,
                interest: found,
                ..
            } = wait.target()
            else {
                panic!("{name}: on io: {:?}", wait.target());
            };
            assert_eq!(*found, Some(interest), "{name}");
            let Some(ResourceObservation::Io(io)) = &r.observation else {
                unreachable!()
            };
            assert_eq!(*addr, io.scheduled_io.addr);
        };
        use crate::tokio::bundle::Interest;
        expect_io("local_reader", Interest::READABLE);
        expect_io("local_set_io::reader", Interest::READABLE);
        expect_io("local_writer", Interest::WRITABLE);
        expect_io("local_watcher", Interest::READABLE);
        let gated = row(&rows, task_named(&list, "local_gated_reader"));
        assert!(matches!(
            gated.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::Continuation)
        ));

        // The reader's registration: its readiness word, its guard,
        // and the reader slot's waker data word.
        let reader = task_named(&list, "local_reader");
        let Some(ResourceObservation::Io(io)) = &row(&rows, reader).observation else {
            unreachable!()
        };
        let registration = ctx
            .read_keyed(io.scheduled_io, &ReadContext::none())
            .unwrap();
        let readiness = ctx
            .walk(WalkRole::ScheduledIoReadiness)
            .walk_at(registration)
            .unwrap();
        let lock = ctx
            .walk(WalkRole::ScheduledIoLock)
            .walk_at(registration)
            .unwrap();
        let waiters = ctx
            .walk(WalkRole::ScheduledIoWaiters)
            .walk_at(registration)
            .unwrap();
        let raw = ctx
            .walk(WalkRole::IoReaderWaker)
            .walk(waiters)
            .unwrap()
            .optional()
            .expect("the reader slot is armed");
        let data = ctx.walk(WalkRole::WakerData).walk_at(raw).unwrap();
        let other = task_named(&list, "local_writer").addr.0;
        let cases: Vec<(&str, Corrupt<'_>, &str)> = vec![
            (
                "readable delivered",
                Corrupt::new(&snapshot).patch(readiness.addr, ready::READABLE),
                "ResourceReady(IoReady)",
            ),
            (
                "read closed delivered",
                Corrupt::new(&snapshot).patch(readiness.addr, ready::READ_CLOSED),
                "ResourceReady(IoReady)",
            ),
            (
                "writable delivered is not the reader's",
                Corrupt::new(&snapshot).patch(readiness.addr, ready::WRITABLE),
                "Waiting",
            ),
            (
                "shut down",
                Corrupt::new(&snapshot).patch(readiness.addr, ready::SHUTDOWN),
                "ResourceReady(IoShutdown)",
            ),
            (
                "another task's waker in the slot",
                Corrupt::new(&snapshot).patch(data.addr, other),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "locked",
                Corrupt::new(&snapshot).patch_byte(lock.addr, 0b01),
                "Unknown(ResourceStateUnproven)",
            ),
        ];
        for (what, patched, expected) in cases {
            let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
            let (list, rows, _) = assessed(&ctx, &patched);
            let row = row(&rows, task_named(&list, "local_reader"));
            let spelled = format!("{:?}", row.assessment);
            assert!(
                spelled.starts_with(expected),
                "{what}: {spelled} {:?}",
                row.notes
            );
            // The note names what was read: the lock held, or the
            // slot's task.
            match what {
                "locked" => assert!(row.notes[0].contains("locked"), "{:?}", row.notes),
                "another task's waker in the slot" => {
                    assert!(row.notes[0].contains("not this one"), "{:?}", row.notes)
                }
                _ => {}
            }
        }

        // The readiness await: its node notified is ready; its state
        // word at Done likewise.
        let watcher = task_named(&list, "local_watcher");
        let await_ = primitive_of(&ctx, watcher);
        let node = ctx.walk(WalkRole::ReadinessWaiter).walk_at(await_).unwrap();
        let flag = ctx
            .walk(WalkRole::ReadinessWaiterReady)
            .walk_at(node)
            .unwrap();
        let patched = Corrupt::new(&snapshot).patch_byte(flag.addr, 1);
        let ctx2 = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list2, rows2, _) = assessed(&ctx2, &patched);
        assert!(matches!(
            row(&rows2, task_named(&list2, "local_watcher")).assessment,
            WaitAssessment::ResourceReady(ReadyReason::IoNotified)
        ));
        // Another task's waker on the listed node: a contradiction, not
        // a wait on this task's behalf.
        let raw = ctx
            .walk(WalkRole::ReadinessWaiterWaker)
            .walk(node)
            .unwrap()
            .optional()
            .expect("the node is armed");
        let data = ctx.walk(WalkRole::WakerData).walk_at(raw).unwrap();
        let patched = Corrupt::new(&snapshot).patch(data.addr, other);
        let ctx5 = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list5, rows5, _) = assessed(&ctx5, &patched);
        let row5 = row(&rows5, task_named(&list5, "local_watcher"));
        assert!(matches!(
            row5.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::ConflictingEvidence)
        ));
        assert!(row5.notes[0].contains("not this one"), "{:?}", row5.notes);
        let state = ctx.walk(WalkRole::ReadinessState).walk_at(await_).unwrap();
        assert_eq!(state.ty.enumerator_name(state.bytes), Some("Waiting"));
        let done = (0u8..8)
            .find(|&v| {
                let mut bytes = state.bytes.to_vec();
                bytes[0] = v;
                state.ty.enumerator_name(&bytes) == Some("Done")
            })
            .expect("Done has a small discriminant");
        let patched = Corrupt::new(&snapshot).patch_byte(state.addr, done);
        let ctx3 = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list3, rows3, _) = assessed(&ctx3, &patched);
        assert!(matches!(
            row(&rows3, task_named(&list3, "local_watcher")).assessment,
            WaitAssessment::ResourceReady(ReadyReason::IoNotified)
        ));

        // An exhausted write never parks: a suspended one contradicts
        // the protocol.
        let writer = task_named(&list, "local_writer");
        let write = primitive_of(&ctx, writer);
        let len = ctx.walk(WalkRole::IoWriteAllBufLen).walk_at(write).unwrap();
        let patched = Corrupt::new(&snapshot).patch(len.addr, 0);
        let ctx4 = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list4, rows4, _) = assessed(&ctx4, &patched);
        let row4 = row(&rows4, task_named(&list4, "local_writer"));
        assert!(matches!(
            row4.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::ConflictingEvidence)
        ));
        assert!(
            row4.notes[0].contains("exhausted write"),
            "{:?}",
            row4.notes
        );
    }

    /// The projection covers every end, and a verified wait gives up
    /// exactly its target.
    #[test]
    fn test_the_continuation_projection_and_the_wait_accessors() {
        let at = ValueKey {
            addr: 0x10,
            ty: hansei_bundle::BundleTypeId(3),
        };
        for (end, expected) in [
            (ChainEnd::Primitive, "Primitive"),
            (ChainEnd::Unresumed, "Unresumed"),
            (ChainEnd::Returned, "Returned"),
            (ChainEnd::Panicked, "Panicked"),
            (ChainEnd::ActivePoll, "ActivePoll"),
            (
                ChainEnd::DepthLimit,
                "Incomplete { reason: DepthLimit, detail: None }",
            ),
            (
                ChainEnd::Cycle { addr: 1 },
                "Incomplete { reason: Cycle, detail: None }",
            ),
            (
                ChainEnd::UnknownContinuation {
                    at,
                    reason: SemanticIssueKind::MultipleChildren,
                },
                "Unknown { at: ValueKey { addr: 16, ty: BundleTypeId(3) }, reason: MultipleChildren }",
            ),
            (
                ChainEnd::Error(anyhow::anyhow!("torn")),
                "Incomplete { reason: Error, detail: Some(\"torn\") }",
            ),
        ] {
            assert_eq!(format!("{:?}", ContinuationStatus::of(&end)), expected);
        }
        let wait = VerifiedWait {
            target: WaitTarget::Io {
                addr: 7,
                fd: None,
                interest: None,
            },
            primitive: at,
            queue_position: Some(2),
        };
        assert_eq!(wait.primitive(), at);
        assert_eq!(wait.queue_position(), Some(2));
        let assessment = WaitAssessment::Waiting(wait);
        assert!(assessment.verified().is_some());
        assert!(WaitAssessment::Unresumed.verified().is_none());
        let WaitAssessment::Waiting(wait) = assessment else {
            unreachable!()
        };
        assert!(matches!(wait.into_target(), WaitTarget::Io { addr: 7, .. }));
    }

    /// The direction masks are tokio's: a readable interest accepts
    /// readable or read-closed, a writable one writable or
    /// write-closed, and any other bit only itself.
    #[test]
    fn test_direction_masks_follow_tokios() {
        assert_eq!(ready::direction_mask(0), 0);
        assert_eq!(ready::direction_mask(ready::READABLE), 0b101);
        assert_eq!(ready::direction_mask(ready::WRITABLE), 0b1010);
        assert_eq!(ready::direction_mask(0b11), 0b1111);
        assert_eq!(ready::direction_mask(0b10_0000), 0b10_0000);
        assert_eq!(
            ready::direction_mask(ready::READ_CLOSED),
            ready::READ_CLOSED
        );
    }

    /// A readiness await's own state word, short of `Waiting`, is its
    /// own answer: never parked, notified, a word no state names, or
    /// unread — each before the registration is consulted.
    #[test]
    fn test_a_readiness_awaits_state_word_is_assessed_first() {
        let (bundle, snapshot) = load_any("local-set-io");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let watcher = task_named(&list, "local_watcher");
        let await_ = primitive_of(&ctx, watcher);
        let observed = ctx.observe_resource(await_, &ReadContext::none());
        let Some(ResourceObservation::Io(io)) = observed.value else {
            panic!("a readiness await observes as io");
        };
        assert_eq!(io.readiness_state, Some(IoFutureState::Waiting));
        let facts = TaskFacts::from(watcher);
        let key = ValueKey::of(await_);
        for (state, expected) in [
            (Some(IoFutureState::Init), "Unknown(ConflictingEvidence)"),
            (Some(IoFutureState::Done), "ResourceReady(IoNotified)"),
            (
                Some(IoFutureState::Unknown(7)),
                "Unknown(ResourceStateUnproven)",
            ),
            (None, "Unknown(ResourceUnreadable)"),
        ] {
            let io = IoObservation {
                readiness_state: state,
                ..io.clone()
            };
            let mut pass = AssessmentPass::new();
            let chain = AwaitChain {
                frames: Vec::new(),
                edges: Vec::new(),
                end: ChainEnd::Primitive,
            };
            let assessed = ctx.assess_io(&mut pass, &io, &facts, &chain, key, &ReadContext::none());
            assert_eq!(
                format!("{:?}", assessed.assessment),
                expected,
                "{state:?}: {:?}",
                assessed.notes
            );
        }
    }

    /// A queued node whose waker names another task is a contradiction
    /// for this one; the walk-shapes victim's node, re-armed for the
    /// abandoner, says so.
    #[test]
    fn test_a_queued_node_must_carry_this_tasks_waker() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let victim = task_named(&list, "victim");
        let other = task_named(&list, "abandoner").addr.0;
        let acquire = primitive_of(&ctx, victim);
        let node = ctx.walk(WalkRole::AcquireNode).walk_at(acquire).unwrap();
        let raw = ctx
            .walk(WalkRole::WaiterWaker)
            .walk(node)
            .unwrap()
            .optional()
            .expect("the victim's node is armed");
        let data = ctx.walk(WalkRole::WakerData).walk_at(raw).unwrap();
        assert_eq!(
            u64::from_le_bytes(data.bytes.try_into().unwrap()),
            victim.addr.0
        );
        let patched = Corrupt::new(&snapshot).patch(data.addr, other);
        let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list, rows, _) = assessed(&ctx, &patched);
        let row = row(&rows, task_named(&list, "victim"));
        assert!(
            matches!(
                row.assessment,
                WaitAssessment::Unknown(WaitUnknownReason::ConflictingEvidence)
            ),
            "{:?}",
            row.assessment
        );
        assert!(row.notes[0].contains("not this one"), "{:?}", row.notes);
    }

    /// A barrier needs an idle owner and a terminal whose protocol
    /// excludes other polling while pending: the futurelock holder
    /// scheduled, or its acquire's binding without that guarantee,
    /// proves none — while the wait itself still verifies in the
    /// latter case. And a barrier's grant is its counter's.
    #[test]
    fn test_a_barrier_needs_an_idle_owner_and_an_exclusive_pending_terminal() {
        let (mut bundle, snapshot) = load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, barriers) = assessed(&ctx, &snapshot);
        assert_eq!(barriers.len(), 1);
        let holder = list
            .tasks
            .iter()
            .find(|t| t.addr == barriers[0].holder)
            .unwrap();
        let acquire_ty = primitive_of(&ctx, holder).ty.id();
        assert!(matches!(
            row(&rows, holder).assessment,
            WaitAssessment::Waiting(_)
        ));

        let scheduled = with_state(&snapshot, &ctx, holder, NOTIFIED);
        let ctx2 = Context::new(&scheduled, BundleView::new(&bundle)).unwrap();
        let (_, rows2, barriers2) = assessed(&ctx2, &scheduled);
        assert!(barriers2.is_empty(), "{barriers2:#?}");
        assert!(matches!(
            rows2
                .iter()
                .find(|r| r.task.addr == holder.addr)
                .unwrap()
                .assessment,
            WaitAssessment::Runnable(RunnableReason::Scheduled)
        ));
        drop(ctx);

        let record = bundle
            .semantics
            .types
            .iter_mut()
            .find(|r| r.ty == acquire_ty)
            .unwrap();
        record.resource.as_mut().unwrap().exclusive_pending = false;
        let ctx3 = testkit::context(&bundle, &snapshot);
        let (list3, rows3, barriers3) = assessed(&ctx3, &snapshot);
        assert!(barriers3.is_empty(), "{barriers3:#?}");
        let holder3 = list3.tasks.iter().find(|t| t.addr == holder.addr).unwrap();
        assert!(matches!(
            row(&rows3, holder3).assessment,
            WaitAssessment::Waiting(_)
        ));

        let mut barrier = PollingBarrier {
            holder: holder.addr,
            holder_id: holder.task_id,
            frame: 0,
            frame_type: String::new(),
            state: String::new(),
            await_loc: None,
            local: String::new(),
            candidate: ValueKey {
                addr: 1,
                ty: acquire_ty,
            },
            future: String::new(),
            owner: None,
            acquire: AcquireObservation {
                future: ValueKey {
                    addr: 1,
                    ty: acquire_ty,
                },
                semaphore: ValueKey {
                    addr: 2,
                    ty: acquire_ty,
                },
                node: 3,
                requested: 2,
                needed: 1,
                queued: true,
                queue_position: None,
            },
            primitive: ValueKey {
                addr: 4,
                ty: acquire_ty,
            },
            terminal: String::new(),
            edges: Vec::new(),
        };
        assert!(!barrier.granted());
        barrier.acquire.needed = 0;
        assert!(barrier.granted());
    }
}

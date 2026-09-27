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
    AwaitChain, ChainEnd, Context, HttpCaller, HttpPhase, HttpRole, HttpVersion, IoResourceInfo,
    IoSlot, OneshotSide, QueuedWaker, Task, TaskKind, TaskList, WaitTarget, semaphore_owner,
};
use super::chain::{FutureInspection, InspectionMode};
use super::graph::TaskRef;
use super::observe::{
    AcquireObservation, ChannelObservation, Consistency, HttpConnObservation,
    HttpNegotiatingObservation, HttpReading, HttpWriting, IoFutureState, IoObservation,
    JoinObservation, KeepAlive, NotifiedObservation, NotifiedState, NotifyObservation, Observed,
    OneshotObservation, QueueObservation, ReadContext, RecvObservation, ResourceObservation,
    ScanBudget, SlotState, TimerObservation, TimerRegistrationState, ValueKey,
};
use super::waitset::{WaitMember, WaitSet};
use super::{Lifecycle, TaskAddr, TaskState};

use hansei_bundle::{
    AccessKind, BundleTypeId, FutureTarget, IoOperationKind, SemanticIssueKind, Step,
};
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
    /// The continuation is unknown at a future that polls several
    /// things, and this task's waker is parked in at least one of them:
    /// the branches the stop frame polls and the registry slots
    /// attributed to the task, any one of which wakes it. A
    /// disjunction, not a dependency: it is no `Waiting` edge, closes
    /// no cycle and establishes no polling barrier.
    Set(WaitSet),
    /// The chain ends in a future whose reviewed poll returns `Pending`
    /// and does nothing else — registers no waker, polls nothing — so
    /// no poll of the task ever returns `Ready`. About readiness, not
    /// waking: a stale or spurious wake still schedules the task, which
    /// polls the terminal and parks again, so a waker slot attributed
    /// to the task contradicts nothing and demotes nothing. The task
    /// is waiting, forever, on nothing that exists.
    NeverReady {
        /// The branches of a `select!` stop every enabled one of which
        /// ends never ready, in branch order with the disabled ones
        /// among them, for the listing; empty where the task's own
        /// chain ends at the terminal.
        members: Vec<WaitMember>,
        /// Branches past the listing cap at such a stop, counted only.
        capped: usize,
    },
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
    /// A message sits at the receiver's read index; the next poll
    /// takes it.
    MessageReady,
    /// The channel is closed and drained: every sender is gone, or
    /// the receiver closed it and every permit is back. The next poll
    /// returns `None`.
    ChannelClosed,
    /// The `Notified` has been notified; the next poll returns.
    Notified,
    /// The oneshot's sender completed — sent a value, or dropped — and
    /// the receiver's next poll takes the outcome.
    OneshotComplete,
    /// The receiver closed the oneshot; its next poll returns the error.
    OneshotClosed,
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

/// A chain's end as an owned, compact status: what a task row keeps
/// after the chain itself is dropped.
#[derive(Clone, Debug)]
pub enum ContinuationStatus {
    Primitive,
    Unresumed,
    Returned,
    Panicked,
    NeverReady,
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
            ChainEnd::NeverReady => ContinuationStatus::NeverReady,
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
    channels: HashMap<ValueKey, ChannelObservation>,
    notifies: HashMap<ValueKey, NotifyObservation>,
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
            channels: HashMap::default(),
            notifies: HashMap::default(),
            budget: ScanBudget::default(),
        }
    }

    /// The channel at `chan`, read on first demand.
    pub fn channel<'b, T: Target>(
        &mut self,
        ctx: &Context<'b, T>,
        chan: ValueKey,
        read: &ReadContext<'_>,
    ) -> &ChannelObservation {
        if !self.channels.contains_key(&chan) {
            let channel = ctx.observe_channel(chan, read, &mut self.budget);
            self.channels.insert(chan, channel);
        }
        &self.channels[&chan]
    }

    /// The `Notify` at `notify`, read on first demand.
    pub fn notify<'b, T: Target>(
        &mut self,
        ctx: &Context<'b, T>,
        notify: ValueKey,
        read: &ReadContext<'_>,
    ) -> &NotifyObservation {
        if !self.notifies.contains_key(&notify) {
            let list = ctx.observe_notify(notify, read, &mut self.budget);
            self.notifies.insert(notify, list);
        }
        &self.notifies[&notify]
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
            // The terminal is the verdict: no resource to read, no
            // branches to enumerate. Whatever slots the registries or
            // the sweep attribute to the task are listed beside it and
            // change nothing.
            ChainEnd::NeverReady => {
                return Assessed::of(WaitAssessment::NeverReady {
                    members: Vec::new(),
                    capped: 0,
                });
            }
            ChainEnd::ActivePoll => {
                return Assessed::unknown(
                    WaitUnknownReason::Lifecycle,
                    "the chain was walked as mid-poll, but the state word reads idle",
                );
            }
            ChainEnd::Primitive => {}
            // The stop is named by the cell (`unknown at <type>`) and
            // explained where the chain ends; nothing is said twice.
            ChainEnd::UnknownContinuation { .. } => {
                return Assessed::of(WaitAssessment::Unknown(WaitUnknownReason::Continuation));
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
            ResourceObservation::Recv(recv) => self.assess_recv(pass, recv, task, primitive, read),
            ResourceObservation::Oneshot(oneshot) => self.assess_oneshot(oneshot, task, primitive),
            ResourceObservation::HttpConn(http) => {
                self.assess_http_conn(pass, http, task, primitive, read)
            }
            ResourceObservation::HttpNegotiating(negotiating) => {
                assess_http_negotiating(negotiating, primitive)
            }
            ResourceObservation::Notified(notified) => {
                let mut assessed = self.assess_notified(pass, notified, task, primitive, read);
                // A `Notified` on one of a watch channel's `Notify`s is
                // the watch's wait: the receiver the chain holds names
                // the `Shared`, and the reading is the channel's.
                if let WaitAssessment::Waiting(verified) = &mut assessed.assessment
                    && let WaitTarget::Notify { addr, .. } = verified.target
                    && let Some(watch) = self.watch_target(&payloads(chain), addr)
                {
                    verified.target = watch;
                }
                assessed
            }
        }
    }

    /// The recv protocol: a value at the read index, or the senders'
    /// close marker in its block, means the next poll returns; a
    /// receiver that closed its own side with every permit back
    /// returns too. Short of those, a wait needs the receiver's waker
    /// cell at rest and holding this task's waker, and a sender still
    /// alive — no sender left with no close marker is a drop in
    /// progress, not a state the channel rests in.
    fn assess_recv(
        &self,
        pass: &mut AssessmentPass,
        recv: &RecvObservation,
        task: &TaskFacts,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        use hansei_bundle::tokio::atomic_waker;
        let channel = pass.channel(self, recv.chan, read);
        let issues = || {
            channel
                .issues
                .iter()
                .map(|issue| issue.detail.clone().unwrap_or_default())
                .collect::<Vec<_>>()
                .join("; ")
        };
        let (Some(senders), Some(index), Some(tail), Some(rx_closed)) = (
            channel.senders,
            channel.index,
            channel.tail_position,
            channel.rx_closed,
        ) else {
            return Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                format!("the channel's words did not read: {}", issues()),
            );
        };
        if index > tail {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!("the read index {index} is past the claimed tail {tail}"),
            );
        }
        match channel.slot {
            SlotState::Value => {
                return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::MessageReady));
            }
            SlotState::Closed => {
                return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::ChannelClosed));
            }
            SlotState::Empty | SlotState::NoBlock => {}
            SlotState::Unknown => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    format!(
                        "the block holding the read index could not be reached: {}",
                        issues()
                    ),
                );
            }
        }
        if rx_closed {
            match (channel.available, channel.capacity) {
                (Some(available), Some(capacity)) if available == capacity => {
                    return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::ChannelClosed));
                }
                (Some(_), Some(_)) => {}
                _ => {
                    return Assessed::unknown(
                        WaitUnknownReason::ResourceStateUnproven,
                        "the receiver closed the channel and whether its permits are all \
                         back did not read",
                    );
                }
            }
        }
        match channel.waker_state {
            Some(atomic_waker::WAITING) => {}
            Some(state) => {
                let doing = if state & atomic_waker::REGISTERING != 0 {
                    "being registered"
                } else {
                    "being taken"
                };
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the receiver's waker is {doing} (state {state:#b})"),
                );
            }
            None => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    format!("the receiver's waker state did not read: {}", issues()),
                );
            }
        }
        match &channel.waker {
            Some(QueuedWaker::Task { addr, .. }) if *addr == task.addr.0 => {}
            Some(QueuedWaker::Task { addr, .. }) => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    format!("the receiver's waker names the task at {addr:#x}, not this one"),
                );
            }
            Some(QueuedWaker::Other { vtable }) => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the receiver's waker is not a task's (vtable {vtable:#x})"),
                );
            }
            Some(QueuedWaker::Unarmed) => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    "the receiver parked but registered no waker",
                );
            }
            None => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    format!("the receiver's waker did not read: {}", issues()),
                );
            }
        }
        if senders == 0 {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "no sender is left and the channel carries no close marker",
            );
        }
        Assessed::of(WaitAssessment::Waiting(VerifiedWait {
            target: WaitTarget::Channel {
                addr: recv.chan.addr,
                senders,
                capacity: channel.capacity,
                unread: tail - index,
            },
            primitive,
            queue_position: None,
        }))
    }

    /// The oneshot receiver's protocol: a completed sender — a value
    /// sent, or the sender dropped — or a receiver that closed its own
    /// side means the next poll returns. Short of those, a wait needs
    /// the state word to say the receiver's task cell is set, and the
    /// cell to hold this task's waker.
    fn assess_oneshot(
        &self,
        oneshot: &OneshotObservation,
        task: &TaskFacts,
        primitive: ValueKey,
    ) -> Assessed {
        let state = oneshot.state;
        if state.complete() {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::OneshotComplete));
        }
        if state.closed() {
            return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::OneshotClosed));
        }
        if !state.rx_task_set() {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "the receiver parked but its state word says no waker is stored",
            );
        }
        match &oneshot.rx_waker {
            Some(QueuedWaker::Task { addr, .. }) if *addr == task.addr.0 => {}
            Some(QueuedWaker::Task { addr, .. }) => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    format!("the receiver's waker names the task at {addr:#x}, not this one"),
                );
            }
            Some(QueuedWaker::Other { vtable }) => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the receiver's waker is not a task's (vtable {vtable:#x})"),
                );
            }
            Some(QueuedWaker::Unarmed) | None => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    "the receiver's waker did not read",
                );
            }
        }
        Assessed::of(WaitAssessment::Waiting(VerifiedWait {
            target: WaitTarget::Oneshot {
                addr: oneshot.inner,
                state,
                side: OneshotSide::Rx,
            },
            primitive,
            queue_position: None,
        }))
    }

    /// hyper's HTTP/1 connection, by the role its dispatcher drives.
    fn assess_http_conn(
        &self,
        pass: &mut AssessmentPass,
        http: &HttpConnObservation,
        task: &TaskFacts,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        match http.role {
            HttpRole::Client => self.assess_http_client(pass, http, task, primitive, read),
            HttpRole::Server => assess_http_server(http, primitive),
        }
    }

    /// hyper's HTTP/1 client connection: the phase its state words put
    /// it in ([`client_phase`]), and the primitive the dispatch is
    /// parked on for that phase, held to the same conditions the
    /// tokio protocols are — the request receiver's waker cell at rest
    /// and holding this task's waker while idle, the response
    /// callback's sender cell holding it while a request is in flight
    /// or its body is being sent. While a response body arrives, or
    /// the connection closes, the dispatch names no primitive: the
    /// socket the connection reads is the registry's to name, and the
    /// verdict stands on the words alone.
    fn assess_http_client(
        &self,
        pass: &mut AssessmentPass,
        http: &HttpConnObservation,
        task: &TaskFacts,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        use hansei_bundle::tokio::atomic_waker;
        let (phase, keep_alive) = match client_phase(http) {
            Ok(decided) => decided,
            Err(reason) => {
                return Assessed::unknown(WaitUnknownReason::ResourceStateUnproven, reason);
            }
        };
        let Some(client) = &http.client else {
            return Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                "the client connection's dispatch is not bound",
            );
        };
        let decline =
            |waker: &Option<QueuedWaker>, cell: &str| waker_decline(waker, task.addr, cell);
        let via = match phase {
            HttpPhase::Idle => {
                let Some(chan) = client.rx else {
                    return Assessed::unknown(
                        WaitUnknownReason::ResourceUnreadable,
                        "the request receiver's channel did not read",
                    );
                };
                let channel = pass.channel(self, chan, read);
                match channel.waker_state {
                    Some(atomic_waker::WAITING) => {}
                    Some(state) => {
                        return Assessed::unknown(
                            WaitUnknownReason::ResourceStateUnproven,
                            format!(
                                "the request receiver's waker is mid-flight (state {state:#b})"
                            ),
                        );
                    }
                    None => {
                        return Assessed::unknown(
                            WaitUnknownReason::ResourceUnreadable,
                            "the request receiver's waker state did not read",
                        );
                    }
                }
                if let Some(declined) = decline(&channel.waker, "request receiver's waker") {
                    return declined;
                }
                let (Some(senders), Some(index), Some(tail)) =
                    (channel.senders, channel.index, channel.tail_position)
                else {
                    return Assessed::unknown(
                        WaitUnknownReason::ResourceUnreadable,
                        "the request channel's words did not read",
                    );
                };
                Some(Box::new(WaitTarget::Channel {
                    addr: chan.addr,
                    senders,
                    capacity: channel.capacity,
                    unread: tail.saturating_sub(index),
                }))
            }
            HttpPhase::AwaitingResponse | HttpPhase::SendingBody(_) => {
                let Some(callback) = &client.callback else {
                    return Assessed::unknown(
                        WaitUnknownReason::ResourceUnreadable,
                        "the response callback's oneshot did not read",
                    );
                };
                if !callback.state.tx_task_set() {
                    return Assessed::unknown(
                        WaitUnknownReason::ConflictingEvidence,
                        "the connection awaits a response but watches no callback",
                    );
                }
                if let Some(declined) =
                    decline(&callback.tx_waker, "response callback's sender cell")
                {
                    return declined;
                }
                Some(Box::new(WaitTarget::Oneshot {
                    addr: callback.inner,
                    state: callback.state,
                    side: OneshotSide::Tx,
                }))
            }
            HttpPhase::ReceivingBody(_) | HttpPhase::Closing => None,
            HttpPhase::Negotiating | HttpPhase::HandlingRequest => {
                unreachable!("a client connection is never in a server phase")
            }
        };
        let caller = in_flight_caller(phase, client);
        Assessed::of(WaitAssessment::Waiting(VerifiedWait {
            target: WaitTarget::HttpConn {
                addr: http.conn,
                role: HttpRole::Client,
                version: Some(HttpVersion::Http1),
                phase,
                method: http.method.clone(),
                keep_alive,
                header_read_timer: false,
                via,
                caller,
            },
            primitive,
            queue_position: None,
        }))
    }

    /// The notified protocol: `Done`, or a notification word on the
    /// node, means the next poll returns; a wait needs `Waiting` with
    /// the node unnotified, the `Notify` in its waiting state at the
    /// `notify_waiters` count the future was created at, and the node
    /// once in the quiescent list with this task's waker on it.
    fn assess_notified(
        &self,
        pass: &mut AssessmentPass,
        notified: &NotifiedObservation,
        task: &TaskFacts,
        primitive: ValueKey,
        read: &ReadContext<'_>,
    ) -> Assessed {
        use hansei_bundle::tokio::notify;
        match notified.state {
            NotifiedState::Done => {
                return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::Notified));
            }
            NotifiedState::Init => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    "the chain is suspended on a Notified that has never been polled",
                );
            }
            NotifiedState::Unknown(word) => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the Notified's state word {word:#x} is no state"),
                );
            }
            NotifiedState::Waiting => {}
        }
        match notified.notification {
            notify::NOTIFICATION_NONE => {}
            notify::NOTIFICATION_ONE | notify::NOTIFICATION_LAST | notify::NOTIFICATION_ALL => {
                return Assessed::of(WaitAssessment::ResourceReady(ReadyReason::Notified));
            }
            word => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    format!("the node's notification word {word:#x} is none the protocol writes"),
                );
            }
        }
        let list = pass.notify(self, notified.notify, read);
        let Some(state) = list.state else {
            return Assessed::unknown(
                WaitUnknownReason::ResourceUnreadable,
                "the Notify's state word did not read",
            );
        };
        match state & notify::STATE_MASK {
            notify::WAITING => {}
            notify::EMPTY => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    "the Notify's state says it has no waiters",
                );
            }
            notify::NOTIFIED => {
                return Assessed::unknown(
                    WaitUnknownReason::ConflictingEvidence,
                    "the Notify's state says it holds a notify_one and has no waiters",
                );
            }
            other => {
                return Assessed::unknown(
                    WaitUnknownReason::ResourceStateUnproven,
                    format!("the Notify's state {other:#b} is none the protocol writes"),
                );
            }
        }
        let calls = state >> notify::CALLS_SHIFT;
        if calls != notified.calls {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!(
                    "notify_waiters has run {} times since this future was created and its \
                     node was not notified",
                    calls.wrapping_sub(notified.calls)
                ),
            );
        }
        if !list.established() {
            let why = match list.consistency {
                Consistency::Mutating => "its lock is held".to_owned(),
                Consistency::Unknown => "its guard could not be decoded".to_owned(),
                Consistency::Quiescent => format!(
                    "the walk stopped short: {}",
                    list.issues
                        .iter()
                        .map(|issue| issue.detail.clone().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            };
            return Assessed::unknown(
                WaitUnknownReason::ResourceStateUnproven,
                format!("the wait list is not a quiescent snapshot: {why}"),
            );
        }
        let mut listed = list.waiters.iter().filter(|w| w.addr == notified.node);
        let Some(node) = listed.next() else {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                format!(
                    "the node at {:#x} is not in the Notify's wait list",
                    notified.node
                ),
            );
        };
        if listed.next().is_some() {
            return Assessed::unknown(
                WaitUnknownReason::ConflictingEvidence,
                "the node appears more than once in the wait list",
            );
        }
        match &node.waker {
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
        let queue_position = list.position(notified.node);
        Assessed::of(WaitAssessment::Waiting(VerifiedWait {
            target: WaitTarget::Notify {
                addr: notified.notify.addr,
                state: Some(state),
                waiters: Some(list.waiters.len()),
            },
            primitive,
            queue_position,
        }))
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
            ResourceObservation::Recv(recv) => {
                let channel = pass.channel(self, recv.chan, read);
                Some(WaitTarget::Channel {
                    addr: recv.chan.addr,
                    senders: channel.senders?,
                    capacity: channel.capacity,
                    unread: channel.tail_position?.saturating_sub(channel.index?),
                })
            }
            // The `Notify`'s list is not walked here: a description of
            // a held `Notified` reads the state word and stops, since
            // the tokens a workload holds thousands of would each walk
            // a list of thousands to print one count. A watch
            // receiver's `Notify` is the exception: the `Shared` a
            // receiver in the chain already names is read for the
            // channel's words.
            ResourceObservation::Notified(notified) => Some(
                self.watch_target(&payloads(chain), notified.notify.addr)
                    .unwrap_or_else(|| WaitTarget::Notify {
                        addr: notified.notify.addr,
                        state: self.notify_state(notified.notify, read),
                        waiters: None,
                    }),
            ),
            ResourceObservation::Oneshot(oneshot) => Some(WaitTarget::Oneshot {
                addr: oneshot.inner,
                state: oneshot.state,
                side: OneshotSide::Rx,
            }),
            // The connection's words, read under no protocol: the phase
            // they decide, and the primitive the client's dispatch holds
            // for it, described without the waker checks a verified
            // wait makes.
            ResourceObservation::HttpConn(http) => match http.role {
                HttpRole::Client => {
                    let (phase, keep_alive) = client_phase(http).ok()?;
                    let client = http.client.as_ref()?;
                    let via = match phase {
                        HttpPhase::Idle => {
                            let chan = client.rx?;
                            let channel = pass.channel(self, chan, read);
                            Some(Box::new(WaitTarget::Channel {
                                addr: chan.addr,
                                senders: channel.senders?,
                                capacity: channel.capacity,
                                unread: channel.tail_position?.saturating_sub(channel.index?),
                            }))
                        }
                        HttpPhase::AwaitingResponse | HttpPhase::SendingBody(_) => {
                            let callback = client.callback.as_ref()?;
                            Some(Box::new(WaitTarget::Oneshot {
                                addr: callback.inner,
                                state: callback.state,
                                side: OneshotSide::Tx,
                            }))
                        }
                        _ => None,
                    };
                    Some(WaitTarget::HttpConn {
                        addr: http.conn,
                        role: HttpRole::Client,
                        version: Some(HttpVersion::Http1),
                        phase,
                        method: http.method.clone(),
                        keep_alive,
                        header_read_timer: false,
                        via,
                        caller: in_flight_caller(phase, client),
                    })
                }
                HttpRole::Server => {
                    let (phase, keep_alive) = server_phase(http).ok()?;
                    let server = http.server.as_ref()?;
                    Some(WaitTarget::HttpConn {
                        addr: http.conn,
                        role: HttpRole::Server,
                        version: Some(HttpVersion::Http1),
                        phase,
                        method: http.method.clone(),
                        keep_alive,
                        header_read_timer: server.header_read_timer_running,
                        via: None,
                        caller: None,
                    })
                }
            },
            ResourceObservation::HttpNegotiating(negotiating) => Some(WaitTarget::HttpConn {
                addr: negotiating.wrapper.addr,
                role: HttpRole::Server,
                version: None,
                phase: HttpPhase::Negotiating,
                method: None,
                keep_alive: true,
                header_read_timer: false,
                via: None,
                caller: None,
            }),
        }
    }
}

/// Who awaits the response a client connection has in flight, from
/// the response callback's own words: the receiver's task cell where
/// the state word says a waker is stored, else whether the receiver is
/// still there at all. `None` in every phase but the two with a
/// request in flight, and where no callback read.
fn in_flight_caller(
    phase: HttpPhase,
    client: &super::observe::HttpClientObservation,
) -> Option<HttpCaller> {
    match phase {
        HttpPhase::AwaitingResponse | HttpPhase::SendingBody(_) => {
            client.callback.as_ref().map(http_caller)
        }
        _ => None,
    }
}

/// The caller a response callback names: the receiver dropped its
/// side (`CLOSED`) and is gone; else it has parked a waker or not; a
/// parked waker is a task's, or something else's, or did not read.
pub fn http_caller(callback: &OneshotObservation) -> HttpCaller {
    if callback.state.closed() {
        return HttpCaller::Gone;
    }
    if !callback.state.rx_task_set() {
        return HttpCaller::Unparked;
    }
    match &callback.rx_waker {
        Some(QueuedWaker::Task { addr, task_id }) => HttpCaller::Task(TaskRef {
            addr: TaskAddr(*addr),
            task_id: *task_id,
        }),
        Some(QueuedWaker::Other { vtable }) => HttpCaller::NotATask {
            vtable: *vtable,
            cell: callback.rx_task_at,
        },
        Some(QueuedWaker::Unarmed) | None => HttpCaller::Unread,
    }
}

/// The decline a primitive's waker cell calls for, `None` where it
/// holds `task`'s own waker — what a connection's wait on the
/// primitive is held to, as the tokio protocols hold theirs: another
/// task's waker is conflicting evidence, a waker that is not a task's
/// is a state the protocol does not vouch for, an empty cell beside a
/// parked connection contradicts it, and a cell that did not read
/// decides nothing. `cell` names the slot in the decline.
fn waker_decline(waker: &Option<QueuedWaker>, task: TaskAddr, cell: &str) -> Option<Assessed> {
    match waker {
        Some(QueuedWaker::Task { addr, .. }) if *addr == task.0 => None,
        Some(QueuedWaker::Task { addr, .. }) => Some(Assessed::unknown(
            WaitUnknownReason::ConflictingEvidence,
            format!("the {cell} names the task at {addr:#x}, not this one"),
        )),
        Some(QueuedWaker::Other { vtable }) => Some(Assessed::unknown(
            WaitUnknownReason::ResourceStateUnproven,
            format!("the {cell} is not a task's (vtable {vtable:#x})"),
        )),
        Some(QueuedWaker::Unarmed) => Some(Assessed::unknown(
            WaitUnknownReason::ConflictingEvidence,
            format!("the connection parked but the {cell} is empty"),
        )),
        None => Some(Assessed::unknown(
            WaitUnknownReason::ResourceUnreadable,
            format!("the {cell} did not read"),
        )),
    }
}

/// The client rows of the connection protocol, decided from the words
/// alone. In the order hyper's own state machine settles them: a
/// closed direction or the dispatcher's closing flag is closing,
/// whatever else the words say; a decoder in `reading` is a response
/// body arriving; a callback beside an encoder in `writing` is a
/// request body going out; a callback with the request head written
/// (`writing` at `KeepAlive`, or still `Init` for the head about to
/// go) is a request awaiting its response; no callback with both
/// directions at `Init` is a connection between exchanges. The second
/// value is whether keep-alive is on — `KA::Disabled` turns it off,
/// `Busy` is also what a fresh connection reads before its first
/// exchange. Any other combination is one the protocol does not
/// produce, and is declined with the words.
pub fn client_phase(http: &HttpConnObservation) -> Result<(HttpPhase, bool), String> {
    let keep_alive = keep_alive_on(&http.keep_alive)?;
    let in_flight = http
        .client
        .as_ref()
        .is_some_and(|client| client.callback.is_some());
    let phase = match (&http.reading, &http.writing) {
        (HttpReading::Unknown(word), _) | (_, HttpWriting::Unknown(word)) => {
            return Err(format!(
                "a state word reads {word}, which the reviewed range does not have"
            ));
        }
        _ if http.is_closing => HttpPhase::Closing,
        (HttpReading::Closed, _) | (_, HttpWriting::Closed) => HttpPhase::Closing,
        (HttpReading::Body(framing) | HttpReading::Continue(framing), _) => {
            HttpPhase::ReceivingBody(*framing)
        }
        (HttpReading::Init, HttpWriting::Body(framing)) if in_flight => {
            HttpPhase::SendingBody(*framing)
        }
        (HttpReading::Init, HttpWriting::KeepAlive | HttpWriting::Init) if in_flight => {
            HttpPhase::AwaitingResponse
        }
        (HttpReading::Init, HttpWriting::Init) => HttpPhase::Idle,
        (reading, writing) => {
            return Err(format!(
                "reading {reading:?} and writing {writing:?} with{} a callback is not a state \
                 the client protocol produces",
                if in_flight { "" } else { "out" }
            ));
        }
    };
    Ok((phase, keep_alive))
}

/// The server rows of the connection protocol, decided from the words
/// and the handler alone, in the order hyper's own state machine
/// settles them: a closed direction or the dispatcher's closing flag is
/// closing; a decoder in `reading` is a request body arriving, whether
/// or not the handler has returned yet; a handler in flight otherwise
/// is a request being handled, whatever the head's words say (the
/// request may be read through and the response not yet begun); an
/// encoder in `writing` with no handler left is the response body
/// going out; both directions at `Init` with no handler is a
/// connection between exchanges. The second value is whether keep-alive
/// is on, as for the client. Any other combination is one the protocol
/// does not produce, and is declined with the words.
pub fn server_phase(http: &HttpConnObservation) -> Result<(HttpPhase, bool), String> {
    let keep_alive = keep_alive_on(&http.keep_alive)?;
    let in_flight = http.server.as_ref().is_some_and(|server| server.in_flight);
    let phase = match (&http.reading, &http.writing) {
        (HttpReading::Unknown(word), _) | (_, HttpWriting::Unknown(word)) => {
            return Err(format!(
                "a state word reads {word}, which the reviewed range does not have"
            ));
        }
        _ if http.is_closing => HttpPhase::Closing,
        (HttpReading::Closed, _) | (_, HttpWriting::Closed) => HttpPhase::Closing,
        (HttpReading::Body(framing) | HttpReading::Continue(framing), _) => {
            HttpPhase::ReceivingBody(*framing)
        }
        _ if in_flight => HttpPhase::HandlingRequest,
        (HttpReading::Init | HttpReading::KeepAlive, HttpWriting::Body(framing)) => {
            HttpPhase::SendingBody(*framing)
        }
        (HttpReading::Init, HttpWriting::Init) => HttpPhase::Idle,
        (reading, writing) => {
            return Err(format!(
                "reading {reading:?} and writing {writing:?} with no handler in flight is not a \
                 state the server protocol produces"
            ));
        }
    };
    Ok((phase, keep_alive))
}

/// Whether the connection stays open after the exchange: `Disabled`
/// turns it off; `Busy` is also what a fresh connection reads before
/// its first exchange. A word outside the reviewed range declines.
fn keep_alive_on(keep_alive: &KeepAlive) -> Result<bool, String> {
    match keep_alive {
        KeepAlive::Idle | KeepAlive::Busy => Ok(true),
        KeepAlive::Disabled => Ok(false),
        KeepAlive::Unknown(word) => Err(format!(
            "keep-alive reads {word}, which the reviewed range does not have"
        )),
    }
}

/// hyper's HTTP/1 server connection: the phase its state words and
/// its in-flight handler put it in ([`server_phase`]). The dispatch
/// names no primitive of its own: idle, the connection is parked on
/// the socket read, which the registry names, and the header-read
/// timer it may have armed is a held future of its own; handling a
/// request, it is parked on whatever the handler awaits, which the
/// census lists under the handler. So the verdict stands on the
/// words, as the client's body and closing rows do.
pub fn assess_http_server(http: &HttpConnObservation, primitive: ValueKey) -> Assessed {
    let (phase, keep_alive) = match server_phase(http) {
        Ok(decided) => decided,
        Err(reason) => {
            return Assessed::unknown(WaitUnknownReason::ResourceStateUnproven, reason);
        }
    };
    let Some(server) = &http.server else {
        return Assessed::unknown(
            WaitUnknownReason::ResourceStateUnproven,
            "the server connection's dispatch is not bound",
        );
    };
    Assessed::of(WaitAssessment::Waiting(VerifiedWait {
        target: WaitTarget::HttpConn {
            addr: http.conn,
            role: HttpRole::Server,
            version: Some(HttpVersion::Http1),
            phase,
            method: http.method.clone(),
            keep_alive,
            header_read_timer: server.header_read_timer_running,
            via: None,
            caller: None,
        },
        primitive,
        queue_position: None,
    }))
}

/// hyper-util's version-choosing wrapper, still reading a
/// connection's first bytes: a server connection with no version
/// yet, parked on the socket read the registry names. The state
/// was read when the wrapper was observed, so the words are the
/// verdict.
pub fn assess_http_negotiating(
    negotiating: &HttpNegotiatingObservation,
    primitive: ValueKey,
) -> Assessed {
    Assessed::of(WaitAssessment::Waiting(VerifiedWait {
        target: WaitTarget::HttpConn {
            addr: negotiating.wrapper.addr,
            role: HttpRole::Server,
            version: None,
            phase: HttpPhase::Negotiating,
            method: None,
            keep_alive: true,
            header_read_timer: false,
            via: None,
            caller: None,
        },
        primitive,
        queue_position: None,
    }))
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
    pub frame_type: BundleTypeId,
    pub state: String,
    pub await_loc: Option<(String, u32)>,
    /// The local, by name, and its identity.
    pub local: String,
    pub candidate: ValueKey,
    /// The held future's own type, past its adapters.
    pub future: BundleTypeId,
    /// The primitive wrapping the semaphore, when the held chain names
    /// it.
    pub owner: Option<&'static str>,
    /// The acquire's observation, with its queue position filled from
    /// the pass's queue where the queue was established.
    pub acquire: AcquireObservation,
    /// The owner chain's terminal, whose completion is the condition:
    /// its identity, and its type for the diagnosis to name.
    pub primitive: ValueKey,
    pub terminal: BundleTypeId,
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
                    .id();
                barriers.push(PollingBarrier {
                    holder: task.addr,
                    holder_id: task.task_id,
                    frame: index,
                    frame_type: frame.future.ty.id(),
                    state: state.name.to_owned(),
                    await_loc: state.await_loc.map(|(file, line)| (file.to_owned(), line)),
                    local: self.view.str(name).unwrap_or("<bad strref>").to_owned(),
                    candidate: ValueKey::of(local),
                    future,
                    owner: semaphore_owner(&held.chain),
                    acquire,
                    primitive,
                    terminal: terminal.ty.id(),
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
    use crate::tokio::bundle::{FutureInfo, Registries, WaitKind};
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

    /// A client dispatcher's words as one read might find them.
    fn http_words(
        keep_alive: KeepAlive,
        reading: HttpReading,
        writing: HttpWriting,
        in_flight: bool,
        is_closing: bool,
    ) -> HttpConnObservation {
        use crate::tokio::observe::HttpClientObservation;
        let key = ValueKey {
            addr: 0xc72d000,
            ty: hansei_bundle::BundleTypeId(7),
        };
        HttpConnObservation {
            dispatcher: key,
            conn: key.addr,
            role: HttpRole::Client,
            keep_alive,
            reading,
            writing,
            method: in_flight.then(|| "GET".to_owned()),
            is_closing,
            read_buf: Some((0, 8192)),
            client: Some(HttpClientObservation {
                callback: in_flight.then_some(OneshotObservation {
                    future: key,
                    arc: key,
                    inner: 0xc72d9e0,
                    state: super::super::model::OneshotState {
                        word: 0b1000,
                        value_present: Some(false),
                    },
                    rx_waker: None,
                    tx_waker: None,
                    rx_task_at: Some(0xc72d9f0),
                    tx_task_at: Some(0xc72d9e0),
                }),
                rx: Some(key),
                want: Some(0x81f4c90),
            }),
            server: None,
        }
    }

    /// The client rows of the connection protocol, decided from
    /// constructed words: the two the fixture parks in, and every row
    /// it never reaches — a body going out or coming in, either
    /// direction closed, the dispatcher's own closing flag, keep-alive
    /// disabled — plus the combinations the protocol never produces,
    /// which decline naming the words rather than guess.
    #[test]
    fn test_client_phase_decides_every_row() {
        use crate::tokio::bundle::BodyFraming;
        use HttpReading as R;
        use HttpWriting as W;
        let decide =
            |ka, r, w, in_flight, closing| client_phase(&http_words(ka, r, w, in_flight, closing));
        assert_eq!(
            decide(KeepAlive::Idle, R::Init, W::Init, false, false),
            Ok((HttpPhase::Idle, true))
        );
        // A fresh connection reads `Busy` before its first exchange
        // and is idle all the same; a disabled keep-alive is idle with
        // the flag off.
        assert_eq!(
            decide(KeepAlive::Busy, R::Init, W::Init, false, false),
            Ok((HttpPhase::Idle, true))
        );
        assert_eq!(
            decide(KeepAlive::Disabled, R::Init, W::Init, false, false),
            Ok((HttpPhase::Idle, false))
        );
        assert_eq!(
            decide(KeepAlive::Busy, R::Init, W::KeepAlive, true, false),
            Ok((HttpPhase::AwaitingResponse, true))
        );
        // The request taken from the channel, its head about to go.
        assert_eq!(
            decide(KeepAlive::Busy, R::Init, W::Init, true, false),
            Ok((HttpPhase::AwaitingResponse, true))
        );
        assert_eq!(
            decide(
                KeepAlive::Busy,
                R::Init,
                W::Body(Some(BodyFraming::Chunked)),
                true,
                false
            ),
            Ok((HttpPhase::SendingBody(Some(BodyFraming::Chunked)), true))
        );
        // The response head delivered, its body arriving: the callback
        // is gone by then.
        let length = Some(BodyFraming::Length { remaining: 1234 });
        assert_eq!(
            decide(KeepAlive::Busy, R::Body(length), W::KeepAlive, false, false),
            Ok((HttpPhase::ReceivingBody(length), true))
        );
        assert_eq!(
            decide(
                KeepAlive::Busy,
                R::Continue(None),
                W::KeepAlive,
                false,
                false
            ),
            Ok((HttpPhase::ReceivingBody(None), true))
        );
        assert_eq!(
            decide(
                KeepAlive::Disabled,
                R::Body(length),
                W::KeepAlive,
                false,
                false
            ),
            Ok((HttpPhase::ReceivingBody(length), false))
        );
        // Closing outranks everything else the words say.
        assert_eq!(
            decide(KeepAlive::Busy, R::Closed, W::KeepAlive, false, false),
            Ok((HttpPhase::Closing, true))
        );
        assert_eq!(
            decide(KeepAlive::Busy, R::Body(length), W::Closed, false, false),
            Ok((HttpPhase::Closing, true))
        );
        assert_eq!(
            decide(KeepAlive::Idle, R::Init, W::Init, false, true),
            Ok((HttpPhase::Closing, true))
        );
        // A body going out with no callback to deliver the response
        // to, or a written head with no callback, is no client state.
        assert!(
            decide(KeepAlive::Busy, R::Init, W::Body(None), false, false)
                .is_err_and(|reason| reason.contains("without a callback"))
        );
        assert!(decide(KeepAlive::Busy, R::Init, W::KeepAlive, false, false).is_err());
        assert!(decide(KeepAlive::Busy, R::KeepAlive, W::Init, false, false).is_err());
        // A word the reviewed range does not have declines with it.
        assert!(
            decide(
                KeepAlive::Unknown("Paused".to_owned()),
                R::Init,
                W::Init,
                false,
                false
            )
            .is_err_and(|reason| reason.contains("Paused"))
        );
        assert!(
            decide(
                KeepAlive::Idle,
                R::Unknown("Draining".to_owned()),
                W::Init,
                false,
                false
            )
            .is_err_and(|reason| reason
                == "a state word reads Draining, which the reviewed range does not have")
        );
    }

    /// The waker cell a connection's primitive holds is held to this
    /// task's waker: another task's, a non-task waker, an empty cell and
    /// an unread one each decline with their own reason.
    #[test]
    fn test_a_connection_primitive_must_hold_this_tasks_waker() {
        let task = TaskAddr(0x7000);
        let reason = |waker| {
            waker_decline(&waker, task, "cell").map(|assessed| match assessed.assessment {
                WaitAssessment::Unknown(reason) => (reason, assessed.notes.join("")),
                other => panic!("{other:?}"),
            })
        };
        let mine = QueuedWaker::Task {
            addr: 0x7000,
            task_id: Some(1),
        };
        let theirs = QueuedWaker::Task {
            addr: 0x7100,
            task_id: Some(2),
        };
        assert_eq!(reason(Some(mine)), None);
        assert_eq!(
            reason(Some(theirs)),
            Some((
                WaitUnknownReason::ConflictingEvidence,
                "the cell names the task at 0x7100, not this one".to_owned()
            ))
        );
        assert_eq!(
            reason(Some(QueuedWaker::Other { vtable: 0x40 })),
            Some((
                WaitUnknownReason::ResourceStateUnproven,
                "the cell is not a task's (vtable 0x40)".to_owned()
            ))
        );
        assert_eq!(
            reason(Some(QueuedWaker::Unarmed)),
            Some((
                WaitUnknownReason::ConflictingEvidence,
                "the connection parked but the cell is empty".to_owned()
            ))
        );
        assert_eq!(
            reason(None),
            Some((
                WaitUnknownReason::ResourceUnreadable,
                "the cell did not read".to_owned()
            ))
        );
    }

    /// A server dispatcher's words as one read might find them.
    fn server_words(
        keep_alive: KeepAlive,
        reading: HttpReading,
        writing: HttpWriting,
        in_flight: bool,
        is_closing: bool,
    ) -> HttpConnObservation {
        use crate::tokio::observe::HttpServerObservation;
        let key = ValueKey {
            addr: 0x8058d80,
            ty: hansei_bundle::BundleTypeId(7),
        };
        HttpConnObservation {
            dispatcher: key,
            conn: key.addr,
            role: HttpRole::Server,
            keep_alive,
            reading,
            writing,
            method: in_flight.then(|| "GET".to_owned()),
            is_closing,
            read_buf: Some((0, 8192)),
            client: None,
            server: Some(HttpServerObservation {
                in_flight,
                header_read_timer_running: false,
                header_read_timeout: None,
                header_read_timer: None,
                peer: Some("[fd00::25]:57400".to_owned()),
                context: Some("app::Context".to_owned()),
                request: None,
            }),
        }
    }

    /// The server rows of the connection protocol, decided from
    /// constructed words: the two the fixture parks in — idle between
    /// exchanges and a handler in flight — and every row it never
    /// reaches: a request body arriving (with or without the handler
    /// still running), the response body going out, either direction
    /// closed, the dispatcher's own closing flag, keep-alive disabled;
    /// and the combinations the protocol never produces, which decline
    /// naming the words rather than guess.
    #[test]
    fn test_server_phase_decides_every_row() {
        use crate::tokio::bundle::BodyFraming;
        use HttpReading as R;
        use HttpWriting as W;
        let decide = |ka, r, w, in_flight, closing| {
            server_phase(&server_words(ka, r, w, in_flight, closing))
        };
        assert_eq!(
            decide(KeepAlive::Idle, R::Init, W::Init, false, false),
            Ok((HttpPhase::Idle, true))
        );
        // A fresh connection reads `Busy` before its first request and
        // is idle all the same; a disabled keep-alive is idle with the
        // flag off.
        assert_eq!(
            decide(KeepAlive::Busy, R::Init, W::Init, false, false),
            Ok((HttpPhase::Idle, true))
        );
        assert_eq!(
            decide(KeepAlive::Disabled, R::Init, W::Init, false, false),
            Ok((HttpPhase::Idle, false))
        );
        // The handler runs whatever the head's words say once the
        // request is read: still `Busy` reading nothing, or the request
        // read through to keep-alive with the response not yet begun.
        assert_eq!(
            decide(KeepAlive::Busy, R::Init, W::Init, true, false),
            Ok((HttpPhase::HandlingRequest, true))
        );
        assert_eq!(
            decide(KeepAlive::Busy, R::KeepAlive, W::Init, true, false),
            Ok((HttpPhase::HandlingRequest, true))
        );
        // A body arriving is the reading, handler or not.
        let length = Some(BodyFraming::Length { remaining: 1234 });
        assert_eq!(
            decide(KeepAlive::Busy, R::Body(length), W::Init, true, false),
            Ok((HttpPhase::ReceivingBody(length), true))
        );
        assert_eq!(
            decide(
                KeepAlive::Busy,
                R::Continue(None),
                W::KeepAlive,
                false,
                false
            ),
            Ok((HttpPhase::ReceivingBody(None), true))
        );
        // The response body going out, the request read through.
        assert_eq!(
            decide(
                KeepAlive::Busy,
                R::KeepAlive,
                W::Body(Some(BodyFraming::Chunked)),
                false,
                false
            ),
            Ok((HttpPhase::SendingBody(Some(BodyFraming::Chunked)), true))
        );
        assert_eq!(
            decide(KeepAlive::Busy, R::Init, W::Body(None), false, false),
            Ok((HttpPhase::SendingBody(None), true))
        );
        // Closing, whatever else the words say.
        assert_eq!(
            decide(KeepAlive::Busy, R::Closed, W::Init, true, false),
            Ok((HttpPhase::Closing, true))
        );
        assert_eq!(
            decide(KeepAlive::Disabled, R::Init, W::Closed, false, false),
            Ok((HttpPhase::Closing, false))
        );
        assert_eq!(
            decide(KeepAlive::Idle, R::Init, W::Init, false, true),
            Ok((HttpPhase::Closing, true))
        );
        // Combinations the protocol does not produce decline with the
        // words, as do words outside the reviewed range.
        let declined = decide(KeepAlive::Busy, R::KeepAlive, W::Init, false, false).unwrap_err();
        assert!(
            declined.contains("KeepAlive") && declined.contains("no handler in flight"),
            "{declined}"
        );
        let declined = decide(KeepAlive::Busy, R::Init, W::KeepAlive, false, false).unwrap_err();
        assert!(
            declined.contains("Init") && declined.contains("KeepAlive"),
            "{declined}"
        );
        assert!(
            decide(
                KeepAlive::Unknown("Odd".into()),
                R::Init,
                W::Init,
                false,
                false
            )
            .unwrap_err()
            .contains("Odd")
        );
        for declined in [
            decide(
                KeepAlive::Idle,
                R::Unknown("Odd".into()),
                W::Init,
                false,
                false,
            ),
            decide(
                KeepAlive::Idle,
                R::Init,
                W::Unknown("Odd".into()),
                false,
                false,
            ),
        ] {
            let declined = declined.unwrap_err();
            assert!(
                declined.contains("Odd") && declined.contains("reviewed range does not have"),
                "{declined}"
            );
        }
    }

    /// The version-choosing wrapper is observed as the connection only
    /// while it reads the first bytes: on the fixture's four HTTP/1
    /// server tasks the wrapper has chosen its version and observing it
    /// fails naming that, while the fifth's reads as negotiating.
    #[test]
    fn test_a_wrapper_that_chose_its_version_is_not_negotiating() {
        use crate::tokio::observe::ResourceObservation;
        let (bundle, snapshot) = load_any("http-conns");
        let ctx = testkit::context(&bundle, &snapshot);
        let e = testkit::enumerate(&ctx, &snapshot);
        let read = ReadContext::none();
        let (mut chosen, mut negotiating) = (0, 0);
        for task in e
            .list
            .tasks
            .iter()
            .filter(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(ctx.view).contains("http_conns::serve")))
        {
            let inspection = ctx.inspect_task(task, &read).unwrap().unwrap();
            let wrapper = inspection
                .chain
                .frames
                .iter()
                .map(|frame| frame.future)
                .find(|future| {
                    future
                        .ty
                        .name()
                        .starts_with("hyper_util::server::conn::auto::UpgradeableConnection<")
                })
                .expect("the serving task's chain crosses the wrapper");
            let observed = ctx.observe_resource(wrapper, &read);
            match observed.value {
                Some(ResourceObservation::HttpNegotiating(n)) => {
                    assert_eq!(n.wrapper.addr, wrapper.addr);
                    negotiating += 1;
                }
                None => {
                    let detail = observed
                        .issues
                        .iter()
                        .filter_map(|issue| issue.detail.as_deref())
                        .collect::<Vec<_>>()
                        .join("; ");
                    assert!(
                        detail.contains("has chosen its version (H1)"),
                        "{detail}"
                    );
                    chosen += 1;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!((chosen, negotiating), (4, 1));
    }

    /// The server's verdict from its words, and the version-choosing
    /// wrapper's: neither names a primitive of its own, the idle
    /// server's line carries the header-read timer where it is armed,
    /// and a server whose dispatch did not bind is declined rather than
    /// assessed as a client.
    #[test]
    fn test_server_and_negotiating_verdicts_stand_on_the_words() {
        use crate::tokio::observe::{HttpNegotiatingObservation, HttpServerObservation};
        use HttpReading as R;
        use HttpWriting as W;
        let primitive = ValueKey {
            addr: 0x8058d80,
            ty: hansei_bundle::BundleTypeId(7),
        };
        let mut idle = server_words(KeepAlive::Idle, R::Init, W::Init, false, false);
        idle.server.as_mut().unwrap().header_read_timer_running = true;
        let assessed = assess_http_server(&idle, primitive);
        let WaitAssessment::Waiting(verified) = &assessed.assessment else {
            panic!("{:?}", assessed.assessment);
        };
        assert_eq!(
            verified.target().line(),
            "http1 server 0x8058d80 (idle, keep-alive, header-read timer armed)"
        );
        assert!(verified.target().via().is_none());
        assert_eq!(verified.primitive(), primitive);
        let handling = server_words(KeepAlive::Busy, R::Init, W::Init, true, false);
        let assessed = assess_http_server(&handling, primitive);
        let WaitAssessment::Waiting(verified) = &assessed.assessment else {
            panic!("{:?}", assessed.assessment);
        };
        assert_eq!(
            verified.target().line(),
            "http1 server 0x8058d80 (GET in flight, handler running)"
        );
        let mut unbound = server_words(KeepAlive::Idle, R::Init, W::Init, false, false);
        unbound.server = None;
        let assessed = assess_http_server(&unbound, primitive);
        assert!(
            matches!(
                assessed.assessment,
                WaitAssessment::Unknown(WaitUnknownReason::ResourceStateUnproven)
            ),
            "{:?}",
            assessed.assessment
        );
        let odd = server_words(
            KeepAlive::Unknown("Odd".into()),
            R::Init,
            W::Init,
            false,
            false,
        );
        let assessed = assess_http_server(&odd, primitive);
        assert!(
            matches!(
                assessed.assessment,
                WaitAssessment::Unknown(WaitUnknownReason::ResourceStateUnproven)
            ),
            "{:?}",
            assessed.assessment
        );
        let wrapper = ValueKey {
            addr: 0x12345,
            ty: hansei_bundle::BundleTypeId(9),
        };
        let assessed = assess_http_negotiating(&HttpNegotiatingObservation { wrapper }, wrapper);
        let WaitAssessment::Waiting(verified) = &assessed.assessment else {
            panic!("{:?}", assessed.assessment);
        };
        assert_eq!(
            verified.target().line(),
            "http server 0x12345 (negotiating version)"
        );
        assert_eq!(verified.target().group_label(), "http server negotiating");
        assert!(verified.target().via().is_none());
        // A server observation never carries a client's dispatch.
        let _ = HttpServerObservation {
            in_flight: false,
            header_read_timer_running: false,
            header_read_timeout: None,
            header_read_timer: None,
            peer: None,
            context: None,
            request: None,
        };
    }

    /// The connection's target described under no protocol reads the
    /// same words the verdict does, `via` included: the idle client's
    /// request channel and the in-flight client's response callback,
    /// each the target the assessment verified.
    #[test]
    fn test_the_observed_connection_names_its_primitive() {
        let (bundle, snapshot) = load_any("http-conns");
        let ctx = testkit::context(&bundle, &snapshot);
        let e = testkit::enumerate(&ctx, &snapshot);
        let read = ReadContext::none();
        let mut pass = AssessmentPass::new();
        let mut seen = 0;
        for task in e
            .list
            .tasks
            .iter()
            .filter(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(ctx.view).contains("{impl#0}::execute")))
        {
            let inspection = ctx.inspect_task(task, &read).unwrap().unwrap();
            let observation = inspection.primitive.value.as_ref().unwrap();
            let observed = ctx
                .observed_target(&mut pass, observation, &inspection.chain, &e.list, &read)
                .unwrap();
            let assessed = ctx.assess_wait(&mut pass, &inspection, &task.into(), &e.list, &read);
            let WaitAssessment::Waiting(verified) = &assessed.assessment else {
                panic!("{:?} {:?}", assessed.assessment, assessed.notes);
            };
            assert_eq!(observed.line(), verified.target().line());
            let (WaitTarget::HttpConn { phase, via, .. }, Some(verified_via)) =
                (&observed, verified.target().via())
            else {
                panic!("{observed:?}");
            };
            let via = via.as_deref().expect("a client phase with a primitive");
            assert_eq!(via.line(), verified_via.line());
            // And the caller, read the same way on both: the task
            // awaiting the parked response, none while idle.
            assert_eq!(observed.caller(), verified.target().caller());
            match phase {
                HttpPhase::Idle => {
                    assert!(matches!(via, WaitTarget::Channel { .. }), "{via}");
                    assert_eq!(observed.caller(), None);
                }
                HttpPhase::AwaitingResponse => {
                    assert!(
                        matches!(
                            via,
                            WaitTarget::Oneshot {
                                side: OneshotSide::Tx,
                                ..
                            }
                        ),
                        "{via}"
                    );
                    let requester = task_named(&e.list, ctx.view, "http_conns::requester");
                    assert_eq!(
                        observed.caller(),
                        Some(&HttpCaller::Task(TaskRef {
                            addr: requester.addr,
                            task_id: requester.task_id,
                        }))
                    );
                }
                other => panic!("{other:?}"),
            }
            seen += 1;
        }
        assert_eq!(seen, 2);
    }

    fn task_named<'a>(list: &'a TaskList, view: BundleView<'_>, name: &str) -> &'a Task {
        let hits: Vec<&Task> = list
            .tasks
            .iter()
            .filter(|t| matches!(&t.future, FutureInfo::Known(k) if k.name(view).contains(name)))
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
        let analysis = graph::analyze(ctx, &list, &Registries::default(), &ReadContext::none());
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
        let joiner = task_named(&list, ctx.view, "joiner");
        for (bits, expected) in [
            (COMPLETE, "NotWaiting(Complete)"),
            (NOTIFIED, "Runnable(Scheduled)"),
            (RUNNING, "Runnable(ActivePoll)"),
        ] {
            let patched = with_state(&snapshot, &ctx, joiner, bits);
            let ctx = Context::new(&patched, BundleView::new(&bundle)).unwrap();
            let (list, rows, _) = assessed(&ctx, &patched);
            let row = row(&rows, task_named(&list, ctx.view, "joiner"));
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
        let joiner = task_named(&list, ctx.view, "joiner");
        let sleeper = task_named(&list, ctx.view, "sleeper");
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
            row(&rows2, task_named(&list2, ctx.view, "joiner")).assessment,
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
        let row3 = row(&rows3, task_named(&list3, ctx.view, "joiner"));
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
        let row4 = row(&rows4, task_named(&list4, ctx.view, "joiner"));
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
        let sleeper = task_named(&list, ctx.view, "sleeper");
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
            let row = row(&rows, task_named(&list, ctx.view, "sleeper"));
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
        let future = ctx.view.ty(barrier.future).unwrap().name();
        assert!(future.contains("do_async_thing"), "{future}");
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

    /// The address of the `Some` word a head route enters: the option
    /// itself, whose zero is an empty list.
    fn option_word(ctx: &Context<'_, Snapshot>, role: WalkRole, root: Value<'_>) -> u64 {
        let steps = &ctx.view.bundle().walks.entries[&role].steps;
        let option = steps
            .iter()
            .position(|s| matches!(s, Step::Variant(_)))
            .expect("the head route enters Some");
        let crate::tokio::contract::Walked::At(head) = crate::tokio::contract::execute_steps(
            ctx,
            &ReadContext::none(),
            root,
            &steps[..option],
        )
        .unwrap() else {
            panic!("the option is reached");
        };
        head.addr
    }

    /// The `RawWaker` a registered waker walk lands on: its data and
    /// vtable words.
    fn raw_waker_words(ctx: &Context<'_, Snapshot>, role: WalkRole, root: Value<'_>) -> (u64, u64) {
        let raw = ctx
            .walk(role)
            .walk(root)
            .unwrap()
            .optional()
            .expect("armed");
        let data = ctx.walk(WalkRole::WakerData).walk_at(raw).unwrap();
        let vtable = ctx.walk(WalkRole::WakerVtable).walk_at(raw).unwrap();
        (data.addr, vtable.addr)
    }

    /// Re-assess `task` over a patched target.
    fn reassessed<T: Target>(
        bundle: &hansei_bundle::Bundle,
        patched: &T,
        task: &Task,
    ) -> (String, Vec<String>, bool) {
        let ctx = Context::new(patched, BundleView::new(bundle)).unwrap();
        let (list, rows, _) = assessed(&ctx, patched);
        let task = list.tasks.iter().find(|t| t.addr == task.addr).unwrap();
        let row = row(&rows, task);
        (
            format!("{:?}", row.assessment),
            row.notes.clone(),
            row.observation.is_some(),
        )
    }

    /// The recv protocol on the channels fixture: the receiver parked
    /// on an empty channel with its one sender held elsewhere waits,
    /// with the sender count, the capacity and nothing unread. Then
    /// each window the protocol distinguishes, frozen by hand: a
    /// message written at the read index, the last sender gone and
    /// the close marker set, that sender gone before the marker, the
    /// receiver closed from its own side with every permit back and
    /// with one still out, the waker cell mid-registration, the waker
    /// another task's, and no waker at all.
    #[test]
    fn test_the_recv_protocol_reads_the_channel_and_its_head_block() {
        use hansei_bundle::tokio::{atomic_waker, mpsc};
        let (bundle, snapshot) = load_any("channels");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, _) = assessed(&ctx, &snapshot);
        let waiter = task_named(&list, ctx.view, "recv_waiter");
        let parked = row(&rows, waiter);
        let WaitAssessment::Waiting(wait) = &parked.assessment else {
            panic!("recv waits: {:?} {:?}", parked.assessment, parked.notes);
        };
        let WaitTarget::Channel {
            addr,
            senders,
            capacity,
            unread,
        } = wait.target()
        else {
            panic!("on a channel: {:?}", wait.target());
        };
        assert_eq!((*senders, *capacity, *unread), (1, Some(4), 0));
        assert_eq!(wait.queue_position(), None);
        let Some(ResourceObservation::Recv(recv)) = &parked.observation else {
            unreachable!()
        };
        assert_eq!(recv.chan.addr, *addr);
        assert_eq!(recv.future, wait.primitive());

        let chan = ctx.read_keyed(recv.chan, &ReadContext::none()).unwrap();
        let tx_count = ctx.walk(WalkRole::ChanTxCount).walk_at(chan).unwrap().addr;
        let rx_closed = ctx.walk(WalkRole::ChanRxClosed).walk_at(chan).unwrap().addr;
        let waker_state = ctx
            .walk(WalkRole::ChanRxWakerState)
            .walk_at(chan)
            .unwrap()
            .addr;
        let permits = ctx
            .walk(WalkRole::ChanSemaphorePermits)
            .walk_at(chan)
            .unwrap()
            .addr;
        let index_word = ctx.walk(WalkRole::ChanRxIndex).walk_at(chan).unwrap();
        let tail_word = ctx.walk(WalkRole::ChanTailPosition).walk_at(chan).unwrap();
        let index: u64 = index_word.parse(&snapshot).unwrap();
        assert_eq!(index, 0, "the fixture's receiver has read nothing");
        let (data, vtable) = raw_waker_words(&ctx, WalkRole::ChanRxWaker, chan);
        let head = ctx.walk(WalkRole::ChanRxHead).walk_at(chan).unwrap();
        let block_ty = head.ty.pointer_target().unwrap();
        let head: u64 = head.parse(&snapshot).unwrap();
        let block = Value::read(&snapshot, block_ty, head).unwrap();
        let start: u64 = ctx.walk(WalkRole::BlockStartIndex).read(block).unwrap();
        assert_eq!(
            start,
            index & mpsc::BLOCK_MASK,
            "the head block holds the index"
        );
        let ready = ctx.walk(WalkRole::BlockReadySlots).walk_at(block).unwrap();
        let ready_word: u64 = ready.parse(&snapshot).unwrap();
        assert_eq!(
            ready_word & (1 << (index & mpsc::SLOT_MASK)),
            0,
            "nothing at the index"
        );
        let holder = task_named(&list, ctx.view, "channels::hold");
        // The windows move the read index off zero where its slot's
        // bit or the unread count would otherwise be indistinguishable
        // from a zero.
        let cases: Vec<(&str, Corrupt<'_>, &str, &str)> = vec![
            (
                "a message at the read index",
                Corrupt::new(&snapshot)
                    .patch(index_word.addr, 1)
                    .patch(tail_word.addr, 2)
                    .patch(ready.addr, ready_word | (1 << 1)),
                "ResourceReady(MessageReady)",
                "",
            ),
            (
                "two slots claimed and neither written",
                Corrupt::new(&snapshot)
                    .patch(index_word.addr, 1)
                    .patch(tail_word.addr, 3),
                "Waiting(",
                "unread: 2",
            ),
            (
                "the read index past the claimed tail",
                Corrupt::new(&snapshot).patch(index_word.addr, 1),
                "Unknown(ConflictingEvidence)",
                "past the claimed tail",
            ),
            (
                "the last sender gone, the close marker set",
                Corrupt::new(&snapshot)
                    .patch(tx_count, 0)
                    .patch(ready.addr, ready_word | mpsc::TX_CLOSED),
                "ResourceReady(ChannelClosed)",
                "",
            ),
            (
                "the last sender gone before its close marker",
                Corrupt::new(&snapshot).patch(tx_count, 0),
                "Unknown(ConflictingEvidence)",
                "no sender is left",
            ),
            (
                "the receiver closed with every permit back",
                Corrupt::new(&snapshot).patch_byte(rx_closed, 1),
                "ResourceReady(ChannelClosed)",
                "",
            ),
            (
                "the receiver closed with a permit out",
                Corrupt::new(&snapshot)
                    .patch_byte(rx_closed, 1)
                    .patch(permits, 3 << 1),
                "Waiting(",
                "unread: 0",
            ),
            (
                "the waker cell mid-registration",
                Corrupt::new(&snapshot).patch(waker_state, atomic_waker::REGISTERING),
                "Unknown(ResourceStateUnproven)",
                "being registered",
            ),
            (
                "the waker cell mid-wake",
                Corrupt::new(&snapshot).patch(waker_state, atomic_waker::WAKING),
                "Unknown(ResourceStateUnproven)",
                "being taken",
            ),
            (
                "another task's waker",
                Corrupt::new(&snapshot).patch(data, holder.addr.0),
                "Unknown(ConflictingEvidence)",
                "not this one",
            ),
            (
                "no waker registered",
                Corrupt::new(&snapshot).patch(vtable, 0),
                "Unknown(ConflictingEvidence)",
                "registered no waker",
            ),
        ];
        for (what, patched, expected, said) in cases {
            let (assessment, notes, observed) = reassessed(&bundle, &patched, waiter);
            let matched = if expected.ends_with('(') {
                assessment.starts_with(expected)
            } else {
                assessment == expected
            };
            assert!(matched, "{what}: {assessment} {notes:?}");
            assert!(
                assessment.contains(said) || notes.iter().any(|n| n.contains(said)),
                "{what}: {assessment} {notes:?}"
            );
            assert!(observed, "{what}: the observation is kept");
        }

        // The semaphore's closed bit is read beside its permits, for
        // the description's sake: the fixture's is open.
        let read = ReadContext::none();
        let open = ctx.observe_channel(recv.chan, &read, &mut ScanBudget::default());
        assert_eq!(
            (open.semaphore_closed, open.capacity),
            (Some(false), Some(4))
        );
        let closed = Corrupt::new(&snapshot).patch(
            permits,
            (4 << hansei_bundle::tokio::semaphore::PERMIT_SHIFT)
                | hansei_bundle::tokio::semaphore::CLOSED,
        );
        let ctx = Context::new(&closed, BundleView::new(&bundle)).unwrap();
        let shut = ctx.observe_channel(recv.chan, &read, &mut ScanBudget::default());
        assert_eq!(
            (shut.semaphore_closed, shut.available),
            (Some(true), Some(4))
        );
    }

    /// Every waiter on one `Notify` gets its own place in wake order:
    /// the joinset fixture parks five tasks on one, and their verified
    /// waits take the five positions once each.
    #[test]
    fn test_notify_waiters_take_distinct_wake_positions() {
        let (bundle, snapshot) = load_any("joinset");
        let ctx = testkit::context(&bundle, &snapshot);
        let (_, rows, _) = assessed(&ctx, &snapshot);
        let mut positions: Vec<usize> = rows
            .iter()
            .filter_map(|r| r.assessment.verified())
            .filter(|w| {
                matches!(
                    w.target(),
                    WaitTarget::Notify {
                        waiters: Some(5),
                        ..
                    }
                )
            })
            .map(|w| {
                w.queue_position()
                    .expect("an established list places its node")
            })
            .collect();
        positions.sort_unstable();
        assert_eq!(positions, [0, 1, 2, 3, 4]);
    }

    /// The oneshot receiver's protocol on the armed-select fixture: the
    /// holder, parked on a receiver whose sender is leaked alive,
    /// waits, with the shared state read through its `Arc` — the
    /// receiver's cell set, nothing sent, the cell holding its waker.
    /// Then each window the protocol distinguishes, frozen by hand:
    /// the sender completed, the receiver closed, the cell's bit clear,
    /// and the cell holding another task's waker. The selector's held
    /// `once` describes as a oneshot too, and its `changed` as the
    /// watch whose `Notify` the chain ends on.
    #[test]
    fn test_the_oneshot_protocol_reads_the_receivers_inner() {
        use hansei_bundle::tokio::oneshot;
        let (bundle, snapshot) = load_any("armed-select");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, _) = assessed(&ctx, &snapshot);
        let holder = task_named(&list, ctx.view, "armed_select::holder");
        let parked = row(&rows, holder);
        let WaitAssessment::Waiting(wait) = &parked.assessment else {
            panic!("oneshot waits: {:?} {:?}", parked.assessment, parked.notes);
        };
        let WaitTarget::Oneshot { addr, state, .. } = wait.target() else {
            panic!("on a oneshot: {:?}", wait.target());
        };
        assert!(state.rx_task_set() && !state.complete() && !state.closed());
        assert_eq!(state.value_present, Some(false));
        assert_eq!(
            wait.target().to_string(),
            format!("oneshot rx {addr:#x} (nothing sent, sender alive)")
        );
        let Some(ResourceObservation::Oneshot(observed)) = &parked.observation else {
            unreachable!()
        };
        assert_eq!(observed.inner, *addr);
        assert_eq!(observed.future, wait.primitive());
        assert_eq!(
            observed.rx_waker.as_ref().and_then(|w| w.task()),
            Some(holder.addr.0)
        );
        // The `Inner` is the `ArcInner`'s data, past the two counts.
        assert!(observed.inner > observed.arc.addr && observed.inner - observed.arc.addr <= 16);

        let arc = ctx.read_keyed(observed.arc, &ReadContext::none()).unwrap();
        // The two task cells sit where the `Inner`'s own layout puts
        // them, whether or not a waker is stored: what a slot found in
        // either is joined to this observation by.
        let inner_ty = arc.ty.member("data").unwrap().ty();
        let cell = |name: &str| Some(observed.inner + inner_ty.member(name).unwrap().offset());
        assert_eq!(observed.rx_task_at, cell("rx_task"));
        assert_eq!(observed.tx_task_at, cell("tx_task"));
        assert!(!state.tx_task_set() && observed.tx_waker.is_none());
        let state_at = ctx.walk(WalkRole::OneshotState).walk_at(arc).unwrap();
        let word: u64 = state_at.parse(&snapshot).unwrap();
        assert_eq!(word, state.word);
        let (data, _) = raw_waker_words(&ctx, WalkRole::OneshotRxTask, arc);
        let selector = task_named(&list, ctx.view, "armed_select::selector");
        let cases: Vec<(&str, Corrupt<'_>, &str)> = vec![
            (
                "the sender completed",
                Corrupt::new(&snapshot).patch(state_at.addr, word | oneshot::VALUE_SENT),
                "ResourceReady(OneshotComplete)",
            ),
            (
                "the receiver closed",
                Corrupt::new(&snapshot).patch(state_at.addr, word | oneshot::CLOSED),
                "ResourceReady(OneshotClosed)",
            ),
            (
                "no waker stored",
                Corrupt::new(&snapshot).patch(state_at.addr, word & !oneshot::RX_TASK_SET),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "another task's waker",
                Corrupt::new(&snapshot).patch(data, selector.addr.0),
                "Unknown(ConflictingEvidence)",
            ),
        ];
        for (what, patched, expected) in cases {
            let (assessment, notes, observed) = reassessed(&bundle, &patched, holder);
            assert_eq!(assessment, expected, "{what}: {notes:?}");
            assert!(observed, "{what}: the observation is kept");
        }

        // The selector's finds: the held receiver describes as the
        // oneshot it is, and `changed` as the watch its `Notified`
        // belongs to — its chain crosses tokio's `Coop` wrapper to the
        // `changed_impl` inside, whose borrowed `Shared` names the
        // channel, since `changed`'s own frame keeps no receiver past
        // its await. That `changed_impl` is on the chain, not a find of
        // its own.
        let census = testkit::census(&ctx, &list);
        let find = |local: &str| {
            census
                .held
                .iter()
                .find(|h| h.local == local)
                .unwrap_or_else(|| panic!("a `{local}` find"))
        };
        assert!(matches!(find("once").wait, Some(WaitKind::Oneshot { .. })));
        assert!(matches!(find("changed").wait, Some(WaitKind::Watch { .. })));
        assert!(
            census.held.iter().all(|h| h.local != "fut"),
            "changed_impl is accounted to changed's chain"
        );
        assert!(matches!(find("recv").wait, Some(WaitKind::Channel { .. })));
    }

    /// The notified protocol on the channels fixture: the waiter parked
    /// on the `Notify` waits, first in a one-node list, with its node's
    /// waker naming it. Then each window, frozen by hand: the future
    /// `Done`, its node notified, the future never polled, the `Notify`
    /// claiming no waiters, a `notify_waiters` since the future was
    /// made, the list read under its lock, the list empty, and the
    /// node's waker another task's.
    #[test]
    fn test_the_notified_protocol_reads_the_future_and_the_notify() {
        use hansei_bundle::tokio::notify;
        let (bundle, snapshot) = load_any("channels");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, _) = assessed(&ctx, &snapshot);
        let waiter = task_named(&list, ctx.view, "notify_waiter");
        let parked = row(&rows, waiter);
        let WaitAssessment::Waiting(wait) = &parked.assessment else {
            panic!("notified waits: {:?} {:?}", parked.assessment, parked.notes);
        };
        let WaitTarget::Notify {
            addr,
            state,
            waiters,
        } = wait.target()
        else {
            panic!("on a Notify: {:?}", wait.target());
        };
        assert_eq!(*waiters, Some(1));
        assert_eq!(state.map(|s| s & notify::STATE_MASK), Some(notify::WAITING));
        assert_eq!(
            wait.target().to_string(),
            format!("notify rx {addr:#x} (waiting, 1 queued)")
        );
        assert_eq!(wait.queue_position(), Some(0));
        let Some(ResourceObservation::Notified(notified)) = &parked.observation else {
            unreachable!()
        };
        assert_eq!(notified.notify.addr, *addr);
        assert_eq!(
            (notified.state, notified.notification),
            (NotifiedState::Waiting, 0)
        );
        let wait_list = ctx.observe_notify(
            notified.notify,
            &ReadContext::none(),
            &mut ScanBudget::default(),
        );
        assert!(wait_list.established());
        assert_eq!(wait_list.waiters.len(), 1);
        assert_eq!(wait_list.waiters[0].addr, notified.node);
        assert_eq!(wait_list.waiters[0].waker.task(), Some(waiter.addr.0));
        assert_eq!(wait_list.waiters[0].notification, notify::NOTIFICATION_NONE);

        let future = primitive_of(&ctx, waiter);
        let state = ctx
            .walk(WalkRole::NotifiedState)
            .walk_at(future)
            .unwrap()
            .addr;
        let node = ctx.walk(WalkRole::NotifiedWaiter).walk_at(future).unwrap();
        let notification = ctx
            .walk(WalkRole::NotifyWaiterNotification)
            .walk_at(node)
            .unwrap()
            .addr;
        let (data, _) = raw_waker_words(&ctx, WalkRole::NotifyWaiterWaker, node);
        let notify_value = ctx
            .read_keyed(notified.notify, &ReadContext::none())
            .unwrap();
        let notify_state = ctx
            .walk(WalkRole::NotifyState)
            .walk_at(notify_value)
            .unwrap();
        let state_word: u64 = notify_state.parse(&snapshot).unwrap();
        assert_eq!(state_word & notify::STATE_MASK, notify::WAITING);
        let lock = ctx
            .walk(WalkRole::NotifyLock)
            .walk_at(notify_value)
            .unwrap()
            .addr;
        let head = option_word(&ctx, WalkRole::NotifyQueueHead, notify_value);
        let holder = task_named(&list, ctx.view, "channels::hold");
        let cases: Vec<(&str, Corrupt<'_>, &str)> = vec![
            (
                "done",
                Corrupt::new(&snapshot).patch_byte(state, 2),
                "ResourceReady(Notified)",
            ),
            (
                "the node notified",
                Corrupt::new(&snapshot).patch(notification, notify::NOTIFICATION_ONE),
                "ResourceReady(Notified)",
            ),
            (
                "never polled",
                Corrupt::new(&snapshot).patch_byte(state, 0),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "the Notify claims no waiters",
                Corrupt::new(&snapshot).patch(notify_state.addr, state_word & !notify::STATE_MASK),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "notify_waiters ran since",
                Corrupt::new(&snapshot)
                    .patch(notify_state.addr, state_word + (1 << notify::CALLS_SHIFT)),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "read under its lock",
                Corrupt::new(&snapshot).patch_byte(lock, 0b01),
                "Unknown(ResourceStateUnproven)",
            ),
            (
                "absent from an empty list",
                Corrupt::new(&snapshot).patch(head, 0),
                "Unknown(ConflictingEvidence)",
            ),
            (
                "another task's waker",
                Corrupt::new(&snapshot).patch(data, holder.addr.0),
                "Unknown(ConflictingEvidence)",
            ),
        ];
        for (what, patched, expected) in cases {
            let (assessment, notes, observed) = reassessed(&bundle, &patched, waiter);
            assert_eq!(assessment, expected, "{what}: {notes:?}");
            assert!(observed, "{what}: the observation is kept");
        }
    }

    /// A chain that ends at a `Notified` is complete under its rule,
    /// so a queued acquire held by value in the frame above it is a
    /// polling barrier: the walk-shapes abandoner waits on its
    /// `Notify`, and the acquire it polled once and left — queued,
    /// ungranted — is held off its chain. The victim, parked on the
    /// same mutex, waits too. A chain the rule leaves unknown proves
    /// none of this, which is what the Notified windows in
    /// [`test_the_notified_protocol_reads_the_future_and_the_notify`]
    /// pin the other way round.
    #[test]
    fn test_a_notified_chain_proves_the_by_value_barrier() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let (list, rows, barriers) = assessed(&ctx, &snapshot);
        let abandoner = row(&rows, task_named(&list, ctx.view, "abandoner"));
        let WaitAssessment::Waiting(wait) = &abandoner.assessment else {
            panic!("{:?} {:?}", abandoner.assessment, abandoner.notes);
        };
        assert!(matches!(wait.target(), WaitTarget::Notify { .. }));
        assert!(matches!(
            abandoner.continuation,
            ContinuationStatus::Primitive
        ));
        assert!(matches!(
            abandoner.observation,
            Some(ResourceObservation::Notified(_))
        ));
        let barrier = barriers
            .iter()
            .find(|b| b.holder == abandoner.task.addr)
            .unwrap_or_else(|| panic!("{barriers:#?}"));
        assert_eq!(barrier.local, "fut");
        assert!(!barrier.granted());
        assert!(barrier.acquire.queued);
        assert_eq!(barrier.acquire.needed, 1);
        assert_eq!(barrier.primitive, wait.primitive());
        // The victim, parked on the same mutex, does wait.
        let victim = row(&rows, task_named(&list, ctx.view, "victim"));
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
            let task = task_named(&list, ctx.view, name);
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
        let gated = row(&rows, task_named(&list, ctx.view, "local_gated_reader"));
        assert!(matches!(
            gated.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::Continuation)
        ));

        // The reader's registration: its readiness word, its guard,
        // and the reader slot's waker data word.
        let reader = task_named(&list, ctx.view, "local_reader");
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
        let other = task_named(&list, ctx.view, "local_writer").addr.0;
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
            let row = row(&rows, task_named(&list, ctx.view, "local_reader"));
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
        let watcher = task_named(&list, ctx.view, "local_watcher");
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
            row(&rows2, task_named(&list2, ctx.view, "local_watcher")).assessment,
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
        let row5 = row(&rows5, task_named(&list5, ctx.view, "local_watcher"));
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
            row(&rows3, task_named(&list3, ctx.view, "local_watcher")).assessment,
            WaitAssessment::ResourceReady(ReadyReason::IoNotified)
        ));

        // An exhausted write never parks: a suspended one contradicts
        // the protocol.
        let writer = task_named(&list, ctx.view, "local_writer");
        let write = primitive_of(&ctx, writer);
        let len = ctx.walk(WalkRole::IoWriteAllBufLen).walk_at(write).unwrap();
        let patched = Corrupt::new(&snapshot).patch(len.addr, 0);
        let ctx4 = Context::new(&patched, BundleView::new(&bundle)).unwrap();
        let (list4, rows4, _) = assessed(&ctx4, &patched);
        let row4 = row(&rows4, task_named(&list4, ctx.view, "local_writer"));
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
            (ChainEnd::NeverReady, "NeverReady"),
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
        let watcher = task_named(&list, ctx.view, "local_watcher");
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
        let victim = task_named(&list, ctx.view, "victim");
        let other = task_named(&list, ctx.view, "abandoner").addr.0;
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
        let row = row(&rows, task_named(&list, ctx.view, "victim"));
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
            frame_type: BundleTypeId(0),
            state: String::new(),
            await_loc: None,
            local: String::new(),
            candidate: ValueKey {
                addr: 1,
                ty: acquire_ty,
            },
            future: BundleTypeId(0),
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
            terminal: BundleTypeId(0),
            edges: Vec::new(),
        };
        assert!(!barrier.granted());
        barrier.acquire.needed = 0;
        assert!(barrier.granted());
    }
}

#[cfg(test)]
mod caller_tests {
    use super::*;
    use crate::tokio::TaskAddr;
    use crate::tokio::bundle::OneshotState;
    use crate::tokio::observe::HttpClientObservation;

    fn callback(word: u64, rx_waker: Option<QueuedWaker>) -> OneshotObservation {
        let key = ValueKey {
            addr: 0xc72d000,
            ty: hansei_bundle::BundleTypeId(7),
        };
        OneshotObservation {
            future: key,
            arc: key,
            inner: 0xc72d9e0,
            state: OneshotState {
                word,
                value_present: Some(false),
            },
            rx_waker,
            tx_waker: None,
            rx_task_at: Some(0xc72d9f0),
            tx_task_at: Some(0xc72d9e0),
        }
    }

    /// Who awaits the response, from the callback's words alone: the
    /// task whose waker the receiver cell holds; a receiver that closed
    /// its side is gone whatever else the word says; one that stored no
    /// waker is alive and unparked; a waker that is no task's is named
    /// by its vtable; a cell the word says is set but that did not read
    /// says so — and only the two in-flight phases ask.
    #[test]
    fn test_the_caller_is_read_from_the_callback() {
        use hansei_bundle::tokio::oneshot::{CLOSED, RX_TASK_SET, TX_TASK_SET};
        let waker = QueuedWaker::Task {
            addr: 0x7ae9380,
            task_id: Some(4307675),
        };
        let named = HttpCaller::Task(TaskRef {
            addr: TaskAddr(0x7ae9380),
            task_id: Some(4307675),
        });
        let set = RX_TASK_SET | TX_TASK_SET;
        assert_eq!(http_caller(&callback(set, Some(waker.clone()))), named);
        assert_eq!(
            http_caller(&callback(set | CLOSED, Some(waker.clone()))),
            HttpCaller::Gone
        );
        assert_eq!(
            http_caller(&callback(TX_TASK_SET, None)),
            HttpCaller::Unparked
        );
        assert_eq!(
            http_caller(&callback(
                set,
                Some(QueuedWaker::Other { vtable: 0x70738b8 })
            )),
            HttpCaller::NotATask {
                vtable: 0x70738b8,
                cell: Some(0xc72d9f0),
            }
        );
        assert_eq!(http_caller(&callback(set, None)), HttpCaller::Unread);
        assert_eq!(
            http_caller(&callback(set, Some(QueuedWaker::Unarmed))),
            HttpCaller::Unread
        );
        let client = HttpClientObservation {
            callback: Some(callback(set, Some(waker))),
            rx: None,
            want: None,
        };
        assert_eq!(
            in_flight_caller(HttpPhase::AwaitingResponse, &client),
            Some(named.clone())
        );
        assert_eq!(
            in_flight_caller(HttpPhase::SendingBody(None), &client),
            Some(named)
        );
        for phase in [
            HttpPhase::Idle,
            HttpPhase::ReceivingBody(None),
            HttpPhase::Closing,
        ] {
            assert_eq!(in_flight_caller(phase, &client), None, "{phase:?}");
        }
        let unread = HttpClientObservation {
            callback: None,
            rx: None,
            want: None,
        };
        assert_eq!(in_flight_caller(HttpPhase::AwaitingResponse, &unread), None);
    }
}

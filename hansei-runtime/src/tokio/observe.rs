// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Raw resource observations, and what a read over target memory is
//! corroborated against.
//!
//! An observation is what a supported reader decodes out of one
//! resource value — the task a `JoinHandle` names, the five words of a
//! semaphore `Acquire`, an io operation's registration — with nothing
//! decided about it: not whether the holder is waiting on it, not
//! whether the referenced task is listed, not whether a queue position
//! means anything. Those are later operations over these records, and
//! keeping them apart is what lets discovery consume a held handle
//! without first diagnosing a wait.
//!
//! Every route that dereferences a pointer on behalf of discovery or
//! semantic interpretation takes a [`ReadContext`] explicitly: the
//! allocator's account of the heap, where the target has one, so a
//! referent the allocator has taken back is refused before it is read
//! and a live block bounds what may be read out of it. The recorded
//! walk contract's own accessors pass an empty context — they read
//! what the runtime's structures point at, and their corroboration is
//! the census's — so no caller inherits the renderer's implicit
//! peeling or an unstated heap by accident.

use super::bundle::{
    BodyFraming, HttpRole, Interest, NotifyWaiter, OneshotState, QueuedWaker, SemaphoreWaiter,
};
use super::{RawInstant, TaskAddr};

use hansei_bundle::{BundleTypeId, IoOperationKind, Step};

/// A value's identity for observation caches and diagnostics: where it
/// is and which nominal type it was read as. The type is part of the
/// key because one address read as two types is two observations, and
/// two library copies can give one layout two ids.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ValueKey {
    pub addr: u64,
    pub ty: BundleTypeId,
}

impl ValueKey {
    /// The key of a value as it was read.
    pub fn of(value: reify::Value<'_>) -> Self {
        ValueKey {
            addr: value.addr,
            ty: value.ty.id(),
        }
    }
}

/// The evidence a read is held to.
#[derive(Copy, Clone, Default)]
pub struct ReadContext<'a> {
    /// The allocator's account of what is handed out, where the target
    /// has one to consult. `None` claims nothing: every read is then
    /// bounded only by the target's own mappings.
    pub heap: Option<&'a dyn reify::Heap>,
}

impl<'a> ReadContext<'a> {
    /// No allocator evidence: reads are uncorroborated.
    pub const fn none() -> Self {
        ReadContext { heap: None }
    }

    /// Reads corroborated against `heap`.
    pub fn with_heap(heap: &'a dyn reify::Heap) -> Self {
        ReadContext { heap: Some(heap) }
    }

    /// Whether the allocator has taken back the block at `addr`. Only a
    /// `Freed` answer refuses; `Live` is the ordinary answer and
    /// `Unknown` claims nothing.
    pub fn taken_back(&self, addr: u64) -> bool {
        self.heap
            .is_some_and(|heap| matches!(heap.locate(addr), reify::Liveness::Freed))
    }

    /// Why a typed read of `size` bytes at `addr` cannot be believed,
    /// or `None` when the allocator permits it: the block is freed, or
    /// the typed range runs past the live block holding its start. An
    /// `Unknown` block permits the read but corroborates nothing.
    pub fn refusal(&self, addr: u64, size: u64) -> Option<Refusal> {
        let heap = self.heap?;
        match heap.locate(addr) {
            reify::Liveness::Freed => Some(Refusal::Freed { addr }),
            reify::Liveness::Live { block } => {
                let end = addr.checked_add(size)?;
                (end > block.end).then_some(Refusal::OutsideAllocation { addr, size, block })
            }
            reify::Liveness::Unknown => None,
        }
    }
}

/// Why the allocator's evidence refuses a typed read. Carried as the
/// source of the executor's error so a reader that reports issues can
/// name the kind without parsing the message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The block holding `addr` has been taken back.
    Freed { addr: u64 },
    /// The typed range runs past the live block holding its start.
    OutsideAllocation {
        addr: u64,
        size: u64,
        block: std::ops::Range<u64>,
    },
}

impl Refusal {
    /// The issue kind this refusal is reported as.
    pub fn kind(&self) -> WalkIssueKind {
        match self {
            Refusal::Freed { .. } => WalkIssueKind::Freed,
            Refusal::OutsideAllocation { .. } => WalkIssueKind::OutsideAllocation,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Freed { addr } => {
                write!(f, "the allocator has taken back the memory at {addr:#x}")
            }
            Refusal::OutsideAllocation { addr, size, block } => write!(
                f,
                "{size} bytes at {addr:#x} run past the allocation holding it \
                 ({:#x}..{:#x})",
                block.start, block.end
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The issue an error raised on the way to a value is reported as: the
/// allocator's refusal by its kind where one is in the chain, and a
/// failed read otherwise. The message is kept whole as the detail.
pub fn issue_of(at: ValueKey, error: &anyhow::Error) -> WalkIssue {
    let kind = error
        .chain()
        .find_map(|e| e.downcast_ref::<Refusal>())
        .map(Refusal::kind)
        .unwrap_or(WalkIssueKind::ReadFailed);
    WalkIssue::new(at, kind, format!("{error:#}"))
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// One observation, with everything that went wrong obtaining it.
///
/// `value` is `None` when the observation was unavailable — the value
/// is not a bound resource, or a read on the way failed — and never
/// stands for an empty queue, a completed future, or a task that is not
/// there. The issues say why where there is a why; a value that is
/// simply not a resource has none.
#[derive(Debug)]
pub struct Observed<T> {
    pub value: Option<T>,
    pub issues: Vec<WalkIssue>,
}

impl<T> Observed<T> {
    /// Nothing observed and nothing to report: the value is no resource.
    pub fn none() -> Self {
        Observed {
            value: None,
            issues: Vec::new(),
        }
    }

    /// An observation obtained without incident.
    pub fn of(value: T) -> Self {
        Observed {
            value: Some(value),
            issues: Vec::new(),
        }
    }

    /// Nothing observed, for the recorded reason.
    pub fn failed(issue: WalkIssue) -> Self {
        Observed {
            value: None,
            issues: vec![issue],
        }
    }
}

/// A `JoinHandle`: the task header it references. Whether that task is
/// listed, complete, or awaited is not observed here — the handle
/// establishes the reference and nothing else.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JoinObservation {
    pub handle: ValueKey,
    pub header: TaskAddr,
}

/// A `batch_semaphore::Acquire`: its five raw words, read in place.
/// `queued` records that a previous poll linked the node into the
/// queue and is not cleared by a grant, so it is not current queue
/// membership; `queue_position` is filled only from a complete,
/// quiescent queue observation ([`QueueObservation::position`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AcquireObservation {
    pub future: ValueKey,
    /// The contended `Semaphore`, keyed by its nominal type: two
    /// library copies give one layout two ids, and a queue read under
    /// one must not answer for the other.
    pub semaphore: ValueKey,
    /// The `Waiter` node embedded in the future.
    pub node: u64,
    /// Permits the acquire asked for.
    pub requested: u64,
    /// Permits the node still needs; 0 once fully granted.
    pub needed: u64,
    pub queued: bool,
    pub queue_position: Option<usize>,
}

/// A bounded io operation or a readiness await: the exact registration
/// it belongs to, and what its own storage says about the wait.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IoObservation {
    pub future: ValueKey,
    pub operation: IoOperationKind,
    /// The `ScheduledIo` the operation's reader or writer registered,
    /// or a readiness await named outright — the driver's identity for
    /// the resource.
    pub scheduled_io: ValueKey,
    /// The readiness the operation waits for: a direction for a
    /// reader or writer, the recorded interest for a readiness await.
    pub interest: Interest,
    /// A readiness await's own `Waiter` node, embedded in the future;
    /// the direction slots hold a bare waker and have no node.
    pub waiter_node: Option<u64>,
    /// Bytes the operation has left to move — an empty read buffer or
    /// an exhausted write completes without parking.
    pub remaining: Option<u64>,
    /// A readiness await's own state word.
    pub readiness_state: Option<IoFutureState>,
    /// The `is_ready` flag on a readiness await's node.
    pub waiter_ready: Option<bool>,
}

/// A readiness await's `State`, as its own enumeration spells it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IoFutureState {
    Init,
    Waiting,
    Done,
    /// A word no enumerator claims.
    Unknown(u64),
}

/// Whether a guarded structure was read outside anyone's critical
/// section. A stopped process need not have stopped outside every
/// lock, and a list read while its mutex is held is a list mid-edit.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Consistency {
    /// The guard was decoded and reads unlocked.
    Quiescent,
    /// The guard reads locked: whatever was read may be mid-edit.
    Mutating,
    /// The guard's representation is not one this reader decodes, or
    /// it could not be read.
    Unknown,
}

/// A `tokio::time::Sleep`: the deadline it caches and where its timer
/// entry is in the wheel's life.
#[derive(Clone, PartialEq, Debug)]
pub struct TimerObservation {
    pub future: ValueKey,
    pub deadline: Option<RawInstant>,
    pub state: TimerRegistrationState,
}

/// Where a sleep's timer entry is, decoded from the entry's state word
/// with the same sentinels the wheel harvest reads
/// ([`WheelState`](super::bundle::WheelState)).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TimerRegistrationState {
    /// The sleep has never been polled: no timer entry exists yet, so
    /// nothing is registered anywhere.
    NotRegistered,
    /// In the wheel, due at this tick.
    Registered { tick: u64 },
    /// Marked to fire by the driver, the wakeup not yet delivered.
    PendingFire,
    /// The entry exists but is not in the wheel: fired or cancelled
    /// and not yet reclaimed by a poll, or not yet inserted.
    Deregistered,
    /// The word could not be observed: the binding is absent, the
    /// timer is of a flavor this reader does not decode, or the read
    /// failed. The issues say which.
    Unknown,
}

/// The bounded mpsc receiver's `recv` future: the `PollFn` itself holds
/// nothing but a reference to the receiver's `Rx`, so the observation
/// is the channel that `Rx` shares — everything the protocol reads is
/// in it, read on demand ([`ChannelObservation`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecvObservation {
    pub future: ValueKey,
    /// The `Chan<T, S>` behind the receiver's `Arc`, keyed by its
    /// nominal type.
    pub chan: ValueKey,
}

/// A `Notified`: what its own storage says, read in place. The `Notify`
/// it borrowed is read on demand ([`NotifyObservation`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NotifiedObservation {
    pub future: ValueKey,
    /// The `Notify` the future borrowed, keyed by its nominal type.
    pub notify: ValueKey,
    pub state: NotifiedState,
    /// The `Waiter` node embedded in the future.
    pub node: u64,
    /// The node's notification word: which wake, if any, unlinked it.
    pub notification: u64,
    /// The `notify_waiters` count the future was created at.
    pub calls: u64,
}

/// A `Notified`'s `State`, as its own enumeration names it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NotifiedState {
    Init,
    Waiting,
    Done,
    /// A word no enumerator claims.
    Unknown(u64),
}

/// A `oneshot::Receiver`: the shared `Inner` behind its `Arc` and every
/// word the recv protocol reads from it, read in place — the state
/// word, whether the value slot holds one, and the waker in the
/// receiver's own task cell.
#[derive(Clone, PartialEq, Debug)]
pub struct OneshotObservation {
    pub future: ValueKey,
    /// The `ArcInner<Inner<T>>` the receiver's pointer names, keyed by
    /// its nominal type.
    pub arc: ValueKey,
    /// The `Inner`'s own address: the primitive a slot in either task
    /// cell names.
    pub inner: u64,
    pub state: OneshotState,
    /// The waker in `rx_task`, where the state word says one is there.
    pub rx_waker: Option<QueuedWaker>,
    /// The waker in `tx_task`, where the state word says one is there:
    /// a sender's `poll_closed` registration, which an HTTP client
    /// connection parks its response callback on.
    pub tx_waker: Option<QueuedWaker>,
}

/// hyper's `KA`, the connection's keep-alive word.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeepAlive {
    /// Between exchanges.
    Idle,
    /// An exchange is in progress — also a fresh connection's word,
    /// before its first.
    Busy,
    /// The connection closes after this exchange.
    Disabled,
    /// An enumerator the reviewed range does not have.
    Unknown(String),
}

/// hyper's `Reading`, with the body's framing where the variant
/// carries a decoder and that decoder's `kind` read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HttpReading {
    Init,
    Continue(Option<BodyFraming>),
    Body(Option<BodyFraming>),
    KeepAlive,
    Closed,
    Unknown(String),
}

/// hyper's `Writing`, with the body's framing where the variant
/// carries an encoder and that encoder's `kind` read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HttpWriting {
    Init,
    Body(Option<BodyFraming>),
    KeepAlive,
    Closed,
    Unknown(String),
}

/// hyper's HTTP/1 `Dispatcher` as one read found it: every word the
/// connection verdict reads, in place, and the primitive the role's
/// dispatch is parked on where it names one.
#[derive(Clone, PartialEq, Debug)]
pub struct HttpConnObservation {
    pub dispatcher: ValueKey,
    /// The `Conn`'s address: what a filter names the connection by.
    pub conn: u64,
    pub role: HttpRole,
    pub keep_alive: KeepAlive,
    pub reading: HttpReading,
    pub writing: HttpWriting,
    /// The method's name (`GET`), where a message is in flight and its
    /// method is one of the named ones; `None` between exchanges, for
    /// an extension method, and where the word did not read.
    pub method: Option<String>,
    pub is_closing: bool,
    /// The read buffer's fill: bytes read off the socket and not yet
    /// parsed, and the buffer's capacity; `None` where the words did
    /// not read.
    pub read_buf: Option<(u64, u64)>,
    /// The client dispatch's words, for a client.
    pub client: Option<HttpClientObservation>,
    /// The server dispatch's words, for a server.
    pub server: Option<HttpServerObservation>,
}

/// The client dispatch as one read found it.
#[derive(Clone, PartialEq, Debug)]
pub struct HttpClientObservation {
    /// The response callback's oneshot, where a request is in flight:
    /// the `Sender` the dispatcher watches for cancellation.
    pub callback: Option<OneshotObservation>,
    /// The channel behind the request receiver, keyed by the `Chan`'s
    /// own type.
    pub rx: Option<ValueKey>,
}

/// The server dispatch as one read found it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpServerObservation {
    /// Whether a handler is running: the `Option` behind `in_flight`
    /// is `Some`.
    pub in_flight: bool,
    /// The running handler's future type, as the chain walk names it
    /// past its adapters — the concrete type behind a boxed `dyn` where
    /// the bundle carries it. `None` between requests, and where the
    /// box's pointee could not be named.
    pub handler: Option<String>,
    /// Whether the header-read timer is armed.
    pub header_read_timer_running: bool,
    /// The peer's address as std spells it, where the binding routes to
    /// one and it read.
    pub peer: Option<String>,
}

/// hyper-util's version-choosing wrapper as one read found it, still
/// reading a connection's first bytes: a connection with no HTTP/1
/// words yet, named by the wrapper's own address.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct HttpNegotiatingObservation {
    pub wrapper: ValueKey,
}

/// What one resource value was observed to be.
#[derive(Clone, PartialEq, Debug)]
pub enum ResourceObservation {
    Join(JoinObservation),
    Acquire(AcquireObservation),
    Timer(TimerObservation),
    Io(IoObservation),
    Recv(RecvObservation),
    Notified(NotifiedObservation),
    Oneshot(OneshotObservation),
    /// Boxed: the connection's words are several times any other
    /// observation's, and every chain end carries one of these.
    HttpConn(Box<HttpConnObservation>),
    HttpNegotiating(HttpNegotiatingObservation),
}

/// What a pop at the receiver's read index would find, as `Rx::pop`
/// finds it: the block holding the index, then its ready word.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SlotState {
    /// A written value sits at the index.
    Value,
    /// No value at the index and the block carries the senders' close
    /// marker: the channel is closed and drained.
    Closed,
    /// No value at the index and no close marker: nothing to read,
    /// whether or not a sender has claimed the slot.
    Empty,
    /// No block holds the index yet: nothing to read.
    NoBlock,
    /// The block chain could not be walked to the index; the issues
    /// say why.
    Unknown,
}

/// A bounded mpsc channel as one read found it: every word the recv
/// protocol reads, read on explicit demand from the `Chan` a recv
/// observation named. Each word is `None` where it did not read, with
/// the failure in `issues`.
#[derive(Debug)]
pub struct ChannelObservation {
    pub chan: ValueKey,
    /// Live `Sender`s (`tx_count`); weak senders are not counted.
    pub senders: Option<u64>,
    /// The next slot a sender claims.
    pub tail_position: Option<u64>,
    /// The next slot the receiver reads.
    pub index: Option<u64>,
    /// Whether the receiver closed the channel from its own side.
    pub rx_closed: Option<bool>,
    pub slot: SlotState,
    /// The bounded semaphore's bound: the channel's capacity.
    pub capacity: Option<u64>,
    /// Permits free in the bounded semaphore: capacity less the
    /// messages queued or in flight.
    pub available: Option<u64>,
    pub semaphore_closed: Option<bool>,
    /// The `AtomicWaker`'s state word; anything but at rest means a
    /// registration or a wake is mid-flight.
    pub waker_state: Option<u64>,
    /// The waker the receiver registered, or none.
    pub waker: Option<QueuedWaker>,
    pub issues: Vec<WalkIssue>,
}

/// A `Notify`'s state word and wait list as one walk found it, read on
/// explicit demand from the `Notify` a `Notified` borrowed. Like a
/// semaphore's queue, only a complete walk under an unlocked guard
/// establishes membership or wake order.
#[derive(Debug)]
pub struct NotifyObservation {
    pub notify: ValueKey,
    /// The state word: the list state in its low bits, the
    /// `notify_waiters` count above them.
    pub state: Option<u64>,
    /// The nodes reached: in `notify_one`'s wake order when
    /// `complete`, in walk order — newest first — otherwise.
    pub waiters: Vec<NotifyWaiter>,
    pub complete: bool,
    pub consistency: Consistency,
    pub issues: Vec<WalkIssue>,
}

impl NotifyObservation {
    /// Whether the walk established the list: complete, and read
    /// outside its lock.
    pub fn established(&self) -> bool {
        self.complete && self.consistency == Consistency::Quiescent
    }

    /// The node's place in `notify_one`'s wake order, if established.
    pub fn position(&self, node: u64) -> Option<usize> {
        if !self.established() {
            return None;
        }
        self.waiters.iter().position(|w| w.addr == node)
    }
}

/// A semaphore's wait queue as one walk found it, read on explicit
/// demand rather than as a side effect of identifying every acquire.
///
/// The prefix a failing walk reached is kept beside the failure: those
/// nodes are real for discovery and diagnostics. Only a complete walk
/// of a quiescent queue establishes wake order or absence, which is
/// what [`position`](Self::position) and [`contains`](Self::contains)
/// are held to.
#[derive(Debug)]
pub struct QueueObservation {
    pub semaphore: ValueKey,
    /// The nodes reached: in wake order when `complete`, in walk order
    /// — newest first — otherwise, since reversing a prefix places
    /// nothing.
    pub waiters: Vec<SemaphoreWaiter>,
    pub complete: bool,
    pub consistency: Consistency,
    /// The `CLOSED` bit of the permits word.
    pub closed: Option<bool>,
    /// The wait list's own closed flag, kept under its lock.
    pub queue_closed: Option<bool>,
    /// The permits word's available count.
    pub available: Option<u64>,
    pub issues: Vec<WalkIssue>,
}

impl QueueObservation {
    /// Whether the walk establishes the queue's contents: every node
    /// reached, with nobody mid-edit.
    pub fn established(&self) -> bool {
        self.complete && self.consistency == Consistency::Quiescent
    }

    /// `node`'s wake-order position, when the walk establishes one.
    pub fn position(&self, node: u64) -> Option<usize> {
        if !self.established() {
            return None;
        }
        self.waiters.iter().position(|w| w.addr == node)
    }

    /// Whether `node` is queued: a node reached is queued whatever the
    /// walk's state, and only an established walk can say one is not.
    pub fn contains(&self, node: u64) -> Option<bool> {
        if self.waiters.iter().any(|w| w.addr == node) {
            return Some(true);
        }
        self.established().then_some(false)
    }
}

/// One reference to a task header, with where it was found.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TaskReference {
    pub target: TaskAddr,
    pub source: ReferenceSource,
    /// The resource value the reference was decoded from.
    pub source_value: Option<ValueKey>,
    /// The task whose storage the scan started in.
    pub root_task: Option<TaskAddr>,
    /// The literal steps from the scan's root to the source value.
    pub path: Vec<Step>,
}

/// What kind of storage referenced the task.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ReferenceSource {
    /// A `JoinHandle`'s raw task pointer.
    JoinHandle,
    /// A task waker in a semaphore's wait queue.
    SemaphoreWaker,
    /// A task waker armed on a timer entry.
    TimerWaker,
    /// A task waker parked on an io registration.
    IoWaker,
    /// The join waker a task's Trailer holds.
    JoinTrailerWaker,
    /// A `JoinSet` entry's handle.
    JoinSetEntry,
    /// The task waker a bounded mpsc receiver registered on its channel.
    ChannelWaker,
    /// A task waker queued on a `Notify`.
    NotifyWaker,
    /// The task waker a oneshot receiver stored in its task cell.
    OneshotWaker,
}

impl std::fmt::Display for ReferenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::JoinHandle => "a JoinHandle",
            Self::SemaphoreWaker => "a task waker queued on a semaphore",
            Self::TimerWaker => "a task waker armed on a timer",
            Self::IoWaker => "a task waker parked on an io registration",
            Self::JoinTrailerWaker => "a join waker in a task's Trailer",
            Self::JoinSetEntry => "a JoinSet entry",
            Self::ChannelWaker => "a task waker registered by a channel receiver",
            Self::NotifyWaker => "a task waker queued on a Notify",
            Self::OneshotWaker => "a task waker stored by a oneshot receiver",
        })
    }
}

/// Something a walk could not do, at the value it could not do it to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WalkIssue {
    pub at: ValueKey,
    pub kind: WalkIssueKind,
    pub detail: Option<String>,
}

impl WalkIssue {
    pub fn new(at: ValueKey, kind: WalkIssueKind, detail: impl Into<String>) -> Self {
        WalkIssue {
            at,
            kind,
            detail: Some(detail.into()),
        }
    }

    pub fn bare(at: ValueKey, kind: WalkIssueKind) -> Self {
        WalkIssue {
            at,
            kind,
            detail: None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WalkIssueKind {
    /// The target could not serve the bytes, or a recorded binding is
    /// not there to execute.
    ReadFailed,
    /// The allocator has taken the referent back.
    Freed,
    /// The typed range runs past the live allocation holding it.
    OutsideAllocation,
    /// The bytes do not decode as the type they were read as.
    InvalidLayout,
    /// A variant or option the route needed is not the active one.
    InactiveStorage,
    /// Storage whose initialization the bundle cannot vouch for: a
    /// coroutine no reviewed convention bound, a capture that may be
    /// uninitialized in this state.
    UnknownInitialization,
    UnknownContinuation,
    UnknownDynamicType,
    AmbiguousDynamicType,
    /// An array in relevant storage: its elements are not scanned.
    UnsupportedArray,
    /// The inline descent reached its depth limit.
    DepthLimit,
    /// Futures nested inside futures past the nesting limit.
    HopLimit,
    /// A run-wide visit or referent budget, or a container's child
    /// cap, was exhausted.
    VisitLimit,
    Cycle,
    /// A container's own count disagrees with what its lists hold.
    CountMismatch,
}

// ---------------------------------------------------------------------------
// Scan limits and sinks
// ---------------------------------------------------------------------------

/// Where a scan's hard limits sit. Safety caps against corrupt memory
/// and pathological programs, not evidence thresholds: a healthy
/// workload that reaches one is reported, never silently trimmed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ScanLimits {
    /// Aggregate levels descended inside one root value.
    pub max_depth: u16,
    /// Futures nested inside futures, each a new root.
    pub max_future_nesting: u16,
    /// Frames an await chain may run to.
    pub max_chain_depth: u16,
    /// Nodes one container walk lists.
    pub max_children: u32,
    /// Values visited inline, per discovery run.
    pub max_inline_visits: u64,
    /// Referents read through a pointer, per discovery run.
    pub max_referent_expansions: u64,
    /// Items of discovery work — an owner enumerated, a task scanned,
    /// a find validated, a registry harvested — per discovery run.
    pub max_work_items: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        ScanLimits {
            max_depth: 12,
            max_future_nesting: 8,
            max_chain_depth: 64,
            max_children: 65_536,
            max_inline_visits: 16_777_216,
            max_referent_expansions: 1_048_576,
            max_work_items: 4_194_304,
        }
    }
}

/// The run-wide counters a scan charges against its limits. Depth and
/// nesting are call-stack parameters; these two accumulate across every
/// root of one discovery run.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScanBudget {
    pub limits: ScanLimits,
    pub inline_visits: u64,
    pub referent_expansions: u64,
}

impl ScanBudget {
    pub fn new(limits: ScanLimits) -> Self {
        ScanBudget {
            limits,
            inline_visits: 0,
            referent_expansions: 0,
        }
    }

    /// Charge one inline visit, before making it: `false` when the
    /// budget is spent and the visit must not happen.
    pub fn charge_visit(&mut self) -> bool {
        if self.inline_visits >= self.limits.max_inline_visits {
            return false;
        }
        self.inline_visits += 1;
        true
    }

    /// Charge one referent expansion, before reading it.
    pub fn charge_referent(&mut self) -> bool {
        if self.referent_expansions >= self.limits.max_referent_expansions {
            return false;
        }
        self.referent_expansions += 1;
        true
    }
}

impl Default for ScanBudget {
    fn default() -> Self {
        ScanBudget::new(ScanLimits::default())
    }
}

/// What one scan call cost and whether it saw everything it set out to:
/// `complete` is false for any refused, unsupported, failed or capped
/// subtree, with the sink holding the precise issues.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ScanCompletion {
    pub complete: bool,
    pub inline_visits: u64,
    pub referent_expansions: u64,
}

/// Where a scan delivers what it finds, one reference at a time. The
/// path is borrowed from the scanner's own stack; a sink that keeps
/// provenance copies it, and a counting sink allocates nothing.
pub trait ReferenceSink {
    fn reference(
        &mut self,
        target: TaskAddr,
        source: ReferenceSource,
        source_value: Option<ValueKey>,
        root_task: Option<TaskAddr>,
        path: &[Step],
    );

    fn issue(&mut self, issue: WalkIssue);
}

/// A sink that keeps everything, path included.
#[derive(Default, Debug)]
pub struct CollectedReferences {
    pub references: Vec<TaskReference>,
    pub issues: Vec<WalkIssue>,
}

impl ReferenceSink for CollectedReferences {
    fn reference(
        &mut self,
        target: TaskAddr,
        source: ReferenceSource,
        source_value: Option<ValueKey>,
        root_task: Option<TaskAddr>,
        path: &[Step],
    ) {
        self.references.push(TaskReference {
            target,
            source,
            source_value,
            root_task,
            path: path.to_vec(),
        });
    }

    fn issue(&mut self, issue: WalkIssue) {
        self.issues.push(issue);
    }
}

/// The raw lock words guarding tokio's wait lists. Like the task state
/// bits, these are constants folded into their crates' code, knowable
/// only from source: parking_lot's `RawMutex` keeps its state in one
/// byte whose low bit is the lock, and std's futex mutex keeps a word
/// that reads zero while unlocked. Every other guard representation —
/// the pthread mutex std uses where there is no futex — is one this
/// reader does not decode.
pub(crate) mod lock {
    pub const PARKING_LOT_RAW_MUTEX: &str = "parking_lot::raw_mutex::RawMutex";
    pub const PARKING_LOT_LOCKED_BIT: u8 = 0b01;
    pub const STD_FUTEX_MUTEX: &str = "std::sys::sync::mutex::futex::Mutex";
    pub const STD_FUTEX_UNLOCKED: u32 = 0;
}

/// Whether the guard `lock` was read locked, by its concrete
/// representation. `Unknown` for any representation this does not
/// decode, and for one whose bytes are short.
pub(crate) fn lock_consistency(lock: reify::Value<'_>) -> Consistency {
    match lock.ty.name() {
        lock::PARKING_LOT_RAW_MUTEX => match lock.bytes.first() {
            Some(state) if state & lock::PARKING_LOT_LOCKED_BIT != 0 => Consistency::Mutating,
            Some(_) => Consistency::Quiescent,
            None => Consistency::Unknown,
        },
        lock::STD_FUTEX_MUTEX => match lock.bytes.first_chunk::<4>() {
            Some(word) if u32::from_le_bytes(*word) != lock::STD_FUTEX_UNLOCKED => {
                Consistency::Mutating
            }
            Some(_) => Consistency::Quiescent,
            None => Consistency::Unknown,
        },
        _ => Consistency::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokio::bundle::QueuedWaker;

    fn key(addr: u64) -> ValueKey {
        ValueKey {
            addr,
            ty: BundleTypeId(7),
        }
    }

    fn waiter(addr: u64) -> SemaphoreWaiter {
        SemaphoreWaiter {
            addr,
            needed: 1,
            waker_at: None,
            waker: QueuedWaker::Unarmed,
        }
    }

    fn queue(waiters: &[u64], complete: bool, consistency: Consistency) -> QueueObservation {
        QueueObservation {
            semaphore: key(0x100),
            waiters: waiters.iter().map(|&a| waiter(a)).collect(),
            complete,
            consistency,
            closed: Some(false),
            queue_closed: Some(false),
            available: Some(0),
            issues: Vec::new(),
        }
    }

    /// Only a complete walk of a quiescent queue places a node or says
    /// one is absent; a partial or mid-edit queue still says a node it
    /// reached is queued.
    #[test]
    fn test_positions_and_absence_need_an_established_queue() {
        let established = queue(&[0xa, 0xb], true, Consistency::Quiescent);
        assert!(established.established());
        assert_eq!(established.position(0xb), Some(1));
        assert_eq!(established.position(0xc), None);
        assert_eq!(established.contains(0xa), Some(true));
        assert_eq!(established.contains(0xc), Some(false));

        for (complete, consistency) in [
            (false, Consistency::Quiescent),
            (true, Consistency::Mutating),
            (true, Consistency::Unknown),
        ] {
            let q = queue(&[0xa, 0xb], complete, consistency);
            assert!(!q.established(), "{complete} {consistency:?}");
            assert_eq!(q.position(0xa), None, "{complete} {consistency:?}");
            assert_eq!(q.contains(0xa), Some(true), "{complete} {consistency:?}");
            assert_eq!(q.contains(0xc), None, "{complete} {consistency:?}");
        }
    }

    /// The budget refuses the visit past its limit, and charges only
    /// the ones it permits.
    #[test]
    fn test_the_budget_charges_before_the_visit_and_refuses_past_its_limit() {
        let mut budget = ScanBudget::new(ScanLimits {
            max_inline_visits: 2,
            max_referent_expansions: 1,
            ..ScanLimits::default()
        });
        assert!(budget.charge_visit());
        assert!(budget.charge_visit());
        assert!(!budget.charge_visit());
        assert_eq!(budget.inline_visits, 2);
        assert!(budget.charge_referent());
        assert!(!budget.charge_referent());
        assert_eq!(budget.referent_expansions, 1);
    }

    /// The guard decoder knows two representations by name — the
    /// parking_lot byte with its lock bit, the std futex word that
    /// reads zero unlocked — and answers `Unknown` for anything else,
    /// short bytes included.
    #[test]
    fn test_the_guard_decoder_reads_each_representation_by_name() {
        use crate::testkit;
        use hansei_bundle::BundleView;

        // The Linux set: std's futex mutex exists only there.
        let (bundle, _) = testkit::load("linux", "futurelock");
        let view = BundleView::new(&bundle);
        let raw_mutex = view
            .find_by_name(lock::PARKING_LOT_RAW_MUTEX)
            .next()
            .expect("parking_lot's RawMutex");
        let futex = view
            .find_by_name(lock::STD_FUTEX_MUTEX)
            .next()
            .expect("std's futex Mutex");
        let other = view.find_by_name("u32").next().unwrap();
        let at = 0x1000;

        assert_eq!(
            lock_consistency(reify::Value::new(raw_mutex, at, &[0])),
            Consistency::Quiescent
        );
        // The parked bit alone is not the lock bit.
        assert_eq!(
            lock_consistency(reify::Value::new(raw_mutex, at, &[0b10])),
            Consistency::Quiescent
        );
        assert_eq!(
            lock_consistency(reify::Value::new(raw_mutex, at, &[0b11])),
            Consistency::Mutating
        );
        assert_eq!(
            lock_consistency(reify::Value::new(raw_mutex, at, &[])),
            Consistency::Unknown
        );

        assert_eq!(
            lock_consistency(reify::Value::new(futex, at, &[0, 0, 0, 0])),
            Consistency::Quiescent
        );
        assert_eq!(
            lock_consistency(reify::Value::new(futex, at, &[1, 0, 0, 0])),
            Consistency::Mutating
        );
        assert_eq!(
            lock_consistency(reify::Value::new(futex, at, &[0, 0, 0, 2])),
            Consistency::Mutating
        );
        assert_eq!(
            lock_consistency(reify::Value::new(futex, at, &[0, 0])),
            Consistency::Unknown
        );

        assert_eq!(
            lock_consistency(reify::Value::new(other, at, &[0, 0, 0, 0])),
            Consistency::Unknown
        );
    }

    /// The collecting sink keeps a copy of the borrowed path.
    #[test]
    fn test_the_collecting_sink_copies_the_path() {
        let mut sink = CollectedReferences::default();
        let path = [Step::Deref, Step::ActiveVariant];
        sink.reference(
            TaskAddr(0x10),
            ReferenceSource::JoinHandle,
            Some(key(0x20)),
            Some(TaskAddr(0x30)),
            &path,
        );
        sink.issue(WalkIssue::bare(key(0x40), WalkIssueKind::Cycle));
        assert_eq!(
            sink.references,
            vec![TaskReference {
                target: TaskAddr(0x10),
                source: ReferenceSource::JoinHandle,
                source_value: Some(key(0x20)),
                root_task: Some(TaskAddr(0x30)),
                path: path.to_vec(),
            }]
        );
        assert_eq!(sink.issues.len(), 1);
        assert_eq!(sink.issues[0].kind, WalkIssueKind::Cycle);
        assert_eq!(sink.issues[0].detail, None);
    }
}

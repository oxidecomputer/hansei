// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the walker reports: the observation model — tasks, workers,
//! await chains, wait targets — and its `Display` forms. Nothing here
//! reads a target; [`bundle`](super::bundle) builds these, and the
//! census, graph, and every command consume them.

pub use super::discovery::{
    OwnerIndex, OwnerKey, OwnerResolution, TaskKind, TaskRecord, TaskStore,
};
use super::observe::{Consistency, ReferenceSource, ValueKey};
use super::{Lifecycle, Location, RawInstant, TaskAddr, TaskState};

use hansei_bundle::tokio::timer;
use hansei_bundle::{BundleTypeId, FutureKind, FutureTarget, SemanticIssueKind, TaskEntryId};
use reify::Value;

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

/// Result of resolving the bundle's symbol fingerprint against the target.
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

/// Which scheduler a discovered runtime runs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum RuntimeFlavor {
    MultiThread,
    CurrentThread,
}

impl fmt::Display for RuntimeFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiThread => f.write_str("multi_thread"),
            Self::CurrentThread => f.write_str("current_thread"),
        }
    }
}

/// One runtime discovered in the target: the flavor's `Handle`
/// (deref'd — everything the runtime shares hangs off it) and the
/// threads whose `Context` points at it. current_thread makes more than
/// one runtime per process ordinary — each `block_on` thread can carry
/// its own — so discovery reports them all; see
/// [`Context::find_runtimes`].
#[derive(Clone, Debug)]
pub struct RuntimeRef<'b> {
    pub flavor: RuntimeFlavor,
    pub handle: Value<'b>,
    /// The id the global owned-list counter gave this scheduler's
    /// list — what every task it owns carries as its `Header.owner_id`,
    /// and what an owner claim on this runtime is held to. `None`
    /// where the row did not bind against this target, in which case
    /// nothing validates as owned by it.
    pub owned_id: Option<u64>,
    /// The tids of the workers whose `Context` reaches this handle, in
    /// discovery order. Empty on a runtime no thread is currently in —
    /// see [`DiscoveryRoute::WorkerContext`].
    pub worker_tids: Vec<u32>,
    /// How the runtime was found.
    pub route: DiscoveryRoute,
}

impl RuntimeRef<'_> {
    /// The stable key discovery files this runtime's tasks under.
    pub fn owner_key(&self) -> OwnerKey {
        OwnerKey::Runtime {
            flavor: self.flavor,
            handle: self.handle.addr,
        }
    }
}

/// One `tokio::task::LocalSet` discovered in the target: the
/// `task::local::Shared` its task list hangs off — the address every
/// discovery route converges on — and how it was found. See
/// [`Context::discover_hidden_tasks`].
#[derive(Clone, Debug)]
pub struct LocalSetRef<'b> {
    /// The set's `Shared`, read in place; its address is the set's
    /// identity.
    pub shared: Value<'b>,
    /// `LocalOwnedTasks.id`: drawn from the same global counter as the
    /// scheduler lists' ids, and carried by every task of the set as
    /// its `Header.owner_id` — the claim enumeration cross-checks.
    pub owned_id: u64,
    /// The tokio `ThreadId` counter of the thread the set is pinned to,
    /// when its row bound.
    pub owner: Option<u64>,
    /// The LWP pinned to: the TLS route's thread, or the worker whose
    /// `Context.thread_id` equals `owner`. `None` when neither answers
    /// — the owning thread may hold no runtime context at all.
    pub owner_tid: Option<u32>,
    /// The route that found the set first.
    pub route: DiscoveryRoute,
}

impl LocalSetRef<'_> {
    /// The stable key discovery files this set's tasks under.
    pub fn owner_key(&self) -> OwnerKey {
        OwnerKey::LocalSet {
            shared: self.shared.addr,
        }
    }
}

/// Which route found a task list's owner — a [`LocalSetRef`], or a
/// [`RuntimeRef`] no thread's `Context` points at.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DiscoveryRoute {
    /// A thread's `Context` points at it: the ordinary way a runtime is
    /// found, and the only one that also says which threads run it. No
    /// local set is ever found this way.
    WorkerContext,
    /// A timer entry parked in a discovered runtime's own wheel was
    /// armed with one of their wakers — a registry of parked tasks
    /// whatever list owns them, and so a route to a list nothing
    /// enumerated points at.
    Wheel,
    /// An io resource registered with a discovered runtime's driver
    /// held one of their wakers — the same registry argument as the
    /// wheel, for tasks waiting on a socket rather than on time.
    Io,
    /// The thread's `task::local::CURRENT` anchor, populated only while
    /// a set is being polled (or held entered).
    Tls,
    /// An entry of a discovered runtime's blocking-pool queue: a
    /// `spawn_blocking` cell waiting for a pool thread, which no task
    /// list carries.
    BlockingQueue,
    /// The reference scan over an enumerated task's initialized
    /// storage ([`Context::scan_references`]) met a reference of this
    /// kind to one of its tasks — wherever in that storage it sat, not
    /// only at the end of an await chain.
    ///
    /// [`Context::scan_references`]: super::bundle::Context::scan_references
    Scanned(ReferenceSource),
}

impl fmt::Display for DiscoveryRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerContext => f.write_str("a thread's runtime context"),
            Self::Wheel => f.write_str("a task waker on a timer parked in a runtime's wheel"),
            Self::Io => {
                f.write_str("a task waker on an io resource registered with a runtime's driver")
            }
            Self::Tls => f.write_str("the polling thread's TLS anchor"),
            Self::BlockingQueue => f.write_str("a runtime's blocking-pool queue"),
            Self::Scanned(source) => write!(f, "{source} scanned in an enumerated task's storage"),
        }
    }
}

/// The class of task an unlisted `Header` belongs to, keyed by the
/// *type* of its cell's recorded scheduler `S` — a definite statement
/// from recorded data, never a guess. `None` travels where the future
/// (and so its `S`) could not be resolved.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum UnlistedTaskKind {
    /// Bound into a `LocalSet`'s own list — one discovery could not
    /// enumerate, or the task would be listed.
    LocalSet,
    /// A `spawn_blocking` task; no list carries those at all.
    Blocking,
    /// Bound into the sharded owned list of a runtime the session's
    /// population does not cover — one a `--runtime` selection left
    /// out, or one discovery reached and refused, since a runtime a
    /// task points at is otherwise enumerated along with it.
    OtherRuntime(RuntimeFlavor),
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
    pub(crate) fn from_word(word: u64) -> Self {
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

/// What a current_thread runtime's one "worker" — the `block_on`
/// thread — is doing, and whether its root future has a wakeup pending;
/// the CT sibling of [`ParkStates`]. See [`Context::ct_park_state`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CtParkState {
    /// `Shared.woken`: a wakeup for the `block_on` future was delivered
    /// and not yet consumed by a poll.
    pub woken: bool,
    pub activity: CtActivity,
}

/// Where a CT `block_on` thread is in its run loop, read from where the
/// scheduler core is and which task the thread says it is inside. The
/// loop checks the core *into* the context's `RefCell` around every
/// closure it runs under the scheduler — a park (with the driver taken
/// out of the core for exactly that long), a poll of the root future,
/// and a poll of each spawned task alike — and holds it on the stack,
/// unreadable from here, only in the bookkeeping between those. A
/// checked-in core with its driver therefore says "polling", and the
/// thread-local task id says what: `None` is the root future, since
/// nothing but a task's poll sets it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CtActivity {
    /// Core checked in, driver taken: blocked in the system's readiness
    /// call (or a zero-duration yield to it) on the runtime's behalf.
    Parked,
    /// Core checked in, driver present, no task id: polling the
    /// `block_on` future itself.
    PollingBlockOn,
    /// Core checked in, driver present, task id set: polling the task
    /// with that id — one the scheduler ran, or one a `LocalSet` polled
    /// under the root future. The id is what the thread-local says; it
    /// is the caller's to check against the task list, as a task id
    /// also stands while a completed task's output is taken.
    PollingTask(u64),
    /// Core checked out to the thread's stack, no task id: between
    /// polls, in the scheduler's own bookkeeping.
    BetweenPolls,
    /// Core checked out to the thread's stack with a task id set: the
    /// one path that leaves this is runtime shutdown, which drains the
    /// owned tasks with the core held as a local and drops each
    /// task's future under its id.
    DroppingTask(u64),
}

impl fmt::Display for CtActivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parked => f.write_str("parked in the driver"),
            Self::PollingBlockOn => f.write_str("polling the block_on future"),
            Self::PollingTask(id) => write!(f, "polling task {id}"),
            Self::BetweenPolls => f.write_str("between polls"),
            Self::DroppingTask(id) => write!(f, "dropping task {id} at shutdown"),
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

/// What the registry harvests keep beside their discovery candidates:
/// every wheel entry and io waiter touched, joined to the task whose
/// waker it holds. Built once at attach, while the wheel and
/// registration walks run; the tasks listing joins it to rows by task
/// address.
#[derive(Debug, Default)]
pub struct Registries {
    /// Every entry linked in a walked wheel, armed or not.
    pub timers: Vec<TimerEntryInfo>,
    /// Every io resource in a walked registration list.
    pub io: Vec<IoResourceInfo>,
    /// The target's clock at the moment it stopped, where its lwps
    /// stamp one — what a deadline is reported relative to.
    pub stopped: Option<RawInstant>,
    /// The joins' index, built on the first lookup — so after the
    /// harvest has pushed its last entry, which is the only order the
    /// attach runs them in. A production target has tens of thousands
    /// of entries and as many tasks asking after them, and scanning
    /// the lists per task made every listing quadratic.
    by_task: OnceLock<TaskIndex>,
}

/// Where each task's entries sit: positions into `timers`, and
/// (resource, waiter) positions into `io`.
#[derive(Debug, Default)]
struct TaskIndex {
    timers: HashMap<u64, Vec<usize>>,
    io: HashMap<u64, Vec<(usize, usize)>>,
}

impl Registries {
    /// Registries over the given harvests, for a caller that has them
    /// whole; the attach fills the fields as it walks instead.
    pub fn new(timers: Vec<TimerEntryInfo>, io: Vec<IoResourceInfo>) -> Registries {
        Registries {
            timers,
            io,
            stopped: None,
            by_task: OnceLock::new(),
        }
    }

    fn index(&self) -> &TaskIndex {
        self.by_task.get_or_init(|| {
            let mut index = TaskIndex::default();
            for (i, timer) in self.timers.iter().enumerate() {
                if let Some(task) = timer.task {
                    index.timers.entry(task).or_default().push(i);
                }
            }
            for (r, res) in self.io.iter().enumerate() {
                for (w, waiter) in res.waiters.iter().enumerate() {
                    if let Some(task) = waiter.task {
                        index.io.entry(task).or_default().push((r, w));
                    }
                }
            }
            index
        })
    }

    /// The wheel entries armed with `task`'s waker, in wheel order.
    pub fn timers_of(&self, task: u64) -> impl Iterator<Item = &TimerEntryInfo> {
        self.index()
            .timers
            .get(&task)
            .into_iter()
            .flatten()
            .map(|&i| &self.timers[i])
    }

    /// The io waiters parked by `task`, each with the resource it is
    /// on, in registration order.
    pub fn io_of(&self, task: u64) -> impl Iterator<Item = (&IoResourceInfo, &IoWaiterInfo)> {
        self.index()
            .io
            .get(&task)
            .into_iter()
            .flatten()
            .map(|&(r, w)| {
                let res = &self.io[r];
                (res, &res.waiters[w])
            })
    }
}

/// One `TimerShared` linked in a runtime's wheel.
#[derive(Clone, Debug)]
pub struct TimerEntryInfo {
    /// The entry's address.
    pub entry: u64,
    /// The `StateCell` word — the deadline tick while registered, a
    /// sentinel once fired or deregistered. `None` where the bundle
    /// records no binding for it, or the word did not read.
    pub state: Option<u64>,
    /// The task the armed waker names, when it is a task's.
    pub task: Option<u64>,
    /// Where the entry's waker pair sits, where one was decoded: the
    /// slot the waker sweep must find again.
    pub waker_at: Option<u64>,
    /// The deadline the registration word encodes, on the target's
    /// monotonic clock: the driver's epoch plus the tick, rounded up to
    /// the millisecond the way tokio registered it. `None` where the
    /// word is a sentinel, did not read, or the epoch did not.
    pub deadline: Option<RawInstant>,
}

impl TimerEntryInfo {
    /// The deadline a registration word encodes against the driver's
    /// epoch: `start` plus the tick in milliseconds, or `None` for the
    /// fired and deregistered sentinels, which are no tick.
    pub fn wheel_deadline(start: RawInstant, state: u64) -> Option<RawInstant> {
        if state == timer::STATE_DEREGISTERED || state == timer::STATE_PENDING_FIRE {
            return None;
        }
        let ns = state.checked_mul(1_000_000)? as u128 + start.tv_nsec as u128;
        let tv_sec = start
            .tv_sec
            .checked_add(u64::try_from(ns / 1_000_000_000).ok()?)?;
        Some(RawInstant {
            tv_sec,
            tv_nsec: (ns % 1_000_000_000) as u32,
        })
    }

    /// The entry's decoded wheel state, where the word was readable.
    pub fn wheel_state(&self) -> Option<WheelState> {
        Some(match self.state? {
            timer::STATE_DEREGISTERED => WheelState::Deregistered,
            timer::STATE_PENDING_FIRE => WheelState::PendingFire,
            _ => WheelState::Registered,
        })
    }
}

/// Where a wheel entry is in its life, decoded from its state word.
/// The sentinels are tokio's own constants, folded into its code at
/// compile time and so — as with [`TaskState`](super::TaskState) —
/// knowable only from its source; they are spelled once, in
/// [`hansei_bundle::tokio::timer`], where the timer formatters read the
/// same values, so `print` and `tasks` cannot decode one word two ways.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WheelState {
    /// The word is the deadline tick: parked, not yet due.
    Registered,
    /// Queued for delivery: the driver has marked it to fire.
    PendingFire,
    /// Fired or cancelled with the entry not yet reclaimed — a wakeup
    /// delivered (or abandoned) and not yet consumed by a poll.
    Deregistered,
}

impl fmt::Display for WheelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registered => f.write_str(timer::REGISTERED),
            Self::PendingFire => f.write_str(timer::PENDING_FIRE),
            Self::Deregistered => f.write_str("fired, not yet polled"),
        }
    }
}

/// One `ScheduledIo` in a runtime's registration list.
#[derive(Clone, Debug)]
pub struct IoResourceInfo {
    /// The `ScheduledIo`'s address — the driver's identity for the
    /// resource.
    pub addr: u64,
    /// The packed readiness word (`Ready` in the low bits); `None`
    /// where the bundle records no binding, or the word did not read.
    pub readiness: Option<u64>,
    /// Whether the guard around the waiters read unlocked: a waiter
    /// list read while its mutex is held is a list mid-edit.
    pub consistency: Consistency,
    /// Everything parked on the resource: armed wakers in the two
    /// direction slots and on the readiness list.
    pub waiters: Vec<IoWaiterInfo>,
}

impl IoResourceInfo {
    /// The decoded delivered-readiness set, where the word was readable.
    pub fn ready(&self) -> Option<Readiness> {
        self.readiness.map(|word| Readiness((word & 0xffff) as u16))
    }
}

/// One armed waker parked on an io resource.
#[derive(Clone, Debug)]
pub struct IoWaiterInfo {
    /// Which of the resource's three waker sites holds it.
    pub slot: IoSlot,
    /// The task the waker names, when it is a task's.
    pub task: Option<u64>,
    /// Where the waker pair sits, where one was decoded.
    pub waker_at: Option<u64>,
    /// The `Waiter` node's address, for a listed waiter — the exact
    /// identity a readiness await's own embedded node is matched
    /// against. The direction slots are bare wakers with no node.
    pub node: Option<u64>,
    /// A listed node's `is_ready` flag, where it read: set by the
    /// resource's wake path once the awaited readiness arrived.
    pub ready: Option<bool>,
}

/// The three waker sites of a `ScheduledIo`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IoSlot {
    /// The `AsyncRead` direction slot.
    Reader,
    /// The `AsyncWrite` direction slot.
    Writer,
    /// A node on the readiness list, carrying the interest it parked
    /// for — `None` where the interest did not read.
    Listed { interest: Option<Interest> },
}

impl IoSlot {
    /// The readiness the parked future waits for. The direction slots
    /// imply theirs; a listed node carries its own.
    pub fn interest(&self) -> Option<Interest> {
        match self {
            Self::Reader => Some(Interest::READABLE),
            Self::Writer => Some(Interest::WRITABLE),
            Self::Listed { interest } => *interest,
        }
    }
}

/// A parked waiter's interest set, in tokio's `Interest` bits.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Interest(pub u64);

impl Interest {
    /// The readiness an `AsyncRead` path waits for.
    pub const READABLE: Interest = Interest(0b01);
    /// The readiness an `AsyncWrite` path waits for.
    pub const WRITABLE: Interest = Interest(0b10);

    pub fn union(self, other: Interest) -> Interest {
        Interest(self.0 | other.0)
    }
}

impl fmt::Display for Interest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        spell_bits(
            f,
            self.0,
            &[
                (0b01, "readable"),
                (0b10, "writable"),
                (0b100, "aio"),
                (0b1000, "lio"),
                (0b1_0000, "priority"),
                (0b10_0000, "error"),
            ],
        )
    }
}

/// A resource's delivered readiness, in tokio's `Ready` bits.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Readiness(pub u16);

impl fmt::Display for Readiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        spell_bits(
            f,
            self.0 as u64,
            &[
                (0b1, "readable"),
                (0b10, "writable"),
                (0b100, "read closed"),
                (0b1000, "write closed"),
                (0b1_0000, "priority"),
                (0b10_0000, "error"),
            ],
        )
    }
}

/// Spell a bit set as ` | `-joined names — unknown bits in binary, so
/// a constant tokio moves is visible rather than silently dropped —
/// and an empty set as `<none>`.
fn spell_bits(f: &mut fmt::Formatter<'_>, word: u64, names: &[(u64, &str)]) -> fmt::Result {
    let mut rest = word;
    let mut first = true;
    for (bit, name) in names {
        if word & bit != 0 {
            if !first {
                f.write_str(" | ")?;
            }
            f.write_str(name)?;
            first = false;
            rest &= !bit;
        }
    }
    if rest != 0 {
        if !first {
            f.write_str(" | ")?;
        }
        write!(f, "{rest:#b}")?;
        first = false;
    }
    if first {
        f.write_str("<none>")?;
    }
    Ok(())
}

/// The result of walking every owned-task shard.
#[derive(Debug, Default)]
pub struct TaskList {
    /// The rows: every resident record of `records` the session's
    /// selection keeps, sorted by task id (tasks with no readable id
    /// last, by address). Rebuilt from the records whenever discovery
    /// adds to them ([`TaskList::reproject`]).
    pub tasks: Vec<Task>,
    /// Per-shard walk failures; the shards that produced `tasks` are
    /// unaffected by these.
    pub errors: Vec<anyhow::Error>,
    /// Everything discovery established about every header it met —
    /// the rows above and the headers that are nobody's row (a
    /// complete task a handle keeps alive), with each one's sources,
    /// owner claims and diagnostics.
    pub records: TaskStore,
}

impl TaskList {
    /// A list of rows with no records behind them — for a caller
    /// laying out a population no target holds.
    pub fn new(tasks: Vec<Task>) -> Self {
        TaskList {
            tasks,
            ..Default::default()
        }
    }

    /// Whether the walk enumerated a task whose Header is at `addr`. A
    /// live Header this returns false for belongs to something the
    /// scheduler's owned list never carries: a `spawn_blocking` task,
    /// or a task of some other runtime in the process.
    pub fn contains(&self, addr: u64) -> bool {
        self.tasks.iter().any(|t| t.addr.0 == addr)
    }

    /// The record behind a row — or behind a header that is no row.
    pub fn record(&self, addr: u64) -> Option<&TaskRecord> {
        self.records.record_at(addr)
    }

    /// Rebuild the rows from the records: every resident record not
    /// owned by a runtime in `excluded` (by handle address).
    pub(crate) fn reproject(&mut self, excluded: &[u64]) {
        self.tasks = self.records.project(excluded);
    }
}

/// Every task's allocation, sorted by address, for resolving raw
/// pointers — a queued waker's data word, the `NonNull<Header>` inside
/// a `JoinHandle`, any address a value dump shows. Built by
/// [`Context::task_extents`].
#[derive(Debug)]
pub struct TaskExtents {
    /// `(start, end, index into the list this was built from)`.
    pub(crate) spans: Vec<(u64, u64, usize)>,
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

/// Everything a bare task `Header` pointer establishes about the task
/// it heads, read by [`Context::read_task_header`]: the identity a
/// `JoinHandle`, a registered waker, a queue entry or an owned-list
/// link all hand over alike. It carries no owner group and no list
/// link — which list the task is in, and where that list goes next,
/// are facts about the list, not about the task, and a handle to a
/// task that has left its list still identifies it.
///
/// [`Context::read_task_header`]: super::bundle::Context::read_task_header
#[derive(Clone, Debug)]
pub struct DecodedTaskHeader {
    pub addr: TaskAddr,
    pub state: TaskState,
    pub owner_id: Option<u64>,
    pub task_id: Option<u64>,
    /// Where the task was spawned, when the target records it
    /// (`tokio_unstable` task instrumentation).
    pub spawn_location: Option<Location>,
    /// The `Vtable` the Header points at, and the Trailer offset it
    /// records — where the task's own allocation places its Trailer.
    pub vtable_addr: u64,
    pub trailer_offset: u64,
    pub future: FutureInfo,
}

impl DecodedTaskHeader {
    /// The header as a task before any route has said what it is: a
    /// kind and an owner nobody has established. What a record
    /// reconciles from every route is [`TaskRecord::task`].
    pub fn into_task(self) -> Task {
        Task {
            addr: self.addr,
            state: self.state,
            owner_id: self.owner_id,
            task_id: self.task_id,
            spawn_location: self.spawn_location,
            future: self.future,
            kind: TaskKind::Unknown,
            owner: OwnerResolution::Unknown,
        }
    }
}

/// One enumerated task.
#[derive(Clone, Debug)]
pub struct Task {
    pub addr: TaskAddr,
    pub state: TaskState,
    pub owner_id: Option<u64>,
    pub task_id: Option<u64>,
    /// Where the task was spawned, when the target records it
    /// (`tokio_unstable` task instrumentation).
    pub spawn_location: Option<Location>,
    pub future: FutureInfo,
    /// What kind of task it is, from the evidence that said so: a
    /// scheduler-owned task, a `spawn_blocking` cell (whose STATE
    /// spells queued or running, never idle — the pool has no parked
    /// state), or neither established. See [`TaskKind`].
    pub kind: TaskKind,
    /// Who owns it, reconciled from every validated claim — a list
    /// that links it, a cell scheduler whose list id it carries, a
    /// pool queue it is an entry of. An owner nobody established is
    /// `Unknown`, never runtime 0; the listings number a `Known`
    /// owner through the session's [`OwnerIndex`].
    ///
    /// [`OwnerIndex`]: super::discovery::OwnerIndex
    pub owner: OwnerResolution,
}

impl Task {
    /// Whether the task is a `spawn_blocking` cell — exactly that, so
    /// a kind nobody established reads as neither kind.
    pub fn is_blocking(&self) -> bool {
        self.kind == TaskKind::Blocking
    }
}

/// The task's concrete future type, resolved via the symbol join — or not.
#[derive(Clone, Debug)]
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
        candidates: Vec<TypeCandidate>,
    },
}

/// One concrete type an ambiguous symbol join could mean. The id is the
/// part of the report the shared normalized spelling cannot carry: two
/// candidates often differ only inside their generic arguments, and
/// `type <id>` is the handle that names each exactly.
#[derive(Clone, Debug)]
pub struct TypeCandidate {
    /// The raw bundle type name, folded for display by the printer.
    pub name: String,
    pub ty: BundleTypeId,
}

/// A future resolved through the bundle's task join table.
#[derive(Clone, Debug)]
pub struct KnownFuture {
    pub entry: TaskEntryId,
    /// Demangled name of the future type (display only).
    pub display_name: String,
    pub kind: FutureKind,
    /// Source file/line where the future is defined.
    pub decl: Option<(String, u32)>,
    /// The mangled vtable-fn symbol the join matched on.
    pub symbol: String,
}

/// A task's decoded `Stage<T>`.
#[derive(Debug)]
pub enum TaskStage<'b> {
    /// The state machine is resident; walk it with
    /// [`Context::inspect_future`].
    ///
    /// [`Context::inspect_future`]: super::bundle::Context::inspect_future
    Running(Value<'b>),
    /// `Result<T::Output, JoinError>`: the task returned, panicked, or
    /// was cancelled, and the output has not been consumed yet.
    Finished(Value<'b>),
    /// The output was already taken through the join handle.
    Consumed,
}

/// The await chain of a resident future, outermost future first.
#[derive(Debug)]
pub struct AwaitChain<'b> {
    pub frames: Vec<AwaitFrame<'b>>,
    /// One edge per continuation the walk followed, `edges[i]` from
    /// `frames[i]` to `frames[i + 1]`: the recorded route it ran and
    /// the reviewed exclusivity of that hop.
    pub edges: Vec<ChainEdge<'b>>,
    /// Why the walk stopped: the terminal it reached, or what cut it
    /// short.
    pub end: ChainEnd,
}

impl<'b> AwaitChain<'b> {
    /// The primitive the chain ends in, when it ends in one: the only
    /// value a resource observation may be read from as a candidate
    /// wait. Any other end — a terminal state, an unknown continuation,
    /// a cut — has no primitive, and its last frame is not one.
    pub fn primitive_leaf(&self) -> Option<Value<'b>> {
        match self.end {
            ChainEnd::Primitive => self.frames.last().map(|f| f.future),
            _ => None,
        }
    }

    /// Whether every edge the walk followed carries the reviewed
    /// exclusive bit — the control-flow half of a polling barrier.
    /// True of a chain with no edges.
    pub fn all_exclusive(&self) -> bool {
        self.edges.iter().all(|e| e.exclusive)
    }

    /// The identity of every frame the chain reached: the concrete
    /// referents, whatever route reached them — an aliasing pointer
    /// route lands on the same key.
    pub fn referents(&self) -> impl Iterator<Item = ValueKey> + '_ {
        self.frames.iter().map(|f| ValueKey::of(f.future))
    }
}

/// One hop of an await chain as the explicit engine followed it.
#[derive(Debug)]
pub struct ChainEdge<'b> {
    /// Frame indexes into the chain: the future polled, and the future
    /// its program delegated to.
    pub from: u32,
    pub to: u32,
    /// The recorded route the hop ran, borrowed from the bundle.
    pub selected: &'b FutureTarget,
    /// The reviewed control-flow guarantee of this hop: while the
    /// delegate stays pending, polling `from` polls nothing but it.
    pub exclusive: bool,
    pub source: ValueKey,
    pub target: ValueKey,
}

/// One future in an await chain.
#[derive(Debug)]
pub struct AwaitFrame<'b> {
    /// The future being polled at this depth.
    pub future: Value<'b>,
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
    /// recorded it.
    pub await_loc: Option<(&'b str, u32)>,
    /// The active variant's payload: the state's live locals, including
    /// compiler-generated `__…` slots and the `__awaitee` itself.
    pub payload: Value<'b>,
}

/// Why an await-chain walk stopped.
#[derive(Debug)]
pub enum ChainEnd {
    /// The last frame is a bound primitive — a `Sleep`, a `JoinHandle`,
    /// an `Acquire`, a socket operation — whose program says its poll
    /// reads a resource rather than another future. The one end a
    /// resource observation may be read from as a candidate wait.
    Primitive,
    /// The last frame is a coroutine that has never been polled: its
    /// storage holds arguments, and nothing is awaited.
    Unresumed,
    /// The last frame is a coroutine that has returned.
    Returned,
    /// The last frame is a coroutine that panicked.
    Panicked,
    /// The last frame is a future whose reviewed poll returns `Pending`
    /// without registering a waker or polling anything: no poll of it
    /// ever returns `Ready`. About readiness, not waking — a stale or
    /// spurious wake still schedules the task, which polls this and
    /// parks again.
    NeverReady,
    /// The last frame's continuation is not established: no semantic
    /// record, no rule for its shape, a state its rule declined, or a
    /// case its program has no action for. What it holds may still be
    /// inspected; what it polls is not known.
    UnknownContinuation {
        /// The frame whose continuation is unknown.
        at: ValueKey,
        reason: SemanticIssueKind,
    },
    /// The root belongs to a task mid-poll: its saved discriminants may
    /// be mid-mutation, so nothing below the root is read as a chain.
    ActivePoll,
    /// A `dyn Future` awaitee whose vtable symbols joined nothing in the
    /// bundle; the raw poll symbol is reported and nothing is guessed.
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
        /// The concrete bundle types sharing the normalized key.
        candidates: Vec<TypeCandidate>,
    },
    /// The depth bound was hit.
    DepthLimit,
    /// The same (address, type) pair reappeared.
    Cycle { addr: u64 },
    /// Reading or decoding below the last frame failed.
    Error(anyhow::Error),
}

/// What a leaf future is waiting on.
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
        /// this session cannot list: the blocking pool, another
        /// runtime, or a local set discovery could not enumerate.
        listed: bool,
        /// Which of those, when the vtable join could resolve the
        /// task's future and read its recorded scheduler type.
        /// Meaningful only when `listed` is false.
        kind: Option<UnlistedTaskKind>,
    },
    /// Parked on an io resource: the driver's `ScheduledIo` holds the
    /// task's waker until the awaited readiness arrives.
    Io {
        /// The `ScheduledIo`'s address.
        addr: u64,
        /// The fd, where a known resource type in the task's frames
        /// owns the registration — the `ScheduledIo` records none
        /// itself.
        fd: Option<i32>,
        /// The readiness awaited, where the parked slot spelled one.
        interest: Option<Interest>,
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
    /// A bounded mpsc `Receiver::recv`, parked on an empty channel
    /// with its waker in the channel's receiver slot.
    Channel {
        /// The `Chan` behind the receiver's `Arc`.
        addr: u64,
        /// Live senders.
        senders: u64,
        /// The channel's capacity.
        capacity: Option<u64>,
        /// Slots claimed past the read index: messages queued, or
        /// being written — for a verified wait, only the latter.
        unread: u64,
    },
    /// A `Notified`, queued on its `Notify` with this task's waker.
    /// The list itself stays with the observation: a `Notify` behind a
    /// cancellation token collects thousands of waiters, and the
    /// listing prints one row per waiter.
    Notify {
        addr: u64,
        /// The `Notify`'s state word, where it read: the low bits say
        /// whether waiters are queued.
        state: Option<u64>,
        /// Nodes in the wait list, where the list was walked: a
        /// verified wait walked it; a held future's description reads
        /// the state word and nothing past it.
        waiters: Option<usize>,
    },
    /// A `oneshot::Receiver`, parked with its waker in the shared
    /// `Inner`'s `rx_task` until the sender completes. Only the
    /// receiver is ever a chain leaf: a sender's `poll_closed` is
    /// reached through its `tx_task` slot, never through a wait — but
    /// an HTTP client connection names the sender it watches as what
    /// it is parked on, so the side is recorded.
    Oneshot {
        /// The `Inner` behind both handles' `Arc`.
        addr: u64,
        state: OneshotState,
        /// Which handle's slot the wait is worded for.
        side: OneshotSide,
    },
    /// A watch receiver's `changed`, queued on one of the channel's
    /// `Notify`s: a `Notified` whose `Notify` lies in the `Shared` a
    /// `watch::Receiver` in the same chain points at.
    Watch {
        /// The `Shared` behind the receiver's `Arc`.
        addr: u64,
        /// The published version.
        version: u64,
        /// Whether the sender side closed.
        closed: bool,
        receivers: u64,
        senders: u64,
    },
    /// hyper's HTTP/1 connection, read from its dispatcher's state
    /// words: where the exchange stands, and the primitive the
    /// connection is parked on for the next step where the rule
    /// itself knows it — the client's request receiver while idle,
    /// its response callback while a request is in flight.
    HttpConn {
        /// The `Conn`'s address, which is what a filter names.
        addr: u64,
        role: HttpRole,
        /// `None` while the server is still choosing the version.
        version: Option<HttpVersion>,
        phase: HttpPhase,
        /// The method of the message in flight, as its name reads
        /// (`GET`); `None` between exchanges, or where it did not read.
        method: Option<String>,
        /// Whether the connection stays open after this exchange:
        /// false where hyper disabled keep-alive.
        keep_alive: bool,
        /// The primitive the connection is parked on, where the rule
        /// names one.
        via: Option<Box<WaitTarget>>,
    },
}

pub use hansei_bundle::HttpRole;

/// The HTTP version a connection speaks, once it knows.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum HttpVersion {
    Http1,
}

/// How a message body is framed on the wire, as hyper's decoder or
/// encoder carries it.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum BodyFraming {
    /// A `Content-Length` body, with the bytes still to go.
    Length {
        remaining: u64,
    },
    Chunked,
    /// Ends when the connection closes.
    CloseDelimited,
}

impl fmt::Display for BodyFraming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { remaining } => {
                write!(f, "{} remaining", counted_noun(*remaining, "byte"))
            }
            Self::Chunked => f.write_str("chunked"),
            Self::CloseDelimited => f.write_str("close-delimited"),
        }
    }
}

/// Where an HTTP/1 exchange stands, decided from the connection's
/// state words.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum HttpPhase {
    /// Between exchanges: a client parked for its next request, a
    /// server for the peer's.
    Idle,
    /// The client has written its request and awaits the response
    /// head.
    AwaitingResponse,
    /// The client has written the request head and is still writing
    /// its body; `None` where the encoder's framing did not read.
    SendingBody(Option<BodyFraming>),
    /// A message head has been read and its body is still arriving.
    ReceivingBody(Option<BodyFraming>),
    /// One or both directions are closed.
    Closing,
    /// The server is still reading the first bytes to choose the
    /// version.
    Negotiating,
    /// The server has read a request and its handler is running.
    HandlingRequest,
}

impl HttpPhase {
    /// The phase as a bucket names it, without the framing or counts
    /// that would fragment one.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::AwaitingResponse => "awaiting response",
            Self::SendingBody(_) => "sending body",
            Self::ReceivingBody(_) => "receiving body",
            Self::Closing => "closing",
            Self::Negotiating => "negotiating",
            Self::HandlingRequest => "handling request",
        }
    }

    /// The phase alone, for a tally.
    pub fn kind(&self) -> HttpPhaseKind {
        match self {
            Self::Idle => HttpPhaseKind::Idle,
            Self::AwaitingResponse => HttpPhaseKind::AwaitingResponse,
            Self::SendingBody(_) => HttpPhaseKind::SendingBody,
            Self::ReceivingBody(_) => HttpPhaseKind::ReceivingBody,
            Self::Closing => HttpPhaseKind::Closing,
            Self::Negotiating => HttpPhaseKind::Negotiating,
            Self::HandlingRequest => HttpPhaseKind::HandlingRequest,
        }
    }
}

/// [`HttpPhase`] without its framing, as a tally counts it.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum HttpPhaseKind {
    Idle,
    AwaitingResponse,
    SendingBody,
    ReceivingBody,
    Closing,
    Negotiating,
    HandlingRequest,
}

/// The kind word a connection's cell and bucket open with: the version
/// and the role, or the bare `http` for a connection still choosing.
pub fn http_kind_word(role: HttpRole, version: Option<HttpVersion>) -> &'static str {
    match (version, role) {
        (Some(HttpVersion::Http1), HttpRole::Client) => "http1 client",
        (Some(HttpVersion::Http1), HttpRole::Server) => "http1 server",
        (None, HttpRole::Client) => "http client",
        (None, HttpRole::Server) => "http server",
    }
}

/// The parenthesised reading of a connection line: the phase, the
/// method where one is in flight, the body's framing where a body is
/// moving, and keep-alive where it is off.
pub fn http_words(
    role: HttpRole,
    phase: HttpPhase,
    method: Option<&str>,
    keep_alive: bool,
) -> String {
    let method = method.unwrap_or("request");
    let in_flight = match role {
        HttpRole::Client => format!("{method} sent"),
        HttpRole::Server => format!("{method} in flight"),
    };
    let mut words: Vec<String> = match phase {
        HttpPhase::Idle => vec![
            "idle".to_owned(),
            if keep_alive {
                "keep-alive".to_owned()
            } else {
                "keep-alive off".to_owned()
            },
        ],
        HttpPhase::AwaitingResponse => vec![in_flight, "awaiting response headers".to_owned()],
        HttpPhase::SendingBody(framing) => {
            let mut words = vec![in_flight, "sending body".to_owned()];
            words.extend(framing.map(|f| f.to_string()));
            words
        }
        HttpPhase::ReceivingBody(framing) => {
            let mut words = vec![in_flight, "receiving body".to_owned()];
            words.extend(framing.map(|f| f.to_string()));
            words
        }
        HttpPhase::Closing => vec!["closing".to_owned()],
        HttpPhase::Negotiating => vec!["negotiating version".to_owned()],
        HttpPhase::HandlingRequest => vec![in_flight, "handler running".to_owned()],
    };
    if !keep_alive && phase != HttpPhase::Idle {
        words.push("keep-alive off".to_owned());
    }
    words.join(", ")
}

/// A oneshot's shared state word with the presence of its value: what
/// the sender and receiver sides each say about the channel.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct OneshotState {
    /// The `Inner.state` word.
    pub word: u64,
    /// Whether `Inner.value` holds a value, where its discriminant
    /// read.
    pub value_present: Option<bool>,
}

/// Which handle's slot a oneshot reading is worded for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OneshotSide {
    Rx,
    Tx,
}

impl OneshotState {
    /// The receiver stored its waker in `rx_task`.
    pub fn rx_task_set(&self) -> bool {
        self.word & hansei_bundle::tokio::oneshot::RX_TASK_SET != 0
    }

    /// The sender stored its waker in `tx_task`.
    pub fn tx_task_set(&self) -> bool {
        self.word & hansei_bundle::tokio::oneshot::TX_TASK_SET != 0
    }

    /// The sender completed: sent a value, or dropped.
    pub fn complete(&self) -> bool {
        self.word & hansei_bundle::tokio::oneshot::VALUE_SENT != 0
    }

    /// The receiver closed or dropped.
    pub fn closed(&self) -> bool {
        self.word & hansei_bundle::tokio::oneshot::CLOSED != 0
    }

    /// The channel's state in words, from one side: what the sender
    /// has done, and whether the other handle is still there. A parked
    /// receiver reads `nothing sent, sender alive`; a sender watching
    /// for the receiver reads `nothing sent, receiver alive`.
    pub fn words(&self, side: OneshotSide) -> String {
        let mut parts: Vec<&str> = Vec::new();
        match (self.complete(), self.value_present) {
            (true, Some(true)) => parts.push("value sent"),
            (true, Some(false)) => parts.extend(["nothing sent", "sender gone"]),
            (true, None) => parts.push("sender completed"),
            (false, _) => {
                parts.push("nothing sent");
                if side == OneshotSide::Rx && !self.closed() {
                    parts.push("sender alive");
                }
            }
        }
        if self.closed() {
            parts.push("receiver closed");
        } else if side == OneshotSide::Tx {
            parts.push("receiver alive");
        }
        parts.join(", ")
    }
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
    /// Another task, through its `JoinHandle`, by the address of the
    /// `Header` that identifies it — so a find that merely holds a
    /// handle still names the task on the other end of it.
    Task { addr: u64 },
    /// An io resource, through the driver's registration.
    Io,
    /// A semaphore, named by the primitive wrapping it where the frame
    /// awaiting it says which (`tokio::sync::Mutex`, …).
    Semaphore { owner: Option<&'static str> },
    /// A bounded mpsc receiver's channel, by the address of the `Chan`
    /// behind the receiver's `Arc` — the primitive a slot in its
    /// receiver cell names.
    Channel { addr: u64 },
    /// A `Notify`, by its address — the primitive a slot in a queued
    /// `Notified` node names.
    Notify { addr: u64 },
    /// A oneshot, by the address of its `Inner` — the primitive a slot
    /// in either task cell names.
    Oneshot { addr: u64 },
    /// A watch channel, by the address of its `Shared` — the primitive
    /// a slot queued on one of its `Notify`s names.
    Watch { addr: u64 },
    /// An HTTP connection, by its role, version and phase — the
    /// identity a bucket keeps; the method and the body's counts are a
    /// row's detail.
    HttpConn {
        role: HttpRole,
        version: Option<HttpVersion>,
        phase: HttpPhaseKind,
    },
}

impl WaitKind {
    /// The kind word a listing's cell names the wait by, as
    /// [`WaitTarget::cell`] names the target the kind was tallied from
    /// — except a task, which a cell names by its id and a tally holds
    /// only the address of.
    pub fn word(&self) -> &'static str {
        match self {
            Self::Timer { .. } => "timer",
            Self::Task { .. } => "task",
            Self::Io => "io",
            Self::Semaphore { .. } => "semaphore",
            Self::Channel { .. } => "mpsc rx",
            Self::Notify { .. } => "notify rx",
            Self::Oneshot { .. } => "oneshot rx",
            Self::Watch { .. } => "watch rx",
            Self::HttpConn { role, version, .. } => http_kind_word(*role, *version),
        }
    }
}

impl WaitTarget {
    /// The wait as a listing's cell names it: the kind word alone — a
    /// task by its id, which is what every listing calls it — and
    /// nothing the reader read about the resource. Its address, a
    /// deadline, a channel's counts, a wake queue are the detail
    /// lines' to print, where a row's cell has no room for them.
    pub fn cell(&self) -> String {
        match self {
            Self::Task {
                task_id: Some(id), ..
            } => format!("task {id}"),
            _ => self.kind().word().to_string(),
        }
    }

    /// The kind-level spelling `tasks --group waiting-on` buckets rows
    /// by: the identity that groups usefully — which task, which
    /// semaphore — with the per-row detail (deadlines, permit counts,
    /// wake queues) dropped, so one bucket collects every waiter.
    pub fn group_label(&self) -> String {
        match self {
            Self::Timer { .. } => "timer".to_string(),
            Self::Task { addr, task_id, .. } => match task_id {
                Some(id) => format!("task {id}"),
                None => format!("the task at {addr:#x}"),
            },
            Self::Io { .. } => "io".to_string(),
            Self::Semaphore { addr, owner, .. } => match owner {
                Some(owner) => format!("a {owner} (semaphore {addr:#x})"),
                None => format!("the semaphore at {addr:#x}"),
            },
            // The kind word alone: what a slot in the same primitive
            // is bucketed under, so a leaf's reading and a slot's share
            // a bucket. Which `Notify` is a `--with waiting-on 0x…`
            // filter's question, not the bucket's.
            Self::Channel { .. } => "mpsc rx".to_string(),
            Self::Notify { .. } => "notify rx".to_string(),
            Self::Oneshot { .. } => "oneshot rx".to_string(),
            Self::Watch { .. } => "watch rx".to_string(),
            // The cell plus the phase and nothing else, so a method or
            // a byte count never fragments a bucket.
            Self::HttpConn {
                role,
                version,
                phase,
                ..
            } => format!("{} {}", http_kind_word(*role, *version), phase.word()),
        }
    }

    /// What the reading adds where it is a line of its own rather
    /// than a parenthetical: a channel's sender count, bound and
    /// claimed slots; a watch's version and handle counts. The other
    /// targets carry their words on the line that names them.
    pub fn words(&self) -> Option<String> {
        match self {
            Self::Channel {
                senders,
                capacity,
                unread,
                ..
            } => Some(channel_words(*senders, *capacity, *unread)),
            Self::Watch {
                version,
                closed,
                receivers,
                senders,
                ..
            } => Some(watch_words(*version, *closed, *receivers, *senders)),
            _ => None,
        }
    }

    /// This wait as a tally counts it.
    pub fn kind(&self) -> WaitKind {
        match self {
            Self::Timer { deadline, stopped } => WaitKind::Timer {
                past_due: stopped.map(|stopped| {
                    (deadline.tv_sec, deadline.tv_nsec) < (stopped.tv_sec, stopped.tv_nsec)
                }),
            },
            Self::Task { addr, .. } => WaitKind::Task { addr: *addr },
            Self::Io { .. } => WaitKind::Io,
            Self::Semaphore { owner, .. } => WaitKind::Semaphore { owner: *owner },
            Self::Channel { addr, .. } => WaitKind::Channel { addr: *addr },
            Self::Notify { addr, .. } => WaitKind::Notify { addr: *addr },
            Self::Oneshot { addr, .. } => WaitKind::Oneshot { addr: *addr },
            Self::Watch { addr, .. } => WaitKind::Watch { addr: *addr },
            Self::HttpConn {
                role,
                version,
                phase,
                ..
            } => WaitKind::HttpConn {
                role: *role,
                version: *version,
                phase: phase.kind(),
            },
        }
    }

    /// The primitive a connection is parked on, where its rule names
    /// one: the `via:` line under the connection's own.
    pub fn via(&self) -> Option<&WaitTarget> {
        match self {
            Self::HttpConn { via, .. } => via.as_deref(),
            _ => None,
        }
    }

    /// The line a target prints as, reading included: the target with
    /// its words in parentheses where those are a line of their own,
    /// the target alone where they are already on it.
    pub fn line(&self) -> String {
        match self.words() {
            Some(words) => format!("{self} ({words})"),
            None => self.to_string(),
        }
    }
}

/// `1 sender` / `2 senders`.
pub fn counted_noun(n: u64, noun: &str) -> String {
    match n {
        1 => format!("1 {noun}"),
        n => format!("{n} {noun}s"),
    }
}

/// The words a channel's reading appends to its cell entry, without
/// the parentheses: the live senders, the capacity where the channel
/// is bounded, and the slots claimed past the read index.
pub fn channel_words(senders: u64, capacity: Option<u64>, unread: u64) -> String {
    let mut words = counted_noun(senders, "sender");
    if let Some(capacity) = capacity {
        words.push_str(&format!(", capacity {capacity}"));
    }
    words.push_str(&format!(", {unread} unread"));
    words
}

/// The words a `Notify`'s reading appends to its cell entry: what its
/// state word says — `idle`, `waiting`, `notified` — and, where the
/// wait list was walked, how many are queued. Empty where neither
/// read.
pub fn notify_words(state: Option<u64>, waiters: Option<usize>) -> String {
    use hansei_bundle::tokio::notify;
    let mut words: Vec<String> = Vec::new();
    if let Some(state) = state {
        words.push(match state & notify::STATE_MASK {
            notify::EMPTY => "idle".to_string(),
            notify::WAITING => "waiting".to_string(),
            notify::NOTIFIED => "notified".to_string(),
            other => format!("state {other:#b}"),
        });
    }
    if let Some(waiters) = waiters {
        words.push(format!("{waiters} queued"));
    }
    words.join(", ")
}

/// The words a watch channel's reading appends to its cell entry: the
/// published version, both handle counts, and whether it closed.
pub fn watch_words(version: u64, closed: bool, receivers: u64, senders: u64) -> String {
    let mut words = format!(
        "version {version}, {}, {}",
        counted_noun(senders, "sender"),
        counted_noun(receivers, "receiver")
    );
    if closed {
        words.push_str(", closed");
    }
    words
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
    /// Where the node's waker pair sits, where one is registered.
    pub waker_at: Option<u64>,
}

/// One node in a `Notify`'s wait list.
#[derive(Clone, Debug)]
pub struct NotifyWaiter {
    /// The `Waiter` node's address; it lives inside the `Notified`
    /// future itself.
    pub addr: u64,
    /// The node's notification word: zero until a wake unlinks it.
    pub notification: u64,
    /// Who waking this node schedules.
    pub waker: QueuedWaker,
}

/// The waker registered in a wait-queue node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum QueuedWaker {
    /// A tokio task waker: the wake edge points at this task.
    Task { addr: u64, task_id: Option<u64> },
    /// Not a task waker (a `block_on` thread, say) — or the
    /// `WAKER_VTABLE` static could not be resolved in the target.
    Other { vtable: u64 },
    /// No waker registered.
    Unarmed,
}

impl QueuedWaker {
    /// The task header the waker names, when it is a task's.
    pub fn task(&self) -> Option<u64> {
        match self {
            Self::Task { addr, .. } => Some(*addr),
            Self::Other { .. } | Self::Unarmed => None,
        }
    }
}

/// A deadline in words: relative to the stop instant when the lwps
/// stamp one — the wait remaining as of the moment the target was
/// observed, or overdue once the deadline has passed — else the
/// absolute point on the target's monotonic clock, which is all there
/// is to say.
pub fn deadline_text(deadline: RawInstant, stopped: Option<RawInstant>) -> String {
    match stopped {
        Some(stopped) => {
            let ns = |i: RawInstant| i.tv_sec as i128 * 1_000_000_000 + i.tv_nsec as i128;
            let delta = ns(deadline) - ns(stopped);
            let word = if delta < 0 {
                "overdue by "
            } else {
                "deadline +"
            };
            let delta = delta.unsigned_abs();
            format!(
                "{word}{}.{:03}s",
                delta / 1_000_000_000,
                (delta % 1_000_000_000) / 1_000_000
            )
        }
        None => format!(
            "deadline {}.{:03}s on the target's monotonic clock",
            deadline.tv_sec,
            deadline.tv_nsec / 1_000_000
        ),
    }
}

impl fmt::Display for WaitTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timer { deadline, stopped } => {
                write!(f, "timer ({})", deadline_text(*deadline, *stopped))
            }
            Self::Task {
                task_id,
                addr,
                state,
                listed,
                kind,
            } => {
                match task_id {
                    Some(id) => write!(f, "task {id}")?,
                    None => write!(f, "the task at {addr:#x}")?,
                }
                // Either way the listings cannot show it: complete
                // means off the owned list, alive only through this
                // handle; alive-but-unlisted means it runs somewhere
                // this session does not enumerate — named definitely
                // when its cell's recorded scheduler type says which.
                if state.lifecycle() == Lifecycle::Complete {
                    write!(f, " — already complete, awaiting consumption")?;
                } else if !listed {
                    let where_ = match kind {
                        Some(UnlistedTaskKind::Blocking) => {
                            "a spawn_blocking task (no task list carries those)".to_owned()
                        }
                        Some(UnlistedTaskKind::OtherRuntime(flavor)) => {
                            format!("a task of a {flavor} runtime this session does not list")
                        }
                        Some(UnlistedTaskKind::LocalSet) => {
                            "a task of a local set this session could not enumerate".to_owned()
                        }
                        None => "not in the scheduler's owned tasks \
                             (a spawn_blocking task, or another runtime's)"
                            .to_owned(),
                    };
                    write!(f, " — {}, {where_}", state.lifecycle())?;
                }
                Ok(())
            }
            Self::Io { addr, fd, interest } => {
                match fd {
                    Some(fd) => write!(f, "io fd {fd}")?,
                    None => write!(f, "io {addr:#x}")?,
                }
                match interest {
                    Some(interest) => write!(f, " ({interest})"),
                    None => write!(f, " (readiness)"),
                }
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
                    wake_queue(f, waiters.iter().map(|w| &w.waker))?;
                }
                Ok(())
            }
            // A channel's counts run long and the line naming it
            // already carries a verdict, so they are a line of their
            // own ([`WaitTarget::words`]) rather than a parenthetical
            // here.
            Self::Channel { addr, .. } => write!(f, "mpsc rx {addr:#x}"),
            Self::Notify {
                addr,
                state,
                waiters,
            } => {
                write!(f, "notify rx {addr:#x}")?;
                let words = notify_words(*state, *waiters);
                if !words.is_empty() {
                    write!(f, " ({words})")?;
                }
                Ok(())
            }
            Self::Oneshot { addr, state, side } => {
                let end = match side {
                    OneshotSide::Rx => "rx",
                    OneshotSide::Tx => "tx",
                };
                write!(f, "oneshot {end} {addr:#x} ({})", state.words(*side))
            }
            // The connection's reading is its verdict, so it sits on
            // the line; the primitive it is parked on is a line of its
            // own below ([`WaitTarget::via`]).
            Self::HttpConn {
                addr,
                role,
                version,
                phase,
                method,
                keep_alive,
                ..
            } => write!(
                f,
                "{} {addr:#x} ({})",
                http_kind_word(*role, *version),
                http_words(*role, *phase, method.as_deref(), *keep_alive)
            ),
            // Only a receiver's `changed` parks on a watch channel's
            // `Notify`, so the side is not in doubt; the version and
            // the handle counts are a line of their own, as a
            // channel's are.
            Self::Watch { addr, .. } => write!(f, "watch rx {addr:#x}"),
        }
    }
}

/// A wait queue's wakers, in wake order, each by the task it wakes.
fn wake_queue<'a>(
    f: &mut fmt::Formatter<'_>,
    wakers: impl Iterator<Item = &'a QueuedWaker>,
) -> fmt::Result {
    for (i, waker) in wakers.enumerate() {
        let sep = if i == 0 { " " } else { ", " };
        match waker {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The park-state prose the thread listings embed.
    #[test]
    fn test_park_state_display() {
        let cases = [
            (ParkState::Awake, "awake"),
            (ParkState::Condvar, "parked"),
            (ParkState::Driver, "parked in the io driver"),
            (ParkState::Notified, "notified, waking"),
            (ParkState::Unknown(7), "an unknown park state (7)"),
        ];
        for (state, expected) in cases {
            assert_eq!(state.to_string(), expected);
        }
    }

    /// The CT activity prose, likewise.
    #[test]
    fn test_ct_activity_display() {
        let cases = [
            (CtActivity::Parked, "parked in the driver"),
            (CtActivity::PollingBlockOn, "polling the block_on future"),
            (CtActivity::PollingTask(7), "polling task 7"),
            (CtActivity::BetweenPolls, "between polls"),
            (CtActivity::DroppingTask(7), "dropping task 7 at shutdown"),
        ];
        for (activity, expected) in cases {
            assert_eq!(activity.to_string(), expected);
        }
    }

    /// A span is half-open: locate answers for its start and last byte
    /// and not for its one-past end, whichever span follows.
    #[test]
    fn test_task_extents_spans_are_half_open() {
        let extents = TaskExtents {
            spans: vec![(0x1000, 0x1040, 0), (0x2000, 0x2010, 1)],
        };
        assert_eq!(extents.locate(0x0fff), None);
        assert_eq!(extents.locate(0x1000), Some((0, 0)));
        assert_eq!(extents.locate(0x103f), Some((0, 0x3f)));
        assert_eq!(extents.locate(0x1040), None);
        assert_eq!(extents.locate(0x2000), Some((1, 0)));
        assert_eq!(extents.locate(0x2010), None);
    }

    /// past_due is strict: a deadline exactly at the stop instant has
    /// not passed yet, on either side of the seconds/nanos split.
    #[test]
    fn test_timer_past_due_is_strict() {
        let at = |tv_sec, tv_nsec| RawInstant { tv_sec, tv_nsec };
        let kind = |deadline, stopped| WaitTarget::Timer { deadline, stopped }.kind();
        let past_due = |past_due| WaitKind::Timer { past_due };

        assert_eq!(kind(at(10, 0), Some(at(10, 0))), past_due(Some(false)));
        assert_eq!(
            kind(at(9, 999_999_999), Some(at(10, 0))),
            past_due(Some(true))
        );
        assert_eq!(kind(at(10, 1), Some(at(10, 0))), past_due(Some(false)));
        assert_eq!(kind(at(10, 0), None), past_due(None));
    }

    /// The compact wait spellings every surface shares — the row, the
    /// trace's `waiting on`, the graph — and the kind-level labels
    /// The connection target, one line per client row the protocol
    /// decides — the fixture parks in two of them, so the rest are
    /// pinned here: the kind word and the `Conn`'s address, the
    /// reading in parentheses with the method, the framing and the
    /// keep-alive flag where each applies; the cell is the kind word,
    /// the bucket the cell plus the phase and nothing else; and the
    /// primitive the rule names is a line of its own, never on the
    /// connection's.
    #[test]
    fn test_http_conn_target_words() {
        let conn = |phase, method: Option<&str>, keep_alive, via: Option<WaitTarget>| {
            WaitTarget::HttpConn {
                addr: 0xc72d000,
                role: HttpRole::Client,
                version: Some(HttpVersion::Http1),
                phase,
                method: method.map(str::to_owned),
                keep_alive,
                via: via.map(Box::new),
            }
        };
        let rx = WaitTarget::Channel {
            addr: 0xfb0f700,
            senders: 1,
            capacity: None,
            unread: 0,
        };
        let idle = conn(HttpPhase::Idle, None, true, Some(rx));
        assert_eq!(
            idle.to_string(),
            "http1 client 0xc72d000 (idle, keep-alive)"
        );
        assert_eq!(idle.words(), None);
        assert_eq!(idle.cell(), "http1 client");
        assert_eq!(idle.group_label(), "http1 client idle");
        assert_eq!(
            idle.via().map(WaitTarget::line).as_deref(),
            Some("mpsc rx 0xfb0f700 (1 sender, 0 unread)")
        );
        assert_eq!(
            idle.kind(),
            WaitKind::HttpConn {
                role: HttpRole::Client,
                version: Some(HttpVersion::Http1),
                phase: HttpPhaseKind::Idle,
            }
        );
        assert_eq!(idle.kind().word(), "http1 client");
        assert_eq!(
            conn(HttpPhase::Idle, None, false, None).to_string(),
            "http1 client 0xc72d000 (idle, keep-alive off)"
        );
        let tx = WaitTarget::Oneshot {
            addr: 0xc72d9e0,
            state: OneshotState {
                word: 0b1000,
                value_present: Some(false),
            },
            side: OneshotSide::Tx,
        };
        let awaiting = conn(HttpPhase::AwaitingResponse, Some("GET"), true, Some(tx));
        assert_eq!(
            awaiting.to_string(),
            "http1 client 0xc72d000 (GET sent, awaiting response headers)"
        );
        assert_eq!(awaiting.group_label(), "http1 client awaiting response");
        assert_eq!(
            awaiting.via().map(WaitTarget::line).as_deref(),
            Some("oneshot tx 0xc72d9e0 (nothing sent, receiver alive)")
        );
        // No method read: the request is named as such.
        assert_eq!(
            conn(HttpPhase::AwaitingResponse, None, true, None).to_string(),
            "http1 client 0xc72d000 (request sent, awaiting response headers)"
        );
        assert_eq!(
            conn(
                HttpPhase::SendingBody(Some(BodyFraming::Chunked)),
                Some("POST"),
                true,
                None
            )
            .to_string(),
            "http1 client 0xc72d000 (POST sent, sending body, chunked)"
        );
        let receiving = conn(
            HttpPhase::ReceivingBody(Some(BodyFraming::Length { remaining: 1234 })),
            Some("GET"),
            true,
            None,
        );
        assert_eq!(
            receiving.to_string(),
            "http1 client 0xc72d000 (GET sent, receiving body, 1234 bytes remaining)"
        );
        assert_eq!(receiving.group_label(), "http1 client receiving body");
        assert!(receiving.via().is_none());
        assert_eq!(
            conn(
                HttpPhase::ReceivingBody(Some(BodyFraming::Length { remaining: 1 })),
                Some("GET"),
                false,
                None
            )
            .to_string(),
            "http1 client 0xc72d000 (GET sent, receiving body, 1 byte remaining, keep-alive off)"
        );
        assert_eq!(
            conn(
                HttpPhase::ReceivingBody(Some(BodyFraming::CloseDelimited)),
                Some("GET"),
                true,
                None
            )
            .to_string(),
            "http1 client 0xc72d000 (GET sent, receiving body, close-delimited)"
        );
        // A framing that did not read leaves the phase alone.
        assert_eq!(
            conn(HttpPhase::ReceivingBody(None), Some("GET"), true, None).to_string(),
            "http1 client 0xc72d000 (GET sent, receiving body)"
        );
        let closing = conn(HttpPhase::Closing, Some("GET"), true, None);
        assert_eq!(closing.to_string(), "http1 client 0xc72d000 (closing)");
        assert_eq!(closing.group_label(), "http1 client closing");
        // The server's words, ready for its binding: a version still
        // being chosen is the bare `http`.
        let negotiating = WaitTarget::HttpConn {
            addr: 0x8058d80,
            role: HttpRole::Server,
            version: None,
            phase: HttpPhase::Negotiating,
            method: None,
            keep_alive: true,
            via: None,
        };
        assert_eq!(
            negotiating.to_string(),
            "http server 0x8058d80 (negotiating version)"
        );
        assert_eq!(negotiating.cell(), "http server");
        assert_eq!(negotiating.group_label(), "http server negotiating");
        let handling = WaitTarget::HttpConn {
            addr: 0x8058d80,
            role: HttpRole::Server,
            version: Some(HttpVersion::Http1),
            phase: HttpPhase::HandlingRequest,
            method: Some("GET".to_owned()),
            keep_alive: true,
            via: None,
        };
        assert_eq!(
            handling.to_string(),
            "http1 server 0x8058d80 (GET in flight, handler running)"
        );
        assert_eq!(handling.group_label(), "http1 server handling request");
    }

    /// The channel targets: each printed as the kind word, the
    /// primitive's address and its words in parentheses — the same
    /// shape a slot entry for the primitive takes — with the bucket a
    /// slot in the same primitive is filed under.
    #[test]
    fn test_channel_target_words() {
        let channel = WaitTarget::Channel {
            addr: 0x9000,
            senders: 1,
            capacity: Some(4),
            unread: 0,
        };
        // The counts are a line of their own, not a parenthetical.
        assert_eq!(channel.to_string(), "mpsc rx 0x9000");
        assert_eq!(
            channel.words().as_deref(),
            Some("1 sender, capacity 4, 0 unread")
        );
        assert_eq!(channel.group_label(), "mpsc rx");
        let unbounded = WaitTarget::Channel {
            addr: 0x9000,
            senders: 2,
            capacity: None,
            unread: 3,
        };
        assert_eq!(unbounded.to_string(), "mpsc rx 0x9000");
        assert_eq!(unbounded.words().as_deref(), Some("2 senders, 3 unread"));
        // A oneshot's words stay on the line that names it.
        assert_eq!(
            WaitTarget::Oneshot {
                addr: 0xa000,
                state: OneshotState {
                    word: 0,
                    value_present: Some(false),
                },
                side: OneshotSide::Rx,
            }
            .words(),
            None
        );

        let parked = OneshotState {
            word: 0b0001,
            value_present: Some(false),
        };
        let oneshot = WaitTarget::Oneshot {
            addr: 0xa000,
            state: parked,
            side: OneshotSide::Rx,
        };
        assert_eq!(
            oneshot.to_string(),
            "oneshot rx 0xa000 (nothing sent, sender alive)"
        );
        assert_eq!(oneshot.group_label(), "oneshot rx");
        assert_eq!(oneshot.kind(), WaitKind::Oneshot { addr: 0xa000 });
        // The sending side, as a connection's callback names it: the
        // words are the sender's, the kind the oneshot's.
        let watched = WaitTarget::Oneshot {
            addr: 0xa000,
            state: OneshotState {
                word: 0b1000,
                value_present: Some(false),
            },
            side: OneshotSide::Tx,
        };
        assert_eq!(
            watched.to_string(),
            "oneshot tx 0xa000 (nothing sent, receiver alive)"
        );
        assert_eq!(watched.kind(), WaitKind::Oneshot { addr: 0xa000 });

        let watch = WaitTarget::Watch {
            addr: 0xc000,
            version: 3,
            closed: true,
            receivers: 2,
            senders: 0,
        };
        assert_eq!(watch.to_string(), "watch rx 0xc000");
        assert_eq!(
            watch.words().as_deref(),
            Some("version 3, 0 senders, 2 receivers, closed")
        );
        assert_eq!(watch.group_label(), "watch rx");
        assert_eq!(watch.kind(), WaitKind::Watch { addr: 0xc000 });
    }

    /// The oneshot's words from each side, over every state the bits
    /// and the value can be in: a parked receiver, a parked sender, a
    /// sender that dropped without sending, a value sent, a receiver
    /// closed, and a completion whose value did not read.
    #[test]
    fn test_oneshot_state_words() {
        let state = |word, value_present| OneshotState {
            word,
            value_present,
        };
        let rx = |s: OneshotState| s.words(OneshotSide::Rx);
        let tx = |s: OneshotState| s.words(OneshotSide::Tx);
        let parked = state(0b1001, Some(false));
        assert!(parked.rx_task_set() && parked.tx_task_set());
        assert!(!parked.complete() && !parked.closed());
        assert_eq!(rx(parked), "nothing sent, sender alive");
        assert_eq!(tx(parked), "nothing sent, receiver alive");
        let dropped = state(0b0011, Some(false));
        assert_eq!(rx(dropped), "nothing sent, sender gone");
        assert_eq!(tx(dropped), "nothing sent, sender gone, receiver alive");
        let sent = state(0b0011, Some(true));
        assert_eq!(rx(sent), "value sent");
        let closed = state(0b1100, Some(false));
        assert!(closed.closed());
        assert_eq!(rx(closed), "nothing sent, receiver closed");
        assert_eq!(tx(closed), "nothing sent, receiver closed");
        let unread = state(0b0010, None);
        assert_eq!(rx(unread), "sender completed");
    }

    /// grouping buckets by.
    #[test]
    fn test_wait_target_spellings() {
        let at = |tv_sec, tv_nsec| RawInstant { tv_sec, tv_nsec };
        let timer = |deadline, stopped| WaitTarget::Timer { deadline, stopped };
        assert_eq!(
            timer(at(12, 0), Some(at(2, 0))).to_string(),
            "timer (deadline +10.000s)"
        );
        // The cell is the kind word alone: the deadline is the detail
        // lines' to print.
        assert_eq!(timer(at(12, 0), Some(at(2, 0))).cell(), "timer");
        assert_eq!(
            timer(at(2, 641_000_000), Some(at(12, 0))).to_string(),
            "timer (overdue by 9.359s)"
        );
        assert_eq!(
            timer(at(12, 500_000_000), None).to_string(),
            "timer (deadline 12.500s on the target's monotonic clock)"
        );
        assert_eq!(timer(at(12, 0), Some(at(2, 0))).group_label(), "timer");

        let task = WaitTarget::Task {
            addr: 0x5000,
            task_id: Some(42),
            state: TaskState(1 << 6),
            listed: true,
            kind: None,
        };
        assert_eq!(task.to_string(), "task 42");
        assert_eq!(task.group_label(), "task 42");
        let anonymous = WaitTarget::Task {
            addr: 0x5000,
            task_id: None,
            state: TaskState(1 << 6),
            listed: true,
            kind: None,
        };
        assert_eq!(anonymous.to_string(), "the task at 0x5000");
        assert_eq!(anonymous.group_label(), "the task at 0x5000");

        let semaphore = WaitTarget::Semaphore {
            addr: 0x9000,
            owner: Some("tokio::sync::Mutex"),
            num_permits: 1,
            available: 0,
            closed: false,
            waiters: Vec::new(),
        };
        assert_eq!(
            semaphore.to_string(),
            "a tokio::sync::Mutex (semaphore 0x9000): 1 permit requested, 0 available"
        );
        assert_eq!(
            semaphore.group_label(),
            "a tokio::sync::Mutex (semaphore 0x9000)"
        );
        let unowned = WaitTarget::Semaphore {
            addr: 0x9000,
            owner: None,
            num_permits: 1,
            available: 0,
            closed: false,
            waiters: Vec::new(),
        };
        assert_eq!(unowned.group_label(), "the semaphore at 0x9000");

        let io = |fd, interest| WaitTarget::Io {
            addr: 0xa000,
            fd,
            interest,
        };
        assert_eq!(
            io(None, Some(Interest(0b01))).to_string(),
            "io 0xa000 (readable)"
        );
        assert_eq!(
            io(Some(17), Some(Interest(0b11))).to_string(),
            "io fd 17 (readable | writable)"
        );
        assert_eq!(io(None, None).to_string(), "io 0xa000 (readiness)");
        assert_eq!(io(None, None).group_label(), "io");
    }

    /// The wheel-state sentinels and the bit spellings: what the `-v`
    /// detail lines print, decoded from raw registry words.
    #[test]
    fn test_registry_words_decode() {
        let entry = |state| TimerEntryInfo {
            entry: 0x10,
            state,
            task: None,
            waker_at: None,
            deadline: None,
        };
        assert_eq!(
            entry(Some(1234)).wheel_state(),
            Some(WheelState::Registered)
        );
        assert_eq!(
            entry(Some(u64::MAX - 1)).wheel_state(),
            Some(WheelState::PendingFire)
        );
        assert_eq!(
            entry(Some(u64::MAX)).wheel_state(),
            Some(WheelState::Deregistered)
        );
        assert_eq!(entry(None).wheel_state(), None);
        assert_eq!(WheelState::Registered.to_string(), "registered");
        assert_eq!(WheelState::PendingFire.to_string(), "pending fire");
        assert_eq!(
            WheelState::Deregistered.to_string(),
            "fired, not yet polled"
        );

        assert_eq!(Readiness(0).to_string(), "<none>");
        assert_eq!(Readiness(0b101).to_string(), "readable | read closed");
        // An unknown bit prints in binary rather than vanishing.
        assert_eq!(Readiness(0b100_0001).to_string(), "readable | 0b1000000");
        assert_eq!(Interest(0b01).union(Interest(0b10)), Interest(0b11));
        // Overlapping bits stay set: a union, not a toggle.
        assert_eq!(Interest(0b01).union(Interest(0b01)), Interest(0b01));
        assert_eq!(IoSlot::Reader.interest(), Some(Interest(0b01)));
        assert_eq!(IoSlot::Writer.interest(), Some(Interest(0b10)));
        assert_eq!(IoSlot::Listed { interest: None }.interest(), None);

        let res = IoResourceInfo {
            addr: 0x20,
            readiness: Some(0x7fff_0002),
            consistency: Consistency::Unknown,
            waiters: Vec::new(),
        };
        // The packed word's high bits (the driver tick) are not
        // readiness.
        assert_eq!(res.ready(), Some(Readiness(0b10)));
    }

    /// A registration word is a millisecond tick from the driver's
    /// epoch, and the deadline it encodes carries into the seconds; the
    /// fired and deregistered sentinels encode none.
    #[test]
    fn test_a_wheel_word_decodes_to_a_deadline_from_the_epoch() {
        let start = RawInstant {
            tv_sec: 100,
            tv_nsec: 999_000_000,
        };
        assert_eq!(
            TimerEntryInfo::wheel_deadline(start, 0),
            Some(start),
            "tick zero is the epoch"
        );
        assert_eq!(
            TimerEntryInfo::wheel_deadline(start, 1_500),
            Some(RawInstant {
                tv_sec: 102,
                tv_nsec: 499_000_000,
            })
        );
        assert_eq!(
            TimerEntryInfo::wheel_deadline(start, timer::STATE_DEREGISTERED),
            None
        );
        assert_eq!(
            TimerEntryInfo::wheel_deadline(start, timer::STATE_PENDING_FIRE),
            None
        );
        assert_eq!(
            deadline_text(
                RawInstant {
                    tv_sec: 40,
                    tv_nsec: 369_000_000
                },
                Some(RawInstant {
                    tv_sec: 12,
                    tv_nsec: 0
                })
            ),
            "deadline +28.369s"
        );
    }

    /// The registry joins hand back exactly the entries armed with the
    /// asked-for task's waker.
    #[test]
    fn test_registries_join_by_task() {
        let registries = Registries::new(
            vec![
                TimerEntryInfo {
                    entry: 0x10,
                    state: None,
                    task: Some(0x1000),
                    waker_at: None,
                    deadline: None,
                },
                TimerEntryInfo {
                    entry: 0x20,
                    state: None,
                    task: None,
                    waker_at: None,
                    deadline: None,
                },
            ],
            vec![IoResourceInfo {
                addr: 0x30,
                readiness: None,
                consistency: Consistency::Unknown,
                waiters: vec![
                    IoWaiterInfo {
                        slot: IoSlot::Reader,
                        task: Some(0x1000),
                        waker_at: None,
                        node: None,
                        ready: None,
                    },
                    IoWaiterInfo {
                        slot: IoSlot::Writer,
                        task: Some(0x2000),
                        waker_at: None,
                        node: None,
                        ready: None,
                    },
                ],
            }],
        );
        let timers: Vec<u64> = registries.timers_of(0x1000).map(|t| t.entry).collect();
        assert_eq!(timers, [0x10]);
        assert!(registries.timers_of(0x9999).next().is_none());
        let io: Vec<(u64, IoSlot)> = registries
            .io_of(0x1000)
            .map(|(r, w)| (r.addr, w.slot))
            .collect();
        assert_eq!(io, [(0x30, IoSlot::Reader)]);
        assert!(registries.io_of(0x9999).next().is_none());
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the walker reports: the observation model — tasks, workers,
//! await chains, wait targets — and its `Display` forms. Nothing here
//! reads a target; [`bundle`](super::bundle) builds these, and the
//! census, graph, and every command consume them.

use super::{Lifecycle, Location, RawInstant, TaskAddr, TaskState};

use hansei_bundle::{BundleTypeId, FutureKind, TaskEntryId};
use reify::Value;

use std::fmt;

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
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
    /// The tids of the workers whose `Context` reaches this handle, in
    /// discovery order. Empty on a runtime no thread is currently in —
    /// see [`DiscoveryRoute::WorkerContext`].
    pub worker_tids: Vec<u32>,
    /// How the runtime was found.
    pub route: DiscoveryRoute,
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

/// Which route found a task list's owner — a [`LocalSetRef`], or a
/// [`RuntimeRef`] no thread's `Context` points at.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DiscoveryRoute {
    /// A thread's `Context` points at it: the ordinary way a runtime is
    /// found, and the only one that also says which threads run it. No
    /// local set is ever found this way.
    WorkerContext,
    /// A `JoinHandle` on an enumerated task's await chain pointed at
    /// one of its tasks.
    JoinHandle,
    /// A task waker in a walked waiter queue pointed at one of them.
    QueuedWaker,
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
}

impl fmt::Display for DiscoveryRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerContext => f.write_str("a thread's runtime context"),
            Self::JoinHandle => f.write_str("a JoinHandle held by an enumerated task"),
            Self::QueuedWaker => f.write_str("a task waker in a walked waiter queue"),
            Self::Wheel => f.write_str("a task waker on a timer parked in a runtime's wheel"),
            Self::Io => {
                f.write_str("a task waker on an io resource registered with a runtime's driver")
            }
            Self::Tls => f.write_str("the polling thread's TLS anchor"),
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
/// scheduler core is: the loop checks the core *into* the context's
/// `RefCell` while it parks or polls the root future — taking the
/// driver out of it for exactly as long as it parks — and holds it on
/// the stack, unreadable from here, while it runs tasks.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CtActivity {
    /// Core checked in, driver taken: blocked in the system's readiness
    /// call (or a zero-duration yield to it) on the runtime's behalf.
    Parked,
    /// Core checked in, driver present: polling the `block_on` future
    /// itself.
    PollingBlockOn,
    /// Core checked out to the thread's stack: running spawned tasks or
    /// the scheduler's own bookkeeping.
    RunningTasks,
}

impl fmt::Display for CtActivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parked => f.write_str("parked in the driver"),
            Self::PollingBlockOn => f.write_str("polling the block_on future"),
            Self::RunningTasks => f.write_str("running tasks"),
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
}

impl Registries {
    /// The wheel entries armed with `task`'s waker.
    pub fn timers_of(&self, task: u64) -> impl Iterator<Item = &TimerEntryInfo> {
        self.timers.iter().filter(move |t| t.task == Some(task))
    }

    /// The io waiters parked by `task`, each with the resource it is on.
    pub fn io_of(&self, task: u64) -> impl Iterator<Item = (&IoResourceInfo, &IoWaiterInfo)> {
        self.io.iter().flat_map(move |res| {
            res.waiters
                .iter()
                .filter(move |w| w.task == Some(task))
                .map(move |w| (res, w))
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
}

impl TimerEntryInfo {
    /// The entry's decoded wheel state, where the word was readable.
    pub fn wheel_state(&self) -> Option<WheelState> {
        const DEREGISTERED: u64 = u64::MAX;
        const PENDING_FIRE: u64 = DEREGISTERED - 1;
        Some(match self.state? {
            DEREGISTERED => WheelState::Deregistered,
            PENDING_FIRE => WheelState::PendingFire,
            _ => WheelState::Registered,
        })
    }
}

/// Where a wheel entry is in its life, decoded from its state word.
/// The sentinels are tokio's own constants, folded into its code at
/// compile time and so — as with [`TaskState`](super::TaskState) —
/// knowable only from its source.
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
            Self::Registered => f.write_str("registered"),
            Self::PendingFire => f.write_str("pending fire"),
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
            Self::Reader => Some(Interest(0b01)),
            Self::Writer => Some(Interest(0b10)),
            Self::Listed { interest } => *interest,
        }
    }
}

/// A parked waiter's interest set, in tokio's `Interest` bits.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Interest(pub u64);

impl Interest {
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
    /// Which group owns it: an index into the merged population's group
    /// space — every [`RuntimeRef`], those a thread's context reaches
    /// first and those discovery found after, then the
    /// [`LocalSetRef`]s — stamped by [`Context::enumerate_all_tasks`]
    /// and [`Context::discover_hidden_tasks`]. 0 on the single-runtime,
    /// no-local-set targets that are nearly all of them.
    pub group: usize,
    /// A `spawn_blocking` cell rather than a scheduler-owned task:
    /// found in the pool's queue, or through a `JoinHandle` whose
    /// cell records the blocking scheduler. Its STATE spells queued
    /// or running, never idle — the pool has no parked state.
    pub blocking: bool,
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
#[derive(Debug)]
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
    /// [`Context::await_chain`].
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
    pub future: Value<'b>,
    /// The decoded coroutine state; `None` for plain (leaf) futures.
    pub state: Option<FrameState<'b>>,
    /// The mangled symbol that identified this frame, when it was
    /// reached through a `dyn Future` vtable in target memory.
    pub dyn_symbol: Option<String>,
    /// The member the chain descended through, when this frame is a
    /// wrapper whose one inner future is the next frame rather than a
    /// suspended coroutine naming an `__awaitee`.
    ///
    /// A consumer walking a frame's locals must skip it for the same
    /// reason it skips `__awaitee`: it is the next frame, counted there,
    /// not a future held beside the chain.
    pub inner: Option<&'b str>,
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
    /// Bottomed out normally: a non-coroutine leaf future, or a state
    /// with nothing awaited.
    Leaf,
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
}

impl WaitTarget {
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
                // (overdue once the deadline has passed) — else the absolute
                // point, which is all there is to say.
                if let Some(stopped) = stopped {
                    let ns = |i: &RawInstant| i.tv_sec as i128 * 1_000_000_000 + i.tv_nsec as i128;
                    let delta = ns(deadline) - ns(stopped);
                    let word = if delta < 0 {
                        "overdue by "
                    } else {
                        "deadline +"
                    };
                    let delta = delta.unsigned_abs();
                    write!(
                        f,
                        "timer ({word}{}.{:03}s)",
                        delta / 1_000_000_000,
                        (delta % 1_000_000_000) / 1_000_000
                    )
                } else {
                    write!(
                        f,
                        "timer (deadline {}.{:03}s on the target's monotonic clock)",
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
            (CtActivity::RunningTasks, "running tasks"),
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
    /// grouping buckets by.
    #[test]
    fn test_wait_target_spellings() {
        let at = |tv_sec, tv_nsec| RawInstant { tv_sec, tv_nsec };
        let timer = |deadline, stopped| WaitTarget::Timer { deadline, stopped };
        assert_eq!(
            timer(at(12, 0), Some(at(2, 0))).to_string(),
            "timer (deadline +10.000s)"
        );
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
        assert_eq!(IoSlot::Reader.interest(), Some(Interest(0b01)));
        assert_eq!(IoSlot::Writer.interest(), Some(Interest(0b10)));
        assert_eq!(IoSlot::Listed { interest: None }.interest(), None);

        let res = IoResourceInfo {
            addr: 0x20,
            readiness: Some(0x7fff_0002),
            waiters: Vec::new(),
        };
        // The packed word's high bits (the driver tick) are not
        // readiness.
        assert_eq!(res.ready(), Some(Readiness(0b10)));
    }

    /// The registry joins hand back exactly the entries armed with the
    /// asked-for task's waker.
    #[test]
    fn test_registries_join_by_task() {
        let registries = Registries {
            timers: vec![
                TimerEntryInfo {
                    entry: 0x10,
                    state: None,
                    task: Some(0x1000),
                },
                TimerEntryInfo {
                    entry: 0x20,
                    state: None,
                    task: None,
                },
            ],
            io: vec![IoResourceInfo {
                addr: 0x30,
                readiness: None,
                waiters: vec![
                    IoWaiterInfo {
                        slot: IoSlot::Reader,
                        task: Some(0x1000),
                    },
                    IoWaiterInfo {
                        slot: IoSlot::Writer,
                        task: Some(0x2000),
                    },
                ],
            }],
        };
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

    /// Granted means nothing more is needed — the future holds the
    /// resource, not merely a place in line.
    #[test]
    fn test_granted_is_needed_zero() {
        let acquire = |needed| AbandonedAcquire {
            frame: "frame".to_owned(),
            state: "Suspend0".to_owned(),
            await_loc: None,
            local: "fut".to_owned(),
            future: "Acquire".to_owned(),
            owner: None,
            semaphore: 0x10,
            node: 0x20,
            num_permits: 2,
            needed,
        };
        assert!(acquire(0).granted());
        assert!(!acquire(1).granted());
    }
}

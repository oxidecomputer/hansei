// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What the walker reports: the observation model — tasks, workers,
//! await chains, wait targets — and its `Display` forms. Nothing here
//! reads a target; [`bundle`](super::bundle) builds these, and the
//! census, graph, and every command consume them.

use super::{Lifecycle, Location, RawInstant, TaskAddr, TaskState};

use hansei_bundle::{FutureKind, TaskEntryId};
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
    /// discovery order.
    pub worker_tids: Vec<u32>,
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
    /// Which runtime owns it: an index into the [`RuntimeRef`] list the
    /// enumeration merged, stamped by [`Context::enumerate_all_tasks`].
    /// 0 on the single-runtime targets that are nearly all of them.
    pub runtime: usize,
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
        candidates: Vec<String>,
    },
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
        /// Concrete bundle type names sharing the normalized key.
        candidates: Vec<String>,
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
        /// this session cannot list: the blocking pool, or another
        /// runtime.
        listed: bool,
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
    /// A semaphore, named by the primitive wrapping it where the frame
    /// awaiting it says which (`tokio::sync::Mutex`, …).
    Semaphore { owner: Option<&'static str> },
}

impl WaitTarget {
    /// This wait as a tally counts it.
    pub fn kind(&self) -> WaitKind {
        match self {
            Self::Timer { deadline, stopped } => WaitKind::Timer {
                past_due: stopped.map(|stopped| {
                    (deadline.tv_sec, deadline.tv_nsec) < (stopped.tv_sec, stopped.tv_nsec)
                }),
            },
            Self::Task { addr, .. } => WaitKind::Task { addr: *addr },
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
                // (negative once the deadline has passed) — else the absolute
                // point, which is all there is to say.
                if let Some(stopped) = stopped {
                    let ns = |i: &RawInstant| i.tv_sec as i128 * 1_000_000_000 + i.tv_nsec as i128;
                    let delta = ns(deadline) - ns(stopped);
                    let sign = if delta < 0 { "-" } else { "" };
                    let delta = delta.unsigned_abs();
                    write!(
                        f,
                        "the timer: deadline {sign}{}.{:03}s",
                        delta / 1_000_000_000,
                        (delta % 1_000_000_000) / 1_000_000
                    )
                } else {
                    write!(
                        f,
                        "the timer: deadline {}.{:03}s on the target's monotonic clock",
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
            } => {
                match task_id {
                    Some(id) => write!(f, "task {id} (JoinHandle)")?,
                    None => write!(f, "the task at {addr:#x} (JoinHandle)")?,
                }
                // Either way the listings cannot show it: complete
                // means off the owned list, alive only through this
                // handle; alive-but-unlisted means it runs somewhere
                // this session does not enumerate.
                if state.lifecycle() == Lifecycle::Complete {
                    write!(f, " — already complete, awaiting consumption")?;
                } else if !listed {
                    write!(
                        f,
                        " — {}, but not in the scheduler's owned tasks \
                         (a spawn_blocking task, or another runtime's)",
                        state.lifecycle()
                    )?;
                }
                Ok(())
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

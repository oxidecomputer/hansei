// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tokio specific types that are loadable from CTF and/or DWARF debug info

pub mod bundle;
// The CTF and debugdb-based DWARF paths read live targets through
// libproc; only the bundle path compiles everywhere.
#[cfg(target_os = "illumos")]
pub mod ctf;
#[cfg(target_os = "illumos")]
pub mod dwarf;
pub mod graph;

#[cfg(target_os = "illumos")]
use anyhow::Context as _;
#[cfg(target_os = "illumos")]
use proc::{Proc, Regs};

#[cfg(target_os = "illumos")]
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::mem;
#[cfg(target_os = "illumos")]
use std::ops::Range;
use std::time::{Duration, Instant};
#[cfg(target_os = "illumos")]
use unwind::Backtrace;

#[cfg(target_os = "illumos")]
#[derive(Debug)]
pub struct TokioRuntime {
    pub workers: BTreeMap<u32, WorkerState>,
    pub scheduler: Scheduler,
    pub now: Instant,
}

#[cfg(target_os = "illumos")]
impl TokioRuntime {
    pub fn active_workers(&self) -> Vec<&WorkerState> {
        let len = self.scheduler.shared.active_workers.len();
        let mut workers = Vec::with_capacity(len);

        for active in &self.scheduler.shared.active_workers {
            let worker = self
                .workers
                .values()
                .find(|state| {
                    let Some(id) = state.thd_ctx.worker_index else {
                        return false;
                    };
                    id == *active
                })
                .unwrap();
            workers.push(worker);
        }
        workers
    }
}

#[cfg(target_os = "illumos")]
#[derive(Clone, PartialEq, Debug)]
pub struct WorkerState {
    pub thd_ctx: ThreadCtx,
    pub backtrace: Option<Backtrace>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ThreadCtx {
    pub current_task_id: Option<u64>,
    pub thread_id: Option<u64>,
    pub worker_index: Option<u64>,
    pub worker_core: Option<WorkerCore>,
    pub defer: Vec<Waker>,
    pub runtime: EnterRuntime,
    pub budget: Budget,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum EnterRuntime {
    Entered { allow_block_in_place: bool },
    NotEntered,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Budget(pub Option<u8>);

impl Budget {
    pub fn has_remaining(&self) -> bool {
        self.0.map_or(true, |b| b > 0)
    }

    pub fn is_unconstrained(&self) -> bool {
        self.0.is_none()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Scheduler {
    pub shared: Shared,
    pub driver: DriverHandle,
}

#[derive(Clone, PartialEq, Debug)]
pub struct WorkerCore {
    pub tick: u32,
    pub global_queue_interval: u32,
    pub lifo_enabled: bool,
    pub lifo_slot: Option<TaskAddr>,
    pub run_queue: TaskQueue,
    pub is_searching: bool,
    pub is_shutdown: bool,
    pub is_traced: bool,
    pub park: Option<Parker>,
    pub stats: WorkerStats,
}

#[derive(Clone, PartialEq)]
pub struct Parker(pub u64);

impl Parker {
    const EMPTY: u64 = 0;
    const PARKED_CONDVAR: u64 = 1;
    const PARKED_DRIVER: u64 = 2;
    const NOTIFIED: u64 = 3;

    pub fn is_unparked(&self) -> bool {
        self.0 == Self::EMPTY
    }

    pub fn is_parked_waiting(&self) -> bool {
        self.0 == Self::PARKED_CONDVAR
    }

    pub fn is_parked_driving_io(&self) -> bool {
        self.0 == Self::PARKED_DRIVER
    }

    pub fn is_notified(&self) -> bool {
        self.0 == Self::NOTIFIED
    }
}

impl fmt::Debug for Parker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_desc = match self.0 {
            Self::EMPTY => format_args!("running ({})", self.0),
            Self::PARKED_CONDVAR => format_args!("parked_condvar ({})", self.0),
            Self::PARKED_DRIVER => format_args!("parked_io_driver ({})", self.0),
            Self::NOTIFIED => format_args!("notify_wake ({})", self.0),
            _ => format_args!("unknown ({})", self.0),
        };

        f.debug_struct("Parker")
            .field("state", &state_desc)
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct WorkerStats {
    /// The metrics batch used to report runtime-level metrics/stats to the
    /// user.
    pub batch: MetricsBatch,
    /// Number of tasks polled in the batch of scheduled tasks
    pub tasks_polled_in_batch: u64,
    /// Exponentially-weighted moving average of time spent polling scheduled a
    /// task.
    ///
    /// Tracked in nanoseconds, stored as a `f64` since that is what we use with
    /// the EWMA calculations
    pub task_poll_time_ewma: f64,
}

#[derive(Clone, PartialEq)]
pub struct MetricsBatch {
    /// The total busy duration in nanoseconds.
    pub busy_duration_total: u64,
    // Instant at which work last resumed (continued after park).
    pub processing_scheduled_tasks_started_at: Option<RawInstant>,
    /// Number of times the worker parked.
    pub park_count: u64,
    /// Number of times the worker parked and unparked.
    pub park_unpark_count: u64,
    /// Number of times the worker woke w/o doing work.
    pub noop_count: u64,
    /// Number of tasks stolen.
    pub steal_count: u64,
    /// Number of times tasks where stolen.
    pub steal_operations: u64,
    /// Number of tasks that were polled by the worker.
    pub poll_count: u64,
    /// Number of tasks polled when the worker entered park. This is used to
    /// track the noop count.
    pub poll_count_on_last_park: u64,
    /// Number of tasks that were scheduled locally on this worker.
    pub local_schedule_count: u64,
    /// Number of tasks moved to the global queue to make space in the local
    /// queue
    pub overflow_count: u64,
}

impl fmt::Debug for MetricsBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsBatch")
            .field(
                "busy_duration_total",
                &format_args!(
                    "{} ({})",
                    self.busy_duration_total,
                    humantime::format_duration(Duration::from_nanos(self.busy_duration_total))
                ),
            )
            .field("park_count", &self.park_count)
            .field("park_unpark_count", &self.park_unpark_count)
            .field("noop_count", &self.noop_count)
            .field("steal_count", &self.steal_count)
            .field("steal_operations", &self.steal_operations)
            .field("poll_count", &self.poll_count)
            .field("poll_count_on_last_park", &self.poll_count_on_last_park)
            .field("local_schedule_count", &self.local_schedule_count)
            .field("overflow_count", &self.overflow_count)
            .field(
                "processing_scheduled_tasks_started_at",
                &self.processing_scheduled_tasks_started_at,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Shared {
    // /// Per-worker remote state. All other workers have access to this and is
    // /// how they communicate between each other.
    pub remotes: Box<[Remote]>,
    /// Tokio uses this to access the global task queue used for.
    /// For our purposes we just use to to easily see the number of pending jobs.
    pub inject_len: u64,

    /// Coordinates idle workers
    pub idle: Idle,

    /// Not a real field, the inverse of `Idle.idle_sleepers`
    pub active_workers: BTreeSet<u64>,

    /// Collection of all active tasks spawned onto this executor.
    pub owned: OwnedTasks,

    /// Data synchronized by the scheduler mutex
    pub synced: Synced,

    // /// Cores that have observed the shutdown signal
    // ///
    // /// The core is **not** placed back in the worker to avoid it from being
    // /// stolen by a thread that was spawned as part of `block_in_place`.
    // #[allow(clippy::vec_box)] // we're moving an already-boxed value
    // shutdown_cores: Mutex<Vec<Box<Core>>>,

    // /// The number of cores that have observed the trace signal.
    // pub(super) trace_status: TraceStatus,
    /// Scheduler configuration options
    pub config: Config,
    // /// Collects metrics from the runtime.
    pub scheduler_metrics: SchedulerMetrics,
    pub worker_metrics: Box<[WorkerMetrics]>,
    // /// Only held to trigger some code on drop. This is used to get internal
    // /// runtime metrics that can be useful when doing performance
    // /// investigations. This does nothing (empty struct, no drop impl) unless
    // /// the `tokio_internal_mt_counters` `cfg` flag is set.
    // _counters: Counters,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Remote {
    pub steal: TaskQueue,
    pub unpark: Parker,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Idle {
    pub num_searching: u64,
    pub num_unparked: u64,
    pub num_workers: u64,
}

#[derive(Clone, PartialEq)]
pub struct OwnedTasks {
    pub tasks: HashMap<TaskAddr, TaskHeader>,
    pub added: u64,
    pub count: u64,
    pub closed: bool,
    pub shard_mask: u64,
}

impl fmt::Debug for OwnedTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedTasks")
            .field("tasks", &self.tasks)
            .field("added", &self.added)
            .field("count", &self.count)
            .field("shard_mask", &format_args!("{:#b}", self.shard_mask))
            .finish()
    }
}

// TODO non-zero? Validate mapping?
#[derive(Copy, Clone, PartialEq, PartialOrd, Ord, Hash, Eq)]
pub struct TaskAddr(pub u64);

impl fmt::Debug for TaskAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Synced {
    pub idle_sleepers: BTreeSet<u64>,
    pub inject_closed: bool,
    pub inject_head: Option<TaskAddr>,
    pub inject_tail: Option<TaskAddr>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Inject {
    pub len: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Config {
    /// How many ticks before pulling a task from the global/remote queue?
    pub global_queue_interval: Option<u32>,

    /// How many ticks before yielding to the driver for timer and I/O events?
    pub event_interval: u32,

    // /// Callback for a worker parking itself
    // pub(crate) before_park: Option<Callback>,

    // /// Callback for a worker unparking itself
    // pub(crate) after_unpark: Option<Callback>,

    // /// To run before each task is spawned.
    // pub(crate) before_spawn: Option<TaskCallback>,

    // /// To run after each task is terminated.
    // pub(crate) after_termination: Option<TaskCallback>,

    // /// To run before each poll
    // #[cfg(tokio_unstable)]
    // pub(crate) before_poll: Option<TaskCallback>,

    // /// To run after each poll
    // #[cfg(tokio_unstable)]
    // pub(crate) after_poll: Option<TaskCallback>,
    /// The multi-threaded scheduler includes a per-worker LIFO slot used to
    /// store the last scheduled task. This can improve certain usage patterns,
    /// especially message passing between tasks. However, this LIFO slot is not
    /// currently stealable.
    ///
    /// Eventually, the LIFO slot **will** become stealable, however as a
    /// stop-gap, this unstable option lets users disable the LIFO task.
    pub disable_lifo_slot: bool,
    // /// Random number generator seed to configure runtimes to act in a
    // /// deterministic way.
    // pub(crate) seed_generator: RngSeedGenerator,

    // /// How to build poll time histograms
    // pub(crate) metrics_poll_count_histogram: Option<crate::runtime::HistogramBuilder>,

    // #[cfg(tokio_unstable)]
    // /// How to respond to unhandled task panics.
    // pub(crate) unhandled_panic: crate::runtime::UnhandledPanic,
}

#[derive(Clone, PartialEq, Debug)]
pub struct SchedulerMetrics {
    pub remote_schedule_count: u64,
    pub budget_forced_yield_count: u64,
}

#[derive(Clone, PartialEq)]
pub struct WorkerMetrics {
    pub busy_duration_total: u64,
    pub queue_depth: u64,
    pub thread_id: Option<u64>,
    pub park_count: u64,
    pub park_unpark_count: u64,
    pub noop_count: u64,
    pub steal_count: u64,
    pub steal_operations: u64,
    pub poll_count: u64,
    pub mean_poll_time: u64,
    pub local_schedule_count: u64,
    pub overflow_count: u64,
}

impl fmt::Debug for WorkerMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetricsBatch")
            .field(
                "busy_duration_total",
                &format_args!(
                    "{} ({})",
                    self.busy_duration_total,
                    humantime::format_duration(Duration::from_nanos(self.busy_duration_total))
                ),
            )
            .field("queue_depth", &self.queue_depth)
            .field("thread_id", &self.thread_id)
            .field("park_count", &self.park_count)
            .field("park_unpark_count", &self.park_unpark_count)
            .field("noop_count", &self.noop_count)
            .field("steal_count", &self.steal_count)
            .field("steal_operations", &self.steal_operations)
            .field("poll_count", &self.poll_count)
            .field("mean_poll_time", &self.mean_poll_time)
            .field("local_schedule_count", &self.local_schedule_count)
            .field("overflow_count", &self.overflow_count)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct TaskQueue {
    pub head: u64,
    pub tail: u32,
    pub tasks: Vec<TaskAddr>,
}
impl fmt::Debug for TaskQueue {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TaskQueue")
            .field("head", &format_args!("{:#016x}", self.head))
            .field("tail", &format_args!("{:#016x}", self.tail))
            .field("tasks", &self.tasks)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct TaskHeader {
    pub state: u64,
    pub runtime_id: Option<u64>,
    pub id: u64,
    pub spawn_location: Location,
    pub waker: Option<Waker>,
}

impl TaskHeader {
    /// The task is currently being run.
    const RUNNING: u64 = 0b0001;

    /// The task is complete.
    ///
    /// Once this bit is set, it is never unset.
    const COMPLETE: u64 = 0b0010;

    /// Extracts the task's lifecycle value from the state.
    const LIFECYCLE_MASK: u64 = 0b11;

    /// Flag tracking if the task has been pushed into a run queue.
    const NOTIFIED: u64 = 0b100;

    /// The join handle is still around.
    const JOIN_INTEREST: u64 = 0b1_000;

    /// A join handle waker has been set.
    const JOIN_WAKER: u64 = 0b10_000;

    /// The task has been forcibly cancelled.
    const CANCELLED: u64 = 0b100_000;

    /// All bits.
    const STATE_MASK: u64 = Self::LIFECYCLE_MASK
        | Self::NOTIFIED
        | Self::JOIN_INTEREST
        | Self::JOIN_WAKER
        | Self::CANCELLED;

    /// Bits used by the ref count portion of the state.
    const REF_COUNT_MASK: u64 = !Self::STATE_MASK;

    /// Number of positions to shift the ref count.
    const REF_COUNT_SHIFT: u64 = Self::REF_COUNT_MASK.count_zeros() as u64;

    pub fn is_running(&self) -> bool {
        self.state & Self::RUNNING == Self::RUNNING
    }

    pub fn is_idle(&self) -> bool {
        self.state & (Self::RUNNING | Self::COMPLETE) == 0
    }

    pub fn is_notified(&self) -> bool {
        self.state & Self::NOTIFIED == Self::NOTIFIED
    }

    pub fn is_cancelled(&self) -> bool {
        self.state & Self::CANCELLED == Self::CANCELLED
    }

    pub fn is_complete(&self) -> bool {
        self.state & Self::COMPLETE == Self::COMPLETE
    }

    pub fn is_join_interested(&self) -> bool {
        self.state & Self::JOIN_INTEREST == Self::JOIN_INTEREST
    }

    pub fn ref_count(&self) -> u64 {
        (self.state & Self::REF_COUNT_MASK) >> Self::REF_COUNT_SHIFT
    }

    pub fn is_join_waker_set(&self) -> bool {
        self.state & Self::JOIN_WAKER == Self::JOIN_WAKER
    }
}

impl fmt::Debug for TaskHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TaskHeader")
            .field("id", &self.id)
            .field("spawn_location", &self.spawn_location)
            .field("ref_count", &self.ref_count())
            .field("waker", &self.waker)
            .field("runtime_id", &self.runtime_id)
            .field("inner_state", &format_args!("{:#b}", self.state))
            .field("is_running", &self.is_running())
            .field("is_complete", &self.is_complete())
            .field("is_notified", &self.is_notified())
            .field("is_cancelled", &self.is_cancelled())
            .field("is_join_interested", &self.is_join_interested())
            .field("is_join_waker_set", &self.is_join_waker_set())
            .finish()
    }
}

/// Find the address of the thread-local `tokio::runtime::context::Context` for
/// this LWP, if present. The first three u64s of this type form a
/// recognizeable pattern unlikely to be replicated by other types.
#[cfg(target_os = "illumos")]
pub fn find_thd_context(
    regs: &Regs,
    brk_range: &Range<u64>,
    proc: &Proc,
) -> anyhow::Result<Option<u64>> {
    let tls = proc
        .tsd_from_regs(regs)
        .context("failed to get thread-local data")?;
    for addr in tls {
        // The `tokio::runtime::context::Context` is heap allocated.
        // So far I haven't observed this being located in an anonymous mmap.
        //if !brk_range.contains(&addr) {
        //    continue;
        //}
        const CONTEXT_SIZE: u64 = 3 * size_of::<u64>() as u64;
        let mut buf = [0u8; CONTEXT_SIZE as usize];

        // The value may be unmapped.
        if proc.pread_exact(&mut buf, addr).is_err() {
            continue;
        }
        let buf: [u64; 3] = unsafe { mem::transmute(buf) };

        // The first item is a refcell's `BorrowCounter` isize. In well-behaved
        // code this is always -1, 0, or 1. Values outside of this will trigger
        // a panic.
        let borrow_counter = buf[0] as i64;
        if !(-1..=1).contains(&borrow_counter) {
            continue;
        }

        // The next is the discriminant for the
        // Option<tokio::runtime::scheduler::Handle>. This may be 0, 1, or 2, as
        // CurrentThread, MultiThread, and None, respectively. We only care
        // about MultiThread.
        let discrim = buf[1];
        if discrim != 1 {
            continue;
        }

        // The third item is the pointer to the
        // tokio::runtime::scheduler::Handle, which is heap allocated.
        let handle = buf[2];
        if !brk_range.contains(&handle) {
            continue;
        }

        return Ok(Some(addr));
    }

    Ok(None)
}

/// The raw `Header.state` bitfield of a task, with the derived lifecycle
/// classification (plan §3.2).
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct TaskState(pub u64);

impl TaskState {
    /// The task is currently being run.
    const RUNNING: u64 = 0b0001;
    /// The task is complete. Once set, never unset.
    const COMPLETE: u64 = 0b0010;
    /// The task has been pushed into a run queue.
    const NOTIFIED: u64 = 0b100;
    /// The join handle is still around.
    const JOIN_INTEREST: u64 = 0b1_000;
    /// A join handle waker has been set.
    const JOIN_WAKER: u64 = 0b10_000;
    /// The task has been forcibly cancelled.
    const CANCELLED: u64 = 0b100_000;

    const STATE_MASK: u64 = Self::RUNNING
        | Self::COMPLETE
        | Self::NOTIFIED
        | Self::JOIN_INTEREST
        | Self::JOIN_WAKER
        | Self::CANCELLED;
    const REF_COUNT_MASK: u64 = !Self::STATE_MASK;
    const REF_COUNT_SHIFT: u64 = Self::REF_COUNT_MASK.count_zeros() as u64;

    pub fn is_running(&self) -> bool {
        self.0 & Self::RUNNING != 0
    }

    pub fn is_complete(&self) -> bool {
        self.0 & Self::COMPLETE != 0
    }

    pub fn is_notified(&self) -> bool {
        self.0 & Self::NOTIFIED != 0
    }

    pub fn is_cancelled(&self) -> bool {
        self.0 & Self::CANCELLED != 0
    }

    pub fn is_join_interested(&self) -> bool {
        self.0 & Self::JOIN_INTEREST != 0
    }

    pub fn is_join_waker_set(&self) -> bool {
        self.0 & Self::JOIN_WAKER != 0
    }

    pub fn ref_count(&self) -> u64 {
        (self.0 & Self::REF_COUNT_MASK) >> Self::REF_COUNT_SHIFT
    }

    /// Derived lifecycle classification (plan §3.2). `COMPLETE` wins over
    /// `RUNNING` (the final poll sets both until the ref is dropped), and
    /// `NOTIFIED` only matters while the task is idle.
    pub fn lifecycle(&self) -> Lifecycle {
        if self.is_complete() {
            Lifecycle::Complete
        } else if self.is_running() {
            Lifecycle::Running
        } else if self.is_notified() {
            Lifecycle::Queued
        } else {
            Lifecycle::Idle
        }
    }
}

impl fmt::Debug for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskState")
            .field("lifecycle", &self.lifecycle())
            .field("ref_count", &self.ref_count())
            .field("is_cancelled", &self.is_cancelled())
            .field("is_join_interested", &self.is_join_interested())
            .field("is_join_waker_set", &self.is_join_waker_set())
            .field("bits", &format_args!("{:#b}", self.0))
            .finish()
    }
}

/// What a task is doing right now, derived from its state bits.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Lifecycle {
    /// Mid-poll on some worker thread.
    Running,
    /// Notified while idle: sitting in a run queue, not yet picked up.
    Queued,
    /// Suspended, waiting on a waker.
    Idle,
    /// Finished: returned, panicked, or cancelled.
    Complete,
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Self::Running => "running",
            Self::Queued => "queued",
            Self::Idle => "idle",
            Self::Complete => "complete",
        };
        f.write_str(desc)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Location {
    pub filename: String,
    pub line: u32,
    pub col: u32,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.filename, self.line, self.col)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct DriverHandle {
    pub io: IoHandle,
    pub time: TimeHandle,
    pub clock: Clock,
}

#[derive(Clone, PartialEq, Debug)]
pub enum IoHandle {
    Enabled(IoEnabled),
    Disabled(IoDisabled),
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoEnabled {
    pub num_pending_release: u64,
    pub waker_fd: i32,
    pub poll_fd: i32,
    pub metrics: IoDriverMetrics,
    pub synced: IoSynced,
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDisabled {
    pub park: ParkThread,
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoSynced {
    pub registrations: Vec<ScheduledIo>,
    pub is_shutdown: bool,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ScheduledIo {
    //head: Option<Box<Self>>,
    pub readiness: Ready,
    pub waiters: Waiters,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ready(pub u64);

impl Ready {
    const EMPTY: u64 = 0b0_00;
    const READABLE: u64 = 0b0_01;
    const WRITABLE: u64 = 0b0_10;
    const READ_CLOSED: u64 = 0b0_0100;
    const WRITE_CLOSED: u64 = 0b0_1000;
    const ERROR: u64 = 0b10_0000;
    const TICK: u64 = ((1 << 15) - 1) << 16;
    const SHUTDOWN: u64 = 1 << 31;

    /// Returns a `Ready` representing readiness for all operations.
    pub const ALL: Ready = Ready(
        Self::READABLE | Self::WRITABLE | Self::READ_CLOSED | Self::WRITE_CLOSED | Self::ERROR,
    );

    /// Returns true if `Ready` is the empty set.
    pub fn is_empty(self) -> bool {
        self.0 == Self::EMPTY
    }

    /// Returns `true` if the value includes `readable`.
    pub fn is_readable(self) -> bool {
        self.contains(Self::READABLE) || self.is_read_closed()
    }

    /// Returns `true` if the value includes writable `readiness`.
    pub fn is_writable(self) -> bool {
        self.contains(Self::WRITABLE) || self.is_write_closed()
    }

    /// Returns `true` if the value includes read-closed `readiness`.
    pub fn is_read_closed(self) -> bool {
        self.contains(Self::READ_CLOSED)
    }

    /// Returns `true` if the value includes write-closed `readiness`.
    pub fn is_write_closed(self) -> bool {
        self.contains(Self::WRITE_CLOSED)
    }

    /// Returns `true` if the value includes error `readiness`.
    pub fn is_error(self) -> bool {
        self.contains(Self::ERROR)
    }

    /// Returns `true` if the value includes error `readiness`.
    pub fn tick(self) -> u64 {
        self.0 & Self::TICK >> 16
    }

    /// Returns `true` if the value includes shutdown.
    pub fn is_shutdown(self) -> bool {
        self.contains(Self::SHUTDOWN)
    }

    /// Returns true if `self` is a superset of `other`.
    pub(crate) fn contains(self, other: u64) -> bool {
        (self.0 & other) == other
    }
}

impl fmt::Debug for Ready {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Ready")
            .field("is_readable", &self.is_readable())
            .field("is_writable", &self.is_writable())
            .field("is_read_closed", &self.is_read_closed())
            .field("is_write_closed", &self.is_write_closed())
            .field("is_error", &self.is_error())
            .field("tick", &self.tick())
            .field("is_shutdown", &self.is_shutdown())
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Waiters {
    pub list: Vec<Waiter>,
    pub reader: Option<Waker>,
    pub writer: Option<Waker>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Waiter {
    pub interest: Interest,
    pub is_ready: bool,
    pub waker: Option<Waker>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Interest(pub u64);

impl Interest {
    /// Interest in all readable events.
    ///
    /// Readable interest includes read-closed events.
    const READABLE: u64 = 0b0001;

    /// Interest in all writable events.
    ///
    /// Writable interest includes write-closed events.
    const WRITABLE: u64 = 0b0010;

    /// Interest in error events.
    ///
    /// Passes error interest to the underlying OS selector.
    /// Behavior is platform-specific, read your platform's documentation.
    const ERROR: u64 = 0b0010_0000;

    /// Returns true if the value includes readable interest.
    pub const fn is_readable(self) -> bool {
        self.0 & Self::READABLE != 0
    }

    /// Returns true if the value includes writable interest.
    pub const fn is_writable(self) -> bool {
        self.0 & Self::WRITABLE != 0
    }

    /// Returns true if the value includes error interest.
    pub const fn is_error(self) -> bool {
        self.0 & Self::ERROR != 0
    }
}

impl fmt::Debug for Interest {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = false;

        if self.is_readable() {
            if separator {
                write!(fmt, " | ")?;
            }
            write!(fmt, "READABLE")?;
            separator = true;
        }

        if self.is_writable() {
            if separator {
                write!(fmt, " | ")?;
            }
            write!(fmt, "WRITABLE")?;
            separator = true;
        }

        if self.is_error() {
            if separator {
                write!(fmt, " | ")?;
            }
            write!(fmt, "ERROR")?;
            separator = true;
        }

        let _ = separator;

        Ok(())
    }
}

#[derive(Clone, PartialEq)]
pub struct Waker {
    pub dependent_task: Option<TaskAddr>,
    pub dependent_park: Option<ParkThread>,
    pub data: TaskAddr,
    pub wake: &'static str,
    pub wake_by_ref: &'static str,
    pub clone: &'static str,
    pub drop: &'static str,
}

impl fmt::Debug for Waker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waker")
            .field("dependent_task", &self.dependent_task)
            .field("dependent_park", &self.dependent_park)
            .field("data", &self.data)
            .field("wake", &self.wake)
            .field("wake_by_ref", &self.wake_by_ref)
            .field("clone", &self.clone)
            .field("drop", &self.drop)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct ParkThread(pub u64);

impl ParkThread {
    const EMPTY: u64 = 0;
    const PARKED: u64 = 1;
    const NOTIFIED: u64 = 2;

    pub fn is_empty(&self) -> bool {
        self.0 == Self::EMPTY
    }

    pub fn is_notified(&self) -> bool {
        self.0 == Self::NOTIFIED
    }

    pub fn is_parked(&self) -> bool {
        self.0 == Self::PARKED
    }
}

impl fmt::Debug for ParkThread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_desc = match self.0 {
            Self::EMPTY => "empty",
            Self::NOTIFIED => "notified",
            Self::PARKED => "parked",
            _ => "invalid state",
        };
        f.debug_struct("ParkThread")
            .field("state", &format_args!("{} ({})", self.0, state_desc))
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDriverMetrics {
    pub fd_registered_count: u64,
    pub fd_deregistered_count: u64,
    pub ready_count: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimeHandle {
    pub is_shutdown: bool,
    pub did_wake: bool,
    pub time_source: RawInstant,
    pub wheel: Wheel,
    pub next_wake: Option<u64>,
}

/// Must match the layout of `tokio::time::Instant`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct RawInstant {
    pub tv_sec: u64,
    pub tv_nsec: u32,
}

impl TryFrom<proc::Timespec> for RawInstant {
    type Error = anyhow::Error;

    fn try_from(value: proc::Timespec) -> std::result::Result<Self, Self::Error> {
        const NSEC_PER_SEC: i64 = 1_000_000_000;
        if value.tv_nsec < 0 || value.tv_nsec >= NSEC_PER_SEC {
            anyhow::bail!("invalid process timestamp {value:?}");
        }

        Ok(Self {
            tv_sec: value.tv_sec as u64,
            tv_nsec: value.tv_nsec as u32,
        })
    }
}

impl From<RawInstant> for Instant {
    fn from(value: RawInstant) -> Self {
        assert_eq!(size_of::<RawInstant>(), size_of::<Instant>());

        // SAFETY: RawInstant has the same layout as the underlying `Timespec`
        // used by `tokio::time::Instant`, we hope.
        unsafe { mem::transmute(value) }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Clock {
    base: RawInstant,
    unfrozen: Option<RawInstant>,
    enable_pausing: bool,
}

#[derive(Clone, PartialEq)]
pub struct Wheel {
    /// The number of milliseconds elapsed since the wheel started.
    pub elapsed: u64,

    /// Timer wheel.
    ///
    /// Levels:
    ///
    /// * 1 ms slots / 64 ms range
    /// * 64 ms slots / ~ 4 sec range
    /// * ~ 4 sec slots / ~ 4 min range
    /// * ~ 4 min slots / ~ 4 hr range
    /// * ~ 4 hr slots / ~ 12 day range
    /// * ~ 12 day slots / ~ 2 yr range
    pub levels: Vec<Level>,
    pub pending: Vec<TimerShared>,
}

impl Wheel {
    pub fn next_expiration(&self) -> Option<Expiration> {
        for level in self.levels.iter() {
            if let Some(expiration) = level.next_expiration(self.elapsed) {
                return Some(expiration);
            }
        }

        None
    }

    pub fn elapsed_dur(&self) -> Duration {
        Duration::from_millis(self.elapsed)
    }
}

impl fmt::Debug for Wheel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wheel")
            .field("elapsed", &self.elapsed)
            .field("levels", &self.levels)
            .field("pending", &self.pending)
            .field("next_expiration", &self.next_expiration())
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct Level {
    pub level: u64,
    pub occupied: u64,
    pub slot: Vec<TimerSlot>,
}

impl fmt::Debug for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Level")
            .field("level", &self.level)
            .field("occupied", &format_args!("{:#064b}", self.occupied))
            .field("slot", &self.slot)
            .finish()
    }
}

impl Level {
    const LEVEL_MULT: u64 = 64;

    pub fn next_expiration(&self, now: u64) -> Option<Expiration> {
        // Use the `occupied` bit field to get the index of the next slot that
        // needs to be processed.
        let slot = self.next_occupied_slot(now)?;

        // From the slot index, calculate the `Instant` at which it needs to be
        // processed. This value *must* be in the future with respect to `now`.
        let level_range = self.level_range();
        let slot_range = self.slot_range();

        // Compute the start date of the current level by masking the low bits
        // of `now` (`level_range` is a power of 2).
        let level_start = now & !(level_range - 1);
        let mut deadline = level_start + slot as u64 * slot_range;

        if deadline <= now {
            deadline += level_range;
        }

        Some(Expiration {
            level: self.level,
            slot,
            deadline,
        })
    }

    fn next_occupied_slot(&self, now: u64) -> Option<u64> {
        if self.occupied == 0 {
            return None;
        }

        // Get the slot for now using Maths
        let now_slot = now / self.slot_range();
        let occupied = self.occupied.rotate_right(now_slot as u32);
        let zeros = occupied.trailing_zeros() as u64;
        let slot = (zeros + now_slot) % Self::LEVEL_MULT;

        Some(slot)
    }

    fn slot_range(&self) -> u64 {
        Self::LEVEL_MULT.pow(self.level as u32) as u64
    }

    fn level_range(&self) -> u64 {
        Self::LEVEL_MULT * self.slot_range()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Expiration {
    /// The level containing the slot.
    pub level: u64,

    /// The slot index.
    pub slot: u64,

    /// The instant at which the slot needs to be processed.
    pub deadline: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimerSlot {
    pub slot_id: usize,
    pub timers: Vec<TimerShared>,
}

#[derive(Clone, PartialEq)]
pub struct TimerShared {
    pub registered_when: u64,
    pub time_state: TimerState,
    pub dur_remaining: Option<Duration>,
    pub result: String,
    pub waker_state: WakerState,
    pub waker: Option<Waker>,
}

impl fmt::Debug for TimerShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimerShared")
            .field("registered_when", &self.registered_when)
            .field("time_state", &self.time_state)
            .field("time_remaining", &self.dur_remaining)
            .field("result", &self.result)
            .field("waker_state", &self.waker_state)
            .field("waker", &self.waker)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct TimerState(pub u64);

impl TimerState {
    const STATE_DEREGISTERED: u64 = u64::MAX;
    const STATE_PENDING_FIRE: u64 = Self::STATE_DEREGISTERED - 1;

    pub fn is_deregistered(&self) -> bool {
        self.0 == Self::STATE_DEREGISTERED
    }

    pub fn is_pending_fire(&self) -> bool {
        self.0 == Self::STATE_PENDING_FIRE
    }

    pub fn duration(&self, start: Duration) -> Option<Duration> {
        if self.0 == Self::STATE_DEREGISTERED {
            return None;
        }
        let current = Duration::from_millis(self.0);
        Some(current - start)
    }
}
impl fmt::Debug for TimerState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TimerState")
            .field("is_deregistered", &self.is_deregistered())
            .field("is_pending_fire", &self.is_pending_fire())
            .field("inner", &self.0)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct WakerState(pub u64);

impl WakerState {
    /// Idle state.
    const WAITING: u64 = 0;

    /// A new waker value is being registered with the `AtomicWaker` cell.
    const REGISTERING: u64 = 0b01;

    /// The task currently registered with the `AtomicWaker` cell is being woken.
    const WAKING: u64 = 0b10;

    pub fn is_waiting(&self) -> bool {
        self.0 == Self::WAITING
    }

    pub fn is_registering(&self) -> bool {
        self.0 & Self::REGISTERING != 0
    }

    pub fn is_waking(&self) -> bool {
        self.0 & Self::WAKING != 0
    }
}

impl fmt::Debug for WakerState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("WakerState")
            .field("is_waiting", &self.is_waiting())
            .field("is_registering", &self.is_registering())
            .field("is_waking", &self.is_waking())
            .field("inner", &format_args!("{:#b}", self.0))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Lifecycle, TaskState};

    const RUNNING: u64 = 0b0001;
    const COMPLETE: u64 = 0b0010;
    const NOTIFIED: u64 = 0b100;
    const JOIN_INTEREST: u64 = 0b1_000;
    const JOIN_WAKER: u64 = 0b10_000;
    const CANCELLED: u64 = 0b100_000;
    const REF_ONE: u64 = 1 << 6;

    /// Every lifecycle classification from plan §3.2, including tokio's
    /// INITIAL_STATE (0xCC: ref count 3, NOTIFIED | JOIN_INTEREST) and
    /// concurrently-set flag combinations.
    #[test]
    fn test_lifecycle_classification() {
        let cases: &[(u64, Lifecycle)] = &[
            // INITIAL_STATE: freshly spawned, queued for its first poll.
            (0xCC, Lifecycle::Queued),
            (2 * REF_ONE, Lifecycle::Idle),
            (2 * REF_ONE | JOIN_INTEREST | JOIN_WAKER, Lifecycle::Idle),
            (2 * REF_ONE | NOTIFIED, Lifecycle::Queued),
            (2 * REF_ONE | RUNNING, Lifecycle::Running),
            // Woken again while mid-poll: still running.
            (2 * REF_ONE | RUNNING | NOTIFIED, Lifecycle::Running),
            (REF_ONE | COMPLETE, Lifecycle::Complete),
            // The final poll sets COMPLETE while RUNNING is still set.
            (REF_ONE | COMPLETE | RUNNING, Lifecycle::Complete),
            (REF_ONE | COMPLETE | CANCELLED, Lifecycle::Complete),
            // Cancelled but not yet complete: still waiting to be polled.
            (2 * REF_ONE | NOTIFIED | CANCELLED, Lifecycle::Queued),
        ];
        for &(bits, expected) in cases {
            let state = TaskState(bits);
            assert_eq!(state.lifecycle(), expected, "state bits {bits:#b}");
        }
    }

    #[test]
    fn test_state_flags_and_ref_count() {
        let initial = TaskState(0xCC);
        assert_eq!(initial.ref_count(), 3);
        assert!(initial.is_notified());
        assert!(initial.is_join_interested());
        assert!(!initial.is_running());
        assert!(!initial.is_complete());
        assert!(!initial.is_cancelled());
        assert!(!initial.is_join_waker_set());

        let state = TaskState(5 * REF_ONE | RUNNING | JOIN_WAKER | CANCELLED);
        assert_eq!(state.ref_count(), 5);
        assert!(state.is_running());
        assert!(state.is_join_waker_set());
        assert!(state.is_cancelled());
        assert!(!state.is_notified());
    }
}

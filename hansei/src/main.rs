use anyhow::{Context as _, Result};
use clap::Parser;
use durin::TypeId;
use durin::read::{BytesFromCore, CtfReader, ParseWithCtf, TypeInfo, TypeInfoRef};
use durin::{Error, TypeKind};
use proc::Core;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::mem;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub mod unwind;

/// TypeId of tokio::runtime::task::core::Header.
static HDR_ID: OnceLock<TypeId> = OnceLock::new();
/// TypeId of core::panic::location::Location.
static LOC_ID: OnceLock<TypeId> = OnceLock::new();
/// Cache of symbol names for vtable members.
static SYMBOL_CACHE: OnceLock<Mutex<HashMap<u64, &'static str>>> = OnceLock::new();

#[derive(clap::Parser)]
struct Args {
    /// The core dump to open.
    core: PathBuf,

    /// The CTF file to read.
    #[clap(long, short)]
    ctf: PathBuf,
}

fn main() {
    let args = Args::parse();
    let mut stdout = io::stdout().lock();

    if let Err(e) = exec(args, &mut stdout) {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "{e:#}");
        std::process::exit(1);
    }
}

fn exec(args: Args, _out: &mut dyn io::Write) -> Result<()> {
    let core = Core::open(&args.core)
        .with_context(|| format!("failed to open {} as a core", args.core.display()))?;
    let status = core.status();
    let brk_range = status.brk_range;

    let ctf_bytes =
        fs::read(&args.ctf).with_context(|| format!("failed to read {}", args.ctf.display()))?;
    let ctf = CtfReader::load(&ctf_bytes)?;

    let ctx_ty = ctf
        .find_ty("tokio::runtime::context::Context", TypeKind::Struct)
        .unwrap();

    let lwps = core.lwps()?;

    let backtraces = unwind::load_frames(&core)?;
    let mut workers = BTreeMap::new();

    let mut scheduler = None;
    for lwp in &lwps {
        if let Some(addr) = find_context(lwp.tid, &brk_range, &core)? {
            //eprintln!("Context for TID {}: {addr:#x}", lwp.tid);
            let info = TypeInfo::from_addr(ctx_ty, addr, &ctf, &core)?.unwrap();
            let ctx: ThreadCtx = info.parse()?;
            workers.insert(lwp.tid, ctx);

            if scheduler.is_none() {
                let sched = info
                    .member("current")?
                    .member("handle")?
                    .member("value")?
                    .select_variant("Some")?
                    .select_variant("MultiThread")?
                    .deref_ptr()?
                    .member("data")?
                    .parse::<Scheduler>()?;
                scheduler = Some(sched);
            }
        }
    }
    let scheduler = scheduler.unwrap();

    for active in &scheduler.shared.active_workers {
        let (tid, ctx) = workers
            .iter()
            .find(|(_tid, ctx)| {
                let Some(id) = ctx.worker_index else {
                    return false;
                };
                id == *active
            })
            .unwrap();
        eprintln!("{ctx:#?}");
        for frame in &backtraces[tid] {
            let mangled = frame
                .symbol
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or_default();
            let demangled = format!("{:#}", rustc_demangle::demangle(mangled));
            eprintln!("{:#018x} {demangled}", frame.regs.rip);
        }
        eprintln!("");
    }
    eprintln!("{:#?}", scheduler);

    Ok(())
}

fn lookup_symbol(addr: u64, core: &Core) -> &'static str {
    let cache = SYMBOL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    *cache.lock().unwrap().entry(addr).or_insert_with(|| {
        let sym = core.lookup_symbol(addr).unwrap();
        let s = format!("{:#}", rustc_demangle::demangle(&sym.name));
        // Leak the String so we can treat it as a &'static str.
        Box::leak(s.into_boxed_str())
    })
}

/// Find the address of the thread-local `tokio::runtime::context::Context` for
/// this LWP, if present. The first three u64s of this type form a
/// recognizeable pattern unlikely to be replicated by other types.
fn find_context(tid: u32, brk_range: &Range<u64>, core: &Core) -> Result<Option<u64>> {
    // So far I've always observed the Context at `tls[4]`, but there's no
    // reason to assume this will remain the case. Check all of the slots to be
    // safe.
    let tls = core.lwp_tsd(tid)?;
    for addr in tls {
        // The `tokio::runtime::context::Context` is heap allocated.
        if !brk_range.contains(&addr) {
            continue;
        }
        const CONTEXT_SIZE: u64 = 3 * size_of::<u64>() as u64;
        let mut buf = [0u8; CONTEXT_SIZE as usize];

        // The value may be unmapped.
        if core.pread_exact(&mut buf, addr).is_err() {
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

#[derive(Clone, PartialEq, Debug)]
struct ThreadCtx {
    current_task_id: Option<u64>,
    thread_id: Option<u64>,
    worker_index: Option<u64>,
    worker_core: Option<WorkerCore>,
    defer: Vec<Waker>,
    runtime: EnterRuntime,
    budget: Budget,
}

impl ParseWithCtf for ThreadCtx {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let current_task_id = info.member("current_task_id")?.parse()?;
        let thread_id = info.member("thread_id")?.parse()?;
        let runtime = info.member("runtime")?.parse()?;
        let budget = info.member("budget")?.parse()?;

        let Some(sched_ptr) = info.member("scheduler")?.try_deref_ptr()? else {
            return Ok(Self {
                current_task_id,
                thread_id,
                runtime,
                budget,
                defer: Vec::new(),
                worker_index: None,
                worker_core: None,
            });
        };

        let sched_info = sched_ptr.select_variant("MultiThread")?.to_owned();

        let worker_index = match sched_info.member("worker")?.try_deref_ptr()? {
            Some(worker) => {
                let idx = worker.member("data")?.member("index")?.parse()?;
                Some(idx)
            }
            None => None,
        };

        let worker_core = match sched_info
            .member("core")?
            .member("value")?
            .try_select_variant("Some")?
        {
            Some(i) => {
                let core = i.deref_ptr()?.parse()?;
                Some(core)
            }
            None => None,
        };

        let defer = sched_info.member("defer")?.member("value")?.parse()?;

        Ok(Self {
            current_task_id,
            thread_id,
            worker_index,
            worker_core,
            runtime,
            defer,
            budget,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum EnterRuntime {
    Entered { allow_block_in_place: bool },
    NotEntered,
}

impl ParseWithCtf for EnterRuntime {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        match info.active_variant()? {
            ("Entered", var_info) => {
                let allow_block_in_place = var_info.parse()?;
                Ok(Self::Entered {
                    allow_block_in_place,
                })
            }
            ("NotEntered", _) => Ok(Self::NotEntered),
            (other, _) => Err(durin::Error::invalid_enum_value(other.to_string())),
        }
    }
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

impl ParseWithCtf for Budget {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse()?;
        Ok(Self(inner))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Scheduler {
    shared: Shared,
    driver: DriverHandle,
}

impl ParseWithCtf for Scheduler {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let shared = info.member("shared")?.parse()?;
        let driver = info.member("driver")?.parse()?;

        Ok(Self { shared, driver })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct WorkerCore {
    tick: u32,
    global_queue_interval: u32,
    lifo_enabled: bool,
    lifo_slot: Option<TaskHeader>,
    run_queue: TaskQueue,
    is_searching: bool,
    is_shutdown: bool,
    is_traced: bool,
    park: Option<Parker>,
    stats: WorkerStats,
}
impl ParseWithCtf for WorkerCore {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let global_queue_interval = info.member("global_queue_interval")?.parse()?;
        let tick = info.member("tick")?.parse()?;
        let lifo_enabled = info.member("lifo_enabled")?.parse()?;
        let lifo_slot = info
            .member("lifo_slot")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr().and_then(|i| i.parse()))
            .transpose()?;
        let is_searching = info.member("is_searching")?.parse()?;
        let is_shutdown = info.member("is_shutdown")?.parse()?;
        let is_traced = info.member("is_traced")?.parse()?;
        let park = info.member("park")?.parse()?;
        let stats = info.member("stats")?.parse()?;

        let run_queue = info
            .member("run_queue")?
            .deref_ptr()?
            .member("data")?
            .parse()?;

        Ok(WorkerCore {
            global_queue_interval,
            tick,
            lifo_enabled,
            lifo_slot,
            run_queue,
            is_searching,
            is_shutdown,
            is_traced,
            park,
            stats,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct Parker {
    state: u64,
}

impl Parker {
    const EMPTY: u64 = 0;
    const PARKED_CONDVAR: u64 = 1;
    const PARKED_DRIVER: u64 = 2;
    const NOTIFIED: u64 = 3;

    pub fn is_unparked(&self) -> bool {
        self.state == Self::EMPTY
    }

    pub fn is_parked_waiting(&self) -> bool {
        self.state == Self::PARKED_CONDVAR
    }

    pub fn is_parked_driving_io(&self) -> bool {
        self.state == Self::PARKED_DRIVER
    }

    pub fn is_notified(&self) -> bool {
        self.state == Self::NOTIFIED
    }
}

impl ParseWithCtf for Parker {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let state = info.deref_ptr()?.member("data")?.member("state")?.parse()?;

        Ok(Self { state })
    }
}

impl fmt::Debug for Parker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state_desc = match self.state {
            Self::EMPTY => format_args!("running ({})", self.state),
            Self::PARKED_CONDVAR => format_args!("parked_condvar ({})", self.state),
            Self::PARKED_DRIVER => format_args!("parked_io_driver ({})", self.state),
            Self::NOTIFIED => format_args!("notify_wake ({})", self.state),
            _ => format_args!("unknown ({})", self.state),
        };

        f.debug_struct("Parker")
            .field("state", &state_desc)
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
struct WorkerStats {
    /// The metrics batch used to report runtime-level metrics/stats to the
    /// user.
    batch: MetricsBatch,
    /// Number of tasks polled in the batch of scheduled tasks
    tasks_polled_in_batch: u64,
    /// Exponentially-weighted moving average of time spent polling scheduled a
    /// task.
    ///
    /// Tracked in nanoseconds, stored as a `f64` since that is what we use with
    /// the EWMA calculations
    task_poll_time_ewma: f64,
}

impl ParseWithCtf for WorkerStats {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let batch = info.member("batch")?.parse()?;
        let tasks_polled_in_batch = info.member("tasks_polled_in_batch")?.parse()?;
        let task_poll_time_ewma = info.member("task_poll_time_ewma")?.parse()?;

        Ok(Self {
            batch,
            tasks_polled_in_batch,
            task_poll_time_ewma,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
struct MetricsBatch {
    /// The total busy duration in nanoseconds.
    busy_duration_total: u64,
    // Instant at which work last resumed (continued after park).
    processing_scheduled_tasks_started_at: Option<Duration>, // TODO is duration useful here?
    /// Number of times the worker parked.
    park_count: u64,
    /// Number of times the worker parked and unparked.
    park_unpark_count: u64,
    /// Number of times the worker woke w/o doing work.
    noop_count: u64,
    /// Number of tasks stolen.
    steal_count: u64,
    /// Number of times tasks where stolen.
    steal_operations: u64,
    /// Number of tasks that were polled by the worker.
    poll_count: u64,
    /// Number of tasks polled when the worker entered park. This is used to
    /// track the noop count.
    poll_count_on_last_park: u64,
    /// Number of tasks that were scheduled locally on this worker.
    local_schedule_count: u64,
    /// Number of tasks moved to the global queue to make space in the local
    /// queue
    overflow_count: u64,
}

impl ParseWithCtf for MetricsBatch {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let busy_duration_total = info.member("busy_duration_total")?.parse()?;
        let processing_scheduled_tasks_started_at = info
            .member("processing_scheduled_tasks_started_at")?
            .parse::<Option<RawInstant>>()?
            .map(|raw_time| Duration::new(raw_time.tv_sec, raw_time.tv_nsec));
        let park_count = info.member("park_count")?.parse()?;
        let park_unpark_count = info.member("park_unpark_count")?.parse()?;
        let noop_count = info.member("noop_count")?.parse()?;
        let steal_count = info.member("steal_count")?.parse()?;
        let steal_operations = info.member("steal_operations")?.parse()?;
        let poll_count = info.member("poll_count")?.parse()?;
        let poll_count_on_last_park = info.member("poll_count_on_last_park")?.parse()?;
        let local_schedule_count = info.member("local_schedule_count")?.parse()?;
        let overflow_count = info.member("overflow_count")?.parse()?;

        Ok(Self {
            busy_duration_total,
            park_count,
            park_unpark_count,
            noop_count,
            steal_count,
            steal_operations,
            poll_count,
            poll_count_on_last_park,
            local_schedule_count,
            overflow_count,
            processing_scheduled_tasks_started_at,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Shared {
    // /// Per-worker remote state. All other workers have access to this and is
    // /// how they communicate between each other.
    remotes: Box<[Remote]>,
    /// Tokio uses this to access the global task queue used for.
    /// For our purposes we just use to to easily see the number of pending jobs.
    pub inject_len: u64,

    /// Coordinates idle workers
    idle: Idle,

    /// Not a real field, the inverse of `Idle.idle_sleepers`
    active_workers: BTreeSet<u64>,

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
    config: Config,
    // /// Collects metrics from the runtime.
    scheduler_metrics: SchedulerMetrics,
    worker_metrics: Box<[WorkerMetrics]>,
    // /// Only held to trigger some code on drop. This is used to get internal
    // /// runtime metrics that can be useful when doing performance
    // /// investigations. This does nothing (empty struct, no drop impl) unless
    // /// the `tokio_internal_mt_counters` `cfg` flag is set.
    // _counters: Counters,
}

impl ParseWithCtf for Shared {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let remotes = info.member("remotes")?.parse()?;
        let config = info.member("config")?.parse()?;
        let inject_len = info.member("inject")?.parse()?;
        let idle: Idle = info.member("idle")?.parse()?;
        let owned = info.member("owned")?.parse()?;
        let scheduler_metrics = info.member("scheduler_metrics")?.parse()?;
        let worker_metrics = info.member("worker_metrics")?.parse()?;

        let synced: Synced = info.member("synced")?.member("data")?.parse()?;
        let mut active_workers = BTreeSet::new();
        for i in 0u64..idle.num_workers {
            if !synced.idle_sleepers.contains(&i) {
                active_workers.insert(i);
            }
        }

        Ok(Self {
            remotes,
            inject_len,
            idle,
            active_workers,
            owned,
            synced,
            config,
            scheduler_metrics,
            worker_metrics,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Remote {
    steal: TaskQueue,
    unpark: Parker,
}

impl ParseWithCtf for Remote {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let steal = info.member("steal")?.deref_ptr()?.member("data")?.parse()?;
        let unpark = info.member("unpark")?.parse()?;

        Ok(Self { steal, unpark })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Idle {
    num_searching: u64,
    num_unparked: u64,
    num_workers: u64,
}

impl ParseWithCtf for Idle {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        const UNPARK_SHIFT: u64 = 16;
        const UNPARK_MASK: u64 = !SEARCH_MASK;
        const SEARCH_MASK: u64 = (1 << UNPARK_SHIFT) - 1;

        let num_workers = info.member("num_workers")?.parse()?;
        let state: u64 = info.member("state")?.parse()?;
        let num_searching = state & SEARCH_MASK;
        let num_unparked = (state & UNPARK_MASK) >> UNPARK_SHIFT;

        Ok(Self {
            num_workers,
            num_searching,
            num_unparked,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct OwnedTasks {
    list: Vec<Vec<TaskHeader>>,
    added: u64,
    count: u64,
    closed: bool,
    shard_mask: u64,
}

impl ParseWithCtf for OwnedTasks {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let closed = info.member("closed")?.parse()?;

        let list_info = info.member("list")?;
        let added = list_info.member("added")?.parse()?;
        let count = list_info.member("count")?.parse()?;
        let shard_mask = list_info.member("shard_mask")?.parse()?;

        let list = list_info.member("lists")?.boxed_slice_elements(|i| {
            let mut tasks = Vec::new();
            if let Some(mut head_info) = i
                .member("data")?
                .member("head")?
                .try_select_variant("Some")?
                .map(|i| i.deref_ptr())
                .transpose()?
            {
                loop {
                    let task = head_info.parse()?;
                    tasks.push(task);

                    let Some(next) = head_info
                        .member("queue_next")?
                        .try_select_variant("Some")?
                        .map(|i| i.deref_ptr())
                        .transpose()?
                    else {
                        break;
                    };
                    head_info = next.to_owned();
                }
            }

            Ok(tasks)
        })?;

        Ok(OwnedTasks {
            list,
            added,
            count,
            closed,
            shard_mask,
        })
    }
}

impl fmt::Debug for OwnedTasks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedTasks")
            .field("list", &self.list)
            .field("added", &self.added)
            .field("count", &self.count)
            .field("shard_mask", &format_args!("{:#b}", self.shard_mask))
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Synced {
    idle_sleepers: BTreeSet<u64>,
    inject_closed: bool,
    inject_head: Option<TaskHeader>,
    inject_tail: Option<TaskHeader>,
}

impl ParseWithCtf for Synced {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let idle_sleepers = info
            .member("idle")?
            .parse::<Vec<u64>>()?
            .into_iter()
            .collect();

        let inject_info = info.member("inject")?;
        let inject_closed = inject_info.member("is_closed")?.parse()?;

        let inject_head = inject_info
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr().and_then(|i| i.parse()))
            .transpose()?;

        let inject_tail = inject_info
            .member("tail")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr().and_then(|i| i.parse()))
            .transpose()?;

        Ok(Synced {
            idle_sleepers,
            inject_closed,
            inject_head,
            inject_tail,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Inject {
    len: u64,
}

impl ParseWithCtf for Inject {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let len = info.member("len")?.parse()?;
        Ok(Inject { len })
    }
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

impl ParseWithCtf for Config {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let global_queue_interval = info.member("global_queue_interval")?.parse()?;
        let event_interval = info.member("event_interval")?.parse()?;
        let disable_lifo_slot = info.member("disable_lifo_slot")?.parse()?;

        Ok(Self {
            global_queue_interval,
            event_interval,
            disable_lifo_slot,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SchedulerMetrics {
    remote_schedule_count: u64,
    budget_forced_yield_count: u64,
}

impl ParseWithCtf for SchedulerMetrics {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let remote_schedule_count = info.member("remote_schedule_count")?.parse()?;
        let budget_forced_yield_count = info.member("budget_forced_yield_count")?.parse()?;

        Ok(Self {
            remote_schedule_count,
            budget_forced_yield_count,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct WorkerMetrics {
    busy_duration_total: u64,
    queue_depth: u64,
    thread_id: Option<u64>,
    park_count: u64,
    park_unpark_count: u64,
    noop_count: u64,
    steal_count: u64,
    steal_operations: u64,
    poll_count: u64,
    mean_poll_time: u64,
    local_schedule_count: u64,
    overflow_count: u64,
}

impl ParseWithCtf for WorkerMetrics {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let busy_duration_total = info.member("busy_duration_total")?.parse()?;
        let queue_depth = info.member("queue_depth")?.parse()?;
        let thread_id = info.member("thread_id")?.member("data")?.parse()?;
        let park_count = info.member("park_count")?.parse()?;
        let park_unpark_count = info.member("park_unpark_count")?.parse()?;
        let noop_count = info.member("noop_count")?.parse()?;
        let steal_count = info.member("steal_count")?.parse()?;
        let steal_operations = info.member("steal_operations")?.parse()?;
        let poll_count = info.member("poll_count")?.parse()?;
        let mean_poll_time = info.member("mean_poll_time")?.parse()?;
        let local_schedule_count = info.member("local_schedule_count")?.parse()?;
        let overflow_count = info.member("overflow_count")?.parse()?;

        Ok(Self {
            busy_duration_total,
            queue_depth,
            thread_id,
            park_count,
            park_unpark_count,
            noop_count,
            steal_count,
            steal_operations,
            poll_count,
            mean_poll_time,
            local_schedule_count,
            overflow_count,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct TaskQueue {
    head: u64,
    tail: u32,
    tasks: Vec<TaskHeader>,
}

impl ParseWithCtf for TaskQueue {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let head: u64 = info.member("head")?.parse()?;
        let tail: u32 = info.member("tail")?.parse()?;

        let buf_info = info.member("buffer")?.deref_ptr()?;

        let real_head = (head & u32::MAX as u64) as u32;
        let len = tail.wrapping_sub(real_head) as usize;

        let mut tasks = Vec::with_capacity(len);

        for elem_info in buf_info.as_ref().array_elements()?.take(len) {
            let task = elem_info.member("value")?.deref_ptr()?.parse()?;
            tasks.push(task);
        }

        Ok(TaskQueue { head, tail, tasks })
    }
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
    state: u64,
    runtime_id: Option<u64>,
    id: u64,
    spawn_location: Location,
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

impl ParseWithCtf for TaskHeader {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let state = info.member("state")?.parse()?;
        let runtime_id = info.member("owner_id")?.parse()?;

        let vtable_info = info.member("vtable")?.deref_ptr()?;

        let id_offset: u64 = vtable_info.member("id_offset")?.parse()?;
        let id_addr = info.addr + id_offset;
        let id_bytes = info
            .core
            .read_bytes(id_addr, size_of::<u64>() as u64)?
            .unwrap();
        let id = u64::from_le_bytes(id_bytes.try_into().unwrap());

        // This is the offset from the Header address to the address of
        // `spawn_location`.
        let spawn_offset: u64 = vtable_info.member("spawn_location_offset")?.parse()?;
        let spawn_ptr_addr = info.addr + spawn_offset;
        let spawn_ptr = info
            .core
            .read_u64(spawn_ptr_addr)
            .map_err(|e| Error::null_ptr(Some(e.into())))?;

        // The CTF isn't aware we have a *Location here, so manually find the type and parse.
        let spawn_id = LOC_ID.get_or_init(|| {
            info.ctf
                .find_ty("core::panic::location::Location", TypeKind::Struct)
                .unwrap()
                .id()
        });
        let spawn_ty = info.ctf.ty(*spawn_id);
        let spawn_buf = info.core.read_type(spawn_ptr, spawn_ty, info.ctf)?.unwrap();
        let spawn_info = info.clone().with_ty(spawn_ty).with_buf(&spawn_buf);
        let spawn_location = spawn_info.parse()?;

        Ok(TaskHeader {
            state,
            runtime_id,
            id,
            spawn_location,
        })
    }
}

impl fmt::Debug for TaskHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TaskHeader")
            .field("runtime_id", &self.runtime_id)
            .field("spawn_location", &self.spawn_location)
            .field("id", &self.id)
            .field("ref_count", &self.ref_count())
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

#[derive(Clone, PartialEq, Debug)]
pub struct Location {
    filename: String,
    line: u32,
    col: u32,
}

impl ParseWithCtf for Location {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let filename = info.member("filename")?.parse()?;
        let line = info.member("line")?.parse()?;
        let col = info.member("col")?.parse()?;

        Ok(Self {
            filename,
            line,
            col,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct DriverHandle {
    io: IoHandle,
    time: Option<TimeHandle>,
}

impl ParseWithCtf for DriverHandle {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let io = info.member("io")?.parse()?;
        let time = info
            .member("time")?
            .try_select_variant("Some")?
            .map(|i| i.parse())
            .transpose()?;

        Ok(Self { io, time })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum IoHandle {
    Enabled(IoEnabled),
    Disabled(IoDisabled),
}

impl ParseWithCtf for IoHandle {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        match info.active_variant()? {
            ("Enabled", info) => {
                let inner = info.parse()?;
                Ok(IoHandle::Enabled(inner))
            }
            ("Disabled", info) => {
                let inner = info.parse()?;
                Ok(IoHandle::Disabled(inner))
            }
            (other, info) => Err(Error::no_enumerator(info.ty.id(), other.to_string())),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoEnabled {
    num_pending_release: u64,
    waker_fd: i32,
    poll_fd: i32,
    metrics: IoDriverMetrics,
    synced: IoSynced,
}

impl ParseWithCtf for IoEnabled {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let num_pending_release = info.member("registrations")?.parse()?;
        let metrics = info.member("metrics")?.parse()?;
        let waker_fd = info.member("waker")?.parse()?;
        let synced = info.member("synced")?.member("data")?.parse()?;
        let poll_fd = info.member("registry")?.parse()?;

        Ok(Self {
            num_pending_release,
            waker_fd,
            poll_fd,
            metrics,
            synced,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDisabled {
    park: u32,
}

impl ParseWithCtf for IoDisabled {
    fn parse_with_ctf(_info: &TypeInfoRef) -> durin::Result<Self> {
        todo!();
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoSynced {
    registrations: Vec<ScheduledIo>,
    is_shutdown: bool,
}

impl ParseWithCtf for IoSynced {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let is_shutdown = info.member("is_shutdown")?.parse()?;
        let mut registrations = Vec::new();
        if let Some(mut head_info) = info
            .member("registrations")?
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr())
            .transpose()?
        {
            loop {
                let sched = head_info.parse()?;
                registrations.push(sched);

                let Some(next) = head_info
                    .member("linked_list_pointers")?
                    .member("next")?
                    .try_select_variant("Some")?
                    .map(|i| i.deref_ptr())
                    .transpose()?
                else {
                    break;
                };
                head_info = next;
            }
        }

        Ok(Self {
            registrations,
            is_shutdown,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct ScheduledIo {
    //head: Option<Box<Self>>,
    readiness: Ready,
    waiters: Waiters,
}

impl ParseWithCtf for ScheduledIo {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let readiness = info.member("readiness")?.parse()?;
        let waiters = info.member("waiters")?.member("data")?.parse()?;

        Ok(Self { readiness, waiters })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ready(pub u64);

impl ParseWithCtf for Ready {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse()?;
        Ok(Self(inner))
    }
}

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
    list: Vec<Waiter>,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

impl ParseWithCtf for Waiters {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let mut list = Vec::new();
        if let Some(mut head_info) = info
            .member("list")?
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr())
            .transpose()?
        {
            loop {
                let waiter = head_info.parse()?;
                list.push(waiter);

                let Some(next) = head_info
                    .member("pointers")?
                    .member("next")?
                    .try_select_variant("Some")?
                    .map(|i| i.deref_ptr())
                    .transpose()?
                else {
                    break;
                };
                head_info = next;
            }
        }
        let reader = info
            .member("reader")?
            .try_select_variant("Some")?
            .map(|i| i.parse())
            .transpose()?;

        let writer = info
            .member("writer")?
            .try_select_variant("Some")?
            .map(|i| i.parse())
            .transpose()?;

        Ok(Self {
            list,
            reader,
            writer,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Waiter {
    interest: Interest,
    is_ready: bool,
    waker: Option<Waker>,
}

impl ParseWithCtf for Waiter {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let interest = info.member("interest")?.parse()?;
        let is_ready = info.member("is_ready")?.parse()?;

        let waker = info
            .member("waker")?
            .try_select_variant("Some")?
            .map(|info| info.parse())
            .transpose()?;

        Ok(Self {
            interest,
            is_ready,
            waker,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Interest(pub u64);

impl ParseWithCtf for Interest {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse()?;
        Ok(Self(inner))
    }
}

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
    dependent_task: Option<TaskHeader>,
    data: u64,
    wake: &'static str,
    wake_by_ref: &'static str,
    clone: &'static str,
    drop: &'static str,
}

impl ParseWithCtf for Waker {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let data = info.member("data")?.parse()?;
        let vtable_info = info.member("vtable")?.deref_ptr()?;

        let wake_addr = vtable_info.member("wake")?.parse()?;
        let wake_by_ref_addr = vtable_info.member("wake_by_ref")?.parse()?;
        let clone_addr = vtable_info.member("clone")?.parse()?;
        let drop_addr = vtable_info.member("drop")?.parse()?;

        let wake = lookup_symbol(wake_addr, info.core);
        let wake_by_ref = lookup_symbol(wake_by_ref_addr, info.core);
        let clone = lookup_symbol(clone_addr, info.core);
        let drop = lookup_symbol(drop_addr, info.core);

        let dependent_task;
        if wake == "tokio::runtime::task::waker::wake_by_val" {
            let hdr_id = HDR_ID.get_or_init(|| {
                info.ctf
                    .find_ty(
                        "*const_tokio::runtime::task::core::Header",
                        TypeKind::Pointer,
                    )
                    .unwrap()
                    .id()
            });
            let hdr_info = info.member("data")?.with_ty(info.ctf.ty(*hdr_id));
            let hdr = hdr_info.deref_ptr()?.parse::<TaskHeader>()?;
            dependent_task = Some(hdr);
        } else {
            dependent_task = None;
        }

        Ok(Self {
            dependent_task,
            data,
            wake,
            wake_by_ref,
            clone,
            drop,
        })
    }
}

impl fmt::Debug for Waker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waker")
            .field("header", &self.dependent_task)
            .field("data", &format_args!("{:#x}", self.data))
            .field("wake", &self.wake)
            .field("wake_by_ref", &self.wake_by_ref)
            .field("clone", &self.clone)
            .field("drop", &self.drop)
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDriverMetrics {
    fd_registered_count: u64,
    fd_deregistered_count: u64,
    ready_count: u64,
}

impl ParseWithCtf for IoDriverMetrics {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let fd_registered_count = info.member("fd_registered_count")?.parse()?;
        let fd_deregistered_count = info.member("fd_deregistered_count")?.parse()?;
        let ready_count = info.member("ready_count")?.parse()?;

        Ok(Self {
            fd_registered_count,
            fd_deregistered_count,
            ready_count,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimeHandle {
    is_shutdown: bool,
    did_wake: bool,
    time_source: Duration,
    wheel: Wheel,
    next_wake: Option<u64>,
}

impl ParseWithCtf for TimeHandle {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let raw_time: RawInstant = info.member("time_source")?.parse()?;
        let time_source = Duration::new(raw_time.tv_sec, raw_time.tv_nsec);

        let inner = info.member("inner")?;
        let is_shutdown = inner.member("is_shutdown")?.parse()?;
        let did_wake = inner.member("did_wake")?.parse()?;

        let state_info = inner.member("state")?.member("data")?;

        let wheel = state_info.member("wheel")?.parse()?;
        let next_wake = state_info.member("next_wake")?.parse()?;

        Ok(Self {
            is_shutdown,
            did_wake,
            time_source,
            wheel,
            next_wake,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
struct RawInstant {
    tv_sec: u64,
    tv_nsec: u32,
}

impl ParseWithCtf for RawInstant {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let tv_sec = info.member("tv_sec")?.parse()?;
        let tv_nsec = info.member("tv_nsec")?.parse()?;

        Ok(Self { tv_sec, tv_nsec })
    }
}

#[derive(Clone, PartialEq)]
pub struct Wheel {
    elapsed: u64,
    levels: Vec<Level>,
    pending: Vec<TimerShared>,
}

impl ParseWithCtf for Wheel {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let elapsed = info.member("elapsed")?.parse()?;

        let levels_info = info.member("levels")?.deref_ptr()?;
        let mut levels = Vec::with_capacity(6);

        for elem_info in levels_info.array_elements()? {
            let level = elem_info.parse()?;
            levels.push(level);
        }

        let mut pending = Vec::new();
        if let Some(mut head_info) = info
            .member("pending")?
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr())
            .transpose()?
        {
            loop {
                let timer = head_info.parse()?;
                pending.push(timer);

                let Some(next) = head_info
                    .member("pointers")?
                    .member("next")?
                    .try_select_variant("Some")?
                    .map(|i| i.deref_ptr())
                    .transpose()?
                else {
                    break;
                };
                head_info = next;
            }
        }

        Ok(Self {
            elapsed,
            levels,
            pending,
        })
    }
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
    level: u64,
    occupied: u64,
    slot: Vec<TimerSlot>,
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

impl ParseWithCtf for Level {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let level = info.member("level")?.parse()?;
        let occupied = info.member("occupied")?.parse()?;

        let slot_info = info.member("slot")?;

        let mut slot = Vec::new();
        for (i, elem_info) in slot_info.array_elements()?.enumerate() {
            let mut slot_timers = TimerSlot {
                slot_id: i,
                timers: Vec::new(),
            };

            // `occupied` acts as a bitmap for which slots contain items.
            if occupied & 1 << i == 0 {
                continue;
            }

            if let Some(mut head_info) = elem_info
                .member("head")?
                .try_select_variant("Some")?
                .map(|i| i.deref_ptr())
                .transpose()?
            {
                loop {
                    let timer = head_info.parse()?;
                    slot_timers.timers.push(timer);

                    let Some(next) = head_info
                        .member("pointers")?
                        .member("next")?
                        .try_select_variant("Some")?
                        .map(|i| i.deref_ptr())
                        .transpose()?
                    else {
                        break;
                    };
                    head_info = next;
                }
            }
            slot.push(slot_timers);
        }

        Ok(Self {
            level,
            occupied,
            slot,
        })
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
    level: u64,

    /// The slot index.
    slot: u64,

    /// The instant at which the slot needs to be processed.
    deadline: u64,
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimerSlot {
    slot_id: usize,
    timers: Vec<TimerShared>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimerShared {
    registered_when: u64,
    time_state: TimerState,
    result: String,
    waker_state: WakerState,
    waker: Option<Waker>,
}

impl ParseWithCtf for TimerShared {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let registered_when = info.member("registered_when")?.parse()?;
        let state_info = info.member("state")?;
        let state = state_info.member("state")?.parse()?;
        let result = state_info.member("result")?.active_variant()?.0.to_string();

        let waker_info = state_info.member("waker")?;
        let waker_state = waker_info.member("state")?.parse()?;
        let waker = waker_info
            .member("waker")?
            .try_select_variant("Some")?
            .map(|i| i.parse())
            .transpose()?;

        Ok(Self {
            registered_when,
            time_state: state,
            result,
            waker_state,
            waker,
        })
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
}

impl ParseWithCtf for TimerState {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse()?;

        Ok(Self(inner))
    }
}

impl fmt::Debug for TimerState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("TimerState")
            .field("is_deregistered", &self.is_deregistered())
            .field("is_pending_fire", &self.is_pending_fire())
            .field("inner", &format_args!("{:#x}", self.0))
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
        self.0 & Self::WAITING != 0
    }

    pub fn is_registering(&self) -> bool {
        self.0 & Self::REGISTERING != 0
    }

    pub fn is_waking(&self) -> bool {
        self.0 & Self::WAKING != 0
    }
}

impl ParseWithCtf for WakerState {
    fn parse_with_ctf(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse()?;

        Ok(Self(inner))
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

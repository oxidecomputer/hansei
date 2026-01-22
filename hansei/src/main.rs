use anyhow::{Context as _, Result};
use clap::Parser;
use durin::read::{
    BytesFromCore, CtfArray, CtfReader, CtfType, Discriminant, ReadCtfType, SelectAction, Selector,
    TypeInfo, TypeInfoRef, TypePath,
};
use proc::Core;

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::mem;
use std::ops::Range;
use std::path::PathBuf;

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

    let core_reader = CoreReader {
        core: &core,
        ctf: &ctf,
    };

    let mut type_map = HashMap::new();
    for ty in ctf.types() {
        let type_name = ty.name(&ctf);
        type_map.insert(type_name, ty);
    }

    let ctx_ty = type_map.get("tokio::runtime::context::Context").unwrap();
    let lwps = core.lwps()?;
    let mut scheduler = None;
    for lwp in &lwps {
        if let Some(addr) = find_context(lwp.tid, &brk_range, &core)? {
            eprintln!("Context for TID {}: {addr:#x}", lwp.tid);
            let info = TypeInfo::from_addr(ctx_ty, addr, &ctf, &core_reader)?.unwrap();
            let ctx = ThreadCtx::from_ctf_info(&info.as_ref())?;
            if scheduler.is_none() {
                let sched_info = info
                    .as_ref()
                    .follow_path(&[
                        TypePath {
                            name: "Context",
                            selector: Selector::Struct { member: "current" },
                        },
                        TypePath {
                            name: "HandleCell",
                            selector: Selector::Struct { member: "handle" },
                        },
                        TypePath {
                            name: "RefCell<Handle>",
                            selector: Selector::Struct { member: "value" },
                        },
                        TypePath {
                            name: "Option<Handle>",
                            selector: Selector::Enum { variant: "Some" },
                        },
                        TypePath {
                            name: "Handle",
                            selector: Selector::Enum {
                                variant: "MultiThread",
                            },
                        },
                        TypePath {
                            name: "Handle::MultiThread",
                            selector: Selector::Struct { member: "__0" },
                        },
                        TypePath {
                            name: "*ArcInner<multi_thread::Handle>",
                            selector: Selector::Pointer,
                        },
                        TypePath {
                            name: "ArcInner<multi_thread::Handle>",
                            selector: Selector::Struct { member: "data" },
                        },
                    ])?
                    .unwrap();
                scheduler = Some(Scheduler::from_ctf_info(&sched_info.as_ref())?);
            }
            eprintln!("{ctx:#?}");
        }
    }
    eprintln!("{:#?}", scheduler.unwrap());

    Ok(())
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

struct CoreReader<'a> {
    core: &'a Core,
    ctf: &'a CtfReader,
}

impl<'a> BytesFromCore for CoreReader<'a> {
    fn read_type(&self, ty: &CtfType, addr: u64) -> durin::Result<Option<Vec<u8>>> {
        let mappings = self.core.mappings().map_err(|e| durin::Error::ReadError {
            ty: ty.id(),
            source: e.into(),
        })?;
        if !mappings
            .as_slice()
            .iter()
            .any(|m| m.range().contains(&addr))
        {
            return Ok(None);
        }

        let mut buf = vec![0u8; ty.size(self.ctf) as usize];
        self.core
            .pread_exact(&mut buf, addr)
            .map_err(|e| durin::Error::ReadError {
                ty: ty.id(),
                source: e.into(),
            })?;
        Ok(Some(buf))
    }

    fn read_bytes(&self, addr: u64, len: u64) -> durin::Result<Option<Vec<u8>>> {
        let mappings = self.core.mappings().map_err(|e| durin::Error::ReadError {
            ty: durin::TypeId::try_from(1).unwrap(),
            source: e.into(),
        })?;
        if !mappings
            .as_slice()
            .iter()
            .any(|m| m.range().contains(&addr))
        {
            return Ok(None);
        }

        let mut buf = vec![0u8; len as usize];
        self.core
            .pread_exact(&mut buf, addr)
            .map_err(|e| durin::Error::ReadError {
                ty: durin::TypeId::try_from(1).unwrap(),
                source: e.into(),
            })?;
        Ok(Some(buf))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct ThreadCtx {
    current_task_id: Option<u64>,
    thread_id: Option<u64>,
    worker_index: Option<u64>,
    worker_core: Option<WorkerCore>,
    runtime: EnterRuntime,
    budget: Budget,
}
impl ReadCtfType for ThreadCtx {
    fn from_ctf_info(ctx_info: &TypeInfoRef) -> durin::Result<Self> {
        let current_task_id = ctx_info.parse_member("current_task_id")?;
        let thread_id = ctx_info.parse_member("thread_id")?;
        let runtime = ctx_info.parse_member("runtime")?;
        let budget = ctx_info.parse_member("budget")?;

        let worker_index = ctx_info
            .follow_path(&[
                TypePath {
                    name: "Context",
                    selector: Selector::Struct {
                        member: "scheduler",
                    },
                },
                TypePath {
                    name: "ContextPtr",
                    selector: Selector::Pointer,
                },
                TypePath {
                    name: "Context",
                    selector: Selector::Enum {
                        variant: "MultiThread",
                    },
                },
                TypePath {
                    name: "Context::MultiThread",
                    selector: Selector::Struct { member: "__0" },
                },
                TypePath {
                    name: "MultiThread",
                    selector: Selector::Struct { member: "worker" },
                },
                TypePath {
                    name: "WorkerPtr",
                    selector: Selector::Pointer,
                },
                TypePath {
                    name: "Arc<Worker>",
                    selector: Selector::Struct { member: "data" },
                },
                TypePath {
                    name: "Worker",
                    selector: Selector::Struct { member: "index" },
                },
            ])?
            .map(|i| u64::from_ctf_info(&i.as_ref()))
            .transpose()?;

        let worker_core = ctx_info
            .follow_path(&[
                TypePath {
                    name: "Context",
                    selector: Selector::Struct {
                        member: "scheduler",
                    },
                },
                TypePath {
                    name: "ContextPtr",
                    selector: Selector::Pointer,
                },
                TypePath {
                    name: "Context",
                    selector: Selector::Enum {
                        variant: "MultiThread",
                    },
                },
                TypePath {
                    name: "Context::MultiThread",
                    selector: Selector::Struct { member: "__0" },
                },
                TypePath {
                    name: "multi_thread::Context",
                    selector: Selector::Struct { member: "core" },
                },
                TypePath {
                    name: "RefCell<Option<*Core>>",
                    selector: Selector::Struct { member: "value" },
                },
                TypePath {
                    name: "Option<*Core>",
                    selector: Selector::Enum { variant: "Some" },
                },
                TypePath {
                    name: "*Worker",
                    selector: Selector::Pointer,
                },
            ])?
            .map(|i| WorkerCore::from_ctf_info(&i.as_ref()))
            .transpose()?;

        Ok(Self {
            current_task_id,
            thread_id,
            worker_index,
            worker_core,
            runtime,
            budget,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum EnterRuntime {
    Entered { allow_block_in_place: bool },
    NotEntered,
}

impl ReadCtfType for EnterRuntime {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        match info.active_variant()? {
            ("Entered", var_info) => {
                let allow_block_in_place = var_info.parse_member("allow_block_in_place")?;
                Ok(Self::Entered {
                    allow_block_in_place,
                })
            }
            ("NotEntered", _) => Ok(Self::NotEntered),
            (other, _) => Err(durin::Error::InvalidEnumValue(other.to_string())),
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

impl ReadCtfType for Budget {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse_ty()?;
        Ok(Self(inner))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Scheduler {
    shared: Shared,
    driver: DriverHandle,
}

impl ReadCtfType for Scheduler {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let shared = info.parse_member("shared")?;
        let driver = info.parse_member("driver")?;

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
    stats: WorkerStats,
}
impl ReadCtfType for WorkerCore {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let global_queue_interval = info.parse_member("global_queue_interval")?;
        let tick = info.parse_member("tick")?;
        let lifo_enabled = info.parse_member("lifo_enabled")?;
        let lifo_slot = info.parse_member("lifo_slot")?;
        let is_searching = info.parse_member("is_searching")?;
        let is_shutdown = info.parse_member("is_shutdown")?;
        let is_traced = info.parse_member("is_traced")?;
        let stats = info.parse_member("stats")?;

        let Some(run_queue_info) = info.follow_path(&[
            TypePath {
                name: "Core",
                selector: Selector::Struct {
                    member: "run_queue",
                },
            },
            TypePath {
                name: "*Arc<Queue>",
                selector: Selector::Pointer,
            },
            TypePath {
                name: "ArcInner<Queue>",
                selector: Selector::Struct { member: "data" },
            },
        ])?
        else {
            panic!();
        };
        let run_queue = run_queue_info.parse_ty()?;

        Ok(WorkerCore {
            global_queue_interval,
            tick,
            lifo_enabled,
            lifo_slot,
            run_queue,
            is_searching,
            is_shutdown,
            is_traced,
            stats,
        })
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

impl ReadCtfType for WorkerStats {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let batch = info.parse_member("batch")?;
        let tasks_polled_in_batch = info.parse_member("tasks_polled_in_batch")?;
        let task_poll_time_ewma = info.parse_member("task_poll_time_ewma")?;

        Ok(Self {
            batch,
            tasks_polled_in_batch,
            task_poll_time_ewma,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct MetricsBatch {
    /// The total busy duration in nanoseconds.
    busy_duration_total: u64,
    // Instant at which work last resumed (continued after park).
    //processing_scheduled_tasks_started_at: Option<Instant>,
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

impl ReadCtfType for MetricsBatch {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let busy_duration_total = info.parse_member("busy_duration_total")?;
        let park_count = info.parse_member("park_count")?;
        let park_unpark_count = info.parse_member("park_unpark_count")?;
        let noop_count = info.parse_member("noop_count")?;
        let steal_count = info.parse_member("steal_count")?;
        let steal_operations = info.parse_member("steal_operations")?;
        let poll_count = info.parse_member("poll_count")?;
        let poll_count_on_last_park = info.parse_member("poll_count_on_last_park")?;
        let local_schedule_count = info.parse_member("local_schedule_count")?;
        let overflow_count = info.parse_member("overflow_count")?;

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
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Shared {
    // /// Per-worker remote state. All other workers have access to this and is
    // /// how they communicate between each other.
    // remotes: Box<[Remote]>,
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
    // pub(super) scheduler_metrics: SchedulerMetrics,

    // pub(super) worker_metrics: Box<[WorkerMetrics]>,

    // /// Only held to trigger some code on drop. This is used to get internal
    // /// runtime metrics that can be useful when doing performance
    // /// investigations. This does nothing (empty struct, no drop impl) unless
    // /// the `tokio_internal_mt_counters` `cfg` flag is set.
    // _counters: Counters,
}

impl ReadCtfType for Shared {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let config = info.parse_member("config")?;
        let inject_len = info.parse_member("inject")?;
        let idle: Idle = info.parse_member("idle")?;
        let owned = info.parse_member("owned")?;
        let Some(synced_info) = info.follow_path(&[
            TypePath {
                name: "Shared",
                selector: Selector::Struct { member: "synced" },
            },
            TypePath {
                name: "Mutex<Synced>",
                selector: Selector::Struct { member: "__1" },
            },
            TypePath {
                name: "RawMutex<Synced>",
                selector: Selector::Struct { member: "data" },
            },
        ])?
        else {
            panic!();
        };
        let synced = Synced::from_ctf_info(&synced_info.as_ref())?;

        let mut active = BTreeSet::new();
        for i in 0u64..idle.num_workers {
            if !synced.idle_sleepers.contains(&i) {
                active.insert(i);
            }
        }

        Ok(Self {
            config,
            inject_len,
            idle,
            active_workers: active,
            owned,
            synced,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Idle {
    num_searching: u64,
    num_unparked: u64,
    num_workers: u64,
}

impl ReadCtfType for Idle {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        const UNPARK_SHIFT: u64 = 16;
        const UNPARK_MASK: u64 = !SEARCH_MASK;
        const SEARCH_MASK: u64 = (1 << UNPARK_SHIFT) - 1;

        let num_workers = info.parse_member("num_workers")?;
        let state: u64 = info.parse_member("state")?;
        let num_searching = state & SEARCH_MASK;
        let num_unparked = (state & UNPARK_MASK) >> UNPARK_SHIFT;

        Ok(Self {
            num_workers,
            num_searching,
            num_unparked,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct OwnedTasks {
    added: u64,
    count: u64,
    closed: bool,
}

impl ReadCtfType for OwnedTasks {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let closed = info.parse_member("closed")?;
        let Some(list_info) = info.follow_path(&[TypePath {
            name: "OwnedTasks",
            selector: Selector::Struct { member: "list" },
        }])?
        else {
            panic!();
        };
        let added = list_info.parse_member("added")?;
        let count = list_info.parse_member("count")?;
        Ok(OwnedTasks {
            added,
            count,
            closed,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Synced {
    idle_sleepers: BTreeSet<u64>,
    inject_closed: bool,
    inject_head: Option<TaskHeader>,
    inject_tail: Option<TaskHeader>,
}

impl ReadCtfType for Synced {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let Some(idle_info) = info.follow_path(&[TypePath {
            name: "Synced",
            selector: Selector::Struct { member: "idle" },
        }])?
        else {
            panic!();
        };
        let idle_sleepers_vec = Vec::<u64>::from_ctf_info(&idle_info.as_ref())?;
        let idle_sleepers = idle_sleepers_vec.into_iter().collect();
        let Some(inject_info) = info.follow_path(&[TypePath {
            name: "Synced",
            selector: Selector::Struct { member: "inject" },
        }])?
        else {
            panic!();
        };
        let inject_closed = inject_info.parse_member("is_closed")?;
        let inject_head = inject_info
            .as_ref()
            .follow_path(&[
                TypePath {
                    name: "Synced",
                    selector: Selector::Struct { member: "head" },
                },
                TypePath {
                    name: "Synced",
                    selector: Selector::Enum { variant: "Some" },
                },
            ])?
            .map(|i| TaskHeader::from_ctf_info(&i.as_ref()))
            .transpose()?;

        let inject_tail = inject_info
            .as_ref()
            .follow_path(&[
                TypePath {
                    name: "Synced",
                    selector: Selector::Struct { member: "tail" },
                },
                TypePath {
                    name: "Synced",
                    selector: Selector::Enum { variant: "Some" },
                },
            ])?
            .map(|i| TaskHeader::from_ctf_info(&i.as_ref()))
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

impl ReadCtfType for Inject {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let len = info.parse_member("len")?;
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

impl ReadCtfType for Config {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let global_queue_interval = info.parse_member("global_queue_interval")?;
        let event_interval = info.parse_member("event_interval")?;
        let disable_lifo_slot = info.parse_member("disable_lifo_slot")?;

        Ok(Self {
            global_queue_interval,
            event_interval,
            disable_lifo_slot,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct TaskQueue {
    head: u64,
    tail: u32,
    tasks: Vec<TaskHeader>,
}

impl ReadCtfType for TaskQueue {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let head: u64 = info.parse_member("head")?;
        let tail: u32 = info.parse_member("tail")?;

        let Some(buf_ty) = info.follow_path(&[
            TypePath {
                name: "buffer",
                selector: Selector::Struct { member: "buffer" },
            },
            TypePath {
                name: "*ptr",
                selector: Selector::Pointer,
            },
        ])?
        else {
            panic!();
        };

        let CtfType::Array {
            ty: CtfArray { element_type, .. },
            ..
        } = buf_ty.ty
        else {
            panic!();
        };

        let elem_ty = buf_ty.ctf.ty(*element_type);
        let elem_size = elem_ty.size(buf_ty.ctf) as usize;

        let real_head = (head & u32::MAX as u64) as u32;
        let len = tail.wrapping_sub(real_head) as usize;

        let mut tasks = Vec::with_capacity(len);

        for (i, chunk) in buf_ty.buf.chunks_exact(elem_size).enumerate().take(len) {
            let item_info = TypeInfoRef {
                ty: elem_ty,
                addr: buf_ty.addr + (i * elem_size) as u64,
                bytes: chunk,
                ctf: buf_ty.ctf,
                reader: buf_ty.reader,
            };
            let Some(task_info) = item_info.follow_path(&[TypePath {
                name: "MaybeUnint<Task>",
                selector: Selector::Struct { member: "value" },
            }])?
            else {
                unreachable!("TODO real error");
            };
            let task = task_info.parse_ty()?;
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
    queue_next: Option<Box<TaskHeader>>,
    owner_id: Option<u64>,
    // vtable: TODO,
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
            .field("is_running", &self.is_running())
            .field("is_complete", &self.is_complete())
            .field("is_notified", &self.is_notified())
            .field("is_cancelled", &self.is_cancelled())
            .field("is_join_interested", &self.is_join_interested())
            .field("is_join_waker_set", &self.is_join_waker_set())
            .field("ref_count", &self.ref_count())
            .field("owner_id", &self.owner_id)
            .field("inner", &format_args!("{:0b}", self.state))
            .finish()
    }
}

impl ReadCtfType for TaskHeader {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let Some(info) = info.follow_path(&[TypePath {
            name: "ptr",
            selector: Selector::Pointer,
        }])?
        else {
            panic!();
        };
        let state = info.parse_member("state")?;
        let queue_next: Option<TaskHeader> = info.parse_member("queue_next")?;

        let owner_id = info.parse_member("owner_id")?;
        Ok(TaskHeader {
            state,
            queue_next: queue_next.map(Box::new),
            owner_id,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct DriverHandle {
    io: IoHandle,
}

impl ReadCtfType for DriverHandle {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let io = info.parse_member("io")?;
        Ok(Self { io })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum IoHandle {
    Enabled(IoEnabled),
    Disabled(IoDisabled),
}

impl ReadCtfType for IoHandle {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        match info.active_variant()? {
            ("Enabled", info) => {
                let handle_info = info.member_info("__0")?;
                let inner = IoEnabled::from_ctf_info(&handle_info)?;
                Ok(IoHandle::Enabled(inner))
            }
            ("Disabled", info) => {
                let handle_info = info.member_info("__0")?;
                let inner = IoDisabled::from_ctf_info(&handle_info)?;
                Ok(IoHandle::Disabled(inner))
            }
            (other, info) => panic!("unexpected variant {other}: {info:?}"),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoEnabled {
    num_pending_release: u64,
    synced: IoSynced,
    metrics: IoDriverMetrics,
    waker_fd: i32,
}

impl ReadCtfType for IoEnabled {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let num_pending_release = info.parse_member("registrations")?;
        let metrics = info.parse_member("metrics")?;
        let waker_fd = info.parse_member("waker")?;
        let synced_info = info
            .follow_path(&[
                TypePath {
                    name: "IoEnabled",
                    selector: Selector::Struct { member: "synced" },
                },
                TypePath {
                    name: "Mutex<Synced>",
                    selector: Selector::Struct { member: "__1" },
                },
                TypePath {
                    name: "RawMutex<Synced>",
                    selector: Selector::Struct { member: "data" },
                },
            ])?
            .unwrap();
        let synced = synced_info.parse_ty()?;

        Ok(Self {
            num_pending_release,
            synced,
            metrics,
            waker_fd,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDisabled {
    park: u32,
}

impl ReadCtfType for IoDisabled {
    fn from_ctf_info(_info: &TypeInfoRef) -> durin::Result<Self> {
        todo!();
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoSynced {
    registrations: Vec<ScheduledIo>,
    is_shutdown: bool,
}

impl ReadCtfType for IoSynced {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let is_shutdown = info.parse_member("is_shutdown")?;
        let mut registrations = Vec::new();
        if let Some(mut head_info) = info.follow_path(&[
            TypePath {
                name: "IoSynced",
                selector: Selector::Struct {
                    member: "registrations",
                },
            },
            TypePath {
                name: "LinkedList",
                selector: Selector::Struct { member: "head" },
            },
            TypePath {
                name: "Option<NonNull<ScheduledIo>>",
                selector: Selector::Enum { variant: "Some" },
            },
            TypePath {
                name: "*NonNull<ScheduledIo>",
                selector: Selector::Pointer,
            },
        ])? {
            loop {
                let sched = head_info.parse_ty()?;
                registrations.push(sched);

                let Some(next) = head_info.follow_path(&[
                    TypePath {
                        name: "PointersInner<ScheduledIo>",
                        selector: Selector::Struct {
                            member: "linked_list_pointers",
                        },
                    },
                    TypePath {
                        name: "PointersInner<ScheduledIo>",
                        selector: Selector::Struct { member: "next" },
                    },
                    TypePath {
                        name: "Option<NonNull<ScheduledIo>>",
                        selector: Selector::Enum { variant: "Some" },
                    },
                    TypePath {
                        name: "NonNull<ScheduledIo>",
                        selector: Selector::Pointer,
                    },
                ])?
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

impl ReadCtfType for ScheduledIo {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let readiness = info.parse_member("readiness")?;
        let waiters = info
            .follow_path(&[
                TypePath {
                    name: "ScheduledIo",
                    selector: Selector::Struct { member: "waiters" },
                },
                TypePath {
                    name: "Mutex<Waiters>",
                    selector: Selector::Struct { member: "__1" },
                },
                TypePath {
                    name: "RawMutex<Waiters>",
                    selector: Selector::Struct { member: "data" },
                },
            ])?
            .map(|i| i.parse_ty())
            .transpose()?
            .unwrap();

        Ok(Self { readiness, waiters })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ready(pub u64);

impl ReadCtfType for Ready {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse_ty()?;
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

impl ReadCtfType for Waiters {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let mut list = Vec::new();
        let prev = info.follow_path(&[
            TypePath {
                name: "Waiters",
                selector: Selector::Struct { member: "list" },
            },
            TypePath {
                name: "LinkedList<Waiter>",
                selector: Selector::Struct { member: "tail" },
            },
            TypePath {
                name: "Option<NonNull<ScheduledIo>>",
                selector: Selector::Enum { variant: "Some" },
            },
            TypePath {
                name: "*NonNull<Waiter>",
                selector: Selector::Pointer,
            },
        ])?;
        if let Some(mut head_info) = info.follow_path(&[
            TypePath {
                name: "Waiters",
                selector: Selector::Struct { member: "list" },
            },
            TypePath {
                name: "LinkedList<Waiter>",
                selector: Selector::Struct { member: "head" },
            },
            TypePath {
                name: "Option<NonNull<ScheduledIo>>",
                selector: Selector::Enum { variant: "Some" },
            },
            TypePath {
                name: "*NonNull<Waiter>",
                selector: Selector::Pointer,
            },
        ])? {
            loop {
                let waiter = head_info.parse_ty()?;
                list.push(waiter);

                let Some(next) = head_info.follow_path(&[
                    TypePath {
                        name: "PointersInner<Waiter>",
                        selector: Selector::Struct { member: "pointers" },
                    },
                    TypePath {
                        name: "PointersInner<Waiter",
                        selector: Selector::Struct { member: "next" },
                    },
                    TypePath {
                        name: "Option<NonNull<Waiter>>",
                        selector: Selector::Enum { variant: "Some" },
                    },
                    TypePath {
                        name: "NonNull<Waiter>",
                        selector: Selector::Pointer,
                    },
                ])?
                else {
                    break;
                };
                head_info = next;
            }
        }
        let reader = info
            .follow_path(&[
                TypePath {
                    name: "Waiters",
                    selector: Selector::Struct { member: "reader" },
                },
                TypePath {
                    name: "Option<Waiter>",
                    selector: Selector::Enum { variant: "Some" },
                },
            ])?
            .map(|i| i.parse_ty())
            .transpose()?;

        let writer = info
            .follow_path(&[
                TypePath {
                    name: "Waiters",
                    selector: Selector::Struct { member: "writer" },
                },
                TypePath {
                    name: "Option<Waiter>",
                    selector: Selector::Enum { variant: "Some" },
                },
            ])?
            .map(|i| i.parse_ty())
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

impl ReadCtfType for Waiter {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let interest = info.parse_member("interest")?;
        let is_ready = info.parse_member("is_ready")?;
        let waker = info
            .follow_path(&[
                TypePath {
                    name: "Waiter",
                    selector: Selector::Struct { member: "waker" },
                },
                TypePath {
                    name: "Option<Waiter>",
                    selector: Selector::Enum { variant: "Some" },
                },
            ])?
            .map(|i| i.parse_ty())
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

impl ReadCtfType for Interest {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse_ty()?;
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
    data: u64,
    wake: u64,
    wake_by_ref: u64,
    clone: u64,
    drop: u64,
}

impl ReadCtfType for Waker {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let data = info.parse_member("data")?;

        let vtable_info = info
            .follow_path(&[
                TypePath {
                    name: "RawWaker",
                    selector: Selector::Struct { member: "vtable" },
                },
                TypePath {
                    name: "*Vtable",
                    selector: Selector::Pointer,
                },
            ])?
            .unwrap();
        let wake = vtable_info.parse_member("wake")?;
        let wake_by_ref = vtable_info.parse_member("wake_by_ref")?;
        let clone = vtable_info.parse_member("clone")?;
        let drop = vtable_info.parse_member("drop")?;

        Ok(Self {
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
            .field("data", &format_args!("{:#x}", self.data))
            .field("wake", &format_args!("{:#x}", self.wake))
            .field("wake_by_ref", &format_args!("{:#x}", self.wake_by_ref))
            .field("clone", &format_args!("{:#x}", self.clone))
            .field("drop", &format_args!("{:#x}", self.drop))
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDriverMetrics {
    fd_registered_count: u64,
    fd_deregistered_count: u64,
    ready_count: u64,
}

impl ReadCtfType for IoDriverMetrics {
    fn from_ctf_info(info: &TypeInfoRef) -> durin::Result<Self> {
        let fd_registered_count = info.parse_member("fd_registered_count")?;
        let fd_deregistered_count = info.parse_member("fd_deregistered_count")?;
        let ready_count = info.parse_member("ready_count")?;

        Ok(Self {
            fd_registered_count,
            fd_deregistered_count,
            ready_count,
        })
    }
}

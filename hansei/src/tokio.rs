use crate::unwind::Frame;

use anyhow::{Context as _, Result};
use durin::TypeId;
use durin::read::{BytesFromCore, CtfContext, CtfReader, ParseWithCtf, TypeInfo, TypeInfoRef};
use durin::{Error, TypeKind};
use petgraph::graphmap::DiGraphMap;
use proc::Core;
use regex::Regex;
use semver::Version;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::mem;
use std::ops::Range;
use std::time::Duration;

pub struct Context<'ctf> {
    pub core: &'ctf Core,
    pub ctf: &'ctf CtfReader,
    pub symbols: RefCell<HashMap<u64, &'static str>>,
    pub header_id: TypeId,
    pub trailer_id: TypeId,
    pub location_id: TypeId,
    pub tokio_version: Version,
}

impl<'ctf> Context<'ctf> {
    fn lookup_symbol(&self, addr: u64) -> &'static str {
        let mut symbols = self.symbols.borrow_mut();

        *symbols.entry(addr).or_insert_with(|| {
            let sym = self.core.lookup_symbol(addr).unwrap();
            let s = format!("{:#}", rustc_demangle::demangle(&sym.name));
            // Leak the String so we can treat it as a &'static str.
            Box::leak(s.into_boxed_str())
        })
    }
}

impl<'ctf> CtfContext<'ctf> for &'ctf Context<'ctf> {
    fn ctf(&self) -> &'ctf CtfReader {
        &self.ctf
    }
    fn core(&self) -> &'ctf Core {
        &self.core
    }
}

#[derive(Debug)]
pub struct TokioRuntime {
    pub workers: BTreeMap<u32, WorkerState>,
    pub scheduler: Scheduler,
}

impl TokioRuntime {
    pub fn parse(ctf: &CtfReader, core: &Core) -> Result<Self> {
        let lwps = core.lwps()?;

        let status = core.status();
        let brk_range = status.brk_range;

        let backtraces = crate::unwind::load_frames(&core)?;
        let mut workers = BTreeMap::new();

        let header_id = ctf
            .find_ty(
                "*const_tokio::runtime::task::core::Header",
                TypeKind::Pointer,
            )
            .unwrap()
            .id();
        let trailer_id = ctf
            .find_ty("tokio::runtime::task::core::Trailer", TypeKind::Struct)
            .unwrap()
            .id();
        let location_id = ctf
            .find_ty("core::panic::location::Location", TypeKind::Struct)
            .unwrap()
            .id();
        let tokio_version = extract_tokio_version(&ctf).context("failed to find tokio version")?;

        let ctx = Context {
            core,
            ctf,
            symbols: RefCell::new(HashMap::new()),
            header_id,
            trailer_id,
            location_id,
            tokio_version,
        };

        let ctx_ty = ctx
            .ctf
            .find_ty("tokio::runtime::context::Context", TypeKind::Struct)
            .unwrap();

        let mut scheduler = None;
        for lwp in &lwps {
            if let Some(addr) = find_context(lwp.tid, &brk_range, &ctx.core)? {
                //eprintln!("Context for TID {}: {addr:#x}", lwp.tid);
                let Some(info) = TypeInfo::from_addr(&ctx, ctx_ty, addr)? else {
                    continue;
                };

                let thd_ctx: ThreadCtx = info.parse(&ctx)?;
                let backtrace = backtraces.get(&lwp.tid).cloned().unwrap_or_default();
                let worker_state = WorkerState {
                    thd_ctx,
                    backtrace: Backtrace { inner: backtrace },
                };
                workers.insert(lwp.tid, worker_state);

                if scheduler.is_none() {
                    let sched = info
                        .member(&ctx, "current")?
                        .member(&ctx, "handle")?
                        .member(&ctx, "value")?
                        .select_variant(&ctx, "Some")?
                        .select_variant(&ctx, "MultiThread")?
                        .deref_ptr(&ctx)?
                        .member(&ctx, "data")?
                        .parse::<Scheduler, _>(&ctx)?;
                    scheduler = Some(sched);
                }
            }
        }
        let Some(scheduler) = scheduler else {
            anyhow::bail!("failed to find scheduler");
        };

        Ok(Self { workers, scheduler })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct WorkerState {
    pub thd_ctx: ThreadCtx,
    pub backtrace: Backtrace,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Backtrace {
    inner: Vec<Frame>,
}

impl Backtrace {
    pub fn stack(&self, max_frames: usize) -> Vec<String> {
        self.inner
            .iter()
            .take(max_frames)
            .map(|frame| {
                let mangled = frame
                    .symbol
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or_default();
                format!(
                    "{:#018x} {:#}",
                    frame.regs.rip,
                    rustc_demangle::demangle(mangled)
                )
            })
            .collect()
    }
}

fn extract_tokio_version(ctf: &CtfReader) -> Result<Version> {
    let tokio_type_pat = Regex::new(r#"__CRATE_tokio-1\.\d+\.\d+__"#).unwrap();
    let Some(tokio_ver_ty) = ctf
        .types()
        .iter()
        .find(|t| t.kind() == TypeKind::Typedef && tokio_type_pat.is_match(t.name(ctf)))
    else {
        anyhow::bail!("failed to find tokio version typedef in CTF");
    };

    let tokio_ver_pat = Regex::new(r#"__CRATE_tokio-(\d+\.\d+\.\d+)__"#).unwrap();
    let Some(ver_match) = tokio_ver_pat
        .captures(tokio_ver_ty.name(&ctf))
        .and_then(|c| c.get(1))
    else {
        anyhow::bail!(
            "failed to find version string in {}",
            tokio_ver_ty.name(ctf)
        );
    };

    let ver = Version::parse(ver_match.as_str())?;
    Ok(ver)
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
pub struct ThreadCtx {
    pub current_task_id: Option<u64>,
    pub thread_id: Option<u64>,
    pub worker_index: Option<u64>,
    pub worker_core: Option<WorkerCore>,
    pub defer: Vec<Waker>,
    pub runtime: EnterRuntime,
    pub budget: Budget,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for ThreadCtx {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let current_task_id = info.member(ctx, "current_task_id")?.parse(ctx)?;
        let thread_id = info.member(ctx, "thread_id")?.parse(ctx)?;
        let runtime = info.member(ctx, "runtime")?.parse(ctx)?;
        let budget = info.member(ctx, "budget")?.parse(ctx)?;

        let Some(sched_ptr) = info.member(ctx, "scheduler")?.try_deref_ptr(ctx)? else {
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

        let sched_info = sched_ptr.select_variant(ctx, "MultiThread")?.to_owned();

        let worker_index = match sched_info.member(ctx, "worker")?.try_deref_ptr(ctx)? {
            Some(worker) => {
                let idx = worker
                    .member(ctx, "data")?
                    .member(ctx, "index")?
                    .parse(ctx)?;
                Some(idx)
            }
            None => None,
        };

        let worker_core = match sched_info
            .member(ctx, "core")?
            .member(ctx, "value")?
            .try_select_variant(ctx, "Some")?
        {
            Some(i) => {
                let core = i.deref_ptr(ctx)?.parse(ctx)?;
                Some(core)
            }
            None => None,
        };

        let defer = sched_info
            .member(ctx, "defer")?
            .member(ctx, "value")?
            .parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for EnterRuntime {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        match info.active_variant(ctx)? {
            ("Entered", var_info) => {
                let allow_block_in_place = var_info.parse(ctx)?;
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Budget {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse(ctx)?;
        Ok(Self(inner))
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Scheduler {
    pub shared: Shared,
    pub driver: DriverHandle,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Scheduler {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let shared = info.member(ctx, "shared")?.parse(ctx)?;
        let driver = info.member(ctx, "driver")?.parse(ctx)?;

        Ok(Self { shared, driver })
    }
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for WorkerCore {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let global_queue_interval = info.member(ctx, "global_queue_interval")?.parse(ctx)?;
        let tick = info.member(ctx, "tick")?.parse(ctx)?;
        let lifo_enabled = info.member(ctx, "lifo_enabled")?.parse(ctx)?;
        let lifo_slot = info
            .member(ctx, "lifo_slot")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;
        let is_searching = info.member(ctx, "is_searching")?.parse(ctx)?;
        let is_shutdown = info.member(ctx, "is_shutdown")?.parse(ctx)?;
        let is_traced = info.member(ctx, "is_traced")?.parse(ctx)?;
        let park = info.member(ctx, "park")?.parse(ctx)?;
        let stats = info.member(ctx, "stats")?.parse(ctx)?;

        let run_queue = info
            .member(ctx, "run_queue")?
            .deref_ptr(ctx)?
            .member(ctx, "data")?
            .parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Parker {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let state = info
            .deref_ptr(ctx)?
            .member(ctx, "data")?
            .member(ctx, "state")?
            .parse(ctx)?;

        Ok(Self(state))
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for WorkerStats {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let batch = info.member(ctx, "batch")?.parse(ctx)?;
        let tasks_polled_in_batch = info.member(ctx, "tasks_polled_in_batch")?.parse(ctx)?;
        let task_poll_time_ewma = info.member(ctx, "task_poll_time_ewma")?.parse(ctx)?;

        Ok(Self {
            batch,
            tasks_polled_in_batch,
            task_poll_time_ewma,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct MetricsBatch {
    /// The total busy duration in nanoseconds.
    pub busy_duration_total: u64,
    // Instant at which work last resumed (continued after park).
    pub processing_scheduled_tasks_started_at: Option<Duration>, // TODO is duration useful here?
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for MetricsBatch {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let busy_duration_total = info.member(ctx, "busy_duration_total")?.parse(ctx)?;
        let processing_scheduled_tasks_started_at = info
            .member(ctx, "processing_scheduled_tasks_started_at")?
            .parse::<Option<RawInstant>, _>(ctx)?
            .map(|raw_time| Duration::new(raw_time.tv_sec, raw_time.tv_nsec));
        let park_count = info.member(ctx, "park_count")?.parse(ctx)?;
        let park_unpark_count = info.member(ctx, "park_unpark_count")?.parse(ctx)?;
        let noop_count = info.member(ctx, "noop_count")?.parse(ctx)?;
        let steal_count = info.member(ctx, "steal_count")?.parse(ctx)?;
        let steal_operations = info.member(ctx, "steal_operations")?.parse(ctx)?;
        let poll_count = info.member(ctx, "poll_count")?.parse(ctx)?;
        let poll_count_on_last_park = info.member(ctx, "poll_count_on_last_park")?.parse(ctx)?;
        let local_schedule_count = info.member(ctx, "local_schedule_count")?.parse(ctx)?;
        let overflow_count = info.member(ctx, "overflow_count")?.parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Shared {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let remotes = info.member(ctx, "remotes")?.parse(ctx)?;
        let config = info.member(ctx, "config")?.parse(ctx)?;
        let inject_len = info.member(ctx, "inject")?.parse(ctx)?;
        let idle: Idle = info.member(ctx, "idle")?.parse(ctx)?;
        let owned = info.member(ctx, "owned")?.parse(ctx)?;
        let scheduler_metrics = info.member(ctx, "scheduler_metrics")?.parse(ctx)?;
        let worker_metrics = info.member(ctx, "worker_metrics")?.parse(ctx)?;

        let synced: Synced = info
            .member(ctx, "synced")?
            .member(ctx, "data")?
            .parse(ctx)?;
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
    pub steal: TaskQueue,
    pub unpark: Parker,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Remote {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let steal = info
            .member(ctx, "steal")?
            .deref_ptr(ctx)?
            .member(ctx, "data")?
            .parse(ctx)?;
        let unpark = info.member(ctx, "unpark")?.parse(ctx)?;

        Ok(Self { steal, unpark })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Idle {
    pub num_searching: u64,
    pub num_unparked: u64,
    pub num_workers: u64,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Idle {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        const UNPARK_SHIFT: u64 = 16;
        const UNPARK_MASK: u64 = !SEARCH_MASK;
        const SEARCH_MASK: u64 = (1 << UNPARK_SHIFT) - 1;

        let num_workers = info.member(ctx, "num_workers")?.parse(ctx)?;
        let state: u64 = info.member(ctx, "state")?.parse(ctx)?;
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
    pub tasks: HashMap<TaskAddr, TaskHeader>,
    pub added: u64,
    pub count: u64,
    pub closed: bool,
    pub shard_mask: u64,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for OwnedTasks {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let closed = info.member(ctx, "closed")?.parse(ctx)?;

        let list_info = info.member(ctx, "list")?;
        let added = list_info.member(ctx, "added")?.parse(ctx)?;
        let count = list_info.member(ctx, "count")?.parse(ctx)?;
        let shard_mask = list_info.member(ctx, "shard_mask")?.parse(ctx)?;

        let mut tasks = HashMap::new();

        list_info
            .member(ctx, "lists")?
            .boxed_slice_elements(ctx, |i| {
                if let Some(mut head_ptr) = i
                    .member(ctx, "data")?
                    .member(ctx, "head")?
                    .try_select_variant(ctx, "Some")?
                    .map(|i| i.to_owned())
                {
                    loop {
                        let addr = head_ptr.parse(ctx)?;
                        let task_info = head_ptr.deref_ptr(ctx)?;
                        let task = task_info.parse(ctx)?;
                        tasks.insert(addr, task);

                        let Some(next_info) = task_info
                            .member(ctx, "queue_next")?
                            .try_select_variant(ctx, "Some")?
                        else {
                            break;
                        };
                        head_ptr = next_info.to_owned();
                    }
                }
                //if let Some(mut head_info) = i
                //    .member("data")?
                //    .member("head")?
                //    .try_select_variant("Some")?
                //    .map(|i| i.deref_ptr())
                //    .transpose()?
                //{
                //    loop {
                //        let task = head_info.parse()?;
                //        list.push(task);

                //        let Some(next) = head_info
                //            .member("queue_next")?
                //            .try_select_variant("Some")?
                //            .map(|i| i.deref_ptr())
                //            .transpose()?
                //        else {
                //            break;
                //        };
                //        head_info = next.to_owned();
                //    }
                //}

                Ok(())
            })?;

        Ok(OwnedTasks {
            tasks,
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
            .field("tasks", &self.tasks)
            .field("added", &self.added)
            .field("count", &self.count)
            .field("shard_mask", &format_args!("{:#b}", self.shard_mask))
            .finish()
    }
}

// TODO non-zero? Validate mapping?
#[derive(Copy, Clone, PartialEq, Hash, Eq)]
pub struct TaskAddr(pub u64);

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for TaskAddr {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let addr = info.parse(ctx)?;
        Ok(Self(addr))
    }
}

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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Synced {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let idle_sleepers = info
            .member(ctx, "idle")?
            .parse::<Vec<u64>, _>(ctx)?
            .into_iter()
            .collect();

        let inject_info = info.member(ctx, "inject")?;
        let inject_closed = inject_info.member(ctx, "is_closed")?.parse(ctx)?;

        let inject_head = inject_info
            .member(ctx, "head")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;

        let inject_tail = inject_info
            .member(ctx, "tail")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
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
    pub len: u64,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Inject {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let len = info.member(ctx, "len")?.parse(ctx)?;
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Config {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let global_queue_interval = info.member(ctx, "global_queue_interval")?.parse(ctx)?;
        let event_interval = info.member(ctx, "event_interval")?.parse(ctx)?;
        let disable_lifo_slot = info.member(ctx, "disable_lifo_slot")?.parse(ctx)?;

        Ok(Self {
            global_queue_interval,
            event_interval,
            disable_lifo_slot,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct SchedulerMetrics {
    pub remote_schedule_count: u64,
    pub budget_forced_yield_count: u64,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for SchedulerMetrics {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let remote_schedule_count = info.member(ctx, "remote_schedule_count")?.parse(ctx)?;
        let budget_forced_yield_count =
            info.member(ctx, "budget_forced_yield_count")?.parse(ctx)?;

        Ok(Self {
            remote_schedule_count,
            budget_forced_yield_count,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for WorkerMetrics {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let busy_duration_total = info.member(ctx, "busy_duration_total")?.parse(ctx)?;
        let queue_depth = info.member(ctx, "queue_depth")?.parse(ctx)?;
        let thread_id = info
            .member(ctx, "thread_id")?
            .member(ctx, "data")?
            .parse(ctx)?;
        let park_count = info.member(ctx, "park_count")?.parse(ctx)?;
        let park_unpark_count = info.member(ctx, "park_unpark_count")?.parse(ctx)?;
        let noop_count = info.member(ctx, "noop_count")?.parse(ctx)?;
        let steal_count = info.member(ctx, "steal_count")?.parse(ctx)?;
        let steal_operations = info.member(ctx, "steal_operations")?.parse(ctx)?;
        let poll_count = info.member(ctx, "poll_count")?.parse(ctx)?;
        let mean_poll_time = info.member(ctx, "mean_poll_time")?.parse(ctx)?;
        let local_schedule_count = info.member(ctx, "local_schedule_count")?.parse(ctx)?;
        let overflow_count = info.member(ctx, "overflow_count")?.parse(ctx)?;

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
    pub head: u64,
    pub tail: u32,
    pub tasks: Vec<TaskAddr>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for TaskQueue {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let head: u64 = info.member(ctx, "head")?.parse(ctx)?;
        let tail: u32 = info.member(ctx, "tail")?.parse(ctx)?;

        let buf_info = info.member(ctx, "buffer")?.deref_ptr(ctx)?;

        let real_head = (head & u32::MAX as u64) as u32;
        let len = tail.wrapping_sub(real_head) as usize;

        let mut tasks = Vec::with_capacity(len);

        for elem_info in buf_info.as_ref().array_elements(ctx)?.take(len) {
            let task_ptr = elem_info.member(ctx, "value")?.parse(ctx)?;
            tasks.push(task_ptr);
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for TaskHeader {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let state = info.member(ctx, "state")?.parse(ctx)?;
        let runtime_id = info.member(ctx, "owner_id")?.parse(ctx)?;

        let vtable_info = info.member(ctx, "vtable")?.deref_ptr(ctx)?;

        let id_offset: u64 = vtable_info.member(ctx, "id_offset")?.parse(ctx)?;
        let id_addr = info.addr + id_offset;
        let id_bytes = ctx
            .core
            .read_bytes(id_addr, size_of::<u64>() as u64)?
            .unwrap();
        let id = u64::from_le_bytes(id_bytes.try_into().unwrap());

        // This is the offset from the Header address to the address of
        // `spawn_location`.
        let spawn_offset: u64 = vtable_info
            .member(ctx, "spawn_location_offset")?
            .parse(ctx)?;
        let spawn_ptr_addr = info.addr + spawn_offset;
        let spawn_ptr = ctx
            .core
            .read_u64(spawn_ptr_addr)
            .map_err(|e| Error::null_ptr(Some(e.into())))?;

        // The CTF isn't aware we have a *Location here, so manually find the type and parse.
        let spawn_ty = ctx.ctf.ty(ctx.location_id);
        let spawn_buf = ctx.core.read_type(spawn_ptr, spawn_ty, &ctx.ctf)?.unwrap();
        let spawn_info = info.clone().with_ty(spawn_ty).with_buf(&spawn_buf);
        let spawn_location = spawn_info.parse(ctx)?;

        // This is the offset from the Header address to the address of the
        // `Trailer` of the task.
        let trailer_offset: u64 = vtable_info.member(ctx, "trailer_offset")?.parse(ctx)?;
        let trailer_ptr = info.addr + trailer_offset;

        let trailer_ty = ctx.ctf.ty(ctx.trailer_id);
        let trailer_buf = ctx
            .core
            .read_type(trailer_ptr, trailer_ty, &ctx.ctf)?
            .unwrap();
        let trailer_info = info.clone().with_ty(trailer_ty).with_buf(&trailer_buf);
        let waker = trailer_info.member(ctx, "waker")?.parse(ctx)?;

        Ok(TaskHeader {
            state,
            runtime_id,
            id,
            spawn_location,
            waker,
        })
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

#[derive(Clone, PartialEq, Debug)]
pub struct Location {
    pub filename: String,
    pub line: u32,
    pub col: u32,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Location {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let filename = info.member(ctx, "filename")?.parse(ctx)?;
        let line = info.member(ctx, "line")?.parse(ctx)?;
        let col = info.member(ctx, "col")?.parse(ctx)?;

        Ok(Self {
            filename,
            line,
            col,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct DriverHandle {
    pub io: IoHandle,
    pub time: Option<TimeHandle>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for DriverHandle {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let io = info.member(ctx, "io")?.parse(ctx)?;
        let time = info
            .member(ctx, "time")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;

        Ok(Self { io, time })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum IoHandle {
    Enabled(IoEnabled),
    Disabled(IoDisabled),
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for IoHandle {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        match info.active_variant(ctx)? {
            ("Enabled", info) => {
                let inner = info.parse(ctx)?;
                Ok(IoHandle::Enabled(inner))
            }
            ("Disabled", info) => {
                let inner = info.parse(ctx)?;
                Ok(IoHandle::Disabled(inner))
            }
            (other, info) => Err(Error::no_enumerator(info.ty.id(), other.to_string())),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoEnabled {
    pub num_pending_release: u64,
    pub waker_fd: i32,
    pub poll_fd: i32,
    pub metrics: IoDriverMetrics,
    pub synced: IoSynced,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for IoEnabled {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let num_pending_release = info.member(ctx, "registrations")?.parse(ctx)?;
        let metrics = info.member(ctx, "metrics")?.parse(ctx)?;
        let waker_fd = info.member(ctx, "waker")?.parse(ctx)?;
        let synced = info
            .member(ctx, "synced")?
            .member(ctx, "data")?
            .parse(ctx)?;
        let poll_fd = info.member(ctx, "registry")?.parse(ctx)?;

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
    pub park: u32,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for IoDisabled {
    fn parse_with_ctf(ctx: &Context, _info: &TypeInfoRef) -> durin::Result<Self> {
        todo!();
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoSynced {
    pub registrations: Vec<ScheduledIo>,
    pub is_shutdown: bool,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for IoSynced {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let is_shutdown = info.member(ctx, "is_shutdown")?.parse(ctx)?;
        let mut registrations = Vec::new();
        if let Some(mut head_info) = info
            .member(ctx, "registrations")?
            .member(ctx, "head")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.deref_ptr(ctx))
            .transpose()?
        {
            loop {
                let sched = head_info.parse(ctx)?;
                registrations.push(sched);

                let Some(next) = head_info
                    .member(ctx, "linked_list_pointers")?
                    .member(ctx, "next")?
                    .try_select_variant(ctx, "Some")?
                    .map(|i| i.deref_ptr(ctx))
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
    pub readiness: Ready,
    pub waiters: Waiters,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for ScheduledIo {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let readiness = info.member(ctx, "readiness")?.parse(ctx)?;
        let waiters = info
            .member(ctx, "waiters")?
            .member(ctx, "data")?
            .parse(ctx)?;

        Ok(Self { readiness, waiters })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Ready(pub u64);

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Ready {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse(ctx)?;
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
    pub list: Vec<Waiter>,
    pub reader: Option<Waker>,
    pub writer: Option<Waker>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Waiters {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let mut list = Vec::new();
        if let Some(mut head_info) = info
            .member(ctx, "list")?
            .member(ctx, "head")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.deref_ptr(ctx))
            .transpose()?
        {
            loop {
                let waiter = head_info.parse(ctx)?;
                list.push(waiter);

                let Some(next) = head_info
                    .member(ctx, "pointers")?
                    .member(ctx, "next")?
                    .try_select_variant(ctx, "Some")?
                    .map(|i| i.deref_ptr(ctx))
                    .transpose()?
                else {
                    break;
                };
                head_info = next;
            }
        }
        let reader = info
            .member(ctx, "reader")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;

        let writer = info
            .member(ctx, "writer")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
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
    pub interest: Interest,
    pub is_ready: bool,
    pub waker: Option<Waker>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Waiter {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let interest = info.member(ctx, "interest")?.parse(ctx)?;
        let is_ready = info.member(ctx, "is_ready")?.parse(ctx)?;

        let waker = info
            .member(ctx, "waker")?
            .try_select_variant(ctx, "Some")?
            .map(|info| info.parse(ctx))
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Interest {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse(ctx)?;
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
    pub dependent_task: Option<TaskAddr>,
    pub data: TaskAddr,
    pub wake: &'static str,
    pub wake_by_ref: &'static str,
    pub clone: &'static str,
    pub drop: &'static str,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Waker {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let data = info.member(ctx, "data")?.parse(ctx)?;
        let vtable_info = info.member(ctx, "vtable")?.deref_ptr(ctx)?;

        let wake_addr = vtable_info.member(ctx, "wake")?.parse(ctx)?;
        let wake_by_ref_addr = vtable_info.member(ctx, "wake_by_ref")?.parse(ctx)?;
        let clone_addr = vtable_info.member(ctx, "clone")?.parse(ctx)?;
        let drop_addr = vtable_info.member(ctx, "drop")?.parse(ctx)?;

        let wake = ctx.lookup_symbol(wake_addr);
        let wake_by_ref = ctx.lookup_symbol(wake_by_ref_addr);
        let clone = ctx.lookup_symbol(clone_addr);
        let drop = ctx.lookup_symbol(drop_addr);

        let dependent_task;
        if wake == "tokio::runtime::task::waker::wake_by_val" {
            let hdr_info = info.member(ctx, "data")?.with_ty(ctx.ctf.ty(ctx.header_id));
            let hdr = hdr_info.parse::<TaskAddr, _>(ctx)?;
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
            .field("data", &self.data)
            .field("wake", &self.wake)
            .field("wake_by_ref", &self.wake_by_ref)
            .field("clone", &self.clone)
            .field("drop", &self.drop)
            .finish()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct IoDriverMetrics {
    pub fd_registered_count: u64,
    pub fd_deregistered_count: u64,
    pub ready_count: u64,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for IoDriverMetrics {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let fd_registered_count = info.member(ctx, "fd_registered_count")?.parse(ctx)?;
        let fd_deregistered_count = info.member(ctx, "fd_deregistered_count")?.parse(ctx)?;
        let ready_count = info.member(ctx, "ready_count")?.parse(ctx)?;

        Ok(Self {
            fd_registered_count,
            fd_deregistered_count,
            ready_count,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct TimeHandle {
    pub is_shutdown: bool,
    pub did_wake: bool,
    pub time_source: Duration,
    pub wheel: Wheel,
    pub next_wake: Option<u64>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for TimeHandle {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let raw_time: RawInstant = info.member(ctx, "time_source")?.parse(ctx)?;
        let time_source = Duration::new(raw_time.tv_sec, raw_time.tv_nsec);

        let mut inner = info.member(ctx, "inner")?;
        if ctx.tokio_version >= Version::new(1, 49, 0) {
            inner = inner.select_variant(ctx, "Traditional")?;
        }

        let is_shutdown = inner.member(ctx, "is_shutdown")?.parse(ctx)?;
        let did_wake = inner.member(ctx, "did_wake")?.parse(ctx)?;

        let state_info = inner.member(ctx, "state")?.member(ctx, "data")?;

        let wheel = state_info.member(ctx, "wheel")?.parse(ctx)?;
        let next_wake = state_info.member(ctx, "next_wake")?.parse(ctx)?;

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
    pub tv_sec: u64,
    pub tv_nsec: u32,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for RawInstant {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let tv_sec = info.member(ctx, "tv_sec")?.parse(ctx)?;
        let tv_nsec = info.member(ctx, "tv_nsec")?.parse(ctx)?;

        Ok(Self { tv_sec, tv_nsec })
    }
}

#[derive(Clone, PartialEq)]
pub struct Wheel {
    pub elapsed: u64,
    pub levels: Vec<Level>,
    pub pending: Vec<TimerShared>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Wheel {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let elapsed = info.member(ctx, "elapsed")?.parse(ctx)?;

        let levels_info = info.member(ctx, "levels")?.deref_ptr(ctx)?;
        let mut levels = Vec::with_capacity(6);

        for elem_info in levels_info.array_elements(ctx)? {
            let level = elem_info.parse(ctx)?;
            levels.push(level);
        }

        let mut pending = Vec::new();
        if let Some(mut head_info) = info
            .member(ctx, "pending")?
            .member(ctx, "head")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.deref_ptr(ctx))
            .transpose()?
        {
            loop {
                let timer = head_info.parse(ctx)?;
                pending.push(timer);

                let Some(next) = head_info
                    .member(ctx, "pointers")?
                    .member(ctx, "next")?
                    .try_select_variant(ctx, "Some")?
                    .map(|i| i.deref_ptr(ctx))
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for Level {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let level = info.member(ctx, "level")?.parse(ctx)?;
        let occupied = info.member(ctx, "occupied")?.parse(ctx)?;

        let slot_info = info.member(ctx, "slot")?;

        let mut slot = Vec::new();
        for (i, elem_info) in slot_info.array_elements(ctx)?.enumerate() {
            let mut slot_timers = TimerSlot {
                slot_id: i,
                timers: Vec::new(),
            };

            // `occupied` acts as a bitmap for which slots contain items.
            if occupied & 1 << i == 0 {
                continue;
            }

            if let Some(mut head_info) = elem_info
                .member(ctx, "head")?
                .try_select_variant(ctx, "Some")?
                .map(|i| i.deref_ptr(ctx))
                .transpose()?
            {
                loop {
                    let timer = head_info.parse(ctx)?;
                    slot_timers.timers.push(timer);

                    let Some(next) = head_info
                        .member(ctx, "pointers")?
                        .member(ctx, "next")?
                        .try_select_variant(ctx, "Some")?
                        .map(|i| i.deref_ptr(ctx))
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
    pub result: String,
    pub waker_state: WakerState,
    pub waker: Option<Waker>,
}

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for TimerShared {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let registered_when = info.member(ctx, "registered_when")?.parse(ctx)?;
        let state_info = info.member(ctx, "state")?;
        let state = state_info.member(ctx, "state")?.parse(ctx)?;
        let result = state_info
            .member(ctx, "result")?
            .active_variant(ctx)?
            .0
            .to_string();

        let waker_info = state_info.member(ctx, "waker")?;
        let waker_state = waker_info.member(ctx, "state")?.parse(ctx)?;
        let waker = waker_info
            .member(ctx, "waker")?
            .try_select_variant(ctx, "Some")?
            .map(|i| i.parse(ctx))
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

impl fmt::Debug for TimerShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimerShared")
            .field("registered_when", &self.registered_when)
            .field("time_state", &self.time_state)
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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for TimerState {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, &'ctf Context<'ctf>> for WakerState {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> durin::Result<Self> {
        let inner = info.parse(ctx)?;

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

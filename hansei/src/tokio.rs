use anyhow::{Context as _, Result};
use durin::TypeKind;
use durin::read::CtfView;
use proc::{Lwp, LwpInfo, Proc, Regs};
use reify::{ParseWithCtf, TypeInfo, TypeInfoRef};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::mem;
use std::ops::Range;

pub use hansei_types::tokio::ctf::{Context, TokioInfo};
pub use hansei_types::tokio::{
    Budget, Clock, Config, DriverHandle, EnterRuntime, Expiration, Idle, Inject, Interest,
    IoDisabled, IoDriverMetrics, IoEnabled, IoHandle, IoSynced, Level, MetricsBatch, OwnedTasks,
    ParkThread, Parker, RawInstant, Ready, Remote, ScheduledIo, Scheduler, SchedulerMetrics,
    Shared, Synced, TaskAddr, TaskHeader, TaskQueue, ThreadCtx, TimeHandle, TimerShared, TimerSlot,
    TimerState, TokioRuntime, Waiter, Waiters, Waker, WakerState, Wheel, WorkerCore, WorkerMetrics,
    WorkerState, WorkerStats,
};

pub fn parse_runtime(
    ctf: CtfView,
    proc: &Proc,
    main_lwp: &Lwp,
    symbols: &mut HashMap<u64, &'static str>,
    capture_backtraces: bool,
) -> Result<TokioRuntime> {
    let Some(ctx_ty) = ctf.find("tokio::runtime::context::Context", TypeKind::Struct) else {
        anyhow::bail!("failed to find tokio::runtime::context::Context CTF type");
    };

    let ctx = Context::new(proc, main_lwp, ctf, symbols).context("failed to create Context")?;

    let lwps = proc.lwps()?;
    let status = proc.status();
    let brk_range = status.brk_range;

    let backtraces = if capture_backtraces {
        let bt = unwind::load_frames(&proc)?;
        Some(bt)
    } else {
        None
    };
    let mut workers = BTreeMap::new();

    let mut scheduler = None;
    for lwp in &lwps {
        if let Some(addr) = find_thd_context(&lwp.regs, &brk_range, &ctx.proc)
            .context("failed to find thread-local context")?
        {
            let info = TypeInfo::from_addr(&ctx, ctx_ty, addr)
                .context("failed to get type information")?;

            let thd_ctx: ThreadCtx = info
                .parse(&ctx)
                .context("failed to parse thread-local context")?;
            let backtrace = backtraces.as_ref().and_then(|bt| bt.get(&lwp.tid).cloned());

            workers.insert(lwp.tid, WorkerState { thd_ctx, backtrace });

            if scheduler.is_none() {
                let sched = info
                    .member("current")?
                    .member("handle")?
                    .member("value")?
                    .select_variant("Some")?
                    .select_variant("MultiThread")?
                    .deref_ptr(&ctx)?
                    .member("data")?
                    .parse::<Scheduler, _>(&ctx)
                    .context("failed to parse scheduler")?;
                scheduler = Some(sched);
            }
        }
    }
    let Some(scheduler) = scheduler else {
        anyhow::bail!("failed to find scheduler");
    };

    // Swap out captured symbols to parent. TODO make this not ugly
    *symbols = ctx.symbols.take();

    Ok(TokioRuntime {
        workers,
        scheduler,
        now: ctx.now,
    })
}

/// The minimal state needed to perform status polling.
#[derive(Debug)]
pub struct MinTokioState {
    pub active: BTreeSet<u64>,
    pub worker_ct: u64,
    pub task_ct: u64,
    pub io_driver: Option<usize>,
}

impl MinTokioState {
    pub fn find_type_info<'a>(ctx: &Context<'a>, lwps: &[LwpInfo]) -> Result<TypeInfo<'a>> {
        let status = ctx.proc.status();
        let brk_range = status.brk_range;

        let Some(ctx_ty) = ctx
            .ctf
            .find("tokio::runtime::context::Context", TypeKind::Struct)
        else {
            anyhow::bail!("failed to find tokio::runtime::context::Context CTF type");
        };

        //let mut scheduler = None;
        let mut sched_info = None;

        for lwp in lwps {
            if let Some(addr) = find_thd_context(&lwp.regs, &brk_range, &ctx.proc)
                .context("failed to find thread-local context")?
            {
                let info = TypeInfo::from_addr(ctx, ctx_ty, addr)
                    .context("failed to get type information")?;

                if sched_info.is_none() {
                    let ctx_info = info
                        .member("current")?
                        .member("handle")?
                        .member("value")?
                        .select_variant("Some")?
                        .select_variant("MultiThread")?
                        .deref_ptr(ctx)?;

                    let info = ctx_info
                        .member("data")
                        .context("failed to get scheduler info")?;

                    sched_info = Some(info.to_owned());

                    break;
                }
            }
        }

        let Some(sched_info) = sched_info else {
            anyhow::bail!("failed to find scheduler");
        };

        Ok(sched_info)
    }

    pub fn parse<'a>(ctx: &Context<'a>, info: &TypeInfo<'a>) -> Result<Self> {
        let scheduler = info
            .parse::<MinScheduler, _>(&ctx)
            .context("failed to parse scheduler")?;

        let io_driver = scheduler
            .parkers
            .iter()
            .enumerate()
            .find(|(_, p)| p.is_parked_driving_io())
            .map(|(i, _)| i);

        Ok(Self {
            active: scheduler.active_workers,
            worker_ct: scheduler.idle.num_workers,
            task_ct: scheduler.count,
            io_driver,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct MinThreadCtx {
    pub current_task_id: Option<u64>,
    pub thread_id: Option<u64>,
    pub worker_index: Option<u64>,
    pub runtime: EnterRuntime,
    pub budget: Budget,
}

impl<'ctf> ParseWithCtf<'ctf, Context<'ctf>> for MinThreadCtx {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> reify::Result<Self> {
        let current_task_id = info.member("current_task_id")?.parse(ctx)?;
        let thread_id = info.member("thread_id")?.parse(ctx)?;
        let runtime = info.member("runtime")?.parse(ctx)?;
        let budget = info.member("budget")?.parse(ctx)?;

        let Some(sched_ptr) = info.member("scheduler")?.try_deref_ptr(ctx)? else {
            return Ok(Self {
                current_task_id,
                thread_id,
                runtime,
                budget,
                worker_index: None,
            });
        };

        let sched_info = sched_ptr.select_variant("MultiThread")?.to_owned();

        let worker_index = match sched_info.member("worker")?.try_deref_ptr(ctx)? {
            Some(worker) => {
                let idx = worker.member("data")?.member("index")?.parse(ctx)?;
                Some(idx)
            }
            None => None,
        };

        Ok(Self {
            current_task_id,
            thread_id,
            worker_index,
            runtime,
            budget,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct MinScheduler {
    pub parkers: Vec<Parker>,
    pub inject_len: u64,
    pub idle: Idle,
    pub count: u64,
    pub active_workers: BTreeSet<u64>,
    pub synced: Synced,
}

impl<'ctf> ParseWithCtf<'ctf, Context<'ctf>> for MinScheduler {
    fn parse_with_ctf(ctx: &Context, info: &TypeInfoRef) -> reify::Result<Self> {
        let info = info.member("shared")?;
        let mut parkers = Vec::new();
        info.member("remotes")?.boxed_slice_elements(ctx, |info| {
            let unpark = info.member("unpark")?.parse(ctx)?;
            parkers.push(unpark);
            Ok(())
        })?;

        let inject_len = info.member("inject")?.parse(ctx)?;
        let idle: Idle = info.member("idle")?.parse(ctx)?;

        let count = info
            .member("owned")?
            .member("list")?
            .member("count")?
            .parse(ctx)?;

        let synced: Synced = info.member("synced")?.member("data")?.parse(ctx)?;

        let mut active_workers = BTreeSet::new();
        for i in 0u64..idle.num_workers {
            if !synced.idle_sleepers.contains(&i) {
                active_workers.insert(i);
            }
        }

        Ok(Self {
            parkers,
            inject_len,
            idle,
            active_workers,
            count,
            synced,
        })
    }
}

/// Find the address of the thread-local `tokio::runtime::context::Context` for
/// this LWP, if present. The first three u64s of this type form a
/// recognizeable pattern unlikely to be replicated by other types.
fn find_thd_context(regs: &Regs, brk_range: &Range<u64>, proc: &Proc) -> Result<Option<u64>> {
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

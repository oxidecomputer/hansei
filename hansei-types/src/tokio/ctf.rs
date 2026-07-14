// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! CTF-based parsing implementations for Tokio runtime types.

use super::*;

use durin::read::{CtfType, CtfView};
use durin::{TypeId, TypeKind};
use proc::{Mappings, Proc};
use regex::Regex;
use reify::{Error, ParseCtx, ParseWithCtf, ReadFromProc, TypeInfoRef};
use semver::Version;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;
use std::time::Instant;

static TOKIO_VER_PAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"__CRATE_tokio-(\d+\.\d+\.\d+)__"#).unwrap());

pub struct Context<'ctf> {
    pub proc: &'ctf Proc,
    pub ctf: CtfView<'ctf>,
    pub symbols: RefCell<HashMap<u64, &'static str>>,
    pub mappings: Mappings,
    pub tokio_info: TokioInfo,
    pub now: Instant,
}

impl<'ctf> Context<'ctf> {
    pub fn new(
        proc: &'ctf Proc,
        main_lwp: &'ctf proc::Lwp,
        ctf: CtfView<'ctf>,
        symbols: &HashMap<u64, &'static str>,
    ) -> anyhow::Result<Self> {
        let mappings = proc.mappings()?;

        // TODO - This assumes the timestamp is valid for all threads. I think
        // this is true, but haven't validated.
        let now = RawInstant::try_from(main_lwp.status())?;

        let tokio_info = TokioInfo::new(&ctf)?;
        Ok(Context {
            proc,
            ctf,
            symbols: RefCell::new(symbols.clone()),
            mappings,
            tokio_info,
            now: now.into(),
        })
    }

    fn lookup_symbol(&self, addr: u64) -> &'static str {
        let mut symbols = self.symbols.borrow_mut();

        *symbols.entry(addr).or_insert_with(|| {
            let sym = self.proc.lookup_symbol_by_addr(addr).unwrap();
            let s = format!("{:#}", rustc_demangle::demangle(&sym.name));

            // Leak the String so we can treat it as a &'static str.
            Box::leak(s.into_boxed_str())
        })
    }
}

impl ParseCtx for Context<'_> {
    type Target = Proc;

    fn proc(&self) -> &Proc {
        self.proc
    }
    fn mappings(&self) -> &Mappings {
        &self.mappings
    }
}

#[derive(Debug)]
pub struct TokioInfo {
    pub header_id: TypeId,
    pub trailer_id: TypeId,
    pub location_id: TypeId,
    pub park_id: TypeId,
    pub tokio_version: Version,
}

impl TokioInfo {
    fn new(ctf: &CtfView) -> anyhow::Result<Self> {
        let Some(header_ty) = ctf.find(
            "*const_tokio::runtime::task::core::Header",
            TypeKind::Pointer,
        ) else {
            anyhow::bail!("failed to find *const_tokio::runtime::task::core::Header CTF type");
        };

        let Some(trailer_ty) = ctf.find("tokio::runtime::task::core::Trailer", TypeKind::Struct)
        else {
            anyhow::bail!("failed to find tokio::runtime::task::core::Trailer CTF type");
        };

        let Some(location_ty) = ctf.find("core::panic::location::Location", TypeKind::Struct)
        else {
            anyhow::bail!("failed to find core::panic::location::Location CTF type");
        };

        let Some(park_ty) = ctf.find(
            "alloc::sync::Arc<tokio::runtime::park::Inner,_alloc::alloc::Global>",
            TypeKind::Struct,
        ) else {
            anyhow::bail!(
                "failed to find alloc::sync::Arc<tokio::runtime::park::Inner, alloc::alloc::Global> CTF type"
            );
        };

        let tokio_version = Self::extract_tokio_version(ctf)
            .map_err(|e| anyhow::anyhow!(e).context("failed to find tokio version"))?;

        Ok(Self {
            header_id: header_ty.id(),
            trailer_id: trailer_ty.id(),
            location_id: location_ty.id(),
            park_id: park_ty.id(),
            tokio_version,
        })
    }

    fn extract_tokio_version(ctf: &CtfView) -> anyhow::Result<Version> {
        let Some(tokio_ver_ty) = ctf
            .types()
            .find(|t| t.kind() == TypeKind::Typedef && TOKIO_VER_PAT.is_match(t.name()))
        else {
            anyhow::bail!("failed to find tokio version typedef in CTF");
        };

        let Some(ver_match) = TOKIO_VER_PAT
            .captures(tokio_ver_ty.name())
            .and_then(|c| c.get(1))
        else {
            anyhow::bail!("failed to find version string in {}", tokio_ver_ty.name());
        };

        let ver = Version::parse(ver_match.as_str())?;
        Ok(ver)
    }
}

struct TimeContext<'ctf> {
    elapsed: u64,
    ctx: &'ctf Context<'ctf>,
}

impl ParseCtx for TimeContext<'_> {
    type Target = Proc;

    fn proc(&self) -> &Proc {
        self.ctx.proc()
    }

    fn mappings(&self) -> &Mappings {
        self.ctx.mappings()
    }
}

// ---------------------------------------------------------------------------
// ParseWithCtf implementations
// ---------------------------------------------------------------------------

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for ThreadCtx {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
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
                defer: Vec::new(),
                worker_index: None,
                worker_core: None,
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

        let worker_core = match sched_info
            .member("core")?
            .member("value")?
            .try_select_variant("Some")?
        {
            Some(i) => {
                let core = i.deref_ptr(ctx)?.parse(ctx)?;
                Some(core)
            }
            None => None,
        };

        let defer = sched_info.member("defer")?.member("value")?.parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for EnterRuntime {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        match info.active_variant()? {
            ("Entered", var_info) => {
                let allow_block_in_place = var_info.parse(ctx)?;
                Ok(Self::Entered {
                    allow_block_in_place,
                })
            }
            ("NotEntered", _) => Ok(Self::NotEntered),
            (other, _) => Err(reify::Error::no_enumerator(
                info.ty.name().to_string(),
                other.to_string(),
            )),
        }
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Budget {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let inner = info.parse(ctx)?;
        Ok(Self(inner))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Scheduler {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let shared = info.member("shared")?.parse(ctx)?;
        let driver = info.member("driver")?.parse(ctx)?;

        Ok(Self { shared, driver })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for WorkerCore {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let global_queue_interval = info.member("global_queue_interval")?.parse(ctx)?;
        let tick = info.member("tick")?.parse(ctx)?;
        let lifo_enabled = info.member("lifo_enabled")?.parse(ctx)?;
        let lifo_slot = info
            .member("lifo_slot")?
            .try_select_variant("Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;
        let is_searching = info.member("is_searching")?.parse(ctx)?;
        let is_shutdown = info.member("is_shutdown")?.parse(ctx)?;
        let is_traced = info.member("is_traced")?.parse(ctx)?;
        let park = info.member("park")?.parse(ctx)?;
        let stats = info.member("stats")?.parse(ctx)?;

        let run_queue = info
            .member("run_queue")?
            .deref_ptr(ctx)?
            .member("data")?
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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Parker {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let state = info
            .deref_ptr(ctx)?
            .member("data")?
            .member("state")?
            .parse(ctx)?;

        Ok(Self(state))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for WorkerStats {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let batch = info.member("batch")?.parse(ctx)?;
        let tasks_polled_in_batch = info.member("tasks_polled_in_batch")?.parse(ctx)?;
        let task_poll_time_ewma = info.member("task_poll_time_ewma")?.parse(ctx)?;

        Ok(Self {
            batch,
            tasks_polled_in_batch,
            task_poll_time_ewma,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for MetricsBatch {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let busy_duration_total = info.member("busy_duration_total")?.parse(ctx)?;
        let processing_scheduled_tasks_started_at = info
            .member("processing_scheduled_tasks_started_at")?
            .parse(ctx)?;
        let park_count = info.member("park_count")?.parse(ctx)?;
        let park_unpark_count = info.member("park_unpark_count")?.parse(ctx)?;
        let noop_count = info.member("noop_count")?.parse(ctx)?;
        let steal_count = info.member("steal_count")?.parse(ctx)?;
        let steal_operations = info.member("steal_operations")?.parse(ctx)?;
        let poll_count = info.member("poll_count")?.parse(ctx)?;
        let poll_count_on_last_park = info.member("poll_count_on_last_park")?.parse(ctx)?;
        let local_schedule_count = info.member("local_schedule_count")?.parse(ctx)?;
        let overflow_count = info.member("overflow_count")?.parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Shared {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let remotes = info.member("remotes")?.parse(ctx)?;
        let config = info.member("config")?.parse(ctx)?;
        let inject_len = info.member("inject")?.parse(ctx)?;
        let idle: Idle = info.member("idle")?.parse(ctx)?;
        let owned = info.member("owned")?.parse(ctx)?;
        let scheduler_metrics = info.member("scheduler_metrics")?.parse(ctx)?;
        let worker_metrics = info.member("worker_metrics")?.parse(ctx)?;

        let synced: Synced = info.member("synced")?.member("data")?.parse(ctx)?;
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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Remote {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let steal = info
            .member("steal")?
            .deref_ptr(ctx)?
            .member("data")?
            .parse(ctx)?;
        let unpark = info.member("unpark")?.parse(ctx)?;

        Ok(Self { steal, unpark })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Idle {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        const UNPARK_SHIFT: u64 = 16;
        const UNPARK_MASK: u64 = !SEARCH_MASK;
        const SEARCH_MASK: u64 = (1 << UNPARK_SHIFT) - 1;

        let num_workers = info.member("num_workers")?.parse(ctx)?;
        let state: u64 = info.member("state")?.parse(ctx)?;
        let num_searching = state & SEARCH_MASK;
        let num_unparked = (state & UNPARK_MASK) >> UNPARK_SHIFT;

        Ok(Self {
            num_workers,
            num_searching,
            num_unparked,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for OwnedTasks {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let closed = info.member("closed")?.parse(ctx)?;

        let list_info = info.member("list")?;
        let added = list_info.member("added")?.parse(ctx)?;
        let count = list_info.member("count")?.parse(ctx)?;
        let shard_mask = list_info.member("shard_mask")?.parse(ctx)?;

        let mut tasks = HashMap::new();

        list_info.member("lists")?.boxed_slice_elements(ctx, |i| {
            if let Some(mut head_ptr) = i
                .member("data")?
                .member("head")?
                .try_select_variant("Some")?
                .map(|i| i.to_owned())
            {
                loop {
                    let addr: TaskAddr = head_ptr.parse(ctx)?;
                    let task_info = head_ptr.deref_ptr(ctx)?;
                    let task = task_info.parse(ctx)?;
                    tasks.insert(addr, task);

                    // The owned list is threaded through the task Trailer's
                    // `owned: linked_list::Pointers<Header>`, reached via the
                    // vtable's trailer_offset. `Header.queue_next` is the
                    // inject-queue link, and is None for a parked task.
                    let vtable_info = task_info.member("vtable")?.deref_ptr(ctx)?;
                    let trailer_offset: u64 = vtable_info.member("trailer_offset")?.parse(ctx)?;
                    let trailer_addr = addr.0 + trailer_offset;

                    let trailer_ty = ctx.ctf.get(ctx.tokio_info.trailer_id);
                    let trailer_buf = ctx.proc.read_bytes(trailer_addr, trailer_ty.size())?;
                    let trailer_info = TypeInfoRef::new(trailer_ty, trailer_addr, &trailer_buf);

                    let Some(next_info) = trailer_info
                        .member("owned")?
                        .member("next")?
                        .try_select_variant("Some")?
                    else {
                        break;
                    };
                    head_ptr = next_info.to_owned();
                }
            }

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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for TaskAddr {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let addr = info.parse(ctx)?;
        if !ctx.mappings.contains_addr(addr) {
            return Err(Error::invalid_addr(addr));
        }
        Ok(Self(addr))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Synced {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let idle_sleepers = info
            .member("idle")?
            .parse::<Vec<u64>, _>(ctx)?
            .into_iter()
            .collect();

        let inject_info = info.member("inject")?;
        let inject_closed = inject_info.member("is_closed")?.parse(ctx)?;

        let inject_head = inject_info
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;

        let inject_tail = inject_info
            .member("tail")?
            .try_select_variant("Some")?
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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Inject {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let len = info.member("len")?.parse(ctx)?;
        Ok(Inject { len })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Config {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let global_queue_interval = info.member("global_queue_interval")?.parse(ctx)?;
        let event_interval = info.member("event_interval")?.parse(ctx)?;
        let disable_lifo_slot = info.member("disable_lifo_slot")?.parse(ctx)?;

        Ok(Self {
            global_queue_interval,
            event_interval,
            disable_lifo_slot,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for SchedulerMetrics {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let remote_schedule_count = info.member("remote_schedule_count")?.parse(ctx)?;
        let budget_forced_yield_count = info.member("budget_forced_yield_count")?.parse(ctx)?;

        Ok(Self {
            remote_schedule_count,
            budget_forced_yield_count,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for WorkerMetrics {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let busy_duration_total = info.member("busy_duration_total")?.parse(ctx)?;
        let queue_depth = info.member("queue_depth")?.parse(ctx)?;
        let thread_id = info.member("thread_id")?.member("data")?.parse(ctx)?;
        let park_count = info.member("park_count")?.parse(ctx)?;
        let park_unpark_count = info.member("park_unpark_count")?.parse(ctx)?;
        let noop_count = info.member("noop_count")?.parse(ctx)?;
        let steal_count = info.member("steal_count")?.parse(ctx)?;
        let steal_operations = info.member("steal_operations")?.parse(ctx)?;
        let poll_count = info.member("poll_count")?.parse(ctx)?;
        let mean_poll_time = info.member("mean_poll_time")?.parse(ctx)?;
        let local_schedule_count = info.member("local_schedule_count")?.parse(ctx)?;
        let overflow_count = info.member("overflow_count")?.parse(ctx)?;

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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for TaskQueue {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let head: u64 = info.member("head")?.parse(ctx)?;
        let tail: u32 = info.member("tail")?.parse(ctx)?;

        let buf_info = info.member("buffer")?.deref_ptr(ctx)?;

        let real_head = (head & u32::MAX as u64) as u32;
        let len = tail.wrapping_sub(real_head) as usize;

        let mut tasks = Vec::with_capacity(len);

        for elem_info in buf_info.as_ref().array_elements()?.take(len) {
            let task_ptr = elem_info.member("value")?.parse(ctx)?;
            tasks.push(task_ptr);
        }

        Ok(TaskQueue { head, tail, tasks })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for TaskHeader {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let state = info.member("state")?.parse(ctx)?;
        let runtime_id = info.member("owner_id")?.parse(ctx)?;

        let vtable_info = info.member("vtable")?.deref_ptr(ctx)?;

        let id_offset: u64 = vtable_info.member("id_offset")?.parse(ctx)?;
        let id_addr = info.addr + id_offset;
        let id_bytes = ctx.proc.read_bytes(id_addr, size_of::<u64>() as u64)?;
        let id = u64::from_le_bytes(id_bytes.try_into().unwrap());

        // This is the offset from the Header address to the address of
        // `spawn_location`.
        let spawn_offset: u64 = vtable_info.member("spawn_location_offset")?.parse(ctx)?;
        let spawn_ptr_addr = info.addr + spawn_offset;
        let spawn_ptr = ctx
            .proc
            .read_u64(spawn_ptr_addr)
            .map_err(|e| Error::invalid_addr(spawn_ptr_addr).with_source(e))?;

        // The CTF isn't aware we have a *Location here, so manually find the type and parse.
        let spawn_ty = ctx.ctf.get(ctx.tokio_info.location_id);
        let spawn_buf = ctx.proc.read_bytes(spawn_ptr, spawn_ty.size())?;
        let spawn_info = info.clone().with_ty(spawn_ty).with_buf(&spawn_buf);
        let spawn_location = spawn_info.parse(ctx)?;

        // This is the offset from the Header address to the address of the
        // `Trailer` of the task.
        let trailer_offset: u64 = vtable_info.member("trailer_offset")?.parse(ctx)?;
        let trailer_ptr = info.addr + trailer_offset;

        let trailer_ty = ctx.ctf.get(ctx.tokio_info.trailer_id);
        let trailer_buf = ctx.proc.read_bytes(trailer_ptr, trailer_ty.size())?;
        let trailer_info = info.clone().with_ty(trailer_ty).with_buf(&trailer_buf);
        let waker = trailer_info.member("waker")?.parse(ctx)?;

        Ok(TaskHeader {
            state,
            runtime_id,
            id,
            spawn_location,
            waker,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Location {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let filename = info.member("filename")?.parse(ctx)?;
        let line = info.member("line")?.parse(ctx)?;
        let col = info.member("col")?.parse(ctx)?;

        Ok(Self {
            filename,
            line,
            col,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for DriverHandle {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let io = info.member("io")?.parse(ctx)?;
        let time = info.member("time")?.select_variant("Some")?.parse(ctx)?;
        let clock = info.member("clock")?.member("data")?.parse(ctx)?;

        Ok(Self { io, time, clock })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for IoHandle {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        match info.active_variant()? {
            ("Enabled", info) => {
                let inner = info.parse(ctx)?;
                Ok(IoHandle::Enabled(inner))
            }
            ("Disabled", info) => {
                let inner = info.parse(ctx)?;
                Ok(IoHandle::Disabled(inner))
            }
            (other, info) => Err(Error::no_enumerator(
                info.ty.name().to_string(),
                other.to_string(),
            )),
        }
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for IoEnabled {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let num_pending_release = info.member("registrations")?.parse(ctx)?;
        let metrics = info.member("metrics")?.parse(ctx)?;
        let waker_fd = info.member("waker")?.parse(ctx)?;
        let synced = info.member("synced")?.member("data")?.parse(ctx)?;
        let poll_fd = info.member("registry")?.parse(ctx)?;

        Ok(Self {
            num_pending_release,
            waker_fd,
            poll_fd,
            metrics,
            synced,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for IoDisabled {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let park = info.deref_ptr(ctx)?.member("data")?.parse(ctx)?;

        Ok(Self { park })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for IoSynced {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let is_shutdown = info.member("is_shutdown")?.parse(ctx)?;
        let mut registrations = Vec::new();
        if let Some(mut head_info) = info
            .member("registrations")?
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr(ctx))
            .transpose()?
        {
            loop {
                let sched = head_info.parse(ctx)?;
                registrations.push(sched);

                let Some(next) = head_info
                    .member("linked_list_pointers")?
                    .member("next")?
                    .try_select_variant("Some")?
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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for ScheduledIo {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let readiness = info.member("readiness")?.parse(ctx)?;
        let waiters = info.member("waiters")?.member("data")?.parse(ctx)?;

        Ok(Self { readiness, waiters })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Ready {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let inner = info.parse(ctx)?;
        Ok(Self(inner))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Waiters {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let mut list = Vec::new();
        if let Some(mut head_info) = info
            .member("list")?
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr(ctx))
            .transpose()?
        {
            loop {
                let waiter = head_info.parse(ctx)?;
                list.push(waiter);

                let Some(next) = head_info
                    .member("pointers")?
                    .member("next")?
                    .try_select_variant("Some")?
                    .map(|i| i.deref_ptr(ctx))
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
            .map(|i| i.parse(ctx))
            .transpose()?;

        let writer = info
            .member("writer")?
            .try_select_variant("Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;

        Ok(Self {
            list,
            reader,
            writer,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Waiter {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let interest = info.member("interest")?.parse(ctx)?;
        let is_ready = info.member("is_ready")?.parse(ctx)?;

        let waker = info
            .member("waker")?
            .try_select_variant("Some")?
            .map(|info| info.parse(ctx))
            .transpose()?;

        Ok(Self {
            interest,
            is_ready,
            waker,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Interest {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let inner = info.parse(ctx)?;
        Ok(Self(inner))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Waker {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let data = info.member("data")?.parse(ctx)?;
        let vtable_info = info.member("vtable")?.deref_ptr(ctx)?;

        let wake_addr = vtable_info.member("wake")?.parse(ctx)?;
        let wake_by_ref_addr = vtable_info.member("wake_by_ref")?.parse(ctx)?;
        let clone_addr = vtable_info.member("clone")?.parse(ctx)?;
        let drop_addr = vtable_info.member("drop")?.parse(ctx)?;

        let wake = ctx.lookup_symbol(wake_addr);
        let wake_by_ref = ctx.lookup_symbol(wake_by_ref_addr);
        let clone = ctx.lookup_symbol(clone_addr);
        let drop = ctx.lookup_symbol(drop_addr);

        let dependent_task = if wake == "tokio::runtime::task::waker::wake_by_val" {
            let hdr_info = info
                .member("data")?
                .with_ty(ctx.ctf.get(ctx.tokio_info.header_id));
            let hdr = hdr_info.parse(ctx)?;
            Some(hdr)
        } else {
            None
        };

        let dependent_park = if wake == "tokio::runtime::park::wake" {
            let park_info = info
                .member("data")?
                .with_ty(ctx.ctf.get(ctx.tokio_info.park_id));
            let park = park_info.deref_ptr(ctx)?.member("data")?.parse(ctx)?;
            Some(park)
        } else {
            None
        };

        Ok(Self {
            dependent_task,
            dependent_park,
            data,
            wake,
            wake_by_ref,
            clone,
            drop,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for ParkThread {
    fn parse_with_ctf(
        ctx: &Context<'ctf>,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let state = info.member("state")?.parse(ctx)?;
        Ok(Self(state))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for IoDriverMetrics {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let fd_registered_count = info.member("fd_registered_count")?.parse(ctx)?;
        let fd_deregistered_count = info.member("fd_deregistered_count")?.parse(ctx)?;
        let ready_count = info.member("ready_count")?.parse(ctx)?;

        Ok(Self {
            fd_registered_count,
            fd_deregistered_count,
            ready_count,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for TimeHandle {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let time_source = info.member("time_source")?.parse(ctx)?;

        let mut inner = info.member("inner")?;
        if ctx.tokio_info.tokio_version >= Version::new(1, 49, 0) {
            inner = inner.select_variant("Traditional")?;
        }

        let is_shutdown = inner.member("is_shutdown")?.parse(ctx)?;
        let did_wake = inner.member("did_wake")?.parse(ctx)?;

        let state_info = inner.member("state")?.member("data")?;

        let wheel = state_info.member("wheel")?.parse(ctx)?;
        let next_wake = state_info.member("next_wake")?.parse(ctx)?;

        Ok(Self {
            is_shutdown,
            did_wake,
            time_source,
            wheel,
            next_wake,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for RawInstant {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let tv_sec = info.member("tv_sec")?.parse(ctx)?;
        let tv_nsec = info.member("tv_nsec")?.parse(ctx)?;

        Ok(Self { tv_sec, tv_nsec })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Clock {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let base = info.member("base")?.parse(ctx)?;
        let unfrozen = info.member("unfrozen")?.parse(ctx)?;
        let enable_pausing = info.member("enable_pausing")?.parse(ctx)?;

        Ok(Self {
            base,
            unfrozen,
            enable_pausing,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for Wheel {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let elapsed = info.member("elapsed")?.parse(ctx)?;

        let levels_info = info.member("levels")?.deref_ptr(ctx)?;
        let mut levels = Vec::with_capacity(6);

        let time_ctx = TimeContext { elapsed, ctx };

        for elem_info in levels_info.array_elements()? {
            let level = elem_info.parse(&time_ctx)?;
            levels.push(level);
        }

        let mut pending = Vec::new();
        if let Some(mut head_info) = info
            .member("pending")?
            .member("head")?
            .try_select_variant("Some")?
            .map(|i| i.deref_ptr(ctx))
            .transpose()?
        {
            loop {
                let timer = head_info.parse(&time_ctx)?;
                pending.push(timer);

                let Some(next) = head_info
                    .member("pointers")?
                    .member("next")?
                    .try_select_variant("Some")?
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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, TimeContext<'ctf>> for Level {
    fn parse_with_ctf(
        time_ctx: &TimeContext,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let TimeContext { ctx, .. } = *time_ctx;
        let level = info.member("level")?.parse(ctx)?;
        let occupied = info.member("occupied")?.parse(ctx)?;

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
                .map(|i| i.deref_ptr(ctx))
                .transpose()?
            {
                loop {
                    let timer = head_info.parse(time_ctx)?;
                    slot_timers.timers.push(timer);

                    let Some(next) = head_info
                        .member("pointers")?
                        .member("next")?
                        .try_select_variant("Some")?
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

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, TimeContext<'ctf>> for TimerShared {
    fn parse_with_ctf(
        time_ctx: &TimeContext,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let TimeContext { elapsed, ctx } = *time_ctx;

        let registered_when = info.member("registered_when")?.parse(ctx)?;
        let state_info = info.member("state")?;
        let time_state = state_info.member("state")?.parse(ctx)?;
        let result = state_info.member("result")?.active_variant()?.0.to_string();

        let waker_info = state_info.member("waker")?;
        let waker_state = waker_info.member("state")?.parse(ctx)?;
        let waker = waker_info
            .member("waker")?
            .try_select_variant("Some")?
            .map(|i| i.parse(ctx))
            .transpose()?;

        let time_remaining = if registered_when >= elapsed {
            Some(Duration::from_millis(registered_when - elapsed))
        } else {
            None
        };

        Ok(Self {
            registered_when,
            time_state,
            dur_remaining: time_remaining,
            result,
            waker_state,
            waker,
        })
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for TimerState {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let inner = info.parse(ctx)?;

        Ok(Self(inner))
    }
}

impl<'ctf> ParseWithCtf<'ctf, CtfType<'ctf>, Context<'ctf>> for WakerState {
    fn parse_with_ctf(
        ctx: &Context,
        info: &TypeInfoRef<'_, 'ctf, CtfType<'ctf>>,
    ) -> reify::Result<Self> {
        let inner = info.parse(ctx)?;

        Ok(Self(inner))
    }
}

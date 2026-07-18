// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! DWARF-based load methods for Tokio runtime types.

use crate::debugger::Dbg;
use anyhow::{Context, Result, bail};
use debugdb::load::Load;
use debugdb::value::{Enum, Pointer, Struct, Value};

use std::collections::BTreeSet;
use std::time::Duration;

use super::{
    Budget, Clock, Config, DriverHandle, EnterRuntime, Idle, Inject, Interest, IoDisabled,
    IoDriverMetrics, IoEnabled, IoHandle, IoSynced, Level, Location, MetricsBatch, OwnedTasks,
    ParkThread, Parker, RawInstant, Ready, Remote, ScheduledIo, Scheduler, SchedulerMetrics,
    Shared, Synced, TaskAddr, TaskHeader, TaskQueue, ThreadCtx, TimeHandle, TimerShared, TimerSlot,
    TimerState, Waiter, Waiters, Waker, WakerState, Wheel, WorkerCore, WorkerMetrics, WorkerState,
    WorkerStats,
};

impl WorkerCore {
    pub fn load(dbg: &Dbg, core: &Struct) -> Result<Self> {
        let tick = core
            .unique_member_named("tick")
            .and_then(|v| v.u32_value())
            .context("failed to load tick")?;

        let global_queue_interval = core
            .unique_member_named("global_queue_interval")
            .and_then(|v| v.u32_value())
            .context("failed to load global_queue_interval")?;

        let lifo_enabled = core
            .unique_member_named("lifo_enabled")
            .and_then(|v| v.bool_value())
            .context("failed to load lifo_enabled")?;

        let lifo_slot = load_option(core, "lifo_slot", load_task_addr_from_notified)
            .context("failed to load lifo_slot")?;

        let run_queue_struct = core
            .unique_member_named("run_queue")
            .and_then(|v| v.as_struct())
            .context("failed to load run_queue")?;
        let run_queue =
            TaskQueue::load(dbg, run_queue_struct).context("failed to load TaskQueue")?;

        let is_searching = core
            .unique_member_named("is_searching")
            .and_then(|v| v.bool_value())
            .context("failed to load is_searching")?;

        let is_shutdown = core
            .unique_member_named("is_shutdown")
            .and_then(|v| v.bool_value())
            .context("failed to load is_shutdown")?;

        let is_traced = core
            .unique_member_named("is_traced")
            .and_then(|v| v.bool_value())
            .context("failed to load is_traced")?;

        let park =
            load_option(core, "park", |s| Parker::load(dbg, s)).context("failed to load park")?;

        let stats_struct = core
            .unique_member_named("stats")
            .and_then(|v| v.as_struct())
            .context("failed to load stats")?;
        let stats = WorkerStats::load(dbg, stats_struct).context("failed to load WorkerStats")?;

        Ok(Self {
            tick,
            global_queue_interval,
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

impl ThreadCtx {
    /// Load from a `tokio::runtime::context::Context` DWARF struct.
    ///
    /// The `scheduler` field is a pointer to the scheduler context enum.
    /// If it's null, the thread doesn't have an active scheduler (no
    /// worker_index, worker_core, or defer).
    pub fn load(dbg: &Dbg, ctx: &Struct) -> Result<Self> {
        let current_task_id =
            Self::load_current_task_id(ctx).context("failed to load current_task_id")?;

        let thread_id =
            Self::load_cell_option_u64(ctx, "thread_id").context("failed to load thread_id")?;

        let runtime_enum = ctx
            .unique_member_named("runtime")
            .and_then(|v| v.as_struct()) // Cell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_enum())
            .context("failed to load runtime")?;
        let runtime =
            EnterRuntime::load_from_enum(runtime_enum).context("failed to load EnterRuntime")?;

        let budget_struct = ctx
            .unique_member_named("budget")
            .and_then(|v| v.as_struct()) // Cell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // coop::Budget
            .context("failed to load budget")?;
        let budget = Budget::load(budget_struct).context("failed to load Budget")?;

        // scheduler is a pointer to the scheduler context enum.
        // If null, this thread has no active scheduler.
        let sched_ptr = ctx
            .unique_member_named("scheduler")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("inner"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_pointer());

        let Some(sched_ptr) = sched_ptr else {
            return Ok(Self {
                current_task_id,
                thread_id,
                worker_index: None,
                worker_core: None,
                defer: Vec::new(),
                runtime,
                budget,
            });
        };

        if sched_ptr.value == 0 {
            return Ok(Self {
                current_task_id,
                thread_id,
                worker_index: None,
                worker_core: None,
                defer: Vec::new(),
                runtime,
                budget,
            });
        }

        let sched_val = sched_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref scheduler pointer")?;
        let sched_enum = sched_val
            .as_enum()
            .context("scheduler context is not an enum")?;

        // Only handle MultiThread for now
        if sched_enum.disc != "MultiThread" {
            return Ok(Self {
                current_task_id,
                thread_id,
                worker_index: None,
                worker_core: None,
                defer: Vec::new(),
                runtime,
                budget,
            });
        }

        let worker_ctx = sched_enum
            .value
            .newtype_value()
            .and_then(|v| v.as_struct())
            .context("failed to extract MultiThread worker context")?;

        // Load worker_index from worker: Arc<Worker> -> data -> index
        let worker_index =
            Self::load_worker_index(dbg, worker_ctx).context("failed to load worker_index")?;

        // Load worker_core from core: RefCell<Option<Box<Core>>>
        let worker_core =
            Self::load_worker_core(dbg, worker_ctx).context("failed to load worker_core")?;

        let defer = Self::load_defer(dbg, worker_ctx).context("failed to load defer")?;

        Ok(Self {
            current_task_id,
            thread_id,
            worker_index,
            worker_core,
            defer,
            runtime,
            budget,
        })
    }

    /// Load `current_task_id` from `Cell<Option<Id>>`.
    fn load_current_task_id(ctx: &Struct) -> Result<Option<u64>> {
        let option_enum = ctx
            .unique_member_named("current_task_id")
            .and_then(|v| v.as_struct()) // Cell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_enum()) // Option<Id>
            .context("failed to navigate to current_task_id")?;

        match option_enum.disc.as_str() {
            "None" => Ok(None),
            "Some" => {
                // Id -> NonZero<u64> -> NonZeroU64Inner -> u64
                let id = option_enum
                    .value
                    .newtype_value() // Id
                    .and_then(|v| v.as_struct())
                    .and_then(|s| s.newtype_value()) // NonZero<u64>
                    .and_then(|v| v.as_struct())
                    .and_then(|s| s.newtype_value()) // NonZeroU64Inner
                    .and_then(|v| v.as_struct())
                    .and_then(|s| s.newtype_value()) // u64
                    .and_then(|v| v.u64_value())
                    .context("failed to extract task id")?;
                Ok(Some(id))
            }
            other => bail!("unexpected current_task_id variant: {other}"),
        }
    }

    /// Load an `Option<u64>` from a `Cell<Option<NonZeroU64>>` field.
    ///
    /// Cell -> UnsafeCell -> value (Option enum)
    /// The inner value may be wrapped in newtype layers (e.g. ThreadId,
    /// NonZero<u64>).
    fn load_cell_option_u64(ctx: &Struct, field: &str) -> Result<Option<u64>> {
        let option_enum = ctx
            .unique_member_named(field)
            .and_then(|v| v.as_struct()) // Cell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_enum())
            .with_context(|| format!("failed to navigate to {field}"))?;

        match option_enum.disc.as_str() {
            "None" => Ok(None),
            "Some" => {
                // Unwrap newtype layers until we find a u64
                let mut val = option_enum.value.newtype_value();
                for _ in 0..10 {
                    let Some(v) = val else { break };
                    if let Some(n) = v.u64_value() {
                        return Ok(Some(n));
                    }
                    val = v.as_struct().and_then(|s| s.newtype_value());
                }
                bail!("failed to extract u64 from {field}")
            }
            other => bail!("unexpected {field} variant: {other}"),
        }
    }

    /// Load worker_index from worker: Arc<Worker> -> data -> index
    fn load_worker_index(dbg: &Dbg, worker_ctx: &Struct) -> Result<Option<u64>> {
        let worker_ptr = match arc_field_ptr(worker_ctx, "worker") {
            Some(ptr) => ptr,
            None => return Ok(None),
        };

        if worker_ptr.value == 0 {
            return Ok(None);
        }

        let arc_inner = worker_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref Arc<Worker>")?;
        let worker = arc_inner_data(&arc_inner).context("failed to navigate to Worker data")?;
        let index = worker
            .unique_member_named("index")
            .and_then(|v| v.u64_value())
            .context("failed to load index")?;
        Ok(Some(index))
    }

    /// Load worker_core from `RefCell<Option<Box<Core>>>`.
    fn load_worker_core(dbg: &Dbg, worker_ctx: &Struct) -> Result<Option<WorkerCore>> {
        let option_enum = worker_ctx
            .unique_member_named("core")
            .and_then(|v| v.as_struct()) // RefCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_enum()); // Option<Box<Core>>

        let Some(option_enum) = option_enum else {
            return Ok(None);
        };

        match option_enum.disc.as_str() {
            "None" => Ok(None),
            "Some" => {
                let box_ptr = option_enum
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_pointer())
                    .context("failed to extract Box<Core> pointer")?;
                let core_val = box_ptr
                    .deref(dbg.segments(), &dbg.db)
                    .context("failed to deref Box<Core>")?;
                let core_struct = core_val.as_struct().context("Core is not a struct")?;
                let core =
                    WorkerCore::load(dbg, core_struct).context("failed to load WorkerCore")?;
                Ok(Some(core))
            }
            other => bail!("unexpected core variant: {other}"),
        }
    }

    /// Load defer `Vec<Waker>` from `Cell<Vec<Waker>>`.
    fn load_defer(dbg: &Dbg, worker_ctx: &Struct) -> Result<Vec<Waker>> {
        let vec_struct = worker_ctx
            .unique_member_named("defer")
            .and_then(|v| v.as_struct()) // Cell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()); // Vec<Waker>

        let Some(vec_struct) = vec_struct else {
            return Ok(Vec::new());
        };

        let len = vec_struct
            .unique_member_named("len")
            .and_then(|v| v.u64_value())
            .unwrap_or(0);

        if len == 0 {
            return Ok(Vec::new());
        }

        let buf_ptr = vec_struct
            .unique_member_named("buf")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("ptr"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("pointer"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("pointer"))
            .and_then(|v| v.as_pointer())
            .context("failed to navigate defer Vec buffer pointer")?;

        let array_val = buf_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref defer Vec buffer")?;

        let Value::Array(elements) = &array_val else {
            bail!("defer buffer is not an array");
        };

        let mut wakers = Vec::with_capacity(len as usize);
        for (i, elem) in elements.iter().take(len as usize).enumerate() {
            let waker_struct = elem
                .as_struct()
                .with_context(|| format!("defer[{i}] is not a struct"))?;
            let waker = Waker::load(dbg, waker_struct)
                .with_context(|| format!("failed to load defer[{i}]"))?;
            wakers.push(waker);
        }

        Ok(wakers)
    }
}

impl WorkerState {
    pub fn load(dbg: &Dbg, ctx: &Struct) -> Result<Self> {
        let thd_ctx = ThreadCtx::load(dbg, ctx).context("failed to load ThreadCtx")?;
        Ok(Self {
            thd_ctx,
            backtrace: None,
        })
    }
}

/// Extract a `TaskAddr` from a `Notified<T>` struct.
///
/// Navigate: `Notified (newtype) -> Task -> raw (RawTask) -> ptr (NonNull)
/// -> pointer`
fn load_task_addr_from_notified(notified: &Struct) -> Result<TaskAddr> {
    let ptr_val = notified
        .newtype_value()
        .and_then(|v| v.as_struct()) // Task
        .and_then(|s| s.unique_member_named("raw"))
        .and_then(|v| v.as_struct()) // RawTask
        .and_then(|s| s.unique_member_named("ptr"))
        .and_then(|v| v.as_struct()) // NonNull
        .and_then(|s| s.unique_member_named("pointer"))
        .and_then(|v| v.pointer_value())
        .context("failed to extract task address from Notified")?;
    Ok(TaskAddr(ptr_val))
}

impl TaskQueue {
    /// Load from a `queue::Local<T>`.
    ///
    /// Navigate through `Local -> inner: Arc<Inner<T>>` to reach the
    /// `Inner` struct, then extract head and tail from their atomics.
    pub fn load(dbg: &Dbg, local: &Struct) -> Result<Self> {
        let arc_ptr =
            arc_field_ptr(local, "inner").context("failed to navigate to Arc<Inner> pointer")?;

        let arc_inner_val = arc_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref Arc<Inner>")?;

        let inner = arc_inner_data(&arc_inner_val).context("failed to navigate to Inner data")?;
        let head = core_atomic_u64(inner, "head").context("failed to load head")?;
        let tail = loom_atomic_u32(inner, "tail").context("failed to load tail")?;

        let real_head = (head & 0xFFFF_FFFF) as u32;
        let tasks =
            Self::load_buffer(dbg, inner, real_head, tail).context("failed to load buffer")?;

        Ok(Self { head, tail, tasks })
    }

    /// Load initialized tasks from the ring buffer.
    ///
    /// The buffer is `Box<[UnsafeCell<MaybeUninit<Notified<T>>>; 256]>`.
    fn load_buffer(dbg: &Dbg, inner: &Struct, real_head: u32, tail: u32) -> Result<Vec<TaskAddr>> {
        const LOCAL_QUEUE_CAPACITY: u32 = 256;
        const MASK: u32 = LOCAL_QUEUE_CAPACITY - 1;

        let len = tail.wrapping_sub(real_head);
        if len == 0 {
            return Ok(Vec::new());
        }

        let box_ptr =
            Self::buffer_box_ptr(inner).context("failed to navigate to buffer Box pointer")?;

        let array_val = box_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref buffer Box")?;
        let Value::Array(elements) = &array_val else {
            bail!("buffer is not an array");
        };

        let mut tasks = Vec::with_capacity(len as usize);
        for i in 0..len {
            let idx = (real_head.wrapping_add(i) & MASK) as usize;
            let element = elements.get(idx).context("buffer index out of bounds")?;

            let ptr_val = raw_task_ptr(element)
                .with_context(|| format!("failed to extract RawTask from buffer[{idx}]"))?;

            tasks.push(TaskAddr(ptr_val));
        }

        Ok(tasks)
    }

    /// Navigate to the buffer `Box` pointer in `Inner`.
    fn buffer_box_ptr(inner: &Struct) -> Option<&Pointer> {
        inner.unique_member_named("buffer")?.as_pointer()
    }
}

/// Extract a `RawTask` pointer from a buffer element.
///
/// `UnsafeCell<MaybeUninit<Notified<T>>>` -> ... -> `NonNull<Header>`
fn raw_task_ptr(element: &Value) -> Option<u64> {
    element
        .as_struct()? // UnsafeCell
        .unique_member_named("value")?
        .as_struct()? // MaybeUninit
        .unique_member_named("value")?
        .as_struct()? // ManuallyDrop
        .unique_member_named("value")?
        .as_struct()? // Notified (transparent)
        .newtype_value()?
        .as_struct()? // Task
        .unique_member_named("raw")?
        .as_struct()? // RawTask
        .unique_member_named("ptr")?
        .as_struct()? // NonNull
        .unique_member_named("pointer")?
        .pointer_value()
}

impl Parker {
    /// Load from a `Parker` struct.
    ///
    /// Navigate through `Parker -> inner: Arc<Inner>` to reach the
    /// `Inner` struct, then extract `state` from its loom atomic.
    pub fn load(dbg: &Dbg, parker: &Struct) -> Result<Self> {
        let arc_ptr =
            arc_field_ptr(parker, "inner").context("failed to navigate to Arc<Inner> pointer")?;

        let arc_inner_val = arc_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref Arc<Inner>")?;
        let inner = arc_inner_data(&arc_inner_val).context("failed to navigate to Inner data")?;

        let state_val = loom_atomic_u64(inner, "state").context("failed to load state")?;

        Ok(Parker(state_val))
    }
}

impl WorkerStats {
    pub fn load(_dbg: &Dbg, stats: &Struct) -> Result<Self> {
        let batch_struct = stats
            .unique_member_named("batch")
            .and_then(|v| v.as_struct())
            .context("failed to load batch")?;
        let batch = MetricsBatch::load(batch_struct).context("failed to load MetricsBatch")?;

        let tasks_polled_in_batch = stats
            .unique_member_named("tasks_polled_in_batch")
            .and_then(|v| v.u64_value())
            .context("failed to load tasks_polled_in_batch")?;

        let task_poll_time_ewma = stats
            .unique_member_named("task_poll_time_ewma")
            .and_then(|v| v.f64_value())
            .context("failed to load task_poll_time_ewma")?;

        Ok(Self {
            batch,
            tasks_polled_in_batch,
            task_poll_time_ewma,
        })
    }
}

impl MetricsBatch {
    pub fn load(batch: &Struct) -> Result<Self> {
        let busy_duration_total = u64_field(batch, "busy_duration_total")?;

        let processing_scheduled_tasks_started_at =
            load_option(batch, "processing_scheduled_tasks_started_at", |s| {
                RawInstant::load_from_struct(s)
            })
            .context("failed to load processing_scheduled_tasks_started_at")?;

        let park_count = u64_field(batch, "park_count")?;
        let park_unpark_count = u64_field(batch, "park_unpark_count")?;
        let noop_count = u64_field(batch, "noop_count")?;
        let steal_count = u64_field(batch, "steal_count")?;
        let steal_operations = u64_field(batch, "steal_operations")?;
        let poll_count = u64_field(batch, "poll_count")?;
        let poll_count_on_last_park = u64_field(batch, "poll_count_on_last_park")?;
        let local_schedule_count = u64_field(batch, "local_schedule_count")?;
        let overflow_count = u64_field(batch, "overflow_count")?;

        Ok(Self {
            busy_duration_total,
            processing_scheduled_tasks_started_at,
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

impl RawInstant {
    /// Load from `std::time::Instant`.
    ///
    /// On illumos, the DWARF layout is:
    /// `Instant` -> `t` (`sys::Instant`) -> `t` (`Timespec`)
    ///   -> `tv_sec` / `tv_nsec`
    fn load_from_struct(s: &Struct) -> Result<Self> {
        let timespec =
            Self::navigate_to_timespec(s).context("failed to navigate Instant to Timespec")?;

        let tv_sec = timespec
            .unique_member_named("tv_sec")
            .and_then(|v| v.i64_value())
            .map(|v| v as u64)
            .context("failed to load tv_sec")?;

        let tv_nsec = timespec
            .unique_member_named("tv_nsec")
            .and_then(|v| v.as_struct())
            .and_then(|v| v.newtype_value())
            .and_then(|v| v.u32_value())
            .context("failed to load tv_nsec")?;

        Ok(Self { tv_sec, tv_nsec })
    }

    fn navigate_to_timespec(s: &Struct) -> Option<&Struct> {
        s.newtype_value()?
            .as_struct()?
            .unique_member_named("t")?
            .as_struct()
    }
}

impl EnterRuntime {
    pub fn load_from_enum(e: &Enum) -> Result<Self> {
        match e.disc.as_str() {
            "Entered" => {
                let allow_block_in_place = e
                    .value
                    .unique_member_named("allow_block_in_place")
                    .and_then(|v| v.bool_value())
                    .context("failed to load allow_block_in_place")?;
                Ok(Self::Entered {
                    allow_block_in_place,
                })
            }
            "NotEntered" => Ok(Self::NotEntered),
            other => bail!("unexpected EnterRuntime variant: {other}"),
        }
    }
}

impl Budget {
    pub fn load(s: &Struct) -> Result<Self> {
        // coop::Budget is a tuple struct: Budget(Option<u8>)
        // Try newtype unwrap first (__0), then named field
        let e = s
            .newtype_value()
            .and_then(|v| v.as_enum())
            .context("failed to navigate Budget inner")?;
        let inner = match e.disc.as_str() {
            "None" => None,
            "Some" => {
                let val = e
                    .value
                    .newtype_value()
                    .and_then(|v| {
                        if let Value::Base(debugdb::value::Base::U8(b)) = v {
                            Some(*b)
                        } else {
                            None
                        }
                    })
                    .context("failed to extract u8 from budget")?;
                Some(val)
            }
            other => bail!("unexpected budget variant: {other}"),
        };
        Ok(Self(inner))
    }

    /// Load from an Option enum that's already been unwrapped from a Cell.
    pub fn load_from_enum(e: &Enum) -> Result<Self> {
        match e.disc.as_str() {
            "None" => Ok(Self(None)),
            "Some" => {
                let val = e
                    .value
                    .newtype_value()
                    .and_then(|v| {
                        if let Value::Base(debugdb::value::Base::U8(b)) = v {
                            Some(*b)
                        } else {
                            None
                        }
                    })
                    .context("failed to extract u8 from budget")?;
                Ok(Self(Some(val)))
            }
            other => bail!("unexpected budget variant: {other}"),
        }
    }
}

impl Scheduler {
    /// Load from a scheduler handle struct that already has `shared` and
    /// `driver` fields.
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let shared_struct = s
            .unique_member_named("shared")
            .and_then(|v| v.as_struct())
            .context("failed to load shared")?;
        let shared = Shared::load(dbg, shared_struct).context("failed to load Shared")?;

        let driver_struct = s
            .unique_member_named("driver")
            .and_then(|v| v.as_struct())
            .context("failed to load driver")?;
        let driver =
            DriverHandle::load(dbg, driver_struct).context("failed to load DriverHandle")?;

        Ok(Self { shared, driver })
    }

    /// Load the Scheduler by navigating from a
    /// `tokio::runtime::context::Context` struct loaded from `context_addr`.
    ///
    /// Navigates: `Context -> current -> handle -> value -> Some ->
    /// MultiThread -> deref Arc -> data`
    pub fn load_from_context(dbg: &Dbg, context: &Struct) -> Result<Self> {
        let handle_ptr = context
            .unique_member_named("current")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("handle"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_enum())
            .context("failed to navigate to scheduler handle")?;

        if handle_ptr.disc == "None" {
            bail!("scheduler handle is None");
        }

        let sched_enum = handle_ptr
            .value
            .newtype_value()
            .and_then(|v| v.as_enum())
            .context("failed to extract scheduler enum")?;

        if sched_enum.disc != "MultiThread" {
            bail!("unsupported scheduler variant: {}", sched_enum.disc);
        }

        let arc_ptr = sched_enum
            .value
            .newtype_value()
            .and_then(|v| v.as_struct()) // Arc
            .and_then(|s| s.unique_member_named("ptr"))
            .and_then(|v| v.as_struct()) // NonNull
            .and_then(|s| s.unique_member_named("pointer"))
            .and_then(|v| v.as_pointer())
            .context("failed to navigate to scheduler Arc pointer")?;

        let arc_inner_val = arc_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref scheduler Arc")?;
        let handle_data = arc_inner_data(&arc_inner_val)
            .context("failed to navigate to scheduler handle data")?;

        Self::load(dbg, handle_data)
    }
}

impl Shared {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let remotes = Self::load_remotes(dbg, s).context("failed to load remotes")?;
        let inject_len = Self::load_inject_len(s).context("failed to load inject_len")?;

        let idle_struct = s
            .unique_member_named("idle")
            .and_then(|v| v.as_struct())
            .context("failed to load idle")?;
        let idle = Idle::load(idle_struct).context("failed to load Idle")?;

        let synced_struct = mutex_data(s, "synced").context("failed to load synced")?;
        let synced = Synced::load(dbg, synced_struct).context("failed to load Synced")?;

        let mut active_workers = BTreeSet::new();
        for i in 0u64..idle.num_workers {
            if !synced.idle_sleepers.contains(&i) {
                active_workers.insert(i);
            }
        }

        let owned_struct = s
            .unique_member_named("owned")
            .and_then(|v| v.as_struct())
            .context("failed to load owned")?;
        let owned =
            OwnedTasks::load_with_tasks(dbg, owned_struct).context("failed to load OwnedTasks")?;

        let config_struct = s
            .unique_member_named("config")
            .and_then(|v| v.as_struct())
            .context("failed to load config")?;
        let config = Config::load(config_struct).context("failed to load Config")?;

        let sched_metrics_struct = s
            .unique_member_named("scheduler_metrics")
            .and_then(|v| v.as_struct())
            .context("failed to load scheduler_metrics")?;
        let scheduler_metrics = SchedulerMetrics::load(sched_metrics_struct)
            .context("failed to load SchedulerMetrics")?;

        let worker_metrics =
            Self::load_worker_metrics(dbg, s).context("failed to load worker_metrics")?;

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

    fn load_remotes(dbg: &Dbg, s: &Struct) -> Result<Box<[Remote]>> {
        let elements = load_boxed_slice(dbg, s, "remotes").context("failed to load remotes")?;

        let mut remotes = Vec::with_capacity(elements.len());
        for (i, elem) in elements.iter().enumerate() {
            let remote_struct = elem
                .as_struct()
                .with_context(|| format!("remote[{i}] is not a struct"))?;
            let remote = Remote::load(dbg, remote_struct)
                .with_context(|| format!("failed to load remote[{i}]"))?;
            remotes.push(remote);
        }
        Ok(remotes.into_boxed_slice())
    }

    fn load_inject_len(s: &Struct) -> Option<u64> {
        let inject = s.unique_member_named("inject")?.as_struct()?;
        loom_atomic_u64(inject, "len")
    }

    fn load_worker_metrics(dbg: &Dbg, s: &Struct) -> Result<Box<[WorkerMetrics]>> {
        let elements =
            load_boxed_slice(dbg, s, "worker_metrics").context("failed to load worker_metrics")?;

        let mut metrics = Vec::with_capacity(elements.len());
        for (i, elem) in elements.iter().enumerate() {
            let wm_struct = elem
                .as_struct()
                .with_context(|| format!("worker_metrics[{i}] is not a struct"))?;
            let wm = WorkerMetrics::load(wm_struct)
                .with_context(|| format!("failed to load worker_metrics[{i}]"))?;
            metrics.push(wm);
        }
        Ok(metrics.into_boxed_slice())
    }
}

impl Remote {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let steal_struct = s
            .unique_member_named("steal")
            .and_then(|v| v.as_struct())
            .context("failed to load steal")?;
        let steal = TaskQueue::load_from_steal(dbg, steal_struct)
            .context("failed to load steal TaskQueue")?;

        let unpark_struct = s
            .unique_member_named("unpark")
            .and_then(|v| v.as_struct())
            .context("failed to load unpark")?;
        let unpark = Parker::load(dbg, unpark_struct).context("failed to load unpark Parker")?;

        Ok(Self { steal, unpark })
    }
}

impl Idle {
    pub fn load(s: &Struct) -> Result<Self> {
        const UNPARK_SHIFT: u64 = 16;
        const SEARCH_MASK: u64 = (1 << UNPARK_SHIFT) - 1;
        const UNPARK_MASK: u64 = !SEARCH_MASK;

        let num_workers = s
            .unique_member_named("num_workers")
            .and_then(|v| v.u64_value())
            .context("failed to load num_workers")?;

        let state = atomic_u64(s, "state").context("failed to load state")?;
        let num_searching = state & SEARCH_MASK;
        let num_unparked = (state & UNPARK_MASK) >> UNPARK_SHIFT;

        Ok(Self {
            num_workers,
            num_searching,
            num_unparked,
        })
    }
}

impl Synced {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let idle_sleepers = load_vec_u64(dbg, s, "idle")
            .unwrap_or_default()
            .into_iter()
            .collect();

        let inject = s
            .unique_member_named("inject")
            .and_then(|v| v.as_struct())
            .context("failed to load inject")?;

        let inject_closed = inject
            .unique_member_named("is_closed")
            .and_then(|v| v.bool_value())
            .context("failed to load inject_closed")?;

        let inject_head =
            load_option_task_addr(inject, "head").context("failed to load inject_head")?;
        let inject_tail =
            load_option_task_addr(inject, "tail").context("failed to load inject_tail")?;

        Ok(Self {
            idle_sleepers,
            inject_closed,
            inject_head,
            inject_tail,
        })
    }
}

impl Inject {
    pub fn load(s: &Struct) -> Result<Self> {
        let len = loom_atomic_u64(s, "len").context("failed to load len")?;
        Ok(Self { len })
    }
}

impl Config {
    pub fn load(s: &Struct) -> Result<Self> {
        let global_queue_interval = load_option_u32(s, "global_queue_interval")
            .context("failed to load global_queue_interval")?;

        let event_interval = s
            .unique_member_named("event_interval")
            .and_then(|v| v.u32_value())
            .context("failed to load event_interval")?;

        let disable_lifo_slot = s
            .unique_member_named("disable_lifo_slot")
            .and_then(|v| v.bool_value())
            .context("failed to load disable_lifo_slot")?;

        Ok(Self {
            global_queue_interval,
            event_interval,
            disable_lifo_slot,
        })
    }
}

impl SchedulerMetrics {
    pub fn load(s: &Struct) -> Result<Self> {
        let remote_schedule_count = atomic_u64(s, "remote_schedule_count")
            .context("failed to load remote_schedule_count")?;
        let budget_forced_yield_count = atomic_u64(s, "budget_forced_yield_count")
            .context("failed to load budget_forced_yield_count")?;

        Ok(Self {
            remote_schedule_count,
            budget_forced_yield_count,
        })
    }
}

impl WorkerMetrics {
    pub fn load(s: &Struct) -> Result<Self> {
        let busy_duration_total =
            atomic_u64(s, "busy_duration_total").context("failed to load busy_duration_total")?;
        let queue_depth = atomic_u64(s, "queue_depth").context("failed to load queue_depth")?;
        // thread_id is wrapped in AtomicCell — skip for now
        let thread_id = None;
        let park_count = atomic_u64(s, "park_count").context("failed to load park_count")?;
        let park_unpark_count =
            atomic_u64(s, "park_unpark_count").context("failed to load park_unpark_count")?;
        let noop_count = atomic_u64(s, "noop_count").context("failed to load noop_count")?;
        let steal_count = atomic_u64(s, "steal_count").context("failed to load steal_count")?;
        let steal_operations =
            atomic_u64(s, "steal_operations").context("failed to load steal_operations")?;
        let poll_count = atomic_u64(s, "poll_count").context("failed to load poll_count")?;
        let mean_poll_time =
            atomic_u64(s, "mean_poll_time").context("failed to load mean_poll_time")?;
        let local_schedule_count =
            atomic_u64(s, "local_schedule_count").context("failed to load local_schedule_count")?;
        let overflow_count =
            atomic_u64(s, "overflow_count").context("failed to load overflow_count")?;

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

impl DriverHandle {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        // io: enum IoHandle with disc Enabled/Disabled
        let io_enum = s
            .unique_member_named("io")
            .and_then(|v| v.as_enum())
            .context("failed to load io")?;
        let io = IoHandle::load_from_enum(dbg, io_enum).context("failed to load IoHandle")?;

        // time: Option<Handle> — the Handle contains the TimeHandle data
        let time_enum = s
            .unique_member_named("time")
            .and_then(|v| v.as_enum())
            .context("failed to load time")?;
        let time = match time_enum.disc.as_str() {
            "Some" => {
                let inner = option_inner_struct(&time_enum.value)
                    .context("failed to extract TimeHandle from Some")?;
                TimeHandle::load(dbg, inner).context("failed to load TimeHandle")?
            }
            other => bail!("unexpected time variant: {other} (expected Some)"),
        };

        // clock: loom Mutex -> __1 (lock_api::Mutex) -> data (UnsafeCell) -> value (Inner)
        let clock_inner = s
            .unique_member_named("clock")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("inner"))
            .and_then(|v| v.as_struct())
            .and_then(|s| mutex_data_from_struct(s))
            .context("failed to load clock")?;
        let clock = Clock::load(clock_inner).context("failed to load Clock")?;

        Ok(Self { io, time, clock })
    }
}

impl IoHandle {
    pub fn load_from_enum(dbg: &Dbg, e: &Enum) -> Result<Self> {
        match e.disc.as_str() {
            "Enabled" => {
                let inner = e
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_struct())
                    .context("failed to extract IoEnabled")?;
                Ok(IoHandle::Enabled(IoEnabled::load(dbg, inner)?))
            }
            "Disabled" => {
                let inner = e
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_struct())
                    .context("failed to extract IoDisabled")?;
                Ok(IoHandle::Disabled(IoDisabled::load(dbg, inner)?))
            }
            other => bail!("unexpected IoHandle variant: {other}"),
        }
    }
}

impl IoEnabled {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        // registrations -> num_pending_release (loom AtomicUsize)
        let num_pending_release = s
            .unique_member_named("registrations")
            .and_then(|v| v.as_struct())
            .and_then(|s| loom_atomic_u64(s, "num_pending_release"))
            .context("failed to load num_pending_release")?;

        let metrics_struct = s
            .unique_member_named("metrics")
            .and_then(|v| v.as_struct())
            .context("failed to load metrics")?;
        let metrics =
            IoDriverMetrics::load(metrics_struct).context("failed to load IoDriverMetrics")?;

        // waker -> inner -> fd -> inner -> __0 -> __0 -> fd -> __0 (I32NotAllOnes)
        let waker_fd = s
            .unique_member_named("waker")
            .and_then(|v| v.as_struct()) // mio::Waker
            .and_then(|s| s.unique_member_named("inner"))
            .and_then(|v| v.as_struct()) // mio::sys Waker
            .and_then(|s| s.unique_member_named("fd"))
            .and_then(|v| v.as_struct()) // std::fs::File
            .and_then(|s| s.unique_member_named("inner"))
            .and_then(|v| v.as_struct()) // sys::fs::File (tuple)
            .and_then(|s| s.newtype_value())
            .and_then(|v| v.as_struct()) // FileDesc (tuple)
            .and_then(|s| s.newtype_value())
            .and_then(|v| v.as_struct()) // OwnedFd
            .and_then(|s| s.unique_member_named("fd"))
            .and_then(|v| v.as_struct()) // I32NotAllOnes (tuple)
            .and_then(|s| s.newtype_value())
            .and_then(|v| v.i64_value())
            .context("failed to load waker_fd")? as i32;

        // registry -> selector -> ep -> fd -> __0 (I32NotAllOnes)
        let poll_fd = s
            .unique_member_named("registry")
            .and_then(|v| v.as_struct()) // mio::Registry
            .and_then(|s| s.unique_member_named("selector"))
            .and_then(|v| v.as_struct()) // mio::Selector
            .and_then(|s| s.unique_member_named("ep"))
            .and_then(|v| v.as_struct()) // OwnedFd
            .and_then(|s| s.unique_member_named("fd"))
            .and_then(|v| v.as_struct()) // I32NotAllOnes (tuple)
            .and_then(|s| s.newtype_value())
            .and_then(|v| v.i64_value())
            .context("failed to load poll_fd")? as i32;

        let synced_struct = mutex_data(s, "synced").context("failed to load synced")?;
        let synced = IoSynced::load(dbg, synced_struct).context("failed to load IoSynced")?;

        Ok(Self {
            num_pending_release,
            waker_fd,
            poll_fd,
            metrics,
            synced,
        })
    }
}

impl IoDisabled {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let arc_ptr = arc_field_ptr(s, "inner")
            .or_else(|| {
                // might be a direct struct, try navigating as pointer
                s.unique_member_named("inner")?
                    .as_struct()?
                    .unique_member_named("ptr")?
                    .as_struct()?
                    .unique_member_named("pointer")?
                    .as_pointer()
                    .or_else(|| s.unique_member_named("inner")?.as_pointer())
            })
            .context("failed to navigate IoDisabled pointer")?;

        let arc_inner_val = arc_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref IoDisabled Arc")?;
        let inner =
            arc_inner_data(&arc_inner_val).context("failed to navigate to IoDisabled data")?;

        let state = loom_atomic_u64(inner, "state").context("failed to load ParkThread state")?;
        Ok(Self {
            park: ParkThread(state),
        })
    }
}

impl IoSynced {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let is_shutdown = s
            .unique_member_named("is_shutdown")
            .and_then(|v| v.bool_value())
            .context("failed to load is_shutdown")?;

        let mut registrations = Vec::new();
        let head_ptr = s
            .unique_member_named("registrations")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("head"))
            .and_then(|v| v.as_enum());

        if let Some(head_enum) = head_ptr
            && head_enum.disc == "Some"
            && let Some(ptr) = head_enum
                .value
                .newtype_value()
                .and_then(|v| v.as_struct())
                .and_then(|s| s.unique_member_named("pointer"))
                .and_then(|v| v.as_pointer())
        {
            load_scheduled_io_list(dbg, ptr, &mut registrations)
                .context("failed to load registrations list")?;
        }

        Ok(Self {
            registrations,
            is_shutdown,
        })
    }
}

impl ScheduledIo {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let readiness_val = atomic_u64(s, "readiness").context("failed to load readiness")?;
        let readiness = Ready(readiness_val);

        let waiters_struct = s
            .unique_member_named("waiters")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("data"))
            .and_then(|v| v.as_struct())
            .context("failed to load waiters")?;
        let waiters = Waiters::load(dbg, waiters_struct).context("failed to load Waiters")?;

        Ok(Self { readiness, waiters })
    }
}

impl IoDriverMetrics {
    pub fn load(s: &Struct) -> Result<Self> {
        let fd_registered_count =
            atomic_u64(s, "fd_registered_count").context("failed to load fd_registered_count")?;
        let fd_deregistered_count = atomic_u64(s, "fd_deregistered_count")
            .context("failed to load fd_deregistered_count")?;
        let ready_count = atomic_u64(s, "ready_count").context("failed to load ready_count")?;

        Ok(Self {
            fd_registered_count,
            fd_deregistered_count,
            ready_count,
        })
    }
}

impl TimeHandle {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        // time_source: TimeSource -> start_time -> tokio::time::Instant -> std (std::time::Instant)
        let time_source_instant = s
            .unique_member_named("time_source")
            .and_then(|v| v.as_struct()) // TimeSource
            .and_then(|s| s.unique_member_named("start_time"))
            .and_then(|v| v.as_struct()) // tokio::time::Instant
            .and_then(|s| s.unique_member_named("std"))
            .and_then(|v| v.as_struct()) // std::time::Instant
            .context("failed to load time_source")?;
        let time_source = RawInstant::load_from_struct(time_source_instant)
            .context("failed to load time_source RawInstant")?;

        // inner may be wrapped in an enum variant "Traditional" in newer tokio
        // inner: enum Inner disc=Traditional
        // Traditional { state: loom Mutex<InnerState>, is_shutdown: AtomicBool, did_wake: AtomicBool }
        let inner_enum = s
            .unique_member_named("inner")
            .and_then(|v| v.as_enum())
            .context("failed to load TimeHandle inner")?;
        if inner_enum.disc != "Traditional" {
            bail!("unsupported time inner variant: {}", inner_enum.disc);
        }
        let inner = &inner_enum.value;

        // is_shutdown: AtomicBool -> v -> UnsafeCell -> value (U8)
        let is_shutdown =
            atomic_bool(inner, "is_shutdown").context("failed to load is_shutdown")?;

        // did_wake: AtomicBool -> v -> UnsafeCell -> value (U8)
        let did_wake = atomic_bool(inner, "did_wake").context("failed to load did_wake")?;

        // state: loom Mutex -> InnerState { next_wake, wheel }
        let state = mutex_data_from_struct(
            inner
                .unique_member_named("state")
                .and_then(|v| v.as_struct())
                .context("failed to load state mutex")?,
        )
        .context("failed to navigate state mutex")?;

        let wheel_struct = state
            .unique_member_named("wheel")
            .and_then(|v| v.as_struct())
            .context("failed to load wheel")?;
        let wheel = Wheel::load(dbg, wheel_struct).context("failed to load Wheel")?;

        // next_wake: Option<NonZero<u64>>
        let next_wake =
            load_option_nonzero_u64(state, "next_wake").context("failed to load next_wake")?;

        Ok(Self {
            is_shutdown,
            did_wake,
            time_source,
            wheel,
            next_wake,
        })
    }
}

impl Clock {
    pub fn load(s: &Struct) -> Result<Self> {
        let base_struct = s
            .unique_member_named("base")
            .and_then(|v| v.as_struct())
            .context("failed to load base")?;
        let base = RawInstant::load_from_struct(base_struct).context("failed to load base")?;

        let unfrozen = load_option(s, "unfrozen", RawInstant::load_from_struct)
            .context("failed to load unfrozen")?;

        let enable_pausing = s
            .unique_member_named("enable_pausing")
            .and_then(|v| v.bool_value())
            .context("failed to load enable_pausing")?;

        Ok(Self {
            base,
            unfrozen,
            enable_pausing,
        })
    }
}

impl Wheel {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let elapsed = s
            .unique_member_named("elapsed")
            .and_then(|v| v.u64_value())
            .context("failed to load elapsed")?;

        let levels_ptr = s
            .unique_member_named("levels")
            .and_then(|v| v.as_pointer())
            .context("failed to navigate to levels pointer")?;
        let levels_val = levels_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref levels pointer")?;
        let Value::Array(level_elements) = &levels_val else {
            bail!("levels is not an array");
        };

        let mut levels = Vec::with_capacity(level_elements.len());
        for (i, elem) in level_elements.iter().enumerate() {
            let level_struct = elem
                .as_struct()
                .with_context(|| format!("level[{i}] is not a struct"))?;
            let level = Level::load(dbg, level_struct, elapsed)
                .with_context(|| format!("failed to load level[{i}]"))?;
            levels.push(level);
        }

        let mut pending = Vec::new();
        let pending_head = s
            .unique_member_named("pending")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("head"))
            .and_then(|v| v.as_enum());

        if let Some(head_enum) = pending_head
            && head_enum.disc == "Some"
            && let Some(ptr) = head_enum
                .value
                .newtype_value()
                .and_then(|v| v.as_struct())
                .and_then(|s| s.unique_member_named("pointer"))
                .and_then(|v| v.as_pointer())
        {
            load_timer_list(dbg, ptr, elapsed, &mut pending)
                .context("failed to load pending timers")?;
        }

        Ok(Self {
            elapsed,
            levels,
            pending,
        })
    }
}

impl Level {
    pub fn load(dbg: &Dbg, s: &Struct, elapsed: u64) -> Result<Self> {
        let level = s
            .unique_member_named("level")
            .and_then(|v| v.u64_value())
            .context("failed to load level")?;

        let occupied = s
            .unique_member_named("occupied")
            .and_then(|v| v.u64_value())
            .context("failed to load occupied")?;

        let slot_val = s
            .unique_member_named("slot")
            .context("failed to load slot")?;
        let Value::Array(slot_elements) = slot_val else {
            bail!("slot is not an array");
        };

        let mut slot = Vec::new();
        for (i, elem) in slot_elements.iter().enumerate() {
            if occupied & (1 << i) == 0 {
                continue;
            }

            let mut timers = Vec::new();
            // Each slot is a linked list. Navigate head -> Option<NonNull<TimerShared>>
            if let Some(head_ptr) = linked_list_head_ptr(elem)? {
                load_timer_list(dbg, head_ptr, elapsed, &mut timers)
                    .with_context(|| format!("failed to load timers in slot[{i}]"))?;
            }

            slot.push(TimerSlot { slot_id: i, timers });
        }

        Ok(Self {
            level,
            occupied,
            slot,
        })
    }
}

impl TimerShared {
    pub fn load(dbg: &Dbg, s: &Struct, elapsed: u64) -> Result<Self> {
        let registered_when = s
            .unique_member_named("registered_when")
            .and_then(|v| v.u64_value())
            .context("failed to load registered_when")?;

        let state_struct = s
            .unique_member_named("state")
            .and_then(|v| v.as_struct())
            .context("failed to load state")?;

        let time_state_val =
            core_atomic_u64(state_struct, "state").context("failed to load time_state")?;
        let time_state = TimerState(time_state_val);

        let result = state_struct
            .unique_member_named("result")
            .and_then(|v| v.as_enum())
            .map(|e| e.disc.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let waker_struct = state_struct
            .unique_member_named("waker")
            .and_then(|v| v.as_struct())
            .context("failed to load waker")?;

        let waker_state_val =
            core_atomic_u64(waker_struct, "state").context("failed to load waker_state")?;
        let waker_state = WakerState(waker_state_val);

        let waker =
            load_option_waker(dbg, waker_struct, "waker").context("failed to load timer waker")?;

        let dur_remaining = if registered_when >= elapsed {
            Some(Duration::from_millis(registered_when - elapsed))
        } else {
            None
        };

        Ok(Self {
            registered_when,
            time_state,
            dur_remaining,
            result,
            waker_state,
            waker,
        })
    }
}

impl ParkThread {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let arc_ptr =
            arc_field_ptr(s, "inner").context("failed to navigate to ParkThread Arc pointer")?;
        let arc_inner_val = arc_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref ParkThread Arc")?;
        let inner =
            arc_inner_data(&arc_inner_val).context("failed to navigate to ParkThread data")?;
        let state = loom_atomic_u64(inner, "state").context("failed to load ParkThread state")?;
        Ok(Self(state))
    }
}

impl Location {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        // filename: NonNull<str> -> pointer -> *const str { data_ptr, length }
        let str_struct = s
            .unique_member_named("filename")
            .and_then(|v| v.as_struct()) // NonNull<str>
            .and_then(|s| s.unique_member_named("pointer"))
            .and_then(|v| v.as_struct()) // *const str
            .context("failed to navigate to filename")?;
        let filename = read_str_from_fat_ptr(dbg, str_struct).context("failed to load filename")?;

        let line = s
            .unique_member_named("line")
            .and_then(|v| v.u32_value())
            .context("failed to load line")?;

        let col = s
            .unique_member_named("col")
            .and_then(|v| v.u32_value())
            .context("failed to load col")?;

        Ok(Self {
            filename,
            line,
            col,
        })
    }
}

impl TaskHeader {
    /// Load a TaskHeader from a pointer to a Header in the core dump.
    ///
    /// `header_addr` is the address of the Header struct in the target
    /// process. The `header` struct has already been loaded from that
    /// address. We need the address to compute offsets into the vtable
    /// for id, spawn_location, and trailer.
    pub fn load(dbg: &Dbg, header_addr: u64, header: &Struct) -> Result<Self> {
        // state: State { val: loom AtomicUsize }
        let state_struct = header
            .unique_member_named("state")
            .and_then(|v| v.as_struct())
            .context("failed to load state struct")?;
        let state = loom_atomic_u64(state_struct, "val").context("failed to load state")?;

        // owner_id: loom UnsafeCell { __0: UnsafeCell { value: Option<NonZero<u64>> } }
        let owner_id_enum = header
            .unique_member_named("owner_id")
            .and_then(|v| v.as_struct()) // loom UnsafeCell
            .and_then(|s| s.newtype_value()) // __0
            .and_then(|v| v.as_struct()) // core UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_enum());
        let runtime_id = match owner_id_enum {
            Some(e) if e.disc == "Some" => {
                // NonZero<u64> -> NonZeroU64Inner -> u64
                let mut val = e.value.newtype_value();
                let mut id = None;
                for _ in 0..10 {
                    let Some(v) = val else { break };
                    if let Some(n) = v.u64_value() {
                        id = Some(n);
                        break;
                    }
                    val = v.as_struct().and_then(|s| s.newtype_value());
                }
                id
            }
            _ => None,
        };

        // Deref the vtable pointer to get offsets
        let vtable_ptr = header
            .unique_member_named("vtable")
            .and_then(|v| v.as_pointer())
            .context("failed to load vtable pointer")?;
        let vtable_val = vtable_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref vtable")?;
        let vtable = vtable_val.as_struct().context("vtable is not a struct")?;

        // Read the task id via the id_offset
        let id_offset = vtable
            .unique_member_named("id_offset")
            .and_then(|v| v.u64_value())
            .context("failed to load id_offset")?;
        let id = dbg
            .core
            .read_u64(header_addr + id_offset)
            .context("failed to read task id")?;

        // Read spawn_location via the spawn_location_offset
        let spawn_offset = vtable
            .unique_member_named("spawn_location_offset")
            .and_then(|v| v.u64_value())
            .context("failed to load spawn_location_offset")?;
        let spawn_ptr = dbg
            .core
            .read_u64(header_addr + spawn_offset)
            .context("failed to read spawn_location pointer")?;
        let spawn_location =
            load_location_from_addr(dbg, spawn_ptr).context("failed to load spawn_location")?;

        // Read the waker from the Trailer via trailer_offset
        let trailer_offset = vtable
            .unique_member_named("trailer_offset")
            .and_then(|v| v.u64_value())
            .context("failed to load trailer_offset")?;
        let waker = load_waker_from_trailer(dbg, header_addr + trailer_offset)
            .context("failed to load waker from trailer")?;

        Ok(Self {
            state,
            runtime_id,
            id,
            spawn_location,
            waker,
        })
    }
}

impl TaskHeader {
    /// Resolve the concrete future type of a task from its vtable.
    ///
    /// The vtable's `poll` function pointer is monomorphized for each
    /// concrete future type. By resolving the symbol name and extracting
    /// the generic parameter, we can determine the type of the future.
    pub fn concrete_type(dbg: &Dbg, header: &Struct) -> Result<String> {
        let vtable_ptr = header
            .unique_member_named("vtable")
            .and_then(|v| v.as_pointer())
            .context("failed to load vtable pointer")?;
        let vtable_val = vtable_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref vtable")?;
        let vtable = vtable_val.as_struct().context("vtable is not a struct")?;

        // Look up vtable function pointers in DWARF debug info.
        // The DWARF subprogram names include full generic parameters.
        let fn_fields = [
            "poll",
            "schedule",
            "dealloc",
            "try_read_output",
            "drop_join_handle_slow",
            "drop_abort_handle",
            "shutdown",
        ];

        for field in fn_fields {
            let Some(fn_addr) = vtable
                .unique_member_named(field)
                .and_then(|v| v.pointer_value())
            else {
                continue;
            };

            // Find the DWARF subprogram containing this address
            if let Some((_, subp)) = dbg
                .db
                .subprograms()
                .find(|(_, subp)| subp.pc_range.as_ref().is_some_and(|r| r.contains(&fn_addr)))
                && let Some(name) = &subp.name
                && name.contains('<')
            {
                return Ok(extract_future_type(name));
            }
        }

        // Fallback: use the ELF symbol name for the poll function
        let fn_addr = vtable
            .unique_member_named("poll")
            .and_then(|v| v.pointer_value())
            .context("failed to find poll in vtable")?;
        let symbol = dbg
            .core
            .lookup_symbol_name_by_addr(fn_addr)
            .unwrap_or_else(|| format!("<unknown@{fn_addr:#x}>"));
        Ok(format!("{:#}", rustc_demangle::demangle(&symbol)))
    }
}

/// Resolve the concrete future type of a task at the given address.
pub fn resolve_task_type(dbg: &Dbg, task_addr: TaskAddr) -> Result<String> {
    let ty_name = "tokio::runtime::task::core::Header";
    let (_, ty) = dbg
        .db
        .types_by_name(ty_name)
        .next()
        .context("Header type not found in debug info")?;

    let header_val = Struct::from_state(dbg.segments(), task_addr.0, &dbg.db, ty)
        .context("failed to load Header from address")?;

    TaskHeader::concrete_type(dbg, &header_val)
}

/// Generate a logical await trace for a task at the given address.
///
/// This loads the task's future from memory using DWARF type info,
/// then walks the async state machine by following `__awaitee` fields
/// through each suspension point.
pub fn task_await_trace(dbg: &Dbg, task_addr: TaskAddr) -> Result<String> {
    // First, find the full Cell<T, S> type name from the vtable
    let header_ty_name = "tokio::runtime::task::core::Header";
    let (_, header_ty) = dbg
        .db
        .types_by_name(header_ty_name)
        .next()
        .context("Header type not found")?;

    let header_val = Struct::from_state(dbg.segments(), task_addr.0, &dbg.db, header_ty)
        .context("failed to load Header")?;

    // Get the vtable to find the full generic type params
    let vtable_ptr = header_val
        .unique_member_named("vtable")
        .and_then(|v| v.as_pointer())
        .context("failed to load vtable pointer")?;
    let vtable_val = vtable_ptr
        .deref(dbg.segments(), &dbg.db)
        .context("failed to deref vtable")?;
    let vtable = vtable_val.as_struct().context("vtable is not a struct")?;

    // Find a function with generic params to extract both T and S
    let fn_fields = ["poll", "dealloc", "try_read_output"];
    let mut future_type = None;
    let mut full_params = None;

    for field in fn_fields {
        let Some(fn_addr) = vtable
            .unique_member_named(field)
            .and_then(|v| v.pointer_value())
        else {
            continue;
        };

        if let Some((_, subp)) = dbg
            .db
            .subprograms()
            .find(|(_, subp)| subp.pc_range.as_ref().is_some_and(|r| r.contains(&fn_addr)))
            && let Some(name) = &subp.name
            && name.contains('<')
        {
            future_type = Some(extract_future_type(name));
            // Extract full params "T, S" from the function name
            if let Some(open) = name.find('<')
                && let Some(close) = name.rfind('>')
            {
                full_params = Some(name[open + 1..close].to_string());
            }
            break;
        }
    }

    let future_type = future_type.context("could not determine future type")?;
    let full_params = full_params.context("could not extract generic params")?;

    // Find the Cell<T, S> DWARF type
    let cell_type_name = format!("tokio::runtime::task::core::Cell<{full_params}>");
    let (_, cell_ty) = dbg
        .db
        .types_by_name(&cell_type_name)
        .next()
        .with_context(|| format!("Cell type not found: {cell_type_name}"))?;

    // Load the full Cell from the task address
    let cell_val = Value::from_state(dbg.segments(), task_addr.0, &dbg.db, cell_ty)
        .context("failed to load Cell")?;

    // Navigate to the future within the Cell:
    // Cell -> core -> stage -> stage
    // The stage is a UnsafeCell containing the future
    let core_struct = cell_val.as_struct().context("Cell is not a struct")?;

    // Path: Cell -> core (Core) -> stage (CoreStage) -> stage (loom UnsafeCell)
    //   -> __0 (UnsafeCell) -> value (Stage<T> enum)
    let loom_cell = core_struct
        .unique_member_named("core")
        .and_then(|v| v.as_struct()) // Core
        .and_then(|s| s.unique_member_named("stage"))
        .and_then(|v| v.as_struct()) // CoreStage
        .and_then(|s| s.unique_member_named("stage"))
        .and_then(|v| v.as_struct()) // loom UnsafeCell
        .context("failed to navigate to CoreStage.stage")?;

    // Unwrap loom UnsafeCell: __0 -> UnsafeCell -> value
    let stage_val = loom_cell
        .newtype_value()
        .and_then(|v| v.as_struct()) // core UnsafeCell
        .and_then(|s| s.unique_member_named("value"))
        .or_else(|| loom_cell.unique_member_named("value"))
        .context("failed to unwrap stage UnsafeCell")?;

    // The stage value is a Stage<T> enum. If it's Running, the future
    // is inside the variant. If it's Finished/Consumed, the task is done.
    let future_val = if let Value::Enum(stage_enum) = stage_val {
        match stage_enum.disc.as_str() {
            "Running" => {
                // Running variant contains the future T
                stage_enum
                    .value
                    .newtype_value()
                    .context("failed to unwrap Running variant")?
            }
            "Finished" => {
                return Ok("task has finished\n".to_string());
            }
            "Consumed" => {
                return Ok("task output has been consumed\n".to_string());
            }
            other => {
                return Ok(format!("task in unexpected state: {other}\n"));
            }
        }
    } else {
        stage_val
    };

    // Walk the async state machine
    let mut output = String::new();
    walk_async_state_machine(dbg, future_val, &future_type, &mut output);

    Ok(output)
}

/// Walk an async state machine value, following __awaitee fields.
fn walk_async_state_machine(dbg: &Dbg, v: &Value, type_hint: &str, output: &mut String) {
    let async_fn_re = regex::Regex::new(r"^(.*)::\{async_fn_env#0\}(<.*)?$").unwrap();
    let async_block_re = regex::Regex::new(r"^(.*)::\{async_block_env#[0-9]+\}(<.*)?$").unwrap();
    let suspend_re = regex::Regex::new(r"::Suspend([0-9]+)$").unwrap();

    let Value::Enum(e) = v else {
        let type_name = match v {
            Value::Struct(s) => &s.name,
            _ => type_hint,
        };
        output.push_str(&format!("hand-rolled future: {type_name}\n"));
        output.push_str(&format!("{}\n", lookup_type_location(dbg, type_name)));
        return;
    };

    let fn_name = if let Some(caps) = async_fn_re.captures(&e.name) {
        caps.get(1).unwrap().as_str().to_string()
    } else if let Some(caps) = async_block_re.captures(&e.name) {
        format!("{}::{{async_block}}", caps.get(1).unwrap().as_str())
    } else {
        output.push_str(&format!("future: {}\n", e.name));
        output.push_str(&format!("{}\n", lookup_type_location(dbg, &e.name)));
        return;
    };

    output.push_str(&format!("{fn_name}\n"));
    output.push_str(&format!("{}\n", lookup_type_location(dbg, &e.name)));

    let state_name = &e.value.name;
    if state_name.ends_with("Unresumed") {
        output.push_str("  future has not yet been polled\n\n");
        return;
    } else if state_name.ends_with("Returned") {
        output.push_str("  future has already resolved\n\n");
        return;
    } else if state_name.ends_with("Panicked") {
        output.push_str("  future panicked on previous poll\n\n");
        return;
    } else if let Some(sc) = suspend_re.captures(state_name) {
        if let Ok(n) = sc[1].parse::<usize>() {
            output.push_str(&format!("  suspended at await point {n}\n\n"));
        } else {
            output.push_str(&format!("  state: {state_name}\n\n"));
        }
    } else {
        output.push_str(&format!("  state: {state_name}\n\n"));
    }

    let awaitee = e
        .value
        .members
        .iter()
        .find(|(name, _)| name.as_deref() == Some("__awaitee"));

    let Some((_, awaitee_val)) = awaitee else {
        return;
    };

    walk_async_state_machine(dbg, awaitee_val, "", output);
}

/// Look up the source file and line for a type by its DWARF name.
///
/// Tries the type itself (for structs with decl_coord), then falls back
/// to finding a subprogram whose name matches (for async fns).
fn lookup_type_location(dbg: &Dbg, type_name: &str) -> String {
    // Try struct type first
    if let Some((_, ty)) = dbg.db.types_by_name(type_name).next()
        && let debugdb::model::Type::Struct(s) = ty
        && let (Some(file), Some(line)) = (&s.decl_coord.file, s.decl_coord.line)
    {
        return format!("  at {file}:{line}");
    }

    // Try to find a subprogram matching the base function name.
    // For "foo::bar::{async_fn_env#0}", look for subprogram "foo::bar".
    let base_name = type_name
        .strip_suffix("::{async_fn_env#0}")
        .or_else(|| {
            // For async blocks, strip the block suffix
            type_name
                .rfind("::{async_block_env#")
                .map(|i| &type_name[..i])
        })
        .unwrap_or(type_name);

    for (_, subp) in dbg.db.subprograms() {
        let Some(name) = &subp.name else { continue };
        if (name == base_name || name == type_name || name.starts_with(base_name))
            && let (Some(file), Some(line)) = (&subp.decl_coord.file, subp.decl_coord.line)
        {
            return format!("  at {file}:{line}");
        }
    }

    String::new()
}

/// Extract the concrete future type from a demangled symbol name.
///
/// Given a symbol like:
///   `tokio::runtime::task::harness::poll::<Foo::bar::{async_block_env#0}>`
/// Returns:
///   `Foo::bar::{async_block_env#0}`
fn extract_future_type(name: &str) -> String {
    // The DWARF name looks like:
    //   tokio::runtime::task::raw::poll<FutureType, SchedulerType>
    // We want the first generic parameter (the future type).
    // Find the first '<' and extract the first comma-separated parameter,
    // handling nested angle brackets.
    let Some(open) = name.find('<') else {
        return name.to_string();
    };

    let params = &name[open + 1..];
    let mut depth = 0;
    let mut end = params.len();
    for (i, c) in params.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth == 0 {
                    end = i;
                    break;
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }

    params[..end].trim().to_string()
}

impl Waker {
    /// Load a `std::task::Waker` from its DWARF struct representation.
    ///
    /// The waker contains a `data` pointer (TaskAddr) and a `vtable`
    /// pointer whose entries are function pointers we resolve to symbol
    /// names.
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        // Waker { waker: RawWaker { data, vtable } }
        let raw_waker = s
            .unique_member_named("waker")
            .and_then(|v| v.as_struct())
            .context("failed to load RawWaker")?;

        let data_val = raw_waker
            .unique_member_named("data")
            .and_then(|v| v.as_pointer())
            .context("failed to load data pointer")?;
        let data = TaskAddr(data_val.value);

        let vtable_ptr = raw_waker
            .unique_member_named("vtable")
            .and_then(|v| v.as_pointer())
            .context("failed to load vtable pointer")?;
        let vtable_val = vtable_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref waker vtable")?;
        let vtable = vtable_val
            .as_struct()
            .context("waker vtable is not a struct")?;

        let wake_addr = vtable
            .unique_member_named("wake")
            .and_then(|v| v.pointer_value())
            .context("failed to load wake")?;
        let wake_by_ref_addr = vtable
            .unique_member_named("wake_by_ref")
            .and_then(|v| v.pointer_value())
            .context("failed to load wake_by_ref")?;
        let clone_addr = vtable
            .unique_member_named("clone")
            .and_then(|v| v.pointer_value())
            .context("failed to load clone")?;
        let drop_addr = vtable
            .unique_member_named("drop")
            .and_then(|v| v.pointer_value())
            .context("failed to load drop")?;

        let wake = lookup_symbol(dbg, wake_addr);
        let wake_by_ref = lookup_symbol(dbg, wake_by_ref_addr);
        let clone = lookup_symbol(dbg, clone_addr);
        let drop = lookup_symbol(dbg, drop_addr);

        // Resolve dependent_task if waker is a task waker
        let dependent_task = if wake == "tokio::runtime::task::waker::wake_by_val" {
            // data points to a Header
            Some(TaskAddr(data_val.value))
        } else {
            None
        };

        // Resolve dependent_park if waker is a park waker
        let dependent_park = if wake == "tokio::runtime::park::wake" {
            load_park_thread_from_arc_ptr(dbg, data_val.value).ok()
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

impl OwnedTasks {
    /// Load from the OwnedTasks struct, including traversing the sharded
    /// linked lists to collect all tasks.
    pub fn load_with_tasks(dbg: &Dbg, s: &Struct) -> Result<Self> {
        // closed: AtomicBool -> v -> UnsafeCell -> value (U8)
        let closed_val = s
            .unique_member_named("closed")
            .and_then(|v| v.as_struct()) // AtomicBool
            .and_then(|s| s.unique_member_named("v"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .context("failed to load closed")?;
        let closed = match closed_val {
            Value::Base(debugdb::value::Base::U8(b)) => *b != 0,
            Value::Base(debugdb::value::Base::Bool(b)) => *b != 0,
            _ => bail!("unexpected closed type: {closed_val:?}"),
        };

        let list = s
            .unique_member_named("list")
            .and_then(|v| v.as_struct())
            .context("failed to load list")?;

        // added: MetricAtomicU64 -> value -> AtomicU64 -> v -> UnsafeCell -> value
        let added = list
            .unique_member_named("added")
            .and_then(|v| v.as_struct()) // MetricAtomicU64
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // AtomicU64
            .and_then(|s| s.unique_member_named("v"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.u64_value())
            .context("failed to load added")?;

        // count: MetricAtomicUsize -> value -> AtomicUsize -> v -> UnsafeCell -> value
        let count = list
            .unique_member_named("count")
            .and_then(|v| v.as_struct()) // MetricAtomicUsize
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct()) // AtomicUsize
            .and_then(|s| s.unique_member_named("v"))
            .and_then(|v| v.as_struct()) // UnsafeCell
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.u64_value())
            .context("failed to load count")?;

        let shard_mask = list
            .unique_member_named("shard_mask")
            .and_then(|v| v.u64_value())
            .context("failed to load shard_mask")?;

        let mut tasks = std::collections::HashMap::new();

        // lists: Box<[loom::Mutex<LinkedList>]> with data_ptr/length
        let shards = load_boxed_slice(dbg, list, "lists").context("failed to load lists")?;

        for shard in &shards {
            // Each shard is a loom parking_lot::Mutex
            // Navigate: __1 (lock_api::Mutex) -> data (UnsafeCell) -> value (LinkedList) -> head
            let linked_list = shard
                .as_struct()
                .and_then(|s| mutex_data_from_struct(s))
                .and_then(|s| s.unique_member_named("head"))
                .and_then(|v| v.as_enum());

            let Some(head_enum) = linked_list else {
                continue;
            };

            if head_enum.disc != "Some" {
                continue;
            }

            let Some(ptr) = head_enum
                .value
                .newtype_value()
                .and_then(|v| v.as_struct()) // NonNull
                .and_then(|s| s.unique_member_named("pointer"))
                .and_then(|v| v.as_pointer())
            else {
                continue;
            };

            // Walk the linked list
            let mut current_ptr = ptr.clone();
            loop {
                let addr = current_ptr.value;
                let header_val = current_ptr
                    .deref(dbg.segments(), &dbg.db)
                    .context("failed to deref task header pointer")?;
                let header_struct = header_val
                    .as_struct()
                    .context("task header is not a struct")?;

                let task_addr = TaskAddr(addr);
                let task = TaskHeader::load(dbg, addr, header_struct)
                    .context("failed to load task header")?;
                tasks.insert(task_addr, task);

                // Follow queue_next: loom UnsafeCell { __0: UnsafeCell { value: Option } }
                let next = header_struct
                    .unique_member_named("queue_next")
                    .and_then(|v| v.as_struct()) // loom UnsafeCell
                    .and_then(|s| s.newtype_value()) // __0
                    .and_then(|v| v.as_struct()) // core UnsafeCell
                    .and_then(|s| s.unique_member_named("value"))
                    .and_then(|v| v.as_enum());

                let Some(next_enum) = next else {
                    break;
                };

                if next_enum.disc != "Some" {
                    break;
                }

                let Some(next_ptr) = next_enum
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_struct())
                    .and_then(|s| s.unique_member_named("pointer"))
                    .and_then(|v| v.as_pointer())
                else {
                    break;
                };

                current_ptr = next_ptr.clone();
            }
        }

        Ok(Self {
            tasks,
            added,
            count,
            closed,
            shard_mask,
        })
    }
}

/// Lookup a symbol name by address, returning a leaked &'static str.
fn lookup_symbol(dbg: &Dbg, addr: u64) -> &'static str {
    match dbg.core.lookup_symbol_name_by_addr(addr) {
        Some(name) => {
            let demangled = format!("{:#}", rustc_demangle::demangle(&name));
            Box::leak(demangled.into_boxed_str())
        }
        None => Box::leak(format!("<unknown@{addr:#x}>").into_boxed_str()),
    }
}

/// Load a Location struct from an address in the core dump.
fn load_location_from_addr(dbg: &Dbg, addr: u64) -> Result<Location> {
    let ty_name = "core::panic::location::Location";
    let (_, ty) = dbg
        .db
        .types_by_name(ty_name)
        .next()
        .context("Location type not found in debug info")?;

    let val = debugdb::value::Struct::from_state(dbg.segments(), addr, &dbg.db, ty)
        .context("failed to load Location from address")?;

    Location::load(dbg, &val)
}

/// Load a ParkThread from an Arc pointer stored in waker data.
fn load_park_thread_from_arc_ptr(dbg: &Dbg, addr: u64) -> Result<ParkThread> {
    // The data pointer in a park waker points to an Arc<Inner>.
    // We need to deref the ArcInner and extract the state.
    let ty_name = "tokio::runtime::park::Inner";
    let (_, ty) = dbg
        .db
        .types_by_name(ty_name)
        .next()
        .context("park::Inner type not found in debug info")?;

    // The addr points to the ArcInner<Inner>, data is at an offset.
    // Load as the ArcInner and navigate to data.
    let val = debugdb::value::Struct::from_state(dbg.segments(), addr, &dbg.db, ty)
        .context("failed to load park::Inner from address")?;

    let state = loom_atomic_u64(&val, "state").context("failed to load park state")?;
    Ok(ParkThread(state))
}

/// Load a Waker from a Trailer struct at a given address.
fn load_waker_from_trailer(dbg: &Dbg, trailer_addr: u64) -> Result<Option<Waker>> {
    let ty_name = "tokio::runtime::task::core::Trailer";
    let (_, ty) = dbg
        .db
        .types_by_name(ty_name)
        .next()
        .context("Trailer type not found in debug info")?;

    let trailer_val = debugdb::value::Struct::from_state(dbg.segments(), trailer_addr, &dbg.db, ty)
        .context("failed to load Trailer from address")?;

    // waker: loom UnsafeCell { __0: UnsafeCell { value: Option<Waker> } }
    let waker_enum = trailer_val
        .unique_member_named("waker")
        .and_then(|v| v.as_struct()) // loom UnsafeCell
        .and_then(|s| s.newtype_value()) // __0
        .and_then(|v| v.as_struct()) // core UnsafeCell
        .and_then(|s| s.unique_member_named("value"))
        .and_then(|v| v.as_enum()) // Option<Waker>
        .context("failed to navigate to waker field")?;

    match waker_enum.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            let waker_struct = option_inner_struct(&waker_enum.value)
                .context("failed to extract waker from Some")?;
            Ok(Some(Waker::load(dbg, waker_struct)?))
        }
        other => bail!("unexpected waker variant: {other}"),
    }
}

/// Read a string from a fat pointer struct with `data_ptr` and `length`.
fn read_str_from_fat_ptr(dbg: &Dbg, s: &Struct) -> Result<String> {
    let ptr_addr = s
        .unique_member_named("data_ptr")
        .and_then(|v| v.as_pointer())
        .map(|p| p.value)
        .context("failed to load data_ptr")?;

    let len = s
        .unique_member_named("length")
        .and_then(|v| v.u64_value())
        .context("failed to load length")? as usize;

    let bytes =
        read_bytes_from_segments(dbg, ptr_addr, len).context("failed to read string bytes")?;

    String::from_utf8(bytes).context("string is not valid UTF-8")
}

/// Read `len` bytes from the core dump segments starting at `addr`.
fn read_bytes_from_segments(dbg: &Dbg, addr: u64, len: usize) -> Result<Vec<u8>> {
    let segments = &dbg.segments.segments;
    let mut result = Vec::with_capacity(len);

    for i in 0..len {
        let byte_addr = addr + i as u64;
        let (range, data) = segments
            .get_key_value(&byte_addr)
            .with_context(|| format!("address {byte_addr:#x} not in segments"))?;
        let offset = (byte_addr - range.start()) as usize;
        result.push(data[offset]);
    }

    Ok(result)
}

impl TaskQueue {
    /// Load from a `queue::Steal<T>` (a tuple struct wrapping `Arc<Inner<T>>`).
    pub fn load_from_steal(dbg: &Dbg, steal: &Struct) -> Result<Self> {
        let arc_ptr = steal
            .newtype_value()
            .and_then(|v| v.as_struct()) // Arc
            .and_then(|s| s.unique_member_named("ptr"))
            .and_then(|v| v.as_struct()) // NonNull
            .and_then(|s| s.unique_member_named("pointer"))
            .and_then(|v| v.as_pointer())
            .context("failed to navigate Steal to Arc pointer")?;

        let arc_inner_val = arc_ptr
            .deref(dbg.segments(), &dbg.db)
            .context("failed to deref Arc<Inner>")?;
        let inner = arc_inner_data(&arc_inner_val).context("failed to navigate to Inner data")?;

        let head = core_atomic_u64(inner, "head").context("failed to load head")?;
        let tail = loom_atomic_u32(inner, "tail").context("failed to load tail")?;

        let real_head = (head & 0xFFFF_FFFF) as u32;
        let tasks =
            Self::load_buffer(dbg, inner, real_head, tail).context("failed to load buffer")?;

        Ok(Self { head, tail, tasks })
    }
}

impl Waiters {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let mut list = Vec::new();
        let head_enum = s
            .unique_member_named("list")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("head"))
            .and_then(|v| v.as_enum());

        if let Some(head_enum) = head_enum
            && head_enum.disc == "Some"
            && let Some(ptr) = head_enum
                .value
                .newtype_value()
                .and_then(|v| v.as_struct())
                .and_then(|s| s.unique_member_named("pointer"))
                .and_then(|v| v.as_pointer())
        {
            load_waiter_list(dbg, ptr, &mut list).context("failed to load waiter list")?;
        }

        let reader = load_option_waker(dbg, s, "reader").context("failed to load reader waker")?;
        let writer = load_option_waker(dbg, s, "writer").context("failed to load writer waker")?;

        Ok(Self {
            list,
            reader,
            writer,
        })
    }
}

impl Waiter {
    pub fn load(dbg: &Dbg, s: &Struct) -> Result<Self> {
        let interest_val = s
            .unique_member_named("interest")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.newtype_value())
            .and_then(|v| v.u64_value())
            .context("failed to load interest")?;
        let interest = Interest(interest_val);

        let is_ready = s
            .unique_member_named("is_ready")
            .and_then(|v| v.bool_value())
            .context("failed to load is_ready")?;

        let waker = load_option_waker(dbg, s, "waker").context("failed to load waker")?;

        Ok(Self {
            interest,
            is_ready,
            waker,
        })
    }
}

/// Load a linked list of Waiter entries by following `pointers.next`.
fn load_waiter_list(dbg: &Dbg, first_ptr: &Pointer, out: &mut Vec<Waiter>) -> Result<()> {
    let mut current_val = first_ptr
        .deref(dbg.segments(), &dbg.db)
        .context("failed to deref waiter pointer")?;

    loop {
        let s = current_val.as_struct().context("waiter is not a struct")?;
        let waiter = Waiter::load(dbg, s)?;
        out.push(waiter);

        let next_enum = s
            .unique_member_named("pointers")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("next"))
            .and_then(|v| v.as_enum());

        let Some(next_enum) = next_enum else {
            break;
        };

        match next_enum.disc.as_str() {
            "None" => break,
            "Some" => {
                let next_ptr = next_enum
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_struct())
                    .and_then(|s| s.unique_member_named("pointer"))
                    .and_then(|v| v.as_pointer())
                    .context("failed to extract next waiter pointer")?;
                current_val = next_ptr
                    .deref(dbg.segments(), &dbg.db)
                    .context("failed to deref next waiter")?;
            }
            other => bail!("unexpected next variant: {other}"),
        }
    }

    Ok(())
}

/// Load a linked list of ScheduledIo entries by following
/// `linked_list_pointers.next`.
fn load_scheduled_io_list(
    dbg: &Dbg,
    first_ptr: &Pointer,
    out: &mut Vec<ScheduledIo>,
) -> Result<()> {
    let mut current_val = first_ptr
        .deref(dbg.segments(), &dbg.db)
        .context("failed to deref ScheduledIo pointer")?;

    loop {
        let s = current_val
            .as_struct()
            .context("ScheduledIo is not a struct")?;
        let sched_io = ScheduledIo::load(dbg, s)?;
        out.push(sched_io);

        let next_enum = s
            .unique_member_named("linked_list_pointers")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("next"))
            .and_then(|v| v.as_enum());

        let Some(next_enum) = next_enum else {
            break;
        };

        match next_enum.disc.as_str() {
            "None" => break,
            "Some" => {
                let next_ptr = next_enum
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_struct())
                    .and_then(|s| s.unique_member_named("pointer"))
                    .and_then(|v| v.as_pointer())
                    .context("failed to extract next ScheduledIo pointer")?;
                current_val = next_ptr
                    .deref(dbg.segments(), &dbg.db)
                    .context("failed to deref next ScheduledIo")?;
            }
            other => bail!("unexpected next variant: {other}"),
        }
    }

    Ok(())
}

/// Load an `Option<Waker>` from an enum field.
fn load_option_waker(dbg: &Dbg, parent: &Struct, field: &str) -> Result<Option<Waker>> {
    let e = match option_field(parent, field) {
        Some(e) => e,
        None => return Ok(None),
    };

    match e.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            let inner = option_inner_struct(&e.value)
                .with_context(|| format!("failed to extract waker from {field}"))?;
            Ok(Some(Waker::load(dbg, inner)?))
        }
        other => bail!("unexpected Option variant for {field}: {other}"),
    }
}

/// Navigate a linked list head from a slot element.
///
/// The slot is a linked list struct with `head: Option<NonNull<TimerShared>>`.
fn linked_list_head_ptr(slot_val: &Value) -> Result<Option<&Pointer>> {
    let slot = slot_val
        .as_struct()
        .context("slot element is not a struct")?;
    let head_enum = slot
        .unique_member_named("head")
        .and_then(|v| v.as_enum())
        .context("failed to load head enum")?;

    match head_enum.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            let ptr = head_enum
                .value
                .newtype_value()
                .and_then(|v| v.as_struct()) // NonNull
                .and_then(|s| s.unique_member_named("pointer"))
                .and_then(|v| v.as_pointer())
                .context("failed to extract NonNull pointer from head")?;
            Ok(Some(ptr))
        }
        other => bail!("unexpected head variant: {other}"),
    }
}

/// Load a linked list of TimerShared entries by following `pointers.next`.
fn load_timer_list(
    dbg: &Dbg,
    first_ptr: &Pointer,
    elapsed: u64,
    out: &mut Vec<TimerShared>,
) -> Result<()> {
    let mut current_val = first_ptr
        .deref(dbg.segments(), &dbg.db)
        .context("failed to deref timer pointer")?;

    loop {
        let s = current_val.as_struct().context("timer is not a struct")?;
        let timer = TimerShared::load(dbg, s, elapsed)?;
        out.push(timer);

        // Follow pointers.next
        let next_enum = s
            .unique_member_named("pointers")
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("next"))
            .and_then(|v| v.as_enum());

        let Some(next_enum) = next_enum else {
            break;
        };

        match next_enum.disc.as_str() {
            "None" => break,
            "Some" => {
                let next_ptr = next_enum
                    .value
                    .newtype_value()
                    .and_then(|v| v.as_struct()) // NonNull
                    .and_then(|s| s.unique_member_named("pointer"))
                    .and_then(|v| v.as_pointer())
                    .context("failed to extract next pointer")?;
                current_val = next_ptr
                    .deref(dbg.segments(), &dbg.db)
                    .context("failed to deref next timer")?;
            }
            other => bail!("unexpected next variant: {other}"),
        }
    }

    Ok(())
}

/// Load an `Option<u32>` from an enum field.
fn load_option_u32(parent: &Struct, field: &str) -> Result<Option<u32>> {
    let e =
        option_field(parent, field).with_context(|| format!("failed to navigate to {field}"))?;

    match e.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            let val = e
                .value
                .newtype_value()
                .and_then(|v| v.u32_value())
                .with_context(|| format!("failed to extract u32 from {field}"))?;
            Ok(Some(val))
        }
        other => bail!("unexpected Option variant for {field}: {other}"),
    }
}

/// Load an `Option<TaskAddr>` from an Option enum field containing a pointer.
fn load_option_task_addr(parent: &Struct, field: &str) -> Result<Option<TaskAddr>> {
    let e =
        option_field(parent, field).with_context(|| format!("failed to navigate to {field}"))?;

    match e.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            let ptr = e
                .value
                .newtype_value()
                .and_then(|v| v.as_struct()) // NonNull
                .and_then(|s| s.unique_member_named("pointer"))
                .and_then(|v| v.pointer_value())
                .with_context(|| format!("failed to extract TaskAddr from {field}"))?;
            Ok(Some(TaskAddr(ptr)))
        }
        other => bail!("unexpected Option variant for {field}: {other}"),
    }
}

/// Load a `Vec<u64>` field by navigating the Vec internals.
fn load_vec_u64(dbg: &Dbg, parent: &Struct, field: &str) -> Result<Vec<u64>> {
    let vec_struct = parent
        .unique_member_named(field)
        .and_then(|v| v.as_struct())
        .with_context(|| format!("failed to navigate to {field}"))?;

    let len = vec_struct
        .unique_member_named("len")
        .and_then(|v| v.u64_value())
        .with_context(|| format!("failed to load {field} len"))?;

    if len == 0 {
        return Ok(Vec::new());
    }

    let buf_val = vec_struct
        .unique_member_named("buf")
        .with_context(|| format!("failed to load {field} buf"))?;
    let data_ptr = find_data_pointer(buf_val)
        .with_context(|| format!("failed to find {field} data pointer"))?;

    let elem_ty = dbg
        .db
        .type_by_id(data_ptr.dest_type_id)
        .context("element type not found")?;
    let elem_size = elem_ty
        .inherent_byte_size()
        .context("element type has no known size")?;

    let mut result = Vec::with_capacity(len as usize);
    for i in 0..len {
        let addr = data_ptr.value + i * elem_size;
        let val = Value::from_state(dbg.segments(), addr, &dbg.db, elem_ty)
            .with_context(|| format!("failed to load {field}[{i}]"))?;
        result.push(val.u64_value().unwrap_or(0));
    }
    Ok(result)
}

/// Extract a u64 field from a struct, with context.
fn u64_field(s: &Struct, field: &str) -> Result<u64> {
    s.unique_member_named(field)
        .and_then(|v| v.u64_value())
        .with_context(|| format!("failed to load {field}"))
}

/// Load elements from a `Box<[T]>` field, which is a fat pointer with
/// `data_ptr` and `length`.
fn load_boxed_slice(dbg: &Dbg, parent: &Struct, field: &str) -> Result<Vec<Value>> {
    let box_struct = parent
        .unique_member_named(field)
        .and_then(|v| v.as_struct())
        .with_context(|| format!("failed to find {field}"))?;

    let data_ptr = box_struct
        .unique_member_named("data_ptr")
        .and_then(|v| v.as_pointer())
        .with_context(|| format!("failed to find {field} data_ptr"))?;

    let length = box_struct
        .unique_member_named("length")
        .and_then(|v| v.u64_value())
        .with_context(|| format!("failed to find {field} length"))? as usize;

    if length == 0 {
        return Ok(Vec::new());
    }

    let elem_ty = dbg
        .db
        .type_by_id(data_ptr.dest_type_id)
        .context("element type not found")?;
    let elem_size = elem_ty
        .inherent_byte_size()
        .context("element type has no known size")?;

    let mut elements = Vec::with_capacity(length);
    for i in 0..length {
        let addr = data_ptr.value + (i as u64) * elem_size;
        let val = Value::from_state(dbg.segments(), addr, &dbg.db, elem_ty)
            .with_context(|| format!("failed to load {field}[{i}]"))?;
        elements.push(val);
    }

    Ok(elements)
}

/// Find a data pointer inside a `Box<[T]>`, `Vec<T>`, or similar container.
///
/// Tries multiple DWARF layouts:
/// - Fat pointer: `data_ptr` (Box<[T]> with data_ptr + length)
/// - Box/Unique: `ptr` -> `pointer` -> `pointer` (thin pointer inside NonNull)
/// - Vec: `buf` -> `ptr` -> `pointer` -> `pointer`
fn find_data_pointer(val: &Value) -> Option<&Pointer> {
    let s = val.as_struct()?;

    // Try: fat pointer (Box<[T]> with data_ptr + length)
    if let Some(p) = s
        .unique_member_named("data_ptr")
        .and_then(|v| v.as_pointer())
    {
        return Some(p);
    }

    // Try: direct pointer field
    if let Some(p) = s
        .unique_member_named("pointer")
        .and_then(|v| v.as_pointer())
    {
        return Some(p);
    }

    // Try: Unique/NonNull -> pointer -> pointer
    if let Some(p) = s
        .unique_member_named("ptr")
        .and_then(|v| v.as_struct())
        .and_then(|s| s.unique_member_named("pointer"))
        .and_then(|v| {
            v.as_pointer().or_else(|| {
                v.as_struct()
                    .and_then(|s| s.unique_member_named("pointer"))
                    .and_then(|v| v.as_pointer())
            })
        })
    {
        return Some(p);
    }

    // Try: Vec layout: buf -> ptr -> pointer -> pointer
    if let Some(p) = s
        .unique_member_named("buf")
        .and_then(|v| v.as_struct())
        .and_then(|s| s.unique_member_named("ptr"))
        .and_then(|v| v.as_struct())
        .and_then(|s| s.unique_member_named("pointer"))
        .and_then(|v| {
            v.as_pointer().or_else(|| {
                v.as_struct()
                    .and_then(|s| s.unique_member_named("pointer"))
                    .and_then(|v| v.as_pointer())
            })
        })
    {
        return Some(p);
    }

    None
}

/// Navigate through an `Arc<T>` field to get the inner pointer.
///
/// `Arc` -> `ptr` (`NonNull`) -> `pointer`
fn arc_field_ptr<'a>(s: &'a Struct, field: &str) -> Option<&'a Pointer> {
    s.unique_member_named(field)?
        .as_struct()? // Arc
        .unique_member_named("ptr")?
        .as_struct()? // NonNull
        .unique_member_named("pointer")?
        .as_pointer()
}

/// Navigate through an `ArcInner<T>` to get the `data` field.
fn arc_inner_data(val: &Value) -> Option<&Struct> {
    val.as_struct()? // ArcInner
        .unique_member_named("data")?
        .as_struct()
}

/// Navigate through a `Mutex<T>` to get the inner data.
///
/// Tries: `field -> data -> value` (std Mutex with UnsafeCell)
/// and: `field -> data` (loom Mutex)
fn mutex_data<'a>(s: &'a Struct, field: &str) -> Option<&'a Struct> {
    let mutex = s.unique_member_named(field)?.as_struct()?;

    // std::sync::Mutex: data (UnsafeCell) -> value
    if let Some(inner) = mutex
        .unique_member_named("data")
        .and_then(|v| v.as_struct())
        .and_then(|s| s.unique_member_named("value"))
        .and_then(|v| v.as_struct())
    {
        return Some(inner);
    }

    // loom Mutex or direct data field
    if let Some(inner) = mutex
        .unique_member_named("data")
        .and_then(|v| v.as_struct())
    {
        return Some(inner);
    }

    // loom parking_lot::Mutex wraps lock_api::Mutex which has `raw`
    // and `data` (UnsafeCell<T>). The loom wrapper is a tuple struct
    // where __1 is the lock_api::Mutex.
    for field_name in ["__1", "__0"] {
        // lock_api::Mutex -> data (UnsafeCell) -> value
        if let Some(inner) = mutex
            .unique_member_named(field_name)
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("data"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct())
        {
            return Some(inner);
        }
    }

    None
}

/// Navigate through a Mutex struct directly (without field lookup) to get
/// the inner data. Works for both std and loom/parking_lot Mutex.
fn mutex_data_from_struct(mutex: &Struct) -> Option<&Struct> {
    // std::sync::Mutex: data (UnsafeCell) -> value
    if let Some(inner) = mutex
        .unique_member_named("data")
        .and_then(|v| v.as_struct())
        .and_then(|s| s.unique_member_named("value"))
        .and_then(|v| v.as_struct())
    {
        return Some(inner);
    }

    // loom parking_lot::Mutex: __1 (lock_api::Mutex) -> data (UnsafeCell) -> value
    for field_name in ["__1", "__0"] {
        if let Some(inner) = mutex
            .unique_member_named(field_name)
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("data"))
            .and_then(|v| v.as_struct())
            .and_then(|s| s.unique_member_named("value"))
            .and_then(|v| v.as_struct())
        {
            return Some(inner);
        }
    }

    None
}

/// Read a bool from an `AtomicBool` field.
///
/// `AtomicBool` -> `v` -> `UnsafeCell` -> `value` (U8 or Bool)
fn atomic_bool(s: &Struct, field: &str) -> Option<bool> {
    let val = s
        .unique_member_named(field)?
        .as_struct()? // AtomicBool
        .unique_member_named("v")?
        .as_struct()? // UnsafeCell
        .unique_member_named("value")?;
    match val {
        Value::Base(debugdb::value::Base::U8(b)) => Some(*b != 0),
        Value::Base(debugdb::value::Base::Bool(b)) => Some(*b != 0),
        _ => None,
    }
}

/// Load an `Option<NonZero<u64>>` from an enum field.
fn load_option_nonzero_u64(parent: &Struct, field: &str) -> Result<Option<u64>> {
    let e =
        option_field(parent, field).with_context(|| format!("failed to navigate to {field}"))?;

    match e.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            // NonZero<u64> -> NonZeroU64Inner -> u64
            let mut val = e.value.newtype_value();
            for _ in 0..10 {
                let Some(v) = val else { break };
                if let Some(n) = v.u64_value() {
                    return Ok(Some(n));
                }
                val = v.as_struct().and_then(|s| s.newtype_value());
            }
            bail!("failed to extract u64 from {field}")
        }
        other => bail!("unexpected Option variant for {field}: {other}"),
    }
}

/// Try to read a u64 from an atomic field, attempting core atomic first,
/// then loom atomic, then MetricAtomicU64.
fn atomic_u64(s: &Struct, field: &str) -> Option<u64> {
    core_atomic_u64(s, field)
        .or_else(|| loom_atomic_u64(s, field))
        .or_else(|| metric_atomic_u64(s, field))
}

/// Navigate through a `MetricAtomicU64` wrapper to get the value.
///
/// `MetricAtomicU64` -> `value` (`AtomicU64`) -> `v` (`UnsafeCell`) -> `value`
fn metric_atomic_u64(s: &Struct, field: &str) -> Option<u64> {
    s.unique_member_named(field)?
        .as_struct()? // MetricAtomicU64
        .unique_member_named("value")?
        .as_struct()? // AtomicU64
        .unique_member_named("v")?
        .as_struct()? // UnsafeCell
        .unique_member_named("value")?
        .u64_value()
}

/// Navigate through a `core::sync::atomic::AtomicU64` to get the value.
///
/// `AtomicU64` -> `v` (`UnsafeCell`) -> `value`
fn core_atomic_u64(s: &Struct, field: &str) -> Option<u64> {
    s.unique_member_named(field)?
        .as_struct()? // AtomicU64
        .unique_member_named("v")?
        .as_struct()? // UnsafeCell
        .unique_member_named("value")?
        .u64_value()
}

/// Navigate through a loom atomic wrapper to the inner `Value`.
///
/// `loom::AtomicXX` -> `inner` (`UnsafeCell`) -> `value` (`core::AtomicXX`)
///   -> `v` (`UnsafeCell`) -> `value`
fn loom_atomic_value<'a>(s: &'a Struct, field: &str) -> Option<&'a Value> {
    s.unique_member_named(field)?
        .as_struct()? // loom AtomicXX
        .unique_member_named("inner")?
        .as_struct()? // UnsafeCell
        .unique_member_named("value")?
        .as_struct()? // core AtomicXX
        .unique_member_named("v")?
        .as_struct()? // UnsafeCell
        .unique_member_named("value")
}

/// Read a `u32` from a loom atomic wrapper.
fn loom_atomic_u32(s: &Struct, field: &str) -> Option<u32> {
    loom_atomic_value(s, field)?.u32_value()
}

/// Read a `u64` from a loom atomic wrapper.
fn loom_atomic_u64(s: &Struct, field: &str) -> Option<u64> {
    loom_atomic_value(s, field)?.u64_value()
}

/// Load an `Option<T>` field from a struct where the inner value is a struct.
fn load_option<T>(
    parent: &Struct,
    field: &str,
    load_fn: impl FnOnce(&Struct) -> Result<T>,
) -> Result<Option<T>> {
    let option_enum =
        option_field(parent, field).with_context(|| format!("failed to navigate to {field}"))?;

    match option_enum.disc.as_str() {
        "None" => Ok(None),
        "Some" => {
            let inner = option_inner_struct(&option_enum.value)
                .with_context(|| format!("failed to extract inner struct from {field}"))?;
            Ok(Some(load_fn(inner)?))
        }
        other => bail!("unexpected Option variant for {field}: {other}"),
    }
}

/// Navigate to an `Option` enum field on a struct.
fn option_field<'a>(parent: &'a Struct, field: &str) -> Option<&'a Enum> {
    parent.unique_member_named(field)?.as_enum()
}

/// Extract the inner struct from an `Option::Some` variant's value.
fn option_inner_struct(option_value: &Struct) -> Option<&Struct> {
    option_value.newtype_value()?.as_struct()
}

/// Debug: recursively print a struct's members and their types.
#[allow(dead_code)]
fn dump_struct(s: &Struct, depth: usize) {
    let indent = "  ".repeat(depth);
    eprintln!("{indent}struct '{}' {{", s.name);
    for (name, val) in &s.members {
        let name = name.as_deref().unwrap_or("?");
        match val {
            Value::Struct(inner) => {
                eprint!("{indent}  {name}: ");
                dump_struct(inner, depth + 1);
            }
            Value::Enum(e) => {
                eprintln!("{indent}  {name}: enum '{}' disc={}", e.name, e.disc);
            }
            Value::Base(b) => {
                eprintln!("{indent}  {name}: {b:?}");
            }
            Value::Pointer(p) => {
                eprintln!("{indent}  {name}: ptr '{}' -> {:#x}", p.name, p.value);
            }
            Value::Array(a) => {
                eprintln!("{indent}  {name}: array[{}]", a.len());
            }
            Value::CEnum(c) => {
                eprintln!("{indent}  {name}: cenum {c:?}");
            }
        }
    }
    eprintln!("{indent}}}");
}

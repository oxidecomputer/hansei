// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Each multi_thread worker as a scheduler sees it: the thread running
//! it, what it is doing, the task it is polling, and the work queued
//! behind it — its LIFO slot and its local run queue — beside the
//! runtime's inject queue, where tasks spawned from outside a worker
//! wait.
//!
//! The queues are read from the `Core` the worker's thread holds, which
//! it does while it runs a task or the driver; a worker parked with its
//! core elsewhere reads as such. Like every queue hansei reads, these
//! are a snapshot only when nothing was changing them: a worker caught
//! pushing or stealing may show a run a moment out of date.

use crate::Session;
use crate::threads;

use anyhow::{Result, anyhow};
use hansei_runtime::tokio::bundle;
use proc::Target;
use reify::Value;

/// tokio's `LOCAL_QUEUE_CAPACITY` on 64-bit targets.
const LOCAL_QUEUE_CAPACITY: u64 = 256;

/// One worker of a multi_thread runtime.
#[derive(Clone, Debug)]
pub struct WorkerInfo {
    /// The runtime, by its index in `runtimes`.
    pub runtime: usize,
    /// The worker's index in its runtime, where its context reads.
    pub index: Option<u64>,
    /// The lwp running it.
    pub lwp: u32,
    /// What the parker and the context say it is doing: `polling`,
    /// `parked`, `in driver`, …
    pub state: String,
    /// The task it is polling, by header address, where the listing
    /// agrees it is running one.
    pub polling: Option<u64>,
    /// Ticks the worker has counted: one per task it ran.
    pub tick: Option<u64>,
    /// The worker's queues, or why they could not be read.
    pub queues: std::result::Result<Queues, String>,
    /// The function at the top of the thread's stack.
    pub frame0: Option<String>,
}

/// A worker's own queued work, by task header address.
#[derive(Clone, Debug, Default)]
pub struct Queues {
    /// The task in the LIFO slot: the one the worker runs next.
    pub lifo: Option<u64>,
    /// The local run queue, oldest first.
    pub local: Vec<u64>,
}

/// A runtime's shared queue: tasks spawned from outside its workers.
#[derive(Clone, Debug)]
pub struct InjectInfo {
    pub runtime: usize,
    /// The count tokio keeps beside the list.
    pub len: Option<u64>,
    /// The tasks on the list, oldest first, as far as it walked.
    pub tasks: Vec<u64>,
}

pub(crate) fn workers<T: Target>(session: &Session<'_, T>) -> Vec<WorkerInfo> {
    let rows = threads::rows(session);
    let mut out = Vec::new();
    for worker in &session.workers {
        let Ok(Some(ctx)) = session.ctx.worker_context(worker) else {
            continue; // not a multi_thread worker
        };
        let Some(runtime) = session
            .runtimes
            .iter()
            .position(|r| r.worker_tids.contains(&worker.tid))
        else {
            continue;
        };
        let row = rows.iter().find(|r| r.lwp == worker.tid);
        // The row's role is `worker N, <state>`.
        let state = row
            .and_then(|r| r.role.split_once(", ").map(|(_, s)| s.to_string()))
            .unwrap_or_else(|| "unknown".into());
        let polling = row
            .and_then(|r| r.task)
            .and_then(|id| session.tasks.tasks.iter().find(|t| t.task_id == Some(id)))
            .map(|t| t.addr.0);
        let core = checked_in_core(session, ctx);
        out.push(WorkerInfo {
            runtime,
            index: session.ctx.worker_index(ctx).ok(),
            lwp: worker.tid,
            state,
            polling,
            tick: core.as_ref().ok().and_then(|c| member_word(c, "tick")),
            queues: core
                .and_then(|core| queues(session, core))
                .map_err(|e| format!("{e:#}")),
            frame0: row.and_then(|r| r.frame0.clone()),
        });
    }
    out.sort_by_key(|w| (w.runtime, w.index, w.lwp));
    out
}

pub(crate) fn injects<T: Target>(session: &Session<'_, T>) -> Vec<InjectInfo> {
    session
        .runtimes
        .iter()
        .enumerate()
        .filter(|(_, rt)| rt.flavor == bundle::RuntimeFlavor::MultiThread)
        .map(|(runtime, rt)| {
            let shared = rt.handle.try_member("shared").ok().flatten();
            // `inject::Shared { len, .. }`, raw so a peel cannot land
            // on `len` itself and lose the name.
            let len = shared
                .and_then(|s| s.try_member_raw("inject").ok().flatten())
                .and_then(|i| i.try_member_raw("len").ok().flatten())
                .and_then(|l| word(&l));
            let tasks = shared
                .and_then(|s| inject_head(session, s))
                .map(|head| linked_tasks(session, head))
                .unwrap_or_default();
            InjectInfo {
                runtime,
                len,
                tasks,
            }
        })
        .collect()
}

/// The `Core` a worker context has checked in: `core` is a
/// `RefCell<Option<Box<Core>>>`.
fn checked_in_core<'b, T: Target>(session: &Session<'b, T>, ctx: Value<'b>) -> Result<Value<'b>> {
    let core = ctx.member("core")?.member("value")?;
    let boxed = core
        .try_select_variant("Some")?
        .ok_or_else(|| anyhow!("its core is not held by this thread"))?;
    Ok(boxed.deref_ptr(session.ctx.proc)?)
}

fn queues<'b, T: Target>(session: &Session<'b, T>, core: Value<'b>) -> Result<Queues> {
    let proc = session.ctx.proc;
    // `lifo_slot: Option<Notified>`: a niche-packed pointer to the
    // task's header, null for `None`.
    let lifo = core
        .try_member_raw("lifo_slot")?
        .and_then(|v| word(&v))
        .filter(|&w| w != 0);

    // `run_queue: Local { inner: Arc<Inner> }`, and `Inner { head,
    // tail, buffer }`: `head` packs (steal, real) as two u32s, real in
    // the low half; the entries run from real to tail, each a
    // `Notified` — a header pointer — in a ring of 256.
    let local = core
        .try_member_raw("run_queue")?
        .ok_or_else(|| anyhow!("the core has no run_queue"))?;
    let arc_ptr = word(&local).ok_or_else(|| anyhow!("run_queue did not read"))?;
    let inner_value = arc_inner_data(session, local)?;
    let head = member_word(&inner_value, "head")
        .ok_or_else(|| anyhow!("the run queue's head did not read"))?;
    let tail = member_word(&inner_value, "tail")
        .ok_or_else(|| anyhow!("the run queue's tail did not read"))?;
    let buffer = inner_value
        .try_member_raw("buffer")?
        .and_then(|b| word(&b))
        .ok_or_else(|| anyhow!("the run queue's buffer did not read"))?;
    let real = head & 0xffff_ffff;
    let tail = tail & 0xffff_ffff;
    let len = tail.wrapping_sub(real) & 0xffff_ffff;
    if len > LOCAL_QUEUE_CAPACITY {
        anyhow::bail!(
            "the run queue at {arc_ptr:#x} reads {len} entries (head {real}, tail {tail}): mid-update, or not a queue"
        );
    }
    let mut local = Vec::new();
    for i in 0..len {
        let slot = (real + i) % LOCAL_QUEUE_CAPACITY;
        let at = buffer + slot * 8;
        local.push(
            proc.read_u64(at)
                .map_err(|e| anyhow!("run queue slot {slot} at {at:#x}: {e}"))?,
        );
    }
    Ok(Queues { lifo, local })
}

/// `Arc<T>` to the `T` it shares: the `data` member of the `ArcInner`
/// its pointer reaches.
fn arc_inner_data<'b, T: Target>(session: &Session<'b, T>, arc: Value<'b>) -> Result<Value<'b>> {
    let mut v = arc;
    // Down to the pointer, whatever wrappers (`Local`, `Arc`,
    // `NonNull`) stand between.
    for _ in 0..4 {
        if v.ty.pointer_target().is_some() {
            break;
        }
        let Some(next) = ["inner", "ptr", "pointer"]
            .iter()
            .find_map(|m| v.try_member_raw(m).ok().flatten())
        else {
            break;
        };
        v = next;
    }
    let pointee = v.deref_ptr(session.ctx.proc)?;
    Ok(pointee.try_member_raw("data")?.unwrap_or(pointee))
}

/// The head of a multi_thread runtime's inject list, under its
/// `synced` lock: `Mutex<Synced>` → `Synced.inject.head`.
fn inject_head<'b, T: Target>(session: &Session<'b, T>, shared: Value<'b>) -> Option<Value<'b>> {
    let _ = session;
    let mut v = shared.try_member_raw("synced").ok().flatten()?;
    // The loom shim wraps std's Mutex, whose guarded value is
    // `data: UnsafeCell<T>` with the value in `value`.
    for step in ["__0", "data", "value"] {
        if let Ok(Some(next)) = v.try_member_raw(step) {
            v = next;
        }
    }
    v.try_member_raw("inject")
        .ok()
        .flatten()?
        .try_member_raw("head")
        .ok()
        .flatten()
}

/// Follow `Header.queue_next` from a list head (`Option<NonNull<Header>>`).
fn linked_tasks<'b, T: Target>(session: &Session<'b, T>, head: Value<'b>) -> Vec<u64> {
    let mut out = Vec::new();
    let mut link = head;
    while out.len() < 4096 {
        let Some(addr) = word(&link).filter(|&w| w != 0) else {
            break;
        };
        out.push(addr);
        let next = link
            .try_select_variant("Some")
            .ok()
            .flatten()
            .and_then(|nn| nn.deref_ptr(session.ctx.proc).ok())
            .and_then(|header| header.try_member_raw("queue_next").ok().flatten());
        match next {
            Some(n) => link = unwrap_cells(n),
            None => break,
        }
    }
    out
}

/// Through the cells a link sits in — tokio's loom `UnsafeCell` (a
/// tuple struct, `__0`) around std's (`value`) — to the `Option`.
fn unwrap_cells(mut v: Value<'_>) -> Value<'_> {
    for _ in 0..4 {
        if v.is_enum() {
            break;
        }
        match ["__0", "value"]
            .iter()
            .find_map(|m| v.try_member_raw(m).ok().flatten())
        {
            Some(inner) => v = inner,
            None => break,
        }
    }
    v
}

/// A value's leading word, as a pointer-sized or smaller integer.
fn word(v: &Value<'_>) -> Option<u64> {
    let bytes = v.bytes;
    match bytes.len() {
        8.. => Some(u64::from_le_bytes(bytes[..8].try_into().ok()?)),
        4..=7 => Some(u64::from(u32::from_le_bytes(bytes[..4].try_into().ok()?))),
        2 | 3 => Some(u64::from(u16::from_le_bytes(bytes[..2].try_into().ok()?))),
        1 => Some(u64::from(bytes[0])),
        _ => None,
    }
}

fn member_word(v: &Value<'_>, name: &str) -> Option<u64> {
    word(&v.try_member(name).ok().flatten()?)
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Waker-based task dependency analysis: what every task is waiting
//! on, who wakes whom, and the futurelocks those edges reveal.
//!
//! The edges come from three reads the bundle backend already makes:
//! `JoinHandle` leaves name the awaited task, semaphore leaves carry
//! the contended semaphore and its wake queue (each queued waker
//! resolved back to a task), and the off-path acquire scan finds lock
//! futures a task holds but will never poll again. Assembling them
//! per-runtime turns individual traces into a diagnosis: a task
//! blocked on a semaphore whose permit sits in an abandoned future is
//! futurelocked (RFD 609), even when — especially when — the holder
//! is the blocked task itself.

use super::bundle::{
    AbandonedAcquire, Context, FutureInfo, Interest, Registries, TaskList, TaskStage, WaitTarget,
};
use super::{Lifecycle, TaskAddr};

use proc::Target;

use std::collections::HashMap;
use std::fmt;

/// A task, named by id when it has one.
#[derive(Copy, Clone, Debug)]
pub struct TaskRef {
    pub addr: TaskAddr,
    pub task_id: Option<u64>,
}

impl fmt::Display for TaskRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.task_id {
            Some(id) => write!(f, "task {id}"),
            None => write!(f, "the task at {:?}", self.addr),
        }
    }
}

/// One task's wait edge.
#[derive(Debug)]
pub struct TaskWait {
    pub task: TaskRef,
    /// What the task's await chain bottoms out in, when it is running
    /// and the leaf is a recognized primitive.
    pub target: Option<WaitTarget>,
    /// How many futures deep the task's await chain runs — the future
    /// it was spawned with, plus everything it is awaiting through, so
    /// a task awaiting nothing is 1. Zero where there is no resident
    /// chain to walk: a finished task, or one whose stage did not
    /// decode.
    pub depth: usize,
    /// The type the chain bottoms out in, however ordinary a future it
    /// is; see [`AwaitChain::leaf`]. `target` says what that leaf *is*
    /// for the few primitives hansei decodes, so this is what a task
    /// waits on where nothing decoded it.
    pub leaf: Option<String>,
    /// The outermost live await site on the chain: the first frame,
    /// walking from the root, whose live state records one — the line
    /// of the task's own code it is suspended behind, rather than of
    /// the libraries awaited through. That is the root frame's own
    /// site whenever the root is a coroutine; a root that is a wrapper
    /// (an `Instrumented`, a boxed `dyn`) has no state to record one,
    /// and the first coroutine below it answers instead. `None` where
    /// no frame records one: no resident chain (never polled,
    /// finished), or a chain of plain futures end to end.
    pub site: Option<(String, u32)>,
}

/// A diagnosed futurelock (RFD 609): an abandoned acquire clogging a
/// semaphore.
#[derive(Debug)]
pub struct Futurelock {
    /// The task whose locals hold the abandoned acquire.
    pub holder: TaskRef,
    pub acquire: AbandonedAcquire,
    /// Tasks whose active await chains are blocked on the same
    /// semaphore. The holder itself commonly appears here — the
    /// self-deadlock shape.
    pub blocked: Vec<TaskRef>,
}

/// The runtime-wide analysis.
#[derive(Debug)]
pub struct Analysis {
    /// One entry per task, in [`TaskList`] order.
    pub waits: Vec<TaskWait>,
    pub futurelocks: Vec<Futurelock>,
    /// Per-task analysis failures; the entries above are unaffected
    /// by them.
    pub errors: Vec<anyhow::Error>,
}

/// Walk every task's await chain and assemble the dependency edges and
/// futurelock diagnoses.
pub fn analyze<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    registries: &Registries,
) -> Analysis {
    let mut waits = Vec::new();
    let mut errors = Vec::new();
    let mut abandoned: Vec<(TaskRef, AbandonedAcquire)> = Vec::new();

    for task in &list.tasks {
        let tref = TaskRef {
            addr: task.addr,
            task_id: task.task_id,
        };
        let mut target = None;
        let mut depth = 0;
        let mut leaf = None;
        let mut site = None;
        // Unknown futures cannot be traced (the task listing already
        // calls them out); finished tasks wait on nothing.
        if matches!(task.future, FutureInfo::Known(_)) {
            match ctx.task_stage(task) {
                Ok(TaskStage::Running(future)) => {
                    let chain = ctx.await_chain(future);
                    depth = chain.frames.len();
                    leaf = chain.leaf().map(str::to_string);
                    site = chain
                        .frames
                        .iter()
                        .find_map(|frame| frame.state.as_ref()?.await_loc)
                        .map(|(file, line)| (file.to_string(), line));
                    match ctx.wait_target(&chain, list) {
                        Some(Ok(t)) => target = Some(t),
                        Some(Err(e)) => {
                            errors.push(e.context(format!("failed to read what {tref} waits on")))
                        }
                        None => {}
                    }
                    for acquire in ctx.abandoned_acquires(&chain) {
                        abandoned.push((tref, acquire));
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    errors.push(e.context(format!("failed to read the stage of {tref}")));
                }
            }
        }
        // The registry join: a parked task whose chain decoded no
        // primitive but whose waker sits on exactly one io resource is
        // waiting on that resource — the driver's own registration
        // list says so. A task also armed on a timer (a `select!` over
        // both) keeps its leaf spelling, since naming one arm of a
        // race as the wait would mislead; `-v` lists every entry.
        if target.is_none()
            && !matches!(
                task.state.lifecycle(),
                Lifecycle::Running | Lifecycle::Complete
            )
            && registries.timers_of(task.addr.0).next().is_none()
        {
            let io: Vec<_> = registries.io_of(task.addr.0).collect();
            if let Some((first, _)) = io.first()
                && io.iter().all(|(res, _)| res.addr == first.addr)
            {
                let interest = io
                    .iter()
                    .filter_map(|(_, waiter)| waiter.slot.interest())
                    .reduce(Interest::union);
                target = Some(WaitTarget::Io {
                    addr: first.addr,
                    fd: None,
                    interest,
                });
            }
        }
        waits.push(TaskWait {
            task: tref,
            target,
            depth,
            leaf,
            site,
        });
    }

    // Who is actively blocked on which semaphore.
    let mut blocked_on: HashMap<u64, Vec<TaskRef>> = HashMap::new();
    for wait in &waits {
        if let Some(WaitTarget::Semaphore { addr, .. }) = &wait.target {
            blocked_on.entry(*addr).or_default().push(wait.task);
        }
    }

    // Every abandoned acquire is a diagnosis: a granted one holds the
    // resource outright, and an ungranted one still holds a place in
    // the wake queue that the permit will eventually be wasted on —
    // whether or not anything is blocked behind it yet.
    let futurelocks = abandoned
        .into_iter()
        .map(|(holder, acquire)| Futurelock {
            blocked: blocked_on
                .get(&acquire.semaphore)
                .cloned()
                .unwrap_or_default(),
            holder,
            acquire,
        })
        .collect();

    Analysis {
        waits,
        futurelocks,
        errors,
    }
}

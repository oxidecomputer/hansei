// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The task dependency analysis: what every task is assessed to be
//! waiting on, who wakes whom, and the conditional polling barriers
//! the exclusive chains establish.
//!
//! Every task is inspected once by its programs ([`Context::
//! inspect_future`]) and assessed under its resources' protocols
//! ([`Context::assess_wait`]); the join edge is also read from the
//! awaited side, off the trailer waker the joined task holds. A
//! `Waiting` assessment is the only definite dependency here. A
//! polling barrier — an acquire a task holds in a future its own
//! exclusive chain cannot poll until its terminal completes — is a
//! conditional diagnosis (RFD 609's futurelock, with the condition
//! spelled), and what it says about the other tasks queued on that
//! semaphore is a reservation or a queue-order relation, never a wait.
//!
//! [`Context::inspect_future`]: super::bundle::Context::inspect_future
//! [`Context::assess_wait`]: super::bundle::Context::assess_wait

use super::assess::{
    Assessed, AssessmentPass, ContinuationStatus, IncompleteReason, NotWaitingReason,
    PollingBarrier, TaskFacts, VerifiedWait, WaitAssessment, WaitUnknownReason,
};
use super::bundle::{Context, FutureInfo, QueuedWaker, TaskList, TaskStage, WaitTarget};
use super::chain::InspectionMode;
use super::observe::{ReadContext, ResourceObservation};
use super::{Lifecycle, TaskAddr};

use proc::Target;

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

/// One task's assessment: the compact projection of its inspection a
/// listing keeps after the chain itself is dropped.
#[derive(Debug)]
pub struct TaskWait {
    pub task: TaskRef,
    /// The one interpretation of the task's chain and resource: a
    /// verified wait, a ready resource, a terminal or runnable state,
    /// or unknown with its reason.
    pub assessment: WaitAssessment,
    /// How the chain ended, owned.
    pub continuation: ContinuationStatus,
    /// How many futures deep the task's await chain runs — the future
    /// it was spawned with, plus everything it is awaiting through, so
    /// a task awaiting nothing is 1. Zero where there is no resident
    /// chain to walk: a finished task, or one whose root did not read.
    pub depth: usize,
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
    /// The raw observation read from the chain's primitive, whatever
    /// the assessment made of it.
    pub observation: Option<ResourceObservation>,
    /// What the protocol read that decided or declined the assessment.
    pub notes: Vec<String>,
}

impl TaskWait {
    /// The verified wait, when the assessment is one.
    pub fn verified(&self) -> Option<&VerifiedWait> {
        self.assessment.verified()
    }
}

/// A waker parked in a task's `Trailer`: the join edge read from the
/// awaited side. `task` is the task whose trailer holds the waker —
/// the one being awaited — and `waiter` is the task the armed waker
/// schedules when the join completes.
#[derive(Copy, Clone, Debug)]
pub struct JoinWaker {
    pub task: TaskRef,
    pub waiter: TaskRef,
}

/// How a verified semaphore wait stands to a polling barrier's acquire
/// on the same semaphore. Neither is a wait on the barrier's holder:
/// capacity, other holders and releases decide whether the waiter
/// progresses, and nothing here proves it cannot.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BarrierRelation {
    /// The barrier's acquire was granted whole: it holds permits, a
    /// reservation every waiter on the semaphore is short of.
    Reservation,
    /// The barrier's acquire is still queued, at a wake-order position
    /// ahead of the waiter's: the permit that reaches its node reaches
    /// it first.
    QueueOrder,
}

/// One verified semaphore wait standing behind one barrier's acquire.
#[derive(Copy, Clone, Debug)]
pub struct Behind {
    /// Index into [`Analysis::waits`].
    pub waiter: usize,
    /// Index into [`Analysis::barriers`].
    pub barrier: usize,
    pub relation: BarrierRelation,
}

/// The runtime-wide analysis.
#[derive(Debug)]
pub struct Analysis {
    /// One entry per task, in [`TaskList`] order.
    pub waits: Vec<TaskWait>,
    /// The conditional polling barriers the exclusive chains establish.
    pub barriers: Vec<PollingBarrier>,
    /// Every armed task waker parked in a listed task's `Trailer`.
    pub join_wakers: Vec<JoinWaker>,
    /// Per-task analysis failures; the entries above are unaffected
    /// by them.
    pub errors: Vec<anyhow::Error>,
}

impl Analysis {
    /// Every verified semaphore wait behind a barrier's acquire on its
    /// semaphore: the typed relations a consumer draws, in place of
    /// any same-semaphore cross product of its own. A reservation
    /// reaches every waiter; a queued acquire reaches only the waiters
    /// at greater wake-order positions in the same established queue —
    /// with no position on either side, nothing.
    pub fn behind(&self) -> Vec<Behind> {
        let mut out = Vec::new();
        for (barrier, held) in self.barriers.iter().enumerate() {
            for (waiter, wait) in self.waits.iter().enumerate() {
                let Some(verified) = wait.verified() else {
                    continue;
                };
                let WaitTarget::Semaphore { addr, .. } = verified.target() else {
                    continue;
                };
                if *addr != held.acquire.semaphore.addr {
                    continue;
                }
                let relation = if held.granted() {
                    BarrierRelation::Reservation
                } else {
                    match (held.acquire.queue_position, verified.queue_position()) {
                        (Some(ahead), Some(behind)) if ahead < behind => {
                            BarrierRelation::QueueOrder
                        }
                        _ => continue,
                    }
                };
                out.push(Behind {
                    waiter,
                    barrier,
                    relation,
                });
            }
        }
        out
    }
}

/// Inspect and assess every task in `list` under `read`, sharing one
/// pass's queue and registration observations across them, and read
/// the join edges off the awaited side.
pub fn analyze<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    read: &ReadContext<'_>,
) -> Analysis {
    let mut pass = AssessmentPass::new();
    let mut waits = Vec::with_capacity(list.tasks.len());
    let mut barriers = Vec::new();
    let mut join_wakers = Vec::new();
    let mut errors = Vec::new();
    for task in &list.tasks {
        let tref = TaskRef {
            addr: task.addr,
            task_id: task.task_id,
        };
        // The join edge from the awaited side: whatever the task's own
        // chain says, its Trailer holds the waker of any task awaiting
        // its `JoinHandle` — armed by that task's first poll of the
        // handle, so the slot answers "what would wake the joiner"
        // even when the joiner's chain did not decode.
        match ctx.trailer_waker(task) {
            Ok(QueuedWaker::Task { addr, task_id }) => join_wakers.push(JoinWaker {
                task: tref,
                waiter: TaskRef {
                    addr: TaskAddr(addr),
                    task_id,
                },
            }),
            Ok(_) => {}
            Err(e) => errors.push(e.context(format!("failed to read {tref}'s trailer waker"))),
        }
        let facts = TaskFacts::from(task);
        let lifecycle = task.state.lifecycle();
        let unknown = |reason, note: String, continuation| TaskWait {
            task: tref,
            assessment: WaitAssessment::Unknown(reason),
            continuation,
            depth: 0,
            site: None,
            observation: None,
            notes: vec![note],
        };
        let no_root = ContinuationStatus::Incomplete {
            reason: IncompleteReason::NoRoot,
            detail: None,
        };
        if !matches!(task.future, FutureInfo::Known(_)) {
            waits.push(unknown(
                WaitUnknownReason::Continuation,
                "the task's future type is not in the tokio info".to_owned(),
                no_root,
            ));
            continue;
        }
        // A complete task's storage is dropped: nothing is read.
        if lifecycle == Lifecycle::Complete {
            waits.push(TaskWait {
                task: tref,
                assessment: WaitAssessment::NotWaiting(NotWaitingReason::Complete),
                continuation: no_root,
                depth: 0,
                site: None,
                observation: None,
                notes: Vec::new(),
            });
            continue;
        }
        let root = match ctx.task_root(task, read) {
            Ok(TaskStage::Running(root)) => root,
            Ok(TaskStage::Finished(_) | TaskStage::Consumed) => {
                waits.push(unknown(
                    WaitUnknownReason::Lifecycle,
                    "the stage holds no resident future, yet the state word is not complete"
                        .to_owned(),
                    no_root,
                ));
                continue;
            }
            Err(e) => {
                waits.push(unknown(
                    WaitUnknownReason::ResourceUnreadable,
                    format!("the root did not read: {e:#}"),
                    ContinuationStatus::Incomplete {
                        reason: IncompleteReason::Error,
                        detail: Some(format!("{e:#}")),
                    },
                ));
                errors.push(e.context(format!("failed to read the root of {tref}")));
                continue;
            }
        };
        let inspection = ctx.inspect_future(root, InspectionMode::Task { lifecycle }, read);
        let Assessed { assessment, notes } =
            ctx.assess_wait(&mut pass, &inspection, &facts, list, read);
        barriers.extend(ctx.polling_barriers(&mut pass, &inspection, &facts, read));
        let chain = &inspection.chain;
        waits.push(TaskWait {
            task: tref,
            assessment,
            continuation: ContinuationStatus::of(&chain.end),
            depth: chain.frames.len(),
            site: chain
                .frames
                .iter()
                .find_map(|frame| frame.state.as_ref()?.await_loc)
                .map(|(file, line)| (file.to_string(), line)),
            observation: inspection.primitive.value,
            notes,
        });
    }
    Analysis {
        waits,
        barriers,
        join_wakers,
        errors,
    }
}

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
use super::bundle::{Context, FutureInfo, QueuedWaker, Registries, TaskList, WaitTarget};
use super::observe::{ReadContext, ResourceObservation};
use super::waitset::{BranchScan, Branches, WaitMember};
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
    /// The stop frame's branches when the continuation is unknown and
    /// no evidence arms any of them: futures the task holds at its
    /// stop and, by everything read here, awaits none of. Empty for
    /// every other assessment — a set carries its members itself.
    pub held: Vec<WaitMember>,
    /// Branches past the listing cap at such a stop, counted only.
    pub held_capped: usize,
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
    /// Where the trailer's waker pair sits.
    pub waker_at: Option<u64>,
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
/// the join edges off the awaited side. `registries` are the wheel
/// entries and io waiters the attach harvested: the slots a wait set
/// is assembled from at an unknown stop, and the diagnostics beside a
/// verified wait they do not belong to.
pub fn analyze<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    registries: &Registries,
    read: &ReadContext<'_>,
) -> Analysis {
    let mut pass = AssessmentPass::new();
    let mut scan = BranchScan::default();
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
        match ctx.trailer_waker_slot(task) {
            Ok((QueuedWaker::Task { addr, task_id }, waker_at)) => join_wakers.push(JoinWaker {
                task: tref,
                waiter: TaskRef {
                    addr: TaskAddr(addr),
                    task_id,
                },
                waker_at,
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
            held: Vec::new(),
            held_capped: 0,
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
                held: Vec::new(),
                held_capped: 0,
            });
            continue;
        }
        let inspection = match ctx.inspect_task(task, read) {
            Ok(Some(inspection)) => inspection,
            Ok(None) => {
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
        let Assessed {
            mut assessment,
            mut notes,
        } = ctx.assess_wait(&mut pass, &inspection, &facts, list, read);
        barriers.extend(ctx.polling_barriers(&mut pass, &inspection, &facts, read));
        let chain = &inspection.chain;
        // Beside the assessment, the registries' slots: at an unknown
        // stop they and the stop's branches make the wait set; beside
        // a verified wait, one they do not belong to is a diagnostic.
        let (mut held, mut held_capped) = (Vec::new(), 0);
        match &assessment {
            WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {
                match ctx.wait_set(
                    &mut pass,
                    &inspection,
                    &facts,
                    list,
                    registries,
                    read,
                    &mut scan,
                ) {
                    Branches::Set(set) => assessment = WaitAssessment::Set(set),
                    Branches::Held { members, capped } => {
                        held = members;
                        held_capped = capped;
                    }
                    Branches::None => {}
                }
            }
            WaitAssessment::Waiting(verified) => {
                notes.extend(ctx.slot_diagnostics(chain, verified.target(), &facts, registries));
            }
            _ => {}
        }
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
            held,
            held_capped,
        });
    }
    Analysis {
        waits,
        barriers,
        join_wakers,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::super::assess::VerifiedWait;
    use super::super::observe::{AcquireObservation, ValueKey};
    use super::*;

    use hansei_bundle::BundleTypeId;

    fn key(addr: u64) -> ValueKey {
        ValueKey {
            addr,
            ty: BundleTypeId(0),
        }
    }

    fn semaphore(addr: u64) -> WaitTarget {
        WaitTarget::Semaphore {
            addr,
            owner: None,
            num_permits: 1,
            available: 0,
            closed: false,
            waiters: Vec::new(),
        }
    }

    /// Task `id`, verified waiting on `target` at wake-order
    /// `position`, where the queue placed it.
    fn wait(id: u64, target: WaitTarget, position: Option<usize>) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000 + id * 0x100),
                task_id: Some(id),
            },
            assessment: WaitAssessment::Waiting(VerifiedWait::testkit(target, position)),
            continuation: ContinuationStatus::Primitive,
            depth: 1,
            site: None,
            observation: None,
            notes: Vec::new(),
            held: Vec::new(),
            held_capped: 0,
        }
    }

    /// The waiters every case below is judged over: on the semaphore
    /// at 0x5000, one placed behind position 1, one ahead of it, one
    /// at it, one the queue did not place; and one on another
    /// semaphore altogether.
    fn waits() -> Vec<TaskWait> {
        vec![
            wait(1, semaphore(0x5000), Some(2)),
            wait(2, semaphore(0x5000), Some(0)),
            wait(3, semaphore(0x5000), Some(1)),
            wait(4, semaphore(0x5000), None),
            wait(5, semaphore(0x6000), Some(3)),
        ]
    }

    /// A barrier holding an acquire on `semaphore` that still needs
    /// `needed` permits, queued at `position`.
    fn barrier(semaphore: u64, needed: u64, position: Option<usize>) -> PollingBarrier {
        PollingBarrier {
            holder: TaskAddr(0x9000),
            holder_id: Some(9),
            frame: 0,
            frame_type: "h::fut".to_string(),
            state: "Suspend0".to_string(),
            await_loc: None,
            local: "held".to_string(),
            candidate: key(0x9100),
            future: "h::acquire".to_string(),
            owner: None,
            acquire: AcquireObservation {
                future: key(0x9100),
                semaphore: key(semaphore),
                node: 0x9200,
                requested: 1,
                needed,
                queued: needed > 0,
                queue_position: position,
            },
            primitive: key(0x9300),
            terminal: "h::leaf".to_string(),
            edges: Vec::new(),
        }
    }

    fn analysis(barrier: PollingBarrier) -> Analysis {
        Analysis {
            waits: waits(),
            barriers: vec![barrier],
            join_wakers: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// The relations as (waiter's task id, relation).
    fn relations(analysis: &Analysis) -> Vec<(u64, BarrierRelation)> {
        analysis
            .behind()
            .into_iter()
            .map(|b| {
                assert_eq!(b.barrier, 0);
                (analysis.waits[b.waiter].task.task_id.unwrap(), b.relation)
            })
            .collect()
    }

    /// A queued acquire reaches exactly the waiters at greater
    /// wake-order positions in its own queue: not the one ahead of it,
    /// not the one at its own position, not one the queue did not
    /// place, and nothing on another semaphore. A queued acquire the
    /// queue did not place reaches no one.
    #[test]
    fn test_a_queued_acquire_is_behind_only_the_positions_past_its_own() {
        assert_eq!(
            relations(&analysis(barrier(0x5000, 1, Some(1)))),
            [(1, BarrierRelation::QueueOrder)]
        );
        assert_eq!(relations(&analysis(barrier(0x5000, 1, None))), []);
    }

    /// A granted acquire is a reservation every waiter on its
    /// semaphore is short of, placed or not — and still nothing to a
    /// waiter on another semaphore.
    #[test]
    fn test_a_granted_acquire_is_a_reservation_every_waiter_is_behind() {
        assert_eq!(
            relations(&analysis(barrier(0x5000, 0, None))),
            [
                (1, BarrierRelation::Reservation),
                (2, BarrierRelation::Reservation),
                (3, BarrierRelation::Reservation),
                (4, BarrierRelation::Reservation),
            ]
        );
    }
}

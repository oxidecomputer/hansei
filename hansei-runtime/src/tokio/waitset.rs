// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The wait set: where a task's waker is parked when its chain stops
//! at a future no rule polls through.
//!
//! A `select!`, a `Timeout`, a hand-written connection state machine:
//! each polls several things and parks the task's waker in each of
//! them, and the chain — which is linear, and stays so — ends at it
//! with the continuation unknown. What *is* known is tokio's own
//! definition of awaiting: the places that hold this task's waker. Two
//! kinds of evidence say where those are. A **branch** is a future-typed
//! value the stop frame holds or borrows, inspected on its own under the
//! task's identity; a **slot** is a live waker location the registries
//! attribute to the task — a wheel entry, an io waiter. The two are
//! joined by containment: a slot inside a branch's storage arms that
//! branch. A branch whose own reviewed protocol read this task's waker
//! is armed by that protocol. A slot inside no branch is a member on
//! its own.
//!
//! The set is an *observation beside* the unknown continuation, never a
//! continuation itself, and it is **disjunctive**: any one member's wake
//! runs the task, and nothing here says the task is blocked until all
//! of them complete. Its consumers draw `WaitingOneOf` relations, which
//! close no cycle and establish no polling barrier — the guarantees a
//! verified `Waiting` carries are untouched. Containment alone arms
//! nothing: a branch that holds no waker of this task's is listed as
//! held, and a stop whose branches are all such prints `unknown` with
//! their count.

use super::assess::{Assessed, AssessmentPass, TaskFacts, WaitAssessment};
use super::bundle::{
    AwaitChain, AwaitFrame, ChainEnd, Context, IoSlot, Readiness, Registries, TaskList, WaitTarget,
    WheelState,
};
use super::census::{self, Find, Path, ScanPlan};
use super::chain::{FutureInspection, InspectionMode, NextFuture};
use super::observe::{ReadContext, ValueKey};

use foldhash::{HashMap, HashSet};
use hansei_bundle::{AccessKind, BundleTypeId, SemanticIssueKind};
use proc::Target;
use reify::Value;

/// How many branches a stop frame's set lists; the rest are counted.
pub const MAX_BRANCHES: usize = 8;

/// How many adapter hops a branch is followed through before it is
/// given up as no future: a `&mut Pin<Box<dyn Sleep>>` is two.
const MAX_ADAPTER_HOPS: usize = 4;

/// Where a task's waker is parked, beside a continuation no rule
/// establishes: the branches its stop frame polls and the slots the
/// registries attribute to it, any one of which wakes it.
#[derive(Debug)]
pub struct WaitSet {
    /// The stop frame the set was computed at.
    pub at: ValueKey,
    /// Why the chain ends there.
    pub reason: SemanticIssueKind,
    /// Every branch, armed or not, then every slot in no branch. At
    /// least one member is armed, or there is no set.
    pub members: Vec<WaitMember>,
    /// Branches past [`MAX_BRANCHES`]: found and counted, not
    /// inspected.
    pub capped: usize,
}

impl WaitSet {
    /// The members the waker is known to be parked in.
    pub fn armed(&self) -> impl Iterator<Item = &WaitMember> {
        self.members.iter().filter(|m| m.armed.is_some())
    }

    /// The cell: every armed member's entry, joined with ` + `, so
    /// a set of one reads exactly as a verified wait on the same
    /// resource would.
    pub fn cell(&self) -> String {
        self.armed()
            .filter_map(WaitMember::cell_entry)
            .collect::<Vec<_>>()
            .join(" + ")
    }

    /// The bucket: the armed members' kinds, distinct, sorted and
    /// joined with `+` — `io+timer` for a select over both.
    pub fn group_label(&self) -> String {
        let mut kinds: Vec<String> = self.armed().filter_map(WaitMember::kind).collect();
        kinds.sort();
        kinds.dedup();
        kinds.join("+")
    }
}

/// One thing the task's waker may be parked in.
#[derive(Debug)]
pub struct WaitMember {
    pub route: MemberRoute,
    /// The branch's identity — the future past the adapters it was
    /// reached through — where there is one.
    pub key: Option<ValueKey>,
    /// That future's type name, for a listing.
    pub future: Option<String>,
    /// The engine's own verdict on the branch under the task's
    /// identity: what its chain ends in and what that resource's
    /// protocol says. `None` for a slot in no branch.
    pub assessment: Option<WaitAssessment>,
    /// What the branch's protocol read, in words.
    pub notes: Vec<String>,
    /// The evidence this task's waker is parked here, or `None` for a
    /// branch merely held.
    pub armed: Option<SlotRef>,
}

impl WaitMember {
    /// The member's entry in a cell: its verified target where its
    /// protocol produced one, else the slot that arms it.
    /// `None` for an unarmed branch, which no cell names.
    pub fn cell_entry(&self) -> Option<String> {
        let armed = self.armed.as_ref()?;
        if let Some(WaitAssessment::Waiting(verified)) = &self.assessment {
            return Some(verified.target().to_string());
        }
        armed.cell_entry()
    }

    /// The kind-level word a bucket files the member under.
    pub fn kind(&self) -> Option<String> {
        let armed = self.armed.as_ref()?;
        if let Some(WaitAssessment::Waiting(verified)) = &self.assessment {
            return Some(verified.target().group_label());
        }
        armed.kind()
    }
}

/// How a member was reached.
#[derive(Clone, Debug)]
pub enum MemberRoute {
    /// A future the stop frame holds in `local`, by value or — with
    /// `borrowed` — through a `&mut`.
    Branch { local: String, borrowed: bool },
    /// A registry slot attributed to the task that lies in no branch.
    /// `within` places it in the task's own chain where it does lie
    /// there.
    SlotOnly { within: Option<String> },
}

/// The evidence a member holds this task's waker.
#[derive(Clone, Debug)]
pub enum SlotRef {
    /// A wheel entry armed with the task's waker.
    Wheel {
        entry: u64,
        state: Option<WheelState>,
    },
    /// An io resource's waiter site holding the task's waker.
    Io {
        resource: u64,
        slot: IoSlot,
        /// The fd, where a resource in the frames names one.
        fd: Option<i32>,
        ready: Option<Readiness>,
    },
    /// The branch's own reviewed protocol read this task's waker in
    /// the resource — a queue node, a receiver's cell, a trailer.
    Protocol,
}

impl SlotRef {
    /// The bare entry, for a member whose assessment names no
    /// target: the slot kind and the resource.
    fn cell_entry(&self) -> Option<String> {
        match self {
            Self::Wheel { entry, .. } => Some(format!("timer {entry:#x}")),
            Self::Io {
                resource, slot, fd, ..
            } => Some(
                WaitTarget::Io {
                    addr: *resource,
                    fd: *fd,
                    interest: slot.interest(),
                }
                .to_string(),
            ),
            Self::Protocol => None,
        }
    }

    fn kind(&self) -> Option<String> {
        match self {
            Self::Wheel { .. } => Some("timer".to_string()),
            Self::Io { .. } => Some("io".to_string()),
            Self::Protocol => None,
        }
    }

    /// The evidence, in words, for a detail line.
    pub fn detail(&self) -> String {
        match self {
            Self::Wheel { entry, state } => {
                let state = match state {
                    Some(state) => format!(", {state}"),
                    None => String::new(),
                };
                format!("this task's waker in wheel entry {entry:#x}{state}")
            }
            Self::Io {
                resource,
                slot,
                ready,
                ..
            } => {
                let site = match slot {
                    IoSlot::Reader => "the read-waiter slot".to_string(),
                    IoSlot::Writer => "the write-waiter slot".to_string(),
                    IoSlot::Listed { .. } => "a waiter node".to_string(),
                };
                let ready = match ready {
                    Some(ready) => format!(", ready: {ready}"),
                    None => String::new(),
                };
                format!("this task's waker in {site} of io {resource:#x}{ready}")
            }
            Self::Protocol => "its protocol read this task's waker".to_string(),
        }
    }
}

/// What the stop frame's branches and the task's slots amount to.
#[derive(Debug)]
pub enum Branches {
    /// At least one member is armed: a wait set.
    Set(WaitSet),
    /// Branches present, none armed, no slot: the task holds these and
    /// awaits none of them by any evidence here.
    Held {
        members: Vec<WaitMember>,
        capped: usize,
    },
    /// No branch and no slot.
    None,
}

/// One future-typed value the stop frame reaches.
struct Branch<'b> {
    local: String,
    borrowed: bool,
    value: Value<'b>,
}

/// Recognition for the branch scan: the census's, with borrowed
/// adapters admitted beside owned ones.
struct Branching<'a, 'b, T>(&'a Context<'b, T>);

impl<T: Target> census::Recognize for Branching<'_, '_, T> {
    fn recognize(&self, id: BundleTypeId) -> census::Recognized {
        use census::Recognized;
        match self.0.container_kind(id) {
            Some(hansei_bundle::ContainerKind::FuturesUnordered) => Recognized::Set,
            Some(hansei_bundle::ContainerKind::JoinSet) => Recognized::JoinSet,
            None if self.0.recognized_future(id) => Recognized::Future,
            None if self.0.any_adapter(id) => Recognized::Adapter,
            None if self.0.storage_unavailable(id) => Recognized::Unavailable,
            None => Recognized::Other,
        }
    }
}

/// The scan plans one analysis shares across every stop frame it
/// enumerates: a plan is a fact of the type.
#[derive(Default)]
pub struct BranchPlans {
    plans: HashMap<BundleTypeId, ScanPlan>,
}

/// Whether `addr` lies in `value`'s storage.
fn contains(value: Value<'_>, addr: u64) -> bool {
    addr >= value.addr && addr - value.addr < value.bytes.len() as u64
}

impl<'b, T: Target> Context<'b, T> {
    /// The future-typed values `frame` holds or borrows: its own locals
    /// scanned through their aggregates and active variants, every
    /// supported adapter followed to what it holds. Depth one — the
    /// frame's members, never a branch's — and capped at
    /// [`MAX_BRANCHES`], the rest counted.
    fn branches_at(
        &self,
        frame: &AwaitFrame<'b>,
        read: &ReadContext<'_>,
        plans: &mut BranchPlans,
    ) -> (Vec<Branch<'b>>, usize) {
        let mut branches = Vec::new();
        let mut capped = 0;
        let mut counts = census::Capped::default();
        let mut stats = census::Stats::default();
        let facts = Branching(self);
        for (name, local) in census::frame_locals(self, frame).locals {
            let mut found = Vec::new();
            census::scan_value(
                local,
                &facts,
                0,
                census::MAX_SCAN_DEPTH,
                Path::default(),
                &mut found,
                &mut counts,
                &mut plans.plans,
                &mut stats,
            );
            for find in found {
                let (value, borrowed) = match find {
                    Find::Future(value) => (value, false),
                    Find::Adapter(adapter) => match self.follow_adapters(adapter, read) {
                        Some(landed) => landed,
                        None => continue,
                    },
                    // A container's children are polled with the
                    // container's own wakers, not the task's: a set
                    // here is not a branch of this task's waker.
                    Find::Set(_) | Find::JoinSet(_) => continue,
                };
                if branches.len() >= MAX_BRANCHES {
                    capped += 1;
                    continue;
                }
                branches.push(Branch {
                    local: name.to_string(),
                    borrowed,
                    value,
                });
            }
        }
        (branches, capped)
    }

    /// Follow an adapter through its recorded routes to the future it
    /// holds, noting whether any hop was a borrow. `None` where no
    /// route lands on a future within the hop bound.
    fn follow_adapters(
        &self,
        adapter: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Option<(Value<'b>, bool)> {
        let mut cur = adapter;
        let mut borrowed = false;
        for _ in 0..MAX_ADAPTER_HOPS {
            let access = self.type_semantics(cur.ty.id())?.access.as_ref()?;
            borrowed |= access.kind == AccessKind::Borrowed;
            let NextFuture::Next { future, .. } = self.access_referent(cur, read)? else {
                return None;
            };
            if self.recognized_future(future.ty.id()) {
                return Some((future, borrowed));
            }
            cur = future;
        }
        None
    }

    /// The wait set at an unknown stop: the stop frame's branches, each
    /// inspected and assessed under `task`'s identity, joined to the
    /// wheel entries and io waiters `registries` attribute to the task.
    /// Only for a chain ending in [`ChainEnd::UnknownContinuation`]:
    /// every other end already says what the task is doing.
    #[allow(clippy::too_many_arguments)]
    pub fn wait_set(
        &self,
        pass: &mut AssessmentPass,
        inspection: &FutureInspection<'b>,
        task: &TaskFacts,
        list: &TaskList,
        registries: &Registries,
        read: &ReadContext<'_>,
        plans: &mut BranchPlans,
    ) -> Branches {
        let chain = &inspection.chain;
        let ChainEnd::UnknownContinuation { at, reason } = &chain.end else {
            return Branches::None;
        };
        let Some(stop) = chain.frames.last() else {
            return Branches::None;
        };
        let (branches, capped) = self.branches_at(stop, read, plans);
        let on_chain: HashSet<ValueKey> = chain.referents().collect();
        let mut seen: HashSet<ValueKey> = HashSet::default();
        let mut members: Vec<WaitMember> = Vec::new();
        let mut chains: Vec<AwaitChain<'b>> = Vec::new();
        for branch in branches {
            let held = self.inspect_future(branch.value, InspectionMode::Held, read);
            // The branch's identity is the first frame past the
            // adapters it was held through, as the census lists a
            // find; a `&mut` among those adapters — a reference the
            // frame borrows, whether found as the future it is or
            // followed as the adapter it also is — makes it borrowed.
            let access = |f: &AwaitFrame<'b>| {
                self.type_semantics(f.future.ty.id())
                    .and_then(|record| record.access.as_ref())
                    .map(|access| access.kind)
            };
            let (index, identity) = held
                .chain
                .frames
                .iter()
                .enumerate()
                .find(|(_, f)| access(f).is_none())
                .unwrap_or((0, &held.chain.frames[0]));
            let borrowed = branch.borrowed
                || held.chain.frames[..index]
                    .iter()
                    .any(|f| access(f) == Some(AccessKind::Borrowed));
            let key = ValueKey::of(identity.future);
            // A branch that is a frame of the task's own chain is that
            // frame, not something the stop polls beside it; a branch
            // reached twice is one branch.
            if on_chain.contains(&key) || !seen.insert(key) {
                continue;
            }
            let Assessed { assessment, notes } = self.assess_wait(pass, &held, task, list, read);
            members.push(WaitMember {
                route: MemberRoute::Branch {
                    local: branch.local,
                    borrowed,
                },
                key: Some(key),
                future: Some(identity.future.ty.name().to_string()),
                assessment: Some(assessment),
                notes,
                armed: None,
            });
            chains.push(held.chain);
        }

        // The slots: each placed in the branch whose storage holds it,
        // or listed on its own.
        let placed = |chains: &[AwaitChain<'b>], addr: u64| {
            chains
                .iter()
                .position(|chain| chain.frames.iter().any(|f| contains(f.future, addr)))
        };
        let within = |addr: u64| {
            chain.frames.iter().enumerate().find_map(|(i, f)| {
                contains(f.future, addr).then(|| {
                    format!(
                        "inside #{}'s storage at +{:#x}",
                        chain.frames.len() - 1 - i,
                        addr - f.future.addr
                    )
                })
            })
        };
        let mut slot_only = Vec::new();
        let mut arm =
            |members: &mut Vec<WaitMember>, index: Option<usize>, slot: SlotRef, at| match index {
                Some(i) if members[i].armed.is_none() => members[i].armed = Some(slot),
                Some(i) => members[i]
                    .notes
                    .push(format!("also armed: {}", slot.detail())),
                None => slot_only.push(WaitMember {
                    route: MemberRoute::SlotOnly { within: within(at) },
                    key: None,
                    future: None,
                    assessment: None,
                    notes: Vec::new(),
                    armed: Some(slot),
                }),
            };
        for timer in registries.timers_of(task.addr.0) {
            let slot = SlotRef::Wheel {
                entry: timer.entry,
                state: timer.wheel_state(),
            };
            arm(
                &mut members,
                placed(&chains, timer.entry),
                slot,
                timer.entry,
            );
        }
        for (resource, waiter) in registries.io_of(task.addr.0) {
            let frames: Vec<Value<'b>> = chain
                .frames
                .iter()
                .chain(chains.iter().flat_map(|c| c.frames.iter()))
                .map(|f| f.future)
                .collect();
            let slot = SlotRef::Io {
                resource: resource.addr,
                slot: waiter.slot,
                fd: self.io_resource_fd(&frames, resource.addr),
                ready: resource.ready(),
            };
            // A listed node lies in the readiness future that owns it;
            // a direction slot lies in the `ScheduledIo`, in no branch.
            let (index, at) = match waiter.node {
                Some(node) => (placed(&chains, node), node),
                None => (None, resource.addr),
            };
            arm(&mut members, index, slot, at);
        }
        members.extend(slot_only);

        // A branch whose own protocol found this task's waker is armed
        // by that protocol — every protocol but the timer's reads the
        // waker, and a timer's evidence is its wheel entry above.
        for member in &mut members {
            if member.armed.is_some() {
                continue;
            }
            let Some(WaitAssessment::Waiting(verified)) = &member.assessment else {
                continue;
            };
            if matches!(verified.target(), WaitTarget::Timer { .. }) {
                member.notes.push(
                    "registered per its protocol, but no wheel entry of this task's lies in it"
                        .to_string(),
                );
                continue;
            }
            member.armed = Some(SlotRef::Protocol);
        }

        if members.iter().any(|m| m.armed.is_some()) {
            Branches::Set(WaitSet {
                at: *at,
                reason: *reason,
                members,
                capped,
            })
        } else if members.is_empty() && capped == 0 {
            Branches::None
        } else {
            Branches::Held { members, capped }
        }
    }

    /// The registry slots attributed to `task` that its verified wait
    /// does not account for: a wheel entry outside the primitive, an io
    /// resource other than the one awaited. Each is a diagnostic — a
    /// stale slot surfacing, or a second registration the chain does
    /// not reach — never a reason to alter the wait.
    pub fn slot_diagnostics(
        &self,
        chain: &AwaitChain<'b>,
        target: &WaitTarget,
        task: &TaskFacts,
        registries: &Registries,
    ) -> Vec<String> {
        let mut notes = Vec::new();
        let primitive = chain.frames.last().map(|f| f.future);
        for timer in registries.timers_of(task.addr.0) {
            let placed = matches!(target, WaitTarget::Timer { .. })
                && primitive.is_some_and(|p| contains(p, timer.entry));
            if !placed {
                notes.push(format!(
                    "the wheel entry {:#x} also holds this task's waker, outside the verified wait",
                    timer.entry
                ));
            }
        }
        for (resource, waiter) in registries.io_of(task.addr.0) {
            let placed = matches!(target, WaitTarget::Io { addr, .. } if *addr == resource.addr);
            if !placed {
                let site = match waiter.slot {
                    IoSlot::Reader => "read-waiter slot",
                    IoSlot::Writer => "write-waiter slot",
                    IoSlot::Listed { .. } => "waiter node",
                };
                notes.push(format!(
                    "io {:#x} also holds this task's waker in a {site}, outside the verified wait",
                    resource.addr
                ));
            }
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, load_any};
    use crate::tokio::assess::WaitUnknownReason;
    use crate::tokio::bundle::{FutureInfo, IoResourceInfo, IoWaiterInfo, Task, TimerEntryInfo};
    use crate::tokio::observe::Consistency;

    use hansei_bundle::tokio::timer;
    use proc::snapshot::Snapshot;

    fn task_named<'a>(list: &'a TaskList, name: &str) -> &'a Task {
        let hits: Vec<&Task> = list
            .tasks
            .iter()
            .filter(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
            .collect();
        assert_eq!(hits.len(), 1, "one task named {name}: {hits:?}");
        hits[0]
    }

    /// The wait set of `task` under `registries`, over a healthy pair.
    fn branches_of(
        ctx: &Context<'_, Snapshot>,
        list: &TaskList,
        task: &Task,
        registries: &Registries,
    ) -> Branches {
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .expect("the root reads")
            .expect("the task holds a resident future");
        ctx.wait_set(
            &mut AssessmentPass::new(),
            &inspection,
            &TaskFacts::from(task),
            list,
            registries,
            &ReadContext::none(),
            &mut BranchPlans::default(),
        )
    }

    fn wheel(entry: u64, task: &Task) -> TimerEntryInfo {
        TimerEntryInfo {
            entry,
            state: Some(1000),
            task: Some(task.addr.0),
        }
    }

    fn io(resource: u64, node: Option<u64>, task: &Task) -> IoResourceInfo {
        IoResourceInfo {
            addr: resource,
            readiness: Some(0b10),
            consistency: Consistency::Quiescent,
            waiters: vec![IoWaiterInfo {
                slot: match node {
                    Some(_) => IoSlot::Listed { interest: None },
                    None => IoSlot::Reader,
                },
                task: Some(task.addr.0),
                node,
                ready: None,
            }],
        }
    }

    /// `walk-shapes`'s `chained` stops at `WrapS`, a wrapper no rule
    /// covers, holding a `WrapE` by value: one branch, its own
    /// continuation unknown, and — with nothing armed anywhere — held
    /// rather than a set. The Notify its innermost future is queued on
    /// is past the branch's own stop, so nothing here reaches it.
    #[test]
    fn test_a_stop_whose_branch_holds_no_slot_is_held_not_a_set() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "chained");
        let Branches::Held { members, capped } =
            branches_of(&ctx, &list, task, &Registries::default())
        else {
            panic!("held");
        };
        assert_eq!(capped, 0);
        assert_eq!(members.len(), 1, "{members:#?}");
        let member = &members[0];
        assert!(
            matches!(&member.route, MemberRoute::Branch { local, borrowed: false } if local == "inner"),
            "{member:#?}"
        );
        assert!(
            member
                .future
                .as_deref()
                .unwrap()
                .starts_with("walk_shapes::WrapE"),
            "{member:#?}"
        );
        assert!(
            matches!(
                member.assessment,
                Some(WaitAssessment::Unknown(WaitUnknownReason::Continuation))
            ),
            "{member:#?}"
        );
        assert!(member.armed.is_none());
        assert_eq!(member.cell_entry(), None);
    }

    /// A wheel entry attributed to the task inside the branch's
    /// storage arms that branch and nothing else: the set names the
    /// entry (the branch's own verdict names no target), buckets as a
    /// timer, and the member carries the entry as its evidence. A
    /// second entry inside the same branch is a note, not a second
    /// member.
    #[test]
    fn test_a_wheel_entry_inside_a_branch_arms_it() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "chained");
        let Branches::Held { members, .. } = branches_of(&ctx, &list, task, &Registries::default())
        else {
            panic!("held");
        };
        let key = members[0].key.expect("a branch has a key");
        let inside = key.addr + 8;
        let registries = Registries::new(
            vec![wheel(inside, task), wheel(inside + 8, task)],
            Vec::new(),
        );
        let Branches::Set(set) = branches_of(&ctx, &list, task, &registries) else {
            panic!("a set");
        };
        assert_eq!(set.members.len(), 1, "{set:#?}");
        assert_eq!(set.armed().count(), 1);
        assert_eq!(set.cell(), format!("timer {inside:#x}"));
        assert_eq!(set.group_label(), "timer");
        let member = &set.members[0];
        assert!(
            matches!(member.armed, Some(SlotRef::Wheel { entry, .. }) if entry == inside),
            "{member:#?}"
        );
        assert!(
            member.notes.iter().any(|n| n.starts_with("also armed:")),
            "{member:#?}"
        );
        assert_eq!(set.at.ty, inspection_stop(&ctx, task));
    }

    fn inspection_stop(ctx: &Context<'_, Snapshot>, task: &Task) -> BundleTypeId {
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        inspection.chain.frames.last().unwrap().future.ty.id()
    }

    /// A slot in no branch is a member of its own, named by its kind
    /// and placed in the task's own chain where it lies there; a
    /// direction slot lies in the `ScheduledIo` and so nowhere in the
    /// task, and a listed node inside a branch arms the branch.
    #[test]
    fn test_a_slot_in_no_branch_is_a_member_on_its_own() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "chained");
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        // The task's own root frame holds the stop, and the stop its
        // branch, inline: a slot in the root's storage outside the
        // stop's is in no branch.
        let root = inspection.chain.frames[0].future;
        let stop = inspection.chain.frames.last().unwrap().future;
        let outside = (0..root.bytes.len() as u64)
            .step_by(8)
            .map(|off| root.addr + off)
            .find(|&addr| !contains(stop, addr))
            .expect("the root frame has storage beside the stop");
        let Branches::Held { members, .. } = branches_of(&ctx, &list, task, &Registries::default())
        else {
            panic!("held");
        };
        let branch = members[0].key.unwrap().addr;
        assert!(contains(stop, branch), "the branch lies in the stop");
        let registries = Registries::new(
            vec![wheel(outside, task)],
            vec![io(0x7000, None, task), io(0x7100, Some(branch + 4), task)],
        );
        let Branches::Set(set) = branches_of(&ctx, &list, task, &registries) else {
            panic!("a set");
        };
        let lines: Vec<String> = set
            .members
            .iter()
            .map(|m| format!("{:?} {:?}", m.route, m.cell_entry()))
            .collect();
        assert_eq!(set.members.len(), 3, "{lines:#?}");
        // The branch, armed by the listed node inside it.
        assert!(
            matches!(
                &set.members[0].armed,
                Some(SlotRef::Io {
                    resource: 0x7100,
                    slot: IoSlot::Listed { .. },
                    ..
                })
            ),
            "{lines:#?}"
        );
        // The wheel entry in the root frame, and the direction slot
        // in no frame at all, each on their own.
        let within = |m: &WaitMember| match &m.route {
            MemberRoute::SlotOnly { within } => within.clone(),
            _ => panic!("slot only"),
        };
        let frames = inspection.chain.frames.len();
        assert_eq!(
            within(&set.members[1]),
            Some(format!(
                "inside #{}'s storage at +{:#x}",
                frames - 1,
                outside - root.addr
            ))
        );
        assert_eq!(
            set.members[1].cell_entry(),
            Some(format!("timer {outside:#x}"))
        );
        assert_eq!(within(&set.members[2]), None);
        assert_eq!(
            set.members[2].cell_entry(),
            Some("io 0x7000 (readable)".to_string())
        );
        assert_eq!(
            set.cell(),
            format!("io 0x7100 (readiness) + timer {outside:#x} + io 0x7000 (readable)")
        );
        assert_eq!(set.group_label(), "io+timer");
    }

    /// Every other end of a chain — a verified primitive here — has no
    /// set to compute, whatever the registries hold.
    #[test]
    fn test_only_an_unknown_continuation_has_a_set() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "sleeper");
        let registries = Registries::new(vec![wheel(0x4000, task)], Vec::new());
        assert!(matches!(
            branches_of(&ctx, &list, task, &registries),
            Branches::None
        ));
    }

    /// Beside a verified wait, a registry slot the wait accounts for is
    /// silent — the sleeper's entry inside its `Sleep` — and one it
    /// does not is a diagnostic: a wheel entry elsewhere, an io slot
    /// on a task awaiting a timer.
    #[test]
    fn test_a_slot_outside_a_verified_wait_is_a_diagnostic() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "sleeper");
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        let sleep = inspection.chain.frames.last().unwrap().future;
        let target = WaitTarget::Timer {
            deadline: crate::tokio::RawInstant {
                tv_sec: 0,
                tv_nsec: 0,
            },
            stopped: None,
        };
        let facts = TaskFacts::from(task);
        let quiet = Registries::new(vec![wheel(sleep.addr + 8, task)], Vec::new());
        assert_eq!(
            ctx.slot_diagnostics(&inspection.chain, &target, &facts, &quiet),
            Vec::<String>::new()
        );
        let loud = Registries::new(vec![wheel(0x4000, task)], vec![io(0x7000, None, task)]);
        let notes = ctx.slot_diagnostics(&inspection.chain, &target, &facts, &loud);
        assert_eq!(notes.len(), 2, "{notes:#?}");
        assert!(notes[0].contains("wheel entry 0x4000 also holds this task's waker"));
        assert!(notes[1].contains("io 0x7000 also holds this task's waker in a read-waiter slot"));
        // An io wait accounts for its own resource, whichever site.
        let io_target = WaitTarget::Io {
            addr: 0x7000,
            fd: None,
            interest: None,
        };
        let notes = ctx.slot_diagnostics(&inspection.chain, &io_target, &facts, &loud);
        assert_eq!(notes.len(), 1, "{notes:#?}");
        assert!(notes[0].contains("wheel entry"));
    }

    /// A timer's registration state, from the entry word, rides along
    /// on the evidence line.
    #[test]
    fn test_the_wheel_evidence_names_the_entry_state() {
        let registered = SlotRef::Wheel {
            entry: 0x10,
            state: Some(WheelState::Registered),
        };
        assert_eq!(
            registered.detail(),
            format!(
                "this task's waker in wheel entry 0x10, {}",
                timer::REGISTERED
            )
        );
        let unread = SlotRef::Wheel {
            entry: 0x10,
            state: None,
        };
        assert_eq!(unread.detail(), "this task's waker in wheel entry 0x10");
        assert_eq!(SlotRef::Protocol.cell_entry(), None);
        assert_eq!(SlotRef::Protocol.kind(), None);
    }
}

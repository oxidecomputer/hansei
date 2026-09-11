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
//! task's identity; a **slot** is a live waker location attributed to
//! the task — by the registries (a wheel entry, an io waiter) while the
//! analysis runs, and by the waker sweep afterwards, which finds every
//! parked pair in memory and names what holds it. The two are joined by
//! containment: a slot inside a branch's storage arms that branch. A
//! branch whose own reviewed protocol read this task's waker is armed
//! by that protocol. A slot inside no branch is a member on its own.
//! The sweep's slots arrive last ([`Context::fold_slots`]), once the
//! attribution has walked the analysis's own frames, so the assessment
//! every consumer reads carries them: the listing, the graph, the
//! census and the trace header say the same thing.
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

use super::Lifecycle;
use super::RawInstant;
use super::assess::{
    Assessed, AssessmentPass, ContinuationStatus, TaskFacts, WaitAssessment, WaitUnknownReason,
};
use super::attribution::{
    Attributed, AttributedSlot, Attribution, RegistrySlot, member_accounts, verified_accounts,
};
use super::bundle::{
    AwaitChain, AwaitFrame, ChainEnd, Context, IoSlot, Readiness, Registries, Task, TaskList,
    WaitTarget, WheelState, deadline_text,
};
use super::census::{self, Find, Path, ScanPlan};
use super::chain::{FutureInspection, InspectionMode, NextFuture};
use super::graph::{Analysis, TaskWait};
use super::observe::{ReadContext, ValueKey};

use foldhash::{HashMap, HashSet};
use hansei_bundle::{AccessKind, BundleTypeId, SelectBinding, SemanticIssueKind};
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
    /// The stop frame the set was computed at: the future no rule
    /// polls through. `None` where the chain was cut short of any
    /// stop — an unresolved trait object, a depth limit, a root that
    /// did not read — and the set is the sweep's slots alone.
    pub at: Option<ValueKey>,
    /// Why the chain ends there, where it ends at a stop.
    pub reason: Option<SemanticIssueKind>,
    /// Every branch, armed or not — a `select!`'s disabled branches
    /// among them, in branch order — then every slot in no branch. At
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

    /// The armed members' `(entry, kind)` pairs, sorted, with every
    /// `unknown` entry past the first collapsed into a count: the
    /// slots in allocations nothing typed reaches tell a reader
    /// nothing apart, and a task parked in six of them reads as
    /// `6× unknown`, not six addresses.
    fn entries(&self) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> = Vec::new();
        let mut unknown = 0usize;
        for member in self.armed() {
            let (Some(entry), Some(kind)) = (member.cell_entry(), member.kind()) else {
                continue;
            };
            if kind == "unknown" {
                unknown += 1;
                if unknown > 1 {
                    continue;
                }
            }
            entries.push((entry, kind));
        }
        if unknown > 1 {
            for entry in &mut entries {
                if entry.1 == "unknown" {
                    entry.0 = format!("{unknown}× unknown");
                }
            }
        }
        entries.sort();
        entries
    }

    /// The cell: every armed member's entry, sorted and joined with
    /// `, `, so a set of one reads exactly as a verified wait on the
    /// same resource would.
    pub fn cell(&self) -> String {
        self.entries()
            .into_iter()
            .map(|(entry, _)| entry)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The bucket: the armed members' kinds, distinct, sorted and
    /// joined with `, ` — `io, timer` for a select over both.
    pub fn group_label(&self) -> String {
        let mut kinds: Vec<String> = self.entries().into_iter().map(|(_, kind)| kind).collect();
        kinds.sort();
        kinds.dedup();
        kinds.join(", ")
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

    /// Whether the member is a `select!` branch its mask has disabled:
    /// listed, but neither held nor armed, and counted nowhere.
    pub fn disabled(&self) -> bool {
        matches!(self.route, MemberRoute::Disabled { .. })
    }
}

/// How a member was reached.
#[derive(Clone, Debug)]
pub enum MemberRoute {
    /// A future the stop frame holds in `local`, by value or — with
    /// `borrowed` — through a `&mut`.
    Branch { local: String, borrowed: bool },
    /// Branch `index` of a `select!`, in source order: member `index`
    /// of the tuple the stop's closure borrows, with `borrowed` where
    /// that member is itself a `&mut` to the frame's own local.
    Select { index: usize, borrowed: bool },
    /// Branch `index` of a `select!` whose mask bit is set: disabled
    /// before its first poll by a false precondition, or after
    /// completing with an output that missed its pattern — which of
    /// the two, nothing in memory says. Not inspected: `ty` names
    /// what it is, and that is all that is listed.
    Disabled { index: usize, ty: BundleTypeId },
    /// A registry slot attributed to the task that lies in no branch.
    /// `within` places it in the task's own chain where it does lie
    /// there.
    SlotOnly { within: Option<String> },
}

impl MemberRoute {
    /// The branch's position in its `select!`, for ordering the listing.
    fn select_index(&self) -> Option<usize> {
        match self {
            MemberRoute::Select { index, .. } | MemberRoute::Disabled { index, .. } => Some(*index),
            MemberRoute::Branch { .. } | MemberRoute::SlotOnly { .. } => None,
        }
    }
}

/// The evidence a member holds this task's waker.
#[derive(Clone, Debug)]
pub enum SlotRef {
    /// A wheel entry armed with the task's waker.
    Wheel {
        entry: u64,
        state: Option<WheelState>,
        /// The deadline the entry's registration word encodes, and
        /// the target's stop instant it is reported against.
        deadline: Option<RawInstant>,
        stopped: Option<RawInstant>,
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
    /// A pair the waker sweep found and the attribution named: what
    /// holds it, read from the holder's own words where a reader
    /// exists. Printed as the slot is everywhere else, against the
    /// target's stop instant.
    Swept {
        slot: Box<AttributedSlot>,
        stopped: Option<RawInstant>,
    },
}

impl SlotRef {
    /// The bare entry, for a member whose assessment names no
    /// target: a wheel entry's deadline where its word encodes one —
    /// the text a verified `Sleep` prints — else the slot kind and
    /// the resource.
    fn cell_entry(&self) -> Option<String> {
        match self {
            Self::Wheel {
                deadline: Some(deadline),
                stopped,
                ..
            } => Some(format!("timer ({})", deadline_text(*deadline, *stopped))),
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
            Self::Swept { slot, stopped } => Some(slot.entry(*stopped)),
        }
    }

    fn kind(&self) -> Option<String> {
        match self {
            Self::Wheel { .. } => Some("timer".to_string()),
            Self::Io { .. } => Some("io".to_string()),
            Self::Protocol => None,
            Self::Swept { slot, .. } => Some(slot.bucket()),
        }
    }

    /// The sweep's account of `slot`, for a member it arms.
    pub fn swept(slot: &AttributedSlot, stopped: Option<RawInstant>) -> SlotRef {
        SlotRef::Swept {
            slot: Box::new(slot.clone()),
            stopped,
        }
    }

    /// The evidence, in words, for a detail line.
    pub fn detail(&self) -> String {
        match self {
            Self::Wheel { entry, state, .. } => {
                let state = match state {
                    Some(state) => format!(", {state}"),
                    None => String::new(),
                };
                format!("this task's waker in wheel entry {entry:#x}{state}")
            }
            // The resource is not named here: the line this sits on
            // already names it, as the member's entry or its target.
            Self::Io { slot, ready, .. } => {
                let site = match slot {
                    IoSlot::Reader => "the read-waiter slot",
                    IoSlot::Writer => "the write-waiter slot",
                    IoSlot::Listed { .. } => "a waiter node",
                };
                let ready = match ready {
                    Some(ready) => format!(", ready: {ready}"),
                    None => String::new(),
                };
                format!("this task's waker in {site}{ready}")
            }
            Self::Protocol => "its protocol read this task's waker".to_string(),
            Self::Swept { slot, stopped } => slot.detail(*stopped),
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

/// One future-typed value the stop frame reaches, and how.
struct Branch<'b> {
    route: MemberRoute,
    value: Value<'b>,
}

/// What enumerating a stop frame's branches found.
#[derive(Default)]
struct Enumerated<'b> {
    /// The branches to inspect, in order.
    branches: Vec<Branch<'b>>,
    /// Branches past the cap: found and counted, not inspected.
    capped: usize,
    /// A `select!`'s disabled branches, as the members they are listed
    /// as: named, not inspected, and never armed.
    disabled: Vec<WaitMember>,
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

/// What one analysis carries across every stop frame it enumerates:
/// the scan plans, which are facts of the types, and the listing cap.
pub struct BranchScan {
    plans: HashMap<BundleTypeId, ScanPlan>,
    /// How many branches a stop lists before counting the rest;
    /// [`MAX_BRANCHES`] outside the tests.
    pub max_branches: usize,
}

impl Default for BranchScan {
    fn default() -> Self {
        BranchScan {
            plans: HashMap::default(),
            max_branches: MAX_BRANCHES,
        }
    }
}

/// Whether `addr` lies in `value`'s storage.
fn contains(value: Value<'_>, addr: u64) -> bool {
    addr >= value.addr && addr - value.addr < value.bytes.len() as u64
}

impl<'b, T: Target> Context<'b, T> {
    /// The future-typed values `frame` holds or borrows. A frame the
    /// bundle bound as a `select!`'s `PollFn` polls the tuple its
    /// closure borrows, member by member, under its mask
    /// ([`Context::select_branches`]); any other frame has its own
    /// locals scanned through their aggregates and active variants,
    /// every supported adapter followed to what it holds. Depth one —
    /// the frame's members, never a branch's — and capped at
    /// [`MAX_BRANCHES`], the rest counted. `notes` collects what could
    /// not be read.
    fn branches_at(
        &self,
        frame: &AwaitFrame<'b>,
        read: &ReadContext<'_>,
        scan: &mut BranchScan,
        notes: &mut Vec<String>,
    ) -> Enumerated<'b> {
        if let Some(binding) = self.select_binding(frame.future.ty.id())
            && let Some(found) =
                self.select_branches(frame, binding, read, scan.max_branches, notes)
        {
            return found;
        }
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
                &mut scan.plans,
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
                if branches.len() >= scan.max_branches {
                    capped += 1;
                    continue;
                }
                branches.push(Branch {
                    route: MemberRoute::Branch {
                        local: name.to_string(),
                        borrowed,
                    },
                    value,
                });
            }
        }
        Enumerated {
            branches,
            capped,
            disabled: Vec::new(),
        }
    }

    /// A `select!`'s branches, as the bound layout reads them: the mask
    /// word and the tuple of branch futures through the closure's two
    /// references, then tuple member `i` as branch `i`. A member whose
    /// mask bit is set is disabled — never polled again, holding no
    /// waker of this task's — and is listed as such without being
    /// inspected. Every other member is a branch whatever its type: a
    /// `&mut` to the frame's own local is followed by the inspection
    /// like any borrowed adapter, and a type no rule recognizes is an
    /// unknown branch, not a missing one. `None`, with the reason
    /// noted, where the mask or the tuple did not read.
    fn select_branches(
        &self,
        frame: &AwaitFrame<'b>,
        binding: &'b SelectBinding,
        read: &ReadContext<'_>,
        max_branches: usize,
        notes: &mut Vec<String>,
    ) -> Option<Enumerated<'b>> {
        // Each route lands on its recorded type by construction: the
        // validator held every endpoint, and the executor reads a
        // pointee as exactly the pointer's declared target.
        let mut landed =
            |steps: &[hansei_bundle::Step], what: &str| match self.route(frame.future, steps, read)
            {
                Ok(value) => Some(value),
                Err(e) => {
                    notes.push(format!("the select! {what} did not read: {e:#}"));
                    None
                }
            };
        let mask = landed(&binding.mask.steps, "branch mask")?;
        let mut word = [0u8; 8];
        let width = mask.bytes.len().min(8);
        word[..width].copy_from_slice(&mask.bytes[..width]);
        let mask = u64::from_le_bytes(word);
        let tuple = landed(&binding.futures.steps, "branch tuple")?;
        let mut found = Enumerated::default();
        for (index, branch) in binding.branches.iter().enumerate() {
            let member = match self.route(tuple, &branch.steps, read) {
                Ok(member) => member,
                Err(e) => {
                    notes.push(format!("select! branch {index} did not read: {e:#}"));
                    continue;
                }
            };
            // The validator bounds the branches by the mask's bits, so
            // the shift is in range; a checked one costs nothing.
            if mask
                .checked_shr(index as u32)
                .is_some_and(|bits| bits & 1 == 1)
            {
                // Named by what the branch is, not the borrow the macro
                // took of it: a `&mut Pin<&mut Sleep>` is a sleep.
                let ty = self.static_referent(member.ty.id());
                found.disabled.push(WaitMember {
                    route: MemberRoute::Disabled { index, ty },
                    key: None,
                    future: self.view.ty(ty).map(|t| t.name().to_string()),
                    assessment: None,
                    notes: Vec::new(),
                    armed: None,
                });
                continue;
            }
            if found.branches.len() >= max_branches {
                found.capped += 1;
                continue;
            }
            found.branches.push(Branch {
                route: MemberRoute::Select {
                    index,
                    borrowed: false,
                },
                value: member,
            });
        }
        Some(found)
    }

    /// The type behind `ty`'s recorded adapter routes, read from the
    /// bundle alone: a `&mut Pin<&mut F>` is `F`, up to the hop bound,
    /// and a dynamic route — whose pointee only memory names — stops
    /// at the adapter. For naming a value nothing reads.
    fn static_referent(&self, ty: BundleTypeId) -> BundleTypeId {
        let mut cur = ty;
        for _ in 0..MAX_ADAPTER_HOPS {
            let Some(hansei_bundle::FutureTarget::Value(path)) = self
                .type_semantics(cur)
                .and_then(|record| record.access.as_ref())
                .map(|access| &access.target)
            else {
                break;
            };
            cur = path.target;
        }
        cur
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

    /// Each branch inspected and assessed under `task`'s identity, as
    /// an unarmed member beside its own chain — a branch that is a
    /// frame of the task's chain is that frame and no member, and a
    /// branch reached twice is one.
    fn members_of(
        &self,
        pass: &mut AssessmentPass,
        chain: &AwaitChain<'b>,
        task: &TaskFacts,
        list: &TaskList,
        read: &ReadContext<'_>,
        branches: Vec<Branch<'b>>,
    ) -> (Vec<WaitMember>, Vec<AwaitChain<'b>>) {
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
            let via_borrow = held.chain.frames[..index]
                .iter()
                .any(|f| access(f) == Some(AccessKind::Borrowed));
            let route = match branch.route {
                MemberRoute::Branch { local, borrowed } => MemberRoute::Branch {
                    local,
                    borrowed: borrowed || via_borrow,
                },
                MemberRoute::Select { index, borrowed } => MemberRoute::Select {
                    index,
                    borrowed: borrowed || via_borrow,
                },
                other => other,
            };
            let key = ValueKey::of(identity.future);
            // A branch that is a frame of the task's own chain is that
            // frame, not something the stop polls beside it; a branch
            // reached twice is one branch.
            if on_chain.contains(&key) || !seen.insert(key) {
                continue;
            }
            let Assessed { assessment, notes } = self.assess_wait(pass, &held, task, list, read);
            members.push(WaitMember {
                route,
                key: Some(key),
                future: Some(identity.future.ty.name().to_string()),
                assessment: Some(assessment),
                notes,
                armed: None,
            });
            chains.push(held.chain);
        }

        (members, chains)
    }

    /// The wait set at an unknown stop: the stop frame's branches, each
    /// inspected and assessed under `task`'s identity, joined to the
    /// wheel entries and io waiters `registries` attribute to the task.
    /// Only for a chain ending in [`ChainEnd::UnknownContinuation`]:
    /// every other end already says what the task is doing. What
    /// could not be read on the way is pushed onto `notes`.
    #[allow(clippy::too_many_arguments)]
    pub fn wait_set(
        &self,
        pass: &mut AssessmentPass,
        inspection: &FutureInspection<'b>,
        task: &TaskFacts,
        list: &TaskList,
        registries: &Registries,
        read: &ReadContext<'_>,
        scan: &mut BranchScan,
        notes: &mut Vec<String>,
    ) -> Branches {
        let chain = &inspection.chain;
        let ChainEnd::UnknownContinuation { at, reason } = &chain.end else {
            return Branches::None;
        };
        let Some(stop) = chain.frames.last() else {
            return Branches::None;
        };
        let Enumerated {
            branches,
            capped,
            disabled,
        } = self.branches_at(stop, read, scan, notes);
        let (mut members, chains) = self.members_of(pass, chain, task, list, read, branches);

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
                deadline: timer.deadline,
                stopped: self.stopped_at(),
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

        // The disabled branches join the listing in branch order, after
        // the slots have been placed against the members they can arm:
        // a disabled branch arms nothing and is placed against nothing.
        members.extend(disabled);
        order_by_branch(&mut members);

        if members.iter().any(|m| m.armed.is_some()) {
            Branches::Set(WaitSet {
                at: Some(*at),
                reason: Some(*reason),
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

    /// Fold the sweep's slots into the analysis: for every task,
    /// what the attribution named as holding its waker joins the
    /// assessment the analysis made without it ([`fold_wait`]). Run
    /// once, after the attribution — which walks the analysis's own
    /// frames, and so cannot run inside it — and before any consumer
    /// reads a wait, so that all of them read the same one.
    pub fn fold_slots(&self, analysis: &mut Analysis, list: &TaskList, attributed: &Attributed) {
        let stopped = self.stopped_at();
        let size_of = |ty: BundleTypeId| self.view.ty(ty).map(|t| t.size());
        for (task, wait) in list.tasks.iter().zip(analysis.waits.iter_mut()) {
            let slots: Vec<&AttributedSlot> = attributed.of_task(task.addr.0).collect();
            if slots.is_empty() {
                continue;
            }
            fold_wait(task, wait, &slots, stopped, &size_of);
        }
    }
}

/// Put a `select!`'s members in branch order — the enabled ones,
/// inspected first, and the disabled ones, appended after the slots
/// were placed — and leave every other member where it was, after
/// them. Stable, so members that are not branches keep their order.
fn order_by_branch(members: &mut [WaitMember]) {
    members.sort_by_key(|m| m.route.select_index().unwrap_or(usize::MAX));
}

/// Where in the task's own chain `addr` lies, as a set member's
/// placement text, or `None` when it lies in no frame.
fn within_frames(
    frames: &[ValueKey],
    addr: u64,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> Option<String> {
    frames.iter().enumerate().find_map(|(i, frame)| {
        let size = size_of(frame.ty)?;
        (addr >= frame.addr && addr - frame.addr < size).then(|| {
            format!(
                "inside #{}'s storage at +{:#x}",
                frames.len() - 1 - i,
                addr - frame.addr
            )
        })
    })
}

/// Whether `slot` is the very pair `member`'s own evidence already
/// stands on: the wheel entry or io waiter a registry decoded, the
/// waker its protocol read in the resource, or a swept pair folded in
/// before. Such a slot adds no member; any other slot the member
/// accounts for is a second place the waker is parked in.
fn twin(
    member: &WaitMember,
    slot: &AttributedSlot,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> bool {
    match (&member.armed, &slot.attribution) {
        (
            Some(SlotRef::Wheel { entry, .. }),
            Attribution::Registry(RegistrySlot::Timer { entry: at, .. }),
        ) => entry == at,
        (
            Some(SlotRef::Io { resource, .. }),
            Attribution::Registry(RegistrySlot::Io { resource: at, .. }),
        ) => resource == at,
        (Some(SlotRef::Swept { slot: swept, .. }), _) => swept.slot == slot.slot,
        (Some(SlotRef::Protocol), _) => matches!(
            &member.assessment,
            Some(WaitAssessment::Waiting(verified)) if verified_accounts(verified, slot, size_of)
        ),
        (Some(SlotRef::Wheel { .. } | SlotRef::Io { .. }), _) | (None, _) => false,
    }
}

/// Fold the slots the sweep attributed to one task into its wait.
///
/// A blocking cell and a mid-poll task are not parked, whatever pair
/// lies in their storage, and are left alone. At an unknown continuation the slots and the stop's branches make
/// the wait set, exactly as the registries' slots did in the analysis:
/// a slot inside a branch's storage, or reached through a pointer the
/// branch holds, arms that branch; a slot no branch accounts for is a
/// member on its own, placed in the task's chain where it lies there;
/// a slot a member's own evidence already stands on is that evidence
/// seen again and adds nothing. A set the analysis already assembled
/// grows the same way, and branches it returned as merely held become
/// a set once something arms one of them or sits beside them. Beside
/// a verified wait a slot the wait does not account for is a
/// diagnostic note, never a member — the same rule the registries'
/// slots follow — except the wheel and io pairs the registries already
/// noted, and a pair in memory nothing typed reaches, which names
/// nothing to contradict the wait with. Every other assessment is
/// definite and is left alone.
pub fn fold_wait(
    task: &Task,
    wait: &mut TaskWait,
    slots: &[&AttributedSlot],
    stopped: Option<RawInstant>,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) {
    if task.is_blocking() || task.state.lifecycle() == Lifecycle::Running {
        return;
    }
    if let WaitAssessment::Waiting(verified) = &wait.assessment {
        for slot in slots {
            // A note names what contradicts the wait. A pair in memory
            // nothing typed reaches names nothing — on a target with no
            // allocator index it may be a ghost of the storage's last
            // occupant — and stays a slot line, never a note.
            if verified_accounts(verified, slot, size_of)
                || matches!(
                    slot.attribution,
                    Attribution::Registry(RegistrySlot::Timer { .. } | RegistrySlot::Io { .. })
                        | Attribution::Unknown { .. }
                )
            {
                continue;
            }
            wait.notes.push(format!(
                "{} also holds this task's waker, outside the verified wait",
                slot.label()
            ));
        }
        return;
    }
    let placeholder = WaitAssessment::Unknown(WaitUnknownReason::Continuation);
    let (mut members, capped, at, reason) =
        match std::mem::replace(&mut wait.assessment, placeholder) {
            WaitAssessment::Set(set) => (set.members, set.capped, set.at, set.reason),
            WaitAssessment::Unknown(WaitUnknownReason::Continuation) => {
                let (at, reason) = match &wait.continuation {
                    ContinuationStatus::Unknown { at, reason } => (Some(*at), Some(*reason)),
                    _ => (None, None),
                };
                (
                    std::mem::take(&mut wait.held),
                    std::mem::take(&mut wait.held_capped),
                    at,
                    reason,
                )
            }
            other => {
                wait.assessment = other;
                return;
            }
        };
    let mut alone = Vec::new();
    for slot in slots {
        // Every member that accounts for the slot: a branch whose
        // storage holds it or whose pointer reached it, a member whose
        // own evidence it is. Seen already anywhere, it adds nothing;
        // otherwise it arms the first unarmed branch it lies in, or
        // stands alone.
        let accounted: Vec<usize> = (0..members.len())
            .filter(|&i| member_accounts(&members[i], slot, size_of))
            .collect();
        if accounted.iter().any(|&i| twin(&members[i], slot, size_of)) {
            continue;
        }
        match accounted.iter().find(|&&i| members[i].armed.is_none()) {
            Some(&i) => members[i].armed = Some(SlotRef::swept(slot, stopped)),
            None => alone.push(WaitMember {
                route: MemberRoute::SlotOnly {
                    within: within_frames(&wait.frames, slot.slot, size_of),
                },
                key: None,
                future: None,
                assessment: None,
                notes: Vec::new(),
                armed: Some(SlotRef::swept(slot, stopped)),
            }),
        }
    }
    members.extend(alone);
    if members.iter().any(|member| member.armed.is_some()) {
        wait.assessment = WaitAssessment::Set(WaitSet {
            at,
            reason,
            members,
            capped,
        });
    } else {
        wait.held = members;
        wait.held_capped = capped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, load_any};
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
            &mut BranchScan::default(),
            &mut Vec::new(),
        )
    }

    fn wheel(entry: u64, task: &Task) -> TimerEntryInfo {
        TimerEntryInfo {
            entry,
            state: Some(1000),
            task: Some(task.addr.0),
            waker_at: None,
            deadline: None,
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
                waker_at: None,
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
        assert_eq!(set.at.unwrap().ty, inspection_stop(&ctx, task));
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
            format!("io 0x7000 (readable), io 0x7100 (readiness), timer {outside:#x}")
        );
        assert_eq!(set.group_label(), "io, timer");
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
            deadline: None,
            stopped: None,
        };
        assert_eq!(
            registered.detail(),
            format!(
                "this task's waker in wheel entry 0x10, {}",
                timer::REGISTERED
            )
        );
        assert_eq!(registered.cell_entry(), Some("timer 0x10".to_string()));
        let unread = SlotRef::Wheel {
            entry: 0x10,
            state: None,
            deadline: None,
            stopped: None,
        };
        assert_eq!(unread.detail(), "this task's waker in wheel entry 0x10");
        // A word that encodes a deadline prints it the way a verified
        // sleep does, in the cell and on the evidence line.
        let at = |tv_sec| RawInstant { tv_sec, tv_nsec: 0 };
        let due = SlotRef::Wheel {
            entry: 0x10,
            state: Some(WheelState::Registered),
            deadline: Some(at(40)),
            stopped: Some(at(12)),
        };
        assert_eq!(
            due.cell_entry(),
            Some("timer (deadline +28.000s)".to_string())
        );
        assert_eq!(due.kind(), Some("timer".to_string()));
        assert_eq!(due.detail(), registered.detail());
        assert_eq!(SlotRef::Protocol.cell_entry(), None);
        assert_eq!(SlotRef::Protocol.kind(), None);
    }

    /// The branch scan's recognition is the census's with one row
    /// more: a borrowed adapter is followed. Judged over every type of
    /// every pair against the semantics records themselves, so the
    /// expectation is not the code under test restated.
    #[test]
    fn test_recognition_admits_borrowed_adapters_and_nothing_else() {
        use crate::tokio::census::{Recognize, Recognized};
        use hansei_bundle::{ContainerKind, StoragePolicy};

        let (mut borrowed, mut unavailable, mut plain) = (0, 0, 0);
        for program in testkit::PROGRAMS {
            let (bundle, snapshot) = load_any(program);
            let ctx = testkit::context(&bundle, &snapshot);
            let facts = Branching(&ctx);
            for id in (0..bundle.types.types.len() as u32).map(BundleTypeId) {
                let record = ctx.type_semantics(id);
                let expected = match record {
                    Some(r)
                        if r.container.as_ref().map(|c| c.kind)
                            == Some(ContainerKind::FuturesUnordered) =>
                    {
                        Recognized::Set
                    }
                    Some(r)
                        if r.container.as_ref().map(|c| c.kind) == Some(ContainerKind::JoinSet) =>
                    {
                        Recognized::JoinSet
                    }
                    Some(r) if r.future.is_some() || r.resource.is_some() => Recognized::Future,
                    Some(r) if r.access.is_some() => {
                        if r.access.as_ref().unwrap().kind == AccessKind::Borrowed {
                            borrowed += 1;
                        }
                        Recognized::Adapter
                    }
                    Some(r) if matches!(r.storage, StoragePolicy::Unavailable(_)) => {
                        unavailable += 1;
                        Recognized::Unavailable
                    }
                    _ => {
                        plain += 1;
                        Recognized::Other
                    }
                };
                let got = facts.recognize(id);
                assert!(
                    std::mem::discriminant(&got) == std::mem::discriminant(&expected),
                    "type {}: {got:?} against {expected:?}",
                    ctx.view
                        .ty(id)
                        .map(|t| t.name().to_owned())
                        .unwrap_or_default()
                );
                // Against the census's own recognition, the one difference.
                let census = ctx.recognize(id);
                let same = std::mem::discriminant(&got) == std::mem::discriminant(&census);
                let differs_on_borrow = matches!(got, Recognized::Adapter)
                    && matches!(census, Recognized::Other)
                    && ctx.any_adapter(id)
                    && !ctx.owned_adapter(id);
                assert!(
                    same || differs_on_borrow,
                    "type {id:?}: {got:?} vs {census:?}"
                );
            }
        }
        assert!(borrowed > 0, "some pair holds a borrowed adapter");
        assert!(plain > 0);
        // No captured pair declares storage unavailable, so that row is
        // held to the record where it occurs and nowhere yet.
        let _ = unavailable;
    }

    /// A borrowed adapter is followed to the future behind it, and the
    /// route remembers the borrow; an owned one is followed and does
    /// not.
    #[test]
    fn test_adapters_are_followed_to_their_future() {
        let (bundle, snapshot) = load_any("delegation-cases");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let access = |ty: BundleTypeId| {
            ctx.type_semantics(ty)
                .and_then(|r| r.access.as_ref())
                .map(|a| a.kind)
        };
        let mut seen = (false, false);
        for task in &list.tasks {
            let Ok(Some(inspection)) = ctx.inspect_task(task, &ReadContext::none()) else {
                continue;
            };
            for (i, frame) in inspection.chain.frames.iter().enumerate() {
                let Some(kind) = access(frame.future.ty.id()) else {
                    continue;
                };
                let Some((future, borrowed)) =
                    ctx.follow_adapters(frame.future, &ReadContext::none())
                else {
                    panic!("{} leads to a future", frame.future.ty.name());
                };
                assert!(ctx.recognized_future(future.ty.id()));
                // The first future past the adapter is what the chain
                // itself reached next — an adapter that is also a
                // future (a pinned `dyn`) included.
                let (skipped, next) = inspection.chain.frames[i + 1..]
                    .iter()
                    .enumerate()
                    .find(|(_, f)| ctx.recognized_future(f.future.ty.id()))
                    .expect("the chain crosses the adapter");
                assert_eq!(ValueKey::of(future), ValueKey::of(next.future));
                let borrow_on_route = inspection.chain.frames[i..=i + skipped]
                    .iter()
                    .any(|f| access(f.future.ty.id()) == Some(AccessKind::Borrowed));
                assert_eq!(borrowed, borrow_on_route, "{}", frame.future.ty.name());
                match kind {
                    AccessKind::Borrowed => seen.0 = true,
                    AccessKind::Owned => seen.1 = true,
                }
            }
        }
        assert_eq!(
            seen,
            (true, true),
            "a borrowed and an owned adapter were followed"
        );
    }

    /// Storage is a half-open range: its first byte is in, the byte
    /// past its end is not.
    #[test]
    fn test_containment_is_half_open() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "chained");
        let root = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap()
            .chain
            .frames[0]
            .future;
        let end = root.addr + root.bytes.len() as u64;
        assert!(contains(root, root.addr));
        assert!(contains(root, end - 1));
        assert!(!contains(root, end));
        assert!(!contains(root, root.addr - 1));
    }

    /// Branches past the cap are counted, not inspected: with the cap
    /// at zero the one branch is a count, the stop is held with no
    /// members, and a slot inside the uninspected branch is a member
    /// on its own — nothing places it, since nothing was inspected.
    #[test]
    fn test_the_cap_counts_what_it_does_not_inspect() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "chained");
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        let capped_to_zero = |registries: &Registries| {
            ctx.wait_set(
                &mut AssessmentPass::new(),
                &inspection,
                &TaskFacts::from(task),
                &list,
                registries,
                &ReadContext::none(),
                &mut BranchScan {
                    max_branches: 0,
                    ..BranchScan::default()
                },
                &mut Vec::new(),
            )
        };
        let Branches::Held { members, capped } = capped_to_zero(&Registries::default()) else {
            panic!("held");
        };
        assert!(members.is_empty());
        assert_eq!(capped, 1);
        let stop = inspection.chain.frames.last().unwrap().future;
        let Branches::Set(set) = capped_to_zero(&Registries::new(
            vec![wheel(stop.addr + 8, task)],
            Vec::new(),
        )) else {
            panic!("a set");
        };
        assert_eq!(set.capped, 1);
        assert_eq!(set.members.len(), 1);
        assert!(matches!(set.members[0].route, MemberRoute::SlotOnly { .. }));
    }

    /// A branch reached twice is one member; a branch that is a frame
    /// of the task's own chain is none; a branch found through a
    /// borrow is a borrowed member whatever its own chain says.
    #[test]
    fn test_members_dedup_and_keep_the_borrow() {
        let (bundle, snapshot) = load_any("walk-shapes");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "chained");
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        let stop = inspection.chain.frames.last().unwrap();
        let mut notes = Vec::new();
        let found = ctx
            .branches_at(
                stop,
                &ReadContext::none(),
                &mut BranchScan::default(),
                &mut notes,
            )
            .branches;
        assert_eq!(found.len(), 1);
        assert!(notes.is_empty(), "{notes:#?}");
        let MemberRoute::Branch { local, .. } = &found[0].route else {
            panic!("{:?}", found[0].route);
        };
        let branch = |borrowed: bool| Branch {
            route: MemberRoute::Branch {
                local: local.clone(),
                borrowed,
            },
            value: found[0].value,
        };
        let root = Branch {
            route: MemberRoute::Branch {
                local: "root".to_string(),
                borrowed: false,
            },
            value: inspection.chain.frames[0].future,
        };
        let (members, chains) = ctx.members_of(
            &mut AssessmentPass::new(),
            &inspection.chain,
            &TaskFacts::from(task),
            &list,
            &ReadContext::none(),
            vec![root, branch(true), branch(false)],
        );
        assert_eq!(members.len(), 1, "{members:#?}");
        assert_eq!(chains.len(), 1);
        assert!(
            matches!(
                &members[0].route,
                MemberRoute::Branch { borrowed: true, .. }
            ),
            "{members:#?}"
        );
    }

    /// A `select!`'s members list in branch order whatever order the
    /// inspection and the mask left them in — a disabled branch ahead
    /// of an enabled one included — and the slots that are no branch
    /// stay after them, in their own order.
    #[test]
    fn test_select_members_list_in_branch_order() {
        let member = |route: MemberRoute| WaitMember {
            route,
            key: None,
            future: None,
            assessment: None,
            notes: Vec::new(),
            armed: None,
        };
        let mut members = vec![
            member(MemberRoute::Select {
                index: 3,
                borrowed: false,
            }),
            member(MemberRoute::Select {
                index: 1,
                borrowed: true,
            }),
            member(MemberRoute::SlotOnly {
                within: Some("a".to_string()),
            }),
            member(MemberRoute::SlotOnly { within: None }),
            member(MemberRoute::Disabled {
                index: 0,
                ty: BundleTypeId(0),
            }),
            member(MemberRoute::Disabled {
                index: 2,
                ty: BundleTypeId(0),
            }),
        ];
        order_by_branch(&mut members);
        let order: Vec<String> = members
            .iter()
            .map(|m| match &m.route {
                MemberRoute::Select { index, .. } => format!("select {index}"),
                MemberRoute::Disabled { index, .. } => format!("disabled {index}"),
                MemberRoute::SlotOnly { within } => format!("slot {within:?}"),
                MemberRoute::Branch { local, .. } => format!("branch {local}"),
            })
            .collect();
        assert_eq!(
            order,
            [
                "disabled 0",
                "select 1",
                "disabled 2",
                "select 3",
                "slot Some(\"a\")",
                "slot None"
            ]
        );
    }

    /// A `select!` with more branches than the cap lists the first ones
    /// and counts the rest: armed-select's four under a cap of two are
    /// the oneshot and the mpsc, both armed by their protocols, and two
    /// counted.
    #[test]
    fn test_select_branches_past_the_cap_are_counted() {
        let (bundle, snapshot) = load_any("armed-select");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "selector");
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        let mut notes = Vec::new();
        let Branches::Set(set) = ctx.wait_set(
            &mut AssessmentPass::new(),
            &inspection,
            &TaskFacts::from(task),
            &list,
            &Registries::default(),
            &ReadContext::none(),
            &mut BranchScan {
                max_branches: 2,
                ..BranchScan::default()
            },
            &mut notes,
        ) else {
            panic!("a set");
        };
        assert!(notes.is_empty(), "{notes:#?}");
        assert_eq!(set.capped, 2);
        let routes: Vec<usize> = set
            .members
            .iter()
            .map(|m| match m.route {
                MemberRoute::Select { index, .. } => index,
                ref other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(routes, [0, 1]);
        assert!(
            set.members
                .iter()
                .all(|m| matches!(m.armed, Some(SlotRef::Protocol)))
        );
        assert_eq!(set.group_label(), "mpsc, oneshot rx");
    }

    /// A stop with no branch and no slot has no set and nothing held.
    #[test]
    fn test_a_bare_stop_has_nothing() {
        let (bundle, snapshot) = load_any("delegation-cases");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "Retained");
        assert!(matches!(
            branches_of(&ctx, &list, task, &Registries::default()),
            Branches::None
        ));
    }

    /// The analysis carries the slot diagnostics onto a verified wait's
    /// notes.
    #[test]
    fn test_the_analysis_notes_a_slot_beside_a_verified_wait() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "sleeper");
        let registries = Registries::new(vec![wheel(0x4000, task)], Vec::new());
        let analysis = crate::tokio::graph::analyze(&ctx, &list, &registries, &ReadContext::none());
        let row = analysis
            .waits
            .iter()
            .find(|w| w.task.addr == task.addr)
            .unwrap();
        assert!(matches!(row.assessment, WaitAssessment::Waiting(_)));
        assert_eq!(row.notes.len(), 1, "{:?}", row.notes);
        assert!(row.notes[0].contains("wheel entry 0x4000 also holds this task's waker"));
        let quiet =
            crate::tokio::graph::analyze(&ctx, &list, &Registries::default(), &ReadContext::none());
        let row = quiet
            .waits
            .iter()
            .find(|w| w.task.addr == task.addr)
            .unwrap();
        assert!(row.notes.is_empty(), "{:?}", row.notes);
    }

    /// The deadline the harvest reads off a wheel entry's word agrees
    /// with the one the `Sleep` owning that entry caches, to the
    /// millisecond tokio rounds a registration up to; the registries
    /// carry the stop instant the analysis reports against.
    #[test]
    fn test_a_wheel_entrys_deadline_agrees_with_its_sleep() {
        use crate::tokio::observe::ResourceObservation;

        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let mut e = testkit::enumerate(&ctx, &snapshot);
        e.discover(&ctx, &[]);
        let task = task_named(&e.list, "sleeper");
        let inspection = ctx
            .inspect_task(task, &ReadContext::none())
            .unwrap()
            .unwrap();
        let sleep = inspection.chain.frames.last().unwrap().future;
        let Some(ResourceObservation::Timer(timer)) = &inspection.primitive.value else {
            panic!("the sleeper ends in a timer: {:?}", inspection.primitive);
        };
        let cached = timer.deadline.expect("the sleep caches its deadline");
        let entries: Vec<_> = e.registries.timers_of(task.addr.0).collect();
        assert_eq!(entries.len(), 1, "{entries:#?}");
        let entry = entries[0];
        assert!(contains(sleep, entry.entry), "the entry lies in the sleep");
        let ns = |i: RawInstant| i.tv_sec as u128 * 1_000_000_000 + i.tv_nsec as u128;
        let harvested = entry.deadline.expect("the epoch bound and the word read");
        assert!(
            ns(harvested) >= ns(cached) && ns(harvested) < ns(cached) + 1_000_000,
            "harvested {harvested:?} against cached {cached:?}"
        );
        assert_eq!(e.registries.stopped, ctx.stopped_at());
    }

    // ---- the fold: the sweep's slots into the analysis ----

    use crate::tokio::assess::VerifiedWait;
    use crate::tokio::attribution::{OwnerKind, SlotPath, SlotRoot, Validity};
    use crate::tokio::bundle::{OwnerResolution, TaskKind};
    use crate::tokio::graph::TaskRef;
    use crate::tokio::wakers::Owner;
    use crate::tokio::{TaskAddr, TaskState};

    /// The one type every hand-built value here has, 0x40 bytes wide.
    const TY: BundleTypeId = BundleTypeId(1);
    const REF_ONE: u64 = 1 << 6;
    const RUNNING: u64 = 0b0001;

    fn size_of(ty: BundleTypeId) -> Option<u64> {
        (ty == TY).then_some(0x40)
    }

    fn key(addr: u64) -> ValueKey {
        ValueKey { addr, ty: TY }
    }

    fn a_task(state: u64, kind: TaskKind) -> Task {
        Task {
            addr: TaskAddr(0x1000),
            state: TaskState(REF_ONE | state),
            owner_id: None,
            task_id: Some(1),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind,
            owner: OwnerResolution::Unknown,
        }
    }

    fn idle() -> Task {
        a_task(0, TaskKind::Async)
    }

    /// A task whose chain — root `0x9000`, stop `0x5000` — ends at a
    /// stop no rule covers, holding `held` there.
    fn stopped(held: Vec<WaitMember>) -> TaskWait {
        TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000),
                task_id: Some(1),
            },
            assessment: WaitAssessment::Unknown(WaitUnknownReason::Continuation),
            continuation: ContinuationStatus::Unknown {
                at: key(0x5000),
                reason: SemanticIssueKind::NoRule,
            },
            depth: 2,
            site: None,
            observation: None,
            notes: Vec::new(),
            held,
            held_capped: 0,
            frames: vec![key(0x9000), key(0x5000)],
        }
    }

    /// A branch of the stop, its storage at `addr`.
    fn branch(addr: u64) -> WaitMember {
        WaitMember {
            route: MemberRoute::Branch {
                local: "b".to_string(),
                borrowed: false,
            },
            key: Some(key(addr)),
            future: Some("x::B".to_string()),
            assessment: Some(WaitAssessment::Unknown(WaitUnknownReason::Continuation)),
            notes: Vec::new(),
            armed: None,
        }
    }

    fn swept(at: u64, attribution: Attribution) -> AttributedSlot {
        AttributedSlot {
            hit: 0,
            slot: at,
            owner: Owner::Task {
                header: 0x1000,
                index: 0,
            },
            attribution,
            within: None,
        }
    }

    fn path() -> SlotPath {
        SlotPath {
            root: SlotRoot::Frame { task: 0, frame: 0 },
            steps: Vec::new(),
            hop: None,
        }
    }

    fn typed(at: u64) -> AttributedSlot {
        swept(
            at,
            Attribution::Typed {
                holder: "x::Holder".to_string(),
                member: "w".to_string(),
                path: path(),
                validity: Validity::Raw,
            },
        )
    }

    fn notify_slot(at: u64, primitive: u64) -> AttributedSlot {
        swept(
            at,
            Attribution::Owner {
                kind: OwnerKind::Notify,
                primitive,
                holder: "Notified".to_string(),
                member: "waiter".to_string(),
                path: path(),
                validity: Validity::SelfDescribing,
                reading: None,
            },
        )
    }

    fn timer_slot(entry: u64) -> AttributedSlot {
        swept(
            entry,
            Attribution::Registry(RegistrySlot::Timer {
                entry,
                state: None,
                deadline: None,
            }),
        )
    }

    fn nowhere(at: u64) -> AttributedSlot {
        swept(
            at,
            Attribution::Unknown {
                cache: None,
                size: None,
                offset: None,
            },
        )
    }

    fn notify_target(addr: u64) -> WaitTarget {
        WaitTarget::Notify {
            addr,
            state: None,
            waiters: None,
        }
    }

    fn fold(task: &Task, wait: &mut TaskWait, slots: &[AttributedSlot]) {
        let slots: Vec<&AttributedSlot> = slots.iter().collect();
        fold_wait(task, wait, &slots, None, &size_of);
    }

    fn set_of(wait: &TaskWait) -> &WaitSet {
        match &wait.assessment {
            WaitAssessment::Set(set) => set,
            other => panic!("a set, not {other:?}"),
        }
    }

    /// A slot inside a held branch arms it, and the held branches
    /// become a set; a slot in no branch is a member on its own,
    /// placed in the chain frame it lies in — the root here, numbered
    /// from the stop — or nowhere. Placement is half-open: the word
    /// one past a frame's end is not in it.
    #[test]
    fn test_the_fold_arms_a_branch_by_a_slot_inside_it() {
        let task = idle();
        let mut wait = stopped(vec![branch(0x6000)]);
        fold(
            &task,
            &mut wait,
            &[typed(0x6010), typed(0x9008), typed(0x7000), typed(0x9040)],
        );
        let set = set_of(&wait);
        assert_eq!(
            (set.at, set.reason),
            (Some(key(0x5000)), Some(SemanticIssueKind::NoRule))
        );
        assert_eq!(set.members.len(), 4, "{:#?}", set.members);
        assert!(matches!(
            &set.members[0].armed,
            Some(SlotRef::Swept { slot, .. }) if slot.slot == 0x6010
        ));
        let within = |member: &WaitMember| match &member.route {
            MemberRoute::SlotOnly { within } => within.clone(),
            other => panic!("a slot on its own, not {other:?}"),
        };
        assert_eq!(
            within(&set.members[1]),
            Some("inside #1's storage at +0x8".to_string())
        );
        assert_eq!(within(&set.members[2]), None);
        assert_eq!(within(&set.members[3]), None, "one past the root's end");
        assert_eq!(
            set.cell(),
            "slot 0x6010 in x::Holder, slot 0x7000 in x::Holder, slot 0x9008 in x::Holder, \
             slot 0x9040 in x::Holder"
        );
        assert_eq!(set.group_label(), "slot in x::Holder");
        assert!(wait.held.is_empty());
    }

    /// The pair a member's evidence already stands on adds nothing: the
    /// wheel entry that armed a branch, the entry a slot-only member
    /// is, the waker a branch's protocol read. A different slot inside
    /// an armed branch is a second place the waker is parked, and a
    /// member on its own.
    #[test]
    fn test_the_fold_skips_a_twin_and_adds_a_second_parking_place() {
        let task = idle();
        let mut armed = branch(0x6000);
        armed.armed = Some(SlotRef::Wheel {
            entry: 0x6008,
            state: None,
            deadline: None,
            stopped: None,
        });
        let mut verified = branch(0x8000);
        verified.assessment = Some(WaitAssessment::Waiting(VerifiedWait::testkit(
            notify_target(0x7000),
            None,
        )));
        verified.armed = Some(SlotRef::Protocol);
        let alone = |armed: SlotRef| WaitMember {
            route: MemberRoute::SlotOnly { within: None },
            key: None,
            future: None,
            assessment: None,
            notes: Vec::new(),
            armed: Some(armed),
        };
        let wheel = alone(SlotRef::Wheel {
            entry: 0xee00,
            state: None,
            deadline: None,
            stopped: None,
        });
        let io = alone(SlotRef::Io {
            resource: 0x7700,
            slot: IoSlot::Reader,
            fd: None,
            ready: None,
        });
        let io_slot = swept(
            0x7708,
            Attribution::Registry(RegistrySlot::Io {
                resource: 0x7700,
                slot: IoSlot::Reader,
                ready: None,
            }),
        );
        let mut wait = stopped(Vec::new());
        wait.assessment = WaitAssessment::Set(WaitSet {
            at: Some(key(0x5000)),
            reason: Some(SemanticIssueKind::NoRule),
            members: vec![armed, verified, wheel, io],
            capped: 1,
        });
        fold(
            &task,
            &mut wait,
            &[
                timer_slot(0x6008),
                timer_slot(0xee00),
                io_slot.clone(),
                notify_slot(0x8010, 0x7000),
                notify_slot(0x6020, 0x7100),
            ],
        );
        let set = set_of(&wait);
        assert_eq!(set.capped, 1);
        assert_eq!(set.members.len(), 5, "{:#?}", set.members);
        assert!(matches!(set.members[0].armed, Some(SlotRef::Wheel { .. })));
        assert!(matches!(set.members[1].armed, Some(SlotRef::Protocol)));
        assert!(matches!(set.members[2].armed, Some(SlotRef::Wheel { .. })));
        assert!(matches!(set.members[3].armed, Some(SlotRef::Io { .. })));
        assert!(matches!(
            &set.members[4].armed,
            Some(SlotRef::Swept { slot, .. }) if slot.slot == 0x6020
        ));
        assert_eq!(
            set.cell(),
            "io 0x7700 (readable), notify 0x7000, notify 0x7100, timer 0x6008, timer 0xee00"
        );
        assert_eq!(set.group_label(), "io, notify, timer");
        // Folding the same slots again changes nothing: every one is
        // now a twin.
        let before = format!("{:?}", set.members);
        fold(
            &task,
            &mut wait,
            &[timer_slot(0x6008), io_slot, notify_slot(0x6020, 0x7100)],
        );
        assert_eq!(format!("{:?}", set_of(&wait).members), before);
    }

    /// Beside a verified wait a slot is never a member: one the wait
    /// accounts for is silent, one it does not is a note — except a
    /// registry's wheel or io pair, which the analysis already noted,
    /// and a pair in untyped memory, which names nothing.
    #[test]
    fn test_the_fold_notes_a_slot_beside_a_verified_wait() {
        let task = idle();
        let mut wait = stopped(Vec::new());
        wait.assessment =
            WaitAssessment::Waiting(VerifiedWait::testkit(notify_target(0x7000), None));
        wait.continuation = ContinuationStatus::Primitive;
        fold(
            &task,
            &mut wait,
            &[
                notify_slot(0x6020, 0x7000),
                notify_slot(0x6040, 0x7100),
                timer_slot(0xdd00),
                nowhere(0x8000),
            ],
        );
        assert!(wait.verified().is_some());
        assert_eq!(
            wait.notes,
            ["notify 0x7100 also holds this task's waker, outside the verified wait"]
        );
    }

    /// Every definite assessment is left alone, whatever the sweep
    /// found in the task's storage — a task never polled, a resource
    /// that did not read — and so are a blocking cell and a mid-poll
    /// task, which are not parked.
    #[test]
    fn test_the_fold_leaves_definite_and_unparked_tasks_alone() {
        let slots = [typed(0x9008)];
        let mut never = stopped(Vec::new());
        never.assessment = WaitAssessment::Unresumed;
        fold(&idle(), &mut never, &slots);
        assert!(matches!(never.assessment, WaitAssessment::Unresumed));

        let mut unread = stopped(Vec::new());
        unread.assessment = WaitAssessment::Unknown(WaitUnknownReason::ResourceUnreadable);
        fold(&idle(), &mut unread, &slots);
        assert!(matches!(
            unread.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::ResourceUnreadable)
        ));

        let mut polled = stopped(vec![branch(0x6000)]);
        fold(&a_task(RUNNING, TaskKind::Async), &mut polled, &slots);
        assert!(matches!(
            polled.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::Continuation)
        ));
        assert_eq!(polled.held.len(), 1);

        let mut blocking = stopped(Vec::new());
        fold(&a_task(0, TaskKind::Blocking), &mut blocking, &slots);
        assert!(matches!(
            blocking.assessment,
            WaitAssessment::Unknown(WaitUnknownReason::Continuation)
        ));
    }

    /// A chain cut short of any stop still gets its set — the sweep's
    /// slots alone, at no stop — and slots in allocations nothing
    /// typed reaches collapse to their count past the first.
    #[test]
    fn test_the_fold_sets_a_cut_chain_and_collapses_the_unknown() {
        let task = idle();
        let mut wait = stopped(Vec::new());
        wait.continuation = ContinuationStatus::Incomplete {
            reason: crate::tokio::assess::IncompleteReason::AmbiguousDyn,
            detail: None,
        };
        wait.frames = Vec::new();
        fold(
            &task,
            &mut wait,
            &[nowhere(0x7000), typed(0x6010), nowhere(0x8000)],
        );
        let set = set_of(&wait);
        assert_eq!((set.at, set.reason), (None, None));
        assert_eq!(set.members.len(), 3);
        assert_eq!(set.cell(), "2× unknown, slot 0x6010 in x::Holder");
        assert_eq!(set.group_label(), "slot in x::Holder, unknown");
        let mut one = stopped(Vec::new());
        fold(&task, &mut one, &[nowhere(0x7000)]);
        assert_eq!(set_of(&one).cell(), "unknown 0x7000");
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The discovery sweep: one queue of finite work items, run to a
//! fixed point.
//!
//! Every route hidden-task discovery runs is an item of
//! `DiscoveryWork`: an admitted owner's list is enumerated once and
//! its registries harvested once, a resident task's storage is scanned
//! once, and every find — a reference in scanned storage, a waker in a
//! registry, an entry of a pool queue — is validated and merged once.
//! Each item can schedule more (an enumeration makes tasks to scan, a
//! scan makes finds to validate, a validated find can admit an owner),
//! and the queue ends because each owner schedules each kind of work
//! once, each record is scanned once, and the finds a scan makes are
//! bounded by its budget. An explicit item cap backs that up against a
//! target that lies, and a run that reaches it reports what was left
//! ([`WorkTally`]) rather than trimming the population quietly.
//!
//! What the sweep does to the target is the `DiscoveryWorld`'s:
//! [`Context`] implements it over a target's memory, and a synthetic
//! world implements it over a graph a test wrote down, which is how
//! the queue is judged against an exhaustive rescan.
//!
//! The sweep also keeps the routes it took — which owner enumerated
//! which task, which task's storage or which owner's registry named
//! which record — as the scope a `--runtime` selection is projected
//! through: a task an excluded runtime owns is never scanned, and a
//! record reachable only through one is out of the selection's scope
//! whenever its owner was learned, with its evidence kept.
//!
//! [`Context`]: super::bundle::Context

use super::bundle::Candidate;
use super::discovery::{OwnerEvidence, OwnerKey, OwnerResolution, TaskRecordId, TaskSource};
use super::model::TaskList;
use super::observe::{ScanBudget, ScanLimits};

use foldhash::{HashMap, HashSet};

use std::collections::VecDeque;
use std::fmt;

/// One item of discovery work.
#[derive(Debug)]
pub(crate) enum DiscoveryWork {
    /// Walk a runtime's owned lists into the store.
    EnumerateRuntime(OwnerKey),
    /// Walk a local set's owned list into the store.
    EnumerateLocalSet(OwnerKey),
    /// Scan a resident record's initialized storage for references.
    ScanTask(TaskRecordId),
    /// Harvest the task wakers armed in a runtime's timer wheel.
    HarvestTimers(OwnerKey),
    /// Harvest the task wakers parked on a runtime's io registrations.
    HarvestIo(OwnerKey),
    /// Read the entries of a runtime's blocking-pool queue.
    HarvestBlockingQueue(OwnerKey),
    /// Validate one find and merge it into the store, admitting the
    /// owner its cell names; `from` is the route that made it.
    Validate { candidate: Candidate, from: Origin },
}

/// Where a find came from: the task whose storage held it, or the
/// owner whose registry or queue did.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Origin {
    Task(TaskRecordId),
    Owner(OwnerKey),
}

/// Which of a runtime's registries a harvest reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Registry {
    Timers,
    Io,
    BlockingQueue,
}

/// What the sweep asks of the target. Every method files what it
/// found into `list.records` and what failed into `list.errors`; the
/// sweep never reads the target itself.
pub(crate) trait DiscoveryWorld {
    /// Walk an admitted owner's list, filing each member with the
    /// owner's claim where the list's id is the member's.
    fn enumerate(&mut self, owner: OwnerKey, list: &mut TaskList);

    /// Scan one resident record's storage under the run's budget; the
    /// references found, as candidates.
    fn scan(
        &mut self,
        id: TaskRecordId,
        list: &mut TaskList,
        budget: &mut ScanBudget,
    ) -> Vec<Candidate>;

    /// Read one registry of an admitted runtime; its finds.
    fn harvest(
        &mut self,
        owner: OwnerKey,
        registry: Registry,
        list: &mut TaskList,
    ) -> Vec<Candidate>;

    /// Validate one find and merge it: decode the header once per
    /// address, file the source and any claim, and follow a fresh
    /// scheduler-owned task home to the owner its cell names. The
    /// owners that admitted, in admission order — none for an owner
    /// already admitted, excluded, or that did not claim the task.
    fn validate(&mut self, candidate: Candidate, list: &mut TaskList) -> Vec<OwnerKey>;
}

/// The owners discovery starts from: the runtimes the worker threads'
/// contexts reached — whose lists the caller enumerated before the
/// sweep — and the local sets the TLS probe found.
#[derive(Clone, Debug, Default)]
pub(crate) struct Roots {
    pub runtimes: Vec<OwnerKey>,
    pub sets: Vec<OwnerKey>,
}

/// Items of work by kind: what a sweep did, or what it had left when
/// its cap ended it.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct WorkTally {
    pub runtimes: usize,
    pub sets: usize,
    pub scans: usize,
    pub timers: usize,
    pub io: usize,
    pub queues: usize,
    pub validations: usize,
}

impl WorkTally {
    pub fn total(&self) -> usize {
        self.runtimes
            + self.sets
            + self.scans
            + self.timers
            + self.io
            + self.queues
            + self.validations
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

impl fmt::Display for WorkTally {
    /// The nonzero kinds, as a list: `3 tasks to scan, 2 finds to
    /// validate`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kinds = [
            (self.runtimes, "runtime", "runtimes", "to enumerate"),
            (self.sets, "local set", "local sets", "to enumerate"),
            (self.scans, "task", "tasks", "to scan"),
            (self.validations, "find", "finds", "to validate"),
            (self.timers, "timer wheel", "timer wheels", "to harvest"),
            (self.io, "io driver", "io drivers", "to harvest"),
            (
                self.queues,
                "blocking queue",
                "blocking queues",
                "to harvest",
            ),
        ];
        let mut first = true;
        for (count, one, many, verb) in kinds {
            if count == 0 {
                continue;
            }
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            let noun = if count == 1 { one } else { many };
            write!(f, "{count} {noun} {verb}")?;
        }
        if first {
            f.write_str("nothing")?;
        }
        Ok(())
    }
}

/// What one sweep did and left. The account of what ran — the items
/// by kind, the excluded tasks left unscanned — is what the tests
/// judge the queue by; production reads what was left and what the
/// scope reached.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SweepOutcome {
    /// The items processed.
    pub processed: WorkTally,
    /// The items still queued when the sweep ended — empty unless the
    /// cap ended it.
    pub remaining: WorkTally,
    /// Whether the item cap ended the sweep with work outstanding.
    pub capped: bool,
    /// The scan budget as the sweep left it.
    pub budget: ScanBudget,
    /// Every owner the selection's scope reaches: the roots, and what
    /// was admitted along a route from them that crosses no task an
    /// excluded runtime owns. An admitted owner absent here was reached
    /// only through such a task.
    pub reached: Vec<OwnerKey>,
    /// Resident records whose owner is excluded, so whose storage was
    /// not scanned.
    pub unscanned_excluded: usize,
}

/// The queue: one FIFO per kind, drained in a fixed order of kinds.
///
/// The order is the old rounds' order made explicit, and it is what
/// keeps a route's *first* find stable: a validation runs before
/// anything it could have made obsolete; an admitted owner is
/// enumerated before more is scanned, so a list an enumerated task
/// points at is credited to that reference; every scan runs before
/// any registry is read, so a set some task holds a handle into is
/// found through the handle rather than through whichever member
/// happens to hold a timer; and the pool queues come last, since
/// their cells bootstrap nothing.
#[derive(Default)]
struct Queue {
    validations: VecDeque<(Candidate, Origin)>,
    runtimes: VecDeque<OwnerKey>,
    sets: VecDeque<OwnerKey>,
    scans: VecDeque<TaskRecordId>,
    timers: VecDeque<OwnerKey>,
    io: VecDeque<OwnerKey>,
    queues: VecDeque<OwnerKey>,
}

impl Queue {
    fn pop(&mut self) -> Option<DiscoveryWork> {
        if let Some((candidate, from)) = self.validations.pop_front() {
            return Some(DiscoveryWork::Validate { candidate, from });
        }
        if let Some(owner) = self.runtimes.pop_front() {
            return Some(DiscoveryWork::EnumerateRuntime(owner));
        }
        if let Some(owner) = self.sets.pop_front() {
            return Some(DiscoveryWork::EnumerateLocalSet(owner));
        }
        if let Some(id) = self.scans.pop_front() {
            return Some(DiscoveryWork::ScanTask(id));
        }
        if let Some(owner) = self.timers.pop_front() {
            return Some(DiscoveryWork::HarvestTimers(owner));
        }
        if let Some(owner) = self.io.pop_front() {
            return Some(DiscoveryWork::HarvestIo(owner));
        }
        if let Some(owner) = self.queues.pop_front() {
            return Some(DiscoveryWork::HarvestBlockingQueue(owner));
        }
        None
    }

    fn tally(&self) -> WorkTally {
        WorkTally {
            runtimes: self.runtimes.len(),
            sets: self.sets.len(),
            scans: self.scans.len(),
            timers: self.timers.len(),
            io: self.io.len(),
            queues: self.queues.len(),
            validations: self.validations.len(),
        }
    }
}

/// Whether an owner is one the selection excludes: a runtime, by
/// handle address. A local set is never excluded (see
/// [`Context::discover_hidden_tasks`]).
///
/// [`Context::discover_hidden_tasks`]: super::bundle::Context::discover_hidden_tasks
fn is_excluded(owner: OwnerKey, excluded: &[u64]) -> bool {
    match owner {
        OwnerKey::Runtime { handle, .. } => excluded.contains(&handle),
        OwnerKey::LocalSet { .. } => false,
    }
}

/// Whether a record is proven owned by an excluded runtime: its one
/// established owner is one. A conflict naming an excluded owner is
/// not proof, and neither is an unknown.
fn excluded_owned(owner: &OwnerResolution, excluded: &[u64]) -> bool {
    owner.known().is_some_and(|key| is_excluded(key, excluded))
}

/// Run discovery over `world` to its fixed point, from `roots`, under
/// `limits`. The root runtimes' lists are what the caller enumerated
/// into `list` already, so only their registries are scheduled; the
/// root sets are enumerated. Every owner admitted along the way
/// schedules its population and registries once, every record that
/// becomes resident schedules its scan once, and every find is
/// validated once. When the sweep ends the records outside the
/// selection's scope are marked so, and the owners inside it returned.
pub(crate) fn sweep<W: DiscoveryWorld>(
    world: &mut W,
    list: &mut TaskList,
    roots: &Roots,
    excluded: &[u64],
    limits: ScanLimits,
) -> SweepOutcome {
    let mut queue = Queue::default();
    let mut budget = ScanBudget::new(limits);
    let mut processed = WorkTally::default();
    let mut scheduled: HashSet<OwnerKey> = HashSet::default();
    // Each find's route, for the scope: (where it came from, what it
    // named).
    let mut found_from: Vec<(Origin, TaskRecordId)> = Vec::new();
    let mut unscanned_excluded = 0;

    let mut schedule_owner = |owner: OwnerKey, enumerate: bool, queue: &mut Queue| {
        if is_excluded(owner, excluded) || !scheduled.insert(owner) {
            return;
        }
        match owner {
            OwnerKey::Runtime { .. } => {
                if enumerate {
                    queue.runtimes.push_back(owner);
                }
                queue.timers.push_back(owner);
                queue.io.push_back(owner);
                queue.queues.push_back(owner);
            }
            OwnerKey::LocalSet { .. } => queue.sets.push_back(owner),
        }
    };
    for &runtime in &roots.runtimes {
        schedule_owner(runtime, false, &mut queue);
    }
    for &set in &roots.sets {
        schedule_owner(set, true, &mut queue);
    }
    // Whatever the caller enumerated before the sweep is scannable
    // now; whatever the sweep files becomes so as it does.
    queue.scans.extend(list.records.take_scannable());

    let mut capped = false;
    loop {
        if (processed.total() as u64) >= limits.max_work_items {
            capped = !queue.tally().is_empty();
            break;
        }
        let Some(item) = queue.pop() else {
            break;
        };
        match item {
            DiscoveryWork::Validate { candidate, from } => {
                processed.validations += 1;
                let addr = candidate.addr();
                let admitted = world.validate(candidate, list);
                if let Some(id) = list.records.lookup(addr) {
                    found_from.push((from, id));
                }
                for owner in admitted {
                    schedule_owner(owner, true, &mut queue);
                }
                queue.scans.extend(list.records.take_scannable());
            }
            DiscoveryWork::EnumerateRuntime(owner) => {
                processed.runtimes += 1;
                world.enumerate(owner, list);
                queue.scans.extend(list.records.take_scannable());
            }
            DiscoveryWork::EnumerateLocalSet(owner) => {
                processed.sets += 1;
                world.enumerate(owner, list);
                queue.scans.extend(list.records.take_scannable());
            }
            DiscoveryWork::ScanTask(id) => {
                processed.scans += 1;
                // A task an excluded runtime owns is not in the
                // selection, and neither is anything reachable only
                // through its storage.
                if excluded_owned(&list.records.record(id).owner(), excluded) {
                    unscanned_excluded += 1;
                    continue;
                }
                for candidate in world.scan(id, list, &mut budget) {
                    queue.validations.push_back((candidate, Origin::Task(id)));
                }
            }
            DiscoveryWork::HarvestTimers(owner) => {
                processed.timers += 1;
                for candidate in world.harvest(owner, Registry::Timers, list) {
                    queue
                        .validations
                        .push_back((candidate, Origin::Owner(owner)));
                }
            }
            DiscoveryWork::HarvestIo(owner) => {
                processed.io += 1;
                for candidate in world.harvest(owner, Registry::Io, list) {
                    queue
                        .validations
                        .push_back((candidate, Origin::Owner(owner)));
                }
            }
            DiscoveryWork::HarvestBlockingQueue(owner) => {
                processed.queues += 1;
                for candidate in world.harvest(owner, Registry::BlockingQueue, list) {
                    queue
                        .validations
                        .push_back((candidate, Origin::Owner(owner)));
                }
            }
        }
    }
    let remaining = queue.tally();
    let reached = apply_scope(list, roots, &found_from, excluded);
    SweepOutcome {
        processed,
        remaining,
        capped,
        budget,
        reached,
        unscanned_excluded,
    }
}

/// The selection's scope, recomputed over everything the sweep kept:
/// from the roots, an owner reaches every record its list or queue
/// carries and every record its registries named; a record whose one
/// owner is not excluded reaches every record its storage named and
/// every owner its cell was validated against. A record the walk never
/// reaches is marked out of scope; the owners it reaches are returned,
/// in root-then-admission order.
///
/// The list and queue links are read off the records' sources, the
/// cell links off their claims, and the registry and storage links off
/// `found_from` — so the scope stands whenever an owner was learned,
/// and a task whose owner turned out excluded after its storage was
/// scanned still takes its descendants out of the projection without
/// erasing what was found there.
fn apply_scope(
    list: &mut TaskList,
    roots: &Roots,
    found_from: &[(Origin, TaskRecordId)],
    excluded: &[u64],
) -> Vec<OwnerKey> {
    let store = &list.records;
    let mut owner_tasks: HashMap<OwnerKey, Vec<TaskRecordId>> = HashMap::default();
    let mut task_tasks: HashMap<TaskRecordId, Vec<TaskRecordId>> = HashMap::default();
    for (id, record) in store.records() {
        for source in &record.sources {
            match source {
                TaskSource::OwnedList { owner, .. } | TaskSource::BlockingQueue { owner, .. } => {
                    owner_tasks.entry(*owner).or_default().push(id);
                }
                TaskSource::Reference(_) => {}
            }
        }
    }
    for &(from, id) in found_from {
        match from {
            Origin::Owner(owner) => owner_tasks.entry(owner).or_default().push(id),
            Origin::Task(task) => task_tasks.entry(task).or_default().push(id),
        }
    }

    let mut reached_owners: Vec<OwnerKey> = Vec::new();
    let mut seen_owners: HashSet<OwnerKey> = HashSet::default();
    let mut reached_tasks = vec![false; store.len()];
    let mut work: VecDeque<Origin> = VecDeque::new();
    for &owner in roots.runtimes.iter().chain(&roots.sets) {
        if !is_excluded(owner, excluded) && seen_owners.insert(owner) {
            reached_owners.push(owner);
            work.push_back(Origin::Owner(owner));
        }
    }
    while let Some(node) = work.pop_front() {
        match node {
            Origin::Owner(owner) => {
                for &id in owner_tasks
                    .get(&owner)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                {
                    if !reached_tasks[id.0] {
                        reached_tasks[id.0] = true;
                        work.push_back(Origin::Task(id));
                    }
                }
            }
            Origin::Task(id) => {
                let record = store.record(id);
                if excluded_owned(&record.owner(), excluded) {
                    continue;
                }
                for &next in task_tasks.get(&id).map(Vec::as_slice).unwrap_or_default() {
                    if !reached_tasks[next.0] {
                        reached_tasks[next.0] = true;
                        work.push_back(Origin::Task(next));
                    }
                }
                for claim in &record.owner_claims {
                    if !matches!(claim.evidence, OwnerEvidence::CellScheduler { .. }) {
                        continue;
                    }
                    let owner = claim.owner;
                    if !is_excluded(owner, excluded) && seen_owners.insert(owner) {
                        reached_owners.push(owner);
                        work.push_back(Origin::Owner(owner));
                    }
                }
            }
        }
    }
    for (index, reached) in reached_tasks.into_iter().enumerate() {
        list.records.set_scope(TaskRecordId(index), reached);
    }
    reached_owners
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokio::discovery::{
        DiscoveryIssue, Observation, OwnerClaim, TaskKind, TaskStore, list_claim,
    };
    use crate::tokio::model::{DecodedTaskHeader, DiscoveryRoute, FutureInfo, RuntimeFlavor};
    use crate::tokio::observe::{ReferenceSource, TaskReference, ValueKey};
    use crate::tokio::{TaskAddr, TaskState};

    use anyhow::anyhow;
    use hansei_bundle::BundleTypeId;

    use std::collections::{BTreeMap, BTreeSet};

    const REF_ONE: u64 = 1 << 6;
    const COMPLETE: u64 = 0b0010;

    fn rt(handle: u64) -> OwnerKey {
        OwnerKey::Runtime {
            flavor: RuntimeFlavor::MultiThread,
            handle,
        }
    }

    fn set(shared: u64) -> OwnerKey {
        OwnerKey::LocalSet { shared }
    }

    fn key(addr: u64) -> ValueKey {
        ValueKey {
            addr,
            ty: BundleTypeId(1),
        }
    }

    /// One task of a synthetic target: its lifecycle bits, the owner
    /// id its header records, the kind its cell's scheduler type says,
    /// and the owner that scheduler names (`None` for a blocking cell
    /// or an unclassifiable one).
    #[derive(Clone, Debug)]
    struct Fake {
        state: u64,
        owner_id: Option<u64>,
        kind: Option<TaskKind>,
        cell: Option<OwnerKey>,
    }

    impl Fake {
        fn header(&self, addr: u64) -> DecodedTaskHeader {
            DecodedTaskHeader {
                addr: TaskAddr(addr),
                state: TaskState(REF_ONE | self.state),
                owner_id: self.owner_id,
                task_id: Some(addr >> 4),
                spawn_location: None,
                vtable_addr: 0xf000,
                trailer_offset: 0x40,
                future: FutureInfo::Unknown { poll_symbol: None },
            }
        }
    }

    /// A target as a graph: owners with list ids and members, tasks
    /// with headers, what each task's storage references, and each
    /// runtime's registries. `validate` mirrors what the live world
    /// does with a find, including the owner bootstrap and its
    /// exclusion rule.
    #[derive(Clone, Debug, Default)]
    struct World {
        ids: BTreeMap<OwnerKey, u64>,
        lists: BTreeMap<OwnerKey, Vec<u64>>,
        tasks: BTreeMap<u64, Fake>,
        refs: BTreeMap<u64, Vec<u64>>,
        timers: BTreeMap<OwnerKey, Vec<u64>>,
        io: BTreeMap<OwnerKey, Vec<u64>>,
        pool: BTreeMap<OwnerKey, Vec<u64>>,
        excluded: Vec<u64>,
        /// Every owner the world admitted, in admission order — roots
        /// first, as the caller admits them.
        admitted: Vec<OwnerKey>,
        calls: WorkTally,
    }

    impl World {
        fn owner(&mut self, owner: OwnerKey, id: u64, members: &[u64]) -> &mut Self {
            self.ids.insert(owner, id);
            self.lists.insert(owner, members.to_vec());
            self
        }

        fn task(&mut self, addr: u64, owner_id: Option<u64>, cell: Option<OwnerKey>) -> &mut Self {
            let kind = cell.map(|_| TaskKind::Async);
            self.tasks.insert(
                addr,
                Fake {
                    state: 0,
                    owner_id,
                    kind,
                    cell,
                },
            );
            self
        }

        fn blocking(&mut self, addr: u64) -> &mut Self {
            self.tasks.insert(
                addr,
                Fake {
                    state: 0,
                    owner_id: None,
                    kind: Some(TaskKind::Blocking),
                    cell: None,
                },
            );
            self
        }

        fn complete(&mut self, addr: u64) -> &mut Self {
            self.tasks.get_mut(&addr).unwrap().state = COMPLETE;
            self
        }

        fn refs(&mut self, from: u64, to: &[u64]) -> &mut Self {
            self.refs.entry(from).or_default().extend(to);
            self
        }

        fn reference(target: u64, source: ReferenceSource, holder: Option<u64>) -> Candidate {
            Candidate::Reference {
                reference: TaskReference {
                    target: TaskAddr(target),
                    source,
                    source_value: Some(key(holder.unwrap_or(target) + 0x10)),
                    root_task: holder.map(TaskAddr),
                    path: Vec::new(),
                },
                route: match source {
                    ReferenceSource::TimerWaker => DiscoveryRoute::Wheel,
                    ReferenceSource::IoWaker => DiscoveryRoute::Io,
                    other => DiscoveryRoute::Scanned(other),
                },
            }
        }

        /// The root runtimes' lists, enumerated the way a session
        /// enumerates them before discovery.
        fn enumerated(&mut self, roots: &Roots) -> TaskList {
            let mut list = TaskList::default();
            for &owner in &roots.runtimes {
                self.admitted.push(owner);
                self.enumerate(owner, &mut list);
            }
            for &owner in &roots.sets {
                self.admitted.push(owner);
            }
            list
        }
    }

    impl DiscoveryWorld for World {
        fn enumerate(&mut self, owner: OwnerKey, list: &mut TaskList) {
            match owner {
                OwnerKey::Runtime { .. } => self.calls.runtimes += 1,
                OwnerKey::LocalSet { .. } => self.calls.sets += 1,
            }
            let Some(members) = self.lists.get(&owner) else {
                list.errors.push(anyhow!("no list for {owner}"));
                return;
            };
            let head = members.first().copied().unwrap_or(0);
            for &addr in members {
                let fake = &self.tasks[&addr];
                let header = fake.header(addr);
                let (claim, mismatch) =
                    list_claim(owner, head, self.ids.get(&owner).copied(), &header);
                let effect = list.records.observe(
                    header,
                    Observation {
                        source: TaskSource::OwnedList { owner, head },
                        kind: fake.kind,
                        claim,
                    },
                );
                if let Some(mismatch) = mismatch {
                    list.records.issue(effect.record, mismatch);
                }
            }
        }

        fn scan(
            &mut self,
            id: TaskRecordId,
            list: &mut TaskList,
            _: &mut ScanBudget,
        ) -> Vec<Candidate> {
            self.calls.scans += 1;
            list.records.mark_scanned(id);
            let addr = list.records.record(id).addr().0;
            self.refs
                .get(&addr)
                .map(|targets| {
                    targets
                        .iter()
                        .map(|&t| World::reference(t, ReferenceSource::JoinHandle, Some(addr)))
                        .collect()
                })
                .unwrap_or_default()
        }

        fn harvest(
            &mut self,
            owner: OwnerKey,
            registry: Registry,
            _: &mut TaskList,
        ) -> Vec<Candidate> {
            match registry {
                Registry::Timers => {
                    self.calls.timers += 1;
                    self.timers
                        .get(&owner)
                        .map(|ts| {
                            ts.iter()
                                .map(|&t| World::reference(t, ReferenceSource::TimerWaker, None))
                                .collect()
                        })
                        .unwrap_or_default()
                }
                Registry::Io => {
                    self.calls.io += 1;
                    self.io
                        .get(&owner)
                        .map(|ts| {
                            ts.iter()
                                .map(|&t| World::reference(t, ReferenceSource::IoWaker, None))
                                .collect()
                        })
                        .unwrap_or_default()
                }
                Registry::BlockingQueue => {
                    self.calls.queues += 1;
                    self.pool
                        .get(&owner)
                        .map(|ts| {
                            ts.iter()
                                .map(|&t| Candidate::Queued {
                                    addr: t,
                                    owner,
                                    queue: key(0x9000),
                                    entry: t + 0x100,
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                }
            }
        }

        fn validate(&mut self, candidate: Candidate, list: &mut TaskList) -> Vec<OwnerKey> {
            self.calls.validations += 1;
            let addr = candidate.addr();
            let (source, claim) = match candidate {
                Candidate::Reference { reference, .. } => (TaskSource::Reference(reference), None),
                Candidate::Queued {
                    owner,
                    queue,
                    entry,
                    ..
                } => (
                    TaskSource::BlockingQueue {
                        owner,
                        queue,
                        entry,
                    },
                    Some(OwnerClaim {
                        owner,
                        evidence: OwnerEvidence::BlockingQueue { queue, entry },
                    }),
                ),
            };
            if let Some(id) = list.records.lookup(addr) {
                list.records.observe_at(
                    id,
                    Observation {
                        source,
                        kind: None,
                        claim,
                    },
                );
                return Vec::new();
            }
            let Some(fake) = self.tasks.get(&addr).cloned() else {
                list.errors
                    .push(anyhow!("failed to decode the task at {addr:#x}"));
                return Vec::new();
            };
            let effect = list.records.observe(
                fake.header(addr),
                Observation {
                    source,
                    kind: fake.kind,
                    claim,
                },
            );
            let Some(owner) = fake.cell else {
                return Vec::new();
            };
            let Some(&list_id) = self.ids.get(&owner) else {
                list.errors
                    .push(anyhow!("the owned list's id did not bind for {owner}"));
                return Vec::new();
            };
            if fake.owner_id != Some(list_id) {
                list.records.issue(
                    effect.record,
                    DiscoveryIssue::OwnerIdMismatch {
                        addr: TaskAddr(addr),
                        owner,
                        expected: list_id,
                        found: fake.owner_id,
                    },
                );
                return Vec::new();
            }
            list.records.claim(
                effect.record,
                OwnerClaim {
                    owner,
                    evidence: OwnerEvidence::CellScheduler {
                        scheduler: key(match owner {
                            OwnerKey::Runtime { handle, .. } => handle,
                            OwnerKey::LocalSet { shared } => shared,
                        }),
                        owner_id: list_id,
                    },
                },
            );
            if is_excluded(owner, &self.excluded) || self.admitted.contains(&owner) {
                return Vec::new();
            }
            self.admitted.push(owner);
            vec![owner]
        }
    }

    /// What a discovery run established, in a form two runs can be
    /// compared by whatever order they ran in: per record its kind,
    /// owner, residency and how many sources named it. Not how many
    /// claims: a record a list claimed first gains no claim from a
    /// later reference's cell — the bootstrap runs at the first decode
    /// only — and one a reference found first does, to the same owner.
    #[derive(PartialEq, Eq, Debug)]
    struct Fixpoint {
        records: BTreeSet<(u64, String, String, bool, usize)>,
        rows: BTreeSet<u64>,
        admitted: BTreeSet<OwnerKey>,
        issues: BTreeSet<String>,
    }

    fn fixpoint(world: &World, list: &TaskList) -> Fixpoint {
        Fixpoint {
            records: list
                .records
                .records()
                .map(|(_, r)| {
                    (
                        r.addr().0,
                        format!("{:?}", r.kind()),
                        format!("{:?}", r.owner()),
                        r.resident(),
                        r.sources.len() + r.omitted_sources,
                    )
                })
                .collect(),
            rows: list.tasks.iter().map(|t| t.addr.0).collect(),
            admitted: world.admitted.iter().copied().collect(),
            issues: list.records.issues().map(ToString::to_string).collect(),
        }
    }

    /// The exhaustive rescan the queue is judged against: every pass
    /// enumerates every admitted owner not yet enumerated, scans every
    /// resident record not yet scanned (never one an excluded runtime
    /// owns), harvests every admitted runtime not yet harvested, and
    /// the run ends on the first pass that did nothing.
    fn exhaustive(world: &mut World, list: &mut TaskList, roots: &Roots) -> Vec<OwnerKey> {
        let excluded = world.excluded.clone();
        let mut enumerated: BTreeSet<OwnerKey> = roots.runtimes.iter().copied().collect();
        let mut harvested: BTreeSet<OwnerKey> = BTreeSet::new();
        let mut budget = ScanBudget::default();
        loop {
            let mut did = false;
            for owner in world.admitted.clone() {
                if enumerated.insert(owner) {
                    world.enumerate(owner, list);
                    did = true;
                }
            }
            let unscanned: Vec<TaskRecordId> = list
                .records
                .records()
                .filter(|(_, r)| {
                    r.resident() && !r.scanned && !excluded_owned(&r.owner(), &excluded)
                })
                .map(|(id, _)| id)
                .collect();
            for id in unscanned {
                did = true;
                for candidate in world.scan(id, list, &mut budget) {
                    world.validate(candidate, list);
                }
            }
            for owner in world.admitted.clone() {
                if !matches!(owner, OwnerKey::Runtime { .. }) || !harvested.insert(owner) {
                    continue;
                }
                did = true;
                for registry in [Registry::Timers, Registry::Io, Registry::BlockingQueue] {
                    for candidate in world.harvest(owner, registry, list) {
                        world.validate(candidate, list);
                    }
                }
            }
            if !did {
                break;
            }
        }
        list.reproject(&excluded);
        world.admitted.clone()
    }

    /// Run the queue over a world from `roots`, the way the live
    /// sweep runs it: the root runtimes enumerated first.
    fn queued(world: &mut World, roots: &Roots, limits: ScanLimits) -> (TaskList, SweepOutcome) {
        let mut list = world.enumerated(roots);
        let excluded = world.excluded.clone();
        let outcome = sweep(world, &mut list, roots, &excluded, limits);
        list.reproject(&excluded);
        (list, outcome)
    }

    /// A small pseudo-random target: two to four owners with lists,
    /// tasks whose cells name them (right or wrong), references among
    /// tasks, registries and pools, and sometimes an excluded runtime.
    fn random_world(seed: u64) -> (World, Roots) {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let mut world = World::default();
        let owners: Vec<OwnerKey> = (0..2 + next(3) as usize)
            .map(|i| {
                if i == 0 || next(2) == 0 {
                    rt(0x1000 * (i as u64 + 1))
                } else {
                    set(0x1000 * (i as u64 + 1))
                }
            })
            .collect();
        for (i, &owner) in owners.iter().enumerate() {
            world.ids.insert(owner, 10 + i as u64);
            world.lists.insert(owner, Vec::new());
        }
        let tasks = 4 + next(8);
        let addrs: Vec<u64> = (0..tasks).map(|i| 0x10_000 + 0x100 * i).collect();
        for &addr in &addrs {
            match next(6) {
                // Listed by its owner, cell agreeing.
                0..=2 => {
                    let owner = owners[next(owners.len() as u64) as usize];
                    world.lists.get_mut(&owner).unwrap().push(addr);
                    world.task(addr, Some(world.ids[&owner]), Some(owner));
                }
                // A cell naming an owner whose list does not carry it:
                // the id agrees or not.
                3 => {
                    let owner = owners[next(owners.len() as u64) as usize];
                    let id = world.ids[&owner] + next(2);
                    world.task(addr, Some(id), Some(owner));
                }
                // A blocking cell, queued somewhere or only referenced.
                4 => {
                    world.blocking(addr);
                    if next(2) == 0 {
                        let owner = owners[next(owners.len() as u64) as usize];
                        if matches!(owner, OwnerKey::Runtime { .. }) {
                            world.pool.entry(owner).or_default().push(addr);
                        }
                    }
                }
                // An unclassifiable header.
                _ => {
                    world.task(addr, Some(next(20)), None);
                }
            }
            if next(5) == 0 {
                world.complete(addr);
            }
        }
        for &from in &addrs {
            let n = next(3);
            for _ in 0..n {
                let to = addrs[next(tasks) as usize];
                world.refs.entry(from).or_default().push(to);
            }
        }
        for &owner in &owners {
            if !matches!(owner, OwnerKey::Runtime { .. }) {
                continue;
            }
            for _ in 0..next(3) {
                let t = addrs[next(tasks) as usize];
                world.timers.entry(owner).or_default().push(t);
            }
            for _ in 0..next(2) {
                let t = addrs[next(tasks) as usize];
                world.io.entry(owner).or_default().push(t);
            }
        }
        // Roots: the first runtime always; another owner as a second
        // root sometimes; one non-root runtime excluded sometimes.
        let mut roots = Roots {
            runtimes: vec![owners[0]],
            sets: Vec::new(),
        };
        if owners.len() > 1 && next(3) == 0 {
            match owners[1] {
                OwnerKey::Runtime { .. } => roots.runtimes.push(owners[1]),
                OwnerKey::LocalSet { .. } => roots.sets.push(owners[1]),
            }
        }
        if next(3) == 0 {
            for &owner in &owners[1..] {
                if let OwnerKey::Runtime { handle, .. } = owner
                    && !roots.runtimes.contains(&owner)
                {
                    world.excluded.push(handle);
                    break;
                }
            }
        }
        (world, roots)
    }

    /// The queued sweep and the exhaustive rescan reach the same fixed
    /// point on every generated graph: the same records with the same
    /// kind, owner, residency and evidence counts, the same rows, the
    /// same admitted owners, the same diagnostics.
    #[test]
    fn test_the_queue_matches_an_exhaustive_rescan() {
        let mut nontrivial = 0;
        for seed in 0..300 {
            let (world, roots) = random_world(seed);
            let mut a = world.clone();
            let (list_a, outcome) = queued(&mut a, &roots, ScanLimits::default());
            assert!(!outcome.capped, "seed {seed}: {:?}", outcome.remaining);
            assert!(outcome.remaining.is_empty(), "seed {seed}");
            let mut b = world.clone();
            let mut list_b = b.enumerated(&roots);
            exhaustive(&mut b, &mut list_b, &roots);
            assert_eq!(
                fixpoint(&a, &list_a),
                fixpoint(&b, &list_b),
                "seed {seed}: {world:#?}"
            );
            // The queue did each kind of work as often as the rescan:
            // once per owner, once per scannable record.
            assert_eq!(a.calls, b.calls, "seed {seed}");
            if a.admitted.len() > roots.runtimes.len() + roots.sets.len() {
                nontrivial += 1;
            }
        }
        assert!(nontrivial > 30, "{nontrivial} graphs admitted an owner");
    }

    /// The order of finds cannot change the fixed point: the same
    /// graph with every reference list and registry reversed reaches
    /// the same records and rows.
    #[test]
    fn test_arrival_order_does_not_change_the_fixed_point() {
        for seed in 0..100 {
            let (world, roots) = random_world(seed);
            let mut reversed = world.clone();
            for targets in reversed.refs.values_mut() {
                targets.reverse();
            }
            for targets in reversed.timers.values_mut() {
                targets.reverse();
            }
            for targets in reversed.io.values_mut() {
                targets.reverse();
            }
            let mut a = world.clone();
            let (list_a, _) = queued(&mut a, &roots, ScanLimits::default());
            let (list_b, _) = queued(&mut reversed, &roots, ScanLimits::default());
            assert_eq!(
                fixpoint(&a, &list_a),
                fixpoint(&reversed, &list_b),
                "seed {seed}"
            );
        }
    }

    /// The item cap ends the sweep with the frontier reported by kind
    /// rather than trimmed away: a chain of referencing tasks capped
    /// mid-way leaves scans and validations outstanding, and the
    /// records found so far keep their evidence.
    #[test]
    fn test_the_cap_reports_the_remaining_frontier() {
        let mut world = World::default();
        let root = rt(0x1000);
        world.owner(root, 10, &[0x10_000]);
        world.task(0x10_000, Some(10), Some(root));
        // A chain: each task's storage names the next, none listed.
        for i in 1..6u64 {
            let addr = 0x10_000 + 0x100 * i;
            world.task(addr, Some(99), None);
            world.refs(addr - 0x100, &[addr]);
        }
        let roots = Roots {
            runtimes: vec![root],
            sets: Vec::new(),
        };
        let uncapped = queued(&mut world.clone(), &roots, ScanLimits::default());
        assert_eq!(uncapped.0.tasks.len(), 6);
        assert!(!uncapped.1.capped);
        assert_eq!(uncapped.1.processed.scans, 6);
        assert_eq!(uncapped.1.processed.validations, 5);
        assert_eq!(
            (
                uncapped.1.processed.timers,
                uncapped.1.processed.io,
                uncapped.1.processed.queues
            ),
            (1, 1, 1)
        );

        let limits = ScanLimits {
            max_work_items: 3,
            ..ScanLimits::default()
        };
        let (list, outcome) = queued(&mut world, &roots, limits);
        assert!(outcome.capped);
        assert_eq!(outcome.processed.total(), 3);
        // Scan, validate, scan: the third task is found and unscanned,
        // and the root's registries are still queued.
        assert_eq!(outcome.processed.scans, 2);
        assert_eq!(outcome.processed.validations, 1);
        assert_eq!(outcome.remaining.validations, 1);
        assert_eq!(
            (
                outcome.remaining.timers,
                outcome.remaining.io,
                outcome.remaining.queues
            ),
            (1, 1, 1)
        );
        assert_eq!(
            outcome.remaining.to_string(),
            "1 find to validate, 1 timer wheel to harvest, 1 io driver to harvest, \
             1 blocking queue to harvest"
        );
        assert_eq!(list.tasks.len(), 2, "{:#?}", list.tasks);
        assert!(list.errors.is_empty(), "{:?}", list.errors);
    }

    #[test]
    fn test_the_tally_spells_itself() {
        assert_eq!(WorkTally::default().to_string(), "nothing");
        let tally = WorkTally {
            runtimes: 2,
            sets: 1,
            scans: 3,
            timers: 0,
            io: 2,
            queues: 1,
            validations: 0,
        };
        assert_eq!(tally.total(), 9);
        assert_eq!(
            tally.to_string(),
            "2 runtimes to enumerate, 1 local set to enumerate, 3 tasks to scan, \
             2 io drivers to harvest, 1 blocking queue to harvest"
        );
    }

    /// Scope over the routes: a set reached only through a task an
    /// excluded runtime owns is not admitted, its tasks are no rows,
    /// and the excluded task's own storage is never scanned; the same
    /// set reached independently — through an included task, or from
    /// the TLS root — is, whichever route runs first.
    fn scoped_world() -> (World, OwnerKey, OwnerKey, OwnerKey) {
        let root = rt(0x1000);
        let hidden = rt(0x2000);
        let local = set(0x3000);
        let mut world = World::default();
        world
            .owner(root, 10, &[0x10_000])
            .owner(hidden, 20, &[0x20_000])
            .owner(local, 30, &[0x30_000, 0x30_100]);
        // The root's task holds a handle on the hidden runtime's task,
        // whose storage holds a handle on a set member.
        world
            .task(0x10_000, Some(10), Some(root))
            .task(0x20_000, Some(20), Some(hidden))
            .task(0x30_000, Some(30), Some(local))
            .task(0x30_100, Some(30), Some(local))
            .refs(0x10_000, &[0x20_000])
            .refs(0x20_000, &[0x30_000]);
        (world, root, hidden, local)
    }

    #[test]
    fn test_a_set_behind_an_excluded_runtime_is_out_of_scope() {
        let (mut world, root, hidden, local) = scoped_world();
        let roots = Roots {
            runtimes: vec![root],
            sets: Vec::new(),
        };
        // Nothing excluded: the hidden runtime is admitted through the
        // handle, its task is scanned, and the set behind it is found.
        let (list, outcome) = queued(&mut world.clone(), &roots, ScanLimits::default());
        assert_eq!(world.admitted, Vec::<OwnerKey>::new());
        assert_eq!(outcome.reached, [root, hidden, local]);
        assert_eq!(list.tasks.len(), 4, "{:#?}", list.tasks);
        assert_eq!(outcome.unscanned_excluded, 0);

        // The hidden runtime excluded: its task is decoded and claimed
        // — the record says whose it is — but not scanned, so the set
        // is never reached and its members are nobody's rows.
        let OwnerKey::Runtime { handle, .. } = hidden else {
            unreachable!()
        };
        world.excluded.push(handle);
        let (list, outcome) = queued(&mut world, &roots, ScanLimits::default());
        assert_eq!(world.admitted, [root]);
        assert_eq!(outcome.reached, [root]);
        assert_eq!(outcome.unscanned_excluded, 1);
        let rows: Vec<u64> = list.tasks.iter().map(|t| t.addr.0).collect();
        assert_eq!(rows, [0x10_000]);
        let record = list
            .record(0x20_000)
            .expect("the excluded task keeps its record");
        assert_eq!(record.owner(), OwnerResolution::Known(hidden));
        assert!(record.in_scope(), "reached through the root's handle");
        assert!(list.record(0x30_000).is_none(), "never found");
        assert!(list.errors.is_empty(), "{:?}", list.errors);
    }

    #[test]
    fn test_a_set_also_reached_from_the_selection_stays_in_scope() {
        for order in [0, 1] {
            let (mut world, root, hidden, local) = scoped_world();
            let OwnerKey::Runtime { handle, .. } = hidden else {
                unreachable!()
            };
            world.excluded.push(handle);
            // The root's task also holds a handle on the other member:
            // before or after the handle into the excluded runtime.
            let refs = world.refs.get_mut(&0x10_000).unwrap();
            if order == 0 {
                refs.insert(0, 0x30_100);
            } else {
                refs.push(0x30_100);
            }
            let roots = Roots {
                runtimes: vec![root],
                sets: Vec::new(),
            };
            let (list, outcome) = queued(&mut world, &roots, ScanLimits::default());
            assert_eq!(outcome.reached, [root, local], "order {order}");
            let rows: BTreeSet<u64> = list.tasks.iter().map(|t| t.addr.0).collect();
            assert_eq!(
                rows,
                BTreeSet::from([0x10_000, 0x30_000, 0x30_100]),
                "order {order}"
            );
            assert!(
                list.record(0x20_000)
                    .is_some_and(|r| !r.task().owner.known().is_none())
            );
        }
    }

    #[test]
    fn test_a_tls_root_set_is_in_scope_whatever_else_reaches_it() {
        let (mut world, root, hidden, local) = scoped_world();
        let OwnerKey::Runtime { handle, .. } = hidden else {
            unreachable!()
        };
        world.excluded.push(handle);
        let roots = Roots {
            runtimes: vec![root],
            sets: vec![local],
        };
        let (list, outcome) = queued(&mut world, &roots, ScanLimits::default());
        assert_eq!(outcome.reached, [root, local]);
        assert_eq!(outcome.processed.sets, 1);
        let rows: BTreeSet<u64> = list.tasks.iter().map(|t| t.addr.0).collect();
        assert_eq!(rows, BTreeSet::from([0x10_000, 0x30_000, 0x30_100]));
    }

    /// An owner learned excluded after its task's storage was scanned
    /// — which no live route produces today, since a cell's claim is
    /// bootstrapped at the first decode, but which the scope is
    /// recomputed for all the same — takes the descendants found
    /// through that storage out of the projection and keeps their
    /// records, in either order of the routes.
    #[test]
    fn test_late_exclusion_removes_descendants_and_keeps_evidence() {
        let root = rt(0x1000);
        let hidden = rt(0x2000);
        let local = set(0x3000);
        let OwnerKey::Runtime { handle, .. } = hidden else {
            unreachable!()
        };
        let excluded = [handle];
        for order in [0, 1] {
            let mut list = TaskList::default();
            let mut store = TaskStore::new();
            let fake = |owner_id| Fake {
                state: 0,
                owner_id: Some(owner_id),
                kind: Some(TaskKind::Async),
                cell: None,
            };
            let listed = |owner: OwnerKey, head: u64, addr: u64, owner_id: u64| {
                let header = fake(owner_id).header(addr);
                let (claim, _) = list_claim(owner, head, Some(owner_id), &header);
                (
                    header,
                    Observation {
                        source: TaskSource::OwnedList { owner, head },
                        kind: Some(TaskKind::Async),
                        claim,
                    },
                )
            };
            let (h, o) = listed(root, 0x10_000, 0x10_000, 10);
            let a = store.observe(h, o).record;
            // The hidden runtime's task, found through the root task's
            // handle and scanned before (order 0) or after (order 1)
            // its cell claim arrived.
            let b_header = fake(20).header(0x20_000);
            let b_ref = Observation {
                source: TaskSource::Reference(TaskReference {
                    target: TaskAddr(0x20_000),
                    source: ReferenceSource::JoinHandle,
                    source_value: Some(key(0x10_010)),
                    root_task: Some(TaskAddr(0x10_000)),
                    path: Vec::new(),
                }),
                kind: Some(TaskKind::Async),
                claim: None,
            };
            let b_claim = OwnerClaim {
                owner: hidden,
                evidence: OwnerEvidence::CellScheduler {
                    scheduler: key(0x2000),
                    owner_id: 20,
                },
            };
            let b = store.observe(b_header, b_ref).record;
            if order == 1 {
                store.claim(b, b_claim.clone());
            }
            let (h, o) = listed(local, 0x30_000, 0x30_000, 30);
            let c = store.observe(h, o).record;
            let c_claim = OwnerClaim {
                owner: local,
                evidence: OwnerEvidence::CellScheduler {
                    scheduler: key(0x3000),
                    owner_id: 30,
                },
            };
            store.claim(c, c_claim);
            if order == 0 {
                store.claim(b, b_claim);
            }
            list.records = store;
            let roots = Roots {
                runtimes: vec![root],
                sets: Vec::new(),
            };
            let mut links = vec![(Origin::Task(a), b), (Origin::Task(b), c)];
            if order == 1 {
                links.reverse();
            }
            let reached = apply_scope(&mut list, &roots, &links, &excluded);
            assert_eq!(reached, [root], "order {order}");
            list.reproject(&excluded);
            let rows: Vec<u64> = list.tasks.iter().map(|t| t.addr.0).collect();
            assert_eq!(rows, [0x10_000], "order {order}");
            let dropped = list.record(0x30_000).unwrap();
            assert!(!dropped.in_scope(), "order {order}");
            assert_eq!(dropped.owner(), OwnerResolution::Known(local));
            assert!(dropped.resident(), "the evidence is kept");
            assert!(list.record(0x20_000).unwrap().in_scope());

            // With nothing excluded the same evidence reaches everything.
            let reached = apply_scope(&mut list, &roots, &links, &[]);
            assert_eq!(reached, [root, hidden, local], "order {order}");
            list.reproject(&[]);
            assert_eq!(list.tasks.len(), 3, "order {order}");
        }
    }

    /// A conflict naming an excluded owner is a row and is scanned:
    /// the exclusion is proven ownership, and a conflict proves
    /// nothing.
    #[test]
    fn test_a_conflict_naming_an_excluded_owner_is_still_scanned() {
        let root = rt(0x1000);
        let hidden = rt(0x2000);
        let OwnerKey::Runtime { handle, .. } = hidden else {
            unreachable!()
        };
        let mut world = World::default();
        world
            .owner(root, 10, &[0x10_000, 0x10_100])
            .owner(hidden, 20, &[]);
        // Listed by the root — the list's id is the task's — but the
        // cell names the hidden runtime, whose id is *also* recorded
        // as the task's by a queue: two validated owners.
        world
            .task(0x10_000, Some(10), Some(root))
            .task(0x10_100, Some(10), Some(root))
            .blocking(0x10_200)
            .refs(0x10_100, &[0x10_200]);
        world.pool.insert(hidden, vec![0x10_100]);
        world.excluded.push(handle);
        // The root's own pool harvest cannot reach the hidden pool; a
        // find of the hidden queue is filed by hand to make the conflict.
        let roots = Roots {
            runtimes: vec![root],
            sets: Vec::new(),
        };
        let mut list = world.enumerated(&roots);
        world.validate(
            Candidate::Queued {
                addr: 0x10_100,
                owner: hidden,
                queue: key(0x9000),
                entry: 0x10_200,
            },
            &mut list,
        );
        let record = list.record(0x10_100).unwrap();
        assert!(
            matches!(record.owner(), OwnerResolution::Conflict(_)),
            "{record:#?}"
        );
        let excluded = world.excluded.clone();
        let outcome = sweep(
            &mut world,
            &mut list,
            &roots,
            &excluded,
            ScanLimits::default(),
        );
        list.reproject(&excluded);
        assert_eq!(outcome.unscanned_excluded, 0);
        let rows: BTreeSet<u64> = list.tasks.iter().map(|t| t.addr.0).collect();
        assert_eq!(
            rows,
            BTreeSet::from([0x10_000, 0x10_100, 0x10_200]),
            "{:#?}",
            list.tasks
        );
    }

    /// Owners schedule their work once however many finds admit them,
    /// and an excluded owner schedules none.
    #[test]
    fn test_each_owner_schedules_its_work_once() {
        let root = rt(0x1000);
        let other = rt(0x2000);
        let mut world = World::default();
        world
            .owner(root, 10, &[0x10_000, 0x10_100])
            .owner(other, 20, &[0x20_000, 0x20_100]);
        world
            .task(0x10_000, Some(10), Some(root))
            .task(0x10_100, Some(10), Some(root))
            .task(0x20_000, Some(20), Some(other))
            .task(0x20_100, Some(20), Some(other))
            // Both root tasks name both of the other's tasks.
            .refs(0x10_000, &[0x20_000, 0x20_100])
            .refs(0x10_100, &[0x20_100, 0x20_000]);
        world.timers.insert(root, vec![0x20_000]);
        let roots = Roots {
            runtimes: vec![root],
            sets: Vec::new(),
        };
        let (list, outcome) = queued(&mut world, &roots, ScanLimits::default());
        assert_eq!(outcome.processed.runtimes, 1, "{:?}", outcome.processed);
        assert_eq!(
            (
                outcome.processed.timers,
                outcome.processed.io,
                outcome.processed.queues
            ),
            (2, 2, 2)
        );
        assert_eq!(outcome.processed.scans, 4);
        assert_eq!(outcome.processed.validations, 5);
        assert_eq!(list.tasks.len(), 4);
        let record = list.record(0x20_000).unwrap();
        // Three sources: the list, two handles, a timer — the timer's
        // and the handles' order is the queue's, list first since the
        // owner was enumerated before the second handle was validated.
        assert_eq!(record.sources.len(), 4, "{:#?}", record.sources);
        assert!(matches!(record.sources[0], TaskSource::Reference(_)));
        assert!(matches!(record.sources[1], TaskSource::OwnedList { .. }));
    }
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Task evidence reconciliation: one record per task `Header` for an
//! analysis run, fed by every discovery route with what it observed —
//! a list walked, a handle scanned, a queue read — rather than each
//! route deciding a finished row at its first encounter.
//!
//! The routes establish different things. Membership in an owned list
//! or a blocking queue makes a task a resident row and, once the
//! list's id and the header's `owner_id` agree, names its owner. A
//! reference — a `JoinHandle`, a registered waker — identifies the
//! task and nothing more: it manufactures no kind and no owner, and a
//! task it names that no list claims has an owner nobody established,
//! which the record says outright rather than filing it under whatever
//! runtime came first. Where two routes disagree the disagreement is a
//! diagnostic the record keeps, never a later reading overwriting an
//! earlier one: the target is frozen, so there is no later.
//!
//! [`TaskStore::observe`] is the one entry point; [`TaskStore::project`]
//! turns the records into the rows a listing shows, and [`OwnerIndex`]
//! maps the stable owner keys those rows carry to the group numbers the
//! listings print.

use super::model::{DecodedTaskHeader, FutureInfo, LocalSetRef, RuntimeFlavor, RuntimeRef, Task};
use super::observe::{TaskReference, ValueKey, WalkIssue};
use super::{Lifecycle, TaskAddr};

use foldhash::HashMap;

use std::fmt;

/// A record's position in its [`TaskStore`]: a handle for the run's
/// duration, never a row index — rows are rebuilt and re-sorted by
/// [`TaskStore::project`], and relations and census attribution index
/// those.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TaskRecordId(pub usize);

/// The stable identity of something that owns tasks, as discovery
/// keys it before any display numbering exists: a runtime by the
/// validated referent of its handle — the `Handle` inside the `Arc`,
/// which every slot pointing at that runtime shares, never the address
/// of one such slot — and a `LocalSet` by its `Shared`. The flavor is
/// part of a runtime's key: two incompatible views of one address are
/// a conflict, not two owners.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum OwnerKey {
    Runtime { flavor: RuntimeFlavor, handle: u64 },
    LocalSet { shared: u64 },
}

impl fmt::Display for OwnerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime { flavor, handle } => {
                write!(f, "the {flavor} runtime at {handle:#x}")
            }
            Self::LocalSet { shared } => write!(f, "the local set at {shared:#x}"),
        }
    }
}

/// What kind of task a header heads, from the evidence that says so:
/// an owned list makes a task `Async`, a blocking-pool queue makes it
/// `Blocking`, and a cell whose recorded scheduler type the tokio
/// info classified says either. `Unknown` is no evidence at all — a
/// header a handle named whose future the symbol join could not
/// resolve — and `Conflict` is evidence that disagreed, which no later
/// agreement clears.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TaskKind {
    Unknown,
    Async,
    Blocking,
    Conflict,
}

/// Who owns a task, reconciled from every validated claim: none is
/// `Unknown`, one distinct key is `Known`, more than one is
/// `Conflict`. Later evidence can fill an unknown; it cannot erase a
/// conflict.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OwnerResolution {
    Unknown,
    Known(OwnerKey),
    Conflict(Vec<OwnerKey>),
}

impl OwnerResolution {
    /// The one owner, where one is established.
    pub fn known(&self) -> Option<OwnerKey> {
        match self {
            Self::Known(key) => Some(*key),
            Self::Unknown | Self::Conflict(_) => None,
        }
    }
}

/// One validated claim that an owner owns a task, with what validated
/// it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OwnerClaim {
    pub owner: OwnerKey,
    pub evidence: OwnerEvidence,
}

/// How an owner claim was validated. Every kind carries the list or
/// queue identity it was held to; a bare handle to a task is not
/// among them, because a handle's holder owns nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum OwnerEvidence {
    /// The task is linked in the owner's owned list, and the list's
    /// id is the task's `Header.owner_id`.
    OwnedList { head: u64, owner_id: u64 },
    /// The task's cell records the owner as its scheduler, and the
    /// owner's list id is the task's `Header.owner_id`.
    CellScheduler { scheduler: ValueKey, owner_id: u64 },
    /// The cell is an entry in the owner's blocking-pool queue.
    BlockingQueue { queue: ValueKey, entry: u64 },
}

/// Where a route met the task.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TaskSource {
    /// Linked in an owner's owned list, from `head`.
    OwnedList { owner: OwnerKey, head: u64 },
    /// Named by a reference in some value's storage, or by a waker
    /// parked in a runtime's registry.
    Reference(TaskReference),
    /// An entry of an owner's blocking-pool queue.
    BlockingQueue {
        owner: OwnerKey,
        queue: ValueKey,
        entry: u64,
    },
}

impl TaskSource {
    /// The kind of task the source itself establishes: a list carries
    /// only scheduler-owned tasks, a pool queue only blocking cells,
    /// and a reference says nothing.
    fn kind(&self) -> Option<TaskKind> {
        match self {
            Self::OwnedList { .. } => Some(TaskKind::Async),
            Self::BlockingQueue { .. } => Some(TaskKind::Blocking),
            Self::Reference(_) => None,
        }
    }

    /// Whether this source makes the task a listing row on its own:
    /// membership in a list or a queue does, a reference does not.
    fn lists(&self) -> bool {
        !matches!(self, Self::Reference(_))
    }
}

/// One route's report about one task: where it met it, what kind the
/// route's own evidence — beyond the source's — makes it, and the
/// owner claim it validated, if any.
#[derive(Clone, Debug)]
pub struct Observation {
    pub source: TaskSource,
    /// Kind evidence from outside the source: the class the tokio
    /// info recorded for the cell's scheduler type.
    pub kind: Option<TaskKind>,
    pub claim: Option<OwnerClaim>,
}

/// A disagreement discovery met and kept.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DiscoveryIssue {
    /// Two decodes of the header disagreed on its identity words.
    HeaderConflict {
        addr: TaskAddr,
        detail: String,
    },
    /// The retained kind evidence names both kinds.
    KindConflict {
        addr: TaskAddr,
    },
    /// The validated claims name more than one owner.
    OwnerConflict {
        addr: TaskAddr,
        owners: Vec<OwnerKey>,
    },
    /// A list or scheduler that led to the task does not claim it:
    /// its id is not the task's `Header.owner_id`.
    OwnerIdMismatch {
        addr: TaskAddr,
        owner: OwnerKey,
        expected: u64,
        found: Option<u64>,
    },
    Walk(WalkIssue),
}

impl fmt::Display for DiscoveryIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderConflict { addr, detail } => {
                write!(f, "the task at {addr:?} was decoded two ways: {detail}")
            }
            Self::KindConflict { addr } => write!(
                f,
                "the task at {addr:?} is claimed as both a scheduler-owned task and a \
                 blocking cell; its kind is left unknown"
            ),
            Self::OwnerConflict { addr, owners } => {
                let owners: Vec<String> = owners.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "the task at {addr:?} is claimed by more than one owner: {}",
                    owners.join("; ")
                )
            }
            Self::OwnerIdMismatch {
                addr,
                owner,
                expected,
                found,
            } => write!(
                f,
                "{owner} led to the task at {addr:?} but its owned-list id {expected} does not \
                 claim it (owner_id {})",
                found.map_or("<none>".to_owned(), |id| id.to_string())
            ),
            Self::Walk(issue) => write!(f, "{issue:?}"),
        }
    }
}

/// How many explanatory references a record keeps per source kind
/// before counting the rest: a task every other task holds a handle
/// to is a fact worth one line, not ten thousand.
const RETAINED_REFERENCES: usize = 8;

/// Everything discovery established about one task header.
#[derive(Debug)]
pub struct TaskRecord {
    /// The first decode of the header. A later decode that disagreed
    /// is a [`DiscoveryIssue::HeaderConflict`], which disables typed
    /// interpretation of the task ([`TaskRecord::task`] reports the
    /// future unknown) rather than letting this copy act as the truth.
    pub header: DecodedTaskHeader,
    /// Every distinct source that met the task, in arrival order, up
    /// to [`RETAINED_REFERENCES`] references; the rest are counted.
    pub sources: Vec<TaskSource>,
    pub omitted_sources: usize,
    /// The distinct kinds the evidence asserted.
    kinds: Vec<TaskKind>,
    /// Every distinct validated claim.
    pub owner_claims: Vec<OwnerClaim>,
    pub issues: Vec<DiscoveryIssue>,
    /// Whether the reference scan has walked this task's storage.
    pub(crate) scanned: bool,
}

impl TaskRecord {
    fn new(header: DecodedTaskHeader) -> Self {
        TaskRecord {
            header,
            sources: Vec::new(),
            omitted_sources: 0,
            kinds: Vec::new(),
            owner_claims: Vec::new(),
            issues: Vec::new(),
            scanned: false,
        }
    }

    pub fn addr(&self) -> TaskAddr {
        self.header.addr
    }

    /// The kind, from all retained kind evidence: none is unknown,
    /// agreement selects, disagreement is a conflict that stays.
    pub fn kind(&self) -> TaskKind {
        match self.kinds.as_slice() {
            [] => TaskKind::Unknown,
            [kind] => *kind,
            _ => TaskKind::Conflict,
        }
    }

    /// The owner, from the distinct validated owner keys — a conflict
    /// names them in key order, whatever order the claims arrived in.
    pub fn owner(&self) -> OwnerResolution {
        let mut owners: Vec<OwnerKey> = Vec::new();
        for claim in &self.owner_claims {
            if !owners.contains(&claim.owner) {
                owners.push(claim.owner);
            }
        }
        owners.sort_unstable();
        match owners.as_slice() {
            [] => OwnerResolution::Unknown,
            [owner] => OwnerResolution::Known(*owner),
            _ => OwnerResolution::Conflict(owners),
        }
    }

    /// Whether the record is a listing row: a task some list or queue
    /// carries, or one a reference named that has not completed. A
    /// complete task a handle keeps alive is retained for the join it
    /// explains and is nobody's row.
    pub fn resident(&self) -> bool {
        if self.sources.iter().any(TaskSource::lists) {
            return true;
        }
        !self.sources.is_empty() && self.header.state.lifecycle() != Lifecycle::Complete
    }

    /// Whether two decodes of the header disagreed.
    pub fn header_conflict(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| matches!(issue, DiscoveryIssue::HeaderConflict { .. }))
    }

    /// The record as a listing row.
    pub fn task(&self) -> Task {
        let header = &self.header;
        Task {
            addr: header.addr,
            state: header.state,
            owner_id: header.owner_id,
            task_id: header.task_id,
            spawn_location: header.spawn_location.clone(),
            // A header decoded two ways names no type anything may
            // read the cell by.
            future: match self.header_conflict() {
                true => FutureInfo::Unknown { poll_symbol: None },
                false => header.future.clone(),
            },
            kind: self.kind(),
            owner: self.owner(),
        }
    }

    fn add_kind(&mut self, kind: TaskKind) {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
    }

    fn add_source(&mut self, source: TaskSource) {
        if self.sources.contains(&source) {
            return;
        }
        if let TaskSource::Reference(_) = &source {
            let retained = self
                .sources
                .iter()
                .filter(|s| matches!(s, TaskSource::Reference(_)))
                .count();
            if retained >= RETAINED_REFERENCES {
                self.omitted_sources += 1;
                return;
            }
        }
        self.sources.push(source);
    }

    fn add_claim(&mut self, claim: OwnerClaim) {
        if !self.owner_claims.contains(&claim) {
            self.owner_claims.push(claim);
        }
    }

    fn add_issue(&mut self, issue: DiscoveryIssue) {
        if !self.issues.contains(&issue) {
            self.issues.push(issue);
        }
    }

    /// Recompute the standing conflict diagnostics from the retained
    /// evidence. They are derived, so recomputing is idempotent; they
    /// are kept on the record so a reader sees them beside the
    /// evidence that raised them.
    fn reconcile(&mut self) {
        let addr = self.addr();
        if self.kind() == TaskKind::Conflict {
            self.add_issue(DiscoveryIssue::KindConflict { addr });
        }
        if let OwnerResolution::Conflict(owners) = self.owner() {
            // One standing conflict per record, over the current set
            // of owners: an earlier, shorter one is superseded.
            self.issues
                .retain(|issue| !matches!(issue, DiscoveryIssue::OwnerConflict { .. }));
            self.issues
                .push(DiscoveryIssue::OwnerConflict { addr, owners });
        }
    }
}

/// What one observation changed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MergeEffect {
    pub record: TaskRecordId,
    /// Whether the header was new to the store.
    pub inserted: bool,
    pub owner_changed: bool,
    pub kind_changed: bool,
}

/// The records of one analysis run, keyed by header address.
#[derive(Debug, Default)]
pub struct TaskStore {
    by_addr: HashMap<u64, TaskRecordId>,
    records: Vec<TaskRecord>,
}

impl TaskStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record for a header address, if one was decoded.
    pub fn lookup(&self, addr: u64) -> Option<TaskRecordId> {
        self.by_addr.get(&addr).copied()
    }

    pub fn record(&self, id: TaskRecordId) -> &TaskRecord {
        &self.records[id.0]
    }

    pub fn record_at(&self, addr: u64) -> Option<&TaskRecord> {
        self.lookup(addr).map(|id| self.record(id))
    }

    /// Every record, in insertion order.
    pub fn records(&self) -> impl Iterator<Item = (TaskRecordId, &TaskRecord)> {
        self.records
            .iter()
            .enumerate()
            .map(|(i, r)| (TaskRecordId(i), r))
    }

    /// File a decoded header with what a route observed about it.
    ///
    /// A new address inserts the identity. An address already decoded
    /// has its identity words compared first — the target is frozen,
    /// so a header that reads two ways is a diagnostic, and the first
    /// decode is kept only as the copy the diagnostic is filed on —
    /// and the observation merged the same way [`TaskStore::observe_at`]
    /// merges it.
    pub fn observe(&mut self, header: DecodedTaskHeader, observation: Observation) -> MergeEffect {
        let addr = header.addr;
        match self.lookup(addr.0) {
            Some(id) => {
                if let Some(detail) = identity_conflict(&self.records[id.0].header, &header) {
                    self.records[id.0].add_issue(DiscoveryIssue::HeaderConflict { addr, detail });
                }
                self.observe_at(id, observation)
            }
            None => {
                let id = TaskRecordId(self.records.len());
                self.by_addr.insert(addr.0, id);
                self.records.push(TaskRecord::new(header));
                let mut effect = self.observe_at(id, observation);
                effect.inserted = true;
                effect
            }
        }
    }

    /// Merge an observation into a record already decoded: the source
    /// and any kind evidence and claim it carries, without decoding
    /// the header again.
    pub fn observe_at(&mut self, id: TaskRecordId, observation: Observation) -> MergeEffect {
        let record = &mut self.records[id.0];
        let (kind_before, owner_before) = (record.kind(), record.owner());
        if let Some(kind) = observation.source.kind() {
            record.add_kind(kind);
        }
        if let Some(kind) = observation.kind {
            record.add_kind(kind);
        }
        record.add_source(observation.source);
        if let Some(claim) = observation.claim {
            record.add_claim(claim);
        }
        record.reconcile();
        MergeEffect {
            record: id,
            inserted: false,
            owner_changed: record.owner() != owner_before,
            kind_changed: record.kind() != kind_before,
        }
    }

    /// Add a validated owner claim to a record already decoded — the
    /// claim a fresh reference's cell scheduler makes, which is known
    /// only after the reference itself was filed.
    pub fn claim(&mut self, id: TaskRecordId, claim: OwnerClaim) -> MergeEffect {
        let record = &mut self.records[id.0];
        let owner_before = record.owner();
        record.add_claim(claim);
        record.reconcile();
        MergeEffect {
            record: id,
            inserted: false,
            owner_changed: record.owner() != owner_before,
            kind_changed: false,
        }
    }

    /// File a diagnostic on a record.
    pub fn issue(&mut self, id: TaskRecordId, issue: DiscoveryIssue) {
        self.records[id.0].add_issue(issue);
    }

    pub(crate) fn mark_scanned(&mut self, id: TaskRecordId) {
        self.records[id.0].scanned = true;
    }

    /// Every diagnostic on every record, in record order.
    pub fn issues(&self) -> impl Iterator<Item = &DiscoveryIssue> {
        self.records.iter().flat_map(|r| r.issues.iter())
    }

    /// The listing rows: every resident record not owned by a runtime
    /// in `excluded` (by handle address), sorted by task id, the
    /// idless last by address. A record whose owner is in conflict
    /// stays a row whichever owners the conflict names — an excluded
    /// owner in a conflict is a diagnostic, not a selection.
    pub fn project(&self, excluded: &[u64]) -> Vec<Task> {
        let mut tasks: Vec<Task> = self
            .records
            .iter()
            .filter(|record| record.resident())
            .map(TaskRecord::task)
            .filter(|task| match task.owner {
                OwnerResolution::Known(OwnerKey::Runtime { handle, .. }) => {
                    !excluded.contains(&handle)
                }
                _ => true,
            })
            .collect();
        tasks.sort_by_key(|t| (t.task_id.is_none(), t.task_id, t.addr.0));
        tasks
    }
}

/// How two decodes of one header disagree, if they do.
fn identity_conflict(first: &DecodedTaskHeader, second: &DecodedTaskHeader) -> Option<String> {
    let mut diffs = Vec::new();
    if first.vtable_addr != second.vtable_addr {
        diffs.push(format!(
            "vtable {:#x} vs {:#x}",
            first.vtable_addr, second.vtable_addr
        ));
    }
    if first.trailer_offset != second.trailer_offset {
        diffs.push(format!(
            "trailer offset {:#x} vs {:#x}",
            first.trailer_offset, second.trailer_offset
        ));
    }
    if first.state != second.state {
        diffs.push(format!(
            "state word {:#x} vs {:#x}",
            first.state.0, second.state.0
        ));
    }
    if first.task_id != second.task_id {
        diffs.push(format!(
            "task id {:?} vs {:?}",
            first.task_id, second.task_id
        ));
    }
    if first.owner_id != second.owner_id {
        diffs.push(format!(
            "owner id {:?} vs {:?}",
            first.owner_id, second.owner_id
        ));
    }
    (!diffs.is_empty()).then(|| diffs.join(", "))
}

/// The map from stable owner keys to the group numbers the listings
/// print: the retained runtimes in their established order, then the
/// local sets in theirs. Built once, after discovery completes, so no
/// number is handed out while discovery is still free to find more.
#[derive(Debug, Default)]
pub struct OwnerIndex {
    keys: Vec<OwnerKey>,
    by_key: HashMap<OwnerKey, usize>,
    runtimes: usize,
}

impl OwnerIndex {
    pub fn new(runtimes: &[RuntimeRef<'_>], sets: &[LocalSetRef<'_>]) -> Self {
        let keys = runtimes
            .iter()
            .map(RuntimeRef::owner_key)
            .chain(sets.iter().map(LocalSetRef::owner_key))
            .collect();
        Self::from_keys(keys, runtimes.len())
    }

    /// An index over explicit keys, the first `runtimes` of which are
    /// runtimes' — for a caller laying out a population no target
    /// holds.
    pub fn from_keys(keys: Vec<OwnerKey>, runtimes: usize) -> Self {
        let by_key = keys.iter().enumerate().map(|(i, k)| (*k, i)).collect();
        OwnerIndex {
            keys,
            by_key,
            runtimes,
        }
    }

    /// The group of a task's owner, where one is established and
    /// indexed. Unknown and conflicting owners have no group; neither
    /// does an owner the session excluded.
    pub fn group_of(&self, task: &Task) -> Option<usize> {
        self.group_of_key(task.owner.known()?)
    }

    pub fn group_of_key(&self, key: OwnerKey) -> Option<usize> {
        self.by_key.get(&key).copied()
    }

    pub fn key(&self, group: usize) -> Option<OwnerKey> {
        self.keys.get(group).copied()
    }

    pub fn keys(&self) -> &[OwnerKey] {
        &self.keys
    }

    /// How many groups there are, runtimes and sets together.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many of the groups are runtimes: groups `0..runtimes()`.
    pub fn runtimes(&self) -> usize {
        self.runtimes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokio::TaskState;
    use crate::tokio::model::FutureInfo;
    use crate::tokio::observe::ReferenceSource;

    use hansei_bundle::BundleTypeId;

    const REF_ONE: u64 = 1 << 6;
    const COMPLETE: u64 = 0b0010;

    fn header(addr: u64, state: u64, owner_id: Option<u64>) -> DecodedTaskHeader {
        DecodedTaskHeader {
            addr: TaskAddr(addr),
            state: TaskState(REF_ONE | state),
            owner_id,
            task_id: Some(addr >> 8),
            spawn_location: None,
            vtable_addr: 0xf000,
            trailer_offset: 0x40,
            future: FutureInfo::Unknown { poll_symbol: None },
        }
    }

    fn key(addr: u64, ty: u32) -> ValueKey {
        ValueKey {
            addr,
            ty: BundleTypeId(ty),
        }
    }

    const RT0: OwnerKey = OwnerKey::Runtime {
        flavor: RuntimeFlavor::MultiThread,
        handle: 0x1000,
    };
    const RT1: OwnerKey = OwnerKey::Runtime {
        flavor: RuntimeFlavor::CurrentThread,
        handle: 0x2000,
    };
    const SET: OwnerKey = OwnerKey::LocalSet { shared: 0x3000 };

    fn handle_ref(target: u64, holder: u64) -> Observation {
        Observation {
            source: TaskSource::Reference(TaskReference {
                target: TaskAddr(target),
                source: ReferenceSource::JoinHandle,
                source_value: Some(key(holder + 0x10, 7)),
                root_task: Some(TaskAddr(holder)),
                path: Vec::new(),
            }),
            kind: None,
            claim: None,
        }
    }

    fn classed(observation: Observation, kind: TaskKind) -> Observation {
        Observation {
            kind: Some(kind),
            ..observation
        }
    }

    fn queued(owner: OwnerKey, entry: u64) -> Observation {
        Observation {
            source: TaskSource::BlockingQueue {
                owner,
                queue: key(0x9000, 3),
                entry,
            },
            kind: None,
            claim: Some(OwnerClaim {
                owner,
                evidence: OwnerEvidence::BlockingQueue {
                    queue: key(0x9000, 3),
                    entry,
                },
            }),
        }
    }

    fn listed(owner: OwnerKey, head: u64, owner_id: u64) -> Observation {
        Observation {
            source: TaskSource::OwnedList { owner, head },
            kind: None,
            claim: Some(OwnerClaim {
                owner,
                evidence: OwnerEvidence::OwnedList { head, owner_id },
            }),
        }
    }

    fn cell(owner: OwnerKey, scheduler: u64, owner_id: u64) -> Observation {
        Observation {
            source: TaskSource::Reference(TaskReference {
                target: TaskAddr(0),
                source: ReferenceSource::JoinHandle,
                source_value: None,
                root_task: None,
                path: Vec::new(),
            }),
            kind: Some(TaskKind::Async),
            claim: Some(OwnerClaim {
                owner,
                evidence: OwnerEvidence::CellScheduler {
                    scheduler: key(scheduler, 9),
                    owner_id,
                },
            }),
        }
    }

    /// The result of feeding `observations` in every order: one
    /// distinct `(kind, owner, resident, issues)` tuple, or the test
    /// names the orders that differ.
    fn every_order(addr: u64, state: u64, observations: &[Observation]) -> TaskRecordShape {
        let n = observations.len();
        let mut shapes: Vec<(Vec<usize>, TaskRecordShape)> = Vec::new();
        for order in permutations(n) {
            let mut store = TaskStore::new();
            for &i in &order {
                store.observe(header(addr, state, Some(1)), observations[i].clone());
            }
            assert_eq!(store.len(), 1, "{order:?}");
            let record = store.record_at(addr).unwrap();
            shapes.push((order, TaskRecordShape::of(record)));
        }
        let first = shapes[0].1.clone();
        for (order, shape) in &shapes {
            assert_eq!(
                *shape, first,
                "order {order:?} differs from {:?}",
                shapes[0].0
            );
        }
        first
    }

    fn permutations(n: usize) -> Vec<Vec<usize>> {
        fn go(rest: &mut Vec<usize>, prefix: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
            if rest.is_empty() {
                out.push(prefix.clone());
                return;
            }
            for i in 0..rest.len() {
                let x = rest.remove(i);
                prefix.push(x);
                go(rest, prefix, out);
                prefix.pop();
                rest.insert(i, x);
            }
        }
        let mut out = Vec::new();
        go(&mut (0..n).collect(), &mut Vec::new(), &mut out);
        out
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct TaskRecordShape {
        kind: TaskKind,
        owner: OwnerResolution,
        resident: bool,
        issues: Vec<DiscoveryIssue>,
        claims: usize,
        sources: usize,
    }

    impl TaskRecordShape {
        fn of(record: &TaskRecord) -> Self {
            let mut issues = record.issues.clone();
            issues.sort_by_key(|i| i.to_string());
            TaskRecordShape {
                kind: record.kind(),
                owner: record.owner(),
                resident: record.resident(),
                issues,
                claims: record.owner_claims.len(),
                sources: record.sources.len(),
            }
        }
    }

    /// A blocking cell met through a handle and through its pool
    /// queue, in either order: one record, kind blocking, owned by the
    /// queue's runtime, listed.
    #[test]
    fn test_handle_and_queue_agree_in_either_order() {
        let shape = every_order(
            0x100,
            0,
            &[
                classed(handle_ref(0x100, 0x500), TaskKind::Blocking),
                queued(RT0, 0x9100),
            ],
        );
        assert_eq!(
            shape,
            TaskRecordShape {
                kind: TaskKind::Blocking,
                owner: OwnerResolution::Known(RT0),
                resident: true,
                issues: Vec::new(),
                claims: 1,
                sources: 2,
            }
        );
    }

    /// The same queue observed twice is one source and one claim.
    #[test]
    fn test_a_repeated_queue_observation_is_idempotent() {
        let shape = every_order(0x100, 0, &[queued(RT0, 0x9100), queued(RT0, 0x9100)]);
        assert_eq!((shape.claims, shape.sources), (1, 1));
        assert_eq!(shape.owner, OwnerResolution::Known(RT0));
    }

    /// Two runtimes' queues both claiming one cell is a conflict that
    /// no order hides and no third agreeing observation clears.
    #[test]
    fn test_two_distinct_queue_claims_conflict_and_persist() {
        let observations = [
            queued(RT0, 0x9100),
            queued(RT1, 0x9200),
            queued(RT0, 0x9100),
        ];
        let shape = every_order(0x100, 0, &observations);
        assert_eq!(shape.owner, OwnerResolution::Conflict(vec![RT0, RT1]));
        assert_eq!(
            shape.issues,
            [DiscoveryIssue::OwnerConflict {
                addr: TaskAddr(0x100),
                owners: vec![RT0, RT1]
            }]
        );
        assert!(shape.resident);
    }

    /// A handle to a task whose future the join could not resolve
    /// establishes the task and nothing else: no kind, no owner, and
    /// — since it is live — a row of its own.
    #[test]
    fn test_a_bare_reference_manufactures_nothing() {
        let shape = every_order(0x100, 0, &[handle_ref(0x100, 0x500)]);
        assert_eq!(
            (shape.kind, shape.owner, shape.resident),
            (TaskKind::Unknown, OwnerResolution::Unknown, true)
        );
        assert!(shape.issues.is_empty());
    }

    /// A complete task a handle keeps alive is kept — the join it
    /// explains needs it — but is nobody's row; the same header in a
    /// list is a row, complete or not.
    #[test]
    fn test_a_complete_referenced_task_is_not_resident() {
        let held = every_order(0x100, COMPLETE, &[handle_ref(0x100, 0x500)]);
        assert!(!held.resident);
        let listed = every_order(
            0x100,
            COMPLETE,
            &[handle_ref(0x100, 0x500), listed(RT0, 0x7000, 1)],
        );
        assert!(listed.resident);
    }

    /// A runtime reached through two different cells is one owner:
    /// the key is the handle's referent, so two claims with distinct
    /// evidence name one key and the task is `Known`, not in conflict.
    #[test]
    fn test_two_cell_slots_for_one_runtime_are_one_owner() {
        let shape = every_order(
            0x100,
            0,
            &[
                cell(RT0, 0x1000, 1),
                cell(RT0, 0x1000, 1),
                listed(RT0, 0x7000, 1),
            ],
        );
        assert_eq!(shape.owner, OwnerResolution::Known(RT0));
        assert_eq!(shape.claims, 2, "distinct evidence for one owner is kept");
        assert!(shape.issues.is_empty());
    }

    /// A list and a queue disagreeing on kind is a conflict that
    /// stays: the third, agreeing list observation does not clear it.
    #[test]
    fn test_kind_disagreement_is_a_persistent_conflict() {
        let shape = every_order(
            0x100,
            0,
            &[
                listed(RT0, 0x7000, 1),
                queued(RT0, 0x9100),
                listed(RT0, 0x7000, 1),
            ],
        );
        assert_eq!(shape.kind, TaskKind::Conflict);
        assert_eq!(
            shape.issues,
            [DiscoveryIssue::KindConflict {
                addr: TaskAddr(0x100)
            }]
        );
        // The owner is untouched by the kind conflict.
        assert_eq!(shape.owner, OwnerResolution::Known(RT0));
    }

    /// A set's list and a runtime's list both claiming one task is an
    /// owner conflict between two kinds of owner.
    #[test]
    fn test_a_set_and_a_runtime_claiming_one_task_conflict() {
        let shape = every_order(0x100, 0, &[listed(RT0, 0x7000, 1), listed(SET, 0x8000, 1)]);
        assert_eq!(shape.owner, OwnerResolution::Conflict(vec![RT0, SET]));
    }

    /// The same address decoded two ways is a header conflict: the
    /// record keeps the first decode and the row reports no future,
    /// so nothing reads the cell by a type the decodes disagreed on.
    #[test]
    fn test_conflicting_header_views_disable_typed_interpretation() {
        let mut store = TaskStore::new();
        let first = store.observe(header(0x100, 0, Some(1)), listed(RT0, 0x7000, 1));
        assert!(first.inserted);
        let mut other = header(0x100, 0, Some(1));
        other.vtable_addr = 0xf100;
        other.task_id = Some(99);
        let second = store.observe(other, handle_ref(0x100, 0x500));
        assert!(!second.inserted);
        let record = store.record_at(0x100).unwrap();
        assert!(record.header_conflict());
        assert_eq!(
            record.issues,
            [DiscoveryIssue::HeaderConflict {
                addr: TaskAddr(0x100),
                detail: "vtable 0xf000 vs 0xf100, task id Some(1) vs Some(99)".into()
            }]
        );
        assert_eq!(record.header.task_id, Some(1), "the first decode is kept");
        assert!(matches!(
            record.task().future,
            FutureInfo::Unknown { poll_symbol: None }
        ));
        // Ownership is still reconciled from the claims.
        assert_eq!(record.task().owner, OwnerResolution::Known(RT0));
    }

    /// The merge effect says what changed: insertion, then an owner
    /// filled in, then nothing on a repeat.
    #[test]
    fn test_the_merge_effect_reports_what_changed() {
        let mut store = TaskStore::new();
        let a = store.observe(header(0x100, 0, Some(1)), handle_ref(0x100, 0x500));
        assert_eq!(
            a,
            MergeEffect {
                record: TaskRecordId(0),
                inserted: true,
                owner_changed: false,
                kind_changed: false,
            }
        );
        let b = store.observe(header(0x100, 0, Some(1)), queued(RT0, 0x9100));
        assert_eq!(
            b,
            MergeEffect {
                record: TaskRecordId(0),
                inserted: false,
                owner_changed: true,
                kind_changed: true,
            }
        );
        let c = store.observe_at(TaskRecordId(0), queued(RT0, 0x9100));
        assert_eq!(
            c,
            MergeEffect {
                record: TaskRecordId(0),
                inserted: false,
                owner_changed: false,
                kind_changed: false,
            }
        );
    }

    /// References past the retained count are counted, not kept, and
    /// never at the cost of a distinct owner claim.
    #[test]
    fn test_references_past_the_budget_are_counted() {
        let mut store = TaskStore::new();
        for holder in 0..(RETAINED_REFERENCES as u64 + 3) {
            store.observe(
                header(0x100, 0, Some(1)),
                handle_ref(0x100, 0x1000 + holder * 0x100),
            );
        }
        store.observe(header(0x100, 0, Some(1)), queued(RT0, 0x9100));
        let record = store.record_at(0x100).unwrap();
        assert_eq!(record.omitted_sources, 3);
        assert_eq!(record.sources.len(), RETAINED_REFERENCES + 1);
        assert_eq!(record.owner(), OwnerResolution::Known(RT0));
    }

    /// The projection: resident rows only, sorted by id with the
    /// idless last, and a task owned by an excluded runtime left out —
    /// unless its ownership is in conflict, which stays visible.
    #[test]
    fn test_the_projection_selects_and_sorts() {
        let mut store = TaskStore::new();
        let mut idless = header(0x900, 0, Some(1));
        idless.task_id = None;
        store.observe(idless, listed(RT0, 0x7000, 1));
        store.observe(header(0x300, 0, Some(1)), listed(RT0, 0x7000, 1));
        store.observe(header(0x100, 0, Some(2)), listed(RT1, 0x7100, 2));
        store.observe(header(0x200, COMPLETE, Some(1)), handle_ref(0x200, 0x300));
        store.observe(header(0x400, 0, Some(1)), listed(RT1, 0x7100, 1));
        store.observe(header(0x400, 0, Some(1)), listed(RT0, 0x7000, 1));

        let all: Vec<u64> = store.project(&[]).iter().map(|t| t.addr.0).collect();
        assert_eq!(all, [0x100, 0x300, 0x400, 0x900]);

        let selected: Vec<u64> = store.project(&[0x2000]).iter().map(|t| t.addr.0).collect();
        assert_eq!(
            selected,
            [0x300, 0x400, 0x900],
            "the conflict at 0x400 stays"
        );
        let conflicted = store.record_at(0x400).unwrap().task();
        assert_eq!(
            conflicted.owner,
            OwnerResolution::Conflict(vec![RT0, RT1]),
            "named in key order, not arrival order"
        );
    }

    /// The index numbers runtimes first, then sets, and answers no
    /// group for an unknown, conflicting or unindexed owner.
    #[test]
    fn test_the_owner_index_numbers_known_owners_only() {
        let index = OwnerIndex::from_keys(vec![RT0, RT1, SET], 2);
        assert_eq!((index.len(), index.runtimes()), (3, 2));
        let task = |owner: OwnerResolution| {
            let mut task = TaskRecord::new(header(0x100, 0, None)).task();
            task.owner = owner;
            task
        };
        assert_eq!(index.group_of(&task(OwnerResolution::Known(RT0))), Some(0));
        assert_eq!(index.group_of(&task(OwnerResolution::Known(SET))), Some(2));
        assert_eq!(index.group_of(&task(OwnerResolution::Unknown)), None);
        assert_eq!(
            index.group_of(&task(OwnerResolution::Conflict(vec![RT0, RT1]))),
            None
        );
        let stranger = OwnerKey::LocalSet { shared: 0x4000 };
        assert_eq!(
            index.group_of(&task(OwnerResolution::Known(stranger))),
            None
        );
        assert_eq!(index.key(1), Some(RT1));
        assert_eq!(index.key(3), None);
    }

    #[test]
    fn test_issues_spell_themselves() {
        assert_eq!(
            DiscoveryIssue::OwnerIdMismatch {
                addr: TaskAddr(0x100),
                owner: SET,
                expected: 7,
                found: Some(9),
            }
            .to_string(),
            "the local set at 0x3000 led to the task at 0x100 but its owned-list id 7 does \
             not claim it (owner_id 9)"
        );
        assert_eq!(
            DiscoveryIssue::OwnerConflict {
                addr: TaskAddr(0x100),
                owners: vec![RT0, SET],
            }
            .to_string(),
            "the task at 0x100 is claimed by more than one owner: the multi_thread runtime \
             at 0x1000; the local set at 0x3000"
        );
    }
}

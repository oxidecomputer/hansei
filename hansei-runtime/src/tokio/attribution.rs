// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Attribution: what holds each waker slot the sweep admitted.
//!
//! The sweep ([`super::wakers`]) finds every clone of a task's waker
//! and says whose it is and what kind of memory it sits in; it names
//! nothing. Naming is this module's business, and it goes by the types
//! the bundle already carries rather than by a list of primitives
//! someone taught it. In order, per admitted hit:
//!
//! 1. **The registries.** A harvest that decoded the pair — a wheel
//!    entry, an io waiter, a semaphore queue node, a trailer — recorded
//!    where it was; a hit at that address is that slot, spelled as the
//!    registries spell it today.
//! 2. **Containment.** A hit inside a typed value the analysis or the
//!    census holds — a chain frame, a held find, a set child — is
//!    walked down to by offset ([`Context::locate_member`]): struct
//!    member by member, an enum through its active variant, a
//!    `MaybeUninit` through its `value`. Landing on a `Waker` names the
//!    slot by the innermost type that owns it; landing in an inactive
//!    variant, or on anything else, demotes the hit as stale.
//! 3. **One corroborated hop.** A pointer member of one of those values
//!    whose target lies in the allocation holding the hit lets the
//!    pointee be walked the same way — and only then: the pointee is
//!    decoded because a hit naming the same task already sits in it,
//!    never because a pointer merely points there.
//! 4. **Unknown.** What the allocator index says about the buffer, and
//!    nothing else.
//!
//! The owner-name table then gives a slot located in a `oneshot::Inner`,
//! a `mpsc::chan::Chan` or a `Notified` its kind word; every other typed
//! location is spelled by the type that holds it. Two rules keep the
//! cost at one more descent over storage the census already descends:
//! hits are grouped by owner before any value is walked, and an owner's
//! pointer members are collected once, sorted, and searched per hit.
//! Nothing here scans a mapping.

use super::RawInstant;
use super::bundle::{
    Context, IoResourceInfo, IoSlot, IoWaiterInfo, Readiness, Registries, TaskList, TimerEntryInfo,
    WaitTarget, WheelState, deadline_text,
};
use super::census::{FutureCensus, Via};
use super::contract::{Walked, execute_steps_over};
use super::graph::{Analysis, TaskRef, TaskWait};
use super::observe::{ReadContext, ValueKey};
use super::semantics::SemanticIndex;
use super::wakers::{Hit, Owner, WakerSlots};
use crate::heap::umem::{Liveness, Source, UmemHeap};

use foldhash::{HashMap, HashSet};
use hansei_bundle::names::{ImplFold, fold_type_name, outer_path};
use hansei_bundle::{
    BundleType, BundleTypeId, BundleView, TypeClass, TypeSemantics, WalkOutcome, WalkRole,
};
use proc::Target;
use reify::Value;

/// How deep the offset walk and the pointer enumeration descend
/// through aggregates before giving up: a waker sits a few members
/// down, never dozens.
const MAX_DEPTH: usize = 24;

/// The type a slot is: `Waker { waker: RawWaker }`, whose `RawWaker`
/// starts at its own address.
const WAKER: &str = "core::task::wake::Waker";
const RAW_WAKER: &str = "core::task::wake::RawWaker";

/// Types that are storage for one value spelled another way, never the
/// owner of a slot: the walk passes through them to name what holds
/// them. Matched by prefix, since each is generic.
const WRAPPERS: &[&str] = &[
    "core::option::Option<",
    "core::mem::maybe_uninit::MaybeUninit<",
    "core::mem::manually_drop::ManuallyDrop<",
    "core::cell::UnsafeCell<",
    "tokio::loom::std::unsafe_cell::UnsafeCell<",
    "tokio::sync::oneshot::Task",
    "crossbeam_utils::cache_padded::CachePadded<",
    "tokio::util::cacheline::CachePadded<",
];

/// What the containing type says about whether a slot is current.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Validity {
    /// The path crossed an `Option`'s `Some`: the storage says a waker
    /// is there.
    SelfDescribing,
    /// The path crossed a `MaybeUninit` under a state word whose bit
    /// for this slot is set — the bit named here (`rx_task_set`).
    Gated(&'static str),
    /// The path crossed a `MaybeUninit` under a state word this build
    /// does not read: the bytes are a waker's, and nothing says the
    /// slot is current.
    Unchecked,
    /// Neither: a waker by value, current for as long as its holder is.
    Raw,
}

impl Validity {
    /// The word a detail line appends, or nothing for a slot that
    /// vouches for itself.
    fn note(self) -> String {
        match self {
            Validity::SelfDescribing | Validity::Raw => String::new(),
            Validity::Gated(bit) => format!(" ({bit})"),
            Validity::Unchecked => " (unchecked)".to_string(),
        }
    }
}

/// Which typed value a slot's path starts from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SlotRoot {
    /// A frame of a task's own chain, numbered as the listings display
    /// frames: `#0` the most recently polled.
    Frame { task: usize, frame: usize },
    /// A held find, by its index in [`FutureCensus::held`] and the
    /// address the listings print for it.
    Find { index: usize, addr: u64 },
    /// A set child, by set and child index and its root's address.
    Child { set: usize, child: usize, addr: u64 },
}

impl std::fmt::Display for SlotRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotRoot::Frame { frame, .. } => write!(f, "#{frame}"),
            SlotRoot::Find { addr, .. } => write!(f, "the future at {addr:#x}"),
            SlotRoot::Child { addr, .. } => write!(f, "the set child at {addr:#x}"),
        }
    }
}

/// Where a slot was found, as a path from a root the census or the
/// analysis holds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotPath {
    pub root: SlotRoot,
    /// The member steps from the root: to the slot, or — with `hop` —
    /// to the pointer member the hop followed.
    pub steps: Vec<String>,
    /// The one corroborated hop, where the slot lies behind a pointer.
    pub hop: Option<Hop>,
}

/// A pointer followed to the allocation holding the slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hop {
    /// The pointee's address.
    pub addr: u64,
    /// The pointee's type, as the bundle names it, and its id.
    pub pointee: String,
    pub pointee_ty: BundleTypeId,
    /// The member steps from the pointee to the slot.
    pub steps: Vec<String>,
}

impl SlotPath {
    /// The path as a detail line spells it: the root, then the member
    /// names on the way, tuple positions and enum variants left out
    /// (they say how the storage is spelled, not what holds it).
    fn text(&self) -> String {
        let mut out = self.root.to_string();
        let names = |steps: &[String]| -> String {
            let kept: Vec<&str> = steps
                .iter()
                .map(String::as_str)
                .filter(|s| {
                    !s.starts_with("__")
                        && !s.starts_with('<')
                        && !matches!(*s, "ptr" | "pointer" | "value" | "*")
                })
                .collect();
            kept.join(" → ")
        };
        let head = names(&self.steps);
        if !head.is_empty() {
            out.push(' ');
            out.push_str(&head);
        }
        if let Some(hop) = &self.hop {
            let tail = names(&hop.steps);
            out.push_str(" → *");
            if !tail.is_empty() {
                out.push_str(" → ");
                out.push_str(&tail);
            }
        }
        out
    }
}

/// A slot one of the registries decoded: spelled as they spell it.
#[derive(Clone, Debug)]
pub enum RegistrySlot {
    Timer {
        entry: u64,
        state: Option<WheelState>,
        deadline: Option<RawInstant>,
    },
    Io {
        resource: u64,
        slot: IoSlot,
        ready: Option<Readiness>,
    },
    Semaphore {
        semaphore: u64,
        node: u64,
    },
    Join {
        /// The task whose trailer holds the slot: the one awaited.
        task: TaskRef,
    },
}

/// The primitive a slot's owning type is, where the owner-name table
/// names one.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum OwnerKind {
    /// A oneshot's `rx_task`: the receiver awaiting the value.
    OneshotRx,
    /// A oneshot's `tx_task`: the sender watching for the receiver to
    /// go away, not a wait for a value.
    OneshotTx,
    /// A bounded or unbounded mpsc channel's receiver slot.
    Mpsc,
    /// A `Notified` node queued on one of a watch channel's `Notify`s:
    /// a receiver awaiting a change.
    Watch,
    /// A `Notified` node queued on a bare `Notify`.
    Notify,
}

impl OwnerKind {
    /// The kind word a cell and a bucket use.
    pub fn word(self) -> &'static str {
        match self {
            OwnerKind::OneshotRx => "oneshot rx",
            OwnerKind::OneshotTx => "oneshot tx",
            OwnerKind::Mpsc => "mpsc",
            OwnerKind::Watch => "watch",
            OwnerKind::Notify => "notify",
        }
    }
}

/// What a slot was attributed to.
#[derive(Clone, Debug)]
pub enum Attribution {
    /// A registry decoded this pair and recorded where it was.
    Registry(RegistrySlot),
    /// A typed location whose owning type the owner-name table names.
    Owner {
        kind: OwnerKind,
        /// The primitive's address: the `Inner`, `Chan` or `Notify`.
        primitive: u64,
        /// The owning type as a detail line spells it (`Inner`), and
        /// the member of it the slot sits under (`rx_task`).
        holder: String,
        member: String,
        path: SlotPath,
        validity: Validity,
    },
    /// A typed location no table names: spelled by the innermost type
    /// holding it.
    Typed {
        /// The holding type's display name, generic arguments dropped.
        holder: String,
        /// Its member the slot sits under.
        member: String,
        path: SlotPath,
        validity: Validity,
    },
    /// A live allocation nothing typed reaches.
    Unknown {
        cache: Option<String>,
        size: Option<u64>,
        offset: Option<u64>,
    },
}

/// One admitted hit with what it was attributed to.
#[derive(Clone, Debug)]
pub struct AttributedSlot {
    /// Index into [`WakerSlots::hits`].
    pub hit: usize,
    pub slot: u64,
    pub owner: Owner,
    pub attribution: Attribution,
    /// For a registry slot, the innermost typed value holding it — a
    /// `Sleep` find around its wheel entry — so the find it sits in is
    /// armed by it as a located slot's would be.
    pub within: Option<SlotRoot>,
}

impl AttributedSlot {
    /// The cell entry, before any reader's detail: the kind word and
    /// the address that identifies the slot.
    pub fn entry(&self, stopped: Option<RawInstant>) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer {
                entry, deadline, ..
            }) => match deadline {
                Some(deadline) => format!("timer ({})", deadline_text(*deadline, stopped)),
                None => format!("timer {entry:#x}"),
            },
            Attribution::Registry(RegistrySlot::Io { resource, slot, .. }) => {
                format!("io {resource:#x}{}", io_side(slot))
            }
            Attribution::Registry(RegistrySlot::Semaphore { semaphore, .. }) => {
                format!("semaphore {semaphore:#x}")
            }
            Attribution::Registry(RegistrySlot::Join { task }) => format!("join {task}"),
            Attribution::Owner {
                kind, primitive, ..
            } => format!("{} {primitive:#x}", kind.word()),
            Attribution::Typed { holder, .. } => format!("slot {:#x} in {holder}", self.slot),
            Attribution::Unknown { .. } => format!("unknown {:#x}", self.slot),
        }
    }

    /// The slot's label for a detail line: the kind word and the
    /// address that identifies the slot, whatever a reader would add.
    pub fn label(&self) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer { entry, .. }) => format!("timer {entry:#x}"),
            Attribution::Typed { .. } => format!("slot {:#x}", self.slot),
            _ => self.entry(None),
        }
    }

    /// The bucket `--group waiting-on` files the slot under: the kind,
    /// with identity kept where it groups usefully.
    pub fn bucket(&self) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer { .. }) => "timer".to_string(),
            Attribution::Registry(RegistrySlot::Io { slot, .. }) => format!("io{}", io_side(slot)),
            Attribution::Registry(RegistrySlot::Semaphore { semaphore, .. }) => {
                format!("semaphore {semaphore:#x}")
            }
            Attribution::Registry(RegistrySlot::Join { task }) => format!("join {task}"),
            Attribution::Owner { kind, .. } => kind.word().to_string(),
            Attribution::Typed { holder, .. } => format!("slot in {holder}"),
            Attribution::Unknown { .. } => "unknown".to_string(),
        }
    }

    /// The detail line's text after the entry: where the slot is and
    /// what says it is current.
    pub fn detail(&self, stopped: Option<RawInstant>) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer {
                state, deadline, ..
            }) => {
                let state = match state {
                    Some(state) => format!(", {state}"),
                    None => String::new(),
                };
                let due = match deadline {
                    Some(deadline) => format!(", {}", deadline_text(*deadline, stopped)),
                    None => String::new(),
                };
                format!("waker in the wheel entry{state}{due}")
            }
            Attribution::Registry(RegistrySlot::Io { slot, ready, .. }) => {
                let site = match slot {
                    IoSlot::Reader => "the read-waiter slot",
                    IoSlot::Writer => "the write-waiter slot",
                    IoSlot::Listed { .. } => "a waiter node",
                };
                let interest = match slot.interest() {
                    Some(interest) => format!("awaiting {interest}"),
                    None => "interest unreadable".to_string(),
                };
                let ready = match ready {
                    Some(ready) => format!(", ready: {ready}"),
                    None => String::new(),
                };
                format!("{interest} via {site}{ready}")
            }
            Attribution::Registry(RegistrySlot::Semaphore { node, .. }) => {
                format!("waker in its wake-queue node {node:#x}")
            }
            Attribution::Registry(RegistrySlot::Join { .. }) => "waker in its trailer".to_string(),
            Attribution::Owner {
                holder,
                member,
                path,
                validity,
                ..
            }
            | Attribution::Typed {
                holder,
                member,
                path,
                validity,
            } => {
                let reached = match path.hop {
                    Some(_) => "reached from",
                    None => "in",
                };
                format!(
                    "waker in {holder}.{member}{}, {reached} {}",
                    validity.note(),
                    path.text()
                )
            }
            Attribution::Unknown {
                cache,
                size,
                offset,
            } => match (cache, size, offset) {
                (Some(cache), Some(size), Some(offset)) => {
                    format!("in a {size}-byte {cache} buffer at +{offset}")
                }
                (None, Some(size), Some(offset)) => {
                    format!("in a {size}-byte allocation at +{offset}")
                }
                _ => "in memory nothing typed reaches".to_string(),
            },
        }
    }

    /// The path, where the slot was located by type.
    pub fn path(&self) -> Option<&SlotPath> {
        match &self.attribution {
            Attribution::Owner { path, .. } | Attribution::Typed { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// The `read`/`write`/`<interest>` suffix an io slot's spelling carries.
fn io_side(slot: &IoSlot) -> String {
    match slot {
        IoSlot::Reader => " read".to_string(),
        IoSlot::Writer => " write".to_string(),
        IoSlot::Listed { .. } => match slot.interest() {
            Some(interest) => format!(" {interest}"),
            None => String::new(),
        },
    }
}

/// Why an admitted hit was demoted rather than attributed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StaleReason {
    /// The offset lies in an inactive variant of an enum on the way:
    /// storage of a state the value is no longer in.
    InactiveVariant,
    /// The offset lies in a coroutine local the active state does not
    /// initialize.
    DeadLocal,
    /// The walk landed on something that is not a `Waker`.
    NotAWaker,
    /// The slot lies under a state word whose bit for it is clear: a
    /// oneshot `Task` whose `*_TASK_SET` bit says no waker is stored.
    GateClear,
}

impl StaleReason {
    pub fn text(self) -> &'static str {
        match self {
            StaleReason::InactiveVariant => "in an inactive variant",
            StaleReason::DeadLocal => "in a local the active state does not initialize",
            StaleReason::NotAWaker => "not at a Waker",
            StaleReason::GateClear => "under a state word that says no waker is set",
        }
    }
}

/// A hit inside a typed value that did not locate to a slot.
#[derive(Clone, Debug)]
pub struct Stale {
    pub hit: usize,
    pub slot: u64,
    pub owner: Owner,
    pub root: SlotRoot,
    pub reason: StaleReason,
}

/// What the attribution did, for `info`.
#[derive(Clone, Debug, Default)]
pub struct AttributionStats {
    pub registry: usize,
    pub owner: usize,
    pub typed: usize,
    pub unknown: usize,
    pub stale: usize,
    /// Owners whose typed values were walked.
    pub owners: usize,
    pub elapsed: std::time::Duration,
}

/// Every admitted slot, attributed, indexed by who it wakes and by
/// which find it sits in or was reached from.
#[derive(Debug, Default)]
pub struct Attributed {
    /// One per admitted hit, in [`WakerSlots::hits`] order.
    pub slots: Vec<AttributedSlot>,
    pub stale: Vec<Stale>,
    pub stats: AttributionStats,
    by_task: HashMap<u64, Vec<usize>>,
    by_child: HashMap<(usize, usize), Vec<usize>>,
    by_find: HashMap<usize, Vec<usize>>,
    by_slot: HashMap<u64, usize>,
}

impl Attributed {
    /// The slots waking the task whose header is `addr`, in slot order.
    pub fn of_task(&self, addr: u64) -> impl Iterator<Item = &AttributedSlot> {
        self.by_task
            .get(&addr)
            .into_iter()
            .flatten()
            .map(|&i| &self.slots[i])
    }

    /// The slots waking set child `(set, child)`.
    pub fn of_child(&self, set: usize, child: usize) -> impl Iterator<Item = &AttributedSlot> {
        self.by_child
            .get(&(set, child))
            .into_iter()
            .flatten()
            .map(|&i| &self.slots[i])
    }

    /// The root a slot is filed under: the located path's, or the
    /// value a registry slot sits in.
    fn root_of(slot: &AttributedSlot) -> Option<SlotRoot> {
        slot.path().map(|p| p.root).or(slot.within)
    }

    /// The slots attributed to held find `index`: inside its storage,
    /// or reached through a pointer member of it.
    pub fn of_find(&self, index: usize) -> impl Iterator<Item = &AttributedSlot> {
        self.by_find
            .get(&index)
            .into_iter()
            .flatten()
            .map(|&i| &self.slots[i])
    }

    /// Whether any slot attributes to held find `index`.
    pub fn find_armed(&self, index: usize) -> bool {
        self.by_find.contains_key(&index)
    }

    /// The slot at exactly `addr`, if one was attributed.
    pub fn at(&self, addr: u64) -> Option<&AttributedSlot> {
        self.by_slot.get(&addr).map(|&i| &self.slots[i])
    }

    /// A population of slots laid out by hand, indexed the way the
    /// attributor indexes its own — for a listing test over a shape no
    /// fixture holds.
    pub fn from_slots(slots: Vec<AttributedSlot>) -> Attributed {
        let mut out = Attributed {
            slots,
            ..Attributed::default()
        };
        out.index();
        out
    }

    /// The audit's second cross-check: every admitted hit inside a
    /// typed value must have located to a slot. One line per
    /// demotion; empty is clean.
    pub fn audit(&self, list: &TaskList) -> Vec<String> {
        self.stale
            .iter()
            .map(|s| {
                let owner = match s.owner {
                    Owner::Task { index, .. } => match list.tasks[index].task_id {
                        Some(id) => format!("task {id}"),
                        None => format!("the task at {:#x}", list.tasks[index].addr.0),
                    },
                    Owner::Child { set, child } => format!("child {child} of set {set}"),
                };
                format!(
                    "the hit at {:#x} names {owner} and sits in {} but is {}",
                    s.slot,
                    s.root,
                    s.reason.text()
                )
            })
            .collect()
    }

    fn index(&mut self) {
        for (i, slot) in self.slots.iter().enumerate() {
            match slot.owner {
                Owner::Task { header, .. } => self.by_task.entry(header).or_default().push(i),
                Owner::Child { set, child } => {
                    self.by_child.entry((set, child)).or_default().push(i)
                }
            }
            match Self::root_of(slot) {
                Some(SlotRoot::Find { index, .. }) => {
                    self.by_find.entry(index).or_default().push(i)
                }
                // A task's own waker located through a child's root is
                // the child's to show too, once.
                Some(SlotRoot::Child { set, child, .. })
                    if !matches!(slot.owner, Owner::Child { .. }) =>
                {
                    self.by_child.entry((set, child)).or_default().push(i)
                }
                _ => {}
            }
            self.by_slot.insert(slot.slot, i);
            match &slot.attribution {
                Attribution::Registry(_) => self.stats.registry += 1,
                Attribution::Owner { .. } => self.stats.owner += 1,
                Attribution::Typed { .. } => self.stats.typed += 1,
                Attribution::Unknown { .. } => self.stats.unknown += 1,
            }
        }
        self.stats.stale = self.stale.len();
    }
}

/// What the attributor reads: the sweep's territory plus the analysis,
/// whose chain frames and registry-decoded pairs are the typed values
/// and the addresses attribution is checked against.
pub struct Sources<'a> {
    pub list: &'a TaskList,
    pub census: &'a FutureCensus,
    pub registries: &'a Registries,
    pub analysis: &'a Analysis,
    pub heap: Option<&'a UmemHeap>,
    pub impls: &'a ImplFold,
}

/// One typed value an owner holds, from which a slot may be located:
/// a chain frame, a find, a set child's root.
struct Root<'b> {
    at: SlotRoot,
    value: Value<'b>,
}

impl Root<'_> {
    /// The path to a slot located `steps` into this root, or — with
    /// `hop` — to the pointer member at `steps` and on into the
    /// pointee.
    fn path(&self, steps: Vec<String>, hop: Option<Hop>) -> SlotPath {
        SlotPath {
            root: self.at,
            steps,
            hop,
        }
    }
}

/// A pointer member of one of an owner's roots. Its path is not kept:
/// tens of thousands of owners hold dozens of pointers each, and only
/// the one that corroborates a hit is ever spelled, by walking to its
/// address again ([`Context::steps_to`]).
#[derive(Copy, Clone)]
struct PointerMember {
    target: u64,
    pointee: BundleTypeId,
    /// Index into the owner's roots, which come innermost first: two
    /// roots holding the same pointer — a find and the frame it sits
    /// in — are tried in that order, so the slot is the find's.
    root: usize,
    /// The pointer word's own address.
    at: u64,
}

/// What an offset walk ends at.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Terminal {
    /// A `Waker` at the offset: the slot.
    Waker,
    /// A pointer at the offset: the member a hop followed.
    Pointer,
}

/// An offset walk's trail and what it crossed.
struct Descent<'b> {
    trail: Vec<Step<'b>>,
    crossed_option: bool,
    crossed_union: bool,
}

/// The result of walking a typed value down to an offset.
enum Located<'b> {
    /// A `Waker` at the offset, reached through `trail`.
    Slot {
        trail: Vec<Step<'b>>,
        validity: Validity,
    },
    Stale(StaleReason),
}

/// One step of an offset walk: the member entered, and the value it
/// entered from.
#[derive(Clone)]
struct Step<'b> {
    name: String,
    /// The aggregate the step was taken in.
    holder: Value<'b>,
}

/// What the walk reads about types, apart from the session's context
/// so it can be shared across the threads the owners are spread over:
/// the bundle view and the semantic records.
#[derive(Copy, Clone)]
struct Types<'a, 'b> {
    view: BundleView<'b>,
    semantics: &'a SemanticIndex,
    test_bindings: &'b [TypeSemantics],
}

impl<'b> Types<'_, 'b> {
    fn type_semantics(&self, ty: BundleTypeId) -> Option<&'b TypeSemantics> {
        if let Some(binding) = self.test_bindings.iter().find(|record| record.ty == ty) {
            return Some(binding);
        }
        self.semantics
            .get(ty)
            .map(|index| &self.view.bundle().semantics.types[index])
    }
}

/// One attribution's shared state: what every owner's hits are checked
/// against, read-only once built, so owners can be attributed side by
/// side.
struct Attributor<'a, 'b, T> {
    proc: &'b T,
    types: Types<'a, 'b>,
    sources: &'a Sources<'a>,
    registry: HashMap<u64, RegistrySlot>,
    finds: HashMap<OwnerKey, Vec<usize>>,
}

impl<'b, T: Target> Context<'b, T> {
    /// Attribute every admitted hit of `wakers` against `sources`. The
    /// owners are independent, so they are spread over the cores: an
    /// attribution over a core with tens of thousands of parked tasks
    /// is a few hundred milliseconds of walking on one thread.
    pub fn attribute_slots(&self, wakers: &WakerSlots, sources: &Sources<'_>) -> Attributed {
        let started = std::time::Instant::now();
        let (semantics, test_bindings) = self.semantic_parts();
        let attributor = Attributor {
            proc: self.proc,
            types: Types {
                view: self.view,
                semantics,
                test_bindings,
            },
            sources,
            registry: registry_map(sources.registries, sources.analysis),
            finds: finds_by_owner(sources.census),
        };

        // Hits by owner, so each owner's values are walked once.
        let mut by_owner: HashMap<Owner, Vec<usize>> = HashMap::default();
        for (i, hit) in wakers.hits.iter().enumerate() {
            if let (true, Some(owner)) = (hit.admitted, hit.owner) {
                by_owner.entry(owner).or_default().push(i);
            }
        }
        let mut owners: Vec<(Owner, Vec<usize>)> = by_owner.into_iter().collect();
        owners.sort_by_key(|(_, hits)| hits[0]);

        let mut out = Attributed::default();
        out.stats.owners = owners.len();
        // Owners handed out one at a time, since their work is uneven:
        // an http connection task walks two roots and dozens of
        // pointers, a set child with registry hits walks nothing.
        let hits = &wakers.hits;
        let next = std::sync::atomic::AtomicUsize::new(0);
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(owners.len().max(1));
        let results: Vec<(Vec<AttributedSlot>, Vec<Stale>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    let (attributor, owners, next) = (&attributor, &owners, &next);
                    scope.spawn(move || {
                        let (mut slots, mut stale) = (Vec::new(), Vec::new());
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some((owner, indexes)) = owners.get(i) else {
                                break;
                            };
                            attributor.owner(*owner, indexes, hits, &mut slots, &mut stale);
                        }
                        (slots, stale)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("an attribution worker panicked"))
                .collect()
        });
        for (slots, stale) in results {
            out.slots.extend(slots);
            out.stale.extend(stale);
        }
        out.slots.sort_by_key(|s| s.hit);
        out.stale.sort_by_key(|s| s.hit);
        out.index();
        out.stats.elapsed = started.elapsed();
        out
    }
}

impl<'a, 'b, T: Target> Attributor<'a, 'b, T> {
    /// Attribute one owner's admitted hits, appending to `slots` and
    /// `stale`.
    fn owner(
        &self,
        owner: Owner,
        indexes: &[usize],
        hits: &[Hit],
        slots: &mut Vec<AttributedSlot>,
        stale: &mut Vec<Stale>,
    ) {
        let roots = self.roots_of(owner);
        let mut pointers: Option<Vec<PointerMember>> = None;
        for &i in indexes {
            let hit = &hits[i];
            let mut within = None;
            let attribution = if let Some(slot) = self.registry.get(&hit.slot) {
                within = roots
                    .iter()
                    .find(|r| contains(r.value, hit.slot))
                    .map(|r| r.at);
                Attribution::Registry(slot.clone())
            } else {
                match self.by_containment(hit, &roots) {
                    Ok(Some(attribution)) => attribution,
                    Err(mut demoted) => {
                        demoted.hit = i;
                        stale.push(demoted);
                        continue;
                    }
                    Ok(None) => {
                        let pointers = pointers.get_or_insert_with(|| self.pointer_members(&roots));
                        match self.by_hop(hit, &roots, pointers) {
                            Some(attribution) => attribution,
                            None => unknown(hit.slot, self.sources.heap),
                        }
                    }
                }
            };
            // The readers' roles refine an owner slot: the oneshot's
            // state word gates its two task slots, and a `Notified` on
            // one of a watch channel's `Notify`s is the watch's.
            let attribution = match attribution {
                Attribution::Owner {
                    kind: kind @ (OwnerKind::OneshotRx | OwnerKind::OneshotTx),
                    primitive,
                    holder,
                    member,
                    path,
                    validity,
                } => match self.oneshot_gate(kind, &path) {
                    Gate::Set(bit) => Attribution::Owner {
                        kind,
                        primitive,
                        holder,
                        member,
                        path,
                        validity: Validity::Gated(bit),
                    },
                    Gate::Clear => {
                        stale.push(Stale {
                            hit: i,
                            slot: hit.slot,
                            owner,
                            root: path.root,
                            reason: StaleReason::GateClear,
                        });
                        continue;
                    }
                    Gate::Unread => Attribution::Owner {
                        kind,
                        primitive,
                        holder,
                        member,
                        path,
                        validity,
                    },
                },
                Attribution::Owner {
                    kind: OwnerKind::Notify,
                    primitive,
                    holder,
                    member,
                    path,
                    validity,
                } => {
                    let pointers = pointers.get_or_insert_with(|| self.pointer_members(&roots));
                    match self.watch_of(primitive, pointers) {
                        Some(shared) => Attribution::Owner {
                            kind: OwnerKind::Watch,
                            primitive: shared,
                            holder,
                            member,
                            path,
                            validity,
                        },
                        None => Attribution::Owner {
                            kind: OwnerKind::Notify,
                            primitive,
                            holder,
                            member,
                            path,
                            validity,
                        },
                    }
                }
                other => other,
            };
            slots.push(AttributedSlot {
                hit: i,
                slot: hit.slot,
                owner,
                attribution,
                within,
            });
        }
    }

    /// Execute a recorded walk role from `root`, where the bundle bound
    /// it, landing on a value.
    fn walk_role(&self, role: WalkRole, root: Value<'b>) -> Option<Value<'b>> {
        let binding = self.types.view.bundle().walks.entries.get(&role)?;
        if !matches!(binding.outcome, WalkOutcome::Bound { .. }) {
            return None;
        }
        match execute_steps_over(
            self.proc,
            self.types.view,
            &ReadContext::none(),
            root,
            &binding.steps,
        ) {
            Ok(Walked::At(value)) => Some(value),
            _ => None,
        }
    }

    /// The oneshot's state word, read through the `ArcInner` the slot
    /// was reached through, against the bit that says this slot holds
    /// a waker: `RX_TASK_SET` for `rx_task`, `TX_TASK_SET` for
    /// `tx_task`. `Unread` where the role is unbound or the slot was
    /// not reached through the `Arc`.
    fn oneshot_gate(&self, kind: OwnerKind, path: &SlotPath) -> Gate {
        let Some(hop) = &path.hop else {
            return Gate::Unread;
        };
        let Some(ty) = self.types.view.ty(hop.pointee_ty) else {
            return Gate::Unread;
        };
        let Ok(arc) = Value::read(self.proc, ty, hop.addr) else {
            return Gate::Unread;
        };
        let Some(state) = self
            .walk_role(WalkRole::OneshotState, arc)
            .and_then(|v| v.parse::<u64>(self.proc).ok())
        else {
            return Gate::Unread;
        };
        let (bit, name) = match kind {
            OwnerKind::OneshotRx => (ONESHOT_RX_TASK_SET, "rx_task_set"),
            _ => (ONESHOT_TX_TASK_SET, "tx_task_set"),
        };
        if state & bit != 0 {
            Gate::Set(name)
        } else {
            Gate::Clear
        }
    }

    /// The watch channel whose `notify_rx` array holds the `Notify` at
    /// `notify`, among the `Arc<watch::Shared<_>>`s the owner's values
    /// point at: the `Shared`'s address, for the slot's primitive.
    /// Nothing is dereferenced but the `Shared` a pointer the owner
    /// holds already names, and only its `notify_rx` extent is read.
    fn watch_of(&self, notify: u64, pointers: &[PointerMember]) -> Option<u64> {
        let mut seen: HashSet<u64> = HashSet::default();
        for p in pointers {
            let ty = self.types.view.ty(p.pointee)?;
            if !ty
                .name()
                .starts_with("alloc::sync::ArcInner<tokio::sync::watch::Shared<")
                || !seen.insert(p.target)
            {
                continue;
            }
            let Ok(arc) = Value::read(self.proc, ty, p.target) else {
                continue;
            };
            let Some(notify_rx) = self.walk_role(WalkRole::WatchSharedNotifyRx, arc) else {
                continue;
            };
            if contains(notify_rx, notify) {
                let data = ty.member("data").map(|m| m.offset()).unwrap_or(0);
                return Some(arc.addr + data);
            }
        }
        None
    }

    /// The typed values `owner` holds: a task's chain frames (from the
    /// analysis) and the finds the census lists under it; a set
    /// child's root and the finds under it.
    fn roots_of(&self, owner: Owner) -> Vec<Root<'b>> {
        let sources = self.sources;
        let mut roots = Vec::new();
        let read = |addr: u64, ty: BundleTypeId| -> Option<Value<'b>> {
            let ty = self.types.view.ty(ty)?;
            (ty.size() > 0)
                .then(|| Value::read(self.proc, ty, addr).ok())
                .flatten()
        };
        match owner {
            Owner::Task { index, .. } => {
                if let Some(wait) = sources.analysis.waits.get(index) {
                    let n = wait.frames.len();
                    for (i, key) in wait.frames.iter().enumerate() {
                        if let Some(value) = read(key.addr, key.ty) {
                            roots.push(Root {
                                at: SlotRoot::Frame {
                                    task: index,
                                    frame: n - 1 - i,
                                },
                                value,
                            });
                        }
                    }
                }
            }
            Owner::Child { set, child } => {
                if let Some(root) = sources
                    .census
                    .sets
                    .get(set)
                    .and_then(|s| s.children.get(child))
                    .and_then(|c| c.root)
                    && let Some(value) = read(root.addr, root.ty)
                {
                    roots.push(Root {
                        at: SlotRoot::Child {
                            set,
                            child,
                            addr: root.addr,
                        },
                        value,
                    });
                }
            }
        }
        for &i in self.finds.get(&OwnerKey::from(owner)).into_iter().flatten() {
            let held = &sources.census.held[i];
            if let Some(value) = read(held.addr, held.ty) {
                roots.push(Root {
                    at: SlotRoot::Find {
                        index: i,
                        addr: held.addr,
                    },
                    value,
                });
            }
        }
        order_roots(&mut roots);
        roots
    }

    /// Rule 2: the innermost root whose storage holds the hit, walked
    /// down to it. `Ok(None)` where no root holds it.
    fn by_containment(&self, hit: &Hit, roots: &[Root<'b>]) -> Result<Option<Attribution>, Stale> {
        // The roots come innermost first.
        let containing = roots.iter().find(|r| contains(r.value, hit.slot));
        let Some(root) = containing else {
            return Ok(None);
        };
        match self.locate_member(root.value, hit.slot - root.value.addr) {
            Located::Slot { trail, validity } => Ok(Some(self.name_slot(
                root.path(trail.iter().map(|s| s.name.clone()).collect(), None),
                &trail,
                validity,
            ))),
            Located::Stale(reason) => Err(Stale {
                // Filled in by the caller, which knows the index.
                hit: 0,
                slot: hit.slot,
                owner: hit.owner.expect("an admitted hit has an owner"),
                root: root.at,
                reason,
            }),
        }
    }

    /// Rule 3: a pointer member of one of the owner's roots whose
    /// target lies in the allocation holding the hit — the buffer the
    /// allocator index bounds, or, with no index, the pointee's own
    /// extent — corroborates decoding the pointee down to the hit.
    fn by_hop(
        &self,
        hit: &Hit,
        roots: &[Root<'b>],
        pointers: &[PointerMember],
    ) -> Option<Attribution> {
        let buffer = self
            .sources
            .heap
            .and_then(|heap| match heap.locate(hit.slot) {
                Liveness::Live { buffer, .. } => Some(buffer),
                _ => None,
            });
        // Candidates: pointers into the buffer, or — without one — any
        // pointer at or below the slot, cut to those whose pointee
        // reaches it.
        let (lo, hi) = match &buffer {
            Some(buffer) => (buffer.start, buffer.end),
            None => (hit.slot.saturating_sub(1 << 20), hit.slot + 1),
        };
        let from = pointers.partition_point(|p| p.target < lo);
        for p in &pointers[from..] {
            if p.target >= hi {
                break;
            }
            if hit.slot < p.target {
                continue;
            }
            let Some(pointee) = self.types.view.ty(p.pointee) else {
                continue;
            };
            if hit.slot - p.target >= pointee.size() {
                continue;
            }
            let Ok(value) = Value::read(self.proc, pointee, p.target) else {
                continue;
            };
            let Located::Slot { trail, validity } = self.locate_member(value, hit.slot - p.target)
            else {
                continue;
            };
            let root = &roots[p.root];
            let steps = self.steps_to(root.value, p.at - root.value.addr);
            return Some(self.name_slot(
                root.path(
                    steps,
                    Some(Hop {
                        addr: p.target,
                        pointee: pointee.name().to_string(),
                        pointee_ty: pointee.id(),
                        steps: trail.iter().map(|s| s.name.clone()).collect(),
                    }),
                ),
                &trail,
                validity,
            ));
        }
        None
    }

    /// Name a located slot: the owner-name table over the aggregates
    /// on its trail, outermost first, else the innermost aggregate
    /// that is not a wrapper.
    fn name_slot(&self, path: SlotPath, trail: &[Step<'b>], validity: Validity) -> Attribution {
        let impls = self.sources.impls;
        for (i, step) in trail.iter().enumerate() {
            let name = step.holder.ty.name();
            let under = |member: &str| trail[i..].iter().any(|s| s.name == member);
            let kind = if name.starts_with("tokio::sync::oneshot::Inner<") {
                if under("rx_task") {
                    Some((OwnerKind::OneshotRx, step.holder.addr))
                } else if under("tx_task") {
                    Some((OwnerKind::OneshotTx, step.holder.addr))
                } else {
                    None
                }
            } else if name.starts_with("tokio::sync::mpsc::chan::Chan<") {
                Some((OwnerKind::Mpsc, step.holder.addr))
            } else if name.starts_with("tokio::sync::notify::Notified<")
                || name == "tokio::sync::notify::Notified"
            {
                let notify = step
                    .holder
                    .try_member("notify")
                    .ok()
                    .flatten()
                    .and_then(|m| m.parse::<u64>(self.proc).ok());
                notify.map(|notify| (OwnerKind::Notify, notify))
            } else {
                None
            };
            if let Some((kind, primitive)) = kind {
                return Attribution::Owner {
                    kind,
                    primitive,
                    holder: short_name(name),
                    member: step.name.clone(),
                    path,
                    validity,
                };
            }
        }
        let waker_size = trail.last().map(|s| s.holder.ty.size()).unwrap_or(16);
        let innermost = trail
            .iter()
            .rev()
            .find(|s| {
                let name = s.holder.ty.name();
                s.holder.ty.size() > waker_size && !WRAPPERS.iter().any(|w| name.starts_with(w))
            })
            .or(trail.first());
        let (holder, member) = match innermost {
            Some(step) => (
                outer_path(&fold_type_name(step.holder.ty.name(), impls)),
                step.name.clone(),
            ),
            None => ("?".to_string(), "?".to_string()),
        };
        Attribution::Typed {
            holder,
            member,
            path,
            validity,
        }
    }

    /// Walk `value` down to the `Waker` at `offset`, by the bundle's
    /// facts alone: a struct's member holding the offset, an enum's
    /// active variant (an offset in an inactive one is stale), a
    /// coroutine's initialized locals (an offset in a dead one is
    /// stale), a `MaybeUninit`'s `value`, an array's element. Ends at a
    /// `Waker` at the offset, or at something that is not one.
    fn locate_member(&self, value: Value<'b>, offset: u64) -> Located<'b> {
        match self.descend(value, offset, Terminal::Waker) {
            Ok(Descent {
                trail,
                crossed_option,
                crossed_union,
            }) => Located::Slot {
                trail,
                validity: if crossed_union {
                    Validity::Unchecked
                } else if crossed_option {
                    Validity::SelfDescribing
                } else {
                    Validity::Raw
                },
            },
            Err(reason) => Located::Stale(reason),
        }
    }

    /// The member steps from `value` to the pointer word at `offset` —
    /// the path of a pointer the enumeration recorded by address.
    fn steps_to(&self, value: Value<'b>, offset: u64) -> Vec<String> {
        match self.descend(value, offset, Terminal::Pointer) {
            Ok(descent) => descent.trail.into_iter().map(|s| s.name).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The one offset walk: member by member to `terminal` at
    /// `offset`, or the reason the storage there is no current value.
    fn descend(
        &self,
        value: Value<'b>,
        offset: u64,
        terminal: Terminal,
    ) -> Result<Descent<'b>, StaleReason> {
        let mut cur = value;
        let mut offset = offset;
        let mut descent = Descent {
            trail: Vec::new(),
            crossed_option: false,
            crossed_union: false,
        };
        let not_a_waker = Err(StaleReason::NotAWaker);
        for _ in 0..MAX_DEPTH {
            let ty = cur.ty;
            let name = ty.name();
            let at_terminal = match terminal {
                Terminal::Waker => name == WAKER || name == RAW_WAKER,
                Terminal::Pointer => matches!(ty.classify(), TypeClass::Pointer { .. }),
            };
            if at_terminal {
                return match offset {
                    0 => Ok(descent),
                    _ => not_a_waker,
                };
            }
            let step = |trail: &mut Vec<Step<'b>>, name: String, holder: Value<'b>| {
                trail.push(Step { name, holder });
            };
            match ty.classify() {
                TypeClass::Struct => {
                    let Some(m) = ty.members().find(|m| {
                        let size = m.ty().size();
                        size > 0 && m.offset() <= offset && offset < m.offset() + size
                    }) else {
                        return not_a_waker;
                    };
                    let Some(next) = sub(cur, m.offset(), m.ty()) else {
                        return not_a_waker;
                    };
                    step(&mut descent.trail, m.name().to_string(), cur);
                    offset -= m.offset();
                    cur = next;
                }
                TypeClass::Union => {
                    // `MaybeUninit<T> { uninit: (), value: ManuallyDrop<T> }`:
                    // the one union the walk enters, through the member
                    // that spells the storage as a value.
                    let Some(m) = ty
                        .members()
                        .find(|m| m.name() == "value" && m.ty().size() > 0)
                    else {
                        return not_a_waker;
                    };
                    if offset < m.offset() || offset >= m.offset() + m.ty().size() {
                        return not_a_waker;
                    }
                    let Some(next) = sub(cur, m.offset(), m.ty()) else {
                        return not_a_waker;
                    };
                    descent.crossed_union = true;
                    step(&mut descent.trail, m.name().to_string(), cur);
                    offset -= m.offset();
                    cur = next;
                }
                TypeClass::RustEnum => {
                    let Some(Ok(active)) = ty.active_variant(cur.bytes) else {
                        return not_a_waker;
                    };
                    let payload = active.ty;
                    let in_active = payload.size() > 0
                        && active.offset <= offset
                        && offset < active.offset + payload.size();
                    if !in_active {
                        // The discriminant itself, or another variant's
                        // storage: either way no current value.
                        return Err(StaleReason::InactiveVariant);
                    }
                    let Some(next) = sub(cur, active.offset, payload) else {
                        return not_a_waker;
                    };
                    if name.starts_with("core::option::Option<") {
                        descent.crossed_option = true;
                    }
                    // A coroutine's payload is its locals; the active
                    // state says which are initialized.
                    if ty.is_coroutine() {
                        let inner = offset - active.offset;
                        match self.local_liveness(ty, active.name, payload, inner) {
                            LocalLiveness::Live => {}
                            LocalLiveness::Uncertain => descent.crossed_union = true,
                            LocalLiveness::Dead => return Err(StaleReason::DeadLocal),
                        }
                    }
                    step(&mut descent.trail, variant_step(active.name), cur);
                    offset -= active.offset;
                    cur = next;
                }
                TypeClass::Array { element, count } => {
                    let size = element.size();
                    if size == 0 {
                        return not_a_waker;
                    }
                    let index = offset / size;
                    if index >= count {
                        return not_a_waker;
                    }
                    let Some(next) = sub(cur, index * size, element) else {
                        return not_a_waker;
                    };
                    step(&mut descent.trail, "[]".to_string(), cur);
                    offset -= index * size;
                    cur = next;
                }
                _ => return not_a_waker,
            }
        }
        not_a_waker
    }

    /// Whether the local of coroutine `ty`'s state `variant` that holds
    /// `offset` within `payload` is one the state initializes.
    fn local_liveness(
        &self,
        ty: BundleType<'b>,
        variant: &str,
        payload: BundleType<'b>,
        offset: u64,
    ) -> LocalLiveness {
        let Some(layout) = self
            .types
            .type_semantics(ty.id())
            .and_then(|record| record.coroutine.as_ref())
        else {
            return LocalLiveness::Live;
        };
        let Some(state) = layout
            .states
            .iter()
            .find(|s| self.types.view.str(s.variant) == Some(variant))
        else {
            return LocalLiveness::Live;
        };
        let Some(local) = payload.members().find(|m| {
            let size = m.ty().size();
            size > 0 && m.offset() <= offset && offset < m.offset() + size
        }) else {
            return LocalLiveness::Dead;
        };
        let named = |names: &[hansei_bundle::StrRef]| {
            names
                .iter()
                .any(|n| self.types.view.str(*n) == Some(local.name()))
        };
        if named(&state.locals) {
            LocalLiveness::Live
        } else if named(&state.uncertain_locals) {
            LocalLiveness::Uncertain
        } else {
            LocalLiveness::Dead
        }
    }

    /// Every pointer member of every root, sorted by target and then
    /// by root, innermost first: structs descended, enums through
    /// their active variant (a coroutine's through its initialized
    /// locals), unions and arrays stopped at, null and fat pointers
    /// left out.
    fn pointer_members(&self, roots: &[Root<'b>]) -> Vec<PointerMember> {
        let mut out = Vec::new();
        for (index, root) in roots.iter().enumerate() {
            self.collect_pointers(root.value, index, 0, &mut out);
        }
        out.sort_by_key(|p| (p.target, p.root));
        out
    }

    fn collect_pointers(
        &self,
        value: Value<'b>,
        root: usize,
        depth: usize,
        out: &mut Vec<PointerMember>,
    ) {
        if depth >= MAX_DEPTH {
            return;
        }
        let ty = value.ty;
        match ty.classify() {
            TypeClass::Pointer { target } => {
                if ty.dyn_pointer().is_some() || target.size() == 0 {
                    return;
                }
                let Ok(addr) = value.parse::<u64>(self.proc) else {
                    return;
                };
                if addr == 0 {
                    return;
                }
                out.push(PointerMember {
                    target: addr,
                    pointee: target.id(),
                    root,
                    at: value.addr,
                });
            }
            TypeClass::Struct => {
                for m in ty.members() {
                    if m.ty().size() == 0 {
                        continue;
                    }
                    let Some(next) = sub(value, m.offset(), m.ty()) else {
                        continue;
                    };
                    self.collect_pointers(next, root, depth + 1, out);
                }
            }
            TypeClass::RustEnum => {
                let Some(Ok(active)) = ty.active_variant(value.bytes) else {
                    return;
                };
                let Some(next) = sub(value, active.offset, active.ty) else {
                    return;
                };
                if ty.is_coroutine() {
                    // Only the locals the state initializes: a pointer
                    // in a dead local is a value the program discarded.
                    let live = self.live_locals(ty, active.name);
                    for m in active.ty.members() {
                        if m.ty().size() == 0 || !live.as_ref().is_none_or(|l| l.contains(m.name()))
                        {
                            continue;
                        }
                        let Some(local) = sub(next, m.offset(), m.ty()) else {
                            continue;
                        };
                        self.collect_pointers(local, root, depth + 2, out);
                    }
                } else {
                    self.collect_pointers(next, root, depth + 1, out);
                }
            }
            _ => {}
        }
    }

    /// The locals coroutine `ty`'s state `variant` initializes, where
    /// the bundle records the layout; `None` admits every member.
    fn live_locals(&self, ty: BundleType<'b>, variant: &str) -> Option<HashSet<&'b str>> {
        let layout = self
            .types
            .type_semantics(ty.id())
            .and_then(|record| record.coroutine.as_ref())?;
        let state = layout
            .states
            .iter()
            .find(|s| self.types.view.str(s.variant) == Some(variant))?;
        Some(
            state
                .locals
                .iter()
                .chain(&state.uncertain_locals)
                .filter_map(|n| self.types.view.str(*n))
                .collect(),
        )
    }
}

enum LocalLiveness {
    Live,
    Uncertain,
    Dead,
}

/// What a oneshot's state word says about a task slot.
enum Gate {
    Set(&'static str),
    Clear,
    /// The word could not be read: the role is unbound, or the slot
    /// was not reached through the `Arc`.
    Unread,
}

/// The bits of `tokio::sync::oneshot::State`: a waker stored in
/// `rx_task`, and one in `tx_task`.
const ONESHOT_RX_TASK_SET: u64 = 0b0001;
const ONESHOT_TX_TASK_SET: u64 = 0b1000;

/// A variant step's name: `<Some>`, so a path reads apart from a
/// member named the same.
fn variant_step(name: &str) -> String {
    format!("<{name}>")
}

/// Innermost first: a smaller value before a larger one, a find before
/// a frame of the same size (the find is what the listings name), an
/// inner frame before an outer. Wrapper frames that share one
/// allocation with what they wrap are one range each and are walked
/// once.
fn order_roots(roots: &mut Vec<Root<'_>>) {
    let rank = |root: &Root<'_>| match root.at {
        SlotRoot::Find { .. } | SlotRoot::Child { .. } => 0,
        SlotRoot::Frame { frame, .. } => 1 + frame,
    };
    roots.sort_by_key(|r| (r.value.bytes.len(), rank(r)));
    roots.dedup_by_key(|r| (r.value.addr, r.value.bytes.len()));
}

/// The `ty`-typed view at `offset` within `value`, or `None` where the
/// bytes do not cover it.
fn sub<'b>(value: Value<'b>, offset: u64, ty: BundleType<'b>) -> Option<Value<'b>> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(ty.size()).ok()?)?;
    let bytes = value.bytes.get(start..end)?;
    Some(Value::new(ty, value.addr + offset, bytes))
}

/// Whether `addr` lies in `value`'s storage.
fn contains(value: Value<'_>, addr: u64) -> bool {
    addr >= value.addr && addr - value.addr < value.bytes.len() as u64
}

/// A type's last path segment, generic arguments dropped: `Inner`,
/// `Chan`, `Notified`.
fn short_name(name: &str) -> String {
    let base = name.split('<').next().unwrap_or(name);
    base.rsplit("::").next().unwrap_or(base).to_string()
}

/// Rule 4's answer: what the allocator index says about the buffer.
fn unknown(slot: u64, heap: Option<&UmemHeap>) -> Attribution {
    match heap.map(|heap| (heap, heap.locate(slot))) {
        Some((heap, Liveness::Live { buffer, source })) => Attribution::Unknown {
            cache: match source {
                Source::Cache(i) => heap.caches().get(i).map(|c| c.name.clone()),
                Source::Arena(_) => None,
            },
            size: Some(buffer.end - buffer.start),
            offset: Some(slot - buffer.start),
        },
        _ => Attribution::Unknown {
            cache: None,
            size: None,
            offset: None,
        },
    }
}

/// Every pair a registry or the analysis decoded, by its address.
fn registry_map(registries: &Registries, analysis: &Analysis) -> HashMap<u64, RegistrySlot> {
    let mut map = HashMap::default();
    for timer in &registries.timers {
        let TimerEntryInfo {
            entry,
            deadline,
            waker_at: Some(at),
            ..
        } = timer
        else {
            continue;
        };
        map.insert(
            *at,
            RegistrySlot::Timer {
                entry: *entry,
                state: timer.wheel_state(),
                deadline: *deadline,
            },
        );
    }
    for resource in &registries.io {
        let IoResourceInfo { addr, waiters, .. } = resource;
        for waiter in waiters {
            let IoWaiterInfo {
                slot,
                waker_at: Some(at),
                ..
            } = waiter
            else {
                continue;
            };
            map.insert(
                *at,
                RegistrySlot::Io {
                    resource: *addr,
                    slot: *slot,
                    ready: resource.ready(),
                },
            );
        }
    }
    for join in &analysis.join_wakers {
        if let Some(at) = join.waker_at {
            map.insert(at, RegistrySlot::Join { task: join.task });
        }
    }
    for wait in &analysis.waits {
        let Some(WaitTarget::Semaphore { addr, waiters, .. }) = wait.verified().map(|v| v.target())
        else {
            continue;
        };
        for node in waiters {
            if let Some(at) = node.waker_at {
                map.insert(
                    at,
                    RegistrySlot::Semaphore {
                        semaphore: *addr,
                        node: node.addr,
                    },
                );
            }
        }
    }
    map
}

/// An owner without the task header, for keying what is known by
/// index alone.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
enum OwnerKey {
    Task(usize),
    Child(usize, usize),
}

impl From<Owner> for OwnerKey {
    fn from(owner: Owner) -> Self {
        match owner {
            Owner::Task { index, .. } => OwnerKey::Task(index),
            Owner::Child { set, child } => OwnerKey::Child(set, child),
        }
    }
}

/// The held finds under each owner: a task's own, and those under
/// each set child.
fn finds_by_owner(census: &FutureCensus) -> HashMap<OwnerKey, Vec<usize>> {
    let mut map: HashMap<OwnerKey, Vec<usize>> = HashMap::default();
    for (i, held) in census.held.iter().enumerate() {
        // A find nested under another held find belongs to whoever
        // that one belongs to, all the way up.
        let mut via = held.via;
        let owner = loop {
            match via {
                Some(Via::SetChild { set, child }) => break OwnerKey::Child(set, child),
                Some(Via::Held(outer)) => via = census.held[outer].via,
                None => break OwnerKey::Task(held.owner),
            }
        };
        map.entry(owner).or_default().push(i);
    }
    map
}

/// The reader's spelling a slot should carry, where a task's own
/// assessment accounts for it: a verified wait whose primitive or
/// resource holds the slot, or a wait-set member armed by the same
/// registry slot or verified over the storage holding it. `None`
/// leaves the slot its bare spelling.
pub fn accounted_by(
    wait: &TaskWait,
    slot: &AttributedSlot,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> Option<(String, String)> {
    use super::assess::WaitAssessment;
    use super::waitset::SlotRef;

    let within = |key: ValueKey, addr: u64| {
        addr >= key.addr && addr - key.addr < size_of(key.ty).unwrap_or(0)
    };
    let verified_accounts = |verified: &super::assess::VerifiedWait| -> bool {
        let target = verified.target();
        match (&slot.attribution, target) {
            (
                Attribution::Registry(RegistrySlot::Timer { entry, .. }),
                WaitTarget::Timer { .. },
            ) => within(verified.primitive(), *entry),
            (
                Attribution::Registry(RegistrySlot::Io { resource, .. }),
                WaitTarget::Io { addr, .. },
            ) => resource == addr,
            (Attribution::Registry(RegistrySlot::Join { task }), WaitTarget::Task { addr, .. }) => {
                task.addr.0 == *addr
            }
            (
                Attribution::Registry(RegistrySlot::Semaphore { semaphore, .. }),
                WaitTarget::Semaphore { addr, .. },
            ) => semaphore == addr,
            (Attribution::Owner { primitive, .. }, WaitTarget::Channel { addr, .. }) => {
                primitive == addr
            }
            (Attribution::Owner { primitive, .. }, WaitTarget::Notify { addr, .. }) => {
                primitive == addr
            }
            (Attribution::Owner { .. } | Attribution::Typed { .. }, _) => {
                within(verified.primitive(), slot.slot)
            }
            _ => false,
        }
    };
    match &wait.assessment {
        WaitAssessment::Waiting(verified) if verified_accounts(verified) => Some((
            verified.target().to_string(),
            verified.target().group_label(),
        )),
        WaitAssessment::Set(set) => set.members.iter().find_map(|member| {
            let armed = member.armed.as_ref()?;
            let by_registry = match (&slot.attribution, armed) {
                (
                    Attribution::Registry(RegistrySlot::Timer { entry, .. }),
                    SlotRef::Wheel { entry: at, .. },
                ) => entry == at,
                (
                    Attribution::Registry(RegistrySlot::Io { resource, .. }),
                    SlotRef::Io { resource: at, .. },
                ) => resource == at,
                _ => false,
            };
            let by_protocol = match &member.assessment {
                Some(WaitAssessment::Waiting(verified)) => verified_accounts(verified),
                _ => false,
            };
            (by_registry || by_protocol)
                .then(|| Some((member.cell_entry()?, member.kind()?)))
                .flatten()
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, load_any};
    use crate::tokio::bundle::{FutureInfo, Task};
    use crate::tokio::graph::analyze;
    use crate::tokio::observe::ReadContext;
    use crate::tokio::wakers::Territory;

    use proc::snapshot::Snapshot;

    /// Everything the attribution reads over one fixture pair, built
    /// the way a session builds it.
    struct Over<'b> {
        ctx: Context<'b, Snapshot>,
        e: testkit::Enumeration<'b>,
        census: FutureCensus,
        wakers: WakerSlots,
        analysis: Analysis,
        impls: ImplFold,
    }

    impl<'b> Over<'b> {
        fn new(bundle: &'b hansei_bundle::Bundle, snapshot: &'b Snapshot) -> Self {
            let ctx = testkit::context(bundle, snapshot);
            let mut e = testkit::enumerate(&ctx, snapshot);
            e.discover(&ctx, &[]);
            let extents = ctx.task_extents(&e.list);
            let census = testkit::census(&ctx, &e.list);
            let wakers = ctx.sweep_wakers(&Territory {
                list: &e.list,
                extents: &extents,
                census: &census,
                heap: e.heap.as_ref(),
                lwps: &e.lwps,
            });
            let analysis = analyze(&ctx, &e.list, &e.registries, &ReadContext::none());
            Over {
                ctx,
                e,
                census,
                wakers,
                analysis,
                impls: ImplFold::default(),
            }
        }

        fn attribute(&self) -> Attributed {
            self.ctx.attribute_slots(
                &self.wakers,
                &Sources {
                    list: &self.e.list,
                    census: &self.census,
                    registries: &self.e.registries,
                    analysis: &self.analysis,
                    heap: self.e.heap.as_ref(),
                    impls: &self.impls,
                },
            )
        }

        fn task(&self, name: &str) -> &Task {
            self.e
                .list
                .tasks
                .iter()
                .find(
                    |t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)),
                )
                .unwrap_or_else(|| panic!("a task named {name}"))
        }
    }

    /// The index over one fixture pair: the slots of the task named
    /// `name`, in slot order.
    fn slots_of<'a>(
        attributed: &'a Attributed,
        over: &Over<'_>,
        name: &str,
    ) -> Vec<&'a AttributedSlot> {
        attributed.of_task(over.task(name).addr.0).collect()
    }

    /// Over `armed-select`: the selector's four branches are four slots,
    /// each named by what holds it — the oneshot's `rx_task` reached
    /// through the `Receiver` find's `Arc`, the channel's receiver slot
    /// through the frame's `Arc`, the watch's `Notified` node inside the
    /// held `changed_impl`, and the wheel entry the registry decoded.
    /// The holder's one slot is its oneshot's; the waiter's node lies
    /// in its own frame; the driver's waker sits in the set's ready
    /// queue, named by the `AtomicWaker` holding it. The `Receiver`
    /// find is armed by the slot reached through it; the unpolled
    /// `Notified` the holder keeps is not.
    #[test]
    fn test_armed_select_slots_are_named_by_what_holds_them() {
        let (bundle, snapshot) = load_any("armed-select");
        let over = Over::new(&bundle, &snapshot);
        let attributed = over.attribute();
        assert!(attributed.stale.is_empty(), "{:#?}", attributed.stale);
        assert_eq!(attributed.audit(&over.e.list), Vec::<String>::new());
        let stopped = over.e.registries.stopped;

        let selector = slots_of(&attributed, &over, "selector");
        assert_eq!(selector.len(), 4, "{selector:#?}");
        let mut buckets: Vec<String> = selector.iter().map(|s| s.bucket()).collect();
        buckets.sort();
        // The watch's `Notified` reads as a bare `notify` here: the
        // snapshot holds no bytes of the `Shared` its `Notify` lies
        // in, so the watch row cannot fire over a fixture pair.
        assert_eq!(buckets, ["mpsc", "notify", "oneshot rx", "timer"]);
        for slot in &selector {
            match &slot.attribution {
                Attribution::Owner {
                    kind: OwnerKind::OneshotRx,
                    holder,
                    member,
                    path,
                    validity,
                    primitive,
                } => {
                    assert_eq!((holder.as_str(), member.as_str()), ("Inner", "rx_task"));
                    // `MaybeUninit` under the state word, whose bit for
                    // the receiver's slot is set.
                    assert_eq!(*validity, Validity::Gated("rx_task_set"));
                    // Through the `Receiver` find's `inner`, not the
                    // frame that holds the find.
                    assert!(matches!(path.root, SlotRoot::Find { .. }), "{path:?}");
                    assert_eq!(path.steps, ["inner", "<Some>", "__0", "ptr", "pointer"]);
                    let hop = path.hop.as_ref().expect("a hop");
                    assert!(
                        hop.pointee
                            .starts_with("alloc::sync::ArcInner<tokio::sync::oneshot::Inner<")
                    );
                    assert_eq!(hop.steps[..2], ["data", "rx_task"]);
                    // The primitive is the `Inner`, past the `ArcInner`
                    // header.
                    assert!(*primitive > hop.addr && *primitive - hop.addr <= 16);
                    assert_eq!(slot.entry(stopped), format!("oneshot rx {primitive:#x}"));
                    assert!(
                        slot.detail(stopped).starts_with(
                            "waker in Inner.rx_task (rx_task_set), reached from the future at 0x"
                        ),
                        "{}",
                        slot.detail(stopped)
                    );
                }
                Attribution::Owner {
                    kind: OwnerKind::Mpsc,
                    holder,
                    member,
                    path,
                    validity,
                    ..
                } => {
                    assert_eq!((holder.as_str(), member.as_str()), ("Chan", "rx_waker"));
                    assert_eq!(*validity, Validity::SelfDescribing);
                    assert!(
                        matches!(path.root, SlotRoot::Frame { frame: 1, .. }),
                        "{path:?}"
                    );
                    assert_eq!(path.steps[..3], ["<3>", "queue", "chan"]);
                    assert!(path.hop.is_some());
                }
                Attribution::Owner {
                    kind: OwnerKind::Notify,
                    holder,
                    member,
                    path,
                    validity,
                    primitive,
                } => {
                    assert_eq!((holder.as_str(), member.as_str()), ("Notified", "waiter"));
                    assert_eq!(*validity, Validity::SelfDescribing);
                    assert_eq!(slot.entry(stopped), format!("notify {primitive:#x}"));
                    // Inside the held `changed_impl` — the innermost of
                    // the two finds holding it — by containment: its
                    // active state's awaitee is the `Notified`.
                    let SlotRoot::Find { index, .. } = path.root else {
                        panic!("{path:?}");
                    };
                    assert_eq!(over.census.held[index].local, "fut");
                    assert!(path.hop.is_none());
                    assert_eq!(path.steps[1..4], ["__awaitee", "waiter", "waker"]);
                }
                Attribution::Registry(RegistrySlot::Timer { entry, .. }) => {
                    let timer = over
                        .e
                        .registries
                        .timers_of(over.task("selector").addr.0)
                        .next()
                        .expect("the selector's wheel entry");
                    assert_eq!(*entry, timer.entry);
                    assert_eq!(Some(slot.slot), timer.waker_at);
                    // Inside the `Sleep` find, which it arms.
                    assert!(
                        matches!(slot.within, Some(SlotRoot::Find { .. })),
                        "{slot:?}"
                    );
                    assert!(slot.entry(stopped).starts_with("timer (deadline "));
                    assert_eq!(slot.label(), format!("timer {entry:#x}"));
                }
                other => panic!("{other:?}"),
            }
        }

        let holder = slots_of(&attributed, &over, "holder");
        assert_eq!(holder.len(), 1, "{holder:#?}");
        let Attribution::Owner {
            kind: OwnerKind::OneshotRx,
            path,
            ..
        } = &holder[0].attribution
        else {
            panic!("{:?}", holder[0]);
        };
        // The `Receiver` is the chain's leaf frame, not a find.
        assert!(
            matches!(path.root, SlotRoot::Frame { frame: 0, .. }),
            "{path:?}"
        );

        let waiter = slots_of(&attributed, &over, "waiter");
        assert_eq!(waiter.len(), 1, "{waiter:#?}");
        let Attribution::Owner {
            kind: OwnerKind::Notify,
            path,
            primitive,
            ..
        } = &waiter[0].attribution
        else {
            panic!("{:?}", waiter[0]);
        };
        assert!(
            matches!(path.root, SlotRoot::Frame { frame: 0, .. }),
            "{path:?}"
        );
        assert_eq!(waiter[0].entry(stopped), format!("notify {primitive:#x}"));
        assert_eq!(
            waiter[0].detail(stopped),
            "waker in Notified.waiter, in #0 waiter → waker"
        );

        let driver = slots_of(&attributed, &over, "driver");
        assert_eq!(driver.len(), 1, "{driver:#?}");
        let Attribution::Typed {
            holder: holds,
            member,
            path,
            ..
        } = &driver[0].attribution
        else {
            panic!("{:?}", driver[0]);
        };
        assert!(holds.ends_with("AtomicWaker"), "{holds}");
        assert_eq!(member, "waker");
        assert!(path.hop.is_some());
        assert_eq!(
            driver[0].entry(stopped),
            format!("slot {:#x} in {holds}", driver[0].slot)
        );
        assert_eq!(driver[0].bucket(), format!("slot in {holds}"));
        assert_eq!(driver[0].label(), format!("slot {:#x}", driver[0].slot));

        // The finds: the `Receiver` armed through its pointer, the
        // unpolled `Notified` not.
        let find = |local: &str| {
            over.census
                .held
                .iter()
                .position(|h| h.local == local)
                .unwrap_or_else(|| panic!("a find in `{local}`"))
        };
        assert!(attributed.find_armed(find("once")));
        assert!(attributed.find_armed(find("sleep")));
        assert_eq!(attributed.of_find(find("once")).count(), 1);
        assert!(!attributed.find_armed(find("notified")));
        assert!(attributed.at(holder[0].slot).is_some());
        assert!(attributed.at(holder[0].slot + 8).is_none());
        assert_eq!(attributed.stats.owner, 5);
        assert_eq!(attributed.stats.registry, 1);
        assert_eq!(attributed.stats.typed, 1);
        assert_eq!(attributed.stats.unknown, 0);
    }

    /// Over `sleep-join`: both slots are the registries' — the sleeper's
    /// wheel entry and the joiner's waker in the sleeper's trailer —
    /// and each takes its reader's spelling where the task's verified
    /// wait accounts for it.
    #[test]
    fn test_registry_slots_take_the_readers_spelling() {
        let (bundle, snapshot) = load_any("sleep-join");
        let over = Over::new(&bundle, &snapshot);
        let attributed = over.attribute();
        let size_of = |ty: BundleTypeId| over.ctx.view.ty(ty).map(|t| t.size());
        let sleeper = over.task("sleeper");
        let joiner = over
            .e
            .list
            .tasks
            .iter()
            .find(|t| t.addr != sleeper.addr && matches!(t.future, FutureInfo::Known(_)))
            .expect("the joiner");
        let index = |task: &Task| {
            over.e
                .list
                .tasks
                .iter()
                .position(|t| t.addr == task.addr)
                .unwrap()
        };

        let slots: Vec<&AttributedSlot> = attributed.of_task(sleeper.addr.0).collect();
        assert_eq!(slots.len(), 1, "{slots:#?}");
        assert!(matches!(
            slots[0].attribution,
            Attribution::Registry(RegistrySlot::Timer { .. })
        ));
        let wait = &over.analysis.waits[index(sleeper)];
        let (entry, bucket) = accounted_by(wait, slots[0], &size_of).expect("the verified timer");
        assert!(entry.starts_with("timer (deadline "), "{entry}");
        assert_eq!(bucket, "timer");

        let slots: Vec<&AttributedSlot> = attributed.of_task(joiner.addr.0).collect();
        assert_eq!(slots.len(), 1, "{slots:#?}");
        let Attribution::Registry(RegistrySlot::Join { task }) = &slots[0].attribution else {
            panic!("{:?}", slots[0]);
        };
        assert_eq!(task.addr, sleeper.addr);
        assert_eq!(slots[0].detail(None), "waker in its trailer");
        let wait = &over.analysis.waits[index(joiner)];
        let (entry, bucket) = accounted_by(wait, slots[0], &size_of).expect("the verified join");
        assert_eq!(entry, format!("task {}", sleeper.task_id.unwrap()));
        assert_eq!(bucket, entry);
        // A slot the wait does not account for keeps its own spelling.
        let other = attributed.of_task(sleeper.addr.0).next().unwrap();
        assert_eq!(accounted_by(wait, other, &size_of), None);
    }

    /// Over `channels`: every slot is an owner-table slot — the oneshot's
    /// receiver, the channel's receiver, the `Notify` node — and the
    /// oneshot names a primitive the `Receiver`'s `inner` points into.
    #[test]
    fn test_channels_slots_name_their_primitives() {
        let (bundle, snapshot) = load_any("channels");
        let over = Over::new(&bundle, &snapshot);
        let attributed = over.attribute();
        let mut kinds: Vec<OwnerKind> = attributed
            .slots
            .iter()
            .map(|s| match &s.attribution {
                Attribution::Owner { kind, .. } => *kind,
                other => panic!("{other:?}"),
            })
            .collect();
        kinds.sort_by_key(|k| k.word());
        assert_eq!(
            kinds,
            [OwnerKind::Mpsc, OwnerKind::Notify, OwnerKind::OneshotRx]
        );
        assert_eq!(attributed.stats.stale, 0);
    }

    /// The spellings of the slots no fixture holds: an unknown with and
    /// without an allocator's account, and the collapse-free label.
    #[test]
    fn test_unknown_slots_spell_their_allocation() {
        let owner = Owner::Task {
            header: 0x1000,
            index: 0,
        };
        let slot = |attribution| AttributedSlot {
            hit: 0,
            slot: 0x7000,
            owner,
            attribution,
            within: None,
        };
        let known = slot(Attribution::Unknown {
            cache: Some("umem_alloc_96".to_string()),
            size: Some(96),
            offset: Some(48),
        });
        assert_eq!(known.entry(None), "unknown 0x7000");
        assert_eq!(known.label(), "unknown 0x7000");
        assert_eq!(known.bucket(), "unknown");
        assert_eq!(
            known.detail(None),
            "in a 96-byte umem_alloc_96 buffer at +48"
        );
        let bare = slot(Attribution::Unknown {
            cache: None,
            size: None,
            offset: None,
        });
        assert_eq!(bare.detail(None), "in memory nothing typed reaches");
        let arena = slot(Attribution::Unknown {
            cache: None,
            size: Some(4096),
            offset: Some(8),
        });
        assert_eq!(arena.detail(None), "in a 4096-byte allocation at +8");
        let attributed = Attributed::from_slots(vec![known, bare]);
        assert_eq!(attributed.stats.unknown, 2);
        assert_eq!(attributed.of_task(0x1000).count(), 2);
    }
}

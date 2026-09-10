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
    Context, IoResourceInfo, IoSlot, IoWaiterInfo, OneshotSide, OneshotState, Readiness,
    Registries, TaskList, TimerEntryInfo, WaitTarget, WheelState, channel_words, deadline_text,
    notify_words, watch_words,
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
    /// The pointer word's own address, in the value the hop left.
    pub from: u64,
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

/// What a slot's primitive says about itself, read from the words the
/// receiver-rooted roles reach in the value the slot was located in:
/// the detail a cell appends to the kind word and address, so a slot
/// the attributor alone names reads like one a chain leaf's reader
/// names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reading {
    /// The oneshot's state word and value.
    Oneshot(OneshotState),
    /// The channel's sender count, bound and claimed slots.
    Mpsc {
        senders: u64,
        capacity: Option<u64>,
        unread: u64,
    },
    /// The watch channel's version, closed flag and handle counts.
    Watch {
        version: u64,
        closed: bool,
        receivers: u64,
        senders: u64,
    },
    /// The `Notify`'s state word.
    Notify { state: u64 },
}

impl Reading {
    /// The words in a slot entry's parentheses, worded for the side
    /// the slot is on.
    pub fn words(&self, kind: OwnerKind) -> String {
        match self {
            Reading::Oneshot(state) => state.words(match kind {
                OwnerKind::OneshotTx => OneshotSide::Tx,
                _ => OneshotSide::Rx,
            }),
            Reading::Mpsc {
                senders,
                capacity,
                unread,
            } => channel_words(*senders, *capacity, *unread),
            Reading::Watch {
                version,
                closed,
                receivers,
                senders,
            } => watch_words(*version, *closed, *receivers, *senders),
            Reading::Notify { state } => notify_words(Some(*state), None),
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
        /// The primitive's own words, where its roles bound and read.
        reading: Option<Reading>,
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
                kind,
                primitive,
                reading,
                ..
            } => match reading {
                Some(reading) => {
                    format!("{} {primitive:#x} ({})", kind.word(), reading.words(*kind))
                }
                None => format!("{} {primitive:#x}", kind.word()),
            },
            Attribution::Typed { holder, .. } => format!("slot {:#x} in {holder}", self.slot),
            Attribution::Unknown { .. } => format!("unknown {:#x}", self.slot),
        }
    }

    /// The slot's label for a detail line: the kind word and the
    /// address that identifies the slot, whatever a reader would add.
    pub fn label(&self) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer { entry, .. }) => format!("timer {entry:#x}"),
            Attribution::Owner {
                kind, primitive, ..
            } => format!("{} {primitive:#x}", kind.word()),
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
#[derive(Copy, Clone, Debug)]
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
                    reading,
                } => match oneshot_gate(kind, reading.as_ref()) {
                    Gate::Set(bit) => Attribution::Owner {
                        kind,
                        primitive,
                        holder,
                        member,
                        path,
                        validity: Validity::Gated(bit),
                        reading,
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
                        reading,
                    },
                },
                Attribution::Owner {
                    kind: OwnerKind::Notify,
                    primitive,
                    holder,
                    member,
                    path,
                    validity,
                    reading,
                } => {
                    let pointers = pointers.get_or_insert_with(|| self.pointer_members(&roots));
                    match self.watch_of(primitive, pointers) {
                        Some((shared, reading)) => Attribution::Owner {
                            kind: OwnerKind::Watch,
                            primitive: shared,
                            holder,
                            member,
                            path,
                            validity,
                            reading: Some(reading),
                        },
                        None => Attribution::Owner {
                            kind: OwnerKind::Notify,
                            primitive,
                            holder,
                            member,
                            path,
                            validity,
                            reading,
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

    /// A role's word, executed from `root`, where it bound and read.
    fn word_of(&self, role: WalkRole, root: Value<'b>) -> Option<u64> {
        self.walk_role(role, root)?.parse::<u64>(self.proc).ok()
    }

    /// The oneshot's reading, from the `ArcInner<Inner<T>>` value a
    /// slot was reached through: the state word and whether the value
    /// slot holds one.
    fn oneshot_reading(&self, arc: Value<'b>) -> Option<Reading> {
        let word = self.word_of(WalkRole::OneshotState, arc)?;
        let value_present = self
            .walk_role(WalkRole::OneshotValue, arc)
            .and_then(super::bundle::option_present);
        Some(Reading::Oneshot(OneshotState {
            word,
            value_present,
        }))
    }

    /// The channel's reading, from the `Chan` value a slot sits in:
    /// the words the receiver's cell prints beside a `recv`.
    fn mpsc_reading(&self, chan: Value<'b>) -> Option<Reading> {
        let senders = self.word_of(WalkRole::ChanTxCount, chan)?;
        let tail = self.word_of(WalkRole::ChanTailPosition, chan)?;
        let index = self.word_of(WalkRole::ChanRxIndex, chan)?;
        // An unbounded channel has no bound to read.
        let capacity = self.word_of(WalkRole::ChanSemaphoreBound, chan);
        Some(Reading::Mpsc {
            senders,
            capacity,
            unread: tail.saturating_sub(index),
        })
    }

    /// The `Notify`'s reading: its state word, read at the address a
    /// `Notified`'s `notify` member names, as that member's pointee.
    fn notify_reading(&self, notified: Value<'b>) -> Option<Reading> {
        let pointer = notified.try_member("notify").ok().flatten()?;
        let ty = pointer.ty.pointer_target()?;
        let addr = pointer.parse::<u64>(self.proc).ok()?;
        let notify = Value::read(self.proc, ty, addr).ok()?;
        Some(Reading::Notify {
            state: self.word_of(WalkRole::NotifyState, notify)?,
        })
    }

    /// The watch channel's reading, from its `ArcInner<Shared<T>>`.
    fn watch_reading(&self, arc: Value<'b>) -> Option<Reading> {
        use hansei_bundle::tokio::watch;
        let state = self.word_of(WalkRole::WatchSharedState, arc)?;
        Some(Reading::Watch {
            version: state >> watch::VERSION_SHIFT,
            closed: state & watch::CLOSED != 0,
            receivers: self.word_of(WalkRole::WatchSharedRxCount, arc)?,
            senders: self.word_of(WalkRole::WatchSharedTxCount, arc)?,
        })
    }

    /// The watch channel whose `notify_rx` array holds the `Notify` at
    /// `notify`, among the `Arc<watch::Shared<_>>`s the owner's values
    /// point at: the `Shared`'s address, for the slot's primitive, and
    /// the channel's reading. Nothing is dereferenced but the `Shared`
    /// a pointer the owner holds already names.
    fn watch_of(&self, notify: u64, pointers: &[PointerMember]) -> Option<(u64, Reading)> {
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
                let reading = self.watch_reading(arc)?;
                return Some((arc.addr + data, reading));
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
                        from: p.at,
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
                // The `ArcInner` the `Inner` sits in is the step before
                // it on the trail; the receiver-rooted roles read from
                // there.
                let reading = trail[..i]
                    .iter()
                    .rev()
                    .find(|s| s.holder.ty.name().starts_with("alloc::sync::ArcInner<"))
                    .and_then(|arc| self.oneshot_reading(arc.holder));
                if under("rx_task") {
                    Some((OwnerKind::OneshotRx, step.holder.addr, reading))
                } else if under("tx_task") {
                    Some((OwnerKind::OneshotTx, step.holder.addr, reading))
                } else {
                    None
                }
            } else if name.starts_with("tokio::sync::mpsc::chan::Chan<") {
                Some((
                    OwnerKind::Mpsc,
                    step.holder.addr,
                    self.mpsc_reading(step.holder),
                ))
            } else if name.starts_with("tokio::sync::notify::Notified<")
                || name == "tokio::sync::notify::Notified"
            {
                let notify = step
                    .holder
                    .try_member("notify")
                    .ok()
                    .flatten()
                    .and_then(|m| m.parse::<u64>(self.proc).ok());
                notify.map(|notify| (OwnerKind::Notify, notify, self.notify_reading(step.holder)))
            } else {
                None
            };
            if let Some((kind, primitive, reading)) = kind {
                return Attribution::Owner {
                    kind,
                    primitive,
                    holder: short_name(name),
                    member: step.name.clone(),
                    path,
                    validity,
                    reading,
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

/// The oneshot's state word against the bit that says this slot holds
/// a waker: `RX_TASK_SET` for `rx_task`, `TX_TASK_SET` for `tx_task`.
fn oneshot_gate(kind: OwnerKind, reading: Option<&Reading>) -> Gate {
    let Some(Reading::Oneshot(state)) = reading else {
        return Gate::Unread;
    };
    let (set, name) = match kind {
        OwnerKind::OneshotRx => (state.rx_task_set(), "rx_task_set"),
        _ => (state.tx_task_set(), "tx_task_set"),
    };
    if set { Gate::Set(name) } else { Gate::Clear }
}

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

/// Whether a verified wait accounts for a slot: a registry timer inside
/// the verified primitive, a registry io whose resource the target
/// names, a join naming the target task, a semaphore node on the
/// target semaphore, an owner slot whose primitive the `Channel` or
/// `Notify` target names, or any typed slot inside the primitive's
/// bytes.
pub fn verified_accounts(
    verified: &super::assess::VerifiedWait,
    slot: &AttributedSlot,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> bool {
    let within = |key: ValueKey, addr: u64| {
        addr >= key.addr && addr - key.addr < size_of(key.ty).unwrap_or(0)
    };
    match (&slot.attribution, verified.target()) {
        (Attribution::Registry(RegistrySlot::Timer { entry, .. }), WaitTarget::Timer { .. }) => {
            within(verified.primitive(), *entry)
        }
        (Attribution::Registry(RegistrySlot::Io { resource, .. }), WaitTarget::Io { addr, .. }) => {
            resource == addr
        }
        (Attribution::Registry(RegistrySlot::Join { task }), WaitTarget::Task { addr, .. }) => {
            task.addr.0 == *addr
        }
        (
            Attribution::Registry(RegistrySlot::Semaphore { semaphore, .. }),
            WaitTarget::Semaphore { addr, .. },
        ) => semaphore == addr,
        (
            Attribution::Owner {
                kind: OwnerKind::Mpsc,
                primitive,
                ..
            },
            WaitTarget::Channel { addr, .. },
        ) => primitive == addr,
        (
            Attribution::Owner {
                kind: OwnerKind::Notify,
                primitive,
                ..
            },
            WaitTarget::Notify { addr, .. },
        ) => primitive == addr,
        (
            Attribution::Owner {
                kind: OwnerKind::OneshotRx,
                primitive,
                ..
            },
            WaitTarget::Oneshot { addr, .. },
        ) => primitive == addr,
        (
            Attribution::Owner {
                kind: OwnerKind::Watch,
                primitive,
                ..
            },
            WaitTarget::Watch { addr, .. },
        ) => primitive == addr,
        (Attribution::Owner { .. } | Attribution::Typed { .. }, _) => {
            within(verified.primitive(), slot.slot)
        }
        _ => false,
    }
}

/// Whether a wait-set member is armed by a slot: the branch's own
/// storage holds it, the pointer a hop followed lies in the branch,
/// the slot was located from the branch's find, the registry slot
/// that armed the member is this one, or the branch's verified wait
/// accounts for it.
pub fn member_accounts(
    member: &super::waitset::WaitMember,
    slot: &AttributedSlot,
    size_of: &dyn Fn(BundleTypeId) -> Option<u64>,
) -> bool {
    use super::assess::WaitAssessment;
    use super::waitset::SlotRef;

    if let Some(key) = member.key {
        let size = size_of(key.ty).unwrap_or(0);
        let within = |addr: u64| addr >= key.addr && addr - key.addr < size;
        if within(slot.slot) {
            return true;
        }
        if let Some(path) = slot.path() {
            match path.root {
                SlotRoot::Find { addr, .. } | SlotRoot::Child { addr, .. } if addr == key.addr => {
                    return true;
                }
                _ => {}
            }
            if path.hop.as_ref().is_some_and(|hop| within(hop.from)) {
                return true;
            }
        }
        if let Some(SlotRoot::Find { addr, .. }) = slot.within
            && addr == key.addr
        {
            return true;
        }
    }
    let by_registry = match (&slot.attribution, &member.armed) {
        (
            Attribution::Registry(RegistrySlot::Timer { entry, .. }),
            Some(SlotRef::Wheel { entry: at, .. }),
        ) => entry == at,
        (
            Attribution::Registry(RegistrySlot::Io { resource, .. }),
            Some(SlotRef::Io { resource: at, .. }),
        ) => resource == at,
        _ => false,
    };
    by_registry
        || matches!(&member.assessment, Some(WaitAssessment::Waiting(verified))
            if verified_accounts(verified, slot, size_of))
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

    match &wait.assessment {
        WaitAssessment::Waiting(verified) if verified_accounts(verified, slot, size_of) => Some((
            verified.target().to_string(),
            verified.target().group_label(),
        )),
        WaitAssessment::Set(set) => set.members.iter().find_map(|member| {
            member.armed.as_ref()?;
            member_accounts(member, slot, size_of)
                .then(|| Some((member.cell_entry()?, member.kind()?)))
                .flatten()
        }),
        _ => None,
    }
}

impl AttributedSlot {
    /// The slot's detail line: its label, then where it sits and what
    /// says it is current — except a wheel entry, which is spelled by
    /// its deadline, with the wheel's own word appended where the entry
    /// is not simply registered.
    pub fn line(&self, stopped: Option<RawInstant>) -> String {
        if let Attribution::Registry(RegistrySlot::Timer {
            entry,
            state,
            deadline,
        }) = &self.attribution
        {
            let mut line = format!("timer {entry:#x}");
            if let Some(deadline) = deadline {
                line.push(' ');
                line.push_str(&deadline_text(*deadline, stopped));
            }
            if let Some(state) = state
                && *state != WheelState::Registered
            {
                line.push_str(&format!(" ({state})"));
            }
            return line;
        }
        format!("{}: {}", self.label(), self.detail(stopped))
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
        assert_eq!(buckets, ["mpsc", "oneshot rx", "timer", "watch"]);
        for slot in &selector {
            match &slot.attribution {
                Attribution::Owner {
                    kind: OwnerKind::OneshotRx,
                    holder,
                    member,
                    path,
                    validity,
                    primitive,
                    reading,
                } => {
                    assert_eq!((holder.as_str(), member.as_str()), ("Inner", "rx_task"));
                    // `MaybeUninit` under the state word, whose bit for
                    // the receiver's slot is set.
                    assert_eq!(*validity, Validity::Gated("rx_task_set"));
                    // The reading is the parked receiver's: nothing
                    // sent, the sender leaked alive in `main`.
                    let Some(Reading::Oneshot(state)) = reading else {
                        panic!("{reading:?}");
                    };
                    assert!(state.rx_task_set() && !state.complete() && !state.closed());
                    assert_eq!(state.value_present, Some(false));
                    assert_eq!(
                        slot.entry(stopped),
                        format!("oneshot rx {primitive:#x} (nothing sent, sender alive)")
                    );
                    assert_eq!(slot.label(), format!("oneshot rx {primitive:#x}"));
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
                    primitive,
                    reading,
                } => {
                    assert_eq!((holder.as_str(), member.as_str()), ("Chan", "rx_waker"));
                    assert_eq!(*validity, Validity::SelfDescribing);
                    assert!(
                        matches!(path.root, SlotRoot::Frame { frame: 1, .. }),
                        "{path:?}"
                    );
                    assert_eq!(path.steps[..3], ["<3>", "queue", "chan"]);
                    assert!(path.hop.is_some());
                    // The channel's own words: the one sender kept in
                    // `main`, the bound of four, nothing sent.
                    assert_eq!(
                        *reading,
                        Some(Reading::Mpsc {
                            senders: 1,
                            capacity: Some(4),
                            unread: 0,
                        })
                    );
                    assert_eq!(
                        slot.entry(stopped),
                        format!("mpsc {primitive:#x} (1 sender, capacity 4, 0 unread)")
                    );
                }
                Attribution::Owner {
                    kind: OwnerKind::Watch,
                    holder,
                    member,
                    path,
                    validity,
                    primitive,
                    reading,
                } => {
                    // The `Notified` is on one of the watch channel's
                    // `Notify`s: the slot is the watch's, named by its
                    // `Shared` — which the capture read on the slot's
                    // behalf, so the snapshot holds it.
                    assert_eq!((holder.as_str(), member.as_str()), ("Notified", "waiter"));
                    assert_eq!(*validity, Validity::SelfDescribing);
                    // Never sent to, one handle on each side.
                    assert_eq!(
                        *reading,
                        Some(Reading::Watch {
                            version: 0,
                            closed: false,
                            receivers: 1,
                            senders: 1,
                        })
                    );
                    assert_eq!(
                        slot.entry(stopped),
                        format!("watch {primitive:#x} (version 0, 1 sender, 1 receiver)")
                    );
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
        // The `Notify`'s state word says waiters are queued.
        assert_eq!(
            waiter[0].entry(stopped),
            format!("notify {primitive:#x} (waiting)")
        );
        assert_eq!(waiter[0].label(), format!("notify {primitive:#x}"));
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

#[cfg(test)]
mod join_tests {
    //! The joins between a slot and what a reader or a wait-set member
    //! says: laid out by hand, at the boundaries no fixture reaches.

    use super::*;
    use crate::tokio::assess::{ContinuationStatus, VerifiedWait, WaitAssessment};
    use crate::tokio::bundle::{FutureInfo, IoSlot, OwnerResolution, Task, TaskKind};
    use crate::tokio::graph::TaskRef;
    use crate::tokio::waitset::{MemberRoute, SlotRef, WaitMember, WaitSet};
    use crate::tokio::{TaskAddr, TaskState};

    use hansei_bundle::SemanticIssueKind;

    const KEY_TY: BundleTypeId = BundleTypeId(1);
    const KEY_SIZE: u64 = 24;

    fn size_of(ty: BundleTypeId) -> Option<u64> {
        (ty == KEY_TY).then_some(KEY_SIZE)
    }

    fn key() -> ValueKey {
        ValueKey {
            addr: 0x5000,
            ty: KEY_TY,
        }
    }

    fn owner() -> Owner {
        Owner::Task {
            header: 0x1000,
            index: 0,
        }
    }

    fn typed(slot: u64, root: SlotRoot, hop: Option<Hop>) -> AttributedSlot {
        AttributedSlot {
            hit: 0,
            slot,
            owner: owner(),
            attribution: Attribution::Typed {
                holder: "x::Holder".to_string(),
                member: "w".to_string(),
                path: SlotPath {
                    root,
                    steps: vec!["w".to_string()],
                    hop,
                },
                validity: Validity::Raw,
            },
            within: None,
        }
    }

    fn registry(slot: u64, attribution: RegistrySlot, within: Option<SlotRoot>) -> AttributedSlot {
        AttributedSlot {
            hit: 0,
            slot,
            owner: owner(),
            attribution: Attribution::Registry(attribution),
            within,
        }
    }

    fn owned(slot: u64, kind: OwnerKind, primitive: u64) -> AttributedSlot {
        AttributedSlot {
            hit: 0,
            slot,
            owner: owner(),
            attribution: Attribution::Owner {
                kind,
                primitive,
                holder: "Notified".to_string(),
                member: "waiter".to_string(),
                path: SlotPath {
                    root: SlotRoot::Frame { task: 0, frame: 0 },
                    steps: Vec::new(),
                    hop: None,
                },
                validity: Validity::SelfDescribing,
                reading: None,
            },
            within: None,
        }
    }

    fn member(armed: Option<SlotRef>, assessment: Option<WaitAssessment>) -> WaitMember {
        WaitMember {
            route: MemberRoute::Branch {
                local: "b".to_string(),
                borrowed: false,
            },
            key: Some(key()),
            future: None,
            assessment,
            notes: Vec::new(),
            armed,
        }
    }

    fn frame() -> SlotRoot {
        SlotRoot::Frame { task: 0, frame: 0 }
    }

    fn hop(from: u64) -> Hop {
        Hop {
            from,
            addr: 0x9000,
            pointee: "x::Pointee".to_string(),
            pointee_ty: BundleTypeId(2),
            steps: Vec::new(),
        }
    }

    fn timer(entry: u64) -> RegistrySlot {
        RegistrySlot::Timer {
            entry,
            state: None,
            deadline: None,
        }
    }

    fn io(resource: u64) -> RegistrySlot {
        RegistrySlot::Io {
            resource,
            slot: IoSlot::Reader,
            ready: None,
        }
    }

    /// A member is armed by a slot inside its storage — its first byte
    /// in, its last byte in, the byte past its end out, the byte before
    /// it out — by a slot located from its own find, by a slot whose
    /// hop left from a pointer inside it, and by a registry slot the
    /// analysis placed in its find.
    #[test]
    fn test_a_member_claims_the_slots_in_its_storage_and_reached_through_it() {
        let m = member(None, None);
        let claims = |slot: &AttributedSlot| member_accounts(&m, slot, &size_of);
        assert!(claims(&typed(0x5000, frame(), None)));
        assert!(claims(&typed(0x5017, frame(), None)));
        assert!(!claims(&typed(0x5018, frame(), None)));
        assert!(!claims(&typed(0x4ff8, frame(), None)));
        let find = |addr| SlotRoot::Find { index: 0, addr };
        assert!(claims(&typed(0x9000, find(0x5000), None)));
        assert!(!claims(&typed(0x9000, find(0x5008), None)));
        let child = |addr| SlotRoot::Child {
            set: 0,
            child: 0,
            addr,
        };
        assert!(claims(&typed(0x9000, child(0x5000), None)));
        assert!(claims(&typed(0x9000, frame(), Some(hop(0x5010)))));
        assert!(!claims(&typed(0x9000, frame(), Some(hop(0x5018)))));
        assert!(claims(&registry(0x9000, timer(0x9000), Some(find(0x5000)))));
        assert!(!claims(&registry(
            0x9000,
            timer(0x9000),
            Some(find(0x6000))
        )));
        // A member with no identity claims nothing by storage.
        let mut nameless = member(None, None);
        nameless.key = None;
        assert!(!member_accounts(
            &nameless,
            &typed(0x5000, frame(), None),
            &size_of
        ));
    }

    /// The registry evidence that armed a member is the slot itself:
    /// the wheel entry by its address, the io waiter by its resource —
    /// and not a neighbour's.
    #[test]
    fn test_a_member_armed_by_a_registry_slot_claims_exactly_that_slot() {
        let by_wheel = member(
            Some(SlotRef::Wheel {
                entry: 0xdd00,
                state: None,
                deadline: None,
                stopped: None,
            }),
            None,
        );
        assert!(member_accounts(
            &by_wheel,
            &registry(0xdd00, timer(0xdd00), None),
            &size_of
        ));
        assert!(!member_accounts(
            &by_wheel,
            &registry(0xdd08, timer(0xdd08), None),
            &size_of
        ));
        assert!(!member_accounts(
            &by_wheel,
            &registry(0xaa08, io(0xaa00), None),
            &size_of
        ));
        let by_io = member(
            Some(SlotRef::Io {
                resource: 0xaa00,
                slot: IoSlot::Reader,
                fd: None,
                ready: None,
            }),
            None,
        );
        assert!(member_accounts(
            &by_io,
            &registry(0xaa08, io(0xaa00), None),
            &size_of
        ));
        assert!(!member_accounts(
            &by_io,
            &registry(0xab08, io(0xab00), None),
            &size_of
        ));
        assert!(!member_accounts(
            &by_io,
            &registry(0xdd00, timer(0xdd00), None),
            &size_of
        ));
    }

    /// A verified wait accounts for the slot of the primitive it names
    /// — a `Notify` by address, a channel by address — and for a typed
    /// slot inside its primitive's bytes, and for nothing else.
    #[test]
    fn test_a_verified_wait_accounts_for_its_primitives_slot() {
        let notify = VerifiedWait::testkit(
            WaitTarget::Notify {
                addr: 0x7000,
                state: None,
                waiters: None,
            },
            None,
        );
        assert!(verified_accounts(
            &notify,
            &owned(0x7040, OwnerKind::Notify, 0x7000),
            &size_of
        ));
        assert!(!verified_accounts(
            &notify,
            &owned(0x7140, OwnerKind::Notify, 0x7100),
            &size_of
        ));
        assert!(!verified_accounts(
            &notify,
            &owned(0x7040, OwnerKind::Mpsc, 0x7000),
            &size_of
        ));
        let channel = VerifiedWait::testkit(
            WaitTarget::Channel {
                addr: 0x8000,
                senders: 1,
                capacity: None,
                unread: 0,
            },
            None,
        );
        assert!(verified_accounts(
            &channel,
            &owned(0x8080, OwnerKind::Mpsc, 0x8000),
            &size_of
        ));
        assert!(!verified_accounts(
            &channel,
            &owned(0x8080, OwnerKind::Mpsc, 0x8100),
            &size_of
        ));
        // The test-only primitive sits at address zero with a type of
        // size zero: a typed slot at zero is not inside it, and one at
        // zero with a size is.
        assert!(!verified_accounts(
            &channel,
            &typed(0x0, frame(), None),
            &size_of
        ));
        let sized = |_| Some(64);
        assert!(verified_accounts(
            &channel,
            &typed(0x8, frame(), None),
            &sized
        ));
        assert!(!verified_accounts(
            &channel,
            &typed(0x40, frame(), None),
            &sized
        ));
        // A member verified over a resource claims that resource's slot.
        let m = member(
            Some(SlotRef::Protocol),
            Some(WaitAssessment::Waiting(notify)),
        );
        assert!(member_accounts(
            &m,
            &owned(0x7040, OwnerKind::Notify, 0x7000),
            &size_of
        ));
        assert!(!member_accounts(
            &m,
            &owned(0x7040, OwnerKind::Notify, 0x7100),
            &size_of
        ));
    }

    /// Over a wait set, a slot takes the words of the armed member
    /// that claims it; an unarmed member claims nothing, and a task
    /// waiting on nothing accounts for nothing.
    #[test]
    fn test_a_wait_set_speaks_for_the_slot_its_armed_member_claims() {
        let wait = |members: Vec<WaitMember>| TaskWait {
            task: TaskRef {
                addr: TaskAddr(0x1000),
                task_id: Some(1),
            },
            assessment: WaitAssessment::Set(WaitSet {
                at: key(),
                reason: SemanticIssueKind::NoRule,
                members,
                capped: 0,
            }),
            continuation: ContinuationStatus::Primitive,
            depth: 1,
            site: None,
            observation: None,
            notes: Vec::new(),
            held: Vec::new(),
            held_capped: 0,
            frames: Vec::new(),
        };
        let armed = member(
            Some(SlotRef::Wheel {
                entry: 0xdd00,
                state: None,
                deadline: None,
                stopped: None,
            }),
            None,
        );
        let slot = registry(0xdd00, timer(0xdd00), None);
        assert_eq!(
            accounted_by(&wait(vec![armed]), &slot, &size_of),
            Some(("timer 0xdd00".to_string(), "timer".to_string()))
        );
        assert_eq!(
            accounted_by(&wait(vec![member(None, None)]), &slot, &size_of),
            None
        );
        let mut idle = wait(Vec::new());
        idle.assessment = WaitAssessment::Unresumed;
        assert_eq!(accounted_by(&idle, &slot, &size_of), None);
    }

    /// Each demotion has its own words, and the audit names the hit,
    /// its owner as the listings do, the value it sat in and why it
    /// was demoted.
    #[test]
    fn test_stale_hits_are_listed_by_reason_in_the_audit() {
        let reasons = [
            StaleReason::InactiveVariant,
            StaleReason::DeadLocal,
            StaleReason::NotAWaker,
            StaleReason::GateClear,
        ];
        let mut texts: Vec<&str> = reasons.iter().map(|r| r.text()).collect();
        assert!(texts.iter().all(|t| !t.is_empty()));
        texts.sort_unstable();
        texts.dedup();
        assert_eq!(texts.len(), reasons.len());

        let list = TaskList::new(vec![Task {
            addr: TaskAddr(0x1000),
            state: TaskState(1 << 6),
            owner_id: None,
            task_id: Some(7),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
        }]);
        let attributed = Attributed {
            stale: vec![
                Stale {
                    hit: 0,
                    slot: 0x5010,
                    owner: owner(),
                    root: SlotRoot::Frame { task: 0, frame: 1 },
                    reason: StaleReason::InactiveVariant,
                },
                Stale {
                    hit: 1,
                    slot: 0x6020,
                    owner: Owner::Child { set: 0, child: 2 },
                    root: SlotRoot::Find {
                        index: 3,
                        addr: 0x6000,
                    },
                    reason: StaleReason::GateClear,
                },
            ],
            ..Attributed::default()
        };
        let lines = attributed.audit(&list);
        assert_eq!(
            lines,
            [
                "the hit at 0x5010 names task 7 and sits in #1 but is in an inactive variant",
                "the hit at 0x6020 names child 2 of set 0 and sits in the future at 0x6000 but is \
                 under a state word that says no waker is set",
            ]
        );
        assert!(Attributed::default().audit(&list).is_empty());
    }

    /// A task's own slot located through a set child's root is filed
    /// under that child too; the child's own slot is filed once.
    #[test]
    fn test_a_slot_located_through_a_child_root_is_the_childs_once() {
        let child = SlotRoot::Child {
            set: 0,
            child: 1,
            addr: 0x4000,
        };
        let mut of_child = typed(0x4010, child, None);
        of_child.owner = Owner::Child { set: 0, child: 1 };
        let of_task = typed(0x4020, child, None);
        let attributed = Attributed::from_slots(vec![of_child.clone(), of_task.clone()]);
        assert_eq!(attributed.of_child(0, 1).count(), 2);
        assert_eq!(
            Attributed::from_slots(vec![of_child])
                .of_child(0, 1)
                .count(),
            1
        );
        assert_eq!(
            Attributed::from_slots(vec![of_task]).of_child(0, 1).count(),
            1
        );
    }

    /// Roots come innermost first: a find ahead of a frame of the same
    /// size and address, an inner frame ahead of an outer one, and the
    /// wrapper frames that share one range with what they wrap folded
    /// into one.
    #[test]
    fn test_roots_come_innermost_first_a_find_ahead_of_a_frame() {
        use crate::testkit::load_any;
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = crate::testkit::context(&bundle, &snapshot);
        let list = crate::testkit::tasks(&ctx, &snapshot);
        // Any two typed values of different sizes will do: a task's
        // header and its whole cell.
        let task = &list.tasks[0];
        let header = Value::read(
            ctx.proc,
            ctx.view.ty(ctx.view.bundle().infra.header).unwrap(),
            task.addr.0,
        )
        .unwrap();
        let cell = ctx
            .task_extent(task)
            .map(|range| range.end - range.start)
            .unwrap();
        assert!(cell > header.bytes.len() as u64);
        let frame = |frame| SlotRoot::Frame { task: 0, frame };
        let find = SlotRoot::Find {
            index: 0,
            addr: task.addr.0,
        };
        let mut roots = vec![
            Root {
                at: frame(0),
                value: header,
            },
            Root {
                at: find,
                value: header,
            },
            Root {
                at: frame(1),
                value: header,
            },
        ];
        order_roots(&mut roots);
        assert_eq!(roots.len(), 1, "one range, walked once");
        assert_eq!(roots[0].at, find);
        let mut frames = vec![
            Root {
                at: frame(2),
                value: header,
            },
            Root {
                at: frame(0),
                value: header,
            },
        ];
        order_roots(&mut frames);
        assert_eq!(frames[0].at, frame(0), "the inner frame first");
    }
}

#[cfg(test)]
mod synthetic_tests {
    //! The walk over types no fixture holds — a waker at a member's
    //! edge, an array of wakers, a holder exactly a waker wide, a
    //! pointer landing on a boundary — laid out by hand in a bundle of
    //! their own, over bytes planted beside a fixture pair.

    use super::*;
    use crate::heap::umem::tests::{BUFFERS, SlabSpec, cache, fake};
    use crate::testkit::load_any;
    use crate::tokio::bundle::{OneshotState, Registries, TaskList};
    use crate::tokio::census::FutureCensus;
    use crate::tokio::graph::Analysis;
    use crate::tokio::semantics::SemanticIndex;
    use crate::tokio::wakers::{Class, VtableKind};

    use hansei_bundle::{
        Bundle, CoroutineLayout, CoroutinePhase, CoroutineState, DiscrDef, DiscrValue, DiscrValues,
        DynFutureTable, Encoding, FORMAT_VERSION, ImplTable, InfraTypes, MemberDef, MemberRef,
        Meta, ProvenanceTable, SemanticRuleId, SemanticTable, StaticsTable, Step as WalkStep,
        StoragePolicy, StringInterner, TaskTable, TypeDef, TypeTable, VariantDef, VariantShape,
        WalkBinding, WalksTable,
    };
    use proc::snapshot::Snapshot;
    use proc::{LoadedObjectWithPath, LwpInfo, MapFlags, Regs, SymbolBuf};

    use std::ops::Range;

    /// Where the planted mapping sits: high, and in no fixture.
    const BASE: u64 = 0x5f20_0000_0000;
    const SIZE: u64 = 0x2000;

    // The synthetic bundle's type ids.
    const U64: u32 = 0;
    const RAW_WAKER: u32 = 1;
    const WAKER: u32 = 2;
    const UNIT: u32 = 3;
    const OPT_WAKER: u32 = 4;
    const SLIM: u32 = 5;
    const HOLDER: u32 = 6;
    const ARR: u32 = 7;
    const BOXED: u32 = 8;
    const PTR_HOLDER: u32 = 9;
    const FRAME: u32 = 10;
    const PADDED: u32 = 11;
    const CHANLIKE: u32 = 12;
    const NOTIFY_ARR: u32 = 13;
    const SHARED: u32 = 14;
    const ARC_SHARED: u32 = 15;
    const CORO: u32 = 16;
    const CORO_STATE: u32 = 17;

    fn id(i: u32) -> BundleTypeId {
        BundleTypeId(i)
    }

    /// A bundle of the shapes the walk must get right at the edges:
    /// `Holder { a: u64, w: Option<Waker> }` (24 bytes), `Slim { w:
    /// Waker }` (exactly a waker wide), `Boxed { n, ws: [Slim; 3] }`, a
    /// `Frame { p: *const Holder, pad }`, a `Chanlike { x, cp:
    /// CachePadded<Option<Waker>> }` whose wrapper is wider than a
    /// waker, and a watch `Shared` behind an `ArcInner` with the roles
    /// the watch row reads bound.
    fn bundle() -> Bundle {
        let mut strings = StringInterner::new();
        let mut n = |s: &str| strings.intern(s);
        let (u64n, rawn, wakern, unitn) = (
            n("u64"),
            n("core::task::wake::RawWaker"),
            n("core::task::wake::Waker"),
            n("()"),
        );
        let (datan, vtablen, wakerm, nonen, somen, zeron) = (
            n("data"),
            n("vtable"),
            n("waker"),
            n("None"),
            n("Some"),
            n("__0"),
        );
        let (optn, slimn, holdern, boxedn, ptrn, framen) = (
            n("core::option::Option<core::task::wake::Waker>"),
            n("x::Slim"),
            n("x::Holder"),
            n("x::Boxed"),
            n("*const x::Holder"),
            n("x::Frame"),
        );
        let (wn, an, nn, wsn, pn, padn) = (n("w"), n("a"), n("n"), n("ws"), n("p"), n("pad"));
        let (paddedn, chann, valuen, xn, cpn) = (
            n("tokio::util::cacheline::CachePadded<core::option::Option<core::task::wake::Waker>>"),
            n("x::Chanlike"),
            n("value"),
            n("x"),
            n("cp"),
        );
        let (coron, coro_staten, zero_v, three_v, liven, deadn, unsuren, lpn) = (
            n("x::coro::{async_fn_env#0}"),
            n("x::coro::{async_fn_env#0}::Suspend0"),
            n("0"),
            n("3"),
            n("live"),
            n("dead"),
            n("unsure"),
            n("lp"),
        );
        let (sharedn, arcn, notify_rxn, staten, rxn, txn, strongn, weakn) = (
            n("tokio::sync::watch::Shared<u32>"),
            n("alloc::sync::ArcInner<tokio::sync::watch::Shared<u32>>"),
            n("notify_rx"),
            n("state"),
            n("ref_count_rx"),
            n("ref_count_tx"),
            n("strong"),
            n("weak"),
        );
        let member = |name, ty, offset| MemberDef { name, ty, offset };
        let strukt = |name, size, members| TypeDef::Struct {
            name,
            size,
            members,
        };
        let types = vec![
            TypeDef::Base {
                name: u64n,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            strukt(
                rawn,
                16,
                vec![member(datan, id(U64), 0), member(vtablen, id(U64), 8)],
            ),
            strukt(wakern, 16, vec![member(wakerm, id(RAW_WAKER), 0)]),
            strukt(unitn, 0, vec![]),
            // The niche: a null vtable word is `None`.
            TypeDef::Enum {
                name: optn,
                size: 16,
                shape: VariantShape {
                    discr: Some(DiscrDef {
                        offset: 8,
                        ty: id(U64),
                    }),
                    variants: vec![
                        VariantDef {
                            name: nonen,
                            discr_values: Some(DiscrValues(vec![DiscrValue::Value(0)])),
                            payload: member(zeron, id(UNIT), 0),
                            decl: None,
                            await_site: None,
                        },
                        VariantDef {
                            name: somen,
                            discr_values: None,
                            payload: member(zeron, id(WAKER), 0),
                            decl: None,
                            await_site: None,
                        },
                    ],
                },
            },
            strukt(slimn, 16, vec![member(wn, id(WAKER), 0)]),
            strukt(
                holdern,
                24,
                vec![member(an, id(U64), 0), member(wn, id(OPT_WAKER), 8)],
            ),
            TypeDef::Array {
                elem: id(SLIM),
                count: 3,
            },
            strukt(
                boxedn,
                56,
                vec![member(nn, id(U64), 0), member(wsn, id(ARR), 8)],
            ),
            TypeDef::Pointer {
                name: Some(ptrn),
                target: id(HOLDER),
            },
            strukt(
                framen,
                16,
                vec![member(pn, id(PTR_HOLDER), 0), member(padn, id(U64), 8)],
            ),
            strukt(paddedn, 128, vec![member(valuen, id(OPT_WAKER), 0)]),
            strukt(
                chann,
                136,
                vec![member(xn, id(U64), 0), member(cpn, id(PADDED), 8)],
            ),
            TypeDef::Array {
                elem: id(U64),
                count: 32,
            },
            strukt(
                sharedn,
                280,
                vec![
                    member(notify_rxn, id(NOTIFY_ARR), 0),
                    member(staten, id(U64), 256),
                    member(rxn, id(U64), 264),
                    member(txn, id(U64), 272),
                ],
            ),
            strukt(
                arcn,
                296,
                vec![
                    member(strongn, id(U64), 0),
                    member(weakn, id(U64), 8),
                    member(datan, id(SHARED), 16),
                ],
            ),
            // A coroutine: its state word, then the suspended state's
            // locals — a live waker, a dead pointer, a waker whose
            // initialization the layout cannot vouch for, a live pointer.
            TypeDef::Enum {
                name: coron,
                size: 56,
                shape: VariantShape {
                    discr: Some(DiscrDef {
                        offset: 0,
                        ty: id(U64),
                    }),
                    variants: vec![
                        VariantDef {
                            name: zero_v,
                            discr_values: Some(DiscrValues(vec![DiscrValue::Value(0)])),
                            payload: member(zeron, id(UNIT), 8),
                            decl: None,
                            await_site: None,
                        },
                        VariantDef {
                            name: three_v,
                            discr_values: Some(DiscrValues(vec![DiscrValue::Value(3)])),
                            payload: member(zeron, id(CORO_STATE), 8),
                            decl: None,
                            await_site: None,
                        },
                    ],
                },
            },
            strukt(
                coro_staten,
                48,
                vec![
                    member(liven, id(WAKER), 0),
                    member(deadn, id(PTR_HOLDER), 16),
                    member(unsuren, id(WAKER), 24),
                    member(lpn, id(PTR_HOLDER), 40),
                ],
            ),
        ];
        let semantics = SemanticTable {
            types: vec![hansei_bundle::TypeSemantics {
                ty: id(CORO),
                storage: StoragePolicy::CoroutineStates,
                future: None,
                coroutine: Some(CoroutineLayout {
                    rule: SemanticRuleId(0),
                    states: vec![CoroutineState {
                        variant: three_v,
                        stage: CoroutinePhase::Suspended,
                        locals: vec![liven, lpn],
                        uncertain_locals: vec![unsuren],
                    }],
                }),
                access: None,
                resource: None,
                container: None,
                issues: Vec::new(),
            }],
            ..Default::default()
        };
        let mut b = Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings: strings.finish(),
            types: TypeTable {
                types,
                name_index: vec![],
                ..Default::default()
            },
            tasks: TaskTable::default(),
            dyn_futures: DynFutureTable::default(),
            statics: StaticsTable::default(),
            walks: WalksTable::default(),
            infra: InfraTypes {
                header: id(U64),
                vtable: id(U64),
                trailer: id(U64),
                context: id(U64),
                scheduler_handle: id(U64),
                mt_handle: id(U64),
                ct_handle: id(U64),
                location: id(U64),
                raw_waker_vtable: id(U64),
            },
            provenance: ProvenanceTable::default(),
            impls: ImplTable::default(),
            semantics,
        };
        let bind = |last| WalkBinding {
            roots: vec![id(ARC_SHARED)],
            steps: vec![
                WalkStep::Member(MemberRef::Named(datan)),
                WalkStep::Member(MemberRef::Named(last)),
            ],
            outcome: WalkOutcome::Bound {
                spelling: 0,
                spellings: 1,
                note: None,
            },
        };
        for (role, last) in [
            (WalkRole::WatchSharedNotifyRx, notify_rxn),
            (WalkRole::WatchSharedState, staten),
            (WalkRole::WatchSharedRxCount, rxn),
            (WalkRole::WatchSharedTxCount, txn),
        ] {
            b.walks.entries.insert(role, bind(last));
        }
        b
    }

    /// A fixture snapshot with one anonymous, writable mapping planted
    /// beside it, holding the bytes a test lays down.
    struct Planted<'a> {
        inner: &'a Snapshot,
        bytes: Vec<u8>,
    }

    impl<'a> Planted<'a> {
        fn new(inner: &'a Snapshot) -> Self {
            Planted {
                inner,
                bytes: vec![0; SIZE as usize],
            }
        }

        fn word(&mut self, at: u64, value: u64) {
            let off = (at - BASE) as usize;
            self.bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }

        /// A waker pair at `at`: a data word and a nonzero vtable word.
        fn pair(&mut self, at: u64) {
            self.word(at, 0x1234);
            self.word(at + 8, 0xf000);
        }

        fn range(&self) -> Range<u64> {
            BASE..BASE + SIZE
        }
    }

    impl proc::Target for Planted<'_> {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            if self.range().contains(&addr) && addr + len <= BASE + SIZE {
                let off = (addr - BASE) as usize;
                return Ok(&self.bytes[off..off + len as usize]);
            }
            self.inner.read_bytes(addr, len)
        }
        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            if self.range().contains(&addr) {
                return (BASE + SIZE - addr).min(max);
            }
            self.inner.readable_len(addr, max)
        }
        fn lookup_symbol_by_addr(&self, addr: u64) -> Option<SymbolBuf> {
            self.inner.lookup_symbol_by_addr(addr)
        }
        fn lookup_symbol_by_name(&self, name: &str) -> Option<SymbolBuf> {
            self.inner.lookup_symbol_by_name(name)
        }
        fn symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            self.inner.symbols()
        }
        fn object_symbols(&self) -> proc::Result<Vec<SymbolBuf>> {
            self.inner.object_symbols()
        }
        fn mappings(&self) -> proc::Result<proc::Mappings> {
            let planted = LoadedObjectWithPath {
                path: None,
                vaddr: BASE,
                size: SIZE,
                flags: MapFlags(0x04 | 0x02 | 0x40),
            };
            Ok(self
                .inner
                .mappings()?
                .as_slice()
                .iter()
                .cloned()
                .chain([planted])
                .collect())
        }
        fn captured_runs(&self) -> Option<Vec<Range<u64>>> {
            let mut runs = self.inner.captured_runs()?;
            runs.push(self.range());
            Some(runs)
        }
        fn lwps(&self) -> proc::Result<Vec<LwpInfo>> {
            self.inner.lwps()
        }
        fn tls_var_addr(&self, regs: &Regs, sym: &SymbolBuf) -> proc::Result<Option<u64>> {
            self.inner.tls_var_addr(regs, sym)
        }
    }

    /// Everything an attributor over the planted target reads that is
    /// not the target or the bundle: empty sources.
    struct Empty {
        list: TaskList,
        census: FutureCensus,
        registries: Registries,
        analysis: Analysis,
        impls: ImplFold,
        semantics: SemanticIndex,
    }

    impl Empty {
        fn new(bundle: &Bundle) -> Self {
            Empty {
                list: TaskList::new(Vec::new()),
                census: FutureCensus::from_finds(Vec::new(), Vec::new(), Vec::new()),
                registries: Registries::default(),
                analysis: Analysis {
                    waits: Vec::new(),
                    barriers: Vec::new(),
                    join_wakers: Vec::new(),
                    errors: Vec::new(),
                },
                impls: ImplFold::default(),
                semantics: SemanticIndex::new(bundle.types.types.len(), &bundle.semantics.types)
                    .expect("an empty semantic table indexes"),
            }
        }

        fn sources(&self) -> Sources<'_> {
            Sources {
                list: &self.list,
                census: &self.census,
                registries: &self.registries,
                analysis: &self.analysis,
                heap: None,
                impls: &self.impls,
            }
        }
    }

    fn attributor<'a, 'b>(
        proc: &'b Planted<'b>,
        bundle: &'b Bundle,
        empty: &'a Empty,
        sources: &'a Sources<'a>,
    ) -> Attributor<'a, 'b, Planted<'b>> {
        Attributor {
            proc,
            types: Types {
                view: BundleView::new(bundle),
                semantics: &empty.semantics,
                test_bindings: &[],
            },
            sources,
            registry: HashMap::default(),
            finds: HashMap::default(),
        }
    }

    fn value<'b>(at: &Attributor<'_, 'b, Planted<'b>>, ty: u32, addr: u64) -> Value<'b> {
        Value::read(at.proc, at.types.view.ty(id(ty)).unwrap(), addr).unwrap()
    }

    fn hit(slot: u64) -> Hit {
        Hit {
            slot,
            vtable: 0xf000,
            kind: VtableKind::Task,
            data: 0x1000,
            owner: Some(Owner::Task {
                header: 0x1000,
                index: 0,
            }),
            class: Class::Anon,
            admitted: true,
        }
    }

    fn names<'t>(trail: &'t [super::Step<'_>]) -> Vec<&'t str> {
        trail.iter().map(|s| s.name.as_str()).collect()
    }

    /// The offset walk lands on a `Waker` at its first byte and nowhere
    /// else: not on the member before it, not inside it, not past the
    /// value's end, and not in an `Option`'s `None`, which is storage
    /// of a variant the value is not in.
    #[test]
    fn test_the_offset_walk_lands_on_a_waker_and_nowhere_else() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (some, none) = (BASE, BASE + 0x100);
        planted.word(some, 7);
        planted.pair(some + 8);
        planted.word(none, 7);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let holder = value(&at, HOLDER, some);
        match at.locate_member(holder, 8) {
            Located::Slot { trail, validity } => {
                assert_eq!(names(&trail), ["w", "<Some>"]);
                assert_eq!(validity, Validity::SelfDescribing);
            }
            Located::Stale(reason) => panic!("{reason:?}"),
        }
        for offset in [0, 7, 9, 12, 23, 24, 100] {
            assert!(
                matches!(
                    at.locate_member(holder, offset),
                    Located::Stale(StaleReason::NotAWaker)
                ),
                "offset {offset}"
            );
        }
        let none = value(&at, HOLDER, none);
        assert!(matches!(
            at.locate_member(none, 8),
            Located::Stale(StaleReason::InactiveVariant)
        ));
    }

    /// An array is indexed by offset: each element's waker is found at
    /// the element's start, nothing inside an element or past the last
    /// one, and the trail names the array step.
    #[test]
    fn test_the_offset_walk_indexes_arrays() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let boxed = BASE;
        planted.word(boxed, 3);
        for i in 0..3 {
            planted.pair(boxed + 8 + 16 * i);
        }
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let v = value(&at, BOXED, boxed);
        for i in 0..3u64 {
            match at.locate_member(v, 8 + 16 * i) {
                Located::Slot { trail, validity } => {
                    assert_eq!(names(&trail), ["ws", "[]", "w"], "element {i}");
                    assert_eq!(validity, Validity::Raw);
                }
                Located::Stale(reason) => panic!("element {i}: {reason:?}"),
            }
        }
        // Inside the first and second elements' wakers, and past the
        // last element.
        for offset in [16, 32, 8 + 48, 8 + 64] {
            assert!(
                matches!(
                    at.locate_member(v, offset),
                    Located::Stale(StaleReason::NotAWaker)
                ),
                "offset {offset}"
            );
        }
    }

    /// The holder a typed slot is named by is the innermost aggregate
    /// wider than a waker that is not a wrapper: `Slim`, exactly a
    /// waker wide, is passed over for the array holding it, and a
    /// `CachePadded` wider than a waker is passed over, as a wrapper,
    /// for the struct holding it.
    #[test]
    fn test_the_holder_is_the_innermost_wide_aggregate_that_is_no_wrapper() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (boxed, chan) = (BASE, BASE + 0x100);
        planted.pair(boxed + 8 + 32);
        planted.pair(chan + 8);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let root = SlotRoot::Frame { task: 0, frame: 0 };
        let path = || SlotPath {
            root,
            steps: Vec::new(),
            hop: None,
        };

        let Located::Slot { trail, validity } = at.locate_member(value(&at, BOXED, boxed), 40)
        else {
            panic!("the third element's waker");
        };
        let Attribution::Typed { holder, member, .. } = at.name_slot(path(), &trail, validity)
        else {
            panic!("a typed slot");
        };
        let arr = at.types.view.ty(id(ARR)).unwrap().name();
        assert_eq!(holder, outer_path(&fold_type_name(arr, &empty.impls)));
        assert_eq!(member, "[]");

        let Located::Slot { trail, validity } = at.locate_member(value(&at, CHANLIKE, chan), 8)
        else {
            panic!("the padded waker");
        };
        assert_eq!(names(&trail), ["cp", "value", "<Some>"]);
        let Attribution::Typed { holder, member, .. } = at.name_slot(path(), &trail, validity)
        else {
            panic!("a typed slot");
        };
        assert_eq!((holder.as_str(), member.as_str()), ("x::Chanlike", "cp"));
    }

    /// A hop corroborates only a slot inside the pointee: at its first
    /// byte or within it, not at the byte past its end, not below it,
    /// and not inside a waker rather than at one. Containment is held
    /// to the same edges.
    #[test]
    fn test_a_hop_corroborates_only_a_slot_inside_the_pointee() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (frame, holder, none) = (BASE, BASE + 0x100, BASE + 0x200);
        planted.word(frame, holder);
        planted.word(holder, 7);
        planted.pair(holder + 8);
        planted.word(none, 7);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let roots = vec![Root {
            at: SlotRoot::Frame { task: 0, frame: 1 },
            value: value(&at, FRAME, frame),
        }];
        let pointers = at.pointer_members(&roots);
        assert_eq!(
            pointers.len(),
            1,
            "one pointer member, the null pad left out"
        );
        assert_eq!(
            (pointers[0].target, pointers[0].at, pointers[0].pointee),
            (holder, frame, id(HOLDER))
        );
        match at.by_hop(&hit(holder + 8), &roots, &pointers) {
            Some(Attribution::Typed { path, .. }) => {
                assert_eq!(path.root, SlotRoot::Frame { task: 0, frame: 1 });
                assert_eq!(path.steps, ["p"]);
                let hop = path.hop.expect("a hop");
                assert_eq!(
                    (hop.from, hop.addr, hop.pointee_ty),
                    (frame, holder, id(HOLDER))
                );
                assert_eq!(hop.steps, ["w", "<Some>"]);
            }
            other => panic!("{other:?}"),
        }
        for slot in [holder + 24, holder - 8, holder + 12, holder + 0x1000] {
            assert!(
                at.by_hop(&hit(slot), &roots, &pointers).is_none(),
                "{slot:#x}"
            );
        }

        let contained = vec![Root {
            at: SlotRoot::Find {
                index: 0,
                addr: holder,
            },
            value: value(&at, HOLDER, holder),
        }];
        assert!(matches!(
            at.by_containment(&hit(holder + 8), &contained),
            Ok(Some(Attribution::Typed { .. }))
        ));
        assert!(matches!(
            at.by_containment(&hit(holder + 24), &contained),
            Ok(None)
        ));
        assert!(matches!(
            at.by_containment(&hit(holder - 8), &contained),
            Ok(None)
        ));
        assert!(matches!(
            at.by_containment(&hit(holder + 12), &contained),
            Err(Stale {
                reason: StaleReason::NotAWaker,
                ..
            })
        ));
        let dead = vec![Root {
            at: SlotRoot::Find {
                index: 1,
                addr: none,
            },
            value: value(&at, HOLDER, none),
        }];
        assert!(matches!(
            at.by_containment(&hit(none + 8), &dead),
            Err(Stale {
                reason: StaleReason::InactiveVariant,
                ..
            })
        ));
    }

    /// A `Notified` on a `Notify` inside a watch `Shared`'s `notify_rx`
    /// array is the watch's, named by the `Shared` past the `ArcInner`
    /// header with its reading; one past the array, or with no pointer
    /// to the `Shared` among the owner's, is not.
    #[test]
    fn test_a_notify_inside_a_watch_shared_is_the_watchs() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (arc, holder) = (BASE, BASE + 0x800);
        let shared = arc + 16;
        // Version 5, open: the closed bit is clear.
        planted.word(shared + 256, 5 << 1);
        planted.word(shared + 264, 2);
        planted.word(shared + 272, 1);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let pointer = |target, pointee, from| PointerMember {
            target,
            pointee: id(pointee),
            root: 0,
            at: from,
        };
        let pointers = vec![
            pointer(holder, HOLDER, BASE + 0x1000),
            pointer(arc, ARC_SHARED, BASE + 0x1008),
            pointer(arc, ARC_SHARED, BASE + 0x1010),
        ];
        let (primitive, reading) = at
            .watch_of(shared + 40, &pointers)
            .expect("a Notify inside notify_rx");
        assert_eq!(primitive, shared);
        assert_eq!(
            reading,
            Reading::Watch {
                version: 5,
                closed: false,
                receivers: 2,
                senders: 1,
            }
        );
        assert!(
            at.watch_of(shared + 256, &pointers).is_none(),
            "the state word"
        );
        assert!(
            at.watch_of(shared + 40, &pointers[..1]).is_none(),
            "no Shared pointed at"
        );
    }

    /// The oneshot gate against the state word: the receiver's slot
    /// needs `RX_TASK_SET`, the sender's `TX_TASK_SET`, and a slot with
    /// no reading is neither set nor clear.
    #[test]
    fn test_the_oneshot_gate_reads_its_own_bit() {
        let state = |word| {
            Reading::Oneshot(OneshotState {
                word,
                value_present: None,
            })
        };
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotRx, Some(&state(0b0001))),
            Gate::Set("rx_task_set")
        ));
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotTx, Some(&state(0b0001))),
            Gate::Clear
        ));
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotTx, Some(&state(0b1000))),
            Gate::Set("tx_task_set")
        ));
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotRx, Some(&state(0b1000))),
            Gate::Clear
        ));
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotRx, Some(&state(0))),
            Gate::Clear
        ));
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotRx, None),
            Gate::Unread
        ));
        assert!(matches!(
            oneshot_gate(OwnerKind::OneshotRx, Some(&Reading::Notify { state: 1 })),
            Gate::Unread
        ));
    }

    /// A coroutine's locals are read by its active state's layout: a
    /// waker in a live local is a slot, one in a local the state cannot
    /// vouch for is a slot `(unchecked)`, and storage the state does
    /// not initialize is stale whatever it holds — and no pointer is
    /// read out of it.
    #[test]
    fn test_a_dead_local_holds_no_slot_and_an_uncertain_one_is_unchecked() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (coro, holder) = (BASE, BASE + 0x100);
        planted.word(coro, 3);
        planted.pair(coro + 8);
        planted.word(coro + 8 + 16, holder);
        planted.pair(coro + 8 + 24);
        planted.word(coro + 8 + 40, holder);
        planted.word(holder, 7);
        planted.pair(holder + 8);
        // The layout arrives as a test binding too, behind a record for
        // another type: a binding is found by its own type, not taken
        // as the first one there.
        let bindings = [
            TypeSemantics {
                ty: id(U64),
                ..bundle.semantics.types[0].clone()
            },
            bundle.semantics.types[0].clone(),
        ];
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let mut at = attributor(&planted, &bundle, &empty, &sources);
        at.types.test_bindings = &bindings;
        let v = value(&at, CORO, coro);
        match at.locate_member(v, 8) {
            Located::Slot { trail, validity } => {
                assert_eq!(names(&trail), ["<3>", "live"]);
                assert_eq!(validity, Validity::Raw);
            }
            Located::Stale(reason) => panic!("{reason:?}"),
        }
        match at.locate_member(v, 8 + 24) {
            Located::Slot { trail, validity } => {
                assert_eq!(names(&trail), ["<3>", "unsure"]);
                assert_eq!(validity, Validity::Unchecked);
            }
            Located::Stale(reason) => panic!("{reason:?}"),
        }
        for offset in [8 + 16, 8 + 20] {
            assert!(
                matches!(
                    at.locate_member(v, offset),
                    Located::Stale(StaleReason::DeadLocal)
                ),
                "offset {offset}"
            );
        }
        // The state word itself is no local.
        assert!(matches!(
            at.locate_member(v, 0),
            Located::Stale(StaleReason::InactiveVariant)
        ));
        let roots = vec![Root {
            at: SlotRoot::Frame { task: 0, frame: 0 },
            value: v,
        }];
        let pointers = at.pointer_members(&roots);
        assert_eq!(pointers.len(), 1, "the live pointer alone: {pointers:?}");
        assert_eq!(
            (pointers[0].at, pointers[0].target),
            (coro + 8 + 40, holder)
        );
    }

    /// An unknown slot is described by the allocator's account of its
    /// buffer — the cache, the buffer's size, the offset into it — and
    /// by nothing where the buffer is freed or there is no index.
    #[test]
    fn test_an_unknown_slot_is_described_by_its_buffer() {
        let mut f = fake();
        cache(
            &mut f,
            0,
            "umem_alloc_64",
            64,
            0,
            &[SlabSpec {
                base: BUFFERS,
                chunks: 4,
                free: vec![2, 3],
            }],
        );
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        match unknown(BUFFERS + 64 + 24, Some(&heap)) {
            Attribution::Unknown {
                cache,
                size,
                offset,
            } => {
                assert_eq!(cache.as_deref(), Some("umem_alloc_64"));
                assert_eq!((size, offset), (Some(64), Some(24)));
            }
            other => panic!("{other:?}"),
        }
        let bare = |attribution| match attribution {
            Attribution::Unknown {
                cache,
                size,
                offset,
            } => cache.is_none() && size.is_none() && offset.is_none(),
            _ => false,
        };
        assert!(
            bare(unknown(BUFFERS + 2 * 64 + 8, Some(&heap))),
            "a freed buffer"
        );
        assert!(bare(unknown(BUFFERS + 8, None)), "no index");
    }
}

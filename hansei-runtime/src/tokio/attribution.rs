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
    Context, HttpRole, HttpVersion, IoResourceInfo, IoSlot, IoWaiterInfo, OneshotSide,
    OneshotState, Readiness, Registries, TaskList, TimerEntryInfo, WaitTarget, WheelState,
    channel_words, contains, deadline_text, http_kind_word, notify_words, watch_words,
    watch_words_of,
};
use super::census::{FutureCensus, Via};
use super::contract::{Walked, execute_steps_over};
use super::graph::{Analysis, TaskRef};
use super::observe::{ReadContext, ResourceObservation, ValueKey};
use super::semantics::SemanticIndex;
use super::wakers::{Hit, Owner, WakerSlots};
use crate::heap::umem::{Liveness, UmemHeap};

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

/// Whether `ty` is storage for one value named another way, never the
/// owner of a slot: the walk passes through it to name what holds it.
/// That is a struct or union whose one sized member sits at its start
/// — an `UnsafeCell`, a `ManuallyDrop`, a `MaybeUninit`, a
/// `CachePadded` whatever its padding — or an `Option`-shaped enum, whose
/// `Some` is the value itself.
fn is_wrapper(ty: BundleType<'_>) -> bool {
    match ty.classify() {
        TypeClass::Struct | TypeClass::Union => {
            let mut sized = ty.members().filter(|m| m.ty().size() > 0);
            matches!((sized.next(), sized.next()), (Some(m), None) if m.offset() == 0)
        }
        TypeClass::RustEnum => is_option_shaped(ty),
        _ => false,
    }
}

/// Whether `ty` is an enum of a `None` and a `Some` alone: storage that
/// says for itself whether a value is there.
fn is_option_shaped(ty: BundleType<'_>) -> bool {
    let mut names: Vec<&str> = ty.variants().map(|v| v.name).collect();
    names.sort_unstable();
    names == ["None", "Some"]
}

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
    /// address the listings print for it, with the frame of its own
    /// chain the path runs from — `frame` as the listings number
    /// frames, 0 where the cursor lands by default.
    Find {
        index: usize,
        addr: u64,
        frame: usize,
    },
    /// A set child, by set and child index and its root's address.
    Child { set: usize, child: usize, addr: u64 },
}

/// The selector that puts a session's cursor on the root, so the path
/// from it is one `print` can be handed: `frame 1`, `future 0x…`. A
/// set child is a future of its own to the listings, and selected the
/// same way.
impl std::fmt::Display for SlotRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotRoot::Frame { frame, .. } => write!(f, "frame {frame}"),
            // `future 0x…` stands on frame #0 of that future's own
            // chain, so only a path from a frame further out names
            // one.
            SlotRoot::Find { addr, frame: 0, .. } | SlotRoot::Child { addr, .. } => {
                write!(f, "future {addr:#x}")
            }
            SlotRoot::Find { addr, frame, .. } => write!(f, "future {addr:#x} frame {frame}"),
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

/// Whether the task's current await reaches a slot. A task's chain is
/// linear and every coroutine frame has exactly one awaitee, so what
/// the task awaits is always frame #0's construct, and every slot the
/// current await installed sits in that construct or in something an
/// inner frame borrows from an outer one. Every other slot was
/// installed by an await that has since returned: it will wake the
/// task, and the poll that follows will not consume it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Reach {
    /// Frame #0 holds the slot, or a frame strictly inside the holding
    /// one borrows the container: the current await reaches it.
    Awaited(Holding),
    /// Held by an outer frame that nothing inside it borrows: parked
    /// by a completed await.
    Parked(Holding),
    /// A registry slot no typed value of the task's holds.
    Unlocated,
}

/// Where a located slot is held, as a task block names the item the
/// slot is listed under.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Holding {
    /// The value the item is named by: the borrowed value where an
    /// inner frame borrows one along the slot's path, else the frame
    /// local the path starts from (a held find, or the local a frame
    /// path enters), else the holding frame itself.
    pub container: ValueKey,
    /// The chain frame holding it, numbered as the listings number
    /// frames.
    pub frame: usize,
    /// That frame's local the slot is under, where the path names one.
    pub local: Option<String>,
}

impl SlotPath {
    /// The path as a `print` follows it: the root's selector, then the
    /// members from it joined by `.`, the pointer a hop crossed left
    /// implicit. `print` takes the same steps for itself — through a
    /// reference, an `Arc`'s header, a `NonNull`, a transparent
    /// wrapper — so the plumbing those layers carry (`ptr`,
    /// `pointer`) stays out, while the steps it will not take on its
    /// own stay in: an enum's variant, a tuple's position.
    fn location(&self) -> String {
        let mut out = self.root.to_string();
        let mut first = true;
        let steps = self
            .steps
            .iter()
            .chain(self.hop.iter().flat_map(|hop| hop.steps.iter()));
        for step in steps {
            let Some(text) = step_text(step) else {
                continue;
            };
            if text.starts_with('[') {
                out.push_str(text);
            } else {
                out.push(if first { ' ' } else { '.' });
                out.push_str(text);
            }
            first = false;
        }
        out
    }
}

/// Whether a walk step names an enum's variant rather than a member.
fn is_variant(step: &str) -> bool {
    step.starts_with('<') && step.ends_with('>')
}

/// One walk step in the path grammar — `<Some>` as the `.Some` a
/// variant is named by, an array index as its own `[i]` — or nothing
/// for a step a reader does not take: a coroutine's state, the
/// pointer plumbing and the compiler's own slots, which `print`
/// crosses on its own, and which say how the storage is laid out
/// rather than what holds it.
fn step_text(step: &str) -> Option<&str> {
    if is_variant(step) {
        let name = &step[1..step.len() - 1];
        return (!name.starts_with('#')).then_some(name);
    }
    if step.starts_with('[') {
        return Some(step);
    }
    match step {
        _ if step.starts_with("__") => None,
        "ptr" | "pointer" | "value" => None,
        _ => Some(step),
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
            OwnerKind::Mpsc => "mpsc rx",
            OwnerKind::Watch => "watch rx",
            OwnerKind::Notify => "notify rx",
        }
    }

    /// Whether the primitive's reading is a line of its own rather
    /// than a parenthetical on the entry: a channel's and a watch's
    /// counts run long, and the cell or verdict they sat on says
    /// enough without them.
    fn reads_apart(self) -> bool {
        matches!(self, OwnerKind::Mpsc | OwnerKind::Watch)
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
    /// A slot in another task's primitive, placed from that task's
    /// side: the receiver cell of the oneshot an HTTP client connection
    /// watches as its response callback, holding the waker of whoever
    /// awaits the response. The owner's own values never reach the
    /// cell — the receiver sits behind the client library's boxed
    /// future — so the connection's observation of the oneshot, and
    /// the oneshot's own layout, are what place it.
    Response {
        /// The oneshot's `Inner`.
        primitive: u64,
        reading: OneshotState,
        /// The task driving the connection, whose verified wait names
        /// the callback.
        connection: TaskRef,
        /// The connection as its verdict names it: the `Conn`'s
        /// address and its kind words.
        conn: u64,
        role: HttpRole,
        version: Option<HttpVersion>,
    },
    /// Memory nothing typed reaches: a live allocation no root's
    /// value covers, or — on a target with no allocator index — what
    /// may be a ghost of the storage's last occupant.
    Unknown,
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
    /// For a registry slot, the held finds whose own chains run through
    /// the value it lies in, past their own storage — an interval's
    /// tick, whose chain crosses the box to the `Sleep` holding the
    /// wheel entry — each armed by it as the value's own find is. By
    /// index into the census's held finds; the find `within` names,
    /// if one, is not repeated here.
    pub through: Vec<usize>,
    /// The other roots binding the resource the path hopped into: the
    /// same member of the same type, holding the same pointer. A
    /// handle moved out of a struct field leaves its bytes behind, so
    /// one oneshot can be two roots and only one of them heads the
    /// path; every root here reaches this slot as truly as that one
    /// does. Empty for a slot no hop reached.
    pub aliases: Vec<SlotRoot>,
    /// Whether the task's current await reaches the slot, and where
    /// it is held.
    pub reach: Reach,
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
                Some(reading) if !kind.reads_apart() => {
                    format!("{} {primitive:#x} ({})", kind.word(), reading.words(*kind))
                }
                _ => format!("{} {primitive:#x}", kind.word()),
            },
            Attribution::Typed { holder, .. } => format!("slot {:#x} in {holder}", self.slot),
            // What the slot is a wait for is what names it: the
            // response the connection is carrying, not the oneshot's
            // own words, which the connection's `via` line already says.
            Attribution::Response {
                primitive,
                conn,
                role,
                version,
                ..
            } => format!(
                "oneshot rx {primitive:#x} (response for {} {conn:#x})",
                http_kind_word(*role, *version)
            ),
            Attribution::Unknown => format!("unknown @ {:#x}", self.slot),
        }
    }

    /// The slot's entry in a listing's cell: the kind of thing the
    /// waker is parked in, as a verified wait's cell names the same
    /// kind — the kind word alone, with the address and whatever a
    /// reader read left to the detail lines. A typed slot is named by
    /// the type it sits in, as the task block's `held in:` names it;
    /// an unknown one is `unknown`.
    pub fn cell(&self) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer { .. }) => "timer".to_string(),
            Attribution::Registry(RegistrySlot::Io { .. }) => "io".to_string(),
            Attribution::Registry(RegistrySlot::Semaphore { .. }) => "semaphore".to_string(),
            Attribution::Registry(RegistrySlot::Join { task }) => format!("join {task}"),
            Attribution::Owner { kind, .. } => kind.word().to_string(),
            Attribution::Response { .. } => OwnerKind::OneshotRx.word().to_string(),
            Attribution::Typed { holder, .. } => holder.to_string(),
            Attribution::Unknown => "unknown".to_string(),
        }
    }

    /// The slot's label for a detail line: the kind word and the
    /// address that identifies the slot, whatever a reader would add.
    /// A typed slot is named by its holder as well, since nothing
    /// else on its line is: its `location` says where the slot sits,
    /// not what type the storage belongs to.
    pub fn label(&self) -> String {
        match &self.attribution {
            Attribution::Registry(RegistrySlot::Timer { entry, .. }) => format!("timer {entry:#x}"),
            Attribution::Owner {
                kind, primitive, ..
            } => format!("{} {primitive:#x}", kind.word()),
            Attribution::Response { primitive, .. } => {
                format!("{} {primitive:#x}", OwnerKind::OneshotRx.word())
            }
            // A typed slot's entry is already its address and its
            // holder, with no reading to leave off, so it is its own
            // label.
            _ => self.entry(None),
        }
    }

    /// The place the waker is held, for a `held in:` line of a slot
    /// whose entry is all there is to say: the holding type at the
    /// slot's address, or an unknown slot's address alone — the type
    /// first, as an unknown slot's entry already reads.
    pub fn place(&self) -> String {
        match &self.attribution {
            Attribution::Typed { holder, .. } => format!("{holder} @ {:#x}", self.slot),
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
            Attribution::Response { .. } => OwnerKind::OneshotRx.word().to_string(),
            Attribution::Typed { holder, .. } => holder.to_string(),
            Attribution::Unknown => "unknown".to_string(),
        }
    }

    /// The detail line's text after the entry: the place the waker is
    /// held, then what says it is current — worded to follow the
    /// entry on one line, or a `held in:` label. `None` for an
    /// unknown slot, whose address is all there is to say.
    pub fn detail(&self, stopped: Option<RawInstant>) -> Option<String> {
        Some(match &self.attribution {
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
                format!("the wheel entry{state}{due}")
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
                format!("{site}, {interest}{ready}")
            }
            Attribution::Registry(RegistrySlot::Semaphore { node, .. }) => {
                format!("its wake-queue node @ {node:#x}")
            }
            Attribution::Registry(RegistrySlot::Join { .. }) => "its trailer".to_string(),
            // No path of the owner's reaches the cell; the task whose
            // path does is named instead, and `whatis` on the
            // connection's own slot prints that path.
            Attribution::Response { connection, .. } => {
                format!("the response callback's receiver cell, held by {connection}")
            }
            // Where the slot sits is a path, which is a line of its
            // own ([`Self::location`]): the members it names say what
            // holds the waker, and say it the way a `print` reads it.
            Attribution::Owner { .. } | Attribution::Typed { .. } => return None,
            Attribution::Unknown => return None,
        })
    }

    /// What the slot's own reading says where those words are a line
    /// of their own — a channel's counts, a watch's version and
    /// handles. The other primitives carry theirs in the entry.
    pub fn words(&self) -> Option<String> {
        match &self.attribution {
            Attribution::Owner {
                kind,
                reading: Some(reading),
                ..
            } if kind.reads_apart() => Some(reading.words(*kind)),
            _ => None,
        }
    }

    /// Everything the slot's reading says, wherever it is carried:
    /// for a line that is the slot and nothing else, and so has room
    /// for all of it.
    fn reading_words(&self) -> Option<String> {
        match &self.attribution {
            Attribution::Owner {
                kind,
                reading: Some(reading),
                ..
            } => Some(reading.words(*kind)),
            _ => None,
        }
    }

    /// Where the slot sits, as a path from the root it was located
    /// in: a selector for that root and the members to the waker,
    /// which `print` reads as written. The note a gated or unchecked
    /// slot carries closes the line — what the storage says about
    /// itself, where it says anything.
    pub fn location(&self) -> Option<String> {
        let (path, validity) = match &self.attribution {
            Attribution::Owner { path, validity, .. }
            | Attribution::Typed { path, validity, .. } => (path, validity),
            _ => return None,
        };
        Some(format!("{}{}", path.location(), validity.note()))
    }

    /// The path, where the slot was located by type.
    pub fn path(&self) -> Option<&SlotPath> {
        self.attribution.path()
    }
}

impl Attribution {
    /// The path, where the slot was located by type.
    pub fn path(&self) -> Option<&SlotPath> {
        match self {
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
    /// Slots placed from another task's side ([`Attribution::Response`]).
    pub joined: usize,
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
            for &index in &slot.through {
                self.by_find.entry(index).or_default().push(i);
            }
            // A second binding of the resource is armed by the slot as
            // the one the path names is; the root itself is filed
            // below, so nothing is entered twice.
            for alias in &slot.aliases {
                match *alias {
                    SlotRoot::Find { index, .. } => self.by_find.entry(index).or_default().push(i),
                    SlotRoot::Child { set, child, .. }
                        if !matches!(slot.owner, Owner::Child { .. }) =>
                    {
                        self.by_child.entry((set, child)).or_default().push(i)
                    }
                    _ => {}
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
                Attribution::Response { .. } => self.stats.joined += 1,
                Attribution::Unknown => self.stats.unknown += 1,
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

    /// Whether `ty` is the type a slot is: a `RawWaker` — a type the
    /// waker-word roles root at — or a struct that is one at its own
    /// address and nothing else, as `Waker { waker: RawWaker }` is.
    fn is_waker(&self, ty: BundleType<'b>) -> bool {
        let raw = self.view.walk_roots(WalkRole::WakerData);
        if raw.contains(&ty.id()) {
            return true;
        }
        if !matches!(ty.classify(), TypeClass::Struct) {
            return false;
        }
        let mut sized = ty.members().filter(|m| m.ty().size() > 0);
        matches!(
            (sized.next(), sized.next()),
            (Some(m), None)
                if m.offset() == 0 && m.ty().size() == ty.size() && raw.contains(&m.ty().id())
        )
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
        join_response_cells(&mut out.slots, sources);
        out.slots.sort_by_key(|s| s.hit);
        out.stale.sort_by_key(|s| s.hit);
        out.index();
        out.stats.elapsed = started.elapsed();
        out
    }
}

/// The receiver cell of a response callback a verified client
/// connection watches, and what a slot found there is to be named by.
struct ResponseCell {
    primitive: u64,
    reading: OneshotState,
    connection: TaskRef,
    conn: u64,
    role: HttpRole,
    version: Option<HttpVersion>,
    /// The task header the connection's own read of the cell named,
    /// where the waker there is a task's: what the slot's owner must
    /// agree with.
    waker_task: Option<u64>,
}

/// The receiver cells of every response callback the analysis
/// verified a client connection on, by the cell's address. A
/// connection with a request in flight is parked on the callback's
/// sender cell; the same `Inner`'s receiver cell holds the waker of
/// whoever awaits the response, sixteen bytes away by the oneshot's
/// own layout — which the observation recorded, so no offset is
/// assumed here.
fn response_cells(sources: &Sources<'_>) -> HashMap<u64, ResponseCell> {
    let mut cells = HashMap::default();
    for wait in &sources.analysis.waits {
        let Some(verified) = wait.verified() else {
            continue;
        };
        let WaitTarget::HttpConn {
            addr: conn,
            role,
            version,
            via: Some(via),
            ..
        } = verified.target()
        else {
            continue;
        };
        let WaitTarget::Oneshot {
            addr: inner,
            side: OneshotSide::Tx,
            ..
        } = **via
        else {
            continue;
        };
        let Some(ResourceObservation::HttpConn(http)) = &wait.observation else {
            continue;
        };
        let Some(callback) = http
            .client
            .as_ref()
            .and_then(|client| client.callback.as_ref())
        else {
            continue;
        };
        // The cell holds a waker only while the state word says so; a
        // pair found there otherwise is a ghost of an earlier receiver.
        let Some(cell) = callback.rx_task_at else {
            continue;
        };
        if callback.inner != inner || !callback.state.rx_task_set() {
            continue;
        }
        cells.insert(
            cell,
            ResponseCell {
                primitive: inner,
                reading: callback.state,
                connection: wait.task,
                conn: *conn,
                role: *role,
                version: *version,
                waker_task: callback.rx_waker.as_ref().and_then(|waker| waker.task()),
            },
        );
    }
    cells
}

/// Name the slots that lie in a response callback's receiver cell as
/// the caller awaiting a response the analysis knows from the
/// connection's side: a slot no owner's own values reached, and one
/// whose owner's values reached that same oneshot's receiver — what
/// the connection says it is for names it better than the oneshot's own
/// words. The connection's own read of the cell, where it named a task,
/// must name the slot's owner — the join is the address, and that read
/// is its check.
fn join_response_cells(slots: &mut [AttributedSlot], sources: &Sources<'_>) {
    let cells = response_cells(sources);
    if cells.is_empty() {
        return;
    }
    for slot in slots {
        let Some(cell) = cells.get(&slot.slot) else {
            continue;
        };
        let joinable = match &slot.attribution {
            Attribution::Unknown => true,
            Attribution::Owner {
                kind: OwnerKind::OneshotRx,
                primitive,
                ..
            } => *primitive == cell.primitive,
            _ => false,
        };
        if !joinable {
            continue;
        }
        if let (Some(named), Owner::Task { header, .. }) = (cell.waker_task, slot.owner)
            && named != header
        {
            continue;
        }
        slot.attribution = Attribution::Response {
            primitive: cell.primitive,
            reading: cell.reading,
            connection: cell.connection,
            conn: cell.conn,
            role: cell.role,
            version: cell.version,
        };
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
        // The pointers of one root at a time, for the reach verdict,
        // which wants only the roots inside the holding frame: most
        // owners never need the whole enumeration above, and are not
        // made to walk every root for it.
        let mut per_root: Vec<Option<Vec<PointerMember>>> = vec![None; roots.len()];
        let mut chain_roots: Option<Vec<Root<'b>>> = None;
        for &i in indexes {
            let hit = &hits[i];
            let mut within = None;
            let mut through = Vec::new();
            // The root the slot was placed under and the values from
            // it down to the slot, for the reach verdict below.
            let mut placed: Option<(SlotRoot, Vec<ValueKey>)> = None;
            let attribution = if let Some(slot) = self.registry.get(&hit.slot) {
                // A registry slot is filed under the value it lies in:
                // a chain frame or a find. It also arms every find whose
                // chain runs through that value past the find's own
                // storage — the way a task's chain frames are the
                // task's: a boxed `Sleep` an interval's tick polls
                // holds its wheel entry on the heap, where the `Sleep`
                // may be a find of its own under the interval local
                // and the tick a second find polling it. Where no
                // value of its own holds the slot, the first such
                // frame is what it is filed under.
                let chain = chain_roots.get_or_insert_with(|| self.chain_roots_of(owner));
                let holder = roots
                    .iter()
                    .find(|r| contains(r.value, hit.slot))
                    .or_else(|| chain.iter().find(|r| contains(r.value, hit.slot)));
                within = holder.map(|r| r.at);
                placed = holder.map(|r| (r.at, vec![ValueKey::of(r.value)]));
                for root in chain.iter().filter(|r| contains(r.value, hit.slot)) {
                    if let SlotRoot::Find { index, .. } = root.at
                        && within != Some(root.at)
                        && !through.contains(&index)
                    {
                        through.push(index);
                    }
                }
                Attribution::Registry(slot.clone())
            } else {
                let located = match self.by_containment(hit, &roots) {
                    Ok(Some(located)) => Some(located),
                    Err(mut demoted) => {
                        demoted.hit = i;
                        stale.push(demoted);
                        continue;
                    }
                    Ok(None) => {
                        let pointers = pointers.get_or_insert_with(|| self.pointer_members(&roots));
                        self.by_hop(hit, &roots, pointers)
                    }
                };
                match located {
                    Some((attribution, spine)) => {
                        placed = attribution.path().map(|path| (path.root, spine));
                        attribution
                    }
                    None => Attribution::Unknown,
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
            // Collected after the refinements above, which may replace
            // the attribution but never the path it was located by.
            let aliases = match (&attribution, pointers.as_deref()) {
                (
                    Attribution::Owner { path, .. } | Attribution::Typed { path, .. },
                    Some(pointers),
                ) => self.aliases_of(&roots, pointers, path),
                _ => Vec::new(),
            };
            let reach = match &placed {
                Some((at, spine)) => {
                    let steps = attribution.path().map(|p| p.steps.as_slice());
                    self.reach(
                        *at,
                        steps.unwrap_or(&[]),
                        spine,
                        &roots,
                        pointers.as_deref(),
                        &mut per_root,
                    )
                }
                None => Reach::Unlocated,
            };
            slots.push(AttributedSlot {
                hit: i,
                slot: hit.slot,
                owner,
                attribution,
                within,
                through,
                aliases,
                reach,
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

    /// The watch channel whose `notify_rx` array holds the `Notify` at
    /// `notify`, among the `Arc<watch::Shared<_>>`s the owner's values
    /// point at: the `Shared`'s address, for the slot's primitive, and
    /// the channel's reading. Nothing is dereferenced but the `Shared`
    /// a pointer the owner holds already names.
    fn watch_of(&self, notify: u64, pointers: &[PointerMember]) -> Option<(u64, Reading)> {
        let mut seen: HashSet<u64> = HashSet::default();
        let arcs = self.types.view.walk_roots(WalkRole::WatchSharedState);
        for p in pointers {
            if !arcs.contains(&p.pointee) || !seen.insert(p.target) {
                continue;
            }
            let Some(ty) = self.types.view.ty(p.pointee) else {
                continue;
            };
            let Ok(arc) = Value::read(self.proc, ty, p.target) else {
                continue;
            };
            let at = |role| self.walk_role(role, arc);
            let word = |role| self.word_of(role, arc);
            if let Some(words) = watch_words_of(arc, notify, &at, &word) {
                return Some((
                    words.addr,
                    Reading::Watch {
                        version: words.version,
                        closed: words.closed,
                        receivers: words.receivers,
                        senders: words.senders,
                    },
                ));
            }
        }
        None
    }

    /// The addresses the analysis already made branches of `owner`'s
    /// stop — what the task is, by its own state machine, polling. Only
    /// an ordering preference ([`order_roots`]): a root that is none of
    /// them is walked all the same.
    fn branch_addrs(&self, owner: Owner) -> HashSet<u64> {
        use super::assess::WaitAssessment;

        let Owner::Task { index, .. } = owner else {
            return HashSet::default();
        };
        let Some(wait) = self.sources.analysis.waits.get(index) else {
            return HashSet::default();
        };
        let members = match &wait.assessment {
            WaitAssessment::Set(set) => set.members.as_slice(),
            // Every other assessment carries its branches in `held`,
            // empty unless the continuation is unknown.
            _ => wait.held.as_slice(),
        };
        members
            .iter()
            .filter_map(|member| member.key.map(|key| key.addr))
            .collect()
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
                        frame: 0,
                    },
                    value,
                });
            }
        }
        order_roots(&mut roots, &self.branch_addrs(owner));
        roots
    }

    /// The frames each of `owner`'s finds delegates to beyond its own
    /// value — what the find polls through a pointer, a boxed `Sleep`
    /// behind an interval's tick — each filed under the find. Only a
    /// registry slot is placed by these: a typed slot's path names its
    /// root's type, and a chain frame is not the find's.
    fn chain_roots_of(&self, owner: Owner) -> Vec<Root<'b>> {
        let mut roots = Vec::new();
        for &i in self.finds.get(&OwnerKey::from(owner)).into_iter().flatten() {
            let held = &self.sources.census.held[i];
            for key in held.frames.iter().filter(|k| k.addr != held.addr) {
                let Some(ty) = self.types.view.ty(key.ty) else {
                    continue;
                };
                if ty.size() > 0
                    && let Ok(value) = Value::read(self.proc, ty, key.addr)
                {
                    roots.push(Root {
                        at: SlotRoot::Find {
                            index: i,
                            addr: held.addr,
                            // The frame the path runs from is the
                            // innermost one it passes through, which
                            // only the walk knows ([`path_from`]).
                            frame: 0,
                        },
                        value,
                    });
                }
            }
        }
        order_roots(&mut roots, &self.branch_addrs(owner));
        roots
    }

    /// Rule 2: the innermost root whose storage holds the hit, walked
    /// down to it, with the values from the root down to the slot.
    /// `Ok(None)` where no root holds it.
    fn by_containment(
        &self,
        hit: &Hit,
        roots: &[Root<'b>],
    ) -> Result<Option<(Attribution, Vec<ValueKey>)>, Stale> {
        // The roots come innermost first.
        let containing = roots.iter().find(|r| contains(r.value, hit.slot));
        let Some(root) = containing else {
            return Ok(None);
        };
        match self.locate_member(root.value, hit.slot - root.value.addr) {
            Located::Slot { trail, validity } => Ok(Some((
                self.name_slot(self.path_from(root, &trail, None), &trail, validity),
                spine(root.value, &trail),
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
    ) -> Option<(Attribution, Vec<ValueKey>)> {
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
            let offset = hit.slot - p.target;
            if offset >= pointee.size() {
                continue;
            }
            let Ok(value) = Value::read(self.proc, pointee, p.target) else {
                continue;
            };
            let Located::Slot { trail, validity } = self.locate_member(value, offset) else {
                continue;
            };
            let root = &roots[p.root];
            let to_pointer = self.steps_to(root.value, p.at - root.value.addr);
            let mut keys = spine(root.value, &to_pointer);
            keys.extend(spine(value, &trail));
            return Some((
                self.name_slot(
                    self.path_from(
                        root,
                        &to_pointer,
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
                ),
                keys,
            ));
        }
        None
    }

    /// Whether the task's current await reaches a slot placed under
    /// `at`, with `steps` the path's steps from it and `spine` the
    /// values from the root down to the slot ([`spine`]).
    ///
    /// The holding frame is the root's own for a chain frame, the
    /// frame of the find for a find (of the find the task's frame
    /// holds, where finds nest), and #0 for a set child, which is a
    /// chain of its own. A slot held in frame #0 is awaited: the
    /// container is the stop itself. Otherwise the pointers the owner's
    /// roots hold — collected once per owner, innermost root first —
    /// are scanned for one a frame *strictly inside* the holding one
    /// holds whose target and pointee type are a value on the spine,
    /// deepest first: the `&mut JoinSet` a `join_next` captures, the
    /// `&mut Interval` a tick holds. The type constraint is what keeps
    /// a `&mut self` in an inner frame, whose struct happens to
    /// contain things, from reading as awaiting whatever it contains.
    /// Nothing else borrows it: the slot is parked, installed by an
    /// await that has returned.
    fn reach(
        &self,
        at: SlotRoot,
        steps: &[String],
        spine: &[ValueKey],
        roots: &[Root<'b>],
        pointers: Option<&[PointerMember]>,
        per_root: &mut [Option<Vec<PointerMember>>],
    ) -> Reach {
        let Some(first) = spine.first().copied() else {
            return Reach::Unlocated;
        };
        let (frame, local, container, mut keys) = match at {
            SlotRoot::Child { .. } => (0, None, first, spine.to_vec()),
            // Frame #0 is the stop itself, and its own value is the
            // container.
            SlotRoot::Frame { frame: 0, .. } => (0, None, first, spine.to_vec()),
            SlotRoot::Frame { frame, .. } => {
                // The local is what the first named step enters — a
                // coroutine's state step is a frame boundary, not a
                // local, and a plain future's first member is the
                // local's counterpart — or the frame itself where
                // that step enters the slot and no aggregate.
                let named = steps.iter().position(|s| step_text(s).is_some());
                let local = named.and_then(|i| step_text(&steps[i])).map(str::to_string);
                let container = named.and_then(|i| spine.get(i + 1)).copied();
                (frame, local, container.unwrap_or(first), spine.to_vec())
            }
            SlotRoot::Find { index, .. } => {
                let Some((frame, top)) = self.find_frame(index) else {
                    return Reach::Unlocated;
                };
                // The find itself is the container; the frame and local
                // are the outermost find's, which is the one a frame of
                // the task's own holds.
                let held = &self.sources.census.held;
                let container = ValueKey {
                    addr: held[index].addr,
                    ty: held[index].ty,
                };
                // The local holding the find is a value on the way to
                // the slot too, and what a `&mut Interval` borrows.
                let mut keys = spine.to_vec();
                if let Some(local) = self.local_key(roots, frame, &held[top].local) {
                    keys.insert(0, local);
                }
                (frame, Some(held[top].local.clone()), container, keys)
            }
        };
        let holding = |container| Holding {
            container,
            frame,
            local: local.clone(),
        };
        if frame == 0 {
            return Reach::Awaited(holding(container));
        }
        // The pointers of the roots strictly inside the holding frame:
        // from the owner's whole enumeration where a hop already paid
        // for it, else each inner root walked once and kept.
        let inner: Vec<usize> = (0..roots.len())
            .filter(|&r| self.frame_of(roots[r].at).is_some_and(|f| f < frame))
            .collect();
        let borrowed = |members: &[PointerMember], key: &ValueKey| {
            members
                .iter()
                .any(|p| p.target == key.addr && p.pointee == key.ty)
        };
        keys.dedup();
        for key in keys.iter().rev() {
            let hit = match pointers {
                Some(pointers) => borrowed(
                    &pointers
                        .iter()
                        .filter(|p| inner.contains(&p.root))
                        .copied()
                        .collect::<Vec<_>>(),
                    key,
                ),
                None => inner.iter().any(|&r| {
                    let members = per_root[r].get_or_insert_with(|| {
                        let mut out = Vec::new();
                        self.collect_pointers(roots[r].value, r, 0, &mut out);
                        out
                    });
                    borrowed(members, key)
                }),
            };
            if hit {
                return Reach::Awaited(holding(*key));
            }
        }
        Reach::Parked(holding(container))
    }

    /// The chain frame a root is held in, numbered as the listings
    /// number frames: a chain frame's own, a find's holding frame,
    /// none for a set child.
    fn frame_of(&self, at: SlotRoot) -> Option<usize> {
        match at {
            SlotRoot::Frame { frame, .. } => Some(frame),
            SlotRoot::Find { index, .. } => self.find_frame(index).map(|(frame, _)| frame),
            SlotRoot::Child { .. } => None,
        }
    }

    /// The task's chain frame holding find `index` — through the finds
    /// it nests under, up to the one a frame of the task's own holds —
    /// and that outermost find's own index. `None` for a find under a
    /// set child, whose frames are the child's.
    fn find_frame(&self, index: usize) -> Option<(usize, usize)> {
        let held = &self.sources.census.held;
        let mut top = index;
        loop {
            match held.get(top)?.via {
                None => return Some((held[top].frame, top)),
                Some(Via::Held(outer)) => top = outer,
                Some(Via::SetChild { .. }) => return None,
            }
        }
    }

    /// The value of `local` in the coroutine frame `frame` of the
    /// owner's chain, where that frame is among `roots` and its state
    /// holds the local: what a borrow of the local targets.
    fn local_key(&self, roots: &[Root<'b>], frame: usize, local: &str) -> Option<ValueKey> {
        let root = roots
            .iter()
            .find(|r| matches!(r.at, SlotRoot::Frame { frame: f, .. } if f == frame))?;
        let (_, payload) = root.value.active_variant_raw().ok()?;
        let value = payload.try_member_raw(local).ok()??;
        Some(ValueKey::of(value))
    }

    /// The roots other than the one `path` names that hold the very
    /// pointer it hopped through: the same member, at the same offset,
    /// of a root of the same type. Those are two bindings of one
    /// resource — the moved-from copy a `let x = self.y` leaves in the
    /// frame beside the local that owns it now — and a reader asking
    /// about either is asking about this slot.
    ///
    /// Type and offset are what keep that from over-reaching. Two
    /// *different* handles on one allocation — a oneshot's sender and
    /// its receiver, both holding `Arc<Inner<T>>` — point at the same
    /// target, and the receiver's parked waker is no evidence about
    /// the sender. Requiring the same member of the same type admits
    /// only copies of one handle.
    fn aliases_of(
        &self,
        roots: &[Root<'b>],
        pointers: &[PointerMember],
        path: &SlotPath,
    ) -> Vec<SlotRoot> {
        let Some(hop) = &path.hop else {
            return Vec::new();
        };
        let Some(taken) = pointers
            .iter()
            .find(|p| p.at == hop.from && p.target == hop.addr)
        else {
            return Vec::new();
        };
        let base = &roots[taken.root];
        let (ty, offset) = (base.value.ty.id(), taken.at - base.value.addr);
        let mut out = Vec::new();
        // Sorted by target, so the pointers into the pointee are one run.
        let from = pointers.partition_point(|p| p.target < hop.addr);
        for p in &pointers[from..] {
            if p.target != hop.addr {
                break;
            }
            let root = &roots[p.root];
            if p.root == taken.root
                || root.value.ty.id() != ty
                || p.at.checked_sub(root.value.addr) != Some(offset)
                || out.contains(&root.at)
            {
                continue;
            }
            out.push(root.at);
        }
        out
    }

    /// Name a located slot: the owner-name table over the aggregates
    /// on its trail, outermost first, else the innermost aggregate
    /// that is not a wrapper. A primitive owns a slot when its type is
    /// one the walk roles reading it root at — the roles' binder chose
    /// those types for this target's tokio, so the table follows
    /// whatever that release calls them.
    fn name_slot(&self, path: SlotPath, trail: &[Step<'b>], validity: Validity) -> Attribution {
        let impls = self.sources.impls;
        let view = self.types.view;
        // A oneshot's `ArcInner<Inner<T>>`s are the state word's roots;
        // the `Inner`s are what those hold as `data`.
        let oneshot_arcs = view.walk_roots(WalkRole::OneshotState);
        let is_oneshot_inner = |ty: BundleType<'b>| {
            oneshot_arcs.iter().any(|&arc| {
                view.ty(arc)
                    .and_then(|arc| arc.member("data"))
                    .is_some_and(|data| data.ty().id() == ty.id())
            })
        };
        let chans = view.walk_roots(WalkRole::ChanTxCount);
        let notifieds = view.walk_roots(WalkRole::NotifiedNotify);
        for (i, step) in trail.iter().enumerate() {
            let ty = step.holder.ty;
            let name = ty.name();
            let under = |member: &str| trail[i..].iter().any(|s| s.name == member);
            let kind = if is_oneshot_inner(ty) {
                // The `ArcInner` the `Inner` sits in is the step before
                // it on the trail; the receiver-rooted roles read from
                // there.
                let reading = trail[..i]
                    .iter()
                    .rev()
                    .find(|s| oneshot_arcs.contains(&s.holder.ty.id()))
                    .and_then(|arc| self.oneshot_reading(arc.holder));
                if under("rx_task") {
                    Some((OwnerKind::OneshotRx, step.holder.addr, reading))
                } else if under("tx_task") {
                    Some((OwnerKind::OneshotTx, step.holder.addr, reading))
                } else {
                    None
                }
            } else if chans.contains(&ty.id()) {
                Some((
                    OwnerKind::Mpsc,
                    step.holder.addr,
                    self.mpsc_reading(step.holder),
                ))
            } else if notifieds.contains(&ty.id()) {
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
            .find(|s| s.holder.ty.size() > waker_size && !is_wrapper(s.holder.ty))
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
    fn steps_to(&self, value: Value<'b>, offset: u64) -> Vec<Step<'b>> {
        match self.descend(value, offset, Terminal::Pointer) {
            Ok(descent) => descent.trail,
            Err(_) => Vec::new(),
        }
    }

    /// The path to a slot `trail` steps into `root`, or — with `hop` —
    /// to the pointer member at the end of `trail` and on into the
    /// pointee.
    ///
    /// A find is walked from one value, but its chain has frames, and
    /// a cursor on that find stands on the innermost of them. So the
    /// path is re-rooted at the innermost frame the walk passed
    /// through: the steps before it are that frame's own nesting,
    /// which no cursor is outside of, and the ones after it are what a
    /// reader names from where the cursor stands.
    fn path_from(&self, root: &Root<'b>, trail: &[Step<'b>], hop: Option<Hop>) -> SlotPath {
        let SlotRoot::Find { index, addr, .. } = root.at else {
            return SlotPath {
                root: root.at,
                steps: trail.iter().map(|s| s.name.clone()).collect(),
                hop,
            };
        };
        let frames: &[ValueKey] = match self.sources.census.held.get(index) {
            Some(held) => &held.frames,
            None => &[],
        };
        // The chain runs outermost first, the listings number frames
        // the other way round.
        let numbered = |value: Value<'b>| {
            frames
                .iter()
                .position(|f| f.addr == value.addr && f.ty == value.ty.id())
                .map(|at| frames.len() - 1 - at)
        };
        let mut frame = numbered(root.value).unwrap_or(0);
        let mut from = 0;
        for (i, step) in trail.iter().enumerate() {
            if let Some(number) = numbered(step.holder) {
                frame = number;
                from = i;
            }
        }
        SlotPath {
            root: SlotRoot::Find { index, addr, frame },
            steps: trail[from..].iter().map(|s| s.name.clone()).collect(),
            hop,
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
            let at_terminal = match terminal {
                Terminal::Waker => self.types.is_waker(ty),
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
                    if is_option_shaped(ty) {
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
                    step(
                        &mut descent.trail,
                        variant_step(active.name, ty.is_coroutine()),
                        cur,
                    );
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
                    step(&mut descent.trail, format!("[{index}]"), cur);
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
/// member named the same. A coroutine's is marked `<#…>`: its states
/// are numbered rather than named, and it is a frame boundary — the
/// locals under it are what a reader addresses, and a path leaves the
/// state itself out.
fn variant_step(name: &str, coroutine: bool) -> String {
    match coroutine {
        true => format!("<#{name}>"),
        false => format!("<{name}>"),
    }
}

/// Innermost first: a smaller value before a larger one, a find before
/// a frame of the same size (the find is what the listings name), an
/// inner frame before an outer, and — where those leave two roots tied
/// — a branch of the owner's stop before a root that is none. Wrapper
/// frames that share one allocation with what they wrap are one range
/// each and are walked once.
///
/// The tie is not hypothetical: a handle moved out of a struct field
/// leaves a copy of its bytes behind in the frame, so one resource has
/// two roots of the same type and size pointing at it, and whichever
/// the sweep walks from is the one a slot's path names. Naming the
/// branch the analysis already reached means a slot located behind it
/// is recognized as that branch's ([`member_accounts`]) rather than
/// printing beside it as a wake route of its own.
fn order_roots(roots: &mut Vec<Root<'_>>, branches: &HashSet<u64>) {
    let rank = |root: &Root<'_>| match root.at {
        SlotRoot::Find { .. } | SlotRoot::Child { .. } => 0,
        SlotRoot::Frame { frame, .. } => 1 + frame,
    };
    roots.sort_by_key(|r| {
        (
            r.value.bytes.len(),
            rank(r),
            !branches.contains(&r.value.addr),
        )
    });
    roots.dedup_by_key(|r| (r.value.addr, r.value.bytes.len()));
}

/// The values an offset walk passed through, outermost first: the
/// root, then the value each step entered — every aggregate on the
/// way to the slot, which is what a borrow from an inner frame can
/// target. The step's `holder` is the value it was taken in, so the
/// value a step entered is the next step's holder; the last step
/// enters the slot itself, which is no aggregate.
fn spine(root: Value<'_>, trail: &[Step<'_>]) -> Vec<ValueKey> {
    std::iter::once(ValueKey::of(root))
        .chain(trail.iter().skip(1).map(|s| ValueKey::of(s.holder)))
        .collect()
}

/// The `ty`-typed view at `offset` within `value`, or `None` where the
/// bytes do not cover it.
fn sub<'b>(value: Value<'b>, offset: u64, ty: BundleType<'b>) -> Option<Value<'b>> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(ty.size()).ok()?)?;
    let bytes = value.bytes.get(start..end)?;
    Some(Value::new(ty, value.addr + offset, bytes))
}

/// A type's last path segment, generic arguments dropped: `Inner`,
/// `Chan`, `Notified`.
fn short_name(name: &str) -> String {
    let base = name.split('<').next().unwrap_or(name);
    base.rsplit("::").next().unwrap_or(base).to_string()
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
            }
            // A caller's slot named from the connection's side is the
            // same oneshot's receiver cell, named for what it awaits.
            | Attribution::Response { primitive, .. },
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
        // A connection is parked on the primitive its `via` names — the
        // request channel while idle, the response callback's sender
        // cell while a request is in flight — so the slot that primitive
        // accounts for is the connection's; a slot inside the dispatcher
        // itself is too.
        (
            Attribution::Owner {
                kind: OwnerKind::Mpsc,
                primitive,
                ..
            },
            WaitTarget::HttpConn { via: Some(via), .. },
        ) if matches!(**via, WaitTarget::Channel { addr, .. } if addr == *primitive) => true,
        (
            Attribution::Owner {
                kind: OwnerKind::OneshotTx,
                primitive,
                ..
            },
            WaitTarget::HttpConn { via: Some(via), .. },
        ) if matches!(**via, WaitTarget::Oneshot { addr, .. } if addr == *primitive) => true,
        // A connection whose rule names no primitive — a server between
        // requests or handling one, a client with a body arriving, a
        // connection still choosing its version — is parked on its
        // socket, so the io slot is the wait's own. Which registration
        // is the connection's is not established from the dispatcher,
        // so any io slot of the task's is taken for it.
        (
            Attribution::Registry(RegistrySlot::Io { .. }),
            WaitTarget::HttpConn { via: None, .. },
        ) => true,
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
        // The path heads at one binding of the resource; the branch may
        // be another of them.
        if slot.aliases.iter().any(|alias| match *alias {
            SlotRoot::Find { addr, .. } | SlotRoot::Child { addr, .. } => addr == key.addr,
            SlotRoot::Frame { .. } => false,
        }) {
            return true;
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
        (_, Some(SlotRef::Swept { slot: swept, .. })) => swept.slot == slot.slot,
        _ => false,
    };
    by_registry
        || matches!(&member.assessment, Some(WaitAssessment::Waiting(verified))
            if verified_accounts(verified, slot, size_of))
}

impl AttributedSlot {
    /// The slot's detail line: its label, then where it sits and what
    /// says it is current — except a wheel entry, which is spelled by
    /// its deadline, with the wheel's own word appended where the entry
    /// is not simply registered, and an unknown slot, which is its
    /// label alone.
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
        match (self.detail(stopped), self.reading_words()) {
            (Some(detail), _) => format!("{}: {detail}", self.label()),
            // Nothing else stands on this line, so it carries the
            // whole reading — including the words the entry leaves to
            // a line of their own.
            (None, Some(words)) => format!("{} ({words})", self.label()),
            (None, None) => self.label(),
        }
    }

    /// A wheel entry without its deadline: the entry that holds the
    /// waker, and whatever the wheel says about it beyond being
    /// registered. For a line under one that gives the deadline
    /// already, which is the target's to give. `None` for a slot that
    /// is no wheel entry.
    pub fn wheel_entry(&self) -> Option<String> {
        let Attribution::Registry(RegistrySlot::Timer { entry, state, .. }) = &self.attribution
        else {
            return None;
        };
        Some(match state {
            Some(state) if *state != WheelState::Registered => {
                format!("timer @ {entry:#x} ({state})")
            }
            _ => format!("timer @ {entry:#x}"),
        })
    }

    /// What the wait this slot belongs to is on, where the slot names
    /// it: a registry decoded the resource, or the owner table named
    /// the type the slot sits in. `None` for a typed slot no table
    /// names and for an unknown one — their entries say where the
    /// slot is, which is not the same question.
    /// The reading rides along: this names the resource and nothing
    /// else, so it is the line with room for it.
    pub fn waits_on(&self, stopped: Option<RawInstant>) -> Option<String> {
        match &self.attribution {
            Attribution::Registry(_) | Attribution::Owner { .. } | Attribution::Response { .. } => {
                Some(match self.words() {
                    Some(words) => format!("{} ({words})", self.entry(stopped)),
                    None => self.entry(stopped),
                })
            }
            Attribution::Typed { .. } | Attribution::Unknown => None,
        }
    }

    /// The slot's line headed by its entry rather than its label — an
    /// owner slot's primitive with the words its reader read — for a
    /// listing whose cell does not carry those words. The other kinds
    /// have no reading, and their entry heads the line as their label
    /// would.
    pub fn entry_line(&self, stopped: Option<RawInstant>) -> String {
        match (&self.attribution, self.detail(stopped)) {
            (Attribution::Owner { .. }, detail) => match detail {
                Some(detail) => format!("{}: {detail}", self.entry(stopped)),
                None => self.entry(stopped),
            },
            _ => self.line(stopped),
        }
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
                    |t| matches!(&t.future, FutureInfo::Known(k) if k.name(self.ctx.view).contains(name)),
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
        assert_eq!(buckets, ["mpsc rx", "oneshot rx", "timer", "watch rx"]);
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
                    // A oneshot's reading rides on its entry, so it is
                    // not also a line of its own: the line naming the
                    // primitive says it exactly once.
                    assert_eq!(slot.words(), None);
                    assert_eq!(
                        slot.waits_on(stopped),
                        Some(format!(
                            "oneshot rx {primitive:#x} (nothing sent, sender alive)"
                        ))
                    );
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
                    // Where it sits is the path, and the path is the
                    // whole of the detail: the find it was reached
                    // from, the members to the slot as a reader names
                    // them, and the bit that vouches for it.
                    assert_eq!(slot.detail(stopped), None);
                    let at = slot.location().expect("a typed slot has a location");
                    assert!(at.starts_with("future 0x"), "{at}");
                    assert!(
                        at.ends_with(" inner.Some.data.rx_task (rx_task_set)"),
                        "{at}"
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
                    assert_eq!(path.steps[..3], ["<#3>", "queue", "chan"]);
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
                    // The counts are a line of their own, so the
                    // entry names the channel and stops.
                    assert_eq!(slot.entry(stopped), format!("mpsc rx {primitive:#x}"));
                    assert_eq!(
                        slot.words().as_deref(),
                        Some("1 sender, capacity 4, 0 unread")
                    );
                    // Headed by its entry, the counts stay off — that
                    // line carries a verdict beside them; a line that
                    // is the slot alone takes them.
                    assert_eq!(slot.entry_line(stopped), format!("mpsc rx {primitive:#x}"));
                    assert_eq!(
                        slot.line(stopped),
                        format!("mpsc rx {primitive:#x} (1 sender, capacity 4, 0 unread)")
                    );
                    assert_eq!(
                        slot.waits_on(stopped),
                        Some(format!(
                            "mpsc rx {primitive:#x} (1 sender, capacity 4, 0 unread)"
                        ))
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
                    assert_eq!(slot.entry(stopped), format!("watch rx {primitive:#x}"));
                    assert_eq!(
                        slot.words().as_deref(),
                        Some("version 0, 1 sender, 1 receiver")
                    );
                    // The whole reading stands on a line of the slot's
                    // own.
                    assert_eq!(
                        slot.line(stopped),
                        format!("watch rx {primitive:#x} (version 0, 1 sender, 1 receiver)")
                    );
                    // Inside the held `changed` by containment: down
                    // through its awaitee, tokio's `Coop`, into the
                    // `changed_impl` that wrapper's `fut` holds, whose
                    // active state's awaitee is the `Notified` the
                    // slot sits in. That `Notified` is a frame of
                    // `changed`'s own chain — the frame a cursor on
                    // the find stands on — so the path is rooted
                    // there and names the members from it, the
                    // nesting above it left to the cursor.
                    let SlotRoot::Find { index, frame, .. } = path.root else {
                        panic!("{path:?}");
                    };
                    assert_eq!(over.census.held[index].local, "changed");
                    assert_eq!(frame, 0, "{path:?}");
                    assert!(path.hop.is_none());
                    assert_eq!(path.steps[..2], ["waiter", "waker"], "{:?}", path.steps);
                    assert_eq!(
                        slot.location(),
                        Some(format!(
                            "future {:#x} waiter.waker.Some",
                            over.census.held[index].addr
                        ))
                    );
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
            format!("notify rx {primitive:#x} (waiting)")
        );
        assert_eq!(waiter[0].label(), format!("notify rx {primitive:#x}"));
        assert_eq!(waiter[0].detail(stopped), None);
        assert_eq!(
            waiter[0].location().as_deref(),
            Some("frame 0 waiter.waker.Some")
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
        assert_eq!(driver[0].bucket(), *holds);
        assert_eq!(driver[0].cell(), *holds);
        // A typed slot's label names the holder too: nothing else on
        // its line does.
        assert_eq!(
            driver[0].label(),
            format!("slot {:#x} in {holds}", driver[0].slot)
        );

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
        // The ticker's wheel entry lies in the `Sleep` boxed inside its
        // `interval` local — a find of its own, armed by containment —
        // and the pinned `tick`'s chain runs through that box to the
        // same `Sleep`, so the one slot arms both: filed under the
        // `Sleep`, carried to the tick. The pacer's `spare` was never
        // registered and its unpolled `spare_tick` reaches nothing.
        let (interval, tick) = (find("interval"), find("tick"));
        let [entry] = attributed.of_find(interval).collect::<Vec<_>>()[..] else {
            panic!("{:?}", attributed.of_find(interval).collect::<Vec<_>>());
        };
        assert!(
            matches!(
                entry.attribution,
                Attribution::Registry(RegistrySlot::Timer { .. })
            ),
            "{entry:?}"
        );
        assert_eq!(
            entry.within,
            Some(SlotRoot::Find {
                index: interval,
                addr: over.census.held[interval].addr,
                frame: 0,
            })
        );
        assert_eq!(entry.through, vec![tick]);
        assert!(attributed.find_armed(tick));
        assert!(std::ptr::eq(
            attributed.of_find(tick).next().unwrap(),
            entry
        ));
        assert!(!attributed.find_armed(find("spare")));
        assert!(!attributed.find_armed(find("spare_tick")));
        // The interval tasks add the ticker's oneshot slot to the
        // owner-typed count and their two registered `Sleep`s' wheel
        // entries to the registry's, beside the selector's.
        assert_eq!(attributed.stats.owner, 6);
        assert_eq!(attributed.stats.registry, 3);
        assert_eq!(attributed.stats.typed, 1);
        assert_eq!(attributed.stats.unknown, 0);
    }

    /// Over `armed-select`, folded: the selector's four slots make its
    /// set — the cell every consumer reads, in the sweep's own words —
    /// the driver's one typed slot makes a set of one, and the holder's
    /// and the waiter's verified waits stand as they were, with no
    /// note, since the sweep found exactly the wakers their protocols
    /// read.
    #[test]
    fn test_the_fold_gives_every_consumer_the_selectors_set() {
        use crate::tokio::assess::WaitAssessment;
        use crate::tokio::waitset::{MemberRoute, SlotRef};

        let (bundle, snapshot) = load_any("armed-select");
        let over = Over::new(&bundle, &snapshot);
        let attributed = over.attribute();
        let mut analysis = analyze(
            &over.ctx,
            &over.e.list,
            &over.e.registries,
            &ReadContext::none(),
        );
        let index = |name: &str| {
            let task = over.task(name);
            over.e
                .list
                .tasks
                .iter()
                .position(|t| t.addr == task.addr)
                .unwrap()
        };
        // Before the fold the selector's set is what the analysis reads
        // on its own: the `select!`'s four branches, the oneshot, mpsc
        // and watch ones armed by their protocols — the watch's chain
        // crosses tokio's `Coop` to the `Notified` — and the sleep by
        // the registry's wheel entry; the driver has no set at all.
        let WaitAssessment::Set(set) = &analysis.waits[index("selector")].assessment else {
            panic!("{:?}", analysis.waits[index("selector")].assessment);
        };
        assert_eq!(set.members.len(), 4, "{:#?}", set.members);
        assert_eq!(set.armed().count(), 4, "{:#?}", set.members);
        assert_eq!(set.group_label(), "mpsc rx, oneshot rx, timer, watch rx");
        assert!(matches!(
            analysis.waits[index("driver")].assessment,
            WaitAssessment::Unknown(_)
        ));

        over.ctx
            .fold_slots(&mut analysis, &over.e.list, &attributed);

        let selector = &analysis.waits[index("selector")];
        let WaitAssessment::Set(set) = &selector.assessment else {
            panic!("{:?}", selector.assessment);
        };
        assert_eq!(set.armed().count(), 4, "{:#?}", set.members);
        // The wheel entry and the three protocol readings stand as the
        // analysis left them, their swept twins — the watch's waiter
        // node among them — folded into nothing: the sweep found
        // exactly the wakers the protocols read, and arms nothing on
        // its own.
        let armed_by = |pred: &dyn Fn(&SlotRef) -> bool| {
            set.members
                .iter()
                .filter(|m| m.armed.as_ref().is_some_and(pred))
                .count()
        };
        assert_eq!(armed_by(&|s| matches!(s, SlotRef::Wheel { .. })), 1);
        assert_eq!(armed_by(&|s| matches!(s, SlotRef::Protocol)), 3);
        assert_eq!(armed_by(&|s| matches!(s, SlotRef::Swept { .. })), 0);
        // The `select!` rule lists the tuple's four members as the
        // branches, each a `&mut` to the frame's own local, in source
        // order, and every slot arms the branch whose storage — or
        // whose find, reached through the borrow — holds it.
        let routes: Vec<(usize, bool)> = set
            .members
            .iter()
            .map(|m| match m.route {
                MemberRoute::Select {
                    index, borrowed, ..
                } => (index, borrowed),
                ref other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(routes, [(0, true), (1, true), (2, true), (3, true)]);
        assert_eq!(set.cell(), "mpsc rx, oneshot rx, timer, watch rx");
        assert_eq!(set.group_label(), "mpsc rx, oneshot rx, timer, watch rx");
        assert!(selector.held.is_empty());

        let driver = &analysis.waits[index("driver")];
        let WaitAssessment::Set(set) = &driver.assessment else {
            panic!("{:?}", driver.assessment);
        };
        assert_eq!(set.armed().count(), 1);
        assert_eq!(
            set.group_label(),
            "futures_core::task::__internal::atomic_waker::AtomicWaker"
        );

        for name in ["holder", "waiter"] {
            let wait = &analysis.waits[index(name)];
            assert!(wait.verified().is_some(), "{name}: {:?}", wait.assessment);
            assert_eq!(wait.notes, Vec::<String>::new(), "{name}");
        }
    }

    /// Over `sleep-join`: both slots are the registries' — the sleeper's
    /// wheel entry and the joiner's waker in the sleeper's trailer —
    /// and each is accounted for by its task's verified wait, so the
    /// fold adds no note beside either.
    #[test]
    fn test_registry_slots_are_accounted_for_by_the_verified_wait() {
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
        let timer = wait.verified().expect("the verified timer");
        assert!(timer.target().to_string().starts_with("timer (deadline "));
        assert!(verified_accounts(timer, slots[0], &size_of));

        let slots: Vec<&AttributedSlot> = attributed.of_task(joiner.addr.0).collect();
        assert_eq!(slots.len(), 1, "{slots:#?}");
        let Attribution::Registry(RegistrySlot::Join { task }) = &slots[0].attribution else {
            panic!("{:?}", slots[0]);
        };
        assert_eq!(task.addr, sleeper.addr);
        assert_eq!(slots[0].detail(None).as_deref(), Some("its trailer"));
        let wait = &over.analysis.waits[index(joiner)];
        let join = wait.verified().expect("the verified join");
        assert_eq!(
            join.target().to_string(),
            format!("task {}", sleeper.task_id.unwrap())
        );
        assert!(verified_accounts(join, slots[0], &size_of));
        // A slot the wait does not account for is not its.
        let other = attributed.of_task(sleeper.addr.0).next().unwrap();
        assert!(!verified_accounts(join, other, &size_of));

        let mut analysis = analyze(
            &over.ctx,
            &over.e.list,
            &over.e.registries,
            &ReadContext::none(),
        );
        over.ctx
            .fold_slots(&mut analysis, &over.e.list, &attributed);
        for wait in [
            &analysis.waits[index(sleeper)],
            &analysis.waits[index(joiner)],
        ] {
            assert!(wait.verified().is_some(), "{:?}", wait.assessment);
            assert_eq!(wait.notes, Vec::<String>::new());
        }
    }

    /// Over `channels`: the receivers' slots are owner-table slots — the
    /// oneshot's receiver, the channel's receiver, the `Notify` node —
    /// and the blocked sender's is the one typed slot, the waker in the
    /// `Acquire`'s queue node inside its own `send` future.
    #[test]
    fn test_channels_slots_name_their_primitives() {
        let (bundle, snapshot) = load_any("channels");
        let over = Over::new(&bundle, &snapshot);
        let attributed = over.attribute();
        let mut kinds: Vec<OwnerKind> = Vec::new();
        let mut typed: Vec<(String, String)> = Vec::new();
        for slot in &attributed.slots {
            match &slot.attribution {
                Attribution::Owner { kind, .. } => kinds.push(*kind),
                Attribution::Typed { holder, member, .. } => {
                    typed.push((holder.clone(), member.clone()));
                }
                other => panic!("{other:?}"),
            }
        }
        kinds.sort_by_key(|k| k.word());
        assert_eq!(
            kinds,
            [OwnerKind::Mpsc, OwnerKind::Notify, OwnerKind::OneshotRx]
        );
        assert_eq!(
            typed,
            [(
                "tokio::sync::batch_semaphore::Waiter".to_string(),
                "waker".to_string()
            )]
        );
        assert_eq!(attributed.stats.stale, 0);
    }

    /// The caller's slot in the busy connection's response callback:
    /// the requester's own values reach the receiver, but its waker in
    /// the `rx_task` cell is named from the connection's side, as the
    /// response it awaits, while the connection's own sender-cell slot
    /// in the same oneshot stands as it did. The idle connection, with
    /// no callback, joins nothing.
    #[test]
    fn test_the_callers_slot_joins_the_connections_callback() {
        use crate::tokio::bundle::{HttpCaller, HttpPhase};
        let (bundle, snapshot) = load_any("http-conns");
        let over = Over::new(&bundle, &snapshot);
        let attributed = over.attribute();
        let requester = over.task("http_conns::requester");
        let slots: Vec<&AttributedSlot> = attributed.of_task(requester.addr.0).collect();
        assert_eq!(slots.len(), 1, "{slots:?}");
        let Attribution::Response {
            primitive,
            reading,
            connection,
            conn,
            role,
            version,
        } = &slots[0].attribution
        else {
            panic!("{:?}", slots[0].attribution);
        };
        let busy = over
            .analysis
            .waits
            .iter()
            .find(|wait| {
                matches!(
                    wait.verified().map(|v| v.target()),
                    Some(WaitTarget::HttpConn {
                        phase: HttpPhase::AwaitingResponse,
                        ..
                    })
                )
            })
            .expect("a client awaiting its response");
        let WaitTarget::HttpConn {
            addr,
            via: Some(via),
            caller,
            ..
        } = busy.verified().unwrap().target()
        else {
            unreachable!()
        };
        let WaitTarget::Oneshot {
            addr: inner,
            state,
            side: OneshotSide::Tx,
        } = **via
        else {
            panic!("{via}")
        };
        assert_eq!((*primitive, *conn, *connection), (inner, *addr, busy.task));
        assert_eq!(
            (*role, *version),
            (HttpRole::Client, Some(HttpVersion::Http1))
        );
        assert_eq!(*reading, state);
        assert_eq!(
            caller,
            &Some(HttpCaller::Task(TaskRef {
                addr: requester.addr,
                task_id: requester.task_id,
            }))
        );
        assert_eq!(
            slots[0].entry(None),
            format!("oneshot rx {inner:#x} (response for http1 client {addr:#x})")
        );
        // The requester's own chain reaches the receiver, through
        // hyper-util's response future down to the checkout's send, so
        // the slot is located where the requester awaits it.
        assert!(
            matches!(slots[0].reach, Reach::Awaited(_)),
            "{:?}",
            slots[0].reach
        );
        // The connection's own slot in the same oneshot: the sender
        // cell, a different address in the same `Inner`.
        let tx = attributed
            .of_task(busy.task.addr.0)
            .find(|slot| {
                matches!(
                    slot.attribution,
                    Attribution::Owner {
                        kind: OwnerKind::OneshotTx,
                        ..
                    }
                )
            })
            .expect("the sender-cell slot");
        let Attribution::Owner {
            primitive: tx_primitive,
            ..
        } = tx.attribution
        else {
            unreachable!()
        };
        assert_eq!(tx_primitive, inner);
        assert_ne!(tx.slot, slots[0].slot);
        // Two requesters await a response — the hyper-util one and the
        // reqwest one — so two callbacks join.
        assert_eq!(attributed.stats.joined, 2);
    }

    /// A callback joins only when its receiver cell holds a waker by
    /// the state word and belongs to the `Inner` the connection waits
    /// on: either alone leaves the cell a ghost, and nothing joins.
    #[test]
    fn test_a_ghost_callback_joins_nothing() {
        use crate::tokio::observe::OneshotObservation;
        let (bundle, snapshot) = load_any("http-conns");
        let requester = |over: &Over<'_>| over.task("http_conns::requester").addr.0;
        for (what, ghost) in [
            (
                "no receiver waker by the state word",
                (|callback: &mut OneshotObservation| {
                    callback.state.word &= !hansei_bundle::tokio::oneshot::RX_TASK_SET;
                }) as fn(&mut OneshotObservation),
            ),
            ("another Inner", |callback| callback.inner += 8),
        ] {
            let mut over = Over::new(&bundle, &snapshot);
            for wait in &mut over.analysis.waits {
                if let Some(ResourceObservation::HttpConn(http)) = &mut wait.observation
                    && let Some(callback) = http
                        .client
                        .as_mut()
                        .and_then(|client| client.callback.as_mut())
                {
                    ghost(callback);
                }
            }
            let attributed = over.attribute();
            assert_eq!(attributed.stats.joined, 0, "{what}");
            assert!(
                attributed
                    .of_task(requester(&over))
                    .all(|slot| !matches!(slot.attribution, Attribution::Response { .. })),
                "{what}"
            );
        }
    }

    /// The slot no fixture holds, as it prints: an unknown is its
    /// address and nothing more — no detail, and a line that is the
    /// label alone — under the collapse-free bucket word.
    #[test]
    fn test_an_unknown_slot_is_its_address_alone() {
        let owner = Owner::Task {
            header: 0x1000,
            index: 0,
        };
        let slot = |at| AttributedSlot {
            hit: 0,
            slot: at,
            owner,
            attribution: Attribution::Unknown,
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
        };
        let one = slot(0x7000);
        assert_eq!(one.entry(None), "unknown @ 0x7000");
        assert_eq!(one.label(), "unknown @ 0x7000");
        assert_eq!(one.bucket(), "unknown");
        assert_eq!(one.detail(None), None);
        assert_eq!(one.line(None), "unknown @ 0x7000");
        let attributed = Attributed::from_slots(vec![one, slot(0x8000)]);
        assert_eq!(attributed.stats.unknown, 2);
        assert_eq!(attributed.of_task(0x1000).count(), 2);
    }
}

#[cfg(test)]
mod join_tests {
    //! The joins between a slot and what a reader or a wait-set member
    //! says: laid out by hand, at the boundaries no fixture reaches.

    use super::*;
    use crate::tokio::assess::{VerifiedWait, WaitAssessment};
    use crate::tokio::bundle::{
        FutureInfo, HttpPhase, HttpRole, HttpVersion, IoSlot, OwnerResolution, Task, TaskKind,
    };
    use crate::tokio::waitset::{MemberRoute, SlotRef, WaitMember};
    use crate::tokio::{TaskAddr, TaskState};

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
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
        }
    }

    fn registry(slot: u64, attribution: RegistrySlot, within: Option<SlotRoot>) -> AttributedSlot {
        AttributedSlot {
            hit: 0,
            slot,
            owner: owner(),
            attribution: Attribution::Registry(attribution),
            within,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
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
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
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
            entries: None,
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
        let find = |addr| SlotRoot::Find {
            index: 0,
            addr,
            frame: 0,
        };
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

    /// A slot located through one binding of a resource is the
    /// branch's when the branch is another binding of it: a handle
    /// moved out of a struct field leaves its bytes behind, so the
    /// path may head at the copy while the reader asks about the local
    /// that owns it now. Only an address among the aliases claims it —
    /// a frame carries none to compare.
    #[test]
    fn test_a_member_claims_a_slot_reached_through_another_binding_of_it() {
        let m = member(None, None);
        let find = |index, addr| SlotRoot::Find {
            index,
            addr,
            frame: 0,
        };
        // The hop leaves from a root that is not the member's storage.
        let mut slot = typed(0x9000, find(1, 0x7000), Some(hop(0x7000)));
        assert!(!member_accounts(&m, &slot, &size_of));
        slot.aliases = vec![find(0, 0x5000)];
        assert!(member_accounts(&m, &slot, &size_of));
        slot.aliases = vec![find(0, 0x6000)];
        assert!(!member_accounts(&m, &slot, &size_of));
        slot.aliases = vec![frame()];
        assert!(!member_accounts(&m, &slot, &size_of));
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
        // A connection accounts for the slot in the primitive its `via`
        // names — the request channel, the response callback's sender
        // cell — by address and side alike, and for nothing else.
        let conn = |via: WaitTarget| {
            VerifiedWait::testkit(
                WaitTarget::HttpConn {
                    addr: 0xc000,
                    role: HttpRole::Client,
                    version: Some(HttpVersion::Http1),
                    phase: HttpPhase::Idle,
                    method: None,
                    keep_alive: true,
                    header_read_timer: false,
                    via: Some(Box::new(via)),
                    caller: None,
                    tls: None,
                    fd: None,
                },
                None,
            )
        };
        let idle = conn(WaitTarget::Channel {
            addr: 0xb000,
            senders: 1,
            capacity: None,
            unread: 0,
        });
        assert!(verified_accounts(
            &idle,
            &owned(0xb040, OwnerKind::Mpsc, 0xb000),
            &size_of
        ));
        assert!(!verified_accounts(
            &idle,
            &owned(0xb140, OwnerKind::Mpsc, 0xb100),
            &size_of
        ));
        assert!(!verified_accounts(
            &idle,
            &owned(0xb040, OwnerKind::OneshotTx, 0xb000),
            &size_of
        ));
        let in_flight = conn(WaitTarget::Oneshot {
            addr: 0xd000,
            state: OneshotState {
                word: 0b1000,
                value_present: Some(false),
            },
            side: OneshotSide::Tx,
        });
        assert!(verified_accounts(
            &in_flight,
            &owned(0xd020, OwnerKind::OneshotTx, 0xd000),
            &size_of
        ));
        assert!(!verified_accounts(
            &in_flight,
            &owned(0xd120, OwnerKind::OneshotTx, 0xd100),
            &size_of
        ));
        assert!(!verified_accounts(
            &in_flight,
            &owned(0xd020, OwnerKind::OneshotRx, 0xd000),
            &size_of
        ));
        // An io slot is the connection's own exactly where its rule
        // names no primitive: a client parked on its dispatch lists
        // the socket as an item, a server or a body-receiving client
        // is parked on the socket itself.
        assert!(!verified_accounts(
            &idle,
            &registry(0xe000, io(0xe100), None),
            &size_of
        ));
        let on_socket = VerifiedWait::testkit(
            WaitTarget::HttpConn {
                addr: 0xc000,
                role: HttpRole::Server,
                version: Some(HttpVersion::Http1),
                phase: HttpPhase::Idle,
                method: None,
                keep_alive: true,
                header_read_timer: false,
                via: None,
                caller: None,
                tls: None,
                fd: None,
            },
            None,
        );
        assert!(verified_accounts(
            &on_socket,
            &registry(0xe000, io(0xe100), None),
            &size_of
        ));
        assert!(!verified_accounts(
            &on_socket,
            &registry(0xe000, timer(0xe100), None),
            &size_of
        ));
        assert!(!verified_accounts(
            &on_socket,
            &owned(0xb040, OwnerKind::Mpsc, 0xb000),
            &size_of
        ));
        // A oneshot's `Inner` and a watch's `Shared`, by address and
        // by kind alike.
        let oneshot = VerifiedWait::testkit(
            WaitTarget::Oneshot {
                addr: 0x9000,
                state: OneshotState {
                    word: 0b1001,
                    value_present: Some(false),
                },
                side: OneshotSide::Rx,
            },
            None,
        );
        assert!(verified_accounts(
            &oneshot,
            &owned(0x9020, OwnerKind::OneshotRx, 0x9000),
            &size_of
        ));
        assert!(!verified_accounts(
            &oneshot,
            &owned(0x9020, OwnerKind::OneshotTx, 0x9000),
            &size_of
        ));
        assert!(!verified_accounts(
            &oneshot,
            &owned(0x9120, OwnerKind::OneshotRx, 0x9100),
            &size_of
        ));
        let watch = VerifiedWait::testkit(
            WaitTarget::Watch {
                addr: 0xa000,
                version: 3,
                closed: false,
                receivers: 2,
                senders: 1,
            },
            None,
        );
        assert!(verified_accounts(
            &watch,
            &owned(0xa040, OwnerKind::Watch, 0xa000),
            &size_of
        ));
        assert!(!verified_accounts(
            &watch,
            &owned(0xa040, OwnerKind::Notify, 0xa000),
            &size_of
        ));
        assert!(!verified_accounts(
            &watch,
            &owned(0xa140, OwnerKind::Watch, 0xa100),
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
                        frame: 0,
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
                "the hit at 0x5010 names task 7 and sits in frame 1 but is in an inactive variant",
                "the hit at 0x6020 names child 2 of set 0 and sits in future 0x6000 but is \
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
            frame: 0,
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
        order_roots(&mut roots, &HashSet::default());
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
        order_roots(&mut frames, &HashSet::default());
        assert_eq!(frames[0].at, frame(0), "the inner frame first");
    }

    /// A oneshot's reading is worded from the slot's own side: the
    /// receiver's slot says whether the sender is alive, the sender's
    /// whether the receiver is.
    #[test]
    fn test_a_oneshot_reading_is_worded_from_the_slots_side() {
        let parked = Reading::Oneshot(OneshotState {
            word: 0b1001,
            value_present: Some(false),
        });
        let side = |kind| {
            let mut slot = owned(0x5020, kind, 0x5000);
            if let Attribution::Owner { reading, .. } = &mut slot.attribution {
                *reading = Some(parked.clone());
            }
            slot.entry(None)
        };
        assert_eq!(
            side(OwnerKind::OneshotRx),
            "oneshot rx 0x5000 (nothing sent, sender alive)"
        );
        assert_eq!(
            side(OwnerKind::OneshotTx),
            "oneshot tx 0x5000 (nothing sent, receiver alive)"
        );
    }

    /// A step names a variant only when it is bracketed at both ends.
    /// A member whose name merely starts or ends with an angle bracket
    /// is a member, and keeps its name whole — stripping its ends
    /// would hand `print` a path it cannot read.
    #[test]
    fn test_a_variant_step_is_bracketed_at_both_ends() {
        assert!(is_variant("<Some>"));
        assert!(!is_variant("<Some"));
        assert!(!is_variant("Some>"));
        assert!(!is_variant("rx_waker"));
        assert_eq!(step_text("<Some>"), Some("Some"));
        assert_eq!(step_text("<Some"), Some("<Some"));
        assert_eq!(step_text("Some>"), Some("Some>"));
        // A coroutine's state is a frame boundary, not a step.
        assert_eq!(step_text("<#3>"), None);
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
    pub(super) const BASE: u64 = 0x5f20_0000_0000;
    const SIZE: u64 = 0x2000;

    // The synthetic bundle's type ids.
    const U64: u32 = 0;
    const RAW_WAKER: u32 = 1;
    const WAKER: u32 = 2;
    const UNIT: u32 = 3;
    pub(super) const OPT_WAKER: u32 = 4;
    const SLIM: u32 = 5;
    pub(super) const HOLDER: u32 = 6;
    const ARR: u32 = 7;
    const BOXED: u32 = 8;
    const PTR_HOLDER: u32 = 9;
    pub(super) const FRAME: u32 = 10;
    const PADDED: u32 = 11;
    const CHANLIKE: u32 = 12;
    const NOTIFY_ARR: u32 = 13;
    const SHARED: u32 = 14;
    const ARC_SHARED: u32 = 15;
    pub(super) const CORO: u32 = 16;
    const CORO_STATE: u32 = 17;
    const MAYBE: u32 = 18;
    const UNION_HOLDER: u32 = 19;
    const PTR_UNIT: u32 = 20;
    const UNIT_FRAME: u32 = 21;
    const TWO_PTR: u32 = 22;

    pub(super) fn id(i: u32) -> BundleTypeId {
        BundleTypeId(i)
    }

    /// A bundle of the shapes the walk must get right at the edges:
    /// `Holder { a: u64, w: Option<Waker> }` (24 bytes), `Slim { w:
    /// Waker }` (exactly a waker wide), `Boxed { n, ws: [Slim; 3] }`, a
    /// `Frame { p: *const Holder, pad }`, a `Chanlike { x, cp:
    /// CachePadded<Option<Waker>> }` whose wrapper is wider than a
    /// waker, and a watch `Shared` behind an `ArcInner` with the roles
    /// the watch row reads bound.
    pub(super) fn bundle() -> Bundle {
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
        let (mayben, uninitn, union_holdern, mun, ptr_unitn, unit_framen, zn) = (
            n("core::mem::MaybeUninit<core::task::wake::Waker>"),
            n("uninit"),
            n("x::UnionHolder"),
            n("mu"),
            n("*const ()"),
            n("x::UnitFrame"),
            n("z"),
        );
        let (two_ptrn, firstn, secondn) = (n("x::TwoPtr"), n("first"), n("second"));
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
            // The one union the walk enters, by its `value` member —
            // laid past a sized member that is no value, and off the
            // union's start, so the choice and the bounds both show.
            TypeDef::Union {
                name: mayben,
                size: 32,
                members: vec![
                    member(uninitn, id(UNIT), 0),
                    member(padn, id(U64), 0),
                    member(valuen, id(WAKER), 8),
                ],
            },
            strukt(
                union_holdern,
                40,
                vec![member(nn, id(U64), 0), member(mun, id(MAYBE), 8)],
            ),
            // A pointer to nothing sized, beside one worth following.
            TypeDef::Pointer {
                name: Some(ptr_unitn),
                target: id(UNIT),
            },
            strukt(
                unit_framen,
                16,
                vec![member(pn, id(PTR_HOLDER), 0), member(zn, id(PTR_UNIT), 8)],
            ),
            // Two handles on one holder, to tell a copy of one member
            // from a different member reaching the same allocation.
            strukt(
                two_ptrn,
                16,
                vec![
                    member(firstn, id(PTR_HOLDER), 0),
                    member(secondn, id(PTR_HOLDER), 8),
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
                select: None,
                http: None,
                request: None,
                table: None,
                pool: None,
                connected: None,
                io_route: None,
                io: None,
                tls_session: None,
                tls_stream: None,
                stream_peer: None,
                refcount: None,
                lock: None,
                acquires_for: None,
                coroutine_kind: None,
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
        // The waker words, rooted at the `RawWaker` as extraction roots
        // them: what makes it, and the `Waker` around it, a slot.
        b.walks.entries.insert(
            WalkRole::WakerData,
            WalkBinding {
                roots: vec![id(RAW_WAKER)],
                steps: vec![WalkStep::Member(MemberRef::Named(datan))],
                outcome: WalkOutcome::Bound {
                    spelling: 0,
                    spellings: 1,
                    note: None,
                },
            },
        );
        b
    }

    /// A fixture snapshot with one anonymous, writable mapping planted
    /// beside it, holding the bytes a test lays down.
    pub(super) struct Planted<'a> {
        inner: &'a Snapshot,
        base: u64,
        bytes: Vec<u8>,
    }

    impl<'a> Planted<'a> {
        pub(super) fn new(inner: &'a Snapshot) -> Self {
            Self::at(inner, BASE)
        }

        /// The mapping planted at `base` instead: where a test wants
        /// its bytes inside an address range something else fixes.
        fn at(inner: &'a Snapshot, base: u64) -> Self {
            Planted {
                inner,
                base,
                bytes: vec![0; SIZE as usize],
            }
        }

        pub(super) fn word(&mut self, at: u64, value: u64) {
            let off = (at - self.base) as usize;
            self.bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }

        /// A waker pair at `at`: a data word and a nonzero vtable word.
        pub(super) fn pair(&mut self, at: u64) {
            self.word(at, 0x1234);
            self.word(at + 8, 0xf000);
        }

        fn range(&self) -> Range<u64> {
            self.base..self.base + SIZE
        }
    }

    impl proc::Target for Planted<'_> {
        fn read_bytes(&self, addr: u64, len: u64) -> proc::Result<&[u8]> {
            if self.range().contains(&addr) && addr + len <= self.base + SIZE {
                let off = (addr - self.base) as usize;
                return Ok(&self.bytes[off..off + len as usize]);
            }
            self.inner.read_bytes(addr, len)
        }
        fn readable_len(&self, addr: u64, max: u64) -> u64 {
            if self.range().contains(&addr) {
                return (self.base + SIZE - addr).min(max);
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
                vaddr: self.base,
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
        pub(super) fn new(bundle: &Bundle) -> Self {
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

    pub(super) fn hit(slot: u64) -> Hit {
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
                    // The element's own index, so a path can name it.
                    assert_eq!(
                        names(&trail),
                        ["ws".to_string(), format!("[{i}]"), "w".to_string()],
                        "element {i}"
                    );
                    assert_eq!(validity, Validity::Raw);
                    // The element entered is the one at the offset, by
                    // its own address.
                    assert_eq!(trail[2].holder.addr, boxed + 8 + 16 * i, "element {i}");
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
        assert_eq!(member, "[2]");

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

    /// A zero-sized member is no company: a struct whose one sized
    /// member sits at its start beside a zero-sized one is a wrapper,
    /// and one whose sized member is a `RawWaker` a waker. An enum of a
    /// `None` and a `Some` alone is a wrapper, however wide its tag
    /// makes it; one of other variants is not.
    #[test]
    fn test_zero_sized_members_and_options_are_passed_over() {
        let mut b = bundle();
        let mut strings = StringInterner::new();
        for s in b.strings.iter() {
            strings.intern(s);
        }
        let mut n = |s: &str| strings.intern(s);
        let (markern, valuen, wakerm, zeron) = (n("marker"), n("value"), n("waker"), n("__0"));
        let (nonen, somen, leftn, rightn) = (n("None"), n("Some"), n("Left"), n("Right"));
        let (celln, markedn, optn, eithern) = (
            n("x::Cell"),
            n("x::MarkedWaker"),
            n("core::option::Option<x::Slim>"),
            n("x::Either"),
        );
        b.strings = strings.finish();
        let member = |name, ty, offset| MemberDef { name, ty, offset };
        let variant = |name, discr, payload| VariantDef {
            name,
            discr_values: Some(DiscrValues(vec![DiscrValue::Value(discr)])),
            payload: member(zeron, payload, 8),
            decl: None,
            await_site: None,
        };
        let tagged = |name, variants| TypeDef::Enum {
            name,
            size: 24,
            shape: VariantShape {
                discr: Some(DiscrDef {
                    offset: 0,
                    ty: id(U64),
                }),
                variants,
            },
        };
        let first = b.types.types.len() as u32;
        b.types.types.extend([
            TypeDef::Struct {
                name: celln,
                size: 8,
                members: vec![member(markern, id(UNIT), 0), member(valuen, id(U64), 0)],
            },
            TypeDef::Struct {
                name: markedn,
                size: 16,
                members: vec![
                    member(markern, id(UNIT), 0),
                    member(wakerm, id(RAW_WAKER), 0),
                ],
            },
            tagged(
                optn,
                vec![variant(nonen, 0, id(UNIT)), variant(somen, 1, id(SLIM))],
            ),
            tagged(
                eithern,
                vec![variant(leftn, 0, id(SLIM)), variant(rightn, 1, id(SLIM))],
            ),
        ]);
        let view = BundleView::new(&b);
        let ty = |at: u32| view.ty(BundleTypeId(first + at)).unwrap();
        assert!(is_wrapper(ty(0)), "a cell beside a marker");
        assert!(is_wrapper(ty(2)), "a tagged option");
        assert!(!is_wrapper(ty(3)), "an enum of two values");
        let semantics = SemanticIndex::new(b.types.types.len(), &[]).unwrap();
        let types = Types {
            view,
            semantics: &semantics,
            test_bindings: &[],
        };
        assert!(types.is_waker(ty(1)), "a raw waker beside a marker");
        assert!(!types.is_waker(ty(0)), "a word beside a marker");
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
            Some((Attribution::Typed { path, .. }, _)) => {
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
                frame: 0,
            },
            value: value(&at, HOLDER, holder),
        }];
        assert!(matches!(
            at.by_containment(&hit(holder + 8), &contained),
            Ok(Some((Attribution::Typed { .. }, _)))
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
                frame: 0,
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
        // another type that carries no layout: a binding is found by
        // its own type, not taken as the first one there.
        let bindings = [
            TypeSemantics {
                ty: id(U64),
                coroutine: None,
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
                assert_eq!(names(&trail), ["<#3>", "live"]);
                assert_eq!(validity, Validity::Raw);
            }
            Located::Stale(reason) => panic!("{reason:?}"),
        }
        match at.locate_member(v, 8 + 24) {
            Located::Slot { trail, validity } => {
                assert_eq!(names(&trail), ["<#3>", "unsure"]);
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

    /// The walk enters a union through its `value` member alone, and
    /// only where the offset falls inside that member: below it, or at
    /// its end, is no slot. What it finds through a union is unchecked.
    #[test]
    fn test_the_walk_enters_a_union_through_its_value_and_within_it() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let holder = BASE;
        planted.word(holder, 7);
        planted.pair(holder + 8 + 8);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let v = value(&at, UNION_HOLDER, holder);
        match at.locate_member(v, 8 + 8) {
            Located::Slot { trail, validity } => {
                assert_eq!(names(&trail), ["mu", "value"]);
                assert_eq!(validity, Validity::Unchecked);
            }
            Located::Stale(reason) => panic!("{reason:?}"),
        }
        for offset in [8, 8 + 4, 8 + 8 + 16, 8 + 8 + 20] {
            assert!(
                matches!(
                    at.locate_member(v, offset),
                    Located::Stale(StaleReason::NotAWaker)
                ),
                "offset {offset}"
            );
        }
    }

    /// The pointer members a hop may follow are the non-null pointers
    /// to something sized: a `*const ()` is left out even when set.
    #[test]
    fn test_pointer_members_leave_out_pointers_to_nothing() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (frame, holder) = (BASE, BASE + 0x100);
        planted.word(frame, holder);
        planted.word(frame + 8, holder + 0x40);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let roots = vec![Root {
            at: SlotRoot::Frame { task: 0, frame: 1 },
            value: value(&at, UNIT_FRAME, frame),
        }];
        let pointers = at.pointer_members(&roots);
        assert_eq!(pointers.len(), 1, "{pointers:?}");
        assert_eq!((pointers[0].target, pointers[0].at), (holder, frame));
    }

    /// An `Option`'s presence is read from its active variant: a set
    /// waker is `Some`, a null one `None`, and a value that is no enum
    /// answers nothing.
    #[test]
    fn test_option_presence_reads_the_active_variant() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (some, none) = (BASE, BASE + 0x20);
        planted.pair(some);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let present = |ty, addr| super::super::bundle::option_present(value(&at, ty, addr));
        assert_eq!(present(OPT_WAKER, some), Some(true));
        assert_eq!(present(OPT_WAKER, none), Some(false));
        assert_eq!(present(U64, some), None);
    }

    /// The other roots holding the very pointer a hop left from are
    /// the resource's other bindings — the copy a move out of a struct
    /// field leaves in the frame. Same member of the same type only: a
    /// root of another type reaching the same allocation is a
    /// different handle on it, and so is another member of the same
    /// type.
    #[test]
    fn test_a_hops_aliases_are_the_same_member_of_the_same_type() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let holder = BASE + 0x100;
        let (frame_a, frame_b, unit) = (BASE, BASE + 0x20, BASE + 0x40);
        // `two_a` holds the resource in `first`, `two_b` in `second`,
        // `two_c` in both.
        let (two_a, two_b, two_c) = (BASE + 0x60, BASE + 0x80, BASE + 0xa0);
        planted.word(holder, 7);
        planted.pair(holder + 8);
        for at in [frame_a, frame_b, unit, two_a, two_c] {
            planted.word(at, holder);
        }
        planted.word(two_b + 8, holder);
        planted.word(two_c + 8, holder);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let root = |index, ty, addr| Root {
            at: SlotRoot::Find {
                index,
                addr,
                frame: 0,
            },
            value: value(&at, ty, addr),
        };
        let find = |index, addr| SlotRoot::Find {
            index,
            addr,
            frame: 0,
        };
        // The pointers are sorted by root, so the hop is taken from
        // the first root and the aliases are found among the rest.
        let aliases = |roots: &[Root<'_>]| -> Vec<SlotRoot> {
            let pointers = at.pointer_members(roots);
            let path = match at.by_hop(&hit(holder + 8), roots, &pointers) {
                Some((Attribution::Typed { path, .. }, _)) => path,
                other => panic!("{other:?}"),
            };
            assert_eq!(path.root, roots[0].at, "the hop is the first root's");
            at.aliases_of(roots, &pointers, &path)
        };
        assert_eq!(
            aliases(&[
                root(0, FRAME, frame_a),
                root(1, FRAME, frame_b),
                root(2, UNIT_FRAME, unit),
                root(3, TWO_PTR, two_a),
            ]),
            [find(1, frame_b)],
            "the other Frame, not the other types reaching the same holder"
        );
        assert_eq!(
            aliases(&[
                root(0, TWO_PTR, two_a),
                root(1, TWO_PTR, two_b),
                root(2, FRAME, frame_a),
            ]),
            [],
            "`second` is a different handle from `first`"
        );
        assert_eq!(
            aliases(&[root(0, TWO_PTR, two_a), root(1, TWO_PTR, two_c)]),
            [find(1, two_c)],
            "`first` to `first`, though `second` reaches it too"
        );
        // A path with no hop has nothing to alias.
        let roots = [root(0, TWO_PTR, two_a), root(1, TWO_PTR, two_c)];
        let bare = SlotPath {
            root: roots[0].at,
            steps: Vec::new(),
            hop: None,
        };
        assert_eq!(
            at.aliases_of(&roots, &at.pointer_members(&roots), &bare),
            []
        );
    }

    /// Two roots the size and kind rules leave tied are ordered by
    /// which of them the analysis already made a branch of the stop,
    /// so a slot behind the resource they share is located from the
    /// branch a reader asks about rather than from a copy of it.
    #[test]
    fn test_a_branch_outranks_a_root_tied_with_it() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
        let mut planted = Planted::new(&snapshot);
        let (ghost, live) = (BASE, BASE + 0x20);
        planted.word(ghost, BASE + 0x100);
        planted.word(live, BASE + 0x100);
        let empty = Empty::new(&bundle);
        let sources = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &sources);
        let roots = || {
            vec![
                Root {
                    at: SlotRoot::Find {
                        index: 0,
                        addr: ghost,
                        frame: 0,
                    },
                    value: value(&at, FRAME, ghost),
                },
                Root {
                    at: SlotRoot::Find {
                        index: 1,
                        addr: live,
                        frame: 0,
                    },
                    value: value(&at, FRAME, live),
                },
            ]
        };
        let ordered = |branches: &HashSet<u64>| {
            let mut roots = roots();
            order_roots(&mut roots, branches);
            roots.iter().map(|r| r.value.addr).collect::<Vec<_>>()
        };
        assert_eq!(ordered(&HashSet::default()), [ghost, live], "input order");
        assert_eq!(
            ordered(&HashSet::from_iter([live])),
            [live, ghost],
            "the branch first"
        );
        // A branch that is no root of this owner changes nothing.
        assert_eq!(ordered(&HashSet::from_iter([BASE + 0x400])), [ghost, live]);
    }

    /// A hop's candidates are the pointers into the buffer the
    /// allocator index bounds around the hit — one into a buffer below
    /// is not, though its pointee would reach the slot — and, without
    /// an index, the pointers at or below the slot. A pointee starting
    /// exactly at the slot corroborates it; a pointer above the slot
    /// in the same buffer does not.
    #[test]
    fn test_a_hop_reaches_only_from_the_slots_own_buffer() {
        let (_, snapshot) = load_any("sleep-join");
        let bundle = bundle();
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
                free: Vec::new(),
            }],
        );
        let heap = UmemHeap::build(&f).expect("the walk built an index");
        // The slot is the first word of the second buffer; the frame
        // holding the pointers sits past the slabs.
        let (slot, frame) = (BUFFERS + 64, BUFFERS + 0x1000);
        let mut planted = Planted::at(&snapshot, BUFFERS);
        planted.word(frame, slot);
        planted.pair(slot);
        let empty = Empty::new(&bundle);
        let indexed = Sources {
            heap: Some(&heap),
            ..empty.sources()
        };
        let at = attributor(&planted, &bundle, &empty, &indexed);
        let roots = vec![Root {
            at: SlotRoot::Frame { task: 0, frame: 1 },
            value: value(&at, FRAME, frame),
        }];
        // Every candidate is typed as the coroutine state: a waker at
        // its start, another 24 bytes in.
        let ptr = |target| PointerMember {
            target,
            pointee: id(CORO_STATE),
            root: 0,
            at: frame,
        };
        let hop_of = |at: &Attributor<'_, '_, Planted<'_>>, pointers: &[PointerMember]| match at
            .by_hop(&hit(slot), &roots, pointers)
        {
            Some((Attribution::Typed { path, .. }, _)) => {
                let hop = path.hop.expect("a hop");
                Some((hop.addr, hop.steps))
            }
            None => None,
            other => panic!("{other:?}"),
        };
        // The pointer into the buffer below would reach the slot as
        // its `unsure` waker; the index rules it out, and the pointer
        // at the slot itself is the hop.
        assert_eq!(
            hop_of(&at, &[ptr(BUFFERS + 40), ptr(slot)]),
            Some((slot, vec!["live".to_string()]))
        );
        // A pointer past the slot in its own buffer, or into the
        // buffer above, reaches nothing.
        assert_eq!(hop_of(&at, &[ptr(slot + 16)]), None);
        assert_eq!(hop_of(&at, &[ptr(BUFFERS + 128)]), None);
        // Without an index the pointer at the slot still corroborates.
        let bare = empty.sources();
        let at = attributor(&planted, &bundle, &empty, &bare);
        assert_eq!(
            hop_of(&at, &[ptr(slot)]),
            Some((slot, vec!["live".to_string()]))
        );
    }
}

#[cfg(test)]
mod reach_tests {
    //! Whether the current await reaches a slot, over the synthetic
    //! bundle's shapes planted beside a fixture pair: a `Holder`
    //! holding the waker in one frame, a `Frame` whose pointer may or
    //! may not borrow it in the frame inside, and the same holder as
    //! a find of the frame's.

    use super::synthetic_tests::{BASE, CORO, FRAME, HOLDER, OPT_WAKER, Planted, bundle, hit, id};
    use super::*;
    use crate::tokio::assess::{ContinuationStatus, IncompleteReason, WaitAssessment};
    use crate::tokio::bundle::{FutureInfo, OwnerResolution, Registries, Task, TaskKind, TaskList};
    use crate::tokio::census::{FutureCensus, HeldFuture, Via};
    use crate::tokio::graph::{Analysis, TaskRef, TaskWait};
    use crate::tokio::semantics::SemanticIndex;
    use crate::tokio::{TaskAddr, TaskState};

    use hansei_bundle::{Bundle, BundleView};

    /// The owner every planted hit names, as [`hit`] fills it in.
    const OWNER: Owner = Owner::Task {
        header: 0x1000,
        index: 0,
    };

    /// Everything an attributor reads besides the target and the
    /// bundle: one task whose chain is `frames`, root first, and the
    /// finds the census lists under it.
    struct Owned {
        list: TaskList,
        census: FutureCensus,
        registries: Registries,
        analysis: Analysis,
        impls: ImplFold,
        semantics: SemanticIndex,
    }

    impl Owned {
        fn new(bundle: &Bundle, frames: Vec<ValueKey>, held: Vec<HeldFuture>) -> Self {
            let task = Task {
                addr: TaskAddr(0x1000),
                state: TaskState(1 << 6),
                owner_id: Some(1),
                task_id: Some(1),
                spawn_location: None,
                future: FutureInfo::Unknown { poll_symbol: None },
                kind: TaskKind::Async,
                owner: OwnerResolution::Unknown,
            };
            let wait = TaskWait {
                task: TaskRef {
                    addr: TaskAddr(0x1000),
                    task_id: Some(1),
                },
                assessment: WaitAssessment::Unknown(
                    crate::tokio::assess::WaitUnknownReason::Continuation,
                ),
                continuation: ContinuationStatus::Incomplete {
                    reason: IncompleteReason::NoRoot,
                    detail: None,
                },
                depth: frames.len(),
                site: None,
                observation: None,
                notes: Vec::new(),
                held: Vec::new(),
                held_capped: 0,
                frame_sites: vec![None; frames.len()],
                frames,
            };
            Owned {
                list: TaskList::new(vec![task]),
                census: FutureCensus::from_finds(held, Vec::new(), Vec::new()),
                registries: Registries::default(),
                analysis: Analysis {
                    waits: vec![wait],
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

    /// A find of the task's at `addr`, a `Holder` in `frame`'s local
    /// `local`, nested under `via`.
    fn find(addr: u64, frame: usize, local: &str, via: Option<Via>) -> HeldFuture {
        HeldFuture {
            owner: 0,
            frame,
            local: local.to_string(),
            via,
            slot: addr,
            addr,
            ty: id(HOLDER),
            depth: 1,
            frames: Vec::new(),
            future: id(HOLDER),
            state: None,
            waiting_on: None,
            wait: None,
            observation: None,
            request: None,
            continuation: ContinuationStatus::Primitive,
        }
    }

    fn key(ty: u32, addr: u64) -> ValueKey {
        ValueKey { addr, ty: id(ty) }
    }

    /// The verdict on the one hit at `slot`, attributed through the
    /// owner walk over `owned`.
    fn reach_of(planted: &Planted<'_>, bundle: &Bundle, owned: &Owned, slot: u64) -> Reach {
        let sources = owned.sources();
        let at = Attributor {
            proc: planted,
            types: Types {
                view: BundleView::new(bundle),
                semantics: &owned.semantics,
                test_bindings: &[],
            },
            sources: &sources,
            registry: HashMap::default(),
            finds: finds_by_owner(&owned.census),
        };
        let (mut slots, mut stale) = (Vec::new(), Vec::new());
        at.owner(OWNER, &[0], &[hit(slot)], &mut slots, &mut stale);
        assert!(stale.is_empty(), "{stale:?}");
        let [slot] = slots.as_slice() else {
            panic!("{slots:?}");
        };
        slot.reach.clone()
    }

    fn holding(container: ValueKey, frame: usize, local: Option<&str>) -> Holding {
        Holding {
            container,
            frame,
            local: local.map(str::to_string),
        }
    }

    /// A slot in an outer frame's local is awaited where a frame
    /// strictly inside borrows that local — the pointer's target and
    /// pointee type are the local's — and parked where the inner
    /// frame's pointer goes elsewhere, or is the outer frame's own,
    /// or its pointee is another type at the same address. A slot in
    /// frame #0 is awaited whatever points where: the stop is the
    /// container.
    #[test]
    fn test_a_borrow_from_an_inner_frame_makes_a_slot_awaited() {
        let (_, snapshot) = crate::testkit::load_any("sleep-join");
        let bundle = bundle();
        let (frame0, holder, other, coro) = (BASE, BASE + 0x100, BASE + 0x200, BASE + 0x300);
        let mut planted = Planted::new(&snapshot);
        planted.word(holder, 7);
        planted.pair(holder + 8);
        planted.word(other, 7);
        planted.pair(other + 8);
        // A coroutine in state 3 with a live waker as its first local
        // and a null in its live pointer.
        planted.word(coro, 3);
        planted.pair(coro + 8);

        // Root first: the holder is frame #1, the frame with the
        // pointer is #0.
        let chain = |inner| vec![key(HOLDER, holder), key(FRAME, inner)];
        let owned = Owned::new(&bundle, chain(frame0), Vec::new());
        planted.word(frame0, holder);
        assert_eq!(
            reach_of(&planted, &bundle, &owned, holder + 8),
            Reach::Awaited(holding(key(HOLDER, holder), 1, Some("w")))
        );
        // The pointer goes elsewhere: nothing inside borrows the local,
        // and the container is the local the path enters.
        planted.word(frame0, other);
        assert_eq!(
            reach_of(&planted, &bundle, &owned, holder + 8),
            Reach::Parked(holding(key(OPT_WAKER, holder + 8), 1, Some("w")))
        );
        // The borrow comes from an outer frame, not an inner one: the
        // holder is #0 of a chain whose root points at it, and awaited
        // as the stop itself; the frame's own slot, with the holder
        // outside it, is parked.
        planted.word(frame0, holder);
        let reversed = Owned::new(
            &bundle,
            vec![key(FRAME, frame0), key(HOLDER, holder)],
            Vec::new(),
        );
        assert_eq!(
            reach_of(&planted, &bundle, &reversed, holder + 8),
            Reach::Awaited(holding(key(HOLDER, holder), 0, None))
        );
        // The pointee type is not the borrowed value's: a `*const
        // Holder` at a coroutine's address borrows no coroutine.
        planted.word(frame0, coro);
        let typed = Owned::new(
            &bundle,
            vec![key(CORO, coro), key(FRAME, frame0)],
            Vec::new(),
        );
        assert_eq!(
            reach_of(&planted, &bundle, &typed, coro + 8),
            Reach::Parked(holding(key(CORO, coro), 1, Some("live")))
        );
    }

    /// A slot in a find is held in the find's frame and local — the
    /// outermost find's, where finds nest — and is awaited where a
    /// frame inside that one borrows the find.
    #[test]
    fn test_a_slot_in_a_find_is_held_where_the_census_found_it() {
        let (_, snapshot) = crate::testkit::load_any("sleep-join");
        let bundle = bundle();
        let (frame0, coro, holder, nested) = (BASE, BASE + 0x100, BASE + 0x200, BASE + 0x300);
        let mut planted = Planted::new(&snapshot);
        planted.word(coro, 3);
        planted.word(holder, 7);
        planted.pair(holder + 8);
        planted.word(nested, 7);
        planted.pair(nested + 8);
        let held = vec![
            find(holder, 1, "h", None),
            find(nested, 0, "inner", Some(Via::Held(0))),
        ];
        let chain = vec![key(CORO, coro), key(FRAME, frame0)];
        let owned = Owned::new(&bundle, chain, held);
        planted.word(frame0, holder);
        assert_eq!(
            reach_of(&planted, &bundle, &owned, holder + 8),
            Reach::Awaited(holding(key(HOLDER, holder), 1, Some("h")))
        );
        planted.word(frame0, 0);
        assert_eq!(
            reach_of(&planted, &bundle, &owned, holder + 8),
            Reach::Parked(holding(key(HOLDER, holder), 1, Some("h")))
        );
        // The nested find is held where the find it nests under is.
        assert_eq!(
            reach_of(&planted, &bundle, &owned, nested + 8),
            Reach::Parked(holding(key(HOLDER, nested), 1, Some("h")))
        );
        planted.word(frame0, nested);
        assert_eq!(
            reach_of(&planted, &bundle, &owned, nested + 8),
            Reach::Awaited(holding(key(HOLDER, nested), 1, Some("h")))
        );
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use crate::tokio::TaskAddr;

    /// A slot placed from the connection's side prints as the response
    /// it awaits: the oneshot's receiver cell, the connection named by
    /// its verdict's kind words and address; the cell and the bucket
    /// are the receiver's kind; the waker line names the task holding
    /// the cell; and no path of the owner's is claimed for it.
    #[test]
    fn test_a_response_slot_is_named_from_the_connections_side() {
        let slot = AttributedSlot {
            hit: 0,
            slot: 0xc72d9f0,
            owner: Owner::Task {
                header: 0x7ae9380,
                index: 3,
            },
            attribution: Attribution::Response {
                primitive: 0xc72d9e0,
                reading: OneshotState {
                    word: 0b1001,
                    value_present: Some(false),
                },
                connection: TaskRef {
                    addr: TaskAddr(0x804ee80),
                    task_id: Some(4307673),
                },
                conn: 0x124bb090,
                role: HttpRole::Client,
                version: Some(HttpVersion::Http1),
            },
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
        };
        let entry = "oneshot rx 0xc72d9e0 (response for http1 client 0x124bb090)";
        let detail = "the response callback's receiver cell, held by task 4307673";
        assert_eq!(slot.entry(None), entry);
        assert_eq!(slot.label(), "oneshot rx 0xc72d9e0");
        assert_eq!(slot.cell(), "oneshot rx");
        assert_eq!(slot.bucket(), "oneshot rx");
        assert_eq!(slot.place(), entry);
        assert_eq!(slot.detail(None).as_deref(), Some(detail));
        assert_eq!(slot.words(), None);
        assert_eq!(slot.waits_on(None).as_deref(), Some(entry));
        assert_eq!(slot.line(None), format!("oneshot rx 0xc72d9e0: {detail}"));
        assert_eq!(slot.entry_line(None), slot.line(None));
        assert_eq!(slot.location(), None);
        assert!(slot.path().is_none());
        let attributed = Attributed::from_slots(vec![slot]);
        assert_eq!((attributed.stats.joined, attributed.stats.unknown), (1, 0));
        assert_eq!(attributed.of_task(0x7ae9380).count(), 1);
    }
}

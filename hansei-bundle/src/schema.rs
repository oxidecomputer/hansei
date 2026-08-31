//! The bundle's serialized data model.
//!
//! Design rules:
//!
//! - Symbol join tables are keyed by **mangled v0 names**, never demangled
//!   text; demangling is display-only. Lookups strip any `.llvm.<hash>`
//!   suffix before matching (the suffix is a path-sensitive artifact of
//!   LLVM symbol internalization, not part of the name).
//! - Maps are `BTreeMap` rather than `HashMap` so that encoding a bundle is
//!   deterministic: same input, same bytes.
//! - All cross-references are dense indices ([`BundleTypeId`],
//!   [`TaskEntryId`], [`StrRef`]) validated up front by
//!   [`Bundle::validate`](super::Bundle::validate), so readers may index
//!   without per-access checks.

use crate::Encoding;
use crate::strings::{StrRef, StringTable};
use crate::symbols::normalized_v0_key;

use serde::{Deserialize, Serialize};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::num::NonZeroU8;

/// Index into [`TypeTable::types`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct BundleTypeId(pub u32);

/// Index into [`TaskTable::entries`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TaskEntryId(pub u32);

/// A complete bundle: everything `hansei` needs from the debug binary.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub meta: Meta,
    pub strings: StringTable,
    pub types: TypeTable,
    pub tasks: TaskTable,
    pub dyn_futures: DynFutureTable,
    pub statics: StaticsTable,
    pub walks: WalksTable,
    pub infra: InfraTypes,
    pub provenance: ProvenanceTable,
    pub impls: ImplTable,
    pub vtables: VtableTable,
}

// Parallel rendering shares one loaded bundle across worker threads:
// everything here is immutable after load, and the lazy normalized-name
// index is a OnceLock — which must stay true.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Bundle>();
};

/// Identity and validation data for the producing binary.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Copy of the header's format version, for tools that inspect a decoded
    /// bundle without the framing.
    pub format_version: u32,
    /// From the producer's `DW_AT_producer`.
    pub rustc_version: String,
    /// Tokio version, when recoverable from DWARF.
    pub tokio_version: Option<semver::Version>,
    /// Whether the target was built with `--cfg tokio_unstable`, when
    /// decidable from DWARF: the task `Vtable`'s `spawn_location_offset`
    /// member exists only under that cfg. `None` when the vtable type
    /// itself was not found (a non-tokio binary under
    /// `--allow-missing-infra`). Downstream capability logic reads this
    /// to tell "instrumentation absent because the target has none"
    /// from "instrumentation path broken".
    pub tokio_unstable: Option<bool>,
    /// Identity of the binary the bundle describes — the deployed
    /// binary beside split debug info, the one input otherwise.
    pub binary: BinaryIdent,
    /// Identity of the separate debug-info file the DWARF was read
    /// from, when extraction was given one. `None` when one file
    /// played every role.
    pub debug_info: Option<DebugSourceIdent>,
    /// Where the vtable scan read data-section bytes from. [`None`]
    /// means the pass ran with nothing to scan — a companion alone,
    /// which the library entry point permits for tests — so the
    /// bundle's dyn trait-object coverage is incomplete and the read
    /// side should say so.
    ///
    /// [`None`]: VtableDataSource::None
    pub vtable_data: VtableDataSource,
    /// Command line of the extraction, for provenance.
    pub extract_args: String,
    /// Mangled task poll symbols sampled (or all) for target match-rate
    /// validation at attach time.
    pub symbol_fingerprint: Vec<String>,
    /// The newest tokio family the extracting exegesis carried detectors
    /// for. A recovered `tokio_version` above this family's floor took
    /// its layouts as a guess — the newest supported, not ones written
    /// for that release — so the read side surfaces the drift at the
    /// point of use instead of only in `--explain-format`. `None` only
    /// in hand-built bundles.
    pub newest_family: Option<FamilyCeiling>,
}

/// The extractor's newest known tokio family: the tag `--explain-format`
/// names it by and the `(major, minor)` floor of its version range.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct FamilyCeiling {
    pub name: String,
    pub major: u64,
    pub minor: u64,
}

/// Identity of the binary the bundle describes.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct BinaryIdent {
    /// Path basename of the binary.
    pub basename: String,
    /// GNU build-id note (or Mach-O UUID) contents, if present. An
    /// illumos binary carries neither, which is why the hash below is
    /// recorded even though a core offers nothing to check it against.
    pub build_id: Option<Vec<u8>>,
    /// BLAKE3 hash of the whole file.
    pub blake3: [u8; 32],
}

/// Identity of a separate debug-info file — a companion, a dSYM, a
/// dwp, or a full debug binary handed in beside the one that ran. Its
/// pairing with the binary was verified at extraction; the hash is the
/// record of *which* file passed that check.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct DebugSourceIdent {
    /// Path basename of the debug-info file.
    pub basename: String,
    /// BLAKE3 hash of the whole file.
    pub blake3: [u8; 32],
}

/// Where the vtable scan read data-section bytes from.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub enum VtableDataSource {
    /// No input carried data-section contents, so realized trait
    /// objects were not discovered.
    #[default]
    None,
    /// Path basename of the file whose data sections were scanned.
    File(String),
}

/// The layout graph: an index-based arena of type definitions.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct TypeTable {
    pub types: Vec<TypeDef>,
    /// Optional display instructions attached to concrete type layouts.
    /// Types absent from this map use reify's ordinary structural display.
    pub debug_formats: BTreeMap<BundleTypeId, DisplayNode>,
    /// By-name index for the (rarer) name-based lookups: pairs of
    /// (fully-qualified name, type id), sorted by the *resolved string*
    /// so lookups can binary-search without materializing owned keys.
    /// Multiple ids may share one name (e.g. identical instantiations from
    /// different CUs).
    pub name_index: Vec<(StrRef, BundleTypeId)>,
    /// `name_index` positions sorted by
    /// [`rust_type_name_hash`](crate::symbols::rust_type_name_hash) of the
    /// name — `(hash, position)` pairs, one per `name_index` entry, built by
    /// [`TypeTable::build_normalized_index`] when a bundle is assembled.
    ///
    /// A lookup that compares normalized names cannot binary-search
    /// `name_index`, which is sorted by the raw spelling, and a bundle of a
    /// real program holds enough types (nexus: 166,564) that scanning all of
    /// them per lookup was once the dominant cost of rendering a trait
    /// object. Hashing every name to group them costs a third of a second at
    /// that size, which is why the index ships in the bundle rather than
    /// being rebuilt at every load. Like the other derived tables
    /// (`by_normalized_symbol`), its contents ride on the format version:
    /// the hash function changing is a format change.
    pub by_normalized_name: Vec<(u64, u32)>,
    /// O(1) view of `debug_formats`, built on first use: a position per
    /// type id (`u32::MAX` for types without a format) into a flat list
    /// of the display nodes. A census-style walk asks for a type's
    /// format millions of times, which the `BTreeMap` made the single
    /// hottest leaf of the whole command.
    #[serde(skip)]
    pub format_index: SideTable<(Vec<u32>, Vec<DisplayNode>)>,
}

/// A lazily-built in-memory side table riding on serialized data: skipped
/// by serde, empty in clones (a clone rebuilds on first use), and ignored
/// by comparisons.
#[derive(Debug, Default)]
pub struct SideTable<T>(pub std::sync::OnceLock<T>);

impl<T> Clone for SideTable<T> {
    fn clone(&self) -> Self {
        Self(std::sync::OnceLock::new())
    }
}

impl<T> PartialEq for SideTable<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// Which member of an aggregate a [`Step`] or a [`Field`] addresses.
///
/// A name is the better address wherever one selects the member: a member list
/// can be rewritten between a display program being attached and the bundle
/// being finished (extraction drops the members belonging to a coroutine's
/// other states), which shifts every index after the one removed but leaves
/// names alone. Resolution by name also fails closed, so a renamed field
/// declines instead of silently landing on its neighbour.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MemberRef {
    /// Position in the aggregate's member list. Addresses a member no name can
    /// select: an unnamed one (they all intern as `<anon>`), or one of several
    /// sharing a name.
    Index(u32),
    /// The uniquely-named member. A name that is absent, or borne by more than
    /// one member, resolves to nothing.
    Named(StrRef),
}

/// One step in a [`Selector`]: descend into an aggregate member, follow a
/// pointer to the value it points at, or enter a Rust enum's named variant.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Step {
    /// Descend into a struct/union member; adds that member's byte offset and
    /// continues in its type.
    Member(MemberRef),
    /// Follow the current pointer to its pointee, restarting the byte offset
    /// within the target type.
    Deref,
    /// Descend into the named variant's payload of a Rust enum; adds the
    /// payload's byte offset and continues in its type (the per-variant
    /// struct rustc emits, whose members then address the variant's fields).
    ///
    /// The payload's offset is fixed whether or not the variant is active, so
    /// the step *resolves* statically — but its bytes only mean anything when
    /// the variant is the live one, so reify guards every read crossing this
    /// step with the enum's discriminant and degrades to `<inactive variant>`
    /// when another variant holds the storage. That check needs the read to
    /// travel as a guarded place — a [`ValueExpr::Read`] or an
    /// [`DisplayNode::Alias`] — so validation rejects this step in any
    /// selector whose node resolves to a bare offset. Like a named member, a
    /// name that no variant (or more than one) answers to resolves to
    /// nothing.
    Variant(StrRef),
    /// Descend into whichever variant of a Rust enum is live at read time.
    ///
    /// Which variant holds the storage is a property of the running process,
    /// not of the layout, so this step cannot lower to a fixed payload offset
    /// the way [`Step::Variant`] does. It is legal in two positions, and
    /// validation of both fans out over every variant, since any of them may
    /// be the one found: a [`WalkBinding`]'s steps, where the runtime walker
    /// decodes the discriminant and continues in the live variant's payload;
    /// and a [`ValueExpr::Read`]'s selector, which reify resolves to one
    /// guarded place per variant and reads through whichever candidate's
    /// guard selects. Every other display selector rejects it — their reads
    /// resolve to a bare offset, which can carry neither the fan-out nor the
    /// guard — and reify's resolution declines such a program (falling back
    /// to structural display) rather than guessing a variant.
    ActiveVariant,
}

impl MemberRef {
    /// The position of the member this addresses in `members`, or `None` when
    /// nothing there answers to it.
    ///
    /// This is the one place a member address is turned into a position, so
    /// every consumer — validation, reify's resolution, the golden summary —
    /// agrees on what "the member named `x`" means, including that two of them
    /// mean no member at all. `count` is how many members the aggregate has and
    /// `is_named` reports whether member `i` bears a given name; each consumer
    /// supplies the latter for its own representation of a name.
    pub fn resolve(&self, count: usize, is_named: impl Fn(usize, StrRef) -> bool) -> Option<usize> {
        match *self {
            MemberRef::Index(index) => ((index as usize) < count).then_some(index as usize),
            MemberRef::Named(name) => {
                let mut found = (0..count).filter(|&index| is_named(index, name));
                let index = found.next()?;
                found.next().is_none().then_some(index)
            }
        }
    }
}

/// A path from a root type to a nested datum.
///
/// [`Step::Member`] steps descend through struct/union members (by name or by
/// position — see [`MemberRef`]), accumulating byte offsets; a [`Step::Deref`]
/// step crosses a pointer, restarting the offset inside the pointee; a
/// [`Step::Variant`] step enters a Rust enum's named variant payload. A
/// `Selector` unifies what used to be recorded inconsistently as either a bare
/// `u32` member index or a `Vec<u32>` member path, and subsumes the
/// per-formatter "resolve a pointer, then continue against its target" special
/// cases: a cross-pointer reach is just a selector containing a `Deref`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Selector(pub Vec<Step>);

impl Selector {
    /// A selector that descends a single member of the root aggregate, by
    /// position.
    pub fn member(index: u32) -> Self {
        Selector(vec![Step::Member(MemberRef::Index(index))])
    }

    /// A selector that descends a run of members by position, outermost first.
    pub fn members(indices: &[u32]) -> Self {
        Selector(
            indices
                .iter()
                .map(|&index| Step::Member(MemberRef::Index(index)))
                .collect(),
        )
    }

    /// A selector that descends a single member of the root aggregate, by name.
    pub fn named(name: StrRef) -> Self {
        Selector(vec![Step::Member(MemberRef::Named(name))])
    }

    /// A selector that descends a run of members by name, outermost first.
    pub fn named_path(names: &[StrRef]) -> Self {
        Selector(
            names
                .iter()
                .map(|&name| Step::Member(MemberRef::Named(name)))
                .collect(),
        )
    }

    /// Continue this selector with `rest`'s steps, so a detector can compose a
    /// reach out of parts: the path to a field, then the path from that field
    /// to the datum inside it. `rest` is resolved against whatever this
    /// selector lands on, which is why the two compose at all.
    pub fn then(mut self, rest: Selector) -> Self {
        self.0.extend(rest.0);
        self
    }

    /// Continue this selector by following the pointer it lands on. The steps
    /// after this one are resolved against the pointee, from a fresh offset.
    pub fn deref(mut self) -> Self {
        self.0.push(Step::Deref);
        self
    }

    /// Whether this selector has no steps (addresses the root itself).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The selector's steps.
    pub fn steps(&self) -> &[Step] {
        &self.0
    }
}

/// How a single machine word decomposes into human-readable state.
///
/// A word rarely means one thing: it is a small bitfield of an enumerated
/// state, a counter or two, and often reserved bits. Rather than baking each
/// type's bit layout into reify, the layout travels in the bundle as data, so
/// an older reify still renders a newer bundle's semantics correctly.
///
/// reify's one `apply` walks the fields and enforces two "no silent state"
/// rules, so every bit of the word is accountable — a named value, a number,
/// or an explicit unknown:
///
/// 1. An [`FieldRender::Enum`] value absent from its table renders
///    `<unknown: N>`. Enum tables are *exhaustive* by contract.
/// 2. After every field is decoded, any leftover word bit no field covers
///    renders `<unknown bits: 0xNN>`. This is what catches upstream drift: a
///    bit a newer library sets that no table field mentions.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ScalarDecode {
    /// Render the whole word as an unsigned integer.
    Raw,
    /// Render the word as a count of milliseconds, spelled as seconds the way
    /// a duration is written: `12.721s`. The word is read as *signed*, so a
    /// difference of two counters that lost a race renders `-0.004s` rather
    /// than an astronomical wrapped value.
    Millis,
    /// Decompose the word into named sub-fields, low bit first.
    Bits(Vec<BitField>),
}

/// One named sub-field of a word decoded by [`ScalarDecode::Bits`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BitField {
    /// Label printed for this field (`name=…`).
    pub name: StrRef,
    /// Low bit of this field within the word.
    pub shift: u8,
    /// Field width in bits. `None` means "all bits at and above `shift`" — the
    /// trailing counter of a permit/version/generation word. `NonZeroU8`
    /// (rather than a `0` sentinel) makes an empty field unrepresentable.
    pub width: Option<NonZeroU8>,
    /// How the extracted sub-value is rendered.
    pub render: FieldRender,
}

/// How a [`BitField`]'s extracted sub-value is rendered.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FieldRender {
    /// Exhaustive value → label table. A value absent from the table renders
    /// `<unknown: N>` (rule 1 above); there is deliberately no boolean/flag
    /// kind, so a two-state field spells out both labels.
    Enum(Vec<(u64, StrRef)>),
    /// Render the sub-value as an unsigned integer (`name=N`).
    Uint,
}

/// How a [`DisplayNode::Bytes`] array is spelled as text.
///
/// A notation is data rather than a node kind of its own, so a fixed-size byte
/// array with a canonical text form costs one variant here instead of six sites
/// and a format bump. Each admits only the lengths its notation is defined for.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Notation {
    /// 4 or 16 unsigned bytes as an IPv4 or IPv6 address; which one follows
    /// from the count.
    IpAddr,
    /// Exactly 16 unsigned bytes as a hyphenated lowercase UUID, the form
    /// `uuid::Uuid`'s own `Display` produces.
    Uuid,
    /// Any number of unsigned bytes as lowercase hex, unseparated and
    /// unprefixed — how a digest is written everywhere it is written: a Git
    /// object id, a TUF artifact hash, a build id.
    Hex,
}

/// A composable display program for a known type: a recursive tree of nodes
/// that reify interprets with a single generic evaluator, in place of a
/// per-type `write_*` renderer.
///
/// Addressing is by [`Selector`] (resolved against the concrete [`TypeDef`] at
/// extraction time); related node types are [`BundleTypeId`]s. reify holds a
/// parallel *resolved* form of this tree carrying byte offsets rather than
/// selectors; the two share this shape.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum DisplayNode {
    /// Decode a single machine word and print it in place of the value.
    ///
    /// `at` reaches the word (a `usize`, an atomic's inner integer, a state
    /// byte, …); the word's byte width is the size of the type `at` lands on.
    /// `decode` interprets its bits (see [`ScalarDecode`]).
    Scalar { at: Selector, decode: ScalarDecode },
    /// Evaluate `value` (see [`ValueExpr`]) and print the resulting word,
    /// decoded like a [`DisplayNode::Scalar`]'s.
    ///
    /// Where a `Scalar` reads one word at a selector, this renders a word the
    /// program *computes* — a difference of two counters, a masked field —
    /// the way a [`DisplayNode::Variant`] computes its discriminant. The
    /// expression's reads may cross pointers and enum variants, so a failed
    /// or guarded read degrades to its marker in the value's place. The
    /// result is a full 64-bit word; `decode` is checked against that width.
    Computed {
        value: ValueExpr,
        decode: ScalarDecode,
    },
    /// Render the code pointer at `at` as its address and resolved symbol
    /// name, never following it as a data pointer.
    ///
    /// `at` reaches the pointer word (an empty selector addresses the value
    /// itself, as for a bare function pointer; a nonempty one reaches an
    /// embedded slot such as a vtable entry). reify prints `0x<addr>`, appends
    /// ` -> <symbol>` when the address resolves to a function symbol, and
    /// renders a null pointer as `null`.
    Symbol { at: Selector },
    /// Render a curated record of named fields, in order, as
    /// `<type> { field, field, … }`.
    ///
    /// Unlike ordinary structural display this shows *only* the listed
    /// [`Field`]s — the point of a formatter is to hide internal detail — so a
    /// field is included only if it appears here. A field's value is either a
    /// real member rendered structurally, or a nested node; see [`Field`]. The
    /// record is titled with the name of the type the node is rendered against
    /// (the formatted type at top level, or a list element's `node_ty`).
    Struct { fields: Vec<Field> },
    /// Walk an intrusive singly-linked list and render its nodes as
    /// `[elem, elem, …]`.
    ///
    /// `head` (rooted at the containing type) reaches the head word — a
    /// niche-optimized `Option<NonNull<Node>>`, so a zero word is an empty
    /// list. Each element is a `node_ty` value read from the target at the
    /// current node address and rendered via `node`; `next` (rooted at
    /// `node_ty`) reaches that element's successor word. reify guards the walk
    /// against cycles and runaway length.
    List {
        head: Selector,
        next: Selector,
        node: Box<DisplayNode>,
        node_ty: BundleTypeId,
    },
    /// Follow a `(data, len)` string slice to its byte buffer and render it as
    /// a quoted, escaped UTF-8 string.
    ///
    /// `pointer` reaches the data-pointer word and `length` the byte length;
    /// reify reads `length` bytes from the target through the pointer.
    /// `capacity`, when present, reaches an owned buffer's capacity word (a
    /// borrowed `&str` omits it) and is validated to be at least the length. A
    /// null data pointer or an unreadable buffer renders an explicit marker in
    /// place of the string; non-UTF-8 bytes render lossily, each invalid byte
    /// as a `\xNN` escape among the valid runs.
    ///
    /// `nul_terminated` says the length counts a trailing NUL that is not part
    /// of the string — a `CString`/`&CStr`, whose recorded length always
    /// includes its terminator. reify renders one byte fewer, and flags a
    /// buffer whose last byte turns out not to be NUL rather than trusting the
    /// layout blindly.
    Str {
        pointer: Selector,
        length: Selector,
        capacity: Option<Selector>,
        nul_terminated: bool,
    },
    /// Follow a `(data, len)` fat pointer to a contiguous buffer and render its
    /// first `length` `element`s as `[elem, elem, …]`.
    ///
    /// Covers any slice-shaped value — an owned `Vec<T>`, a boxed slice
    /// `Box<[T]>`, or a borrowed slice `&[T]` — just as the `Str` node covers
    /// `&str` and `String`. `pointer` reaches the data-pointer word and `length` the
    /// element count; each element is an `element` value read contiguously from
    /// the buffer. `capacity`, when present, reaches an owned buffer's
    /// allocation capacity (validated to be at least the length, except for a
    /// zero-sized element); it is absent for a borrowed or boxed slice that
    /// carries only a pointer and length. Unlike the intrusive `List` node the
    /// elements are packed in one allocation rather than chained by successor
    /// pointers.
    Slice {
        pointer: Selector,
        length: Selector,
        capacity: Option<Selector>,
        element: BundleTypeId,
    },
    /// Render an inline byte array in the standard textual notation for
    /// whatever it represents.
    ///
    /// `at` reaches the array — an `Ipv4Addr`/`Ipv6Addr`'s or a `Uuid`'s only
    /// member. Unlike `Str` and `Slice` this reads no pointer: the bytes live
    /// in the value's own bytes, so it is a leaf that renders what it lands on
    /// directly. The element type is validated to be an unsigned byte and the
    /// count to be one the notation admits.
    ///
    /// The notation is what distinguishes these types, not their layout: a
    /// `Uuid` and an `Ipv6Addr` are both `[u8; 16]`, and reading one as the
    /// other would be wrong rather than merely ugly.
    Bytes { at: Selector, notation: Notation },
    /// Render the value reached by `at` as though it were the whole value,
    /// peeling a transparent wrapper down to one inner member.
    ///
    /// `at` walks zero or more members from the wrapper to the aliased value,
    /// which is then rendered with reify's ordinary display for its own type.
    /// When `follow_pointers` is true a pointer alias is dereferenced like any
    /// other pointer; when it is false the stored address is shown without
    /// being followed — matching an atomic's `Debug`, which reports an
    /// `AtomicPtr`'s address rather than its pointee.
    Alias { at: Selector, follow_pointers: bool },
    /// Render a readiness bitmap as a count of written slots — `[<n> slots]`
    /// — where `n` is the number of set bits in `bitmap` among the low bits
    /// that cover `slots`.
    ///
    /// Used for a `tokio::sync::mpsc::block::Block<T>`'s inline slot array,
    /// which is not shown directly: a block cannot tell a still-queued
    /// message from an already-consumed one (that needs the channel's
    /// read/write positions), so its `MaybeUninit` bytes may be stale. Only
    /// the written count is reported. `bitmap` reaches the readiness word (bit
    /// `i` set means slot `i` was written); `slots` reaches the inline
    /// `[MaybeUninit<T>; N]` array whose length `N` bounds which bits count
    /// (higher bits are unrelated released/closed flags). The live messages
    /// are shown by the channel-level [`DisplayNode::CustomList`] walk.
    SlotCount { bitmap: Selector, slots: Selector },
    /// Follow the pointer reached by `at`, step `via` across the pointee to the
    /// rendered target, and render that target with `then`.
    ///
    /// `at` reaches a pointer word; `via` is rooted at its pointee and reaches
    /// the value actually rendered (skipping, e.g., an `Arc`'s strong/weak
    /// header to land on the `Chan` inside an `ArcInner`). `then`'s selectors
    /// are rooted at that target. reify reads the target from the process
    /// through the pointer and degrades to a marker (`<null>`, `<truncated>`,
    /// `<target unavailable>`, `<unreadable>`) titled with the *enclosing*
    /// type's name — a `Receiver` reads as the `Chan` it drains. This is the
    /// single-hop cousin of `List`: one pointer, one re-rooted node.
    Pointer {
        at: Selector,
        via: Selector,
        then: Box<DisplayNode>,
    },
    /// Display a Rust trait-object wide pointer and its vtable semantically.
    ///
    /// `pointer` reaches the data pointer and `vtable` the metadata pointer.
    /// The remaining indices address machine words in the vtable array itself;
    /// recording them here keeps rustc's private slot ordering out of bundle
    /// consumers.
    ///
    /// `tail_offset` is the byte offset of the `dyn Trait` tail *within the
    /// struct the data pointer targets*. It is zero for a bare `dyn Trait`
    /// pointee, but nonzero when the pointee is an unsized wrapper such as
    /// `ArcInner<dyn Trait>`, whose sized header precedes the erased value.
    DynPointer {
        pointer: Selector,
        vtable: Selector,
        drop_in_place: u32,
        size: u32,
        align: u32,
        tail_offset: u64,
    },
    /// Render an associative collection as `{ key: value, ... }`.
    ///
    /// `length` reaches the collection's initialized entry count. `key` and
    /// `value` identify the types yielded by `entries`; the entry source owns
    /// only the storage-specific traversal. This keeps presentation, recursive
    /// key/value display, and exact-length accounting shared while allowing
    /// genuinely different collection layouts to retain dedicated walkers.
    Map {
        length: Selector,
        key: BundleTypeId,
        value: BundleTypeId,
        entries: Box<MapEntries>,
    },
    /// Select one of several renderings by matching a computed discriminant,
    /// the way a Rust sum type (`Option`, `Result`, a tagged enum) chooses a
    /// variant — but from a value the IR *computes* rather than a tag read at a
    /// fixed offset. This is what lets a `watch::Receiver` render its unseen
    /// value as `Some(T)`/`None` from a cross-pointer version comparison
    /// without a bespoke node.
    ///
    /// `discriminant` is evaluated (see [`ValueExpr`]); the first [`Arm`] whose
    /// `value` equals it renders, else `default`, else `<unknown: N>` (the same
    /// "no silent state" contract as [`ScalarDecode`]). Only the selected arm
    /// is evaluated, so an unmatched arm's `payload` is never read.
    Variant {
        discriminant: ValueExpr,
        arms: Vec<Arm>,
        default: Option<Box<DisplayNode>>,
    },
    /// Generate a `[e, e, …]` sequence by interpreting a small imperative
    /// program — the general escape hatch for a windowed or paged traversal the
    /// declarative combinators can't shape, such as the mpsc block chain (a
    /// linked list of blocks each holding a slot array, windowed to the queued
    /// range).
    ///
    /// `vars` are seeded once from the rendered value (a seed may not reference
    /// another variable), then while `condition` holds the interpreter runs
    /// `body`: assignments, branches, and `Emit`s. Each `Emit` renders
    /// `element` against the bytes read at the address it computes. The
    /// evaluator caps iterations, so a malformed or cyclic program degrades
    /// rather than looping forever. See [`Stmt`] for the body statements and
    /// [`ValueExpr`] for the sublanguage the program is built from.
    CustomList {
        vars: Vec<ValueExpr>,
        condition: ValueExpr,
        body: Vec<Stmt>,
        element: BundleTypeId,
    },
    /// Render the value as the single token `<elided>`, reading nothing.
    ///
    /// The limit case of a formatter's job of hiding internal detail: for a
    /// type whose insides are never what a debugging session is after (a
    /// tokio runtime handle, a logger), the whole value is suppressed. The
    /// program carries no selectors, addresses no data and cannot decline,
    /// and reify renders it without touching the target. `--ugly` disables
    /// it along with every other custom formatter, which is the way to see
    /// the structure it hides.
    Elided,
}

/// One statement in a [`DisplayNode::CustomList`] body. The body is a flat
/// sequence run each loop iteration; `If` nests further sequences, but there is
/// no inner loop — iteration is the outer `CustomList` loop alone, which keeps
/// the interpreter's iteration cap a hard bound on the work a program can do.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Stmt {
    /// Assign loop variable `var`: `vars[var] = value`.
    Set { var: u32, value: ValueExpr },
    /// Run `then` when `cond` is nonzero, otherwise `otherwise`.
    If {
        cond: ValueExpr,
        then: Vec<Stmt>,
        otherwise: Vec<Stmt>,
    },
    /// Emit one sequence element: render the list's `element` type against the
    /// bytes read at the address `at` computes.
    Emit { at: ValueExpr },
    /// Stop the loop when `cond` is nonzero.
    Break { cond: ValueExpr },
}

/// One arm of a [`DisplayNode::Variant`]: the discriminant `value` it matches,
/// an optional constructor `label`, and an optional `payload` node. It renders
/// as `label`, `label(<payload>)`, or `<payload>` depending on which are
/// present — covering unit variants (`None`), tuple variants (`Some(x)`), and
/// bare boolean-style labels (`closed: false`).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Arm {
    pub value: u64,
    pub label: Option<StrRef>,
    pub payload: Option<Box<DisplayNode>>,
}

impl Arm {
    /// An arm that renders as its label alone — a unit variant, a state name,
    /// a bare boolean.
    pub fn labeled(value: u64, label: StrRef) -> Arm {
        Arm {
            value,
            label: Some(label),
            payload: None,
        }
    }

    /// An arm that renders `node` in the value's place, with no label.
    pub fn payload(value: u64, node: DisplayNode) -> Arm {
        Arm {
            value,
            label: None,
            payload: Some(Box::new(node)),
        }
    }
}

/// A small value sublanguage evaluated at render time against a value's bytes
/// (and, across a [`Step::Deref`], the target process). It exists so a
/// [`DisplayNode::Variant`] discriminant — a length, an index, a predicate —
/// can be *computed* from decoded words rather than only read at a fixed
/// offset. A [`DisplayNode::CustomList`] program builds on the same language,
/// adding loop [`ValueExpr::Var`]iables, computed [`ValueExpr::Load`]s, and
/// integer arithmetic so a block-chain walk can index a slot and test a bound.
/// Still deliberately minimal: operators are added only when a real type needs
/// one (there is, for instance, no shift or division yet).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum ValueExpr {
    /// Read the machine word (≤ 8 bytes) the selector lands on. The selector
    /// may cross a [`Step::Deref`], so a `Read` can reach an `Arc`-backed word.
    Read(Selector),
    /// A literal, e.g. a mask.
    Const(u64),
    /// Bitwise AND of two sub-expressions.
    And(Box<ValueExpr>, Box<ValueExpr>),
    /// Bitwise complement of a sub-expression (`state & Not(mask)` clears bits).
    Not(Box<ValueExpr>),
    /// `1` if the sub-expressions are unequal, else `0`.
    Ne(Box<ValueExpr>, Box<ValueExpr>),
    /// Read a [`DisplayNode::CustomList`] loop variable by index. Meaningless
    /// outside a `CustomList` body, where validation checks the index is in
    /// range; a `Variant` discriminant declares no variables, so any `Var`
    /// there is rejected.
    Var(u32),
    /// Read a `size`-byte machine word (1, 2, 4, or 8) from the target process
    /// at the address the sub-expression computes. Where [`ValueExpr::Read`] is
    /// anchored at the rendered value, `Load` reaches an address held in a loop
    /// variable — the block pointer a `CustomList` walks.
    Load { addr: Box<ValueExpr>, size: u32 },
    /// Wrapping sum of two sub-expressions.
    Add(Box<ValueExpr>, Box<ValueExpr>),
    /// Wrapping difference `lhs - rhs`.
    Sub(Box<ValueExpr>, Box<ValueExpr>),
    /// Wrapping product of two sub-expressions.
    Mul(Box<ValueExpr>, Box<ValueExpr>),
    /// `1` if `lhs < rhs` (unsigned), else `0`.
    Lt(Box<ValueExpr>, Box<ValueExpr>),
}

/// Builders, so a display program composes as the expression it is instead
/// of a pyramid of `Box::new`. The arithmetic and bitwise operators are the
/// std traits (`a + b`, `a & !mask`); the comparisons produce a word rather
/// than a `bool`, which the trait signatures cannot spell, so those are
/// plain methods.
impl ValueExpr {
    /// `1` if `self != rhs`, else `0` ([`ValueExpr::Ne`]).
    #[allow(clippy::should_implement_trait)] // PartialEq::ne must return bool.
    pub fn ne(self, rhs: ValueExpr) -> ValueExpr {
        ValueExpr::Ne(Box::new(self), Box::new(rhs))
    }

    /// `1` if `self < rhs` (unsigned), else `0` ([`ValueExpr::Lt`]).
    pub fn lt(self, rhs: ValueExpr) -> ValueExpr {
        ValueExpr::Lt(Box::new(self), Box::new(rhs))
    }

    /// Read a `size`-byte word at the address `self` computes
    /// ([`ValueExpr::Load`]).
    pub fn load(self, size: u32) -> ValueExpr {
        ValueExpr::Load {
            addr: Box::new(self),
            size,
        }
    }
}

impl std::ops::Add for ValueExpr {
    type Output = ValueExpr;
    fn add(self, rhs: ValueExpr) -> ValueExpr {
        ValueExpr::Add(Box::new(self), Box::new(rhs))
    }
}

impl std::ops::Sub for ValueExpr {
    type Output = ValueExpr;
    fn sub(self, rhs: ValueExpr) -> ValueExpr {
        ValueExpr::Sub(Box::new(self), Box::new(rhs))
    }
}

impl std::ops::Mul for ValueExpr {
    type Output = ValueExpr;
    fn mul(self, rhs: ValueExpr) -> ValueExpr {
        ValueExpr::Mul(Box::new(self), Box::new(rhs))
    }
}

impl std::ops::BitAnd for ValueExpr {
    type Output = ValueExpr;
    fn bitand(self, rhs: ValueExpr) -> ValueExpr {
        ValueExpr::And(Box::new(self), Box::new(rhs))
    }
}

impl std::ops::Not for ValueExpr {
    type Output = ValueExpr;
    fn not(self) -> ValueExpr {
        ValueExpr::Not(Box::new(self))
    }
}

/// A storage-specific producer of key/value entries for [`DisplayNode::Map`].
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum MapEntries {
    /// Walk an `alloc::collections::btree::map::BTreeMap` in key order.
    ///
    /// `root` reaches the map's `Option` root. `root_node` begins at its
    /// `Some` payload and lands on the node-reference structure; `height` and
    /// `node` begin there. Leaf selectors begin at `leaf`, internal selectors
    /// at `internal`, and `edge` at one element of the internal edge array.
    BTree {
        root: Selector,
        root_node: Selector,
        height: Selector,
        node: Selector,
        leaf: BundleTypeId,
        leaf_len: Selector,
        leaf_keys: Selector,
        leaf_values: Selector,
        internal: BundleTypeId,
        internal_data: Selector,
        internal_edges: Selector,
        edge: Selector,
    },
}

/// One field of a [`DisplayNode::Struct`] record.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Field {
    /// A real member of the rendered type, labeled with its DWARF name so the
    /// label need not be duplicated as a string.
    ///
    /// `node` computes the value in place of the member's own (rooted at the
    /// rendered type, the same root as the enclosing `Struct`), which is how
    /// one field of a record is decoded while the rest stay as they are. With
    /// no `node` the member is rendered by reify's ordinary structural
    /// display, recursing into its type — the one field kind that does.
    Member {
        at: MemberRef,
        node: Option<DisplayNode>,
    },
    /// A synthesized field: an explicit `label` whose value is computed by
    /// `node`. The node's selectors are rooted at the rendered type.
    Synth { label: StrRef, node: DisplayNode },
}

impl Field {
    /// A real member, rendered structurally under its own name.
    pub fn member(at: MemberRef) -> Self {
        Field::Member { at, node: None }
    }

    /// A real member whose value `node` computes in place of its own, keeping
    /// its own name as the label.
    pub fn computed(at: MemberRef, node: DisplayNode) -> Self {
        Field::Member {
            at,
            node: Some(node),
        }
    }
}

impl TypeTable {
    /// Get a type definition by id.
    pub fn get(&self, id: BundleTypeId) -> Option<&TypeDef> {
        self.types.get(id.0 as usize)
    }

    /// The byte size of `id`, or `None` when it is not knowable: an `Opaque`
    /// whose size DWARF did not record, an array whose element size is itself
    /// unknown, or a cyclic element chain. Arrays are the one kind that has to
    /// recurse, so the walk carries a seen-set and terminates on any input.
    pub fn size_of(&self, id: BundleTypeId) -> Option<u64> {
        fn go(table: &TypeTable, id: BundleTypeId, seen: &mut Vec<BundleTypeId>) -> Option<u64> {
            if seen.contains(&id) {
                return None;
            }
            match table.get(id)? {
                TypeDef::Base { size, .. }
                | TypeDef::Struct { size, .. }
                | TypeDef::Union { size, .. }
                | TypeDef::Enum { size, .. }
                | TypeDef::CEnum { size, .. } => Some(*size),
                TypeDef::Pointer { .. } => Some(super::POINTER_SIZE),
                TypeDef::Array { elem, count } => {
                    seen.push(id);
                    let size = go(table, *elem, seen)?.checked_mul(*count);
                    seen.pop();
                    size
                }
                TypeDef::Opaque { .. } => None,
            }
        }
        go(self, id, &mut Vec::new())
    }

    /// All type ids whose fully-qualified name is exactly `name`.
    ///
    /// `strings` must be the same table the ids were interned into.
    pub fn find_by_name<'a>(
        &'a self,
        strings: &'a StringTable,
        name: &'a str,
    ) -> impl Iterator<Item = BundleTypeId> + 'a {
        let lo = self
            .name_index
            .partition_point(|&(r, _)| strings.get(r).unwrap_or("") < name);
        self.name_index[lo..]
            .iter()
            .take_while(move |&&(r, _)| strings.get(r) == Some(name))
            .map(|&(_, id)| id)
    }

    /// All type ids whose name equals `name` under
    /// [`rust_type_names_equal`](crate::symbols::rust_type_names_equal),
    /// which accepts the spelling differences between DWARF and a demangler.
    ///
    /// Yields in `name_index` order, as a scan of it would: the stored
    /// index sorts by `(hash, position)`, so one hash's run keeps position
    /// order.
    ///
    /// `strings` must be the table the index's names were interned into.
    pub fn find_by_normalized_name<'a>(
        &'a self,
        strings: &'a StringTable,
        name: &'a str,
    ) -> impl Iterator<Item = BundleTypeId> + 'a {
        let hash = crate::symbols::rust_type_name_hash(name);
        let start = self.by_normalized_name.partition_point(|&(h, _)| h < hash);
        self.by_normalized_name[start..]
            .iter()
            .take_while(move |&&(h, _)| h == hash)
            .filter_map(move |&(_, position)| {
                let (r, id) = *self.name_index.get(position as usize)?;
                let candidate = strings.get(r)?;
                crate::symbols::rust_type_names_equal(candidate, name).then_some(id)
            })
    }

    /// (Re)build [`TypeTable::by_normalized_name`] from `name_index`. Every
    /// assembler of a table calls this once, after the last `name_index`
    /// mutation; a bundle whose index disagrees with its names fails
    /// validation.
    pub fn build_normalized_index(&mut self, strings: &StringTable) {
        self.by_normalized_name = self
            .name_index
            .iter()
            .enumerate()
            .filter_map(|(position, &(r, _))| {
                let name = strings.get(r)?;
                Some((crate::symbols::rust_type_name_hash(name), position as u32))
            })
            .collect();
        self.by_normalized_name.sort_unstable();
    }
}

/// One entry in a type table: layout information for a single type.
///
/// Wrapper kinds reify peels (typedef/const/volatile) are resolved away at
/// extraction time and never appear here.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum TypeDef {
    /// A primitive with a known encoding.
    Base {
        name: StrRef,
        size: u64,
        encoding: Encoding,
    },
    /// A pointer or reference to another type.
    Pointer {
        name: Option<StrRef>,
        target: BundleTypeId,
    },
    /// A fixed-length array.
    Array { elem: BundleTypeId, count: u64 },
    /// A struct (or tuple/closure environment — anything with plain members).
    Struct {
        name: StrRef,
        size: u64,
        members: Vec<MemberDef>,
    },
    /// A union.
    Union {
        name: StrRef,
        size: u64,
        members: Vec<MemberDef>,
    },
    /// A Rust enum: DWARF variant parts, represented faithfully including
    /// niche encodings.
    Enum {
        name: StrRef,
        size: u64,
        shape: VariantShape,
    },
    /// A C-style enumeration: named integer constants over a repr type.
    CEnum {
        name: StrRef,
        size: u64,
        repr: BundleTypeId,
        enumerators: Vec<(StrRef, i128)>,
    },
    /// A type the extractor could not model. Recorded explicitly (with a
    /// `--stats` counter at extraction time) so omissions are never silent.
    Opaque { name: StrRef, size: Option<u64> },
}

/// A named, typed field at a byte offset within a struct or union.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MemberDef {
    pub name: StrRef,
    pub ty: BundleTypeId,
    pub offset: u64,
}

/// The variant structure of a Rust enum, mirroring DWARF variant parts.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VariantShape {
    /// `None` for single-variant / univariant enums with no discriminant.
    pub discr: Option<DiscrDef>,
    pub variants: Vec<VariantDef>,
}

/// Where and what the discriminant is.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DiscrDef {
    pub offset: u64,
    pub ty: BundleTypeId,
}

/// One enum variant and the discriminant value(s) that select it.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VariantDef {
    pub name: StrRef,
    /// Explicit tag value(s), or `None` for the "default" variant in niche
    /// encodings (`DW_AT_discr_value` absent).
    pub discr_values: Option<DiscrValues>,
    /// The variant's payload member (offset + type).
    pub payload: MemberDef,
    /// Declaration coordinates of the variant member. For coroutine state
    /// machines rustc records the *awaited expression* here, so a
    /// `SuspendN` variant's `decl` is its await point's source line.
    pub decl: Option<SourceLoc>,
    /// Where a coroutine suspend point's await is *written*, when that is
    /// known to differ from where `decl` puts it.
    ///
    /// An await produced by a macro is attributed by `decl` to the line
    /// inside the macro that expanded to it — a `tokio::select!` arm
    /// resolves into `select.rs` rather than into the code that wrote the
    /// `select!`. The resume function's `__awaitee` local describes the
    /// same await and is attributed to the expansion site instead, so
    /// this carries that position where extraction could pair the two
    /// unambiguously. `None` means no better answer than `decl` was
    /// found, not that none exists.
    pub await_site: Option<SourceLoc>,
}

/// The discriminant values selecting a variant.
///
/// Values are the discriminant's raw bits **zero-extended to u128** — the
/// same representation a little-endian read of the discriminant's bytes
/// produces, so decoding is a direct comparison regardless of the
/// discriminant type's signedness (a signed `-1i8` tag is stored as
/// `0xff`). u128 width covers the DWARFv4 two-u64-block encoding; ranges
/// cover DWARFv5 `DW_AT_discr_list`.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct DiscrValues(pub Vec<DiscrValue>);

/// A single discriminant value or inclusive range.
#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum DiscrValue {
    Value(u128),
    Range(u128, u128),
}

impl DiscrValues {
    /// Does `raw` (the discriminant's raw bits) select this variant?
    pub fn matches(&self, raw: u128) -> bool {
        self.0.iter().any(|v| match *v {
            DiscrValue::Value(x) => x == raw,
            DiscrValue::Range(lo, hi) => (lo..=hi).contains(&raw),
        })
    }
}

/// The task join table: mangled vtable-fn symbol → spawned future.
///
/// Every monomorphized vtable fn of an instantiation (`poll`, `dealloc`,
/// `try_read_output`, `drop_join_handle_slow`, `drop_abort_handle`,
/// `shutdown`) keys the same entry, so any of them resolved from the
/// target's memory identifies the task's concrete future type.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct TaskTable {
    /// Mangled linkage name → entry. Keys are stored without `.llvm.<hash>`
    /// suffixes; use [`TaskTable::lookup`] which strips them.
    pub by_symbol: BTreeMap<String, TaskEntryId>,
    /// Normalized linkage name → distinct semantic entries. Multiple raw
    /// codegen copies of one entry collapse to one id.
    pub by_normalized_symbol: BTreeMap<String, Vec<TaskEntryId>>,
    pub entries: Vec<TaskFutureEntry>,
}

/// Result of exact-then-normalized symbol resolution.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SymbolLookup<T> {
    Missing,
    Unique(T),
    Ambiguous(Vec<T>),
}

/// Exact-then-normalized resolution over a symbol table and its
/// normalized index, shared by the task and dyn-future tables.
fn lookup_symbol_id<T: Copy>(
    by_symbol: &BTreeMap<String, T>,
    by_normalized_symbol: &BTreeMap<String, Vec<T>>,
    symbol: &str,
) -> SymbolLookup<T> {
    let symbol = strip_llvm_suffix(symbol);
    if let Some(id) = by_symbol.get(symbol) {
        return SymbolLookup::Unique(*id);
    }
    let Some(key) = normalized_v0_key(symbol) else {
        return SymbolLookup::Missing;
    };
    match by_normalized_symbol.get(&key).map(Vec::as_slice) {
        Some([id]) => SymbolLookup::Unique(*id),
        Some(ids) if !ids.is_empty() => SymbolLookup::Ambiguous(ids.to_vec()),
        _ => SymbolLookup::Missing,
    }
}

impl TaskTable {
    pub fn lookup_id(&self, symbol: &str) -> SymbolLookup<TaskEntryId> {
        lookup_symbol_id(&self.by_symbol, &self.by_normalized_symbol, symbol)
    }

    /// Look up a mangled symbol as read from the target's symtab.
    pub fn lookup(&self, symbol: &str) -> Option<&TaskFutureEntry> {
        let SymbolLookup::Unique(id) = self.lookup_id(symbol) else {
            return None;
        };
        self.entries.get(id.0 as usize)
    }
}

/// Type-table ids for one `tokio::runtime::task` instantiation.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TaskFutureEntry {
    /// `T`: the spawned future's concrete type.
    pub future: BundleTypeId,
    /// `tokio::runtime::task::core::Cell<T, S>`.
    pub cell: BundleTypeId,
    /// `tokio::runtime::task::core::Stage<T>`.
    pub stage: BundleTypeId,
    /// `S`: the scheduler (multi_thread vs current_thread handle).
    pub scheduler: BundleTypeId,
    /// Demangled name of `T`, for display only.
    pub display_name: StrRef,
}

/// Join table for `Box<dyn Future>` / `Pin<Box<dyn ...>>` awaitees:
/// linkage names of `<T as core::future::Future>::poll` and
/// `core::ptr::drop_glue::<T>` (rustc ≥ 1.97's spelling of what used to be
/// `drop_in_place`) → `T`'s type id.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct DynFutureTable {
    /// Keys are stored without `.llvm.<hash>` suffixes; use
    /// [`DynFutureTable::lookup`] which strips them.
    pub by_symbol: BTreeMap<String, BundleTypeId>,
    pub by_normalized_symbol: BTreeMap<String, Vec<BundleTypeId>>,
}

impl DynFutureTable {
    pub fn lookup_id(&self, symbol: &str) -> SymbolLookup<BundleTypeId> {
        lookup_symbol_id(&self.by_symbol, &self.by_normalized_symbol, symbol)
    }

    /// Look up a mangled symbol as read from the target's symtab.
    pub fn lookup(&self, symbol: &str) -> Option<BundleTypeId> {
        let SymbolLookup::Unique(id) = self.lookup_id(symbol) else {
            return None;
        };
        Some(id)
    }
}

/// Strip the `.llvm.<decimal>` suffix LLVM appends to internalized copies of
/// a symbol. The suffix is path-sensitive across separate compilations and
/// must never participate in a join.
pub fn strip_llvm_suffix(symbol: &str) -> &str {
    match symbol.rfind(".llvm.") {
        Some(i)
            if symbol[i + ".llvm.".len()..]
                .bytes()
                .all(|b| b.is_ascii_digit())
                && i + ".llvm.".len() < symbol.len() =>
        {
            &symbol[..i]
        }
        _ => symbol,
    }
}

/// Named statics whose *addresses* must be resolved in the target's symtab
/// at attach time.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum StaticRole {
    /// The TLS key holding each thread's `tokio::runtime::context::Context`
    /// (std's `__RUST_STD_INTERNAL_VAL` static for tokio's `CONTEXT`).
    TlsContextKey,
    /// Tokio's task `WAKER_VTABLE` static, identifying task wakers found in
    /// resource waiter lists.
    TaskWakerVtable,
    /// The TLS key holding each thread's `tokio::task::local::LocalData`
    /// (std's `__RUST_STD_INTERNAL_VAL` static for `task::local::CURRENT`) —
    /// the scoped anchor of a `LocalSet` being polled. Present only in
    /// binaries that link `tokio::task::local`, so absence is the expected
    /// shape of most targets, not a breakage.
    TlsLocalSetKey,
}

/// A static's symbol names: the mangled name is the join key, the demangled
/// form is for diagnostics only.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct StaticDef {
    pub symbol: String,
    pub display: String,
}

/// Role → symbol to resolve via `Plookup_by_name` on the target.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct StaticsTable {
    pub entries: BTreeMap<StaticRole, StaticDef>,
}

/// Generates [`WalkRole`]: the enum, [`WalkRole::ALL`], and
/// [`WalkRole::name`] from one row per role, so the three can never
/// disagree — a variant cannot be missing from `ALL`, listed out of
/// declaration order, or left without a report name.
macro_rules! walk_roles {
    ($($variant:ident = $name:literal,)+) => {
        /// Every datum the runtime walk navigates to by declaration, by role.
        ///
        /// One variant per row of the walk contract's table. The names mirror the
        /// contract's own (`Context.current_task_id`, `Sleep.deadline`, …) — see
        /// [`WalkRole::name`] — and the declaration order here is the report's
        /// order.
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
        pub enum WalkRole {
            $($variant,)+
        }

        impl WalkRole {
            /// Every role, in report order (declaration order).
            pub const ALL: &'static [WalkRole] = &[$(WalkRole::$variant,)+];

            /// The role's name as the walk-contract report spells it. These are
            /// stable: the matrix `walk.golden`s diff them.
            pub fn name(self) -> &'static str {
                match self { $(WalkRole::$variant => $name,)+ }
            }
        }
    };
}

// Append only: a role's variant index is its wire encoding inside every
// bundle's `WalkBinding`s, so inserting or reordering rows is a format
// break the version number must own.
walk_roles! {
    CurrentTaskId = "Context.current_task_id",
    ContextThreadId = "Context.thread_id",
    WorkerHandle = "Context.handle",
    CtWorkerHandle = "Context.handle.current_thread",
    WorkerContext = "Context.scheduler",
    CtWorkerContext = "Context.scheduler.current_thread",
    WorkerIndex = "worker::Context.index",
    CtWorkerCore = "current_thread::Context.core",
    CtCoreDriver = "current_thread::Core.driver",
    HandleShared = "Handle.shared",
    SharedRemotes = "Shared.remotes",
    RemoteUnpark = "Remote.unpark",
    ParkerState = "parker::Inner.state",
    ParkerDriverLock = "parker::Inner.driver_lock",
    CtSharedWoken = "current_thread::Shared.woken",
    BlockingMetrics = "Handle.blocking_metrics",
    BlockingThreads = "SpawnerMetrics.num_threads",
    BlockingIdle = "SpawnerMetrics.num_idle_threads",
    BlockingQueueDepth = "SpawnerMetrics.queue_depth",
    OwnedLists = "Shared.owned_lists",
    SchedulerOwnedId = "Shared.owned_id",
    ShardHead = "Shard.head",
    HeaderState = "Header.state",
    HeaderOwnerId = "Header.owner_id",
    HeaderVtable = "Header.vtable",
    TrailerNext = "Trailer.owned_next",
    VtablePoll = "Vtable.poll",
    VtableTrailerOffset = "Vtable.trailer_offset",
    VtableIdOffset = "Vtable.id_offset",
    VtableDealloc = "Vtable.dealloc",
    VtableTryReadOutput = "Vtable.try_read_output",
    VtableDropJoinHandleSlow = "Vtable.drop_join_handle_slow",
    VtableDropAbortHandle = "Vtable.drop_abort_handle",
    VtableShutdown = "Vtable.shutdown",
    VtableSpawnLocationOffset = "Vtable.spawn_location_offset",
    LocationFile = "Location.file",
    LocationLine = "Location.line",
    LocationCol = "Location.col",
    CellStage = "Cell.stage",
    CellStageRunning = "Cell.stage_running",
    CellStageFinished = "Cell.stage_finished",
    CellStageConsumed = "Cell.stage_consumed",
    CellTrailer = "Cell.trailer",
    CellTaskId = "Cell.task_id",
    CellScheduler = "Cell.scheduler",
    SleepDeadline = "Sleep.deadline",
    DeadlineTvSec = "Sleep.deadline.tv_sec",
    DeadlineTvNsec = "Sleep.deadline.tv_nsec",
    JoinHandleRaw = "JoinHandle.raw",
    AcquireSemaphore = "Acquire.semaphore",
    AcquireNumPermits = "Acquire.num_permits",
    AcquireNode = "Acquire.node",
    AcquireNeeded = "Acquire.node.state",
    AcquireQueued = "Acquire.queued",
    SemaphorePermits = "Semaphore.permits",
    SemaphoreQueueHead = "Semaphore.queue_head",
    WaiterNeeded = "Waiter.state",
    WaiterNext = "Waiter.next",
    WaiterWaker = "Waiter.waker",
    WakerData = "RawWaker.data",
    WakerVtable = "RawWaker.vtable",
    SetHeadAll = "FuturesUnordered.head_all",
    SetNodeFuture = "SetNode.future",
    SetNodeNext = "SetNode.next_all",
    JoinSetLength = "JoinSet.length",
    JoinSetLists = "JoinSet.lists",
    JoinSetNotifiedHead = "JoinSet.notified_head",
    JoinSetIdleHead = "JoinSet.idle_head",
    JoinSetEntryValue = "ListEntry.value",
    JoinSetEntryNext = "ListEntry.next",
    LocalOwnedId = "local::Shared.owned_id",
    LocalOwnedHead = "local::Shared.owned_head",
    LocalSetOwner = "local::Shared.owner",
    LocalTlsCtx = "LocalData.ctx",
    LocalCtxShared = "local::Context.shared",
    WheelLevels = "time::Wheel.levels",
    LevelSlots = "wheel::Level.slot",
    SlotHead = "wheel::Slot.head",
    TimerSharedNext = "TimerShared.next",
    TimerSharedWaker = "TimerShared.waker",
    IoRegistrations = "io::Synced.registrations",
    ScheduledIoNext = "ScheduledIo.next",
    ScheduledIoWaiters = "ScheduledIo.waiters",
    IoWaiterHead = "io::Waiters.list",
    IoReaderWaker = "io::Waiters.reader",
    IoWriterWaker = "io::Waiters.writer",
    IoWaiterNext = "io::Waiter.next",
    IoWaiterWaker = "io::Waiter.waker",
    TimerSharedState = "TimerShared.state",
    ScheduledIoReadiness = "ScheduledIo.readiness",
    IoWaiterInterest = "io::Waiter.interest",
    TcpStreamShared = "net::TcpStream.shared",
    TcpStreamFd = "net::TcpStream.fd",
    TcpListenerShared = "net::TcpListener.shared",
    TcpListenerFd = "net::TcpListener.fd",
    UdpSocketShared = "net::UdpSocket.shared",
    UdpSocketFd = "net::UdpSocket.fd",
    UnixStreamShared = "net::UnixStream.shared",
    UnixStreamFd = "net::UnixStream.fd",
    UnixListenerShared = "net::UnixListener.shared",
    UnixListenerFd = "net::UnixListener.fd",
    UnixDatagramShared = "net::UnixDatagram.shared",
    UnixDatagramFd = "net::UnixDatagram.fd",
}

/// What binding one walk role against the target's DWARF concluded.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum WalkOutcome {
    /// The navigation resolved. `spelling` is which declared alternative
    /// bound (0-based) of `spellings`, for the report — anything but the
    /// first is a fallback worth noticing in a report diff.
    Bound {
        spelling: u32,
        spellings: u32,
        /// Extraction-time context for the report: how many root types the
        /// binding was validated against, opaque cells skipped, and the
        /// like.
        note: Option<String>,
    },
    /// Nothing to bind, expectedly: a leaf type the target does not use, an
    /// instrumentation member of a build whose capability the bundle
    /// records as off.
    Absent { reason: String },
    /// No spelling matched the layout — or the roots demanded different
    /// spellings, which one binding cannot serve. One message per miss.
    Broken { errors: Vec<String> },
}

/// One navigation the extraction-time binder resolved against the target's
/// own DWARF, for the runtime walk to execute.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct WalkBinding {
    /// The root types the steps were resolved against — every per-type root
    /// (each task cell, each matching leaf type) for a bound entry, so
    /// validation can re-resolve the binding without knowing how the role's
    /// roots are found. Empty unless the outcome is [`WalkOutcome::Bound`].
    pub roots: Vec<BundleTypeId>,
    /// The bound navigation, name-addressed — same doctrine as display
    /// selectors: names, never positions. Empty unless the outcome is
    /// [`WalkOutcome::Bound`].
    pub steps: Vec<Step>,
    pub outcome: WalkOutcome,
}

/// Navigations whose spellings exegesis bound against this target's DWARF
/// at extraction, for hansei's runtime walk to execute — the walk-contract
/// sibling of [`StaticsTable`]: exegesis locates, hansei consumes by role,
/// never re-searches. One entry per role the binder could say anything
/// about.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct WalksTable {
    pub entries: BTreeMap<WalkRole, WalkBinding>,
}

/// Type-table ids for the non-generic tokio infrastructure types.
///
/// Extraction resolves these from the debug binary's DWARF and fails
/// loudly if any is missing.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct InfraTypes {
    /// `tokio::runtime::task::core::Header`.
    pub header: BundleTypeId,
    /// `tokio::runtime::task::raw::Vtable` — `#[repr(Rust)]`, so its field
    /// offsets must come from here, never from declaration order.
    pub vtable: BundleTypeId,
    /// `tokio::runtime::task::core::Trailer`.
    pub trailer: BundleTypeId,
    /// `tokio::runtime::context::Context`.
    pub context: BundleTypeId,
    /// `tokio::runtime::scheduler::Handle` (enum).
    pub scheduler_handle: BundleTypeId,
    /// `tokio::runtime::scheduler::multi_thread::Handle` (behind an `Arc`).
    /// An opaque placeholder on a target built without `rt-multi-thread`.
    pub mt_handle: BundleTypeId,
    /// `tokio::runtime::scheduler::current_thread::Handle` (behind an
    /// `Arc`) — the other scheduler flavor's handle. At least one of the
    /// two flavor handles resolves on any tokio target.
    pub ct_handle: BundleTypeId,
    /// `core::panic::Location`.
    pub location: BundleTypeId,
    /// `core::task::RawWakerVTable`.
    pub raw_waker_vtable: BundleTypeId,
}

/// Where each task future comes from, indexed by [`TaskEntryId`]
/// (parallel to [`TaskTable::entries`]).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ProvenanceTable {
    pub entries: Vec<Provenance>,
}

/// The impl-block namespaces this bundle's names mention, each resolved
/// to its impl's self type.
///
/// rustc's debug info spells an impl block as an artificial `{impl#N}`
/// namespace, so a method-scoped type's name reads
/// `tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}` — truthful
/// and unreadable. The namespace DIE records nothing about the self
/// type; extraction recovers it from the mangled name of a subprogram
/// inside the block, which spells the real path. Keys are namespace
/// paths up to and including their `{impl#N}` segment; values are the
/// self type's path with generic arguments stripped
/// (`tokio::sync::mutex::Mutex`). Only impl paths occurring in one of
/// the bundle's strings are recorded — display substitution
/// ([`crate::names::ImplFold`]) is the sole consumer, and an impl no
/// name mentions has nothing to substitute into.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ImplTable {
    /// `(impl path, self type path)`, sorted and unique by the resolved
    /// key string. A value never contains an `{impl#` segment of its
    /// own, which keeps substitution idempotent.
    pub entries: Vec<(StrRef, StrRef)>,
}

/// Every trait-object vtable the target's debug info describes.
///
/// rustc emits one `DW_TAG_variable` per vtable it instantiates, named
/// with the whole `<{concrete} as {trait}>::{vtable}` pair, so the answer
/// to "which vtables implement trait T" is in the debug info and needs no
/// scanning. It is carried here because the read side must keep working
/// where there is only a bundle and a core — the host debugging a
/// production target has no DWARF to consult.
///
/// This table is metadata, not roots: an entry never causes a type to be
/// emitted, and [`VtableEntry::type_id`] is filled only when the concrete
/// type was already in the bundle for its own reasons.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct VtableTable {
    /// Sorted by `(trait, concrete, address)` and unique. Several entries
    /// may share an `address` — the linker folded identical vtables
    /// together — and one `(trait, concrete)` pair may appear at several
    /// addresses; neither is a duplicate, and both are the ambiguity a
    /// lookup has to show rather than resolve.
    pub entries: Vec<VtableEntry>,
}

/// The words every Rust vtable opens with — drop glue, size, align —
/// before its first method slot.
pub const VTABLE_HEADER_SLOTS: u16 = 3;

/// One trait-object vtable: which pair it implements, where it is, and
/// how many words it occupies.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VtableEntry {
    /// The trait side, e.g. `core::future::future::Future`.
    pub trait_: StrRef,
    /// The concrete side, e.g. `dyn_future::boxed_leaf::{async_fn_env#0}`.
    pub concrete: StrRef,
    /// Static address in the debug binary's address space; a reader adds
    /// the target's load bias, as it does for a static.
    pub address: u64,
    /// Total words, the drop-glue/size/align header included, so the
    /// first method slot is 3.
    pub slot_count: u16,
    /// Method slots the `{vtable_type}` names no member for, ascending.
    /// rustc emits a vacant entry for a method a trait object cannot
    /// dispatch (`where Self: Sized`, say), and the debug info shows that
    /// statically: a neutral fact about the vtable, not a fault.
    pub undescribed_slots: Vec<u16>,
    /// The concrete type in this bundle's type table, when it is there.
    /// `None` is the common case — a target instantiates far more
    /// vtables than a bundle has reason to describe types for.
    pub type_id: Option<BundleTypeId>,
}

/// Source provenance for one future type.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Provenance {
    /// `DW_AT_decl_file`/`line` of the coroutine type or its async fn.
    pub decl: Option<SourceLoc>,
    pub kind: FutureKind,
}

/// What kind of source construct produced a future type.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FutureKind {
    AsyncFn,
    AsyncBlock,
    Combinator,
    Manual,
}

/// A file/line pair, file interned in the bundle's string table.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SourceLoc {
    pub file: StrRef,
    pub line: u32,
}

/// Cut an absolute source path down to the tail a reader can use.
///
/// Both source paths a reader sees pass through here, so that a file named
/// twice is spelled the same way both times: DWARF line-table paths as a
/// bundle is extracted, and the `file!()` string in a task's
/// `core::panic::Location` as it is read out of the target.
///
/// An absolute path names the build machine's crate cache or toolchain, so
/// `…/registry/src/<index>/tokio-1.50.0` keeps `tokio-1.50.0`,
/// `…/git/checkouts/dendrite-<cache hash>/cc0c307` keeps `dendrite/cc0c307`,
/// both `/rustc/<hash>/library/std/src` and a rustup toolchain's
/// `…/lib/rustlib/src/rust/library/std/src` keep `library/std/src`, and
/// prebuilt std's vendored `/rust/deps/hashbrown-0.15.5/src` keeps
/// `hashbrown-0.15.5/src`. A relative path is already what a reader wants
/// and is kept whole, as is an unrecognized absolute one: wrong-but-complete
/// beats truncated-and-ambiguous.
pub fn strip_build_prefix(path: &str) -> Cow<'_, str> {
    if !path.starts_with('/') {
        return Cow::Borrowed(path);
    }
    if let Some((_, rest)) = path.split_once("/registry/src/")
        && let Some((_, rest)) = rest.split_once('/')
    {
        return Cow::Borrowed(rest);
    }
    if let Some((_, rest)) = path.split_once("/git/checkouts/") {
        // `<name>-<cache hash>/<rev>/…` → `<name>/<rev>/…`; the cache
        // hash disambiguates same-named checkouts on the build machine,
        // which the rev already does for a reader.
        if let Some((checkout, tail)) = rest.split_once('/')
            && let Some((name, hash)) = checkout.rsplit_once('-')
            && hash.len() == 16
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Cow::Owned(format!("{name}/{tail}"));
        }
        return Cow::Borrowed(rest);
    }
    if let Some(rest) = path.strip_prefix("/rustc/")
        && let Some((_, rest)) = rest.split_once('/')
    {
        return Cow::Borrowed(rest);
    }
    if let Some((_, rest)) = path.split_once("/lib/rustlib/src/rust/") {
        return Cow::Borrowed(rest);
    }
    if let Some(rest) = path.strip_prefix("/rust/deps/") {
        return Cow::Borrowed(rest);
    }
    Cow::Borrowed(path)
}

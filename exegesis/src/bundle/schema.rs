//! The bundle's serialized data model.
//!
//! Design rules (see `HANSEI_V0_MANGLING_PLAN.md` §5):
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

use crate::bundle::strings::{StrRef, StringTable};
use crate::raw_types::Encoding;
use crate::symbols::normalized_v0_key;

use serde::{Deserialize, Serialize};

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
    pub infra: InfraTypes,
    pub provenance: ProvenanceTable,
}

/// Identity and validation data for the producing binary (§5.1).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    /// Copy of the header's format version, for tools that inspect a decoded
    /// bundle without the framing.
    pub format_version: u32,
    /// From the producer's `DW_AT_producer`.
    pub rustc_version: String,
    /// Tokio version, when recoverable from DWARF.
    pub tokio_version: Option<semver::Version>,
    /// Identity of the debug binary the bundle was extracted from.
    pub debug_binary: BinaryIdent,
    /// Command line of the extraction, for provenance.
    pub extract_args: String,
    /// Mangled task poll symbols sampled (or all) for target match-rate
    /// validation at attach time.
    pub symbol_fingerprint: Vec<String>,
}

/// Identity of the ELF the bundle was produced from.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct BinaryIdent {
    /// Path basename of the debug binary.
    pub basename: String,
    /// GNU build-id note contents, if present.
    pub build_id: Option<Vec<u8>>,
    /// BLAKE3 hash of the whole ELF file.
    pub blake3: [u8; 32],
}

/// The layout graph (§5.2): an index-based arena of type definitions.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct TypeTable {
    pub types: Vec<TypeDef>,
    /// Optional display instructions attached to concrete type layouts.
    /// Types absent from this map use reify's ordinary structural display.
    pub debug_formats: BTreeMap<BundleTypeId, DebugFormat>,
    /// By-name index for the (rarer) name-based lookups: pairs of
    /// (fully-qualified name, type id), sorted by the *resolved string*
    /// so lookups can binary-search without materializing owned keys.
    /// Multiple ids may share one name (e.g. identical instantiations from
    /// different CUs).
    pub name_index: Vec<(StrRef, BundleTypeId)>,
}

/// One step in a [`Selector`]: descend into an aggregate member, or follow a
/// pointer to the value it points at.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Step {
    /// Index into the current struct/union's member list; adds that member's
    /// byte offset and continues in its type.
    Member(u32),
    /// Follow the current pointer to its pointee, restarting the byte offset
    /// within the target type.
    Deref,
}

/// A path from a root type to a nested datum.
///
/// [`Step::Member`] steps descend through struct/union members, accumulating
/// byte offsets; a [`Step::Deref`] step crosses a pointer, restarting the
/// offset inside the pointee. A `Selector` unifies what used to be recorded
/// inconsistently as either a bare `u32` member index or a `Vec<u32>` member
/// path, and subsumes the per-formatter "resolve a pointer, then continue
/// against its target" special cases: a cross-pointer reach is just a
/// selector containing a `Deref`.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Selector(pub Vec<Step>);

impl Selector {
    /// A selector that descends a single member of the root aggregate.
    pub fn member(index: u32) -> Self {
        Selector(vec![Step::Member(index)])
    }

    /// Prepend a leading [`Step::Member`]: the result descends `index` of a
    /// new root, then continues with this selector's steps. Used by detectors
    /// that anchor an inner path (e.g. an atomic's word) at an outer field.
    pub fn under_member(self, index: u32) -> Self {
        let mut steps = Vec::with_capacity(self.0.len() + 1);
        steps.push(Step::Member(index));
        steps.extend(self.0);
        Selector(steps)
    }

    /// Whether this selector has no steps (addresses the root itself).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The selector's steps.
    pub fn steps(&self) -> &[Step] {
        &self.0
    }

    /// The index of the first step when it is a [`Step::Member`], i.e. the
    /// top-level member this selector descends into. Used where a formatter
    /// also needs that member index (e.g. rendering a struct field in place).
    pub fn first_member(&self) -> Option<u32> {
        match self.0.first() {
            Some(Step::Member(index)) => Some(*index),
            _ => None,
        }
    }
}

/// Build a member-only selector from a legacy member-index path.
impl From<Vec<u32>> for Selector {
    fn from(path: Vec<u32>) -> Self {
        Selector(path.into_iter().map(Step::Member).collect())
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

/// Declarative instructions for displaying a known type.
///
/// Addressing is expressed with [`Selector`]s resolved against the concrete
/// [`TypeDef`]. Exegesis resolves and validates them while it still has the
/// source DWARF's structured generic parameter information; consumers never
/// match type names or private field names.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum DebugFormat {
    /// Display one member as though it were the containing value.
    Transparent { member: Selector },
    /// Apply semantics for a known family of types.
    Known(KnownFormat),
    /// Render the type by interpreting a composable [`DisplayNode`] program.
    ///
    /// This is the target representation of the Formatter IR: instead of one
    /// bespoke [`KnownFormat`] variant per type, a detector emits a tree of a
    /// few shared combinators that reify walks with one generic evaluator. It
    /// is introduced alongside `Known` and formatters migrate onto it one at a
    /// time, so during the transition a bundle may carry either spelling.
    Node(DisplayNode),
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
}

/// One field of a [`DisplayNode::Struct`] record.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Field {
    /// Include real member `index` of the rendered type, labeled with its
    /// DWARF name and rendered with reify's ordinary structural display. This
    /// is the one field kind that recurses into a member's own type.
    Member(u32),
    /// A synthesized field: an explicit `label` whose value is computed by
    /// `node`. The node's selectors are rooted at the rendered type (the same
    /// root as the enclosing `Struct`).
    Named { label: StrRef, node: DisplayNode },
    /// Real member `index`'s DWARF name, but with its value replaced by
    /// `node` (rooted at the rendered type). Reuses the member's name so the
    /// label need not be duplicated as a string; used to decode one field of a
    /// struct in place while keeping its name.
    Override { index: u32, node: DisplayNode },
}

/// Closed set of semantic formatters understood by reify.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum KnownFormat {
    /// Display an atomic's stored value. The selector walks zero or more
    /// concrete struct/union members from the atomic to its value type.
    Atomic { value: Selector },
    /// Display a Rust trait-object wide pointer and its vtable semantically.
    ///
    /// `pointer` and `vtable` index members of the containing aggregate. The
    /// remaining indices address machine words in the vtable array itself;
    /// recording them here keeps rustc's private slot ordering out of bundle
    /// consumers.
    ///
    /// `tail_offset` is the byte offset of the `dyn Trait` tail *within the
    /// struct the data pointer targets*. It is zero for a bare `dyn Trait`
    /// pointee, but nonzero when the pointee is an unsized wrapper such as
    /// `ArcInner<dyn Trait>`, whose sized header (the strong/weak counts)
    /// precedes the erased value. Consumers add it to the data-pointer
    /// address before reading the concrete pointee.
    DynPointer {
        pointer: u32,
        vtable: u32,
        drop_in_place: u32,
        size: u32,
        align: u32,
        tail_offset: u64,
    },
    /// Display a `tokio::sync::mpsc::chan::Chan<T, S>`'s live queued messages.
    /// The receiver has read up to `index` and the sender has written up to
    /// `tail` (both member paths to a `usize` within the channel); the
    /// messages in `[index, tail)` are still queued. `head` is the path to the
    /// receiver's head block pointer. The remaining paths are rooted at the
    /// *block* type (reached through `head`): `start_index` gives a block's
    /// first absolute slot index, `next` its successor block pointer, and
    /// `values` its inline slot array. `element` is the message type `T`. reify
    /// walks the block chain and renders each queued slot as `element`.
    MpscChan {
        tail: Selector,
        index: Selector,
        head: Selector,
        start_index: Selector,
        next: Selector,
        values: Selector,
        element: BundleTypeId,
    },
    /// Display a `tokio::sync::mpsc::block::Block<T>` with its inline `values`
    /// array elided to a count of written slots rather than raw `MaybeUninit`
    /// bytes. `ready_slots` is the member path to the header's readiness
    /// bitmap (bit `i` set means slot `i` was written); `values` is the member
    /// path to the `[MaybeUninit<T>; N]` array, its first element the index of
    /// the `values` member. The slot *contents* are not shown here: a block
    /// cannot tell which written slots are still queued versus already
    /// consumed (that needs the channel's read/write positions), so their
    /// bytes may be stale. The live messages are shown by the channel-level
    /// [`KnownFormat::MpscChan`] formatter instead.
    MpscBlock {
        ready_slots: Selector,
        values: Selector,
    },
    /// Display a `tokio::sync::mpsc::bounded::Receiver<T>` as its underlying
    /// channel. A receiver holds an `Arc<Chan<T, Semaphore>>`; `chan_pointer`
    /// is the member path from the receiver to the raw pointer inside that
    /// `Arc` (ending at a pointer to the `ArcInner` allocation), and `chan` is
    /// the path from the allocation to the `Chan` value, skipping the Arc's
    /// strong/weak header. `bound` and `permits` are member paths *within the
    /// Chan* to the bounded capacity (a plain `usize`) and the batch-semaphore
    /// permit word (bit 0 closed, the rest the available buffer slots). reify
    /// reads the `Chan` through the pointer and renders it with the capacity
    /// and free-slot count prepended, delegating the queued-message walk to the
    /// `Chan`'s own [`KnownFormat::MpscChan`] formatter.
    /// `permits_decode` carries the bit layout of that permit word (bit 0
    /// closed, the rest the available count).
    MpscRx {
        chan_pointer: Selector,
        chan: Selector,
        bound: Selector,
        permits: Selector,
        permits_decode: ScalarDecode,
    },
    /// Display the octets of an IPv4 or IPv6 address in standard notation.
    IpAddress { octets: Selector },
    /// Display the initialized elements of an `alloc::vec::Vec<T, A>`.
    Vec {
        pointer: Selector,
        length: Selector,
        capacity: Selector,
        element: BundleTypeId,
    },
    /// Display a `&str` as quoted, escaped UTF-8.
    Str { pointer: Selector, length: Selector },
    /// Display an `alloc::string::String` as quoted, escaped UTF-8.
    String {
        pointer: Selector,
        length: Selector,
        capacity: Selector,
    },
    /// Display an `alloc::collections::btree::map::BTreeMap<K, V, A>` as
    /// its initialized key/value entries.
    ///
    /// Paths are rooted in the type named by their preceding field. The
    /// root-node path begins at `Option::Some`'s payload, while the edge
    /// path begins at one element of the internal node's edge array.
    BTreeMap {
        root: u32,
        length: u32,
        root_node: Selector,
        height: u32,
        node: Selector,
        key: BundleTypeId,
        value: BundleTypeId,
        leaf: BundleTypeId,
        leaf_len: u32,
        leaf_keys: u32,
        leaf_values: u32,
        internal: BundleTypeId,
        internal_data: u32,
        internal_edges: u32,
        edge: Selector,
    },
}

impl TypeTable {
    /// Get a type definition by id.
    pub fn get(&self, id: BundleTypeId) -> Option<&TypeDef> {
        self.types.get(id.0 as usize)
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
    /// `SuspendN` variant's `decl` is its await point's source line
    /// (§13.5).
    pub decl: Option<SourceLoc>,
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

/// The task join table (§5.3): mangled vtable-fn symbol → spawned future.
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

impl TaskTable {
    pub fn lookup_id(&self, symbol: &str) -> SymbolLookup<TaskEntryId> {
        let symbol = strip_llvm_suffix(symbol);
        if let Some(id) = self.by_symbol.get(symbol) {
            return SymbolLookup::Unique(*id);
        }
        let Some(key) = normalized_v0_key(symbol) else {
            return SymbolLookup::Missing;
        };
        match self.by_normalized_symbol.get(&key).map(Vec::as_slice) {
            Some([id]) => SymbolLookup::Unique(*id),
            Some(ids) if !ids.is_empty() => SymbolLookup::Ambiguous(ids.to_vec()),
            _ => SymbolLookup::Missing,
        }
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

/// Join table for `Box<dyn Future>` / `Pin<Box<dyn ...>>` awaitees (§5.3):
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
        let symbol = strip_llvm_suffix(symbol);
        if let Some(id) = self.by_symbol.get(symbol) {
            return SymbolLookup::Unique(*id);
        }
        let Some(key) = normalized_v0_key(symbol) else {
            return SymbolLookup::Missing;
        };
        match self.by_normalized_symbol.get(&key).map(Vec::as_slice) {
            Some([id]) => SymbolLookup::Unique(*id),
            Some(ids) if !ids.is_empty() => SymbolLookup::Ambiguous(ids.to_vec()),
            _ => SymbolLookup::Missing,
        }
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
/// must never participate in a join (see `docs/v0-mangling-spike.md`).
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
/// at attach time (§5.4).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum StaticRole {
    /// The TLS key holding each thread's `tokio::runtime::context::Context`
    /// (std's `__RUST_STD_INTERNAL_VAL` static for tokio's `CONTEXT`).
    TlsContextKey,
    /// Tokio's task `WAKER_VTABLE` static, identifying task wakers found in
    /// resource waiter lists.
    TaskWakerVtable,
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

/// Type-table ids for the non-generic tokio infrastructure types (§5.4).
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
    pub mt_handle: BundleTypeId,
    /// `core::panic::Location`.
    pub location: BundleTypeId,
    /// `core::task::RawWakerVTable`.
    pub raw_waker_vtable: BundleTypeId,
}

/// Where each task future comes from (§5.5), indexed by [`TaskEntryId`]
/// (parallel to [`TaskTable::entries`]).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ProvenanceTable {
    pub entries: Vec<Provenance>,
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

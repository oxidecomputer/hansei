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
    pub debug_formats: BTreeMap<BundleTypeId, DisplayNode>,
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

    /// A selector that descends a run of members, outermost first.
    pub fn members(indices: &[u32]) -> Self {
        Selector(indices.iter().copied().map(Step::Member).collect())
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
    /// Follow a `(data, len)` string slice to its byte buffer and render it as
    /// a quoted, escaped UTF-8 string.
    ///
    /// `pointer` reaches the data-pointer word and `length` the byte length;
    /// reify reads `length` bytes from the target through the pointer.
    /// `capacity`, when present, reaches an owned buffer's capacity word (a
    /// borrowed `&str` omits it) and is validated to be at least the length. A
    /// null data pointer, an unreadable buffer, or non-UTF-8 bytes render an
    /// explicit marker in place of the string.
    Str {
        pointer: Selector,
        length: Selector,
        capacity: Option<Selector>,
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
    /// Render an inline octet array as an IPv4 or IPv6 address in standard
    /// notation.
    ///
    /// `octets` reaches an inline `[u8; 4]` or `[u8; 16]` array (an
    /// `Ipv4Addr`/`Ipv6Addr`'s only member) — the address version is inferred
    /// from the octet count, which is validated to be 4 or 16. Unlike `Str`
    /// and `Slice` this reads no pointer: the octets live in the value's own
    /// bytes, so it is a leaf that renders the bytes it lands on directly.
    IpAddr { octets: Selector },
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

impl TypeTable {
    /// Get a type definition by id.
    pub fn get(&self, id: BundleTypeId) -> Option<&TypeDef> {
        self.types.get(id.0 as usize)
    }

    /// The byte size of `id`, or `None` when it is not knowable: an `Opaque`
    /// whose size DWARF did not record, an array whose element size is itself
    /// unknown, or a cyclic element chain. Arrays are the one kind that has to
    /// recurse, so the walk carries a seen-set and terminates on any input.
    pub(crate) fn size_of(&self, id: BundleTypeId) -> Option<u64> {
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

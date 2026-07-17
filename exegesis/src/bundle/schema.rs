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
    /// sha256 of the whole ELF file.
    pub sha256: [u8; 32],
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

/// Declarative instructions for displaying a known type.
///
/// Member references are indices into the concrete [`TypeDef`]'s member
/// list. Exegesis resolves and validates them while it still has the source
/// DWARF's structured generic parameter information; consumers never match
/// type names or private field names.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum DebugFormat {
    /// Display one member as though it were the containing value.
    Transparent { member: u32 },
    /// Apply semantics for a known family of types.
    Known(KnownFormat),
}

/// Closed set of semantic formatters understood by reify.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum KnownFormat {
    /// Display an atomic's stored value. The path walks zero or more
    /// concrete struct/union members from the atomic to its value type.
    Atomic { value: Vec<u32> },
    /// Display a pointer value as a function address and symbol. Function
    /// pointers must never be followed as data pointers.
    FunctionPointer,
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
    /// Display the four function pointers in `core::task::RawWakerVTable`
    /// as symbols rather than following them as data pointers.
    RawWakerVTable {
        clone: u32,
        wake: u32,
        wake_by_ref: u32,
        drop: u32,
    },
    /// Display a `parking_lot::raw_mutex::RawMutex` as its decoded lock state
    /// rather than a raw atomic byte. `state` is the member path to the
    /// single-byte atomic; reify interprets parking_lot's fixed bit encoding
    /// (`LOCKED_BIT = 1`, `PARKED_BIT = 2`).
    RawMutex { state: Vec<u32> },
    /// Display a `tokio::sync::notify::Notify` with its `state` field decoded.
    /// `state` is the member path to the atomic `usize`; reify renders the
    /// struct normally but interprets that field as tokio's notification
    /// state (low two bits: idle/waiting/notified) plus the `notify_waiters`
    /// generation counter in the upper bits. The path's first element is the
    /// index of the `state` member within the struct.
    Notify { state: Vec<u32> },
    /// Display a `tokio::sync::batch_semaphore::Semaphore` with its `permits`
    /// field decoded. `permits` is the member path to the atomic `usize`;
    /// reify renders the struct normally but interprets that field as the
    /// available permit count (`value >> 1`) plus a closed flag (bit 0). The
    /// path's first element is the index of the `permits` member.
    Semaphore { permits: Vec<u32> },
    /// Display a `tokio::sync::mpsc::block::Block<T>` showing only the
    /// initialized slots of its inline `values` array. `ready_slots` is the
    /// member path to the header's readiness bitmap (bit `i` set means slot
    /// `i` holds a value); `values` is the member path to the
    /// `[MaybeUninit<T>; N]` array (its first element is the index of the
    /// `values` member, rendered specially). `element` is `T`, displayed in
    /// place of each initialized slot's raw representation.
    MpscBlock { ready_slots: Vec<u32>, values: Vec<u32>, element: BundleTypeId },
    /// Display the octets of an IPv4 or IPv6 address in standard notation.
    IpAddress { octets: u32 },
    /// Display the initialized elements of an `alloc::vec::Vec<T, A>`.
    Vec {
        pointer: Vec<u32>,
        length: Vec<u32>,
        capacity: Vec<u32>,
        element: BundleTypeId,
    },
    /// Display a `&str` as quoted, escaped UTF-8.
    Str { pointer: u32, length: u32 },
    /// Display an `alloc::string::String` as quoted, escaped UTF-8.
    String {
        pointer: Vec<u32>,
        length: Vec<u32>,
        capacity: Vec<u32>,
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
        root_node: Vec<u32>,
        height: u32,
        node: Vec<u32>,
        key: BundleTypeId,
        value: BundleTypeId,
        leaf: BundleTypeId,
        leaf_len: u32,
        leaf_keys: u32,
        leaf_values: u32,
        internal: BundleTypeId,
        internal_data: u32,
        internal_edges: u32,
        edge: Vec<u32>,
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
    Base { name: StrRef, size: u64, encoding: Encoding },
    /// A pointer or reference to another type.
    Pointer { name: Option<StrRef>, target: BundleTypeId },
    /// A fixed-length array.
    Array { elem: BundleTypeId, count: u64 },
    /// A struct (or tuple/closure environment — anything with plain members).
    Struct { name: StrRef, size: u64, members: Vec<MemberDef> },
    /// A union.
    Union { name: StrRef, size: u64, members: Vec<MemberDef> },
    /// A Rust enum: DWARF variant parts, represented faithfully including
    /// niche encodings.
    Enum { name: StrRef, size: u64, shape: VariantShape },
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

/// The variant structure of a Rust enum, mirroring DWARF variant parts
/// (not CTF's synthetic `__discr`/`__variants` encoding).
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
        let SymbolLookup::Unique(id) = self.lookup_id(symbol) else { return None };
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
        let SymbolLookup::Unique(id) = self.lookup_id(symbol) else { return None };
        Some(id)
    }
}

/// Strip the `.llvm.<decimal>` suffix LLVM appends to internalized copies of
/// a symbol. The suffix is path-sensitive across separate compilations and
/// must never participate in a join (see `docs/v0-mangling-spike.md`).
pub fn strip_llvm_suffix(symbol: &str) -> &str {
    match symbol.rfind(".llvm.") {
        Some(i) if symbol[i + ".llvm.".len()..].bytes().all(|b| b.is_ascii_digit())
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
/// These replace `dwarf2ctf -t` hand-feeding; extraction fails loudly if any
/// is missing from the debug binary's DWARF.
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

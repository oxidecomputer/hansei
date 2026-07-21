//! The extraction pipeline (`exegesis extract`, plan §7): turn a debug
//! binary's DWARF into a [`Bundle`].
//!
//! The pipeline has three phases:
//!
//! 1. **Seed discovery** (§7.1): one sweep over all subprograms finds the
//!    `tokio::runtime::task::raw` vtable-fn instantiations (grouped per
//!    `(T, S)` by the DIE references of their template parameters),
//!    `<T as Future>::poll` impls, and `core::ptr::drop_glue::<T>`
//!    instantiations; separate lookups resolve the infra types (§5.4) and
//!    the named statics.
//! 2. **Type binding** (§7.2): `Cell<T, S>` is recovered structurally from
//!    `dealloc`'s `NonNull<Cell<T, S>>` parameter (falling back to a
//!    namespace scan matched on template parameters — never on
//!    reconstructed name strings), and `Stage<T>` by walking the member
//!    graph from `Cell`.
//! 3. **Closure and emission** (§7.3): a worklist over DIE references
//!    converts every reachable type into a [`TypeDef`], interning strings
//!    and remapping DWARF offsets to dense [`BundleTypeId`]s. Anything
//!    unmodelable becomes an explicit `Opaque` entry and a stats counter —
//!    no silent omissions.

use crate::bundle::{
    BinaryIdent, BitField, Bundle, BundleTypeId, DebugFormat, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode, DynFutureTable, Field, FieldRender, FutureKind, InfraTypes, MemberDef, Meta,
    Provenance, ProvenanceTable, ScalarDecode, Selector, SourceLoc, StaticDef, StaticRole,
    StaticsTable, StrRef, StringInterner, TaskEntryId, TaskFutureEntry, TaskTable, TypeDef,
    TypeTable, VariantDef, VariantShape,
};
use std::num::NonZeroU8;

use crate::raw_types::{NsId, RawType, VariantShape as RawVariantShape};
use crate::symbols::normalized_value_index;
use crate::view::{DwView, Func, SourceLocView};
use crate::{DwReader, Encoding, TypeId};

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use tracing::{debug, warn};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::Path;

/// The task vtable functions (`tokio::runtime::task::raw`); any of their
/// symbols resolved from a target identifies the instantiation.
const VTABLE_FNS: [&str; 6] = [
    "poll",
    "dealloc",
    "try_read_output",
    "drop_join_handle_slow",
    "drop_abort_handle",
    "shutdown",
];

const TASK_RAW_NS: &str = "tokio::runtime::task::raw";
const TASK_CORE_NS: &str = "tokio::runtime::task::core";
const DROP_GLUE_NS: &str = "core::ptr";
const WAKER_NS: &str = "tokio::runtime::task::waker";
/// Demangled suffix of `<T as core::future::Future>::poll` impls.
const FUTURE_POLL_SUFFIX: &str = " as core::future::future::Future>::poll";

/// Placeholder name for type references that do not resolve to a parsed
/// DIE (e.g. `DW_TAG_subroutine_type` behind fn pointers).
const UNRESOLVED: &str = "<unresolved>";

/// Options for an extraction run.
#[derive(Default)]
pub struct ExtractOptions {
    /// Extra root types by fully-qualified name (`--include-type`).
    pub include_types: Vec<String>,
    /// Emit placeholders (and go on) when infra types or statics are
    /// missing, instead of failing.
    pub allow_missing_infra: bool,
    /// Provenance string recorded in the bundle's `Meta` (typically the
    /// extraction command line).
    pub extract_args: String,
}

/// Counters describing an extraction run. Anything the extractor skipped,
/// approximated, or could not resolve shows up here — the `Display` form
/// is the `--stats` output.
#[derive(Default, Debug)]
pub struct ExtractStats {
    /// Task-table entries, one per `(T, S)` instantiation.
    pub task_entries: usize,
    /// Mangled symbols keying the task table.
    pub task_symbols: usize,
    /// `task::raw::poll` instantiations found.
    pub poll_instantiations: usize,
    /// Vtable fns skipped because they carry no linkage name.
    pub vtable_missing_linkage: usize,
    /// `Cell<T, S>` recovered from `dealloc`'s `NonNull<Cell<T, S>>`
    /// parameter (tokio versions where `dealloc` takes the cell).
    pub cells_from_dealloc: usize,
    /// `Cell<T, S>` recovered by matching `task::core` instantiations on
    /// their `T`/`S` template-parameter DIE references (tokio 1.52's
    /// `dealloc` takes `NonNull<Header>`, so this is the common path).
    /// Both routes are structural; neither reconstructs name strings.
    pub cells_by_scan: usize,
    /// Entries whose `Cell` could not be found (emitted with an `Opaque`
    /// placeholder).
    pub cells_missing: usize,
    /// Entries whose `Stage<T>` could not be found.
    pub stages_missing: usize,
    /// Distinct future types in the dyn-future table.
    pub dyn_futures: usize,
    /// `<T as Future>::poll` symbols in the dyn-future table.
    pub dyn_poll_symbols: usize,
    /// `drop_glue::<T>` symbols matched to a dyn future type.
    pub dyn_glue_symbols: usize,
    /// `Future::poll` impls skipped because `T` could not be recovered
    /// from the `self: Pin<&mut T>` parameter.
    pub dyn_unresolved_self: usize,
    /// `Future::poll` impls skipped because the self type's DIE is a
    /// declaration without members (fully-inlined `Pin<P>` blanket impls;
    /// such types never back a `dyn Future` vtable).
    pub dyn_decl_only_self: usize,
    /// drop_glue symbols matched by the glue DIE's `drop_glue<T>` display
    /// name rather than a template-parameter DIE reference (release
    /// builds omit the parameter on out-of-line glue definitions).
    pub dyn_glue_by_name: usize,
    /// Infra types that were not found.
    pub infra_missing: Vec<String>,
    /// Statics that were not found.
    pub statics_missing: Vec<String>,
    /// Statics recovered from the symbol table because the DWARF carried no
    /// `DW_TAG_variable` DIE for them (§5.4 fallback, e.g. illumos builds).
    pub statics_from_symtab: usize,
    /// `--include-type` roots resolved.
    pub include_roots: usize,
    /// `--include-type` names that matched nothing.
    pub include_missing: Vec<String>,
    /// Candidate concrete trait-object types recovered from realized vtables
    /// in the debug executable.
    pub vtable_type_hints: usize,
    /// Concrete trait-object layouts added as bundle roots.
    pub vtable_type_roots: usize,
    /// Vtable type hints with no matching DWARF type and byte size.
    pub vtable_types_missing: usize,
    /// Vtable type hints that matched multiple distinct DWARF layouts.
    pub vtable_types_ambiguous: usize,
    /// Total types emitted into the bundle.
    pub types_emitted: usize,
    /// Emitted `Opaque` entries (placeholders included).
    pub opaque_types: usize,
    /// Type references that resolved to no parsed DIE (each becomes the
    /// shared `<unresolved>` opaque).
    pub unresolved_refs: usize,
    /// C-style enums missing a repr type (one was synthesized).
    pub cenum_synth_repr: usize,
    /// Task entries whose provenance carries declaration coordinates.
    pub provenance_located: usize,
}

impl fmt::Display for ExtractStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "task table:")?;
        writeln!(f, "  entries:                {}", self.task_entries)?;
        writeln!(f, "  symbol keys:            {}", self.task_symbols)?;
        writeln!(f, "  poll instantiations:    {}", self.poll_instantiations)?;
        writeln!(
            f,
            "  missing linkage names:  {}",
            self.vtable_missing_linkage
        )?;
        writeln!(f, "  cells via dealloc:      {}", self.cells_from_dealloc)?;
        writeln!(f, "  cells via scan:         {}", self.cells_by_scan)?;
        writeln!(f, "  cells missing:          {}", self.cells_missing)?;
        writeln!(f, "  stages missing:         {}", self.stages_missing)?;
        writeln!(f, "  with provenance:        {}", self.provenance_located)?;
        writeln!(f, "dyn futures:")?;
        writeln!(f, "  future types:           {}", self.dyn_futures)?;
        writeln!(f, "  poll symbols:           {}", self.dyn_poll_symbols)?;
        writeln!(f, "  drop_glue symbols:      {}", self.dyn_glue_symbols)?;
        writeln!(f, "  glue matched by name:   {}", self.dyn_glue_by_name)?;
        writeln!(f, "  unresolved self params: {}", self.dyn_unresolved_self)?;
        writeln!(f, "  decl-only self params:  {}", self.dyn_decl_only_self)?;
        writeln!(f, "types:")?;
        writeln!(f, "  emitted:                {}", self.types_emitted)?;
        writeln!(f, "  opaque:                 {}", self.opaque_types)?;
        writeln!(f, "  unresolved refs:        {}", self.unresolved_refs)?;
        writeln!(f, "  synthesized enum reprs: {}", self.cenum_synth_repr)?;
        writeln!(f, "vtable concrete types:")?;
        writeln!(f, "  hints:                  {}", self.vtable_type_hints)?;
        writeln!(f, "  rooted:                 {}", self.vtable_type_roots)?;
        writeln!(f, "  missing:                {}", self.vtable_types_missing)?;
        writeln!(
            f,
            "  ambiguous:              {}",
            self.vtable_types_ambiguous
        )?;
        writeln!(
            f,
            "include roots:            {} resolved",
            self.include_roots
        )?;
        for name in &self.include_missing {
            writeln!(f, "  MISSING include type:   {name}")?;
        }
        for name in &self.infra_missing {
            writeln!(f, "  MISSING infra type:     {name}")?;
        }
        for name in &self.statics_missing {
            writeln!(f, "  MISSING static:         {name}")?;
        }
        if self.statics_from_symtab > 0 {
            writeln!(f, "  statics via symtab:     {}", self.statics_from_symtab)?;
        }
        Ok(())
    }
}

/// Why an extraction failed.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to read the debug binary")]
    Io(#[from] std::io::Error),
    #[error("failed to parse the debug binary")]
    Object(#[from] object::read::Error),
    #[error("failed to read DWARF")]
    Dwarf(#[from] crate::Error),
    #[error(
        "no tokio task instantiations found — is this a tokio debug binary? \
         (--allow-missing-infra to extract anyway)"
    )]
    NoTaskFutures,
    #[error(
        "missing required tokio infrastructure ({0:?}) — \
         --allow-missing-infra to extract anyway"
    )]
    MissingInfra(Vec<String>),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct VtableTypeHint {
    name: String,
    size: u64,
}

/// Find concrete types named by vtables that are actually present in the
/// debug executable. A Rust vtable begins with drop glue, size, and align;
/// the first method follows that header. Function symbols identify the
/// concrete type, while size and align keep ordinary function tables from
/// becoming roots accidentally.
fn discover_vtable_types<'data, O: Object<'data>>(obj: &O) -> Vec<VtableTypeHint> {
    let mut text_addresses = BTreeSet::new();
    let mut concrete_by_address: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();

    for symbol in obj.symbols().chain(obj.dynamic_symbols()) {
        let address = symbol.address();
        if address == 0 {
            continue;
        }
        if symbol.kind() == SymbolKind::Text {
            text_addresses.insert(address);
        }
        let Some(name) = symbol.name().ok() else {
            continue;
        };
        let Ok(demangled) = rustc_demangle::try_demangle(strip(name)) else {
            continue;
        };
        let display = format!("{demangled:#}");
        let Some(concrete) = crate::symbols::concrete_type_from_vtable_symbol(&display) else {
            continue;
        };
        concrete_by_address
            .entry(address)
            .or_default()
            .insert(concrete.to_owned());
    }

    let mut hints = BTreeSet::new();
    for section in obj.sections() {
        if !matches!(
            section.kind(),
            SectionKind::Data | SectionKind::ReadOnlyData
        ) {
            continue;
        }
        let Ok(data) = section.uncompressed_data() else {
            continue;
        };
        scan_vtable_section(
            data.as_ref(),
            section.address(),
            obj.is_little_endian(),
            &text_addresses,
            &concrete_by_address,
            &mut hints,
        );
    }
    hints.into_iter().collect()
}

fn scan_vtable_section(
    data: &[u8],
    address: u64,
    little_endian: bool,
    text_addresses: &BTreeSet<u64>,
    concrete_by_address: &BTreeMap<u64, BTreeSet<String>>,
    hints: &mut BTreeSet<VtableTypeHint>,
) {
    let first = ((8 - (address & 7)) & 7) as usize;
    if data.len().saturating_sub(first) < 24 {
        return;
    }

    for offset in (first..=data.len() - 24).step_by(8) {
        let drop = read_object_word(&data[offset..offset + 8], little_endian);
        let size = read_object_word(&data[offset + 8..offset + 16], little_endian);
        let align = read_object_word(&data[offset + 16..offset + 24], little_endian);
        if align == 0 || !align.is_power_of_two() || align > (1 << 30) {
            continue;
        }
        if drop != 0 && !text_addresses.contains(&drop) {
            continue;
        }

        let mut concrete = BTreeSet::new();
        if let Some(names) = concrete_by_address.get(&drop) {
            concrete.extend(names.iter().cloned());
        }
        if let Some(method_bytes) = data.get(offset + 24..offset + 32) {
            let method = read_object_word(method_bytes, little_endian);
            if let Some(names) = concrete_by_address.get(&method) {
                concrete.extend(names.iter().cloned());
            }
        }
        hints.extend(
            concrete
                .into_iter()
                .map(|name| VtableTypeHint { name, size }),
        );
    }
}

fn read_object_word(bytes: &[u8], little_endian: bool) -> u64 {
    let bytes: [u8; 8] = bytes.try_into().expect("object word must be eight bytes");
    if little_endian {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    }
}

/// Below this many types, indexing them by name is not worth spawning threads.
const VTABLE_INDEX_PARALLEL_THRESHOLD: usize = 4096;

/// Index a slice of type ids by their normalized fully-qualified name. Pulled
/// out so [`resolve_vtable_type_hints`] can run it on several threads and merge.
fn vtable_name_index(
    reader: &DwReader<'_>,
    ids: &[TypeId],
) -> foldhash::HashMap<String, Vec<(TypeId, u64)>> {
    let mut by_name: foldhash::HashMap<String, Vec<(TypeId, u64)>> = foldhash::HashMap::default();
    for &id in ids {
        let Some(name) = fq_name(reader, id) else {
            continue;
        };
        let Some(size) = raw_type_size(reader, id) else {
            continue;
        };
        by_name
            .entry(crate::symbols::normalized_rust_type_name(&name))
            .or_default()
            .push((id, size));
    }
    by_name
}

fn resolve_vtable_type_hints(
    reader: &DwReader<'_>,
    hints: &[VtableTypeHint],
    stats: &mut ExtractStats,
) -> BTreeSet<TypeId> {
    // Index every canonical type by its normalized fully-qualified name.
    // Computing those names -- a namespace walk, a format, and a normalization
    // pass per type -- over tens of thousands of types dominates emission and
    // is read-only, so fan it out and merge the per-thread shards.
    let ids: Vec<TypeId> = reader.canonical_types().map(|(id, _)| id).collect();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let by_name = if threads <= 1 || ids.len() < VTABLE_INDEX_PARALLEL_THRESHOLD {
        vtable_name_index(reader, &ids)
    } else {
        let chunk = ids.len().div_ceil(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = ids
                .chunks(chunk)
                .map(|c| scope.spawn(move || vtable_name_index(reader, c)))
                .collect();
            let mut merged: foldhash::HashMap<String, Vec<(TypeId, u64)>> =
                foldhash::HashMap::default();
            for handle in handles {
                for (name, mut entries) in handle.join().expect("vtable-index thread panicked") {
                    merged.entry(name).or_default().append(&mut entries);
                }
            }
            merged
        })
    };

    stats.vtable_type_hints = hints.len();
    let mut roots = BTreeSet::new();
    for hint in hints {
        let name = crate::symbols::normalized_rust_type_name(&hint.name);
        let Some(candidates) = by_name.get(&name) else {
            stats.vtable_types_missing += 1;
            continue;
        };
        let candidates: BTreeSet<_> = candidates
            .iter()
            .filter(|(_, size)| *size == hint.size)
            .map(|(id, _)| *id)
            .collect();
        let mut candidates = candidates.into_iter();
        match (candidates.next(), candidates.next()) {
            (Some(id), None) => {
                roots.insert(id);
            }
            (None, _) => stats.vtable_types_missing += 1,
            (Some(_), Some(_)) => stats.vtable_types_ambiguous += 1,
        }
    }
    stats.vtable_type_roots = roots.len();
    roots
}

fn raw_type_size(reader: &DwReader<'_>, id: TypeId) -> Option<u64> {
    match reader.canonical_type(id)? {
        RawType::Base(base) => Some(base.size),
        RawType::Pointer(_) => Some(8),
        RawType::Enum(en) => Some(en.size),
        RawType::Struct(st) => Some(st.size),
        RawType::Union(union) => Some(union.size),
        RawType::Array(array) => {
            raw_type_size(reader, array.elem_type_id)?.checked_mul(array.count)
        }
    }
}

/// Extract a bundle from a debug binary (or any DWARF-bearing object).
pub fn extract_file(path: &Path, opts: &ExtractOptions) -> Result<(Bundle, ExtractStats)> {
    let f = std::fs::File::open(path)?;
    let obj_bytes = std::sync::Arc::new(unsafe { memmap2::Mmap::map(&f) }?);

    // Hash the whole ELF for the bundle's binary identity on a background
    // thread. BLAKE3 over a multi-gigabyte binary is pure overhead on the
    // critical path, but it overlaps entirely with the DWARF parse below.
    // The thread keeps its own `Arc` handle to the mapping, so it is
    // independent of the parse's borrows of the same bytes.
    let blake3_handle = {
        let obj_bytes = std::sync::Arc::clone(&obj_bytes);
        std::thread::spawn(move || blake3::hash(&obj_bytes[..]))
    };

    let obj = object::File::parse(&obj_bytes[..])?;
    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> std::result::Result<
        std::borrow::Cow<'_, [u8]>,
        Box<dyn std::error::Error>,
    > {
        use object::ObjectSection;
        Ok(match obj.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => std::borrow::Cow::Borrowed(&[]),
        })
    };
    let borrow_section =
        |section| gimli::EndianSlice::new(std::borrow::Cow::as_ref(section), endian);

    let dwarf_sections = gimli::DwarfSections::load(&load_section)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let dwarf = dwarf_sections.borrow(borrow_section);

    // Gathering the symbol tables and the vtable-type hints depends only on
    // `obj`, not on the DWARF, so run it on a helper thread that overlaps the
    // (parallel) parse. Serially it is ~0.4s of scanning `.symtab`/`.dynsym`
    // after the read has already finished; overlapped, it is free.
    let (reader, symbols, vtable_types) = std::thread::scope(|scope| {
        let aux = scope.spawn(|| {
            // Named statics can be absent from `.debug_info` yet present in the
            // symbol table (§5.4): illumos release builds emit no
            // `DW_TAG_variable` DIE for tokio/std dependency statics such as
            // `WAKER_VTABLE`, but keep the symbol in `.symtab`/`.dynsym`. Gather
            // both tables so `find_statics` can fall back to a mangled-name match.
            let symbols: Vec<&str> = obj
                .symbols()
                .chain(obj.dynamic_symbols())
                .filter_map(|s| s.name().ok())
                .collect();
            let vtable_types = discover_vtable_types(&obj);
            (symbols, vtable_types)
        });
        let reader = DwReader::read_types(&dwarf, Default::default())?;
        let (symbols, vtable_types) = aux.join().expect("symbol-gathering thread panicked");
        Ok::<_, Error>((reader, symbols, vtable_types))
    })?;

    let view = reader.view();

    let ident = BinaryIdent {
        basename: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        build_id: obj.build_id().ok().flatten().map(|b| b.to_vec()),
        blake3: blake3_handle
            .join()
            .expect("BLAKE3 hashing thread panicked")
            .into(),
    };

    extract_from_view_with_vtable_types(&view, &symbols, ident, opts, &vtable_types)
}

/// Extract a bundle from an already-parsed DWARF view. Split from
/// [`extract_file`] so tests can drive extraction on in-memory objects.
pub fn extract_from_view(
    view: &DwView<'_>,
    symbols: &[&str],
    ident: BinaryIdent,
    opts: &ExtractOptions,
) -> Result<(Bundle, ExtractStats)> {
    extract_from_view_with_vtable_types(view, symbols, ident, opts, &[])
}

/// Below this many subprograms, sweeping them by hand beats spawning threads.
const SWEEP_PARALLEL_THRESHOLD: usize = 4096;

/// Contributions gathered by phase 1's subprogram sweep (§7.1). Accumulated per
/// worker and merged so the sweep — dominated by demangling every `poll*`
/// symbol — can run in parallel.
#[derive(Default)]
struct Sweep {
    /// (T, S) → accumulating seed.
    seeds: BTreeMap<(TypeId, TypeId), TaskSeed>,
    /// Canonical T → mangled `<T as Future>::poll` symbols.
    fut_polls: BTreeMap<TypeId, BTreeSet<String>>,
    /// Canonical T → mangled `drop_glue::<T>` symbols.
    drop_glues: BTreeMap<TypeId, BTreeSet<String>>,
    /// `drop_glue<T>` display name's inner text → symbols, for glue DIEs
    /// without a template-parameter reference.
    glue_by_name: BTreeMap<String, BTreeSet<String>>,
    /// Coroutine env → its resume fn's declaration coordinates.
    resume_locs: BTreeMap<TypeId, OwnedLoc>,
    vtable_missing_linkage: usize,
    dyn_decl_only_self: usize,
    dyn_unresolved_self: usize,
}

impl Sweep {
    /// Fold another worker's contributions in. Called in chunk (i.e. source)
    /// order, so the "first wins" fields resolve exactly as a serial sweep.
    fn merge(&mut self, other: Sweep) {
        for (key, seed) in other.seeds {
            let dst = self.seeds.entry(key).or_default();
            dst.symbols.extend(seed.symbols);
            dst.poll_symbols.extend(seed.poll_symbols);
            if dst.dealloc_param.is_none() {
                dst.dealloc_param = seed.dealloc_param;
            }
            if dst.poll_func_loc.is_none() {
                dst.poll_func_loc = seed.poll_func_loc;
            }
        }
        for (t, syms) in other.fut_polls {
            self.fut_polls.entry(t).or_default().extend(syms);
        }
        for (t, syms) in other.drop_glues {
            self.drop_glues.entry(t).or_default().extend(syms);
        }
        for (name, syms) in other.glue_by_name {
            self.glue_by_name.entry(name).or_default().extend(syms);
        }
        for (t, loc) in other.resume_locs {
            self.resume_locs.entry(t).or_insert(loc);
        }
        self.vtable_missing_linkage += other.vtable_missing_linkage;
        self.dyn_decl_only_self += other.dyn_decl_only_self;
        self.dyn_unresolved_self += other.dyn_unresolved_self;
    }
}

/// Sweep every subprogram into task seeds, dyn-future poll symbols, drop glue,
/// and coroutine resume locations (§7.1). The per-function classification is
/// read-only over the reader and independent, so it is fanned out across a
/// thread pool and the per-worker [`Sweep`]s merged in source order.
fn sweep_functions(view: &DwView<'_>, raw_ns: Option<NsId>, glue_ns: Option<NsId>) -> Sweep {
    let reader = view.collector();
    let funcs: Vec<Func> = view.functions().map(|(_, f)| f).collect();

    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads <= 1 || funcs.len() < SWEEP_PARALLEL_THRESHOLD {
        let mut out = Sweep::default();
        for func in &funcs {
            sweep_function(reader, raw_ns, glue_ns, func, &mut out);
        }
        return out;
    }

    let chunk = funcs.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let handles: Vec<_> = funcs
            .chunks(chunk)
            .map(|chunk| {
                scope.spawn(move || {
                    let mut out = Sweep::default();
                    for func in chunk {
                        sweep_function(reader, raw_ns, glue_ns, func, &mut out);
                    }
                    out
                })
            })
            .collect();
        let mut merged = Sweep::default();
        for handle in handles {
            merged.merge(handle.join().expect("function-sweep thread panicked"));
        }
        merged
    })
}

/// Classify one subprogram into `out`: a task vtable fn, drop glue, a coroutine
/// resume fn, or a `Future::poll` impl.
fn sweep_function(
    reader: &DwReader<'_>,
    raw_ns: Option<NsId>,
    glue_ns: Option<NsId>,
    func: &Func<'_>,
    out: &mut Sweep,
) {
    let Some(name) = func.name() else { return };

    if func.namespace_id() == raw_ns && raw_ns.is_some() {
        let Some(vtable_fn) = VTABLE_FNS
            .iter()
            .find(|v| name.strip_prefix(*v).is_some_and(|r| r.starts_with('<')))
        else {
            return;
        };
        let Some(linkage) = func.linkage_name() else {
            out.vtable_missing_linkage += 1;
            return;
        };
        let mut t = None;
        let mut s = None;
        for p in func.template_params() {
            match p.name() {
                Some("T") => t = Some(reader.canonicalize(p.type_id())),
                Some("S") => s = Some(reader.canonicalize(p.type_id())),
                _ => {}
            }
        }
        let (Some(t), Some(s)) = (t, s) else {
            debug!("vtable fn without T/S template params: {name}");
            return;
        };
        let seed = out.seeds.entry((t, s)).or_default();
        seed.symbols.insert(strip(linkage).to_owned());
        if *vtable_fn == "poll" {
            seed.poll_symbols.insert(strip(linkage).to_owned());
            if seed.poll_func_loc.is_none() {
                seed.poll_func_loc = func.source_loc().map(|l| owned_loc(&l));
            }
        }
        if *vtable_fn == "dealloc" && seed.dealloc_param.is_none() {
            seed.dealloc_param = func.params().next().and_then(|p| p.raw().type_id);
        }
    } else if func.namespace_id() == glue_ns && glue_ns.is_some() && name.starts_with("drop_glue<")
    {
        let Some(linkage) = func.linkage_name() else {
            return;
        };
        let params: Vec<_> = func.template_params().collect();
        if let [p] = params.as_slice() {
            out.drop_glues
                .entry(reader.canonicalize(p.type_id()))
                .or_default()
                .insert(strip(linkage).to_owned());
        } else if let Some(inner) = name
            .strip_prefix("drop_glue<")
            .and_then(|r| r.strip_suffix('>'))
        {
            out.glue_by_name
                .entry(inner.to_owned())
                .or_default()
                .insert(strip(linkage).to_owned());
        }
    } else if name.starts_with("{async_fn#")
        || name.starts_with("{async_block#")
        || name.starts_with("{closure#")
    {
        // Coroutine resume functions are the compiler-generated
        // `<env as Future>::poll` bodies — the symbols `dyn Future` vtables
        // actually point at for async fn/block awaitees. Recognized by shape:
        // `fn(Pin<&mut T>) -> Poll<…>` with a coroutine-env self type.
        let Some(linkage) = func.linkage_name() else {
            return;
        };
        let poll_shaped = func
            .return_type()
            .and_then(|t| t.name())
            .is_some_and(|n| n.starts_with("Poll<"));
        if !poll_shaped {
            return;
        }
        match future_poll_self_type(reader, func) {
            Ok(t) if is_coroutine_env(reader, t) => {
                out.fut_polls
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
                if let Some(loc) = func.source_loc() {
                    out.resume_locs.entry(t).or_insert_with(|| owned_loc(&loc));
                }
            }
            _ => {}
        }
    } else if let Some(linkage) = func.linkage_name() {
        // `<T as Future>::poll` impls live in `{impl#N}` namespaces; the trait
        // path is only visible in the mangled name.
        if !name.starts_with("poll") {
            return;
        }
        let demangled = format!("{:#}", rustc_demangle::demangle(linkage));
        if !demangled.ends_with(FUTURE_POLL_SUFFIX) {
            return;
        }
        match future_poll_self_type(reader, func) {
            Ok(t) => {
                out.fut_polls
                    .entry(t)
                    .or_default()
                    .insert(strip(linkage).to_owned());
            }
            Err(SelfRecovery::DeclOnly) => {
                // Fully-inlined blanket impls (`Pin<P>`, `&mut F`) whose self
                // type DIE is a bare declaration. Those types never back a
                // `dyn Future` vtable, so nothing is lost.
                debug!("declaration-only Future::poll self type: {demangled}");
                out.dyn_decl_only_self += 1;
            }
            Err(SelfRecovery::Unresolved) => {
                debug!("cannot recover T from Future::poll self param: {demangled}");
                out.dyn_unresolved_self += 1;
            }
        }
    }
}

fn extract_from_view_with_vtable_types(
    view: &DwView<'_>,
    symbols: &[&str],
    ident: BinaryIdent,
    opts: &ExtractOptions,
    vtable_types: &[VtableTypeHint],
) -> Result<(Bundle, ExtractStats)> {
    let mut stats = ExtractStats::default();
    let reader = view.collector();

    // Namespace ids for the sweep's membership tests. A missing namespace
    // (e.g. a binary without tokio) simply yields no matches.
    let raw_ns = view.find_ns(TASK_RAW_NS).map(|n| n.id());
    let core_ns = view.find_ns(TASK_CORE_NS).map(|n| n.id());
    let glue_ns = view.find_ns(DROP_GLUE_NS).map(|n| n.id());

    // --- Phase 1: one sweep over all subprograms (§7.1). ---
    let Sweep {
        seeds,
        fut_polls,
        drop_glues,
        glue_by_name,
        resume_locs,
        vtable_missing_linkage,
        dyn_decl_only_self,
        dyn_unresolved_self,
    } = sweep_functions(view, raw_ns, glue_ns);
    stats.vtable_missing_linkage += vtable_missing_linkage;
    stats.dyn_decl_only_self += dyn_decl_only_self;
    stats.dyn_unresolved_self += dyn_unresolved_self;

    if seeds.is_empty() && !opts.allow_missing_infra {
        return Err(Error::NoTaskFutures);
    }

    // --- Phase 2: per-instantiation type binding (§7.2). ---

    // Fallback index: Cell instantiations in task::core, matched on their
    // own template parameters.
    let mut cell_scan: Vec<(TypeId, TypeId, TypeId)> = Vec::new();
    if core_ns.is_some() {
        for (id, raw) in reader.canonical_types() {
            let RawType::Struct(st) = raw else { continue };
            if st.namespace != core_ns {
                continue;
            }
            let name = st.name.map(|n| reader.strings.get(n)).unwrap_or_default();
            if !name.starts_with("Cell<") {
                continue;
            }
            let mut t = None;
            let mut s = None;
            for p in st.template_params.iter() {
                match p.name.map(|n| reader.strings.get(n)) {
                    Some("T") => t = Some(reader.canonicalize(p.type_id)),
                    Some("S") => s = Some(reader.canonicalize(p.type_id)),
                    _ => {}
                }
            }
            if let (Some(t), Some(s)) = (t, s) {
                cell_scan.push((id, t, s));
            }
        }
    }

    struct BoundTask {
        future: TypeId,
        scheduler: TypeId,
        cell: Option<TypeId>,
        stage: Option<TypeId>,
        symbols: BTreeSet<String>,
        poll_symbols: BTreeSet<String>,
        poll_func_loc: Option<OwnedLoc>,
    }

    let mut bound: Vec<BoundTask> = Vec::new();
    for (&(t, s), seed) in &seeds {
        let cell = seed
            .dealloc_param
            .and_then(|p| cell_from_dealloc_param(reader, core_ns, p))
            .inspect(|_| stats.cells_from_dealloc += 1)
            .or_else(|| {
                let found = cell_scan
                    .iter()
                    .find(|&&(_, ct, cs)| ct == t && cs == s)
                    .map(|&(id, _, _)| id);
                if found.is_some() {
                    stats.cells_by_scan += 1;
                }
                found
            });
        if cell.is_none() {
            warn!("no Cell<T, S> instantiation found for a task future");
            stats.cells_missing += 1;
        }

        let stage = cell.and_then(|c| find_stage(reader, core_ns, c));
        if cell.is_some() && stage.is_none() {
            stats.stages_missing += 1;
        }

        bound.push(BoundTask {
            future: t,
            scheduler: s,
            cell,
            stage,
            symbols: seed.symbols.clone(),
            poll_symbols: seed.poll_symbols.clone(),
            poll_func_loc: seed.poll_func_loc.clone(),
        });
    }

    // Dyn-future table: every `<T as Future>::poll` impl, plus the
    // matching `drop_glue::<T>` instantiations (§5.3). drop_glue exists
    // for *every* droppable type, so only glue for known future types is
    // recorded. Glue is matched by the template-parameter DIE reference
    // when the glue DIE carries one, else by its `drop_glue<T>` display
    // name against T's fully-qualified name.
    let mut dyn_by_symbol: BTreeMap<String, TypeId> = BTreeMap::new();
    for (&t, symbols) in &fut_polls {
        for sym in symbols {
            dyn_by_symbol.insert(sym.clone(), t);
            stats.dyn_poll_symbols += 1;
        }
        if let Some(glue) = drop_glues.get(&t) {
            for sym in glue {
                dyn_by_symbol.insert(sym.clone(), t);
                stats.dyn_glue_symbols += 1;
            }
        } else if let Some(glue) = fq_name(reader, t).and_then(|n| glue_by_name.get(&n)) {
            for sym in glue {
                dyn_by_symbol.insert(sym.clone(), t);
                stats.dyn_glue_symbols += 1;
                stats.dyn_glue_by_name += 1;
            }
        }
    }
    stats.dyn_futures = fut_polls.len();

    // Infra types (§5.4) and statics.
    let infra_paths: [(&str, &str); 8] = [
        ("header", "tokio::runtime::task::core::Header"),
        ("vtable", "tokio::runtime::task::raw::Vtable"),
        ("trailer", "tokio::runtime::task::core::Trailer"),
        ("context", "tokio::runtime::context::Context"),
        ("scheduler_handle", "tokio::runtime::scheduler::Handle"),
        (
            "mt_handle",
            "tokio::runtime::scheduler::multi_thread::handle::Handle",
        ),
        ("location", "core::panic::location::Location"),
        ("raw_waker_vtable", "core::task::wake::RawWakerVTable"),
    ];
    let mut infra_ids: Vec<Option<TypeId>> = Vec::new();
    for (_, path) in infra_paths {
        let ids = view.find_all_ids(path);
        if ids.is_empty() {
            stats.infra_missing.push(path.to_owned());
            infra_ids.push(None);
        } else {
            infra_ids.push(Some(reader.canonicalize(ids[0])));
        }
    }

    let statics = find_statics(view, symbols, &mut stats);

    if !opts.allow_missing_infra
        && (!stats.infra_missing.is_empty() || !stats.statics_missing.is_empty())
    {
        let mut missing = stats.infra_missing.clone();
        missing.extend(stats.statics_missing.iter().cloned());
        return Err(Error::MissingInfra(missing));
    }

    // Extra roots.
    let mut include_ids: Vec<TypeId> = Vec::new();
    for name in &opts.include_types {
        let ids = view.find_all_ids(name);
        if ids.is_empty() {
            stats.include_missing.push(name.clone());
        } else {
            stats.include_roots += ids.len();
            include_ids.extend(ids.iter().map(|&id| reader.canonicalize(id)));
        }
    }

    let vtable_type_ids = resolve_vtable_type_hints(reader, vtable_types, &mut stats);

    // --- Phase 3: transitive closure and emission (§7.3). ---

    let mut em = Emitter::new(reader);

    let mut entries: Vec<TaskFutureEntry> = Vec::new();
    let mut provenance: Vec<Provenance> = Vec::new();
    let mut by_symbol: BTreeMap<String, TaskEntryId> = BTreeMap::new();
    let mut fingerprint: BTreeSet<String> = BTreeSet::new();

    for task in &bound {
        let entry_id = TaskEntryId(entries.len() as u32);
        let future = em.emit(task.future);
        let display = em.fq_name_of(task.future);
        let display_name = em.interner.intern(&display);
        let cell = match task.cell {
            Some(c) => em.emit(c),
            None => em.placeholder("<missing: Cell>"),
        };
        let stage = match task.stage {
            Some(st) => em.emit(st),
            None => em.placeholder("<missing: Stage>"),
        };
        let scheduler = em.emit(task.scheduler);

        entries.push(TaskFutureEntry {
            future,
            cell,
            stage,
            scheduler,
            display_name,
        });
        provenance.push(classify_future(
            reader,
            view,
            task.future,
            resume_locs.get(&task.future),
            &mut em,
            &mut stats,
        ));

        for sym in &task.symbols {
            by_symbol.insert(sym.clone(), entry_id);
        }
        fingerprint.extend(task.poll_symbols.iter().cloned());
        stats.poll_instantiations += task.poll_symbols.len();
    }
    stats.task_entries = entries.len();
    stats.task_symbols = by_symbol.len();

    let mut dyn_table: BTreeMap<String, BundleTypeId> = BTreeMap::new();
    for (sym, t) in &dyn_by_symbol {
        dyn_table.insert(sym.clone(), em.emit(*t));
    }

    let infra_bundle_ids: Vec<BundleTypeId> = infra_ids
        .iter()
        .zip(infra_paths.iter())
        .map(|(id, (_, path))| match id {
            Some(id) => em.emit(*id),
            None => em.placeholder(&format!("<missing: {path}>")),
        })
        .collect();

    for id in include_ids {
        em.emit(id);
    }
    for id in vtable_type_ids {
        em.emit(id);
    }

    // Meta.
    let producer = reader
        .producer
        .map(|id| reader.strings.get(id))
        .unwrap_or_default();
    let rustc_version = rustc_version_of(producer);
    let tokio_version = bound
        .iter()
        .filter_map(|t| t.poll_func_loc.as_ref())
        .find_map(tokio_version_of);

    let meta = Meta {
        format_version: crate::bundle::FORMAT_VERSION,
        rustc_version,
        tokio_version,
        debug_binary: ident,
        extract_args: opts.extract_args.clone(),
        symbol_fingerprint: fingerprint.into_iter().collect(),
    };

    stats.unresolved_refs = em.unresolved_refs;
    stats.cenum_synth_repr = em.cenum_synth_repr;
    let (types, strings, opaque_count) = em.finish();
    stats.types_emitted = types.types.len();
    stats.opaque_types = opaque_count;

    let task_normalized = normalized_value_index(&by_symbol);
    let dyn_normalized = normalized_value_index(&dyn_table);
    let bundle = Bundle {
        meta,
        strings,
        types,
        tasks: TaskTable {
            by_symbol,
            by_normalized_symbol: task_normalized,
            entries,
        },
        dyn_futures: DynFutureTable {
            by_symbol: dyn_table,
            by_normalized_symbol: dyn_normalized,
        },
        statics: StaticsTable { entries: statics },
        infra: InfraTypes {
            header: infra_bundle_ids[0],
            vtable: infra_bundle_ids[1],
            trailer: infra_bundle_ids[2],
            context: infra_bundle_ids[3],
            scheduler_handle: infra_bundle_ids[4],
            mt_handle: infra_bundle_ids[5],
            location: infra_bundle_ids[6],
            raw_waker_vtable: infra_bundle_ids[7],
        },
        provenance: ProvenanceTable {
            entries: provenance,
        },
    };

    Ok((bundle, stats))
}

/// Accumulates the vtable fns of one `(T, S)` instantiation during the
/// subprogram sweep.
#[derive(Default)]
struct TaskSeed {
    symbols: BTreeSet<String>,
    poll_symbols: BTreeSet<String>,
    dealloc_param: Option<TypeId>,
    poll_func_loc: Option<OwnedLoc>,
}

/// An owned copy of a source location.
#[derive(Clone, Debug)]
struct OwnedLoc {
    file: Option<String>,
    dir: Option<String>,
    line: Option<u64>,
}

fn owned_loc(l: &SourceLocView<'_>) -> OwnedLoc {
    OwnedLoc {
        file: l.file().map(str::to_owned),
        dir: l.dir().map(str::to_owned),
        line: l.line().map(|n| n.get()),
    }
}

/// Strip a `.llvm.<decimal>` suffix; symbol-table keys are stored
/// unsuffixed (§5.3). DWARF linkage names are unsuffixed in practice, so
/// this is insurance.
fn strip(symbol: &str) -> &str {
    crate::bundle::strip_llvm_suffix(symbol)
}

/// Recover `Cell<T, S>` from `dealloc`'s first parameter
/// (`NonNull<Cell<T, S>>` → member `pointer` → pointee).
fn cell_from_dealloc_param(
    reader: &DwReader<'_>,
    core_ns: Option<NsId>,
    param: TypeId,
) -> Option<TypeId> {
    let RawType::Struct(non_null) = reader.canonical_type(param)? else {
        return None;
    };
    let ptr_member = non_null.members.first()?;
    let RawType::Pointer(p) = reader.canonical_type(ptr_member.type_id)? else {
        return None;
    };
    let cell_id = reader.canonicalize(p.target_type_id);
    let RawType::Struct(cell) = reader.canonical_type(cell_id)? else {
        return None;
    };
    let name = cell.name.map(|n| reader.strings.get(n)).unwrap_or_default();
    (cell.namespace == core_ns && name.starts_with("Cell<")).then_some(cell_id)
}

/// Find `Stage<T>` by walking the member graph from `Cell<T, S>`
/// (`Cell.core.stage.stage.value` in current tokio, but discovered
/// structurally: the first enum named `Stage<…>` in `task::core`).
fn find_stage(reader: &DwReader<'_>, core_ns: Option<NsId>, cell: TypeId) -> Option<TypeId> {
    let mut queue = VecDeque::from([(cell, 0usize)]);
    let mut seen = BTreeSet::new();
    while let Some((id, depth)) = queue.pop_front() {
        if depth > 8 || !seen.insert(id) {
            continue;
        }
        match reader.canonical_type(id)? {
            RawType::Enum(e) => {
                let name = e.name.map(|n| reader.strings.get(n)).unwrap_or_default();
                if e.namespace == core_ns && name.starts_with("Stage<") {
                    return Some(reader.canonicalize(id));
                }
            }
            RawType::Struct(st) => {
                for m in st.members.iter() {
                    queue.push_back((reader.canonicalize(m.type_id), depth + 1));
                }
            }
            RawType::Union(u) => {
                for m in u.members.iter() {
                    queue.push_back((reader.canonicalize(m.type_id), depth + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Why `T` could not be recovered from a poll fn's self parameter.
enum SelfRecovery {
    /// The `Pin<…>` self type's DIE is a declaration with no members.
    DeclOnly,
    /// Anything else: missing parameter, unexpected shape.
    Unresolved,
}

/// Recover `T` from a `<T as Future>::poll` impl's `self: Pin<&mut T>`
/// parameter, as a DIE reference.
fn future_poll_self_type(
    reader: &DwReader<'_>,
    func: &Func<'_>,
) -> std::result::Result<TypeId, SelfRecovery> {
    let unresolved = SelfRecovery::Unresolved;
    let param = func.params().next().ok_or(SelfRecovery::Unresolved)?;
    let pin_id = param.raw().type_id.ok_or(SelfRecovery::Unresolved)?;
    let Some(RawType::Struct(pin)) = reader.canonical_type(pin_id) else {
        return Err(unresolved);
    };
    let name = pin.name.map(|n| reader.strings.get(n)).unwrap_or_default();
    if !name.starts_with("Pin<") {
        return Err(unresolved);
    }
    let inner = pin.members.first().ok_or(SelfRecovery::DeclOnly)?;
    let Some(RawType::Pointer(p)) = reader.canonical_type(inner.type_id) else {
        return Err(unresolved);
    };
    Ok(reader.canonicalize(p.target_type_id))
}

/// Is this type a compiler-generated coroutine environment?
fn is_coroutine_env(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(raw) = reader.canonical_type(id) else {
        return false;
    };
    raw.name()
        .map(|n| reader.strings.get(n))
        .is_some_and(|n| n.starts_with("{async_fn_env#") || n.starts_with("{async_block_env#"))
}

/// The fully-qualified name of a named type, if it has one.
fn fq_name(reader: &DwReader<'_>, id: TypeId) -> Option<String> {
    let raw = reader.canonical_type(id)?;
    let name = raw.name().map(|n| reader.strings.get(n))?;
    Some(match raw.namespace() {
        Some(ns) => format!("{}::{name}", ns_path(reader, ns)),
        None => name.to_owned(),
    })
}

/// The `a::b::c` path of a namespace.
fn ns_path(reader: &DwReader<'_>, ns: NsId) -> String {
    let mut segs = Vec::new();
    let mut cur = Some(ns);
    while let Some(id) = cur {
        let entry = reader.namespaces.get(id);
        segs.push(reader.strings.get(entry.name));
        cur = entry.parent;
    }
    segs.reverse();
    segs.join("::")
}

/// Recognize types whose source-level Debug representation is simpler than
/// their private storage layout. Matching happens here, while structured
/// generic parameters are still available; the bundle records only resolved
/// member indices.
fn known_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    dyn_pointer_debug_format(reader, id)
        .or_else(|| raw_waker_vtable_debug_format(reader, id))
        .or_else(|| function_pointer_debug_format(reader, id))
        .or_else(|| ip_address_debug_format(reader, id))
        .or_else(|| str_debug_format(reader, id))
        .or_else(|| string_debug_format(reader, id))
        // RawMutex, Semaphore, WatchState, and MpscRx carry a `ScalarDecode`
        // whose labels must be interned; they are built in `Emitter::emit`,
        // which holds the string interner, rather than in this chain.
        .or_else(|| mpsc_block_debug_format(reader, id))
        .or_else(|| unsafe_cell_debug_format(reader, id))
        .or_else(|| loom_unsafe_cell_debug_format(reader, id))
        .or_else(|| loom_atomic_debug_format(reader, id))
        .or_else(|| loom_parking_lot_debug_format(reader, id))
        .or_else(|| unique_debug_format(reader, id))
        .or_else(|| non_null_debug_format(reader, id))
        .or_else(|| usize_no_high_bit_debug_format(reader, id))
        .or_else(|| nonzero_debug_format(reader, id))
        .or_else(|| nonzero_inner_debug_format(reader, id))
        .or_else(|| atomic_debug_format(reader, id))
        // Least specific: a bare scalar newtype falls through to here only if
        // no semantic formatter above claimed it.
        .or_else(|| scalar_newtype_debug_format(reader, id))
}

/// A tuple newtype wrapping a single scalar (`Version(usize)`, `Epoch(u64)`,
/// an id, …) is displayed as that inner value. The scalar must fill the whole
/// struct (any other members are zero-sized), so this only ever collapses a
/// genuine wrapper, never a struct that also carries data. Semantic wrappers
/// (atomics, `NonZero`, …) are matched by earlier, more specific formatters.
fn scalar_newtype_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let (index, member) = st.members.iter().enumerate().find(|(_, member)| {
        member.offset == 0 && member.name.map(|name| reader.strings.get(name)) == Some("__0")
    })?;
    let RawType::Base(base) = reader.canonical_type(member.type_id)? else {
        return None;
    };
    if base.size == 0 || st.size != base.size {
        return None;
    }
    Some(DebugFormat::Transparent {
        member: Selector::member(index as u32),
    })
}

#[derive(Clone, Debug)]
struct RawBTreeMapFormat {
    root: u32,
    length: u32,
    root_node: Vec<u32>,
    height: u32,
    node: Vec<u32>,
    key: TypeId,
    value: TypeId,
    leaf: TypeId,
    leaf_len: u32,
    leaf_keys: u32,
    leaf_values: u32,
    internal: TypeId,
    internal_data: u32,
    internal_edges: u32,
    edge: Vec<u32>,
}

#[derive(Clone, Debug)]
struct RawVecFormat {
    pointer: Vec<u32>,
    length: Vec<u32>,
    capacity: Vec<u32>,
    element: TypeId,
}

fn vec_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawVecFormat> {
    let RawType::Struct(vec) = reader.canonical_type(id)? else {
        return None;
    };
    if fq_name(reader, id)?.split('<').next()? != "alloc::vec::Vec" {
        return None;
    }
    let [element_param, alloc_param] = vec.template_params.as_ref() else {
        return None;
    };
    if element_param.name.map(|name| reader.strings.get(name)) != Some("T")
        || alloc_param.name.map(|name| reader.strings.get(name)) != Some("A")
    {
        return None;
    }
    let element = reader.canonicalize(element_param.type_id);
    let alloc = reader.canonicalize(alloc_param.type_id);

    let (buf_index, buf_member) = unique_member(reader, &vec.members, "buf")?;
    let (len_index, len_member) = unique_member(reader, &vec.members, "len")?;
    if !is_unsigned_integer(reader, len_member.type_id, crate::bundle::POINTER_SIZE) {
        return None;
    }

    let RawType::Struct(raw_vec) = reader.canonical_type(buf_member.type_id)? else {
        return None;
    };
    if fq_name(reader, buf_member.type_id)?.split('<').next()? != "alloc::raw_vec::RawVec" {
        return None;
    }
    let [raw_element, raw_alloc] = raw_vec.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(raw_element.type_id) != element
        || reader.canonicalize(raw_alloc.type_id) != alloc
    {
        return None;
    }

    let (inner_index, inner_member) = unique_member(reader, &raw_vec.members, "inner")?;
    let RawType::Struct(inner) = reader.canonical_type(inner_member.type_id)? else {
        return None;
    };
    if fq_name(reader, inner_member.type_id)?.split('<').next()? != "alloc::raw_vec::RawVecInner" {
        return None;
    }
    let [inner_alloc] = inner.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(inner_alloc.type_id) != alloc {
        return None;
    }

    let mut pointer_paths = Vec::new();
    find_pointer_paths_any_offset(
        reader,
        reader.canonicalize(inner_member.type_id),
        &|target| is_unsigned_integer(reader, target, 1),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut pointer_paths,
    );
    let [(pointer_path, _)] = pointer_paths.as_slice() else {
        return None;
    };

    let (cap_index, cap_member) = unique_member(reader, &inner.members, "cap")?;
    let (cap_value, _) = usize_no_high_bit_layout(reader, cap_member.type_id)?;

    let prefix = [buf_index as u32, inner_index as u32];
    Some(RawVecFormat {
        pointer: prefix
            .iter()
            .copied()
            .chain(pointer_path.iter().copied())
            .collect(),
        length: vec![len_index as u32],
        capacity: prefix
            .iter()
            .copied()
            .chain([cap_index as u32, cap_value])
            .collect(),
        element,
    })
}

/// Recognize the private node layout of `BTreeMap<K, V, A>`. Unlike the
/// simpler known formats, this retains a few referenced types until emission
/// so they can be translated to bundle ids.
fn btree_map_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawBTreeMapFormat> {
    if fq_name(reader, id)?.split('<').next()? != "alloc::collections::btree::map::BTreeMap" {
        return None;
    }
    let RawType::Struct(map) = reader.canonical_type(id)? else {
        return None;
    };
    let [key_param, value_param, alloc_param] = map.template_params.as_ref() else {
        return None;
    };
    if key_param.name.map(|name| reader.strings.get(name)) != Some("K")
        || value_param.name.map(|name| reader.strings.get(name)) != Some("V")
        || alloc_param.name.map(|name| reader.strings.get(name)) != Some("A")
    {
        return None;
    }
    let key = reader.canonicalize(key_param.type_id);
    let value = reader.canonicalize(value_param.type_id);

    let (root, root_member) = unique_member(reader, &map.members, "root")?;
    let (length, length_member) = unique_member(reader, &map.members, "length")?;
    if root == length || !is_unsigned_integer(reader, length_member.type_id, 8) {
        return None;
    }

    let RawType::Enum(root_option) = reader.canonical_type(root_member.type_id)? else {
        return None;
    };
    if fq_name(reader, root_member.type_id)?.split('<').next()? != "core::option::Option" {
        return None;
    }
    let some = raw_variant(reader, root_option, "Some")?;
    let mut node_refs = Vec::new();
    find_type_paths(
        reader,
        reader.canonicalize(some.type_id),
        &|candidate| is_btree_node_ref(reader, candidate, key, value),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut node_refs,
    );
    let [(root_node, node_ref)] = node_refs.as_slice() else {
        return None;
    };
    let RawType::Struct(node_ref_ty) = reader.canonical_type(*node_ref)? else {
        return None;
    };
    let (height, height_member) = unique_member(reader, &node_ref_ty.members, "height")?;
    if !is_unsigned_integer(reader, height_member.type_id, 8) {
        return None;
    }

    let (node_member_index, node_member) = unique_member(reader, &node_ref_ty.members, "node")?;
    let mut node_pointers = Vec::new();
    find_pointer_paths(
        reader,
        reader.canonicalize(node_member.type_id),
        &|target| is_btree_node(reader, target, "LeafNode", key, value),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut node_pointers,
    );
    let [(node_tail, leaf)] = node_pointers.as_slice() else {
        return None;
    };
    let mut node = vec![node_member_index as u32];
    node.extend_from_slice(node_tail);

    let RawType::Struct(leaf_ty) = reader.canonical_type(*leaf)? else {
        return None;
    };
    let (leaf_len, leaf_len_member) = unique_member(reader, &leaf_ty.members, "len")?;
    if !is_unsigned_integer(reader, leaf_len_member.type_id, 2) {
        return None;
    }
    let (leaf_keys, keys_member) = unique_member(reader, &leaf_ty.members, "keys")?;
    let (leaf_values, values_member) = unique_member(reader, &leaf_ty.members, "vals")?;
    let RawType::Array(keys) = reader.canonical_type(keys_member.type_id)? else {
        return None;
    };
    let RawType::Array(values) = reader.canonical_type(values_member.type_id)? else {
        return None;
    };
    if keys.count == 0
        || keys.count != values.count
        || maybe_uninit_target(reader, keys.elem_type_id) != Some(key)
        || maybe_uninit_target(reader, values.elem_type_id) != Some(value)
    {
        return None;
    }

    let (_, parent_member) = unique_member(reader, &leaf_ty.members, "parent")?;
    let RawType::Enum(parent_option) = reader.canonical_type(parent_member.type_id)? else {
        return None;
    };
    let parent_some = raw_variant(reader, parent_option, "Some")?;
    let mut parent_pointers = Vec::new();
    find_pointer_paths(
        reader,
        reader.canonicalize(parent_some.type_id),
        &|target| is_btree_node(reader, target, "InternalNode", key, value),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut parent_pointers,
    );
    let [(_, internal)] = parent_pointers.as_slice() else {
        return None;
    };
    let RawType::Struct(internal_ty) = reader.canonical_type(*internal)? else {
        return None;
    };
    let (internal_data, data_member) = unique_member(reader, &internal_ty.members, "data")?;
    if reader.canonicalize(data_member.type_id) != *leaf || data_member.offset != 0 {
        return None;
    }
    let (internal_edges, edges_member) = unique_member(reader, &internal_ty.members, "edges")?;
    let RawType::Array(edges) = reader.canonical_type(edges_member.type_id)? else {
        return None;
    };
    if edges.count != keys.count + 1 {
        return None;
    }
    let mut edge_pointers = Vec::new();
    find_pointer_paths(
        reader,
        reader.canonicalize(edges.elem_type_id),
        &|target| reader.canonicalize(target) == *leaf,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut edge_pointers,
    );
    let [(edge, _)] = edge_pointers.as_slice() else {
        return None;
    };

    Some(RawBTreeMapFormat {
        root: root as u32,
        length: length as u32,
        root_node: root_node.clone(),
        height: height as u32,
        node,
        key,
        value,
        leaf: *leaf,
        leaf_len: leaf_len as u32,
        leaf_keys: leaf_keys as u32,
        leaf_values: leaf_values as u32,
        internal: *internal,
        internal_data: internal_data as u32,
        internal_edges: internal_edges as u32,
        edge: edge.clone(),
    })
}

fn unique_member<'a>(
    reader: &DwReader<'_>,
    members: &'a [crate::raw_types::RawMember<crate::StrId>],
    expected: &str,
) -> Option<(usize, &'a crate::raw_types::RawMember<crate::StrId>)> {
    let mut matches = members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.name.map(|name| reader.strings.get(name)) == Some(expected));
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn raw_variant<'a>(
    reader: &DwReader<'_>,
    en: &'a crate::raw_types::RawEnum<crate::StrId>,
    expected: &str,
) -> Option<&'a crate::raw_types::RawMember<crate::StrId>> {
    let variants: Vec<_> = match &en.shape {
        RawVariantShape::One(variant) => vec![&variant.member],
        RawVariantShape::Many { variants, .. } => variants
            .iter()
            .map(|(_, variant)| &variant.member)
            .collect(),
        RawVariantShape::Zero | RawVariantShape::CStyle { .. } => return None,
    };
    let mut matches = variants
        .into_iter()
        .filter(|member| member.name.map(|name| reader.strings.get(name)) == Some(expected));
    let found = matches.next()?;
    matches.next().is_none().then_some(found)
}

fn is_unsigned_integer(reader: &DwReader<'_>, id: TypeId, size: u64) -> bool {
    matches!(
        reader.canonical_type(id),
        Some(RawType::Base(base)) if base.size == size && base.encoding == Encoding::Unsigned
    )
}

fn is_btree_node_ref(reader: &DwReader<'_>, id: TypeId, key: TypeId, value: TypeId) -> bool {
    let Some(RawType::Struct(st)) = reader.canonical_type(id) else {
        return false;
    };
    fq_name(reader, id).is_some_and(|name| {
        name.split('<').next() == Some("alloc::collections::btree::node::NodeRef")
    }) && st.template_params.len() == 4
        && reader.canonicalize(st.template_params[1].type_id) == key
        && reader.canonicalize(st.template_params[2].type_id) == value
}

fn is_btree_node(
    reader: &DwReader<'_>,
    id: TypeId,
    kind: &str,
    key: TypeId,
    value: TypeId,
) -> bool {
    let Some(RawType::Struct(st)) = reader.canonical_type(id) else {
        return false;
    };
    let expected = match kind {
        "LeafNode" => "alloc::collections::btree::node::LeafNode",
        "InternalNode" => "alloc::collections::btree::node::InternalNode",
        _ => return false,
    };
    fq_name(reader, id).is_some_and(|name| name.split('<').next() == Some(expected))
        && st.template_params.len() == 2
        && reader.canonicalize(st.template_params[0].type_id) == key
        && reader.canonicalize(st.template_params[1].type_id) == value
}

fn maybe_uninit_target(reader: &DwReader<'_>, id: TypeId) -> Option<TypeId> {
    let RawType::Union(union) = reader.canonical_type(id)? else {
        return None;
    };
    if fq_name(reader, id)?.split('<').next()? != "core::mem::maybe_uninit::MaybeUninit" {
        return None;
    }
    let [param] = union.template_params.as_ref() else {
        return None;
    };
    (param.name.map(|name| reader.strings.get(name)) == Some("T"))
        .then(|| reader.canonicalize(param.type_id))
}

fn find_type_paths(
    reader: &DwReader<'_>,
    current: TypeId,
    matches: &impl Fn(TypeId) -> bool,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<(Vec<u32>, TypeId)>,
) {
    let current = reader.canonicalize(current);
    if found.len() > 1 || path.len() >= 8 || seen.contains(&current) {
        return;
    }
    if matches(current) {
        found.push((path.clone(), current));
        return;
    }
    let members = match reader.canonical_type(current) {
        Some(RawType::Struct(st)) => st.members.as_ref(),
        Some(RawType::Union(union)) => union.members.as_ref(),
        _ => return,
    };
    seen.push(current);
    for (index, member) in members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.offset == 0)
    {
        path.push(index as u32);
        find_type_paths(reader, member.type_id, matches, path, seen, found);
        path.pop();
    }
    seen.pop();
}

fn find_pointer_paths(
    reader: &DwReader<'_>,
    current: TypeId,
    matches: &impl Fn(TypeId) -> bool,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<(Vec<u32>, TypeId)>,
) {
    find_pointer_paths_inner(reader, current, matches, path, seen, found, true)
}

fn find_pointer_paths_any_offset(
    reader: &DwReader<'_>,
    current: TypeId,
    matches: &impl Fn(TypeId) -> bool,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<(Vec<u32>, TypeId)>,
) {
    find_pointer_paths_inner(reader, current, matches, path, seen, found, false)
}

fn find_pointer_paths_inner(
    reader: &DwReader<'_>,
    current: TypeId,
    matches: &impl Fn(TypeId) -> bool,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<(Vec<u32>, TypeId)>,
    zero_offset_only: bool,
) {
    let current = reader.canonicalize(current);
    if found.len() > 1 || path.len() >= 8 || seen.contains(&current) {
        return;
    }
    if let Some(RawType::Pointer(pointer)) = reader.canonical_type(current) {
        let target = reader.canonicalize(pointer.target_type_id);
        if matches(target) {
            found.push((path.clone(), target));
        }
        return;
    }
    let members = match reader.canonical_type(current) {
        Some(RawType::Struct(st)) => st.members.as_ref(),
        Some(RawType::Union(union)) => union.members.as_ref(),
        _ => return,
    };
    seen.push(current);
    for (index, member) in members
        .iter()
        .enumerate()
        .filter(|(_, member)| !zero_offset_only || member.offset == 0)
    {
        path.push(index as u32);
        find_pointer_paths_inner(
            reader,
            member.type_id,
            matches,
            path,
            seen,
            found,
            zero_offset_only,
        );
        path.pop();
    }
    seen.pop();
}

fn function_pointer_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Pointer(pointer) = reader.canonical_type(id)? else {
        return None;
    };
    reader
        .is_subroutine_type(pointer.target_type_id)
        .then_some(DebugFormat::Node(DisplayNode::Symbol {
            at: Selector::default(),
        }))
}

fn raw_waker_vtable_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    if fq_name(reader, id).as_deref() != Some("core::task::wake::RawWakerVTable") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let member = |expected: &str| {
        let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
            member.name.map(|name| reader.strings.get(name)) == Some(expected)
                && matches!(
                    reader.canonical_type(member.type_id),
                    Some(RawType::Pointer(_))
                )
        });
        let (index, _) = matches.next()?;
        matches.next().is_none().then_some(index as u32)
    };
    // Render the whole struct, replacing each function-pointer member's value
    // with a `Symbol` node (its address and resolved name) while keeping the
    // member's own name. The fields are emitted in RawWakerVTable's declared
    // order (clone, wake, wake_by_ref, drop) regardless of DWARF member order.
    let symbol = |index: u32| Field::Override {
        index,
        node: DisplayNode::Symbol {
            at: Selector::member(index),
        },
    };
    Some(DebugFormat::Node(DisplayNode::Struct {
        fields: vec![
            symbol(member("clone")?),
            symbol(member("wake")?),
            symbol(member("wake_by_ref")?),
            symbol(member("drop")?),
        ],
    }))
}

fn ip_address_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let expected_octets = match fq_name(reader, id).as_deref()? {
        "core::net::ip_addr::Ipv4Addr" => 4,
        "core::net::ip_addr::Ipv6Addr" => 16,
        _ => return None,
    };
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let (index, member) = unique_member(reader, &st.members, "octets")?;
    if member.offset != 0 {
        return None;
    }
    let RawType::Array(array) = reader.canonical_type(member.type_id)? else {
        return None;
    };
    if array.count != expected_octets || !is_unsigned_integer(reader, array.elem_type_id, 1) {
        return None;
    }
    Some(DebugFormat::Known(crate::bundle::KnownFormat::IpAddress {
        octets: Selector::member(index as u32),
    }))
}

fn str_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    if fq_name(reader, id).as_deref() != Some("&str") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let (pointer, pointer_member) = unique_member(reader, &st.members, "data_ptr")?;
    let (length, length_member) = unique_member(reader, &st.members, "length")?;
    let RawType::Pointer(raw_pointer) = reader.canonical_type(pointer_member.type_id)? else {
        return None;
    };
    if !is_unsigned_integer(reader, raw_pointer.target_type_id, 1)
        || !is_unsigned_integer(reader, length_member.type_id, crate::bundle::POINTER_SIZE)
    {
        return None;
    }
    Some(DebugFormat::Known(crate::bundle::KnownFormat::Str {
        pointer: Selector::member(pointer as u32),
        length: Selector::member(length as u32),
    }))
}

fn string_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    if fq_name(reader, id).as_deref() != Some("alloc::string::String") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let (vec_index, vec_member) = unique_member(reader, &st.members, "vec")?;
    let layout = vec_debug_format(reader, vec_member.type_id)?;
    if !is_unsigned_integer(reader, layout.element, 1) {
        return None;
    }
    let prefix = [vec_index as u32];
    Some(DebugFormat::Known(crate::bundle::KnownFormat::String {
        pointer: prefix
            .iter()
            .copied()
            .chain(layout.pointer)
            .collect::<Vec<u32>>()
            .into(),
        length: prefix
            .iter()
            .copied()
            .chain(layout.length)
            .collect::<Vec<u32>>()
            .into(),
        capacity: prefix
            .iter()
            .copied()
            .chain(layout.capacity)
            .collect::<Vec<u32>>()
            .into(),
    }))
}

/// Recognize a `parking_lot::raw_mutex::RawMutex` and return the selector to its
/// single state byte. The decode table (`LOCKED_BIT`/`PARKED_BIT`) is attached
/// in [`Emitter::emit`], where the string interner is available.
fn parking_lot_raw_mutex_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<Selector> {
    if fq_name(reader, id).as_deref() != Some("parking_lot::raw_mutex::RawMutex") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let (state_index, state_member) = unique_member(reader, &st.members, "state")?;
    // The state is a single-byte atomic (`AtomicU8`). Reuse the atomic
    // detector for the path to the stored byte, then anchor it at `state`.
    let Some(DebugFormat::Known(crate::bundle::KnownFormat::Atomic { value })) =
        atomic_debug_format(reader, state_member.type_id)
    else {
        return None;
    };
    let RawType::Struct(atomic) = reader.canonical_type(state_member.type_id)? else {
        return None;
    };
    if atomic.size != 1 {
        return None;
    }
    Some(value.under_member(state_index as u32))
}

/// The member path from a struct named `type_name` to the atomic `usize`
/// stored in its `field` member. tokio uses its own loom shim internally, so
/// the word sits behind loom/UnsafeCell/Atomic wrappers rather than a bare
/// `core::sync::atomic::Atomic<usize>`; walk the zero-offset chain to the
/// unique `usize` and anchor the path at `field`.
fn atomic_usize_field_path(
    reader: &DwReader<'_>,
    id: TypeId,
    type_name: &str,
    field: &str,
) -> Option<Vec<u32>> {
    if fq_name(reader, id).as_deref() != Some(type_name) {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let (field_index, field_member) = unique_member(reader, &st.members, field)?;
    let mut paths = Vec::new();
    find_zero_offset_uint_paths(
        reader,
        reader.canonicalize(field_member.type_id),
        crate::bundle::POINTER_SIZE,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut paths,
    );
    let [inner] = paths.as_slice() else {
        return None;
    };
    Some(
        std::iter::once(field_index as u32)
            .chain(inner.iter().copied())
            .collect(),
    )
}

/// A `tokio::sync::notify::Notify` and the paths reify needs to render it
/// compactly as a [`crate::bundle::DisplayNode`] record.
struct RawNotifyFormat {
    state: Vec<u32>,
    mutex: Vec<u32>,
    head: Vec<u32>,
    waiter: TypeId,
    waiter_notification: Vec<u32>,
    waiter_next: Vec<u32>,
}

/// Recognize a `tokio::sync::notify::Notify` and record the paths to its
/// notification state word, waiter-mutex state byte, and intrusive waiter queue.
fn notify_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawNotifyFormat> {
    if fq_name(reader, id).as_deref() != Some("tokio::sync::notify::Notify") {
        return None;
    }

    // The notification state word, an atomic `usize` behind tokio's loom shim.
    let state = atomic_usize_field_path(reader, id, "tokio::sync::notify::Notify", "state")?;

    // The waiter list lives behind the `waiters` mutex. tokio wraps it in a loom
    // shim over parking_lot's `lock_api::Mutex`; navigate the shim (`__1`) to the
    // real mutex, whose `raw` is the parking_lot RawMutex and whose `data` (an
    // `UnsafeCell`, member `value`) holds the `LinkedList` directly (there is no
    // `Waitlist` wrapper as in the batch semaphore). Reach the RawMutex's single
    // state byte through its atomic wrapper by walking to the zero-offset `u8`,
    // which works whether the compiler emitted the atomic as the generic
    // `Atomic<u8>` or the concrete `AtomicU8`.
    let (raw_prefix, raw_ty) = field_path(reader, id, &["waiters", "__1", "raw"])?;
    if fq_name(reader, raw_ty).as_deref() != Some("parking_lot::raw_mutex::RawMutex") {
        return None;
    }
    let mut state_tails = Vec::new();
    find_zero_offset_uint_paths(
        reader,
        raw_ty,
        1,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut state_tails,
    );
    let [state_tail] = state_tails.as_slice() else {
        return None;
    };
    let mutex = raw_prefix
        .iter()
        .copied()
        .chain(state_tail.iter().copied())
        .collect();

    let (head, _) = field_path(reader, id, &["waiters", "__1", "data", "value", "head"])?;

    // The queue is a `LinkedList<Waiter, Waiter>`; its node type is the `Waiter`.
    let (_, queue_ty) = field_path(reader, id, &["waiters", "__1", "data", "value"])?;
    let RawType::Struct(list) = reader.canonical_type(queue_ty)? else {
        return None;
    };
    let param = list.template_params.last()?;
    let waiter = reader.canonicalize(param.type_id);
    if fq_name(reader, waiter).as_deref() != Some("tokio::sync::notify::Waiter") {
        return None;
    }

    // Rooted at the `Waiter`: its atomic `notification` word (whether it has been
    // handed a notification) and its successor pointer (`pointers.inner.value.next`).
    let waiter_notification = atomic_usize_field_path(
        reader,
        waiter,
        "tokio::sync::notify::Waiter",
        "notification",
    )?;
    let (waiter_next, _) = field_path(reader, waiter, &["pointers", "inner", "value", "next"])?;

    Some(RawNotifyFormat {
        state,
        mutex,
        head,
        waiter,
        waiter_notification,
        waiter_next,
    })
}

/// A `tokio::sync::batch_semaphore::Semaphore` and the paths reify needs to
/// render it: the full member list (in DWARF order, zero-sized members elided
/// to match structural display) and the path to the atomic permit word within
/// the `permits` member.
struct RawSemaphoreFormat {
    permits: Vec<u32>,
    members: Vec<u32>,
}

/// Recognize a `tokio::sync::batch_semaphore::Semaphore` and record its members
/// plus the path to its atomic permit word; the decode table is attached in
/// [`Emitter::emit`].
fn semaphore_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawSemaphoreFormat> {
    let permits = atomic_usize_field_path(
        reader,
        id,
        "tokio::sync::batch_semaphore::Semaphore",
        "permits",
    )?;
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    // Structural display skips zero-sized members; enumerate over the full list
    // so the surviving indices still address the concrete members.
    let members = st
        .members
        .iter()
        .enumerate()
        .filter(|(_, m)| raw_type_size(reader, m.type_id).unwrap_or(0) > 0)
        .map(|(index, _)| index as u32)
        .collect();
    Some(RawSemaphoreFormat { permits, members })
}

/// Recognize a `tokio::sync::watch::state::AtomicState` and return the selector
/// to its atomic word; the decode table is attached in [`Emitter::emit`].
fn watch_state_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<Selector> {
    let state =
        atomic_usize_field_path(reader, id, "tokio::sync::watch::state::AtomicState", "__0")?;
    Some(state.into())
}

fn mpsc_block_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    if !fq_name(reader, id)
        .as_deref()
        .is_some_and(|name| name.starts_with("tokio::sync::mpsc::block::Block<"))
    {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };

    // The readiness bitmap lives in `header.ready_slots`, an atomic `usize`
    // behind the usual loom/UnsafeCell/Atomic wrappers.
    let (header_index, header_member) = unique_member(reader, &st.members, "header")?;
    let RawType::Struct(header) = reader.canonical_type(header_member.type_id)? else {
        return None;
    };
    let (ready_index, ready_member) = unique_member(reader, &header.members, "ready_slots")?;
    let mut ready_tail = Vec::new();
    find_zero_offset_uint_paths(
        reader,
        reader.canonicalize(ready_member.type_id),
        crate::bundle::POINTER_SIZE,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut ready_tail,
    );
    let [ready_tail] = ready_tail.as_slice() else {
        return None;
    };
    let ready_slots = [header_index as u32, ready_index as u32]
        .into_iter()
        .chain(ready_tail.iter().copied())
        .collect::<Vec<u32>>();

    // The slots are the inline array behind `values.__0`.
    let (values_index, values_member) = unique_member(reader, &st.members, "values")?;
    let RawType::Struct(values) = reader.canonical_type(values_member.type_id)? else {
        return None;
    };
    let (array_index, array_member) = unique_member(reader, &values.members, "__0")?;
    if !matches!(
        reader.canonical_type(array_member.type_id),
        Some(RawType::Array(_))
    ) {
        return None;
    }
    let values = vec![values_index as u32, array_index as u32];

    Some(DebugFormat::Known(crate::bundle::KnownFormat::MpscBlock {
        ready_slots: ready_slots.into(),
        values: values.into(),
    }))
}

/// Recognize a `tokio::sync::mpsc::bounded::Receiver<T>` and record the paths
/// needed to render it as its underlying channel. A receiver wraps an
/// `Arc<Chan<T, Semaphore>>`; navigate to the raw pointer inside the `Arc`,
/// then across the allocation's sized header to the `Chan`, and record the
/// bounded capacity (`semaphore.bound`) and available permit word
/// (`semaphore.semaphore.permits`) as paths rooted at that `Chan`.
/// A `tokio::sync::mpsc::bounded::Receiver<T>` and the selectors reify needs to
/// render it as its channel. The permit-word decode is attached in
/// [`Emitter::emit`]. See [`crate::bundle::KnownFormat::MpscRx`].
struct RawMpscRxFormat {
    chan_pointer: Vec<u32>,
    chan: Vec<u32>,
    bound: Vec<u32>,
    permits: Vec<u32>,
}

fn mpsc_rx_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawMpscRxFormat> {
    if !fq_name(reader, id)
        .as_deref()
        .is_some_and(|name| name.starts_with("tokio::sync::mpsc::bounded::Receiver<"))
    {
        return None;
    }
    // Receiver → Rx → Arc → the `NonNull` raw pointer at `ptr.pointer`, which
    // targets the `ArcInner<Chan>` allocation.
    let (chan_pointer, ptr_ty) = field_path(reader, id, &["chan", "inner", "ptr", "pointer"])?;
    let RawType::Pointer(ptr) = reader.canonical_type(ptr_ty)? else {
        return None;
    };
    let arcinner = reader.canonicalize(ptr.target_type_id);

    // Skip the Arc's strong/weak header to the `data` field: the `Chan`.
    let (chan, chan_ty) = field_path(reader, arcinner, &["data"])?;
    if !fq_name(reader, chan_ty)
        .as_deref()
        .is_some_and(|name| name.starts_with("tokio::sync::mpsc::chan::Chan<"))
    {
        return None;
    }

    // Capacity is the bounded semaphore's `bound`, a plain `usize`.
    let (bound, bound_ty) = field_path(reader, chan_ty, &["semaphore", "bound"])?;
    if !is_unsigned_integer(reader, bound_ty, crate::bundle::POINTER_SIZE) {
        return None;
    }

    // Available buffer slots live in the batch semaphore's atomic `permits`
    // word. Reach the inner `batch_semaphore::Semaphore`, then walk to its
    // permit `usize`, and root the path at the `Chan`.
    let (sem_prefix, sem_ty) = field_path(reader, chan_ty, &["semaphore", "semaphore"])?;
    let permits_tail = atomic_usize_field_path(
        reader,
        sem_ty,
        "tokio::sync::batch_semaphore::Semaphore",
        "permits",
    )?;
    let permits = sem_prefix
        .into_iter()
        .chain(permits_tail)
        .collect::<Vec<u32>>();

    Some(RawMpscRxFormat {
        chan_pointer,
        chan,
        bound,
        permits,
    })
}

/// A `tokio::sync::mpsc::bounded::Semaphore` and the paths reify needs to render
/// it compactly as a [`crate::bundle::DisplayNode`] record.
struct RawBoundedSemaphoreFormat {
    mutex: Vec<u32>,
    closed: Vec<u32>,
    permits: Vec<u32>,
    bound: Vec<u32>,
    head: Vec<u32>,
    waiter: TypeId,
    waiter_state: Vec<u32>,
    waiter_next: Vec<u32>,
}

/// Recognize a `tokio::sync::mpsc::bounded::Semaphore` and record the paths to
/// its mutex state, closed flag, permits, capacity, and intrusive waiter queue.
fn bounded_semaphore_debug_format(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<RawBoundedSemaphoreFormat> {
    if fq_name(reader, id).as_deref() != Some("tokio::sync::mpsc::bounded::Semaphore") {
        return None;
    }

    // The capacity is the bounded semaphore's own `bound`, a plain `usize`.
    let (bound, bound_ty) = field_path(reader, id, &["bound"])?;
    if !is_unsigned_integer(reader, bound_ty, crate::bundle::POINTER_SIZE) {
        return None;
    }

    // The available permits are the inner batch semaphore's atomic word.
    let (sem_prefix, sem_ty) = field_path(reader, id, &["semaphore"])?;
    let permits_tail = atomic_usize_field_path(
        reader,
        sem_ty,
        "tokio::sync::batch_semaphore::Semaphore",
        "permits",
    )?;
    let permits = sem_prefix.iter().copied().chain(permits_tail).collect();

    // The waiter list lives behind the batch semaphore's `waiters` mutex. tokio
    // wraps it in a loom shim over parking_lot's `lock_api::Mutex`; navigate the
    // shim (`__1`) to the real mutex, whose `raw` is the parking_lot RawMutex and
    // whose `data` (an `UnsafeCell`, member `value`) holds the `Waitlist`. Reach
    // the RawMutex's single state byte through its atomic wrapper by walking to
    // the zero-offset `u8`, which works whether the compiler emitted the atomic
    // as the generic `Atomic<u8>` or the concrete `AtomicU8`.
    let (raw_prefix, raw_ty) = field_path(reader, id, &["semaphore", "waiters", "__1", "raw"])?;
    if fq_name(reader, raw_ty).as_deref() != Some("parking_lot::raw_mutex::RawMutex") {
        return None;
    }
    let mut state_tails = Vec::new();
    find_zero_offset_uint_paths(
        reader,
        raw_ty,
        1,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut state_tails,
    );
    let [state_tail] = state_tails.as_slice() else {
        return None;
    };
    let mutex = raw_prefix
        .iter()
        .copied()
        .chain(state_tail.iter().copied())
        .collect();

    let (closed, closed_ty) = field_path(
        reader,
        id,
        &["semaphore", "waiters", "__1", "data", "value", "closed"],
    )?;
    if !matches!(reader.canonical_type(closed_ty), Some(RawType::Base(base)) if base.size == 1) {
        return None;
    }

    let (head, _) = field_path(
        reader,
        id,
        &[
            "semaphore",
            "waiters",
            "__1",
            "data",
            "value",
            "queue",
            "head",
        ],
    )?;

    // The queue is a `LinkedList<Waiter, Waiter>`; its node type is the `Waiter`.
    let (_, queue_ty) = field_path(
        reader,
        id,
        &["semaphore", "waiters", "__1", "data", "value", "queue"],
    )?;
    let RawType::Struct(list) = reader.canonical_type(queue_ty)? else {
        return None;
    };
    let param = list.template_params.last()?;
    let waiter = reader.canonicalize(param.type_id);
    if fq_name(reader, waiter).as_deref() != Some("tokio::sync::batch_semaphore::Waiter") {
        return None;
    }

    // Rooted at the `Waiter`: its atomic `state` word (permits still needed) and
    // its successor pointer (`pointers.inner.value.next`).
    let waiter_state = atomic_usize_field_path(
        reader,
        waiter,
        "tokio::sync::batch_semaphore::Waiter",
        "state",
    )?;
    let (waiter_next, _) = field_path(reader, waiter, &["pointers", "inner", "value", "next"])?;

    Some(RawBoundedSemaphoreFormat {
        mutex,
        closed,
        permits,
        bound,
        head,
        waiter,
        waiter_state,
        waiter_next,
    })
}

/// Walk a chain of named struct members, returning the member-index path and
/// the type reached. Used to record navigation paths through transparent
/// wrappers (CachePadded, UnsafeCell, NonNull) by name.
fn field_path(reader: &DwReader<'_>, ty: TypeId, names: &[&str]) -> Option<(Vec<u32>, TypeId)> {
    let mut path = Vec::with_capacity(names.len());
    let mut cur = reader.canonicalize(ty);
    for name in names {
        let members = match reader.canonical_type(cur)? {
            RawType::Struct(st) => &st.members,
            RawType::Union(u) => &u.members,
            _ => return None,
        };
        let (index, member) = unique_member(reader, members, name)?;
        path.push(index as u32);
        cur = reader.canonicalize(member.type_id);
    }
    Some((path, cur))
}

/// Navigate named members to a field, then walk any atomic/cell wrappers to
/// the `usize` it stores, returning the full member path.
fn usize_field_path(reader: &DwReader<'_>, ty: TypeId, names: &[&str]) -> Option<Vec<u32>> {
    let (head, field_ty) = field_path(reader, ty, names)?;
    let mut tails = Vec::new();
    find_zero_offset_uint_paths(
        reader,
        field_ty,
        crate::bundle::POINTER_SIZE,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut tails,
    );
    let [tail] = tails.as_slice() else {
        return None;
    };
    Some(head.into_iter().chain(tail.iter().copied()).collect())
}

struct RawMpscChanFormat {
    tail: Vec<u32>,
    index: Vec<u32>,
    head: Vec<u32>,
    start_index: Vec<u32>,
    next: Vec<u32>,
    values: Vec<u32>,
    element: TypeId,
}

fn mpsc_chan_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawMpscChanFormat> {
    if !fq_name(reader, id)
        .as_deref()
        .is_some_and(|name| name.starts_with("tokio::sync::mpsc::chan::Chan<"))
    {
        return None;
    }
    // Sender write position and receiver read position, plus the receiver's
    // head block pointer. The rx fields sit behind CachePadded/UnsafeCell
    // wrappers; navigate them by name.
    // `tail_position` is a (shared) atomic usize; `index` is a plain usize on
    // the single-consumer receiver. Walk to the stored word either way.
    let tail = usize_field_path(reader, id, &["tx", "value", "tail_position"])?;
    let index = usize_field_path(reader, id, &["rx_fields", "__0", "value", "list", "index"])?;
    let (head, head_ty) = field_path(
        reader,
        id,
        &["rx_fields", "__0", "value", "list", "head", "pointer"],
    )?;
    let RawType::Pointer(head_ptr) = reader.canonical_type(head_ty)? else {
        return None;
    };
    let block = reader.canonicalize(head_ptr.target_type_id);

    // Paths rooted at the block type.
    let (start_index, _) = field_path(reader, block, &["header", "start_index"])?;
    // `next` is an `AtomicPtr`; walk the atomic wrappers to the raw pointer.
    let (next_head, next_ty) = field_path(reader, block, &["header", "next"])?;
    let mut next_tails = Vec::new();
    find_zero_offset_pointer_paths(
        reader,
        next_ty,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut next_tails,
    );
    let [next_tail] = next_tails.as_slice() else {
        return None;
    };
    let next = next_head
        .iter()
        .copied()
        .chain(next_tail.iter().copied())
        .collect();
    let (values, values_ty) = field_path(reader, block, &["values", "__0"])?;
    if !matches!(reader.canonical_type(values_ty), Some(RawType::Array(_))) {
        return None;
    }

    // `element` is the block's message type `T`.
    let RawType::Struct(bst) = reader.canonical_type(block)? else {
        return None;
    };
    let [param] = bst.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let element = reader.canonicalize(param.type_id);

    Some(RawMpscChanFormat {
        tail,
        index,
        head,
        start_index,
        next,
        values,
        element,
    })
}

/// Like [`find_zero_offset_uint_paths`], but the target is any pointer. Used
/// to reach the raw pointer behind an `AtomicPtr` wrapper.
fn find_zero_offset_pointer_paths(
    reader: &DwReader<'_>,
    current: TypeId,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<Vec<u32>>,
) {
    if found.len() > 1 || path.len() >= 8 || seen.contains(&current) {
        return;
    }
    if matches!(reader.canonical_type(current), Some(RawType::Pointer(_))) {
        found.push(path.clone());
        return;
    }
    seen.push(current);
    let members = match reader.canonical_type(current) {
        Some(RawType::Struct(st)) => st.members.as_ref(),
        Some(RawType::Union(u)) => u.members.as_ref(),
        _ => &[],
    };
    for (index, member) in members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.offset == 0)
    {
        path.push(index as u32);
        find_zero_offset_pointer_paths(
            reader,
            reader.canonicalize(member.type_id),
            path,
            seen,
            found,
        );
        path.pop();
    }
    seen.pop();
}

/// Like [`find_zero_offset_paths`], but the target is any unsigned integer of
/// `size` bytes rather than a specific type id. Used to reach the word behind
/// an atomic wrapper without knowing whether it is the core or loom shape.
fn find_zero_offset_uint_paths(
    reader: &DwReader<'_>,
    current: TypeId,
    size: u64,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<Vec<u32>>,
) {
    if found.len() > 1 || path.len() >= 8 || seen.contains(&current) {
        return;
    }
    if is_unsigned_integer(reader, current, size) {
        found.push(path.clone());
        return;
    }
    seen.push(current);
    let members = match reader.canonical_type(current) {
        Some(RawType::Struct(st)) => st.members.as_ref(),
        Some(RawType::Union(u)) => u.members.as_ref(),
        _ => &[],
    };
    for (index, member) in members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.offset == 0)
    {
        path.push(index as u32);
        find_zero_offset_uint_paths(
            reader,
            reader.canonicalize(member.type_id),
            size,
            path,
            seen,
            found,
        );
        path.pop();
    }
    seen.pop();
}

/// Recognize rustc's DWARF representation of a Rust trait-object wide
/// pointer. The bundle records both member indices and the vtable header
/// ordering so reify never guesses from the private field name or bakes in
/// rustc's slot numbers independently.
fn dyn_pointer_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };

    let mut data_matches = st.members.iter().enumerate().filter_map(|(index, member)| {
        if member.name.map(|name| reader.strings.get(name)) != Some("pointer") {
            return None;
        }
        let RawType::Pointer(pointer) = reader.canonical_type(member.type_id)? else {
            return None;
        };
        let tail_offset = dyn_tail_offset(reader, pointer.target_type_id, &mut Vec::new())?;
        Some((index, tail_offset))
    });
    let (pointer_index, tail_offset) = data_matches.next()?;
    if data_matches.next().is_some() {
        return None;
    }

    let mut vtable_matches = st.members.iter().enumerate().filter(|(_, member)| {
        if member.name.map(|name| reader.strings.get(name)) != Some("vtable") {
            return false;
        }
        let Some(RawType::Pointer(pointer)) = reader.canonical_type(member.type_id) else {
            return false;
        };
        let Some(RawType::Array(array)) = reader.canonical_type(pointer.target_type_id) else {
            return false;
        };
        if array.count < 3 {
            return false;
        }
        let Some(RawType::Base(base)) = reader.canonical_type(array.elem_type_id) else {
            return false;
        };
        base.size == crate::bundle::POINTER_SIZE
            && base.encoding == Encoding::Unsigned
            && base.name.map(|name| reader.strings.get(name)) == Some("usize")
    });
    let (vtable_index, _) = vtable_matches.next()?;
    if vtable_matches.next().is_some() || pointer_index == vtable_index {
        return None;
    }

    Some(DebugFormat::Known(crate::bundle::KnownFormat::DynPointer {
        pointer: pointer_index as u32,
        vtable: vtable_index as u32,
        drop_in_place: 0,
        size: 1,
        align: 2,
        tail_offset,
    }))
}

/// The byte offset of the `dyn Trait` tail within `id`, if `id` is a
/// `dyn Trait` type or an unsized aggregate whose final field recursively
/// contains that dyn tail (such as `ArcInner<dyn Trait>`). Rust wide
/// pointers carry metadata for either shape.
///
/// A bare `dyn Trait` has offset zero; a wrapper contributes the offset of
/// its final member and recurses into it. Returns `None` when there is no
/// dyn tail. Consumers add this to the data-pointer address to reach the
/// erased value, skipping any sized header (e.g. an `Arc`'s refcounts).
fn dyn_tail_offset(reader: &DwReader<'_>, id: TypeId, seen: &mut Vec<TypeId>) -> Option<u64> {
    let id = reader.canonicalize(id);
    if seen.len() >= 8 || seen.contains(&id) {
        return None;
    }
    let raw = reader.canonical_type(id)?;
    if fq_name(reader, id).is_some_and(|name| name.starts_with("dyn ") || name.starts_with("(dyn "))
    {
        return Some(0);
    }
    let RawType::Struct(st) = raw else {
        return None;
    };
    let tail = st.members.last()?;
    seen.push(id);
    let inner = dyn_tail_offset(reader, tail.type_id, seen);
    seen.pop();
    tail.offset.checked_add(inner?)
}

/// Whether `id` has a `dyn Trait` tail (see [`dyn_tail_offset`]).
#[cfg(test)]
fn has_dyn_tail(reader: &DwReader<'_>, id: TypeId, seen: &mut Vec<TypeId>) -> bool {
    dyn_tail_offset(reader, id, seen).is_some()
}

fn unsafe_cell_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let (member, _) = unsafe_cell_layout(reader, id)?;
    Some(DebugFormat::Transparent {
        member: Selector::member(member),
    })
}

fn unsafe_cell_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::cell" || !name.starts_with("UnsafeCell<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let target = reader.canonicalize(param.type_id);
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && member.name.map(|name| reader.strings.get(name)) == Some("value")
            && reader.canonicalize(member.type_id) == target
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some((index as u32, target))
}

fn loom_unsafe_cell_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "tokio::loom::std::unsafe_cell"
        || !name.starts_with("UnsafeCell<")
        || !name.ends_with('>')
    {
        return None;
    }

    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let target = reader.canonicalize(param.type_id);
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && member.name.map(|name| reader.strings.get(name)) == Some("__0")
            && unsafe_cell_layout(reader, member.type_id)
                .is_some_and(|(_, inner_target)| inner_target == target)
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(DebugFormat::Transparent {
        member: Selector::member(index as u32),
    })
}

fn loom_atomic_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let atomic_module = namespace.strip_prefix("tokio::loom::std::atomic_")?;
    if atomic_module.is_empty() || atomic_module.contains("::") {
        return None;
    }
    let name = st.name.map(|name| reader.strings.get(name))?;
    if !name.starts_with("Atomic") {
        return None;
    }

    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        if member.offset != 0 || member.name.map(|name| reader.strings.get(name)) != Some("inner") {
            return false;
        }
        let Some((_, atomic)) = unsafe_cell_layout(reader, member.type_id) else {
            return false;
        };
        atomic_debug_format(reader, atomic).is_some()
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(DebugFormat::Transparent {
        member: Selector::member(index as u32),
    })
}

/// tokio's `loom::std::parking_lot` shims are newtypes that pair a
/// `PhantomData` marker with the real parking_lot lock (`Mutex`, `RwLock`,
/// `Condvar`, and their guards). Display them as the inner lock so the
/// loom scaffolding does not obscure it.
fn loom_parking_lot_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    if namespace != "tokio::loom::std::parking_lot" {
        return None;
    }
    // A single non-marker member sitting at offset zero is the wrapped lock.
    let mut real = st.members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && !fq_name(reader, reader.canonicalize(member.type_id))
                .is_some_and(|name| name.starts_with("core::marker::PhantomData"))
    });
    let (index, _) = real.next()?;
    if real.next().is_some() {
        return None;
    }
    Some(DebugFormat::Transparent {
        member: Selector::member(index as u32),
    })
}

fn non_null_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let (member, _) = non_null_layout(reader, id)?;
    Some(DebugFormat::Transparent {
        member: Selector::member(member),
    })
}

fn non_null_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::ptr::non_null" || !name.starts_with("NonNull<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let target = reader.canonicalize(param.type_id);
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        if member.offset != 0 || member.name.map(|name| reader.strings.get(name)) != Some("pointer")
        {
            return false;
        }
        let Some(RawType::Pointer(pointer)) = reader.canonical_type(member.type_id) else {
            return false;
        };
        reader.canonicalize(pointer.target_type_id) == target
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some((index as u32, target))
}

fn unique_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::ptr::unique" || !name.starts_with("Unique<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let target = reader.canonicalize(param.type_id);
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && member.name.map(|name| reader.strings.get(name)) == Some("pointer")
            && non_null_layout(reader, member.type_id)
                .is_some_and(|(_, inner_target)| inner_target == target)
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(DebugFormat::Transparent {
        member: Selector::member(index as u32),
    })
}

fn usize_no_high_bit_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let (member, _) = usize_no_high_bit_layout(reader, id)?;
    Some(DebugFormat::Transparent {
        member: Selector::member(member),
    })
}

fn usize_no_high_bit_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    if fq_name(reader, id).as_deref() != Some("core::num::niche_types::UsizeNoHighBit") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && member.name.map(|name| reader.strings.get(name)) == Some("__0")
            && is_unsigned_integer(reader, member.type_id, crate::bundle::POINTER_SIZE)
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some((index as u32, reader.canonicalize(st.members[index].type_id)))
}

fn is_integer(reader: &DwReader<'_>, id: TypeId) -> bool {
    matches!(
        reader.canonical_type(id),
        Some(RawType::Base(base)) if matches!(base.encoding, Encoding::Signed | Encoding::Unsigned)
    )
}

/// `core::num::nonzero::NonZero<T>` is a newtype over a niche-typed integer
/// wrapper (`NonZero{U,I}<width>Inner`). Display it as the wrapped integer;
/// paired with [`nonzero_inner_debug_format`] the two layers collapse to the
/// value. Handles every width and signedness.
fn nonzero_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::num::nonzero" || !name.starts_with("NonZero<") || !name.ends_with('>') {
        return None;
    }
    let member = single_zero_offset_field(reader, &st.members, |_| true)?;
    Some(DebugFormat::Transparent {
        member: Selector::member(member),
    })
}

/// The niche-typed inner of a `NonZero<T>`
/// (`core::num::niche_types::NonZero{U,I}<width>Inner`), transparent over its
/// integer field.
fn nonzero_inner_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::num::niche_types"
        || !name.starts_with("NonZero")
        || !name.ends_with("Inner")
    {
        return None;
    }
    let member = single_zero_offset_field(reader, &st.members, |ty| is_integer(reader, ty))?;
    Some(DebugFormat::Transparent {
        member: Selector::member(member),
    })
}

/// The index of the unique `__0` member at offset zero whose type satisfies
/// `accept`, or `None` if there isn't exactly one.
fn single_zero_offset_field(
    reader: &DwReader<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
    accept: impl Fn(TypeId) -> bool,
) -> Option<u32> {
    let mut matches = members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && member.name.map(|name| reader.strings.get(name)) == Some("__0")
            && accept(member.type_id)
    });
    let (index, _) = matches.next()?;
    matches.next().is_none().then_some(index as u32)
}

fn atomic_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else {
        return None;
    };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::sync::atomic" || !name.starts_with("Atomic<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let target = reader.canonicalize(param.type_id);
    let mut paths = Vec::new();
    find_zero_offset_paths(
        reader,
        reader.canonicalize(id),
        target,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut paths,
    );
    let [value] = paths.as_slice() else {
        return None;
    };
    Some(DebugFormat::Known(crate::bundle::KnownFormat::Atomic {
        value: value.clone().into(),
    }))
}

/// Find all short, acyclic member paths from `current` to `target` whose
/// members remain at offset zero. Atomic storage wrappers are layout-only;
/// requiring one unique path prevents us from guessing when rustc changes
/// their representation.
fn find_zero_offset_paths(
    reader: &DwReader<'_>,
    current: TypeId,
    target: TypeId,
    path: &mut Vec<u32>,
    seen: &mut Vec<TypeId>,
    found: &mut Vec<Vec<u32>>,
) {
    if found.len() > 1 || path.len() >= 8 || seen.contains(&current) {
        return;
    }
    if current == target {
        found.push(path.clone());
        return;
    }
    seen.push(current);
    let members = match reader.canonical_type(current) {
        Some(RawType::Struct(st)) => st.members.as_ref(),
        Some(RawType::Union(u)) => u.members.as_ref(),
        _ => &[],
    };
    for (index, member) in members
        .iter()
        .enumerate()
        .filter(|(_, member)| member.offset == 0)
    {
        path.push(index as u32);
        find_zero_offset_paths(
            reader,
            reader.canonicalize(member.type_id),
            target,
            path,
            seen,
            found,
        );
        path.pop();
    }
    seen.pop();
}

/// Locate the named statics (§5.4) by DWARF shape, not by hardcoded
/// mangled names: the TLS key static's path spelling is a std internal
/// that differs across platforms and std versions.
fn find_statics(
    view: &DwView<'_>,
    symbols: &[&str],
    stats: &mut ExtractStats,
) -> BTreeMap<StaticRole, StaticDef> {
    let waker_ns = view.find_ns(WAKER_NS).map(|n| n.id());

    let mut out = BTreeMap::new();
    for (_, var) in view.variables() {
        let Some(linkage) = var.linkage_name() else {
            continue;
        };
        match var.name() {
            // std's thread_local storage for tokio's CONTEXT: named
            // `__RUST_STD_INTERNAL_VAL` (1.97-era std), nested under
            // namespaces rooted at tokio::runtime::context::CONTEXT.
            Some("__RUST_STD_INTERNAL_VAL") => {
                let mut segments = Vec::new();
                let mut ns = var.namespace();
                while let Some(n) = ns {
                    segments.push(n.name().to_owned());
                    ns = n.parent();
                }
                segments.reverse();
                if segments.len() >= 4
                    && segments[..4] == ["tokio", "runtime", "context", "CONTEXT"]
                {
                    out.entry(StaticRole::TlsContextKey).or_insert(StaticDef {
                        symbol: strip(linkage).to_owned(),
                        display: format!("{:#}", rustc_demangle::demangle(linkage)),
                    });
                }
            }
            Some("WAKER_VTABLE") if var.raw().namespace == waker_ns && waker_ns.is_some() => {
                out.entry(StaticRole::TaskWakerVtable).or_insert(StaticDef {
                    symbol: strip(linkage).to_owned(),
                    display: format!("{:#}", rustc_demangle::demangle(linkage)),
                });
            }
            _ => {}
        }
    }

    // Fall back to the symbol table for any static the DWARF sweep missed.
    // On some targets (notably illumos release builds) rustc emits no
    // `DW_TAG_variable` DIE for these tokio/std dependency statics, yet the
    // symbol survives in `.symtab`/`.dynsym`; the mangled v0 name is all the
    // bundle needs, since the consumer resolves the address by name anyway.
    if out.len() < 2 {
        for &sym in symbols {
            let stripped = strip(sym);
            if let Some(role) = match_static_symbol(stripped) {
                out.entry(role).or_insert_with(|| {
                    stats.statics_from_symtab += 1;
                    StaticDef {
                        symbol: stripped.to_owned(),
                        display: format!("{:#}", rustc_demangle::demangle(sym)),
                    }
                });
            }
        }
    }

    if !out.contains_key(&StaticRole::TlsContextKey) {
        stats
            .statics_missing
            .push("TlsContextKey (tokio::runtime::context::CONTEXT thread-local)".to_owned());
    }
    if !out.contains_key(&StaticRole::TaskWakerVtable) {
        stats
            .statics_missing
            .push("TaskWakerVtable (tokio::runtime::task::waker::WAKER_VTABLE)".to_owned());
    }
    out
}

/// Match an ELF symbol-table name to a named static (§5.4) by its v0-mangled
/// shape. Used as a fallback when the DWARF carries no `DW_TAG_variable` DIE
/// for the static (e.g. illumos release builds), where the symbol is still
/// present in `.symtab`/`.dynsym`.
///
/// The match keys on the length-prefixed path segments of the mangled name so
/// it is independent of the crate disambiguator (which varies per build) and
/// of the thread-local implementation (`native` vs `os`), which changes the
/// symbol's namespace nesting but not the `tokio::runtime::context::CONTEXT`
/// prefix or the trailing `__RUST_STD_INTERNAL_VAL` identifier.
fn match_static_symbol(sym: &str) -> Option<StaticRole> {
    if sym.ends_with("5tokio7runtime4task5waker12WAKER_VTABLE") {
        return Some(StaticRole::TaskWakerVtable);
    }
    // Several crates define a `__RUST_STD_INTERNAL_VAL` thread-local; take the
    // one under `tokio::runtime::context::CONTEXT`, not, say,
    // `std::sync::mpmc::context` or `tokio::task::local::CURRENT`.
    if sym.contains("5tokio7runtime7context7CONTEXT") && sym.ends_with("__RUST_STD_INTERNAL_VAL") {
        return Some(StaticRole::TlsContextKey);
    }
    None
}

/// Determine a task future's provenance (§5.5): coroutine env types name
/// their defining async fn/block in their namespace path; the subprogram
/// carries the declaration coordinates the type DIE lacks.
fn classify_future(
    reader: &DwReader<'_>,
    view: &DwView<'_>,
    future: TypeId,
    resume_loc: Option<&OwnedLoc>,
    em: &mut Emitter<'_>,
    stats: &mut ExtractStats,
) -> Provenance {
    let Some(raw) = reader.canonical_type(future) else {
        return Provenance {
            decl: None,
            kind: FutureKind::Manual,
        };
    };
    let name = raw
        .name()
        .map(|n| reader.strings.get(n))
        .unwrap_or_default();

    let kind = if name.starts_with("{async_fn_env#") {
        FutureKind::AsyncFn
    } else if name.starts_with("{async_block_env#") {
        FutureKind::AsyncBlock
    } else {
        // Root namespace segment distinguishes runtime/combinator crates
        // from application types.
        let root = raw.namespace().map(|ns| {
            let mut id = ns;
            loop {
                let entry = reader.namespaces.get(id);
                match entry.parent {
                    Some(p) => id = p,
                    None => break reader.strings.get(entry.name).to_owned(),
                }
            }
        });
        match root.as_deref() {
            Some("tokio" | "futures" | "futures_util" | "futures_core") => FutureKind::Combinator,
            _ => FutureKind::Manual,
        }
    };

    let mut decl = None;

    // The resume fn's own coordinates are the async fn/block's
    // declaration site — the most direct source.
    if matches!(kind, FutureKind::AsyncFn | FutureKind::AsyncBlock)
        && let Some(loc) = resume_loc
        && let (Some(file), Some(line)) = (loc.file.as_deref(), loc.line)
    {
        decl = Some(SourceLoc {
            file: em.interner.intern(file),
            line: line as u32,
        });
    }

    // Fallback: walk up the coroutine's namespace chain looking for the
    // defining subprogram; skip generated scopes ({async_block#N},
    // {closure#N}, …) between the env and the fn.
    if decl.is_none() && matches!(kind, FutureKind::AsyncFn | FutureKind::AsyncBlock) {
        let mut ns = raw.namespace();
        while let Some(id) = ns {
            let entry = reader.namespaces.get(id);
            let leaf = reader.strings.get(entry.name);
            let path = {
                let mut segs = vec![leaf.to_owned()];
                let mut p = entry.parent;
                while let Some(pid) = p {
                    let e = reader.namespaces.get(pid);
                    segs.push(reader.strings.get(e.name).to_owned());
                    p = e.parent;
                }
                segs.reverse();
                segs.join("::")
            };
            if !leaf.starts_with('{')
                && let Some(func) = view.find_func(&path)
            {
                if let Some(loc) = func.source_loc()
                    && let (Some(file), Some(line)) = (loc.file(), loc.line())
                {
                    decl = Some(SourceLoc {
                        file: em.interner.intern(file),
                        line: line.get() as u32,
                    });
                }
                break;
            }
            ns = entry.parent;
        }
    }

    if decl.is_some() {
        stats.provenance_located += 1;
    }
    Provenance { decl, kind }
}

/// Extract `1.97.0 (2d8144b78 2026-07-07)` from a producer string like
/// `clang LLVM (rustc version 1.97.0 (2d8144b78 2026-07-07))`.
fn rustc_version_of(producer: &str) -> String {
    match producer.split_once("rustc version ") {
        Some((_, rest)) => rest.strip_suffix(')').unwrap_or(rest).to_owned(),
        None => producer.to_owned(),
    }
}

/// Recover the tokio version from a registry source path such as
/// `…/tokio-1.52.3/src/runtime/task/raw.rs`.
fn tokio_version_of(loc: &OwnedLoc) -> Option<semver::Version> {
    for part in [loc.dir.as_deref(), loc.file.as_deref()]
        .into_iter()
        .flatten()
    {
        if let Some(i) = part.find("tokio-") {
            let rest = &part[i + "tokio-".len()..];
            let end = rest
                .find(|c: char| c != '.' && !c.is_ascii_digit())
                .unwrap_or(rest.len());
            if let Ok(v) = semver::Version::parse(&rest[..end]) {
                return Some(v);
            }
        }
    }
    None
}

/// Converts reachable DWARF types into bundle [`TypeDef`]s: assigns dense
/// ids up front, then drains a worklist so deep type graphs cannot
/// overflow the stack.
struct Emitter<'a> {
    reader: &'a DwReader<'a>,
    interner: StringInterner,
    ids: BTreeMap<TypeId, BundleTypeId>,
    defs: Vec<TypeDef>,
    debug_formats: BTreeMap<BundleTypeId, DebugFormat>,
    /// Fully-qualified names for the name index, parallel to `defs`.
    names: Vec<Option<String>>,
    pending: VecDeque<(TypeId, BundleTypeId)>,
    unresolved: Option<BundleTypeId>,
    unresolved_refs: usize,
    cenum_synth_repr: usize,
}

impl<'a> Emitter<'a> {
    fn new(reader: &'a DwReader<'a>) -> Self {
        Self {
            reader,
            interner: StringInterner::new(),
            ids: BTreeMap::new(),
            defs: Vec::new(),
            debug_formats: BTreeMap::new(),
            names: Vec::new(),
            pending: VecDeque::new(),
            unresolved: None,
            unresolved_refs: 0,
            cenum_synth_repr: 0,
        }
    }

    /// Build an enumerated [`BitField`], interning its label and value labels.
    fn enum_field(&mut self, name: &str, shift: u8, width: u8, table: &[(u64, &str)]) -> BitField {
        let name = self.interner.intern(name);
        let interner = &mut self.interner;
        let render = FieldRender::Enum(
            table
                .iter()
                .map(|(v, l)| (*v, interner.intern(l)))
                .collect(),
        );
        BitField {
            name,
            shift,
            width: NonZeroU8::new(width),
            render,
        }
    }

    /// Build a single-bit boolean [`BitField`] rendered as `false`/`true`.
    fn bool_field(&mut self, name: &str, shift: u8) -> BitField {
        self.enum_field(name, shift, 1, &[(0, "false"), (1, "true")])
    }

    /// Build an unsigned-integer [`BitField`] covering all bits at and above
    /// `shift` (`width: None`).
    fn uint_tail_field(&mut self, name: &str, shift: u8) -> BitField {
        let name = self.interner.intern(name);
        BitField {
            name,
            shift,
            width: None,
            render: FieldRender::Uint,
        }
    }

    /// parking_lot mutex state byte: bit 0 locked, bit 1 parked.
    fn mutex_byte_decode(&mut self) -> ScalarDecode {
        let locked = self.bool_field("locked", 0);
        let parked = self.bool_field("parked", 1);
        ScalarDecode::Bits(vec![locked, parked])
    }

    /// tokio `Notify` state word: low two bits the notification state, the rest
    /// the `notify_waiters()` generation counter.
    fn notify_state_decode(&mut self) -> ScalarDecode {
        let state = self.enum_field(
            "state",
            0,
            2,
            &[(0, "idle"), (1, "waiting"), (2, "notified")],
        );
        let generation = self.uint_tail_field("generation", 2);
        ScalarDecode::Bits(vec![state, generation])
    }

    /// tokio per-waiter `AtomicNotification` word: kind in bits 0–1, FIFO/LIFO
    /// order in bit 2 (so `notify_one` LIFO reads as the packed value 5).
    fn notification_decode(&mut self) -> ScalarDecode {
        let kind = self.enum_field("kind", 0, 2, &[(0, "none"), (1, "one"), (2, "all")]);
        let order = self.enum_field("order", 2, 1, &[(0, "fifo"), (1, "lifo")]);
        ScalarDecode::Bits(vec![kind, order])
    }

    /// tokio batch-semaphore permit word: bit 0 closed, the rest the available
    /// permit count.
    fn semaphore_permits_decode(&mut self) -> ScalarDecode {
        let closed = self.bool_field("closed", 0);
        let permits = self.uint_tail_field("permits", 1);
        ScalarDecode::Bits(vec![closed, permits])
    }

    /// A boolean byte rendered bare as `false`/`true` (an empty field name, so
    /// no `name=` prefix) — for a bool shown under a record label of its own.
    fn bool_decode(&mut self) -> ScalarDecode {
        ScalarDecode::Bits(vec![self.bool_field("", 0)])
    }

    /// tokio watch `AtomicState`: bit 0 closed, the rest the version counter.
    fn watch_state_decode(&mut self) -> ScalarDecode {
        let closed = self.bool_field("closed", 0);
        let version = self.uint_tail_field("version", 1);
        ScalarDecode::Bits(vec![closed, version])
    }

    /// Build the `queue` field shared by the waiter-mutex formatters (`Notify`
    /// and the bounded-channel `Semaphore`): an intrusive [`DisplayNode::List`]
    /// over the parked `waiter`s, each shown as a one-field record naming what
    /// it is blocked on. `head` reaches the list head (rooted at the formatted
    /// type); `waiter_next` reaches a node's successor and `payload` its
    /// blocked-on word — decoded by `payload_decode` under `payload_label` —
    /// both rooted at `waiter`.
    fn waiter_queue_field(
        &mut self,
        head: Vec<u32>,
        waiter: TypeId,
        waiter_next: Vec<u32>,
        payload_label: &str,
        payload: Vec<u32>,
        payload_decode: ScalarDecode,
    ) -> Field {
        let node_ty = self.reserve(waiter);
        let payload_label = self.interner.intern(payload_label);
        let queue = self.interner.intern("queue");
        Field::Named {
            label: queue,
            node: DisplayNode::List {
                head: head.into(),
                next: waiter_next.into(),
                node: Box::new(DisplayNode::Struct {
                    fields: vec![Field::Named {
                        label: payload_label,
                        node: DisplayNode::Scalar {
                            at: payload.into(),
                            decode: payload_decode,
                        },
                    }],
                }),
                node_ty,
            },
        }
    }

    /// Emit a type (and, transitively, everything it references),
    /// returning its bundle id.
    fn emit(&mut self, id: TypeId) -> BundleTypeId {
        let root = self.reserve(id);
        while let Some((tid, bid)) = self.pending.pop_front() {
            let def = self.convert(tid);
            self.defs[bid.0 as usize] = def;
            if let Some(format) = vec_debug_format(self.reader, tid) {
                let format = crate::bundle::KnownFormat::Vec {
                    pointer: format.pointer.into(),
                    length: format.length.into(),
                    capacity: format.capacity.into(),
                    element: self.reserve(format.element),
                };
                self.debug_formats.insert(bid, DebugFormat::Known(format));
            } else if let Some(format) = btree_map_debug_format(self.reader, tid) {
                let format = crate::bundle::KnownFormat::BTreeMap {
                    root: format.root,
                    length: format.length,
                    root_node: format.root_node.into(),
                    height: format.height,
                    node: format.node.into(),
                    key: self.reserve(format.key),
                    value: self.reserve(format.value),
                    leaf: self.reserve(format.leaf),
                    leaf_len: format.leaf_len,
                    leaf_keys: format.leaf_keys,
                    leaf_values: format.leaf_values,
                    internal: self.reserve(format.internal),
                    internal_data: format.internal_data,
                    internal_edges: format.internal_edges,
                    edge: format.edge.into(),
                };
                self.debug_formats.insert(bid, DebugFormat::Known(format));
            } else if let Some(format) = mpsc_chan_debug_format(self.reader, tid) {
                let format = crate::bundle::KnownFormat::MpscChan {
                    tail: format.tail.into(),
                    index: format.index.into(),
                    head: format.head.into(),
                    start_index: format.start_index.into(),
                    next: format.next.into(),
                    values: format.values.into(),
                    element: self.reserve(format.element),
                };
                self.debug_formats.insert(bid, DebugFormat::Known(format));
            } else if let Some(format) = bounded_semaphore_debug_format(self.reader, tid) {
                // A curated record: the mutex byte, closed flag, permit word,
                // and capacity, plus the intrusive waiter queue as a list whose
                // nodes each show the permits that waiter is blocked on.
                let mutex_decode = self.mutex_byte_decode();
                let permits_decode = self.semaphore_permits_decode();
                let bool_decode = self.bool_decode();
                let queue = self.waiter_queue_field(
                    format.head,
                    format.waiter,
                    format.waiter_next,
                    "permits_needed",
                    format.waiter_state,
                    ScalarDecode::Raw,
                );
                let scalar = |at: Vec<u32>, decode| DisplayNode::Scalar {
                    at: at.into(),
                    decode,
                };
                let named = |label, node| Field::Named { label, node };
                let node = DisplayNode::Struct {
                    fields: vec![
                        named(
                            self.interner.intern("mutex"),
                            scalar(format.mutex, mutex_decode),
                        ),
                        named(
                            self.interner.intern("closed"),
                            scalar(format.closed, bool_decode),
                        ),
                        named(
                            self.interner.intern("permits"),
                            scalar(format.permits, permits_decode),
                        ),
                        named(
                            self.interner.intern("bound"),
                            scalar(format.bound, ScalarDecode::Raw),
                        ),
                        queue,
                    ],
                };
                self.debug_formats.insert(bid, DebugFormat::Node(node));
            } else if let Some(format) = notify_debug_format(self.reader, tid) {
                // A curated record: the notification state word, the waiter
                // mutex byte, and the intrusive waiter queue as a list whose
                // nodes each show whether that waiter has been notified.
                let state_decode = self.notify_state_decode();
                let mutex_decode = self.mutex_byte_decode();
                let notification_decode = self.notification_decode();
                let queue = self.waiter_queue_field(
                    format.head,
                    format.waiter,
                    format.waiter_next,
                    "notification",
                    format.waiter_notification,
                    notification_decode,
                );
                let scalar = |at: Vec<u32>, decode| DisplayNode::Scalar {
                    at: at.into(),
                    decode,
                };
                let named = |label, node| Field::Named { label, node };
                let node = DisplayNode::Struct {
                    fields: vec![
                        named(
                            self.interner.intern("state"),
                            scalar(format.state, state_decode),
                        ),
                        named(
                            self.interner.intern("mutex"),
                            scalar(format.mutex, mutex_decode),
                        ),
                        queue,
                    ],
                };
                self.debug_formats.insert(bid, DebugFormat::Node(node));
            } else if let Some(state) = parking_lot_raw_mutex_debug_format(self.reader, tid) {
                // The whole value is a single decoded lock-state byte.
                let node = DisplayNode::Scalar {
                    at: state,
                    decode: self.mutex_byte_decode(),
                };
                self.debug_formats.insert(bid, DebugFormat::Node(node));
            } else if let Some(format) = semaphore_debug_format(self.reader, tid) {
                // Render the struct, but decode the atomic permit word in place
                // (available count plus closed flag); every other member shows
                // structurally.
                let permits_member = format.permits[0];
                let permits_decode = self.semaphore_permits_decode();
                let fields = format
                    .members
                    .into_iter()
                    .map(|index| {
                        if index == permits_member {
                            Field::Override {
                                index,
                                node: DisplayNode::Scalar {
                                    at: format.permits.clone().into(),
                                    decode: permits_decode.clone(),
                                },
                            }
                        } else {
                            Field::Member(index)
                        }
                    })
                    .collect();
                let node = DisplayNode::Struct { fields };
                self.debug_formats.insert(bid, DebugFormat::Node(node));
            } else if let Some(state) = watch_state_debug_format(self.reader, tid) {
                // The whole value is a single decoded atomic state word: the
                // closed flag in bit 0 and the version counter above it.
                let node = DisplayNode::Scalar {
                    at: state,
                    decode: self.watch_state_decode(),
                };
                self.debug_formats.insert(bid, DebugFormat::Node(node));
            } else if let Some(format) = mpsc_rx_debug_format(self.reader, tid) {
                let format = crate::bundle::KnownFormat::MpscRx {
                    chan_pointer: format.chan_pointer.into(),
                    chan: format.chan.into(),
                    bound: format.bound.into(),
                    permits: format.permits.into(),
                    permits_decode: self.semaphore_permits_decode(),
                };
                self.debug_formats.insert(bid, DebugFormat::Known(format));
            } else if let Some(format) = known_debug_format(self.reader, tid) {
                self.debug_formats.insert(bid, format);
            }
        }
        root
    }

    /// Assign a bundle id for a type, queueing its conversion if new.
    fn reserve(&mut self, id: TypeId) -> BundleTypeId {
        let id = self.reader.canonicalize(id);
        if let Some(&bid) = self.ids.get(&id) {
            return bid;
        }
        if !self.reader.types.contains_key(&id) {
            // A reference to a DIE the reader did not model (fn-pointer
            // targets, mainly). All such references share one explicit
            // `Opaque` entry.
            self.unresolved_refs += 1;
            return self.unresolved_placeholder();
        }
        let fq = self.fq_name(id);
        let bid = self.push_placeholder(fq);
        self.ids.insert(id, bid);
        self.pending.push_back((id, bid));
        bid
    }

    /// The shared `<unresolved>` opaque entry.
    fn unresolved_placeholder(&mut self) -> BundleTypeId {
        if let Some(bid) = self.unresolved {
            return bid;
        }
        let name = self.interner.intern(UNRESOLVED);
        let bid = BundleTypeId(self.defs.len() as u32);
        self.defs.push(TypeDef::Opaque { name, size: None });
        self.names.push(None);
        self.unresolved = Some(bid);
        bid
    }

    /// A named opaque placeholder (missing Cell/Stage/infra).
    fn placeholder(&mut self, name: &str) -> BundleTypeId {
        let name = self.interner.intern(name);
        let bid = BundleTypeId(self.defs.len() as u32);
        self.defs.push(TypeDef::Opaque { name, size: None });
        self.names.push(None);
        bid
    }

    fn push_placeholder(&mut self, name: Option<String>) -> BundleTypeId {
        let bid = BundleTypeId(self.defs.len() as u32);
        let n = self.interner.intern(UNRESOLVED);
        self.defs.push(TypeDef::Opaque {
            name: n,
            size: None,
        });
        self.names.push(name);
        bid
    }

    /// The fully-qualified name of a named type, if it has one.
    fn fq_name(&self, id: TypeId) -> Option<String> {
        fq_name(self.reader, id)
    }

    /// Like [`Emitter::fq_name`], but falls back to `<anon>` for unnamed
    /// types — used for display names, which must always exist.
    fn fq_name_of(&self, id: TypeId) -> String {
        self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned())
    }

    fn intern_opt(&mut self, name: Option<crate::StrId>) -> StrRef {
        let s = name.map(|n| self.reader.strings.get(n)).unwrap_or("<anon>");
        self.interner.intern(s)
    }

    fn convert_member(&mut self, m: &crate::raw_types::RawMember<crate::StrId>) -> MemberDef {
        MemberDef {
            name: self.intern_opt(m.name),
            ty: self.reserve(m.type_id),
            offset: m.offset,
        }
    }

    /// A variant member's declaration coordinates — for coroutines, the
    /// awaited expression's file and line.
    fn member_decl(&mut self, m: &crate::raw_types::RawMember<crate::StrId>) -> Option<SourceLoc> {
        let loc = m.source_loc.as_deref()?;
        let file = loc.file.map(|f| self.reader.strings.get(f))?;
        let line = loc.line?;
        let file = self.interner.intern(file);
        Some(SourceLoc {
            file,
            line: line.get() as u32,
        })
    }

    fn convert(&mut self, id: TypeId) -> TypeDef {
        // `reserve` only queues ids present in the reader.
        let raw = self.reader.types.get(&id).expect("queued type must exist");
        match raw.clone() {
            RawType::Base(b) => TypeDef::Base {
                name: self.intern_opt(b.name),
                size: b.size,
                encoding: b.encoding,
            },
            RawType::Pointer(p) => TypeDef::Pointer {
                name: p.name.map(|n| {
                    let s = self.reader.strings.get(n).to_owned();
                    self.interner.intern(&s)
                }),
                target: self.reserve(p.target_type_id),
            },
            RawType::Array(a) => TypeDef::Array {
                elem: self.reserve(a.elem_type_id),
                count: a.count,
            },
            RawType::Struct(st) => {
                let name = self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned());
                TypeDef::Struct {
                    name: self.interner.intern(&name),
                    size: st.size,
                    members: st.members.iter().map(|m| self.convert_member(m)).collect(),
                }
            }
            RawType::Union(u) => {
                let name = self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned());
                TypeDef::Union {
                    name: self.interner.intern(&name),
                    size: u.size,
                    members: u.members.iter().map(|m| self.convert_member(m)).collect(),
                }
            }
            RawType::Enum(e) => {
                let name = self.fq_name(id).unwrap_or_else(|| "<anon>".to_owned());
                let name = self.interner.intern(&name);
                match &e.shape {
                    RawVariantShape::CStyle {
                        repr_type_id,
                        enumerators,
                    } => {
                        let repr = match repr_type_id {
                            Some(r) => self.reserve(*r),
                            None => {
                                // No DW_AT_type on the enumeration: the
                                // repr is implied by the size. Synthesize
                                // an unsigned base of that width.
                                self.cenum_synth_repr += 1;
                                let n = self.interner.intern("<enum-repr>");
                                let bid = BundleTypeId(self.defs.len() as u32);
                                self.defs.push(TypeDef::Base {
                                    name: n,
                                    size: e.size,
                                    encoding: Encoding::Unsigned,
                                });
                                self.names.push(None);
                                bid
                            }
                        };
                        TypeDef::CEnum {
                            name,
                            size: e.size,
                            repr,
                            enumerators: enumerators
                                .iter()
                                .map(|en| {
                                    let n = self.intern_opt(Some(en.name));
                                    (n, en.value as i128)
                                })
                                .collect(),
                        }
                    }
                    RawVariantShape::Zero => TypeDef::Enum {
                        name,
                        size: e.size,
                        shape: VariantShape {
                            discr: None,
                            variants: Vec::new(),
                        },
                    },
                    RawVariantShape::One(v) => TypeDef::Enum {
                        name,
                        size: e.size,
                        shape: VariantShape {
                            discr: None,
                            variants: vec![VariantDef {
                                name: self.intern_opt(v.member.name),
                                discr_values: None,
                                payload: self.convert_member(&v.member),
                                decl: self.member_decl(&v.member),
                            }],
                        },
                    },
                    RawVariantShape::Many { discr, variants } => TypeDef::Enum {
                        name,
                        size: e.size,
                        shape: VariantShape {
                            discr: discr.as_ref().map(|d| DiscrDef {
                                offset: d.offset,
                                ty: self.reserve(d.type_id),
                            }),
                            variants: variants
                                .iter()
                                .map(|(value, v)| VariantDef {
                                    name: self.intern_opt(v.member.name),
                                    discr_values: value
                                        .map(|x| DiscrValues(vec![DiscrValue::Value(x)])),
                                    payload: self.convert_member(&v.member),
                                    decl: self.member_decl(&v.member),
                                })
                                .collect(),
                        },
                    },
                }
            }
        }
    }

    /// Finish emission: build the sorted name index and the string table.
    /// Returns `(types, strings, opaque_count)`.
    fn finish(mut self) -> (TypeTable, crate::bundle::StringTable, usize) {
        let mut index: Vec<(String, BundleTypeId)> = self
            .names
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.as_ref().map(|n| (n.clone(), BundleTypeId(i as u32))))
            .collect();
        index.sort();
        let name_index = index
            .into_iter()
            .map(|(n, id)| (self.interner.intern(&n), id))
            .collect();

        let opaque = self
            .defs
            .iter()
            .filter(|d| matches!(d, TypeDef::Opaque { .. }))
            .count();

        (
            TypeTable {
                types: self.defs,
                debug_formats: self.debug_formats,
                name_index,
            },
            self.interner.finish(),
            opaque,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StaticRole, VtableTypeHint, dyn_tail_offset, has_dyn_tail, loom_parking_lot_debug_format,
        match_static_symbol, nonzero_debug_format, nonzero_inner_debug_format,
        scalar_newtype_debug_format, scan_vtable_section,
    };
    use crate::raw_types::{NsId, RawMember, RawStruct, RawType};
    use crate::{DwReader, TypeId};
    use gimli::{DebugInfoOffset, UnitSectionOffset};
    use std::collections::{BTreeMap, BTreeSet};

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)))
    }

    fn empty_struct(name: crate::StrId) -> RawType<crate::StrId> {
        RawStruct {
            name: Some(name),
            namespace: None,
            size: 0,
            members: Box::new([]),
            template_params: Box::new([]),
            source_loc: None,
        }
        .into()
    }

    fn wrapper(name: crate::StrId, tail: TypeId) -> RawType<crate::StrId> {
        RawStruct {
            name: Some(name),
            namespace: None,
            size: 16,
            members: Box::new([RawMember {
                name: None,
                offset: 16,
                type_id: tail,
                source_loc: None,
            }]),
            template_params: Box::new([]),
            source_loc: None,
        }
        .into()
    }

    #[test]
    fn test_has_dyn_tail_through_unsized_wrapper() {
        let mut reader = DwReader::default();
        let dyn_id = type_id(1);
        let inner_id = type_id(2);
        let outer_id = type_id(3);
        let plain_id = type_id(4);
        let dyn_name = reader.strings.intern("dyn app::Trait");
        let inner_name = reader
            .strings
            .intern("alloc::sync::ArcInner<dyn app::Trait>");
        let outer_name = reader
            .strings
            .intern("app::Outer<alloc::sync::ArcInner<dyn app::Trait>>");
        let plain_name = reader.strings.intern("app::Plain");
        reader.types.insert(dyn_id, empty_struct(dyn_name));
        reader.types.insert(inner_id, wrapper(inner_name, dyn_id));
        reader.types.insert(outer_id, wrapper(outer_name, inner_id));
        reader.types.insert(plain_id, empty_struct(plain_name));

        assert!(has_dyn_tail(&reader, dyn_id, &mut Vec::new()));
        assert!(has_dyn_tail(&reader, inner_id, &mut Vec::new()));
        assert!(has_dyn_tail(&reader, outer_id, &mut Vec::new()));
        assert!(!has_dyn_tail(&reader, plain_id, &mut Vec::new()));

        // A bare `dyn` sits at offset zero; each wrapper adds its tail
        // member's offset (16), so the erased value is reached by skipping
        // the accumulated sized headers.
        assert_eq!(dyn_tail_offset(&reader, dyn_id, &mut Vec::new()), Some(0));
        assert_eq!(
            dyn_tail_offset(&reader, inner_id, &mut Vec::new()),
            Some(16)
        );
        assert_eq!(
            dyn_tail_offset(&reader, outer_id, &mut Vec::new()),
            Some(32)
        );
        assert_eq!(dyn_tail_offset(&reader, plain_id, &mut Vec::new()), None);
    }

    fn ns_struct(
        namespace: Option<NsId>,
        name: crate::StrId,
        size: u64,
        members: Vec<RawMember<crate::StrId>>,
    ) -> RawType<crate::StrId> {
        RawStruct {
            name: Some(name),
            namespace,
            size,
            members: members.into_boxed_slice(),
            template_params: Box::new([]),
            source_loc: None,
        }
        .into()
    }

    #[test]
    fn test_loom_parking_lot_mutex_is_transparent_over_inner_lock() {
        use crate::bundle::{DebugFormat, Selector};

        let mut reader = DwReader::default();

        // Namespaces: tokio::loom::std::parking_lot and core::marker.
        let mut ns = None;
        for seg in ["tokio", "loom", "std", "parking_lot"] {
            let name = reader.strings.intern(seg);
            ns = Some(reader.namespaces.insert(ns, name));
        }
        let parking_lot = ns.unwrap();
        let core = {
            let name = reader.strings.intern("core");
            reader.namespaces.insert(None, name)
        };
        let marker = {
            let name = reader.strings.intern("marker");
            reader.namespaces.insert(Some(core), name)
        };

        let (m0, m1) = (reader.strings.intern("__0"), reader.strings.intern("__1"));
        let phantom_name = reader.strings.intern("PhantomData<std::sync::Mutex<T>>");
        let inner_name = reader
            .strings
            .intern("lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, T>");
        let mutex_name = reader.strings.intern("Mutex<T>");
        let member = |name, type_id, offset| RawMember {
            name: Some(name),
            offset,
            type_id,
            source_loc: None,
        };

        let phantom_id = type_id(1);
        let inner_id = type_id(2);
        let mutex_id = type_id(3);
        let phantom = ns_struct(Some(marker), phantom_name, 0, vec![]);
        let inner = ns_struct(None, inner_name, 80, vec![]);
        let mutex = ns_struct(
            Some(parking_lot),
            mutex_name,
            80,
            vec![member(m0, phantom_id, 0), member(m1, inner_id, 0)],
        );
        reader.types.insert(phantom_id, phantom);
        reader.types.insert(inner_id, inner);
        reader.types.insert(mutex_id, mutex);

        // The PhantomData marker is skipped; the shim is transparent over the
        // real lock at member index 1.
        assert_eq!(
            loom_parking_lot_debug_format(&reader, mutex_id),
            Some(DebugFormat::Transparent {
                member: Selector::member(1)
            })
        );
        // A bare struct outside the loom parking_lot namespace is untouched.
        assert_eq!(loom_parking_lot_debug_format(&reader, inner_id), None);
    }

    #[test]
    fn test_nonzero_layers_are_transparent_over_the_integer() {
        use crate::bundle::{DebugFormat, Selector};
        use crate::raw_types::{Encoding, RawBase};

        let mut reader = DwReader::default();

        let mut core_num = None;
        for seg in ["core", "num"] {
            let name = reader.strings.intern(seg);
            core_num = Some(reader.namespaces.insert(core_num, name));
        }
        let nonzero_ns = {
            let name = reader.strings.intern("nonzero");
            reader.namespaces.insert(core_num, name)
        };
        let niche_ns = {
            let name = reader.strings.intern("niche_types");
            reader.namespaces.insert(core_num, name)
        };

        let m0 = reader.strings.intern("__0");
        let member = |type_id| RawMember {
            name: Some(m0),
            offset: 0,
            type_id,
            source_loc: None,
        };

        // Exercise a signed width too, to confirm the match is not u64-only.
        let int_id = type_id(1);
        let inner_id = type_id(2);
        let nonzero_id = type_id(3);
        let int_name = reader.strings.intern("i32");
        let inner_name = reader.strings.intern("NonZeroI32Inner");
        let nonzero_name = reader.strings.intern("NonZero<i32>");
        reader.types.insert(
            int_id,
            RawBase {
                name: Some(int_name),
                namespace: None,
                encoding: Encoding::Signed,
                size: 4,
                alignment: None,
            }
            .into(),
        );
        reader.types.insert(
            inner_id,
            ns_struct(Some(niche_ns), inner_name, 4, vec![member(int_id)]),
        );
        reader.types.insert(
            nonzero_id,
            ns_struct(Some(nonzero_ns), nonzero_name, 4, vec![member(inner_id)]),
        );

        assert_eq!(
            nonzero_debug_format(&reader, nonzero_id),
            Some(DebugFormat::Transparent {
                member: Selector::member(0)
            })
        );
        assert_eq!(
            nonzero_inner_debug_format(&reader, inner_id),
            Some(DebugFormat::Transparent {
                member: Selector::member(0)
            })
        );
        // The public wrapper detector does not fire on the inner, nor vice versa.
        assert_eq!(nonzero_debug_format(&reader, inner_id), None);
        assert_eq!(nonzero_inner_debug_format(&reader, nonzero_id), None);
    }

    #[test]
    fn test_scalar_newtype_is_transparent_over_its_value() {
        use crate::bundle::{DebugFormat, Selector};
        use crate::raw_types::{Encoding, RawBase};

        let mut reader = DwReader::default();
        let u64n = reader.strings.intern("u64");
        let u64_id = type_id(1);
        reader.types.insert(
            u64_id,
            RawBase {
                name: Some(u64n),
                namespace: None,
                encoding: Encoding::Unsigned,
                size: 8,
                alignment: None,
            }
            .into(),
        );
        let (m0, m1) = (reader.strings.intern("__0"), reader.strings.intern("__1"));
        let member = |name, type_id, offset| RawMember {
            name: Some(name),
            offset,
            type_id,
            source_loc: None,
        };

        // A tuple newtype over a scalar is transparent over its field.
        let epochn = reader.strings.intern("Epoch");
        let epoch_id = type_id(2);
        reader.types.insert(
            epoch_id,
            ns_struct(None, epochn, 8, vec![member(m0, u64_id, 0)]),
        );
        assert_eq!(
            scalar_newtype_debug_format(&reader, epoch_id),
            Some(DebugFormat::Transparent {
                member: Selector::member(0)
            })
        );

        // A pair is not a wrapper: the scalar does not fill the struct.
        let pairn = reader.strings.intern("Pair");
        let pair_id = type_id(3);
        reader.types.insert(
            pair_id,
            ns_struct(
                None,
                pairn,
                16,
                vec![member(m0, u64_id, 0), member(m1, u64_id, 8)],
            ),
        );
        assert_eq!(scalar_newtype_debug_format(&reader, pair_id), None);

        // Wrapping a non-scalar (a struct) is left alone.
        let wrapn = reader.strings.intern("Wrap");
        let wrap_id = type_id(4);
        reader.types.insert(
            wrap_id,
            ns_struct(None, wrapn, 8, vec![member(m0, epoch_id, 0)]),
        );
        assert_eq!(scalar_newtype_debug_format(&reader, wrap_id), None);
    }

    #[test]
    fn test_scan_vtable_section_uses_drop_and_method_symbols() {
        let drop = 0x1000;
        let method = 0x2000;
        let text_addresses = BTreeSet::from([drop, method]);
        let concrete_by_address = BTreeMap::from([
            (drop, BTreeSet::from(["app::Dropped".to_owned()])),
            (method, BTreeSet::from(["app::NullDrop".to_owned()])),
        ]);
        let data: Vec<u8> = [drop, 24, 8, 0, 0, 16, 8, method]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let mut hints = BTreeSet::new();

        scan_vtable_section(
            &data,
            0,
            true,
            &text_addresses,
            &concrete_by_address,
            &mut hints,
        );

        assert!(hints.contains(&VtableTypeHint {
            name: "app::Dropped".to_owned(),
            size: 24,
        }));
        assert!(hints.contains(&VtableTypeHint {
            name: "app::NullDrop".to_owned(),
            size: 16,
        }));
    }

    // v0-mangled symbols observed in an illumos futurelock release build,
    // whose DWARF omits the `DW_TAG_variable` DIE for these statics.
    #[test]
    fn test_match_waker_vtable_symbol() {
        let sym = "_RNvNtNtNtCsjd01hASgEtw_5tokio7runtime4task5waker12WAKER_VTABLE";
        assert_eq!(match_static_symbol(sym), Some(StaticRole::TaskWakerVtable));
    }

    #[test]
    fn test_match_tls_context_symbol() {
        let sym =
            "_RNvNCNvNtNtCsjd01hASgEtw_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";
        assert_eq!(match_static_symbol(sym), Some(StaticRole::TlsContextKey));
    }

    // Other crates define a `__RUST_STD_INTERNAL_VAL`; only the one nested
    // under `tokio::runtime::context::CONTEXT` is the tokio context key.
    #[test]
    fn test_reject_foreign_internal_val_symbols() {
        let mpmc_context = "_RNvNCNvNvMNtNtNtCsijgp68BdGXk_3std4sync4mpmc7contextNtB8_7Context4with7CONTEXT023___RUST_STD_INTERNAL_VAL";
        let tokio_local =
            "_RNvNCNvNtNtCsjd01hASgEtw_5tokio4task5local7CURRENT023___RUST_STD_INTERNAL_VAL";
        let parking_lot = "_RNvNCNvNvNtCs6eIw0jaMQft_16parking_lot_core11parking_lot16with_thread_data11THREAD_DATA023___RUST_STD_INTERNAL_VAL";
        assert_eq!(match_static_symbol(mpmc_context), None);
        assert_eq!(match_static_symbol(tokio_local), None);
        assert_eq!(match_static_symbol(parking_lot), None);
    }

    #[test]
    fn test_ignore_unrelated_symbols() {
        assert_eq!(match_static_symbol("main"), None);
        assert_eq!(match_static_symbol(""), None);
    }
}

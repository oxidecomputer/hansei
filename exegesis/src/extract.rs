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
    Arm, BinaryIdent, BitField, Bundle, BundleTypeId, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode, DynFutureTable, Field, FieldRender, FutureKind, InfraTypes, MapEntries, MemberDef,
    MemberRef, Meta, Notation, Provenance, ProvenanceTable, ScalarDecode, Selector, Shape,
    SourceLoc, StaticDef, StaticRole, StaticsTable, Step, Stmt, StrRef, StringInterner,
    TaskEntryId, TaskFutureEntry, TaskTable, TypeDef, TypeTable, ValueExpr, VariantDef,
    VariantShape,
};
use std::num::NonZeroU8;

use crate::raw_types::{NsId, RawType, VariantShape as RawVariantShape};
use crate::symbols::normalized_value_index;
use crate::view::{DwView, Func, SourceLocView};
use crate::{DwReader, Encoding, FuncId, TypeId};

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use tracing::{debug, warn};

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
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
    /// Report why a formatter did or did not attach, for every emitted type
    /// whose fully-qualified name contains this substring
    /// (`--explain-format`). See [`explain`].
    pub explain_format: Option<String>,
}

/// Counters describing an extraction run. Anything the extractor skipped,
/// approximated, or could not resolve shows up here — the `Display` form
/// is the `--stats` output.
#[derive(Default, Debug)]
pub struct ExtractStats {
    /// Formatter traces requested with [`ExtractOptions::explain_format`], one
    /// per matching type. Not part of the `Display` form, which is the
    /// `--stats` summary; `exegesis extract --explain-format` renders these
    /// itself, against the bundle the extraction produced.
    pub format_explanations: Vec<FormatExplanation>,
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
    /// Types replaced by an `Opaque` placeholder because a member reached
    /// past the type's declared size (see
    /// `demote_types_with_members_out_of_bounds`).
    pub types_demoted_out_of_bounds: usize,
    /// Type references that resolved to no parsed DIE (each becomes the
    /// shared `<unresolved>` opaque).
    pub unresolved_refs: usize,
    /// C-style enums missing a repr type (one was synthesized).
    pub cenum_synth_repr: usize,
    /// Coroutine enums seen by their state names, and how many of those
    /// carried the `Unresumed` that `drop_members_of_other_states` compares
    /// the rest against. Many seen against none matched means rustc's state
    /// naming moved and the pass is no longer finding its footing.
    pub coroutines_seen: usize,
    pub coroutines_matched: usize,
    /// Coroutine-state members dropped as another state's storage, and
    /// dropped as an exact repeat of one already listed.
    pub state_members_dropped: usize,
    pub state_members_deduplicated: usize,
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
        writeln!(
            f,
            "  demoted (bad layout):   {}",
            self.types_demoted_out_of_bounds
        )?;
        writeln!(f, "  unresolved refs:        {}", self.unresolved_refs)?;
        writeln!(f, "  synthesized enum reprs: {}", self.cenum_synth_repr)?;
        writeln!(f, "coroutines:")?;
        writeln!(f, "  seen:                   {}", self.coroutines_seen)?;
        writeln!(f, "  matched:                {}", self.coroutines_matched)?;
        writeln!(
            f,
            "  members dropped:        {}",
            self.state_members_dropped
        )?;
        writeln!(
            f,
            "  members deduplicated:   {}",
            self.state_members_deduplicated
        )?;
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
            .entry(crate::symbols::normalized_rust_type_name(&name).into_owned())
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
        let Some(candidates) = by_name.get(name.as_ref()) else {
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
            // Mach-O's linker prefixes every global symbol with an
            // underscore, so its tables spell a Rust v0 name `__RNv…`
            // where the DWARF linkage name — and the symbol table of any
            // target the bundle is later resolved against — has `_RNv…`.
            // Undo it here, at the one place symbols enter, so every
            // lookup downstream compares like with like. Left alone, a
            // bundle extracted on macOS carries an empty fingerprint and
            // statics under names no target answers to.
            let underscore_prefixed = obj.format() == object::BinaryFormat::MachO;
            let symbols: Vec<&str> = obj
                .symbols()
                .chain(obj.dynamic_symbols())
                .filter_map(|s| s.name().ok())
                .map(|name| match underscore_prefixed {
                    true => name.strip_prefix('_').unwrap_or(name),
                    false => name,
                })
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
    /// Coroutine env → the `__awaitee` locals of its resume fn: where each
    /// of its awaits is *written*, which for an await produced by a macro
    /// is not where the coroutine type says it is.
    resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
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
        for (t, awaitees) in other.resume_awaitees {
            self.resume_awaitees.entry(t).or_insert(awaitees);
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
    // Sorted by id, i.e. by `.debug_info` offset, because the sweep's
    // "first wins" fields make the order observable and the reader hands
    // functions out in the order of a randomly seeded hash map — the same
    // program would otherwise pick a different `__awaitee` list, resume
    // location, or `poll` declaration on each run.
    let mut funcs: Vec<(FuncId, Func)> = view.functions().collect();
    funcs.sort_unstable_by_key(|&(id, _)| id);
    let funcs: Vec<Func> = funcs.into_iter().map(|(_, func)| func).collect();

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
                let awaitees = func.raw().awaitees.as_ref();
                if !awaitees.is_empty() {
                    out.resume_awaitees.entry(t).or_insert_with(|| {
                        awaitees
                            .iter()
                            .map(|a| {
                                let loc = a.source_loc.as_deref();
                                (
                                    a.type_id,
                                    OwnedLoc {
                                        file: loc
                                            .and_then(|l| l.file)
                                            .map(|f| reader.strings.get(f).to_owned()),
                                        dir: loc
                                            .and_then(|l| l.dir)
                                            .map(|d| reader.strings.get(d).to_owned()),
                                        line: loc.and_then(|l| l.line).map(|n| n.get()),
                                    },
                                )
                            })
                            .collect()
                    });
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
        resume_awaitees,
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

    let mut em = Emitter::new(reader, resume_awaitees, opts.explain_format.clone());

    let mut entries: Vec<TaskFutureEntry> = Vec::new();
    let mut provenance: Vec<Provenance> = Vec::new();
    let mut by_symbol: BTreeMap<String, TaskEntryId> = BTreeMap::new();
    let mut fingerprint: BTreeSet<String> = BTreeSet::new();

    // The fingerprint is resolved against a target's symbol table, so it
    // can only be made of names a symbol table carries. DWARF describes
    // every instantiation the compiler emitted, including ones the
    // linker then dropped for want of a caller — `poll` for tokio's
    // blocking-pool tasks in a program that touches no files, say. Those
    // are absent from this binary and from any target built the same
    // way, so keeping them would fail every well-matched target rather
    // than the mismatched ones the check is for.
    let symtab: BTreeSet<&str> = symbols.iter().map(|s| strip(s)).collect();

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
        fingerprint.extend(
            task.poll_symbols
                .iter()
                .filter(|sym| symtab.contains(sym.as_str()))
                .cloned(),
        );
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
    stats.format_explanations = std::mem::take(&mut em.explanations);
    let (types, strings, counts) = em.finish();
    stats.types_emitted = types.types.len();
    stats.opaque_types = counts.opaque;
    stats.types_demoted_out_of_bounds = counts.demoted;
    stats.coroutines_seen = counts.states.coroutines_seen;
    stats.coroutines_matched = counts.states.coroutines_matched;
    stats.state_members_dropped = counts.states.members_dropped;
    stats.state_members_deduplicated = counts.states.members_deduplicated;

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
    let non_null = struct_of(reader, param)?;
    let ptr_member = non_null.members.first()?;
    let RawType::Pointer(p) = reader.canonical_type(ptr_member.type_id)? else {
        return None;
    };
    let cell_id = reader.canonicalize(p.target_type_id);
    let cell = struct_of(reader, cell_id)?;
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

/// How a type reads in a formatter trace: its name, or its shape when it has
/// none (an anonymous struct, a pointer, an array).
fn type_label(reader: &DwReader<'_>, id: TypeId) -> String {
    if let Some(name) = fq_name(reader, id) {
        return name;
    }
    match reader.canonical_type(id) {
        Some(RawType::Struct(_)) => "an unnamed struct".to_string(),
        Some(RawType::Union(_)) => "an unnamed union".to_string(),
        Some(RawType::Pointer(_)) => "a pointer".to_string(),
        Some(RawType::Array(_)) => "an array".to_string(),
        Some(_) => "an unnamed type".to_string(),
        None => "a type the reader did not model".to_string(),
    }
}

/// The member names of an aggregate, for a formatter trace. Truncated, since
/// the point is to show whether the name a detector wanted is among them.
fn member_labels(
    reader: &DwReader<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
) -> String {
    const SHOWN: usize = 12;
    if members.is_empty() {
        return "no members".to_string();
    }
    let names: Vec<&str> = members
        .iter()
        .take(SHOWN)
        .map(|m| m.name.map_or("<anonymous>", |n| reader.strings.get(n)))
        .collect();
    let rest = members.len().saturating_sub(SHOWN);
    if rest > 0 {
        format!("{} (and {rest} more)", names.join(", "))
    } else {
        names.join(", ")
    }
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

/// Reporting why a formatter did or did not attach to a type.
///
/// A detector fails safe: on any mismatch it returns `None` and the type
/// renders structurally. That is the right behavior and a poor diagnostic —
/// the only evidence is a `debug:` line missing from the dump of a binary
/// with tens of thousands of types, which says nothing about *where* the
/// detector gave up. With `ExtractOptions::explain_format` set, the shared
/// navigators record what they saw while the emitter works on a matching
/// type, and [`Emitter::emit`] keeps the trace.
///
/// The sink is thread-local rather than a reporter threaded through every
/// helper: the emit loop is single-threaded, and a parameter no ordinary
/// extraction reads would spread across every navigation signature.
mod explain {
    use std::cell::RefCell;

    thread_local! {
        static SINK: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    }

    /// Whether a trace is being collected. Checked before a note is
    /// formatted, so an ordinary extraction pays one thread-local read.
    pub(super) fn active() -> bool {
        SINK.with_borrow(Option::is_some)
    }

    /// Add one line to the trace being collected, if any.
    pub(super) fn note(line: String) {
        SINK.with_borrow_mut(|sink| {
            if let Some(lines) = sink {
                lines.push(line);
            }
        });
    }

    /// Run `f` with a trace collected, returning it alongside `f`'s result.
    pub(super) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
        SINK.with_borrow_mut(|sink| *sink = Some(Vec::new()));
        let out = f();
        let lines = SINK.with_borrow_mut(Option::take).unwrap_or_default();
        (out, lines)
    }
}

/// Add a line to the formatter trace when one is being collected. The
/// arguments are formatted only then, so this is free in an ordinary run.
macro_rules! explain {
    ($($arg:tt)*) => {
        if explain::active() {
            explain::note(format!($($arg)*));
        }
    };
}

/// Build a [`Reach`]. `reach![Named("a"), Deref]` reads as the path it describes.
macro_rules! reach {
    ($($step:expr),* $(,)?) => { vec![$($step),*] };
}

/// One type's formatter trace: what the navigators saw while a display program
/// was built for it, and which type it was built for.
///
/// The verdict — the program itself — is deliberately *not* recorded here. It
/// is read back out of the finished bundle by [`FormatExplanation::render`],
/// for two reasons. Rendering a program resolved to member names and byte
/// offsets needs the type table, which is still being built while the trace is
/// collected; and extraction rewrites member lists after programs are attached,
/// so a verdict captured here would describe the program as built rather than
/// as shipped.
#[derive(Debug)]
pub struct FormatExplanation {
    /// The fully-qualified name the type was reported under.
    pub name: String,
    /// The type the trace belongs to, as `exegesis dump` numbers it.
    pub id: BundleTypeId,
    /// What the navigators saw, one line each, in the order they saw it.
    pub trace: Vec<String>,
}

impl FormatExplanation {
    /// The trace as `--explain-format` prints it: the type, what the navigators
    /// saw, then the program `bundle` ended up carrying for it, resolved to the
    /// paths it addresses.
    pub fn render(&self, bundle: &Bundle) -> String {
        use std::fmt::Write as _;
        let mut out = format!("{} [type {}]\n", self.name, self.id.0);
        for line in &self.trace {
            let _ = writeln!(out, "{line}");
        }
        let _ = match bundle.types.debug_formats.get(&self.id) {
            Some(node) => writeln!(
                out,
                "  => {}",
                crate::bundle::describe_node(bundle, self.id, node)
            ),
            None => writeln!(out, "  => no formatter; renders structurally"),
        };
        out
    }
}

/// Recognize a type whose source-level Debug representation is simpler than its
/// private storage layout, and return the display program that renders it —
/// or `None` when the type does not have the shape the detector expects, in
/// which case the type renders structurally.
///
/// Every detector has this one signature, whether or not it uses the
/// [`Emitter`]: a detector that interns a string (a record label, a
/// [`ScalarDecode`] table) or reserves a related type that must be emitted
/// alongside (an `element`, a key/value, a list's node type) needs it, and one
/// that only navigates DWARF opens with `let reader = emitter.reader;`. Keeping
/// the signature uniform is what lets [`BY_NAME`], [`BY_PREFIX`] and
/// [`STRUCTURAL`] be one kind of table, so a detector that later grows a label
/// does not have to move.
type Detector = fn(&mut Emitter<'_>, TypeId) -> Option<DisplayNode>;

/// Detectors keyed by fully-qualified type name with generic arguments
/// stripped. Screening on the name means only the one matching detector runs
/// rather than each in turn, and it is what `--explain-format` reports as the
/// detector it selected — so a detector belongs here whenever a name selects
/// it, and its body then validates only the *structure*. A type named by
/// neither this table nor [`BY_PREFIX`] falls through to [`STRUCTURAL`].
static BY_NAME: &[(&str, Detector)] = &[
    ("&camino::Utf8Path", utf8_path_node),
    ("&str", str_node),
    ("alloc::collections::btree::map::BTreeMap", btree_map_node),
    ("alloc::string::String", string_node),
    ("alloc::vec::Vec", vec_node),
    ("allocator_api2::stable::vec::Vec", vec_node),
    ("camino::Utf8PathBuf", utf8_path_buf_node),
    ("core::cell::UnsafeCell", unsafe_cell_node),
    ("core::net::ip_addr::Ipv4Addr", ip_address_node),
    ("core::net::ip_addr::Ipv6Addr", ip_address_node),
    (
        "core::num::niche_types::UsizeNoHighBit",
        usize_no_high_bit_node,
    ),
    ("core::num::nonzero::NonZero", nonzero_node),
    ("core::ptr::non_null::NonNull", non_null_node),
    ("core::ptr::unique::Unique", unique_node),
    ("core::sync::atomic::Atomic", atomic_node),
    ("core::task::wake::RawWakerVTable", raw_waker_vtable_node),
    ("parking_lot::raw_mutex::RawMutex", raw_mutex_node),
    (
        "tokio::loom::std::unsafe_cell::UnsafeCell",
        loom_unsafe_cell_node,
    ),
    (
        "tokio::sync::batch_semaphore::Semaphore",
        batch_semaphore_node,
    ),
    ("tokio::sync::mpsc::block::Block", mpsc_block_node),
    ("tokio::sync::mpsc::bounded::Receiver", mpsc_handle_node),
    ("tokio::sync::mpsc::bounded::Sender", mpsc_handle_node),
    (
        "tokio::sync::mpsc::bounded::Semaphore",
        bounded_semaphore_node,
    ),
    ("tokio::sync::mpsc::chan::Chan", mpsc_chan_node),
    ("tokio::sync::notify::Notify", notify_node),
    ("tokio::sync::watch::Receiver", watch_receiver_node),
    ("tokio::sync::watch::Sender", watch_sender_node),
    ("tokio::sync::watch::Shared", watch_shared_node),
    ("tokio::sync::watch::state::AtomicState", watch_state_node),
    ("tokio::util::cacheline::CachePadded", cache_padded_node),
    ("tufaceous_artifact::artifact::ArtifactHash", hex_bytes_node),
    ("uuid::Uuid", uuid_node),
];

/// Detectors keyed by a prefix of the *full* name, for a family no single base
/// name spans: a slice carries its element inside the brackets (`&[T]`,
/// `Box<[T]>`, where the `Box<[` prefix is what separates a boxed slice from a
/// thin `Box<T>`), the niche-typed `NonZero` inners are one type per width, and
/// the loom shims live one module per atomic width. A prefix is a looser screen
/// than a name, so these detectors keep the residual check the key cannot
/// express — `NonZeroU32Inner` ends in `Inner`, a loom atomic module has a
/// single segment.
static BY_PREFIX: &[(&str, Detector)] = &[
    ("&[", slice_node),
    ("alloc::boxed::Box<[", slice_node),
    ("core::num::niche_types::NonZero", nonzero_inner_node),
    ("tokio::loom::std::atomic_", loom_atomic_node),
    ("tokio::loom::std::parking_lot::", loom_parking_lot_node),
];

/// Detectors that recognize a type by *shape* alone, tried in order from most
/// to least specific because nothing else separates them. This is the short
/// list on purpose: a detector a name can select belongs in [`BY_NAME`] or
/// [`BY_PREFIX`], where the dispatch is a lookup and `--explain-format` can say
/// which detector ran.
static STRUCTURAL: &[Detector] = &[
    // A `{ pointer, vtable }` pair, then a pointer to a subroutine type.
    dyn_pointer_node,
    function_pointer_node,
    // Least specific: a bare scalar newtype claims a type only if no semantic
    // formatter above it did.
    scalar_newtype_node,
];

/// Try the shape-keyed detectors in order.
fn structural_debug_format(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    STRUCTURAL.iter().find_map(|detector| detector(emitter, id))
}

/// A tuple newtype wrapping a single scalar (`Version(usize)`, `Epoch(u64)`,
/// an id, …) is displayed as that inner value. The scalar must fill the whole
/// struct (any other members are zero-sized), so this only ever collapses a
/// genuine wrapper, never a struct that also carries data. Semantic wrappers
/// (atomics, `NonZero`, …) are claimed by their name-keyed detector first, so
/// this only sees a type no table named.
fn scalar_newtype_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    let scalar = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        matches!(reader.canonical_type(ty), Some(RawType::Base(base))
            if base.size != 0 && base.size == st.size)
    })?;
    transparent(emitter, &st.members, scalar)
}

/// Where a `Vec`-shaped owned buffer keeps its data pointer, length, capacity,
/// and element type. Shared by the two `Vec` spellings [`vec_node`] renders,
/// whose buffers differ in shape but whose display program is identical.
#[derive(Clone, Debug)]
struct VecShape {
    pointer: Selector,
    length: Selector,
    capacity: Selector,
    element: TypeId,
}

/// A `Vec<T, A>`, in either spelling, renders through the `Slice` node: an owned
/// buffer that supplies its capacity for the length check.
fn vec_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let shape = vec_shape(emitter, id).or_else(|| allocator_api2_vec_shape(emitter, id))?;
    Some(DisplayNode::Slice {
        pointer: shape.pointer,
        length: shape.length,
        capacity: Some(shape.capacity),
        element: emitter.reserve(shape.element),
    })
}

fn vec_shape(emitter: &mut Emitter<'_>, id: TypeId) -> Option<VecShape> {
    let reader = emitter.reader;
    let vec = struct_of(reader, id)?;
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

    let (_, buf_member) = unique_member(reader, &vec.members, "buf")?;
    unique_member(reader, &vec.members, "len")?;

    let raw_vec = struct_of(reader, buf_member.type_id)?;
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

    let (_, inner_member) = unique_member(reader, &raw_vec.members, "inner")?;
    let inner = struct_of(reader, inner_member.type_id)?;
    if fq_name(reader, inner_member.type_id)?.split('<').next()? != "alloc::raw_vec::RawVecInner" {
        return None;
    }
    let [inner_alloc] = inner.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(inner_alloc.type_id) != alloc {
        return None;
    }

    let is_byte = |target| is_unsigned_integer(reader, target, 1);
    let (pointer_path, _) = find_unique(
        reader,
        inner_member.type_id,
        Want::PointerTo(&is_byte),
        Through::AnyOffset,
    )?;

    let (_, cap_member) = unique_member(reader, &inner.members, "cap")?;
    let (cap_value, _) = usize_no_high_bit_layout(reader, cap_member.type_id)?;

    // The buffer walk is by name; the pointer was found by shape and the niche
    // newtype's field by position, so both are spliced in and re-addressed.
    let buf = || reach![Named("buf"), Named("inner")];
    let mut pointer = buf();
    pointer.push(Resolved(pointer_path));
    let mut capacity = buf();
    capacity.push(Named("cap"));
    capacity.push(Resolved(Selector::member(cap_value)));
    Some(VecShape {
        pointer: emitter.walk(id, &pointer)?.0,
        length: emitter.walk(id, &reach![Named("len")])?.0,
        capacity: emitter.walk(id, &capacity)?.0,
        element,
    })
}

/// Recognize `allocator_api2::stable::vec::Vec<T, A>`, the `allocator-api2`
/// crate's stable-channel reimplementation of `Vec`. It renders through the
/// same `Slice` node as [`vec_shape`]'s `alloc::vec::Vec`, but its buffer
/// has the pre-`RawVecInner` shape and so needs its own navigation: `buf` is a
/// `RawVec<T, A>` holding `ptr: NonNull<T>` and a plain `cap: usize` directly,
/// with no type-erased `Unique<u8>` and no `Cap` niche newtype. Because the
/// pointer is `NonNull<T>` over the real element (not a `u8` byte pointer), the
/// buffer pointer is matched by its element target rather than by width.
fn allocator_api2_vec_shape(emitter: &mut Emitter<'_>, id: TypeId) -> Option<VecShape> {
    let reader = emitter.reader;
    let vec = struct_of(reader, id)?;
    if fq_name(reader, id)?.split('<').next()? != "allocator_api2::stable::vec::Vec" {
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

    let (_, buf_member) = unique_member(reader, &vec.members, "buf")?;
    unique_member(reader, &vec.members, "len")?;

    let raw_vec = struct_of(reader, buf_member.type_id)?;
    if fq_name(reader, buf_member.type_id)?.split('<').next()?
        != "allocator_api2::stable::raw_vec::RawVec"
    {
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

    // `ptr` and `cap` sit at fixed offsets in `RawVec`, so a zero-offset walk
    // from the buffer yields exactly the one pointer that targets the element
    // type — `ptr.pointer` through the `NonNull<T>` wrapper.
    let is_element = |target| target == element;
    let (pointer_path, _) = find_unique(
        reader,
        buf_member.type_id,
        Want::PointerTo(&is_element),
        Through::ZeroOffset,
    )?;

    unique_member(reader, &raw_vec.members, "cap")?;

    let mut pointer = reach![Named("buf")];
    pointer.push(Resolved(pointer_path));
    Some(VecShape {
        pointer: emitter.walk(id, &pointer)?.0,
        length: emitter.walk(id, &reach![Named("len")])?.0,
        capacity: emitter.walk(id, &reach![Named("buf"), Named("cap")])?.0,
        element,
    })
}

/// Recognize the private node layout of `BTreeMap<K, V, A>` and render it as a
/// `Map` whose entries come from the B-tree walk. The key, value, leaf, and
/// internal node types are all reserved, since the walk renders keys and values
/// and reads both node shapes.
fn btree_map_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    let map = struct_of(reader, id)?;
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
    let is_node_ref = |candidate| is_btree_node_ref(reader, candidate, key, value);
    let (root_node, node_ref) = find_unique(
        reader,
        some.type_id,
        Want::Type(&is_node_ref),
        Through::ZeroOffset,
    )?;
    let node_ref_ty = struct_of(reader, node_ref)?;
    let (_, height_member) = unique_member(reader, &node_ref_ty.members, "height")?;
    if !is_unsigned_integer(reader, height_member.type_id, 8) {
        return None;
    }

    let (_, node_member) = unique_member(reader, &node_ref_ty.members, "node")?;
    let is_leaf_node = |target| is_btree_node(reader, target, "LeafNode", key, value);
    let (node_tail, leaf) = find_unique(
        reader,
        node_member.type_id,
        Want::PointerTo(&is_leaf_node),
        Through::ZeroOffset,
    )?;

    let leaf_ty = struct_of(reader, leaf)?;
    let (_, leaf_len_member) = unique_member(reader, &leaf_ty.members, "len")?;
    if !is_unsigned_integer(reader, leaf_len_member.type_id, 2) {
        return None;
    }
    let (_, keys_member) = unique_member(reader, &leaf_ty.members, "keys")?;
    let (_, values_member) = unique_member(reader, &leaf_ty.members, "vals")?;
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
    let is_internal_node = |target| is_btree_node(reader, target, "InternalNode", key, value);
    let (_, internal) = find_unique(
        reader,
        parent_some.type_id,
        Want::PointerTo(&is_internal_node),
        Through::ZeroOffset,
    )?;
    let internal_ty = struct_of(reader, internal)?;
    let (_, data_member) = unique_member(reader, &internal_ty.members, "data")?;
    if reader.canonicalize(data_member.type_id) != leaf || data_member.offset != 0 {
        return None;
    }
    let (_, edges_member) = unique_member(reader, &internal_ty.members, "edges")?;
    let RawType::Array(edges) = reader.canonical_type(edges_member.type_id)? else {
        return None;
    };
    if edges.count != keys.count + 1 {
        return None;
    }
    let is_leaf = |target| target == leaf;
    let (edge, _) = find_unique(
        reader,
        edges.elem_type_id,
        Want::PointerTo(&is_leaf),
        Through::ZeroOffset,
    )?;

    // Each of the twelve reaches is rooted at whichever type the walk had got
    // to; the three found by shape are spliced in and re-addressed with the
    // rest. Nothing here records a position.
    let mut node_path = reach![Named("node")];
    node_path.push(Resolved(node_tail));
    Some(DisplayNode::Map {
        length: emitter.walk(id, &reach![Named("length")])?.0,
        key: emitter.reserve(key),
        value: emitter.reserve(value),
        entries: Box::new(MapEntries::BTree {
            root: emitter.walk(id, &reach![Named("root")])?.0,
            root_node: emitter.readdress(some.type_id, &root_node)?,
            height: emitter.walk(node_ref, &reach![Named("height")])?.0,
            node: emitter.walk(node_ref, &node_path)?.0,
            leaf: emitter.reserve(leaf),
            leaf_len: emitter.walk(leaf, &reach![Named("len")])?.0,
            leaf_keys: emitter.walk(leaf, &reach![Named("keys")])?.0,
            leaf_values: emitter.walk(leaf, &reach![Named("vals")])?.0,
            internal: emitter.reserve(internal),
            internal_data: emitter.walk(internal, &reach![Named("data")])?.0,
            internal_edges: emitter.walk(internal, &reach![Named("edges")])?.0,
            edge: emitter.readdress(edges.elem_type_id, &edge)?,
        }),
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

/// What a member walk is looking for, and what it reports on arrival.
enum Want<'a> {
    /// A type the predicate accepts, reported as itself.
    Type(&'a dyn Fn(TypeId) -> bool),
    /// A pointer whose target the predicate accepts. The walk lands on the
    /// pointer — so the path stops there rather than crossing it — and
    /// reports the *target*, which is what a caller then navigates.
    PointerTo(&'a dyn Fn(TypeId) -> bool),
}

impl Want<'_> {
    /// How this want reads in a formatter trace.
    fn label(&self) -> &'static str {
        match self {
            Want::Type(_) => "a matching type",
            Want::PointerTo(_) => "a pointer to a matching type",
        }
    }

    /// The type to report for a candidate the walk landed on, or `None` when
    /// it is not what this want is looking for.
    fn accepts(&self, reader: &DwReader<'_>, id: TypeId) -> Option<TypeId> {
        match self {
            Want::Type(pred) => pred(id).then_some(id),
            Want::PointerTo(pred) => {
                let RawType::Pointer(pointer) = reader.canonical_type(id)? else {
                    return None;
                };
                let target = reader.canonicalize(pointer.target_type_id);
                pred(target).then_some(target)
            }
        }
    }
}

/// Which members a walk may descend through.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Through {
    /// Members at offset zero only: the transparent-wrapper chain an atomic,
    /// a cell, or a newtype builds around one datum.
    ZeroOffset,
    /// Every member, for a datum a struct keeps past its own bookkeeping —
    /// the value inside a lock, say.
    AnyOffset,
}

/// A wrapper chain deeper than this is not one; the cap also bounds the walk
/// on a type graph that nests without repeating a type.
const MAX_WRAPPER_DEPTH: usize = 8;

/// The one member path from `root` to what `want` accepts, with the type it
/// reports.
///
/// Uniqueness is the point: two candidates mean this is not the layout the
/// caller recognized, and choosing either would be a guess, so both that and
/// "no candidate" return `None` and the type renders structurally. Every
/// detector that reaches a datum by shape rather than by name goes through
/// here.
fn find_unique(
    reader: &DwReader<'_>,
    root: TypeId,
    want: Want<'_>,
    through: Through,
) -> Option<(Selector, TypeId)> {
    fn walk(
        reader: &DwReader<'_>,
        current: TypeId,
        want: &Want<'_>,
        through: Through,
        path: &mut Vec<u32>,
        seen: &mut Vec<TypeId>,
        found: &mut Vec<(Vec<u32>, TypeId)>,
    ) {
        // One hit past the first is enough to know the answer is ambiguous.
        if found.len() > 1 || path.len() >= MAX_WRAPPER_DEPTH || seen.contains(&current) {
            return;
        }
        if let Some(reported) = want.accepts(reader, current) {
            found.push((path.clone(), reported));
            return;
        }
        let members = match reader.canonical_type(current) {
            Some(RawType::Struct(st)) => st.members.as_ref(),
            Some(RawType::Union(union)) => union.members.as_ref(),
            _ => return,
        };
        seen.push(current);
        for (index, member) in members.iter().enumerate() {
            if through == Through::ZeroOffset && member.offset != 0 {
                continue;
            }
            path.push(index as u32);
            walk(
                reader,
                reader.canonicalize(member.type_id),
                want,
                through,
                path,
                seen,
                found,
            );
            path.pop();
        }
        seen.pop();
    }

    let mut found = Vec::new();
    walk(
        reader,
        reader.canonicalize(root),
        &want,
        through,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut found,
    );
    let [(path, reported)] = found.as_slice() else {
        explain!(
            "  find_unique in {}: {} {} through {}",
            type_label(reader, root),
            if found.is_empty() {
                "found nothing matching".to_string()
            } else {
                format!("found {}+ candidates for", found.len())
            },
            want.label(),
            match through {
                Through::ZeroOffset => "zero-offset members",
                Through::AnyOffset => "any member",
            },
        );
        return None;
    };
    Some((Selector::members(path), *reported))
}

/// The DWARF member a [`MemberRef`] addresses.
///
/// A name in a display program is a [`StrRef`] into the bundle's own string
/// table, so matching one against DWARF means reading it back out of the
/// interner the detector put it in and comparing spellings. The uniqueness
/// rule is [`MemberRef::resolve`]'s, the same one validation and reify apply.
fn raw_member_at<'m>(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    members: &'m [crate::raw_types::RawMember<crate::StrId>],
    at: &MemberRef,
) -> Option<&'m crate::raw_types::RawMember<crate::StrId>> {
    let index = at.resolve(members.len(), |index, name| {
        members[index].name.map(|n| reader.strings.get(n)) == strings.get(name)
    })?;
    members.get(index)
}

/// Walk a [`Selector`] through DWARF from `root`, returning the type it lands
/// on. The DWARF counterpart of the bundle's own `selector_target`; where that
/// one validates a finished bundle, this one lets a detector be held to the
/// same addressing contract while the node is still being built.
fn selector_lands(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    root: TypeId,
    sel: &Selector,
) -> Option<TypeId> {
    let mut cur = reader.canonicalize(root);
    for step in sel.steps() {
        cur = match step {
            Step::Member(at) => {
                let members = match reader.canonical_type(cur)? {
                    RawType::Struct(st) => &st.members,
                    RawType::Union(union) => &union.members,
                    _ => return None,
                };
                reader.canonicalize(raw_member_at(reader, strings, members, at)?.type_id)
            }
            Step::Deref => {
                let RawType::Pointer(pointer) = reader.canonical_type(cur)? else {
                    return None;
                };
                reader.canonicalize(pointer.target_type_id)
            }
        };
    }
    Some(cur)
}

/// Whether DWARF's `id` meets `shape`. This is the [`DwReader`] half of the
/// shared shape table (`crate::bundle::shape`); the bundle's `shape_matches`
/// is the other.
fn raw_shape_matches(reader: &DwReader<'_>, id: TypeId, shape: Shape) -> bool {
    match shape {
        Shape::Word => matches!(raw_type_size(reader, id), Some(1..=8)),
        Shape::Uint(size) => is_unsigned_integer(reader, id, size),
        Shape::PointerSized => raw_type_size(reader, id) == Some(crate::bundle::POINTER_SIZE),
        Shape::Pointer => matches!(reader.canonical_type(id), Some(RawType::Pointer(_))),
        Shape::Array => matches!(reader.canonical_type(id), Some(RawType::Array(_))),
        Shape::Any => true,
    }
}

/// Whether every datum `node` addresses within a value of type `root` is
/// reachable and has the shape its node kind requires.
///
/// This holds a detector to the schema's addressing contract without the
/// detector having to restate it: a formatter that navigated to the wrong
/// member declines here and the type renders structurally, rather than
/// producing a node that only fails when the finished bundle is validated.
///
/// A child node rooted somewhere else — a list element, the target of a
/// pointer hop — is not walked, since its root is a bundle id the detector
/// reserved rather than a `TypeId`; those are checked against the type table
/// on save. Children rendered against this same value are walked.
fn addressing_holds(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    root: TypeId,
    node: &DisplayNode,
) -> bool {
    for addressed in node.addressed() {
        let what = addressed.what;
        if addressed.sel.is_empty() && !addressed.root_allowed {
            explain!("  {what} addresses the value itself, which its node may not do");
            return false;
        }
        let Some(landed) = selector_lands(reader, strings, root, addressed.sel) else {
            explain!("  {what} does not resolve in {}", type_label(reader, root));
            return false;
        };
        if !raw_shape_matches(reader, landed, addressed.shape) {
            explain!(
                "  {what} lands on {}, which is not {}",
                type_label(reader, landed),
                addressed.shape,
            );
            return false;
        }
    }
    match node {
        DisplayNode::Struct { fields } => fields.iter().all(|field| match field {
            Field::Member { node: None, .. } => true,
            Field::Member {
                node: Some(node), ..
            }
            | Field::Synth { node, .. } => addressing_holds(reader, strings, root, node),
        }),
        DisplayNode::Variant { arms, default, .. } => {
            arms.iter().all(|arm| {
                arm.payload
                    .as_ref()
                    .is_none_or(|node| addressing_holds(reader, strings, root, node))
            }) && default
                .as_ref()
                .is_none_or(|node| addressing_holds(reader, strings, root, node))
        }
        _ => true,
    }
}

/// One step of a [`Reach`]: how a detector says to get somewhere, before
/// anything has looked at DWARF.
#[derive(Clone)]
enum ReachStep<'a> {
    /// The uniquely-named member. What a detector reaches for whenever the
    /// spelling is stable, which is nearly always.
    Named(&'a str),
    /// Follow the pointer reached so far.
    Deref,
    /// Descend the zero-offset wrapper chain to the one value of this shape.
    ///
    /// tokio reaches an atomic's word through a different chain of loom,
    /// `UnsafeCell` and atomic shims depending on how the compiler spelled the
    /// atomic, so a pattern says what it is looking for rather than naming
    /// wrappers it cannot predict. Two candidates decline just as none do.
    PeelTo(Shape),
    /// Descend the zero-offset wrapper chain to the `T` a `Wrapper<T>`
    /// declares. What an atomic peels to is its own parameter rather than any
    /// fixed shape — `AtomicPtr` stores a pointer, `AtomicUsize` a word — so
    /// the type the wrapper names is the only thing that identifies it.
    PeelToParam,
    /// The same search for a declared `T`, but through *any* member rather
    /// than the zero-offset chain.
    ///
    /// Where peeling unwraps transparent layers, this digs past a type's own
    /// bookkeeping: a lock keeps its guarded `T` beside a raw lock word, so no
    /// chain of wrappers leads to it. Which bookkeeping there is varies by
    /// platform and lock implementation, so the `T` is searched for rather
    /// than navigated to. Uniqueness still decides: two candidates decline
    /// exactly as none do.
    FindParam,
    /// Continue along a path something else already resolved — how a shape
    /// helper's selectors are anchored under the member that holds them.
    Resolved(Selector),
}

/// A path from a type to a datum inside it, outermost step first.
type Reach<'a> = Vec<ReachStep<'a>>;

// A path is written far more often than it is matched on, so the steps are
// spelled bare: `reach![Named("head"), Deref]` reads as the path it describes.
use ReachStep::{Deref, FindParam, Named, PeelTo, PeelToParam, Resolved};

/// The shape of a `usize`, which most of what a path peels to is.
const WORD: Shape = Shape::Uint(crate::bundle::POINTER_SIZE);

impl Emitter<'_> {
    /// Address the uniquely-named member `name` of `root`, checking it is
    /// there.
    fn member_named(&mut self, root: TypeId, name: &str) -> Option<MemberRef> {
        let members = aggregate_members(self.reader, root)?;
        if unique_member(self.reader, members, name).is_none() {
            explain!(
                "  no unique member `{name}` in {}, which has {}",
                type_label(self.reader, root),
                member_labels(self.reader, members),
            );
            return None;
        }
        Some(MemberRef::Named(self.intern(name)))
    }

    /// Resolve a pattern path against `root`: the selector it lowers to and
    /// the type it lands on.
    fn walk(&mut self, root: TypeId, path: &Reach<'_>) -> Option<(Selector, TypeId)> {
        let mut steps = Vec::new();
        let mut cur = self.reader.canonicalize(root);
        for step in path {
            match step {
                Named(name) => {
                    let members = aggregate_members(self.reader, cur).or_else(|| {
                        explain!(
                            "  path stopped at `{name}`, since {} is not a struct or union",
                            type_label(self.reader, cur),
                        );
                        None
                    })?;
                    let Some((_, member)) = unique_member(self.reader, members, name) else {
                        explain!(
                            "  no unique member `{name}` in {}, which has {}",
                            type_label(self.reader, cur),
                            member_labels(self.reader, members),
                        );
                        return None;
                    };
                    cur = self.reader.canonicalize(member.type_id);
                    steps.push(Step::Member(MemberRef::Named(self.intern(name))));
                }
                ReachStep::Deref => {
                    let Some(RawType::Pointer(pointer)) = self.reader.canonical_type(cur) else {
                        explain!(
                            "  path dereferences {}, which is not a pointer",
                            type_label(self.reader, cur),
                        );
                        return None;
                    };
                    cur = self.reader.canonicalize(pointer.target_type_id);
                    steps.push(Step::Deref);
                }
                ReachStep::PeelTo(shape) => {
                    let reader = self.reader;
                    let accepts = |id| raw_shape_matches(reader, id, *shape);
                    let (found, landed) =
                        self.search(cur, &accepts, Through::ZeroOffset, &shape.to_string())?;
                    steps.extend(found.0);
                    cur = landed;
                }
                ReachStep::PeelToParam => {
                    let (found, landed) = self.search_param(cur, Through::ZeroOffset)?;
                    steps.extend(found.0);
                    cur = landed;
                }
                ReachStep::FindParam => {
                    let (found, landed) = self.search_param(cur, Through::AnyOffset)?;
                    steps.extend(found.0);
                    cur = landed;
                }
                ReachStep::Resolved(sel) => {
                    let Some(landed) = selector_lands(self.reader, &self.interner, cur, sel) else {
                        explain!(
                            "  an already-resolved path does not reach into {}",
                            type_label(self.reader, cur),
                        );
                        return None;
                    };
                    steps.extend(self.readdress(cur, sel)?.0);
                    cur = landed;
                }
            }
        }
        Some((Selector(steps), cur))
    }

    /// Descend from `root` to the one value `accepts` takes, name-addressed —
    /// `through` decides whether that is the zero-offset wrapper chain or any
    /// member. `want` names what was looked for, for the trace when nothing or
    /// several were found.
    fn search(
        &mut self,
        root: TypeId,
        accepts: &dyn Fn(TypeId) -> bool,
        through: Through,
        want: &str,
    ) -> Option<(Selector, TypeId)> {
        let Some((found, landed)) = find_unique(self.reader, root, Want::Type(accepts), through)
        else {
            explain!(
                "  no single {want} is stored in {}",
                type_label(self.reader, root),
            );
            return None;
        };
        Some((self.readdress(root, &found)?, landed))
    }

    /// Search for the `T` the type at `root` declares, either way through.
    fn search_param(&mut self, root: TypeId, through: Through) -> Option<(Selector, TypeId)> {
        let reader = self.reader;
        let Some(param) = struct_of(reader, root).and_then(|st| sole_param_target(reader, st))
        else {
            explain!(
                "  {} does not declare a sole parameter `T`",
                type_label(reader, root),
            );
            return None;
        };
        let accepts = |id| id == param;
        self.search(root, &accepts, through, &type_label(reader, param))
    }

    /// Every member structural display would show — those of nonzero size — as
    /// `Field`s in declaration order, with the named ones computed instead of
    /// rendered.
    ///
    /// A zero-sized member carries no value and structural display elides it,
    /// so a record that listed it would differ from the plain view for no
    /// reason. An override naming a member that is not there, or is elided,
    /// declines: it means the detector is describing a layout this type does
    /// not have.
    ///
    /// Synthesized fields are the caller's business — it splices them around
    /// the result — which is why this is a helper and not a kind of field list.
    /// A record that is "the type itself plus one computed field" and one that
    /// is "the type itself plus a synthetic field" then cost the same.
    fn visible_fields(
        &mut self,
        root: TypeId,
        mut overrides: Vec<(&str, DisplayNode)>,
    ) -> Option<Vec<Field>> {
        let reader = self.reader;
        let members = aggregate_members(reader, root)?;
        let mut fields = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            if raw_type_size(reader, member.type_id).unwrap_or(0) == 0 {
                continue;
            }
            let name = member.name.map(|name| reader.strings.get(name));
            let at = self.address(members, index as u32);
            fields.push(
                match overrides.iter().position(|(want, _)| Some(*want) == name) {
                    Some(position) => Field::computed(at, overrides.remove(position).1),
                    None => Field::member(at),
                },
            );
        }
        overrides.is_empty().then_some(fields)
    }

    /// The type the pointer `ty` targets. Declines, narrating, when it is not
    /// a pointer — the one thing a caller crossing one has to establish before
    /// it can root anything at the far side.
    fn pointee(&self, ty: TypeId) -> Option<TypeId> {
        let Some(RawType::Pointer(pointer)) = self.reader.canonical_type(ty) else {
            explain!(
                "  {} is not a pointer, so nothing is behind it",
                type_label(self.reader, ty),
            );
            return None;
        };
        Some(self.reader.canonicalize(pointer.target_type_id))
    }

    /// [`Emitter::pointee`], reserved, for a node that names the type behind a
    /// pointer rather than rooting a path there.
    fn behind(&mut self, ty: TypeId) -> Option<BundleTypeId> {
        let target = self.pointee(ty)?;
        Some(self.reserve(target))
    }

    /// Re-address a path that was found rather than declared, so it names what
    /// it can.
    ///
    /// A shape walk reports positions, since what it matched on was a type and
    /// not a name. Converting each hop through [`Emitter::address`] here is
    /// what makes a discovered path as durable as a declared one — and it is
    /// the only place that conversion happens, so no walk can forget it.
    fn readdress(&mut self, root: TypeId, found: &Selector) -> Option<Selector> {
        let mut steps = Vec::with_capacity(found.steps().len());
        let mut cur = self.reader.canonicalize(root);
        for step in found.steps() {
            match step {
                Step::Member(at) => {
                    let members = aggregate_members(self.reader, cur)?;
                    let index = at.resolve(members.len(), |index, name| {
                        members[index].name.map(|n| self.reader.strings.get(n))
                            == self.interner.get(name)
                    })?;
                    cur = self.reader.canonicalize(members[index].type_id);
                    steps.push(Step::Member(self.address(members, index as u32)));
                }
                Step::Deref => {
                    let RawType::Pointer(pointer) = self.reader.canonical_type(cur)? else {
                        return None;
                    };
                    cur = self.reader.canonicalize(pointer.target_type_id);
                    steps.push(Step::Deref);
                }
            }
        }
        Some(Selector(steps))
    }

    /// The type a pattern path lands on, for a screen tighter than the shape
    /// the node itself requires.
    fn landed(&mut self, root: TypeId, path: &Reach<'_>) -> Option<TypeId> {
        Some(self.walk(root, path)?.1)
    }
}

/// The members of `id`, or `None` when it is not an aggregate.
fn aggregate_members<'r>(
    reader: &'r DwReader<'_>,
    id: TypeId,
) -> Option<&'r [crate::raw_types::RawMember<crate::StrId>]> {
    match reader.canonical_type(id)? {
        RawType::Struct(st) => Some(&st.members),
        RawType::Union(union) => Some(&union.members),
        _ => None,
    }
}

fn function_pointer_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let RawType::Pointer(pointer) = reader.canonical_type(id)? else {
        return None;
    };
    reader
        .is_subroutine_type(pointer.target_type_id)
        .then_some(DisplayNode::Symbol {
            at: Selector::default(),
        })
}

fn raw_waker_vtable_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // Render the whole struct, replacing each function-pointer member's value
    // with a `Symbol` node (its address and resolved name) while keeping the
    // member's own name. That each member really is a pointer is the `Symbol`
    // node's own requirement, checked once the program is built. The fields are
    // emitted in RawWakerVTable's declared order (clone, wake, wake_by_ref,
    // drop) regardless of DWARF member order.
    let mut fields = Vec::new();
    for name in ["clone", "wake", "wake_by_ref", "drop"] {
        let at = emitter.member_named(id, name)?;
        let node = DisplayNode::Symbol {
            at: emitter.walk(id, &reach![Named(name)])?.0,
        };
        fields.push(Field::computed(at, node));
    }
    Some(DisplayNode::Struct { fields })
}

fn ip_address_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // Both addresses reach this detector; the name says how wide the array is.
    let expected_octets = match fq_name(reader, id).as_deref()? {
        "core::net::ip_addr::Ipv4Addr" => 4,
        "core::net::ip_addr::Ipv6Addr" => 16,
        _ => return None,
    };
    // The octet count is what tells the two apart, and the node's own
    // requirement is only that the path reaches an array.
    let octets = || reach![Named("octets")];
    if !is_byte_array(emitter, id, &octets(), Some(expected_octets)) {
        return None;
    }
    Some(DisplayNode::Bytes {
        at: emitter.walk(id, &octets())?.0,
        notation: Notation::IpAddr,
    })
}

/// A `uuid::Uuid` is a newtype over `[u8; 16]`, rendered in the hyphenated form
/// its own `Display` produces. Sixteen bytes is also an `Ipv6Addr`, so the
/// notation is what separates them, not the layout.
fn uuid_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let bytes = || reach![Named("__0")];
    if !is_byte_array(emitter, id, &bytes(), Some(16)) {
        return None;
    }
    Some(DisplayNode::Bytes {
        at: emitter.walk(id, &bytes())?.0,
        notation: Notation::Uuid,
    })
}

/// A newtype over a byte array whose value is a digest — a TUF artifact hash, a
/// build id — rendered as the lowercase hex everything else that prints one
/// uses, so an id read out of a core can be matched against a log line or a
/// manifest. Any length: SHA-1 is 20 bytes, SHA-256 and BLAKE3 are 32.
fn hex_bytes_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let bytes = || reach![Named("__0")];
    if !is_byte_array(emitter, id, &bytes(), None) {
        return None;
    }
    Some(DisplayNode::Bytes {
        at: emitter.walk(id, &bytes())?.0,
        notation: Notation::Hex,
    })
}

/// Whether `at` reaches an inline array of unsigned bytes — exactly `count` of
/// them when a count is given, any nonzero number otherwise.
///
/// A `Bytes` node requires an array and validation requires the length its
/// notation spells, but only at save time — so a detector that would emit the
/// wrong length screens for it here and declines instead.
fn is_byte_array(
    emitter: &mut Emitter<'_>,
    id: TypeId,
    at: &Reach<'_>,
    count: Option<u64>,
) -> bool {
    let Some(landed) = emitter.landed(id, at) else {
        return false;
    };
    let reader = emitter.reader;
    matches!(reader.canonical_type(landed), Some(RawType::Array(array))
        if count.unwrap_or(array.count) == array.count
            && array.count > 0
            && is_unsigned_integer(reader, array.elem_type_id, 1))
}

fn str_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // The `Str` node accepts any data pointer, since camino's is typed; a `&str`
    // is the byte-erased one, and screening for that here is what keeps this
    // detector from claiming a fat pointer over something else.
    let bytes = emitter.landed(id, &reach![Named("data_ptr"), Deref])?;
    if !is_unsigned_integer(emitter.reader, bytes, 1) {
        return None;
    }
    Some(DisplayNode::Str {
        pointer: emitter.walk(id, &reach![Named("data_ptr")])?.0,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
    })
}

/// A `&[T]` slice reference or a `Box<[T]>` boxed slice. Both are laid out as a
/// `{ data_ptr: *T, length: usize }` fat pointer — identical to `&str` but with
/// an arbitrary element type and no capacity — so both render through the
/// `Slice` node with `capacity: None`, the borrowed counterpart to an owned
/// `Vec`.
fn slice_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // The dispatch table screens by name (`&[` / `alloc::boxed::Box<[`); a thin
    // `Box<T>` has no `[` and `&str`/`String` are UTF-8, so neither reaches
    // here. This describes only the fat-pointer structure.
    let (pointer, ptr_ty) = emitter.walk(id, &reach![Named("data_ptr")])?;
    Some(DisplayNode::Slice {
        pointer,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
        element: emitter.behind(ptr_ty)?,
    })
}

fn string_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // A `String` is a `Vec<u8>` behind a single member, so its data pointer,
    // length, and capacity are the Vec's own paths anchored at the `vec`
    // member. It renders exactly as a `&str` with the capacity checked, so it
    // reuses the `Str` node with the capacity supplied.
    let vec = emitter.landed(id, &reach![Named("vec")])?;
    let shape = vec_shape(emitter, vec)?;
    if !is_unsigned_integer(emitter.reader, shape.element, 1) {
        return None;
    }
    buffer_node(emitter, id, &reach![Named("vec")], shape)
}

/// The `Str` program an owned UTF-8 buffer renders through: a `Vec<u8>`'s own
/// paths, anchored under the walk that reaches the vector.
fn buffer_node(
    emitter: &mut Emitter<'_>,
    root: TypeId,
    prefix: &Reach<'_>,
    shape: VecShape,
) -> Option<DisplayNode> {
    let under = |emitter: &mut Emitter<'_>, sel| {
        let mut path: Reach<'_> = prefix.iter().map(ReachStep::clone).collect();
        path.push(Resolved(sel));
        Some(emitter.walk(root, &path)?.0)
    };
    Some(DisplayNode::Str {
        pointer: under(emitter, shape.pointer)?,
        length: under(emitter, shape.length)?,
        capacity: Some(under(emitter, shape.capacity)?),
    })
}

/// A borrowed `&camino::Utf8Path` is a `{ data_ptr, length }` fat pointer over a
/// guaranteed-UTF-8 byte buffer, laid out exactly like `&str` — only the data
/// pointer is typed `*Utf8Path` rather than `*u8`. It renders through the same
/// `Str` node with no capacity.
fn utf8_path_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Str {
        pointer: emitter.walk(id, &reach![Named("data_ptr")])?.0,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
    })
}

/// An owned `camino::Utf8PathBuf` wraps a `std::path::PathBuf`, which nests
/// `OsString`/`Buf` down to a `Vec<u8>` behind four transparent single-member
/// wrappers (`__0` → `inner` → `inner` → `inner`). Like `String` it is a
/// guaranteed-UTF-8 `Vec<u8>`, so it reuses the same `Str` node with the
/// capacity checked, prefixing the Vec's own paths with the wrapper chain.
fn utf8_path_buf_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let prefix = reach![Named("__0"), Named("inner"), Named("inner"), Named("inner"),];
    let vec = emitter.landed(id, &prefix)?;
    let shape = vec_shape(emitter, vec)?;
    if !is_unsigned_integer(emitter.reader, shape.element, 1) {
        return None;
    }
    buffer_node(emitter, id, &prefix, shape)
}

/// Whether `id` is parking_lot's raw mutex. A caller that reached one behind
/// tokio's loom shim has had no dispatch key screen it.
fn is_raw_mutex(reader: &DwReader<'_>, id: TypeId) -> bool {
    fq_name(reader, id).as_deref() == Some("parking_lot::raw_mutex::RawMutex")
}

/// The raw mutex's single lock-state byte, reached under `prefix`. It sits in
/// a one-byte atomic, which the compiler spells either generically or as a
/// concrete `AtomicU8`, so the byte is peeled to rather than named.
fn mutex_byte_path(mut prefix: Reach<'_>) -> Reach<'_> {
    prefix.push(PeelTo(Shape::Uint(1)));
    prefix
}

/// A `parking_lot::raw_mutex::RawMutex` is a single decoded lock-state byte
/// (`LOCKED_BIT`/`PARKED_BIT`), shown in place of the whole value.
fn raw_mutex_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // The dispatch table screens by name; this describes only the structure.
    // The state is a single-byte atomic, whichever way the compiler spelled it.
    let decode = emitter.mutex_byte_decode();
    Some(DisplayNode::Scalar {
        at: emitter
            .walk(id, &mutex_byte_path(reach![Named("state")]))?
            .0,
        decode,
    })
}

/// Render a `tokio::sync::notify::Notify` as a curated record: the notification
/// state word, the waiter mutex byte, and the intrusive waiter queue as a list
/// whose nodes each show whether that waiter has been handed a notification.
fn notify_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The notification state word, an atomic `usize` behind tokio's loom shim.
    let state = emitter.walk(id, &reach![Named("state"), PeelTo(WORD)])?.0;

    // The waiter list lives behind the `waiters` mutex. tokio wraps it in a loom
    // shim over parking_lot's `lock_api::Mutex`; navigate the shim (`__1`) to the
    // real mutex, whose `raw` is the parking_lot RawMutex and whose `data` (an
    // `UnsafeCell`, member `value`) holds the `LinkedList` directly (there is no
    // `Waitlist` wrapper as in the batch semaphore). Reach the RawMutex's single
    // state byte through its atomic wrapper by walking to the zero-offset `u8`,
    // which works whether the compiler emitted the atomic as the generic
    // `Atomic<u8>` or the concrete `AtomicU8`.
    let raw = reach![Named("waiters"), Named("__1"), Named("raw")];
    if !is_raw_mutex(reader, emitter.landed(id, &raw)?) {
        return None;
    }
    let mutex = emitter.walk(id, &mutex_byte_path(raw))?.0;

    let (head, _) = emitter.walk(
        id,
        &reach![
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("head")
        ],
    )?;

    // The queue is a `LinkedList<Waiter, Waiter>`; its node type is the `Waiter`.
    let (_, queue_ty) = emitter.walk(
        id,
        &reach![
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value")
        ],
    )?;
    let list = struct_of(reader, queue_ty)?;
    let param = list.template_params.last()?;
    let waiter = reader.canonicalize(param.type_id);
    if fq_name(reader, waiter).as_deref() != Some("tokio::sync::notify::Waiter") {
        return None;
    }

    // Rooted at the `Waiter`: its atomic `notification` word (whether it has been
    // handed a notification) and its successor pointer (`pointers.inner.value.next`).
    let waiter_notification = emitter
        .walk(waiter, &reach![Named("notification"), PeelTo(WORD)])?
        .0;
    let (waiter_next, _) = emitter.walk(
        waiter,
        &reach![
            Named("pointers"),
            Named("inner"),
            Named("value"),
            Named("next")
        ],
    )?;

    let state_decode = emitter.notify_state_decode();
    let mutex_decode = emitter.mutex_byte_decode();
    let notification_decode = emitter.notification_decode();
    let queue = emitter.waiter_queue_field(
        head,
        waiter,
        waiter_next,
        "notification",
        waiter_notification,
        notification_decode,
    );
    let state = emitter.named_scalar("state", state, state_decode);
    let mutex = emitter.named_scalar("mutex", mutex, mutex_decode);
    Some(DisplayNode::Struct {
        fields: vec![state, mutex, queue],
    })
}

/// Render a `tokio::sync::batch_semaphore::Semaphore` structurally, but decode
/// its atomic permit word in place (available count plus closed flag); every
/// other member shows as itself.
/// Whether `id` is the batch semaphore. A caller that reached one by walking
/// has had no dispatch key screen it, so the name is checked where it is
/// reached rather than in the detector the key already selected.
fn is_batch_semaphore(reader: &DwReader<'_>, id: TypeId) -> bool {
    fq_name(reader, id).as_deref() == Some("tokio::sync::batch_semaphore::Semaphore")
}

/// The batch semaphore's atomic permit word, reached under `prefix`.
fn permits_path(mut prefix: Reach<'_>) -> Reach<'_> {
    prefix.push(Named("permits"));
    prefix.push(PeelTo(WORD));
    prefix
}

fn batch_semaphore_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // Render the semaphore as itself, with the permit word decoded in place.
    let decode = emitter.semaphore_permits_decode();
    let permits = DisplayNode::Scalar {
        at: emitter.walk(id, &reach![Named("permits"), PeelTo(WORD)])?.0,
        decode,
    };
    Some(DisplayNode::Struct {
        fields: emitter.visible_fields(id, vec![("permits", permits)])?,
    })
}

/// A `tokio::sync::watch::state::AtomicState` is a single decoded atomic state
/// word: the closed flag in bit 0 and the version counter above it.
fn watch_state_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let decode = emitter.watch_state_decode();
    Some(DisplayNode::Scalar {
        at: emitter.walk(id, &reach![Named("__0"), PeelTo(WORD)])?.0,
        decode,
    })
}

fn mpsc_block_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // Render the block as itself, but replace the `values` array with a
    // written-slot count derived from the readiness bitmap in
    // `header.ready_slots` — an atomic `usize` behind the usual loom/cell
    // shims. A block cannot tell a still-queued message from a consumed one,
    // so the values themselves are not shown.
    let values = DisplayNode::SlotCount {
        bitmap: emitter
            .walk(
                id,
                &reach![Named("header"), Named("ready_slots"), PeelTo(WORD)],
            )?
            .0,
        slots: emitter.walk(id, &reach![Named("values"), Named("__0")])?.0,
    };
    Some(DisplayNode::Struct {
        fields: emitter.visible_fields(id, vec![("values", values)])?,
    })
}

/// Render the `Arc`-backed payload of a watch channel as the four things worth
/// knowing about it: the published value, the packed version-and-closed state,
/// and the live receiver and sender counts.
///
/// The value is guarded by a `RwLock` whose bookkeeping differs by platform and
/// lock implementation, so the `T` is searched for rather than navigated to.
/// The other three members render through their own formatters — `AtomicState`
/// decodes itself, and each reference count is an atomic that aliases its word
/// — so the pattern only has to name them.
///
/// The two `Notify` members are deliberately absent: `notify_rx` alone is eight
/// of them, and a watch channel's waiters are reported by the tasks parked on
/// it rather than by the channel they are parked on.
fn watch_shared_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Struct {
        fields: watch_shared_fields(emitter, id)?,
    })
}

/// The record a watch channel's shared state renders as. Shared by
/// [`watch_shared_node`], which is rooted at the allocation, and
/// [`watch_sender_node`], which reaches the same allocation across an `Arc` —
/// so the two cannot drift into showing different things.
fn watch_shared_fields(emitter: &mut Emitter<'_>, root: TypeId) -> Option<Vec<Field>> {
    let value = DisplayNode::Alias {
        at: emitter.walk(root, &reach![Named("value"), FindParam])?.0,
        follow_pointers: true,
    };
    let mut fields = vec![Field::computed(emitter.member_named(root, "value")?, value)];
    for name in ["state", "ref_count_rx", "ref_count_tx"] {
        fields.push(Field::member(emitter.member_named(root, name)?));
    }
    Some(fields)
}

/// Render a `tokio::sync::watch::Sender<T>` as the shared state it publishes
/// to. A sender is one member — an `Arc` of that state — so showing the `Arc`,
/// its `ArcInner` and the strong/weak header before anything useful costs three
/// levels of nesting for no information. Hop the pointer instead and render the
/// state itself.
fn watch_sender_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // A sized `Arc<T>` points at `ArcInner<T> { strong, weak, data: T }`, so the
    // hop is the `NonNull`'s raw pointer and the step past the header is `data`.
    let (at, ptr) = emitter.walk(id, &reach![Named("shared"), Named("ptr"), Named("pointer")])?;
    let pointee = emitter.pointee(ptr)?;
    let (via, target) = emitter.walk(pointee, &reach![Named("data")])?;
    Some(DisplayNode::Pointer {
        at,
        via,
        then: Box::new(DisplayNode::Struct {
            fields: watch_shared_fields(emitter, target)?,
        }),
    })
}

/// Render a `tokio::sync::watch::Receiver<T>` as its one-slot inbox — an unseen
/// value and an independent closed flag — computed by comparing the receiver's
/// observed version with the `Arc`-backed published version. This composes from
/// `Variant` + `ValueExpr` rather than a bespoke node: the state and value words
/// are reached by selectors that cross the `Arc` via a `Deref` step.
fn watch_receiver_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    let receiver = struct_of(reader, id)?;
    let [element_param] = receiver.template_params.as_ref() else {
        return None;
    };
    if element_param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let element = reader.canonicalize(element_param.type_id);

    // Receiver::version is a transparent `Version(usize)` wrapper.
    let observed = emitter.walk(id, &reach![Named("version"), PeelTo(WORD)])?.0;

    // Receiver::shared is an Arc. Its NonNull raw pointer targets ArcInner,
    // whose `data` member is the actual Shared<T> allocation payload.
    let (shared, ptr_ty) =
        emitter.walk(id, &reach![Named("shared"), Named("ptr"), Named("pointer")])?;
    let RawType::Pointer(ptr) = reader.canonical_type(ptr_ty)? else {
        return None;
    };
    let arc_inner = reader.canonicalize(ptr.target_type_id);
    let (shared_data, shared_ty) = emitter.walk(arc_inner, &reach![Named("data")])?;
    if fq_name(reader, shared_ty)?.split('<').next()? != "tokio::sync::watch::Shared" {
        return None;
    }
    let shared_def = struct_of(reader, shared_ty)?;
    let [shared_element] = shared_def.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(shared_element.type_id) != element {
        return None;
    }

    // The packed state is an atomic usize behind Tokio's loom wrappers.
    let state = emitter
        .walk(shared_ty, &reach![Named("state"), PeelTo(WORD)])?
        .0;

    // The value is behind the platform-selected RwLock implementation. Search
    // its concrete aggregate storage for the one T rather than baking in the
    // std/parking_lot wrapper chain.
    let (_, value_member) = unique_member(reader, &shared_def.members, "value")?;
    let is_element = |candidate| candidate == element;
    let (value_tail, _) = find_unique(
        reader,
        value_member.type_id,
        Want::Type(&is_element),
        Through::AnyOffset,
    )?;
    let mut value_path = reach![Named("value")];
    value_path.push(Resolved(value_tail));
    let value = emitter.walk(shared_ty, &value_path)?.0;

    // Reserve the element type so the `Some(T)` alias resolves even if nothing
    // else pulls it into the type graph.
    emitter.reserve(element);

    // A selector from the receiver across its `Arc`: the `shared` pointer, a
    // `Deref` to the `ArcInner`, then `shared_data` (past the strong/weak
    // header) and the tail within the `Shared<T>`.
    let cross_arc = |tail: Selector| shared.clone().deref().then(shared_data.clone()).then(tail);
    let state_sel = cross_arc(state);
    let value_sel = cross_arc(value);
    let closed_mask = 1u64;

    // unseen = observed != (state & !closed_mask), the published version; render
    // the newest value as `Some(T)` when it differs.
    let unseen = DisplayNode::Variant {
        discriminant: ValueExpr::Ne(
            Box::new(ValueExpr::Read(observed)),
            Box::new(ValueExpr::And(
                Box::new(ValueExpr::Read(state_sel.clone())),
                Box::new(ValueExpr::Not(Box::new(ValueExpr::Const(closed_mask)))),
            )),
        ),
        arms: vec![
            Arm {
                value: 0,
                label: Some(emitter.intern("None")),
                payload: None,
            },
            Arm {
                value: 1,
                label: Some(emitter.intern("Some")),
                payload: Some(Box::new(DisplayNode::Alias {
                    at: value_sel,
                    follow_pointers: true,
                })),
            },
        ],
        default: None,
    };
    // closed is the low state bit, independent of the version.
    let closed = DisplayNode::Variant {
        discriminant: ValueExpr::And(
            Box::new(ValueExpr::Read(state_sel)),
            Box::new(ValueExpr::Const(closed_mask)),
        ),
        arms: vec![
            Arm {
                value: 0,
                label: Some(emitter.intern("false")),
                payload: None,
            },
            Arm {
                value: 1,
                label: Some(emitter.intern("true")),
                payload: None,
            },
        ],
        default: None,
    };
    Some(DisplayNode::Struct {
        fields: vec![
            Field::Synth {
                label: emitter.intern("unseen"),
                node: unseen,
            },
            Field::Synth {
                label: emitter.intern("closed"),
                node: closed,
            },
        ],
    })
}

/// Render a bounded mpsc handle — a `Sender` or the `Receiver` — as the channel
/// it is a handle on, reached across its `Arc`: a [`DisplayNode::Pointer`] hop
/// to the `Chan`, whose own record is prefixed with the decoded `capacity` (the
/// bounded semaphore's `bound`) and `free` (the batch semaphore's permit word).
///
/// One detector serves both because they navigate identically: a `Receiver`'s
/// `chan` is a `chan::Rx` and a `Sender`'s a `chan::Tx`, and each holds the
/// shared allocation at `inner`. They also want the same answers — how much
/// room is left, whether the far end is gone, what is in flight — so neither
/// gets a record of its own.
///
/// A sender cannot pick itself out of what it sees: `queued` is every sender's
/// messages, and a sender blocked in `send` is one of the semaphore's waiters
/// with nothing marking which.
fn mpsc_handle_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    // Handle → Rx/Tx → Arc → the `NonNull` raw pointer at `ptr.pointer`, which
    // targets the `ArcInner<Chan>` allocation.
    let (chan_pointer, ptr_ty) = emitter.walk(
        id,
        &reach![
            Named("chan"),
            Named("inner"),
            Named("ptr"),
            Named("pointer")
        ],
    )?;
    let arcinner = emitter.pointee(ptr_ty)?;

    // Skip the Arc's strong/weak header to the `data` field: the `Chan`.
    let (chan, chan_ty) = emitter.walk(arcinner, &reach![Named("data")])?;
    if !fq_name(reader, chan_ty)
        .as_deref()
        .is_some_and(|name| name.starts_with("tokio::sync::mpsc::chan::Chan<"))
    {
        return None;
    }

    // Capacity is the bounded semaphore's `bound`, a plain `usize`.
    let (bound, bound_ty) = emitter.walk(chan_ty, &reach![Named("semaphore"), Named("bound")])?;
    if !is_unsigned_integer(reader, bound_ty, crate::bundle::POINTER_SIZE) {
        return None;
    }

    // Available buffer slots live in the batch semaphore's atomic `permits`
    // word. Reach the inner `batch_semaphore::Semaphore`, then walk to its
    // permit `usize`, and root the path at the `Chan`.
    let inner = reach![Named("semaphore"), Named("semaphore")];
    if !is_batch_semaphore(reader, emitter.landed(chan_ty, &inner)?) {
        return None;
    }
    let permits = emitter.walk(chan_ty, &permits_path(inner.clone()))?.0;

    // The channel behind the pointer renders exactly as a standalone `Chan`
    // would; reuse its navigation so the queued walk and member list are shared.
    let chan_shape = mpsc_chan_shape(emitter, chan_ty)?;

    let permits_decode = emitter.semaphore_permits_decode();
    let capacity = emitter.named_scalar("capacity", bound, ScalarDecode::Raw);
    let free = emitter.named_scalar("free", permits, permits_decode);
    let mut fields = vec![capacity, free];
    fields.extend(emitter.chan_struct_fields(chan_ty, chan_shape)?);
    Some(DisplayNode::Pointer {
        at: chan_pointer,
        via: chan,
        then: Box::new(DisplayNode::Struct { fields }),
    })
}

/// Render a `tokio::sync::mpsc::bounded::Semaphore` as a curated record: the
/// mutex byte, closed flag, permit word, and capacity, plus the intrusive waiter
/// queue as a list whose nodes each show the permits that waiter is blocked on.
fn bounded_semaphore_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    // The capacity is the bounded semaphore's own `bound`, a plain `usize`.
    let (bound, bound_ty) = emitter.walk(id, &reach![Named("bound")])?;
    if !is_unsigned_integer(reader, bound_ty, crate::bundle::POINTER_SIZE) {
        return None;
    }

    // The available permits are the inner batch semaphore's atomic word.
    let inner = reach![Named("semaphore")];
    if !is_batch_semaphore(reader, emitter.landed(id, &inner)?) {
        return None;
    }
    let permits = emitter.walk(id, &permits_path(inner))?.0;

    // The waiter list lives behind the batch semaphore's `waiters` mutex. tokio
    // wraps it in a loom shim over parking_lot's `lock_api::Mutex`; navigate the
    // shim (`__1`) to the real mutex, whose `raw` is the parking_lot RawMutex and
    // whose `data` (an `UnsafeCell`, member `value`) holds the `Waitlist`. Reach
    // the RawMutex's single state byte through its atomic wrapper by walking to
    // the zero-offset `u8`, which works whether the compiler emitted the atomic
    // as the generic `Atomic<u8>` or the concrete `AtomicU8`.
    let raw = reach![
        Named("semaphore"),
        Named("waiters"),
        Named("__1"),
        Named("raw")
    ];
    if !is_raw_mutex(reader, emitter.landed(id, &raw)?) {
        return None;
    }
    let mutex = emitter.walk(id, &mutex_byte_path(raw))?.0;

    let (closed, closed_ty) = emitter.walk(
        id,
        &reach![
            Named("semaphore"),
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("closed")
        ],
    )?;
    if !matches!(reader.canonical_type(closed_ty), Some(RawType::Base(base)) if base.size == 1) {
        return None;
    }

    let (head, _) = emitter.walk(
        id,
        &reach![
            Named("semaphore"),
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("queue"),
            Named("head")
        ],
    )?;

    // The queue is a `LinkedList<Waiter, Waiter>`; its node type is the `Waiter`.
    let (_, queue_ty) = emitter.walk(
        id,
        &reach![
            Named("semaphore"),
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("queue")
        ],
    )?;
    let list = struct_of(reader, queue_ty)?;
    let param = list.template_params.last()?;
    let waiter = reader.canonicalize(param.type_id);
    if fq_name(reader, waiter).as_deref() != Some("tokio::sync::batch_semaphore::Waiter") {
        return None;
    }

    // Rooted at the `Waiter`: its atomic `state` word (permits still needed) and
    // its successor pointer (`pointers.inner.value.next`).
    let waiter_state = emitter
        .walk(waiter, &reach![Named("state"), PeelTo(WORD)])?
        .0;
    let (waiter_next, _) = emitter.walk(
        waiter,
        &reach![
            Named("pointers"),
            Named("inner"),
            Named("value"),
            Named("next")
        ],
    )?;

    let mutex_decode = emitter.mutex_byte_decode();
    let bool_decode = emitter.bool_decode();
    let permits_decode = emitter.semaphore_permits_decode();
    let queue = emitter.waiter_queue_field(
        head,
        waiter,
        waiter_next,
        "permits_needed",
        waiter_state,
        ScalarDecode::Raw,
    );
    let mutex = emitter.named_scalar("mutex", mutex, mutex_decode);
    let closed = emitter.named_scalar("closed", closed, bool_decode);
    let permits = emitter.named_scalar("permits", permits, permits_decode);
    let bound = emitter.named_scalar("bound", bound, ScalarDecode::Raw);
    Some(DisplayNode::Struct {
        fields: vec![mutex, closed, permits, bound, queue],
    })
}

/// Sum the byte offsets `selector` walks within `ty`, returning the datum's
/// total offset and the type it lands on. A [`DisplayNode::CustomList`] bakes
/// block-relative offsets as `Const`s (the block base is a runtime word), so a
/// selector produced by [`field_path`] becomes a plain number here. Only member
/// steps have an offset to sum: a [`Step::Deref`] leaves the value being
/// rendered, so a selector containing one has no offset within `ty` and is
/// rejected.
fn path_offset(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    ty: TypeId,
    selector: &Selector,
) -> Option<(u64, TypeId)> {
    let mut cur = reader.canonicalize(ty);
    let mut offset = 0u64;
    for step in selector.steps() {
        let Step::Member(at) = step else {
            return None;
        };
        let members = match reader.canonical_type(cur)? {
            RawType::Struct(st) => &st.members,
            RawType::Union(u) => &u.members,
            _ => return None,
        };
        let member = raw_member_at(reader, strings, members, at)?;
        offset = offset.checked_add(member.offset)?;
        cur = reader.canonicalize(member.type_id);
    }
    Some((offset, cur))
}

/// Where a `tokio::sync::mpsc::chan::Chan` keeps the state its `queued` walk
/// needs, plus the members it shows structurally. Shared by the standalone
/// `Chan` formatter ([`mpsc_chan_node`]) and the `Receiver` ([`mpsc_rx_node`]),
/// which renders the same record behind a pointer hop.
struct ChanShape {
    /// Value-anchored selectors seeding the walk's loop variables.
    tail: Selector,
    index: Selector,
    head: Selector,
    /// Byte offsets of a block's fields, baked into the CustomList program as
    /// constants since the block base is a runtime pointer.
    start_index_offset: u64,
    next_offset: u64,
    values_offset: u64,
    /// Slot stride and per-block slot count of the inline values array.
    stride: u64,
    count: u64,
    element: TypeId,
}

/// A channel is a struct whose first field is the synthetic `queued` block-chain
/// walk; the rest are its real members.
fn mpsc_chan_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let shape = mpsc_chan_shape(emitter, id)?;
    Some(DisplayNode::Struct {
        fields: emitter.chan_struct_fields(id, shape)?,
    })
}

fn mpsc_chan_shape(emitter: &mut Emitter<'_>, id: TypeId) -> Option<ChanShape> {
    let reader = emitter.reader;
    // Both callers screen by name; this validates only the structure.
    // Sender write position and receiver read position, plus the receiver's
    // head block pointer. The rx fields sit behind CachePadded/UnsafeCell
    // wrappers; navigate them by name.
    // `tail_position` is a (shared) atomic usize; `index` is a plain usize on
    // the single-consumer receiver. Walk to the stored word either way.
    let tail = emitter
        .walk(
            id,
            &reach![
                Named("tx"),
                Named("value"),
                Named("tail_position"),
                PeelTo(WORD)
            ],
        )?
        .0;
    let index = emitter
        .walk(
            id,
            &reach![
                Named("rx_fields"),
                Named("__0"),
                Named("value"),
                Named("list"),
                Named("index"),
                PeelTo(WORD)
            ],
        )?
        .0;
    let (head, head_ty) = emitter.walk(
        id,
        &reach![
            Named("rx_fields"),
            Named("__0"),
            Named("value"),
            Named("list"),
            Named("head"),
            Named("pointer")
        ],
    )?;
    let RawType::Pointer(head_ptr) = reader.canonical_type(head_ty)? else {
        return None;
    };
    let block = reader.canonicalize(head_ptr.target_type_id);

    // Paths rooted at the block type.
    let (start_index, _) = emitter.walk(block, &reach![Named("header"), Named("start_index")])?;
    // `next` is an `AtomicPtr`; walk the atomic wrappers to the raw pointer.
    let next = emitter
        .walk(
            block,
            &reach![Named("header"), Named("next"), PeelTo(Shape::Pointer)],
        )?
        .0;
    let (values, values_ty) = emitter.walk(block, &reach![Named("values"), Named("__0")])?;
    let RawType::Array(values_arr) = reader.canonical_type(values_ty)? else {
        return None;
    };

    // The block base is a runtime pointer, so its fields are reached by Load at
    // constant offsets rather than selectors; resolve those offsets and the
    // slot array's stride/count here.
    let start_index_offset = path_offset(reader, &emitter.interner, block, &start_index)?.0;
    let next_offset = path_offset(reader, &emitter.interner, block, &next)?.0;
    let values_offset = path_offset(reader, &emitter.interner, block, &values)?.0;
    let stride = raw_type_size(reader, values_arr.elem_type_id)?;
    let count = values_arr.count;

    // `element` is the block's message type `T`.
    let bst = struct_of(reader, block)?;
    let [param] = bst.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let element = reader.canonicalize(param.type_id);

    // The channel renders as a struct: the synthetic `queued` field followed
    // by its real members. Structural display skips zero-sized members, so
    // enumerate over the full list and keep the surviving indices.
    Some(ChanShape {
        tail,
        index,
        head,
        start_index_offset,
        next_offset,
        values_offset,
        stride,
        count,
        element,
    })
}

// Compact builders for the mpsc `queued` CustomList program below. The value
// language is verbose to spell with `Box::new`; these keep the program legible.
fn ve_var(id: u32) -> ValueExpr {
    ValueExpr::Var(id)
}
fn ve_const(n: u64) -> ValueExpr {
    ValueExpr::Const(n)
}
fn ve_add(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Add(Box::new(a), Box::new(b))
}
fn ve_sub(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Sub(Box::new(a), Box::new(b))
}
fn ve_mul(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Mul(Box::new(a), Box::new(b))
}
fn ve_lt(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Lt(Box::new(a), Box::new(b))
}
fn ve_load(addr: ValueExpr) -> ValueExpr {
    ValueExpr::Load {
        addr: Box::new(addr),
        size: crate::bundle::POINTER_SIZE as u32,
    }
}

/// Build the synthetic `queued` field's node: a [`DisplayNode::CustomList`] that
/// walks the mpsc block chain and emits the live `[index, tail)` messages,
/// reproducing the retired bespoke `MpscChan` leaf from the general value
/// language. Loop variables are `0 = cur` (the read index, advanced per
/// message), `1 = tail`, and `2 = block` (the current block pointer). A block's
/// fields are read with `Load` at constant offsets because the block base is a
/// runtime word, not a member of the rendered value.
#[allow(clippy::too_many_arguments)]
fn mpsc_queued_node(
    tail: Selector,
    index: Selector,
    head: Selector,
    start_index_offset: u64,
    next_offset: u64,
    values_offset: u64,
    stride: u64,
    count: u64,
    element: BundleTypeId,
) -> DisplayNode {
    // `block->start_index`, recomputed at each use (there is no `start` var).
    let start = || ve_load(ve_add(ve_var(2), ve_const(start_index_offset)));
    DisplayNode::CustomList {
        vars: vec![
            ValueExpr::Read(index), // 0: cur = read index
            ValueExpr::Read(tail),  // 1: tail
            ValueExpr::Read(head),  // 2: block = head pointer
        ],
        condition: ValueExpr::And(
            Box::new(ve_lt(ve_var(0), ve_var(1))),
            Box::new(ValueExpr::Ne(Box::new(ve_var(2)), Box::new(ve_const(0)))),
        ),
        body: vec![
            // A block starting past cur is malformed; stop before the offset
            // subtraction below would underflow.
            Stmt::Break {
                cond: ve_lt(ve_var(0), start()),
            },
            Stmt::If {
                // cur - start < slots: the message lives in this block.
                cond: ve_lt(ve_sub(ve_var(0), start()), ve_const(count)),
                then: vec![
                    // Emit values[cur - start] at values_offset + i*stride.
                    Stmt::Emit {
                        at: ve_add(
                            ve_var(2),
                            ve_add(
                                ve_const(values_offset),
                                ve_mul(ve_sub(ve_var(0), start()), ve_const(stride)),
                            ),
                        ),
                    },
                    Stmt::Set {
                        var: 0,
                        value: ve_add(ve_var(0), ve_const(1)),
                    },
                ],
                // Past this block: follow the successor pointer.
                otherwise: vec![Stmt::Set {
                    var: 2,
                    value: ve_load(ve_add(ve_var(2), ve_const(next_offset))),
                }],
            },
        ],
        element,
    }
}

/// Recognize rustc's DWARF representation of a Rust trait-object wide
/// pointer. The bundle records both member indices and the vtable header
/// ordering so reify never guesses from the private field name or bakes in
/// rustc's slot numbers independently.
fn dyn_pointer_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;

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

    // Both members were found by shape — the screens above are what identify
    // them — so their addresses come from the one place a found member becomes
    // an address.
    let pointer = emitter.address(&st.members, pointer_index as u32);
    let vtable = emitter.address(&st.members, vtable_index as u32);
    Some(DisplayNode::DynPointer {
        pointer: Selector(vec![Step::Member(pointer)]),
        vtable: Selector(vec![Step::Member(vtable)]),
        drop_in_place: 0,
        size: 1,
        align: 2,
        tail_offset,
    })
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

/// tokio pads a field out to a cache line by wrapping it in a struct whose one
/// member is the value; show the value, so the padding does not read as a level
/// of structure that is not there.
fn cache_padded_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Alias {
        at: emitter.walk(id, &reach![Named("value")])?.0,
        follow_pointers: true,
    })
}

fn unsafe_cell_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let st = struct_of(emitter.reader, id)?;
    let (member, _) = unsafe_cell_layout(emitter.reader, id)?;
    transparent(emitter, &st.members, member)
}

/// The member index and `T` of a `core::cell::UnsafeCell<T>`, or `None` if `id`
/// is not one. The name check stays here because the loom shims reach a cell as
/// their own member, where no dispatch table has screened it for them.
fn unsafe_cell_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let st = struct_of(reader, id)?;
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::cell" || !name.starts_with("UnsafeCell<") || !name.ends_with('>') {
        return None;
    }
    let target = sole_param_target(reader, st)?;
    let member = zero_offset_member(reader, &st.members, Some("value"), |ty| {
        reader.canonicalize(ty) == target
    })?;
    Some((member, target))
}

/// tokio's loom shim wraps a `core::cell::UnsafeCell<T>` in a newtype over the
/// same `T`; display it as the cell, which is itself transparent.
fn loom_unsafe_cell_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    let target = sole_param_target(reader, st)?;
    let cell = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        unsafe_cell_layout(reader, ty).is_some_and(|(_, inner)| inner == target)
    })?;
    transparent(emitter, &st.members, cell)
}

fn loom_atomic_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // The prefix key reaches every `atomic_<width>` module; require the single
    // segment and the `Atomic*` type name it cannot express.
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let atomic_module = namespace.strip_prefix("tokio::loom::std::atomic_")?;
    if atomic_module.is_empty() || atomic_module.contains("::") {
        return None;
    }
    let name = st.name.map(|name| reader.strings.get(name))?;
    if !name.starts_with("Atomic") {
        return None;
    }
    // The shim holds the real atomic in an `UnsafeCell`, so accept a member
    // only when a `core::sync::atomic::Atomic<_>` is what the cell contains.
    let inner = zero_offset_member(reader, &st.members, Some("inner"), |ty| {
        unsafe_cell_layout(reader, ty).is_some_and(|(_, atomic)| is_generic_atomic(reader, atomic))
    })?;
    transparent(emitter, &st.members, inner)
}

/// tokio's `loom::std::parking_lot` shims are newtypes that pair a
/// `PhantomData` marker with the real parking_lot lock (`Mutex`, `RwLock`,
/// `Condvar`, and their guards). Display them as the inner lock so the
/// loom scaffolding does not obscure it.
fn loom_parking_lot_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // The prefix key spans the whole shim module — which is the point, since
    // every type in it is a wrapper — but it also admits a submodule the key
    // cannot exclude, so require the module itself.
    if st.namespace.map(|ns| ns_path(reader, ns))? != "tokio::loom::std::parking_lot" {
        return None;
    }
    // Any member name will do, since the shims spell the lock differently; what
    // identifies it is being the one member at offset zero that is not a marker.
    let lock = zero_offset_member(reader, &st.members, None, |ty| {
        !fq_name(reader, reader.canonicalize(ty))
            .is_some_and(|name| name.starts_with("core::marker::PhantomData"))
    })?;
    transparent(emitter, &st.members, lock)
}

fn non_null_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let st = struct_of(emitter.reader, id)?;
    let (member, _) = non_null_layout(emitter.reader, id)?;
    transparent(emitter, &st.members, member)
}

/// The member index and `T` of a `core::ptr::non_null::NonNull<T>`, or `None` if
/// `id` is not one. Like [`unsafe_cell_layout`] this keeps its name check, for
/// [`unique_node`], which reaches a `NonNull` as its own member.
fn non_null_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let st = struct_of(reader, id)?;
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::ptr::non_null" || !name.starts_with("NonNull<") || !name.ends_with('>') {
        return None;
    }
    let target = sole_param_target(reader, st)?;
    let member = zero_offset_member(reader, &st.members, Some("pointer"), |ty| {
        matches!(reader.canonical_type(ty), Some(RawType::Pointer(pointer))
            if reader.canonicalize(pointer.target_type_id) == target)
    })?;
    Some((member, target))
}

/// `core::ptr::unique::Unique<T>` wraps a `NonNull<T>`, itself transparent over
/// the pointer.
fn unique_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    let target = sole_param_target(reader, st)?;
    let pointer = zero_offset_member(reader, &st.members, Some("pointer"), |ty| {
        non_null_layout(reader, ty).is_some_and(|(_, inner)| inner == target)
    })?;
    transparent(emitter, &st.members, pointer)
}

fn usize_no_high_bit_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let st = struct_of(emitter.reader, id)?;
    let (member, _) = usize_no_high_bit_layout(emitter.reader, id)?;
    transparent(emitter, &st.members, member)
}

/// The member index and integer type of a `core::num::niche_types::UsizeNoHighBit`,
/// or `None` if `id` is not one. Keeps its name check for
/// [`allocator_api2_vec_shape`], which reaches one as a capacity member.
fn usize_no_high_bit_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    if fq_name(reader, id).as_deref() != Some("core::num::niche_types::UsizeNoHighBit") {
        return None;
    }
    let st = struct_of(reader, id)?;
    let member = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        is_unsigned_integer(reader, ty, crate::bundle::POINTER_SIZE)
    })?;
    let integer = reader.canonicalize(st.members[member as usize].type_id);
    Some((member, integer))
}

fn is_integer(reader: &DwReader<'_>, id: TypeId) -> bool {
    matches!(
        reader.canonical_type(id),
        Some(RawType::Base(base)) if matches!(base.encoding, Encoding::Signed | Encoding::Unsigned)
    )
}

/// `core::num::nonzero::NonZero<T>` is a newtype over a niche-typed integer
/// wrapper (`NonZero{U,I}<width>Inner`). Display it as the wrapped integer;
/// paired with [`nonzero_inner_node`] the two layers collapse to the
/// value. Handles every width and signedness.
fn nonzero_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // Whatever the width, the wrapped inner is the whole value.
    let inner = zero_offset_member(reader, &st.members, Some("__0"), |_| true)?;
    transparent(emitter, &st.members, inner)
}

/// The niche-typed inner of a `NonZero<T>`
/// (`core::num::niche_types::NonZero{U,I}<width>Inner`), transparent over its
/// integer field.
fn nonzero_inner_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // The prefix key admits any `niche_types::NonZero*`; only the `*Inner`
    // wrappers are transparent over an integer.
    let name = st.name.map(|name| reader.strings.get(name))?;
    if !name.ends_with("Inner") {
        return None;
    }
    let value = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        is_integer(reader, ty)
    })?;
    transparent(emitter, &st.members, value)
}

/// The index of the unique member at offset zero named `name` — or of whatever
/// name, when that is `None` — whose type `accept`s.
///
/// Zero and several both give `None`: a wrapper with two candidate members is
/// not one this can see through, so an ambiguous layout fails closed the same
/// way a renamed member does.
fn zero_offset_member(
    reader: &DwReader<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
    name: Option<&str>,
    accept: impl Fn(TypeId) -> bool,
) -> Option<u32> {
    let mut matches = members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && name.is_none_or(|want| member.name.map(|n| reader.strings.get(n)) == Some(want))
            && accept(member.type_id)
    });
    let (index, _) = matches.next()?;
    matches.next().is_none().then_some(index as u32)
}

/// The struct `id` canonically names, or `None` if it is not a struct. This is a
/// detector's usual first move: a formatter for a named Rust type is a formatter
/// for an aggregate, and one handed anything else declines.
fn struct_of<'r>(
    reader: &'r DwReader<'_>,
    id: TypeId,
) -> Option<&'r crate::raw_types::RawStruct<crate::StrId>> {
    match reader.canonical_type(id)? {
        RawType::Struct(st) => Some(st),
        _ => None,
    }
}

/// The `T` of a wrapper declared `Wrapper<T>`, canonicalized, or `None` if the
/// type does not have exactly that one parameter. A transparent wrapper's
/// member has to *be* this type: checking it is what stops a detector from
/// aliasing whatever else happens to sit at offset zero.
fn sole_param_target(
    reader: &DwReader<'_>,
    st: &crate::raw_types::RawStruct<crate::StrId>,
) -> Option<TypeId> {
    let [param] = st.template_params.as_ref() else {
        return None;
    };
    (param.name.map(|name| reader.strings.get(name)) == Some("T"))
        .then(|| reader.canonicalize(param.type_id))
}

/// A transparent wrapper displays as the one member that *is* its value, so it
/// renders through that member and chases it if it is a pointer. The ten
/// wrappers std and tokio's loom shims interpose all reduce to this; what
/// differs between them is only which member [`zero_offset_member`] accepts.
/// (An atomic is not one of them: it aliases its value without chasing it, and
/// reaches it through a whole wrapper chain, peeling to its own parameter.)
fn transparent(
    emitter: &mut Emitter<'_>,
    members: &[crate::raw_types::RawMember<crate::StrId>],
    member: u32,
) -> Option<DisplayNode> {
    let at = emitter.address(members, member);
    Some(DisplayNode::Alias {
        at: Selector(vec![Step::Member(at)]),
        follow_pointers: true,
    })
}

fn atomic_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // An atomic aliases its stored value but does not chase it: an `AtomicPtr`'s
    // `Debug` reports the address it holds, so `follow_pointers` is false.
    Some(DisplayNode::Alias {
        at: emitter.walk(id, &reach![PeelToParam])?.0,
        follow_pointers: false,
    })
}

/// Whether `id` is the generic `core::sync::atomic::Atomic<T>` spelling, the
/// one tokio's loom shim wraps. A binary also emits concrete `AtomicU8` and
/// `AtomicUsize` types, which declare no `T`; a caller after the word one of
/// those stores peels to a shape instead.
fn is_generic_atomic(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(st) = struct_of(reader, id) else {
        return false;
    };
    let (Some(namespace), Some(name)) = (
        st.namespace.map(|ns| ns_path(reader, ns)),
        st.name.map(|name| reader.strings.get(name)),
    ) else {
        return false;
    };
    namespace == "core::sync::atomic"
        && name.starts_with("Atomic<")
        && name.ends_with('>')
        && sole_param_target(reader, st).is_some()
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

    // A DWARF sweep can name a symbol the binary does not have. The
    // CONTEXT thread-local is emitted once per codegen unit, and the DIE
    // that survives need not be the one whose symbol did: on Linux the
    // DWARF names `CONTEXT::{K#0}::{closure#1}` while the symbol table
    // keeps `{closure#0}`, and the two mangle differently. A name the
    // symtab does not have is no use to a consumer that resolves it by
    // name, so drop it here and let the symbol table answer instead.
    let symtab: BTreeSet<&str> = symbols.iter().map(|s| strip(s)).collect();
    out.retain(|_, def| symtab.contains(def.symbol.as_str()));

    // Fall back to the symbol table for any static the DWARF sweep missed
    // or named unusably. On some targets (notably illumos release builds)
    // rustc emits no `DW_TAG_variable` DIE for these tokio/std dependency
    // statics, yet the symbol survives in `.symtab`/`.dynsym`; the mangled
    // v0 name is all the bundle needs, since the consumer resolves the
    // address by name anyway.
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
    /// Coroutine env → the `__awaitee` locals of its resume fn, used to
    /// report an await at the place it is written rather than the place a
    /// macro expanded it.
    resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
    interner: StringInterner,
    /// Report formatter attachment for types whose name contains this
    /// substring; see [`explain`].
    explain_format: Option<String>,
    /// One trace per explained type, in emission order.
    explanations: Vec<FormatExplanation>,
    ids: BTreeMap<TypeId, BundleTypeId>,
    defs: Vec<TypeDef>,
    debug_formats: BTreeMap<BundleTypeId, DisplayNode>,
    /// Fully-qualified names for the name index, parallel to `defs`.
    names: Vec<Option<String>>,
    pending: VecDeque<(TypeId, BundleTypeId)>,
    unresolved: Option<BundleTypeId>,
    unresolved_refs: usize,
    cenum_synth_repr: usize,
}

impl<'a> Emitter<'a> {
    fn new(
        reader: &'a DwReader<'a>,
        resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
        explain_format: Option<String>,
    ) -> Self {
        Self {
            reader,
            resume_awaitees,
            interner: StringInterner::new(),
            explain_format,
            explanations: Vec::new(),
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

    /// Intern a string for the bundle's string table.
    fn intern(&mut self, s: &str) -> StrRef {
        self.interner.intern(s)
    }

    /// How to address `members[index]`: by its name when it has one no sibling
    /// shares, and by position otherwise.
    ///
    /// This is where a member a detector *found* — by shape, by offset, by
    /// whatever screen it applied — becomes something the bundle can address.
    /// A name is preferred because a member list is still rewritten after the
    /// program is attached, which shifts positions but not names; an unnamed
    /// member (they all intern as `<anon>`) or one of several spelled the same
    /// has no name to use and keeps its position.
    fn address(
        &mut self,
        members: &[crate::raw_types::RawMember<crate::StrId>],
        index: u32,
    ) -> MemberRef {
        let reader = self.reader;
        let named = members
            .get(index as usize)
            .and_then(|member| member.name)
            .map(|name| reader.strings.get(name))
            .filter(|name| unique_member(reader, members, name).is_some());
        match named {
            Some(name) => MemberRef::Named(self.intern(name)),
            None => MemberRef::Index(index),
        }
    }

    /// Build a [`DisplayNode::Struct`] field named `label` whose value is the
    /// decoded word at `at` — the shape every curated sync-primitive record is
    /// mostly made of.
    fn named_scalar(&mut self, label: &str, at: Selector, decode: ScalarDecode) -> Field {
        Field::Synth {
            label: self.intern(label),
            node: DisplayNode::Scalar { at, decode },
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
        head: Selector,
        waiter: TypeId,
        waiter_next: Selector,
        payload_label: &str,
        payload: Selector,
        payload_decode: ScalarDecode,
    ) -> Field {
        let node_ty = self.reserve(waiter);
        let payload_label = self.interner.intern(payload_label);
        let queue = self.interner.intern("queue");
        Field::Synth {
            label: queue,
            node: DisplayNode::List {
                head,
                next: waiter_next,
                node: Box::new(DisplayNode::Struct {
                    fields: vec![Field::Synth {
                        label: payload_label,
                        node: DisplayNode::Scalar {
                            at: payload,
                            decode: payload_decode,
                        },
                    }],
                }),
                node_ty,
            },
        }
    }

    /// Build the fields of a `tokio::sync::mpsc::chan::Chan` record: the
    /// synthetic `queued` field (a [`DisplayNode::CustomList`] walk over the
    /// block chain) followed by the channel's real members shown structurally.
    /// Shared by the
    /// standalone `Chan` formatter and the `Receiver`, which prepends its
    /// decoded `capacity`/`free` fields to the same list.
    fn chan_struct_fields(&mut self, chan: TypeId, shape: ChanShape) -> Option<Vec<Field>> {
        let ChanShape {
            tail,
            index,
            head,
            start_index_offset,
            next_offset,
            values_offset,
            stride,
            count,
            element,
        } = shape;
        let element = self.reserve(element);
        let queued = Field::Synth {
            label: self.intern("queued"),
            node: mpsc_queued_node(
                tail,
                index,
                head,
                start_index_offset,
                next_offset,
                values_offset,
                stride,
                count,
                element,
            ),
        };
        let mut fields = vec![queued];
        fields.extend(self.visible_fields(chan, Vec::new())?);
        Some(fields)
    }

    /// Emit a type (and, transitively, everything it references),
    /// returning its bundle id.
    fn emit(&mut self, id: TypeId) -> BundleTypeId {
        let root = self.reserve(id);
        while let Some((tid, bid)) = self.pending.pop_front() {
            let def = self.convert(tid);
            self.defs[bid.0 as usize] = def;
            let name = fq_name(self.reader, tid);
            let node = match self.explained(name.as_deref()) {
                Some(wanted) => {
                    let (node, trace) =
                        explain::capture(|| self.debug_format_of(tid, name.as_deref()));
                    self.explanations.push(FormatExplanation {
                        name: wanted,
                        id: bid,
                        trace,
                    });
                    node
                }
                None => self.debug_format_of(tid, name.as_deref()),
            };
            if let Some(node) = node {
                self.debug_formats.insert(bid, node);
            }
        }
        root
    }

    /// The display program for one type: its name-keyed detector if it has
    /// one, else the structural chain.
    ///
    /// Whichever produced it, the node is held to the schema's addressing
    /// contract ([`addressing_holds`]) before it is accepted, so a detector
    /// declines the same way whether it noticed the mismatch itself or not.
    fn debug_format_of(&mut self, tid: TypeId, name: Option<&str>) -> Option<DisplayNode> {
        if let Some(node) = self.specific_debug_format(tid, name)
            && addressing_holds(self.reader, &self.interner, tid, &node)
        {
            return Some(node);
        }
        let node = structural_debug_format(self, tid)?;
        addressing_holds(self.reader, &self.interner, tid, &node).then_some(node)
    }

    /// The name to report this type under, when the caller asked for its
    /// formatter to be explained.
    fn explained(&self, name: Option<&str>) -> Option<String> {
        let wanted = self.explain_format.as_deref()?;
        let name = name?;
        name.contains(wanted).then(|| name.to_string())
    }

    /// Build the display program for a type whose fully-qualified name selects a
    /// specific detector: an exact base-name match in [`BY_NAME`], else a
    /// full-name prefix in [`BY_PREFIX`]. A type named by neither falls through
    /// to [`structural_debug_format`], the short shape-keyed chain.
    fn specific_debug_format(&mut self, tid: TypeId, full: Option<&str>) -> Option<DisplayNode> {
        let full = full?;
        // Strip generic arguments for the exact-keyed detectors; the prefix
        // table keeps the full name, since `&[T]`/`Box<[T]>` are not
        // distinguished by a leading path.
        let base = full.split_once('<').map_or(full, |(head, _)| head);
        let matched = BY_NAME.iter().find(|&&(name, _)| name == base).or_else(|| {
            BY_PREFIX
                .iter()
                .find(|&&(prefix, _)| full.starts_with(prefix))
        });
        let Some(&(key, detector)) = matched else {
            explain!("  no name-keyed detector for `{base}`; trying the structural chain");
            return None;
        };
        explain!("  name-keyed detector for `{key}` selected");
        detector(self, tid)
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

    /// The type a coroutine suspend variant awaits, from the `__awaitee`
    /// member of its payload.
    fn awaited_type(&self, payload: TypeId) -> Option<TypeId> {
        let RawType::Struct(s) = self.reader.canonical_type(payload)? else {
            return None;
        };
        s.members
            .iter()
            .find(|m| {
                m.name
                    .is_some_and(|n| self.reader.strings.get(n) == "__awaitee")
            })
            .map(|m| self.reader.canonicalize(m.type_id))
    }

    /// Pair a coroutine's suspend variants with the `__awaitee` locals of
    /// its resume function, so each await can say where it is written
    /// rather than where it expanded.
    ///
    /// The two sides describe the same awaits in different orders, and
    /// the awaited type is what they share — but a coroutine may await
    /// the same type at several points, so type alone does not decide.
    /// Take the unambiguous evidence first: pairs whose coordinates
    /// already agree are the awaits rustc attributed to the code that
    /// wrote them, and matching those removes them from contention.
    /// Among what is left, pair only where a type picks out exactly one
    /// variant and one local.
    ///
    /// Anything still ambiguous stays unmatched. A suspend point
    /// reporting some other await's line would be worse than one
    /// reporting the macro's, which is at least true.
    fn await_sites(
        &mut self,
        coroutine: TypeId,
        members: &[&crate::raw_types::RawMember<crate::StrId>],
    ) -> Vec<Option<SourceLoc>> {
        let mut out = vec![None; members.len()];
        let Some(locals) = self
            .resume_awaitees
            .get(&self.reader.canonicalize(coroutine))
        else {
            return out;
        };
        let locals: Vec<(Option<TypeId>, &OwnedLoc)> = locals
            .iter()
            .map(|(t, loc)| (t.map(|t| self.reader.canonicalize(t)), loc))
            .collect();
        let awaited: Vec<Option<TypeId>> = members
            .iter()
            .map(|m| self.awaited_type(m.type_id))
            .collect();

        let mut taken = vec![false; locals.len()];
        let mut matched: Vec<Option<usize>> = vec![None; members.len()];

        // Pass one: the awaits whose two descriptions already agree.
        for (v, want) in awaited.iter().enumerate() {
            let Some(want) = want else { continue };
            let decl = self.member_loc(members[v]);
            for (l, (ty, loc)) in locals.iter().enumerate() {
                if taken[l] || *ty != Some(*want) {
                    continue;
                }
                if decl.as_ref().is_some_and(|(f, n)| {
                    loc.line == Some(*n as u64) && loc.file.as_deref() == Some(f.as_str())
                }) {
                    taken[l] = true;
                    matched[v] = Some(l);
                    break;
                }
            }
        }

        // Pass two: of what remains, only where the type is decisive on
        // both sides.
        for (v, want) in awaited.iter().enumerate() {
            let Some(want) = want else { continue };
            if matched[v].is_some() {
                continue;
            }
            if awaited
                .iter()
                .enumerate()
                .any(|(o, t)| o != v && matched[o].is_none() && *t == Some(*want))
            {
                continue;
            }
            let mut candidates = locals
                .iter()
                .enumerate()
                .filter(|(l, (ty, _))| !taken[*l] && *ty == Some(*want));
            if let (Some((l, _)), None) = (candidates.next(), candidates.next()) {
                taken[l] = true;
                matched[v] = Some(l);
            }
        }

        for (v, m) in matched.into_iter().enumerate() {
            let Some(l) = m else { continue };
            let (_, loc) = locals[l];
            let (Some(file), Some(line)) = (loc.file.as_deref(), loc.line) else {
                continue;
            };
            let file = self.interner.intern(file);
            out[v] = Some(SourceLoc {
                file,
                line: line as u32,
            });
        }
        out
    }

    /// A variant member's declaration coordinates as plain strings, for
    /// comparing against a resume-function local's.
    fn member_loc(&self, m: &crate::raw_types::RawMember<crate::StrId>) -> Option<(String, u32)> {
        let loc = m.source_loc.as_deref()?;
        let file = loc.file.map(|f| self.reader.strings.get(f))?;
        Some((file.to_owned(), loc.line?.get() as u32))
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
                    RawVariantShape::One(v) => {
                        let sites = self.await_sites(id, &[&v.member]);
                        TypeDef::Enum {
                            name,
                            size: e.size,
                            shape: VariantShape {
                                discr: None,
                                variants: vec![VariantDef {
                                    name: self.intern_opt(v.member.name),
                                    discr_values: None,
                                    payload: self.convert_member(&v.member),
                                    decl: self.member_decl(&v.member),
                                    await_site: sites[0],
                                }],
                            },
                        }
                    }
                    RawVariantShape::Many { discr, variants } => {
                        let members: Vec<_> = variants.iter().map(|(_, v)| &v.member).collect();
                        let sites = self.await_sites(id, &members);
                        TypeDef::Enum {
                            name,
                            size: e.size,
                            shape: VariantShape {
                                discr: discr.as_ref().map(|d| DiscrDef {
                                    offset: d.offset,
                                    ty: self.reserve(d.type_id),
                                }),
                                variants: variants
                                    .iter()
                                    .zip(sites)
                                    .map(|((value, v), await_site)| VariantDef {
                                        name: self.intern_opt(v.member.name),
                                        discr_values: value
                                            .map(|x| DiscrValues(vec![DiscrValue::Value(x)])),
                                        payload: self.convert_member(&v.member),
                                        decl: self.member_decl(&v.member),
                                        await_site,
                                    })
                                    .collect(),
                            },
                        }
                    }
                }
            }
        }
    }

    /// Finish emission: build the sorted name index and the string table.
    fn finish(mut self) -> (TypeTable, crate::bundle::StringTable, Emitted) {
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

        let mut types = TypeTable {
            types: self.defs,
            debug_formats: self.debug_formats,
            name_index,
        };
        let demoted = demote_types_with_members_out_of_bounds(&mut types, &self.names);
        let states = drop_members_of_other_states(&mut types, &self.names);

        let opaque = types
            .types
            .iter()
            .filter(|d| matches!(d, TypeDef::Opaque { .. }))
            .count();

        let counts = Emitted {
            opaque,
            demoted,
            states,
        };
        (types, self.interner.finish(), counts)
    }
}

/// What the closing passes over the emitted table found.
struct Emitted {
    opaque: usize,
    demoted: usize,
    states: StatePass,
}

/// Drop from each of a coroutine's states the members that are not that
/// state's own, returning `(dropped, deduplicated)`.
///
/// Only the active state's storage means anything: which one that is comes
/// from the discriminant, and the others hold whatever the coroutine last
/// left there. rustc's own debuginfo does not hold to that. It lists an
/// `async fn`'s arguments as members of *every* variant, at the offsets they
/// occupy in `Unresumed`, however long ago the state being described stopped
/// using them — `Returned` and `Panicked` carry them too, and there the
/// arguments provably cannot exist.
///
/// The offset is what tells the two apart. An argument still live at a
/// suspend point is a saved local with a slot of its own, and rustc relocates
/// it there (and, separately, lists it twice); one that is dead is left
/// pointing at the slot it had in `Unresumed`. So a member matching an
/// `Unresumed` member exactly — name, type and offset — is `Unresumed`'s
/// storage rather than this state's, and describing it means reading bytes
/// whose meaning ended whenever the coroutine moved past them. In the
/// `simple-await` fixture that is a `oneshot::Sender` consumed by `send()` a
/// line before the await, whose channel has since been freed: what is left
/// at the offset is a dangling pointer into reused heap.
///
/// This recognizes a rustc artifact by its shape, so what it found is
/// reported under `--stats`. The member counts alone are a weak signal — they
/// fall to zero both when rustc stops emitting the artifact and when it
/// renames the states out from under the match — so the coroutines *seen* are
/// counted beside the ones matched to an `Unresumed`. Many seen against none
/// matched says the naming moved; both falling together says the debuginfo
/// did.
///
/// Neither catches the failure that would cost something: an argument left at
/// its `Unresumed` offset while still live would be dropped, and no count
/// would move. Nothing in the bundle separates that case from a dead one —
/// the liveness is in the source — so what guards it is the acceptance suite
/// asserting a fixture's locals in full against a freshly extracted bundle.
fn drop_members_of_other_states(types: &mut TypeTable, names: &[Option<String>]) -> StatePass {
    let mut found = StatePass::default();

    // Every coroutine's `Unresumed` payload, against the other states of the
    // same coroutine. Collected first because the members are read from one
    // entry of the table and written to another.
    let mut work: Vec<(BundleTypeId, Vec<BundleTypeId>)> = Vec::new();
    for def in &types.types {
        let TypeDef::Enum { shape, .. } = def else {
            continue;
        };
        let payloads = || shape.variants.iter().map(|v| v.payload.ty);
        // Coroutine-shaped, by rustc's own names for the states — whether or
        // not the one this pass needs is among them.
        let coroutine = payloads()
            .filter_map(|id| state_name(names, id))
            .any(|n| n == "Returned" || n == "Panicked" || n.starts_with("Suspend"));
        if !coroutine {
            continue;
        }
        found.coroutines_seen += 1;
        let Some(unresumed) = payloads().find(|id| state_name(names, *id) == Some("Unresumed"))
        else {
            continue;
        };
        found.coroutines_matched += 1;
        work.push((
            unresumed,
            payloads().filter(|id| *id != unresumed).collect(),
        ));
    }

    let (mut dropped, mut deduplicated) = (0, 0);
    for (unresumed, states) in work {
        let held_by_unresumed: HashSet<(StrRef, BundleTypeId, u64)> =
            members_of(types, unresumed).iter().map(key).collect();
        for state in states {
            let members = match &mut types.types[state.0 as usize] {
                TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
                _ => continue,
            };
            let mut kept: HashSet<(StrRef, BundleTypeId, u64)> = HashSet::new();
            members.retain(|m| {
                if held_by_unresumed.contains(&key(m)) {
                    dropped += 1;
                    return false;
                }
                // The same member listed twice over, which is how rustc
                // spells an argument that *is* live here: once as the
                // argument, once as the saved local, both at the one slot.
                if !kept.insert(key(m)) {
                    deduplicated += 1;
                    return false;
                }
                true
            });
        }
    }
    found.members_dropped = dropped;
    found.members_deduplicated = deduplicated;
    found
}

/// What [`drop_members_of_other_states`] found, reported under `--stats`.
#[derive(Default, PartialEq, Eq, Debug)]
struct StatePass {
    coroutines_seen: usize,
    coroutines_matched: usize,
    members_dropped: usize,
    members_deduplicated: usize,
}

fn key(m: &MemberDef) -> (StrRef, BundleTypeId, u64) {
    (m.name, m.ty, m.offset)
}

fn members_of(types: &TypeTable, id: BundleTypeId) -> &[MemberDef] {
    match types.get(id) {
        Some(TypeDef::Struct { members, .. }) | Some(TypeDef::Union { members, .. }) => members,
        _ => &[],
    }
}

/// The last path segment of a coroutine state's payload type, which is the
/// state's own name: `Unresumed`, `Returned`, `Suspend0`, and so on.
fn state_name(names: &[Option<String>], id: BundleTypeId) -> Option<&str> {
    let name = names.get(id.0 as usize)?.as_deref()?;
    Some(name.rsplit("::").next().unwrap_or(name))
}

/// Demote any type whose own layout does not hold together to an `Opaque` of
/// the same size, returning how many were replaced.
///
/// A member reaching past the end of its parent means the offsets and sizes
/// DWARF gave us disagree, and anything navigating into such a type reads
/// outside the value. Replacing it keeps its id and byte size -- so every type
/// that embeds or points to it still lays out correctly -- while removing the
/// members that cannot be trusted. The renderer then shows it as a name over
/// its bytes rather than inventing fields, which is the same treatment a type
/// the extractor could not model at all receives.
///
/// A declared size of zero means "unknown", not "empty": an unsized type such
/// as `CStr` or a declaration-only DIE records no byte size. There is nothing
/// to bound those against, so they are left alone.
fn demote_types_with_members_out_of_bounds(
    types: &mut TypeTable,
    names: &[Option<String>],
) -> usize {
    let overflows = |size: u64, m: &MemberDef| {
        types
            .size_of(m.ty)
            .is_some_and(|member_size| m.offset.saturating_add(member_size) > size)
    };

    // Collected first: demoting as we go would turn a type into an `Opaque` of
    // unknown member size and change the verdict for whatever embeds it.
    let mut demote = Vec::new();
    for (i, def) in types.types.iter().enumerate() {
        let (name, size, bad) = match def {
            TypeDef::Struct {
                name,
                size,
                members,
            }
            | TypeDef::Union {
                name,
                size,
                members,
            } => (*name, *size, members.iter().find(|m| overflows(*size, m))),
            TypeDef::Enum { name, size, shape } => (
                *name,
                *size,
                shape
                    .variants
                    .iter()
                    .map(|v| &v.payload)
                    .find(|m| overflows(*size, m)),
            ),
            _ => continue,
        };
        if size == 0 {
            continue;
        }
        let Some(bad) = bad else { continue };
        warn!(
            "type {i} `{}` has size {size} but member at offset {} is {} bytes; \
             emitting it as opaque",
            names
                .get(i)
                .and_then(|n| n.as_deref())
                .unwrap_or("<unnamed>"),
            bad.offset,
            types.size_of(bad.ty).unwrap_or(0),
        );
        demote.push((i, name, size));
    }

    for (i, name, size) in &demote {
        types.types[*i] = TypeDef::Opaque {
            name: *name,
            size: Some(*size),
        };
    }
    demote.len()
}

#[cfg(test)]
mod tests {
    use super::{
        Detector, Emitter, Named, StatePass, StaticRole, VtableTypeHint,
        demote_types_with_members_out_of_bounds, drop_members_of_other_states, dyn_tail_offset,
        has_dyn_tail, match_static_symbol, scalar_newtype_node, scan_vtable_section, str_node,
    };
    use crate::bundle::{DisplayNode, MemberRef, Notation, POINTER_SIZE, Shape, Step};
    use crate::extract::ReachStep::PeelTo;
    use crate::raw_types::{NsId, RawBase, RawMember, RawPointer, RawStruct, RawType};
    use crate::{DwReader, Encoding, TypeId};
    use gimli::{DebugInfoOffset, UnitSectionOffset};
    use std::collections::{BTreeMap, BTreeSet};

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)))
    }

    /// Run one detector directly. Every detector takes an `Emitter` whether or
    /// not it uses one, so a test that only navigates DWARF still needs one.
    fn detect(reader: &DwReader<'_>, detector: Detector, id: TypeId) -> Option<DisplayNode> {
        detector(&mut Emitter::new(reader, BTreeMap::new(), None), id)
    }

    /// Dispatch `id` the way the emitter does, by the name it would carry. This
    /// covers the [`super::BY_NAME`]/[`super::BY_PREFIX`] row as well as the
    /// detector, which is where the name screening now lives.
    fn detect_by_name(reader: &DwReader<'_>, id: TypeId, name: &str) -> Option<DisplayNode> {
        Emitter::new(reader, BTreeMap::new(), None).specific_debug_format(id, Some(name))
    }

    /// The member a transparent wrapper aliases, spelled the way the detector
    /// addressed it: a name where it used one, `#index` where it counted.
    ///
    /// A `MemberRef::Named` carries a string-table position, which says nothing
    /// on its own, so a test that means "aliases `__0`" compares against that
    /// rather than against whatever position the emitter happened to intern it
    /// at.
    fn aliased(node: Option<DisplayNode>, emitter: &Emitter<'_>) -> Option<String> {
        let DisplayNode::Alias {
            at,
            follow_pointers: true,
        } = node?
        else {
            return None;
        };
        match at.steps() {
            [Step::Member(MemberRef::Named(name))] => Some(emitter.interner.get(*name)?.to_owned()),
            [Step::Member(MemberRef::Index(index))] => Some(format!("#{index}")),
            _ => None,
        }
    }

    /// [`aliased`] over one detector run directly.
    fn detect_alias(reader: &DwReader<'_>, detector: Detector, id: TypeId) -> Option<String> {
        let mut emitter = Emitter::new(reader, BTreeMap::new(), None);
        let node = detector(&mut emitter, id);
        aliased(node, &emitter)
    }

    /// [`aliased`] over one dispatch by name.
    fn detect_alias_by_name(reader: &DwReader<'_>, id: TypeId, name: &str) -> Option<String> {
        let mut emitter = Emitter::new(reader, BTreeMap::new(), None);
        let node = emitter.specific_debug_format(id, Some(name));
        aliased(node, &emitter)
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

    /// A failed named walk says which member it wanted and what the type
    /// actually has — the question `--explain-format` exists to answer, since
    /// a detector that returns `None` otherwise leaves no trace at all.
    #[test]
    fn test_a_failed_field_walk_names_the_member_and_the_alternatives() {
        let mut reader = DwReader::default();
        let notify = type_id(1);
        let word = type_id(2);
        let name = reader.strings.intern("Notify");
        let u64_name = reader.strings.intern("u64");
        let waiters = reader.strings.intern("waiters");
        let generation = reader.strings.intern("generation");
        reader.types.insert(
            word,
            crate::raw_types::RawBase {
                name: Some(u64_name),
                namespace: None,
                size: 8,
                alignment: None,
                encoding: crate::Encoding::Unsigned,
            }
            .into(),
        );
        reader.types.insert(
            notify,
            ns_struct(
                None,
                name,
                16,
                vec![
                    RawMember {
                        name: Some(waiters),
                        offset: 0,
                        type_id: word,
                        source_loc: None,
                    },
                    RawMember {
                        name: Some(generation),
                        offset: 8,
                        type_id: word,
                        source_loc: None,
                    },
                ],
            ),
        );

        let walk = |path| {
            super::explain::capture(|| {
                Emitter::new(&reader, BTreeMap::new(), None)
                    .walk(notify, &path)
                    .map(|(at, _)| at)
            })
        };

        // The member is missing: the trace names it and lists what is there.
        let (got, trace) = walk(reach![Named("state")]);
        assert!(got.is_none());
        assert_eq!(trace.len(), 1, "{trace:?}");
        assert!(
            trace[0].contains("no unique member `state`")
                && trace[0].contains("Notify")
                && trace[0].contains("waiters, generation"),
            "{}",
            trace[0]
        );

        // The walk leaves an aggregate: the trace says where it stopped.
        let (got, trace) = walk(reach![Named("waiters"), Named("value")]);
        assert!(got.is_none());
        assert!(
            trace[0].contains("stopped at `value`") && trace[0].contains("u64"),
            "{}",
            trace[0]
        );

        // A walk that fits says nothing — silence is the ordinary case — and
        // addresses what it found by name, the point of describing a layout
        // rather than counting to it.
        let (got, trace) = walk(reach![Named("waiters")]);
        assert!(trace.is_empty(), "{trace:?}");
        let Some(at) = got else {
            panic!("a pattern that fits compiles to its node");
        };
        assert!(
            matches!(at.steps(), [Step::Member(MemberRef::Named(_))]),
            "{at:?}"
        );
    }

    /// A shape-based reach reports both ways it can fail, since "no candidate"
    /// and "more than one" call for opposite fixes.
    #[test]
    fn test_a_failed_shape_walk_separates_absence_from_ambiguity() {
        let mut reader = DwReader::default();
        let holder = type_id(1);
        let word = type_id(2);
        let holder_name = reader.strings.intern("Holder");
        let u64_name = reader.strings.intern("u64");
        let first = reader.strings.intern("first");
        let second = reader.strings.intern("second");
        reader.types.insert(
            word,
            crate::raw_types::RawBase {
                name: Some(u64_name),
                namespace: None,
                size: 8,
                alignment: None,
                encoding: crate::Encoding::Unsigned,
            }
            .into(),
        );
        // Two words, both at offset zero, so a zero-offset walk sees both.
        reader.types.insert(
            holder,
            ns_struct(
                None,
                holder_name,
                8,
                vec![
                    RawMember {
                        name: Some(first),
                        offset: 0,
                        type_id: word,
                        source_loc: None,
                    },
                    RawMember {
                        name: Some(second),
                        offset: 0,
                        type_id: word,
                        source_loc: None,
                    },
                ],
            ),
        );

        let peel = |shape| {
            super::explain::capture(|| {
                Emitter::new(&reader, BTreeMap::new(), None).walk(holder, &reach![PeelTo(shape)])
            })
        };
        let (got, trace) = peel(Shape::Uint(POINTER_SIZE));
        assert!(got.is_none(), "two candidates must not resolve");
        assert!(
            trace[0].contains("candidates") && trace[0].contains("Holder"),
            "{}",
            trace[0]
        );
        // The walk says what it was after, since "nothing" and "several" read
        // the same without it.
        assert!(
            trace[1].contains("no single a 8-byte unsigned integer"),
            "{}",
            trace[1]
        );

        // Nothing of that width is there at all.
        let (got, trace) = peel(Shape::Uint(2));
        assert!(got.is_none());
        assert!(trace[0].contains("found nothing matching"), "{}", trace[0]);
    }

    /// A base type, for a test that cares what a member's shape is.
    fn base(name: crate::StrId, size: u64, encoding: Encoding) -> RawType<crate::StrId> {
        RawBase {
            name: Some(name),
            namespace: None,
            size,
            encoding,
            alignment: None,
        }
        .into()
    }

    /// A fat pointer laid out like `&str`, with `length` given whatever type
    /// the caller wants to test the addressing contract against.
    fn fat_pointer(
        name: crate::StrId,
        data_ptr: crate::StrId,
        pointer_id: TypeId,
        length: crate::StrId,
        length_id: TypeId,
    ) -> RawType<crate::StrId> {
        let member = |name, type_id, offset| RawMember {
            name: Some(name),
            offset,
            type_id,
            source_loc: None,
        };
        ns_struct(
            None,
            name,
            16,
            vec![
                member(data_ptr, pointer_id, 0),
                member(length, length_id, 8),
            ],
        )
    }

    #[test]
    fn test_a_node_addressing_the_wrong_shape_declines() {
        let mut reader = DwReader::default();
        let (data_ptr, length) = (
            reader.strings.intern("data_ptr"),
            reader.strings.intern("length"),
        );

        let byte_id = type_id(1);
        let pointer_id = type_id(2);
        let usize_id = type_id(3);
        let float_id = type_id(4);
        let good_id = type_id(5);
        let bad_id = type_id(6);
        let byte_name = reader.strings.intern("u8");
        let usize_name = reader.strings.intern("usize");
        let float_name = reader.strings.intern("f64");
        let good_name = reader.strings.intern("&str");
        let bad_name = reader.strings.intern("&str");
        reader
            .types
            .insert(byte_id, base(byte_name, 1, Encoding::Unsigned));
        reader.types.insert(
            pointer_id,
            RawPointer {
                name: None,
                target_type_id: byte_id,
            }
            .into(),
        );
        reader
            .types
            .insert(usize_id, base(usize_name, POINTER_SIZE, Encoding::Unsigned));
        reader
            .types
            .insert(float_id, base(float_name, 8, Encoding::Float));
        reader.types.insert(
            good_id,
            fat_pointer(good_name, data_ptr, pointer_id, length, usize_id),
        );
        // Same layout, but the length is a float rather than a `usize`.
        reader.types.insert(
            bad_id,
            fat_pointer(bad_name, data_ptr, pointer_id, length, float_id),
        );

        let format_of = |reader: &DwReader<'_>, id| {
            Emitter::new(reader, BTreeMap::new(), None).debug_format_of(id, Some("&str"))
        };
        assert!(matches!(
            format_of(&reader, good_id),
            Some(DisplayNode::Str { .. })
        ));
        // `str_node` itself no longer looks at the length: the `Str` node
        // requires a `usize` there, and the shared shape table is what holds
        // the detector to it.
        assert!(detect(&reader, str_node, bad_id).is_some());
        assert_eq!(format_of(&reader, bad_id), None);
    }

    /// A `uuid::Uuid`-shaped newtype over `[u8; count]`, so a test can vary the
    /// one thing the notation cares about.
    #[test]
    fn test_a_uuid_is_recognized_only_at_sixteen_bytes() {
        for (count, expected) in [(16, true), (8, false), (4, false)] {
            let mut reader = DwReader::default();
            let m0 = reader.strings.intern("__0");
            let byte_name = reader.strings.intern("u8");
            let uuid_name = reader.strings.intern("Uuid");
            let (byte, array, uuid) = (type_id(1), type_id(2), type_id(3));
            reader
                .types
                .insert(byte, base(byte_name, 1, Encoding::Unsigned));
            reader.types.insert(
                array,
                crate::raw_types::RawArray {
                    elem_type_id: byte,
                    count,
                }
                .into(),
            );
            reader.types.insert(
                uuid,
                ns_struct(
                    None,
                    uuid_name,
                    count,
                    vec![RawMember {
                        name: Some(m0),
                        offset: 0,
                        type_id: array,
                        source_loc: None,
                    }],
                ),
            );

            let got = detect_by_name(&reader, uuid, "uuid::Uuid");
            assert_eq!(
                got.is_some(),
                expected,
                "a {count}-byte newtype should{} be a UUID, got {got:?}",
                if expected { "" } else { " not" },
            );
            // Sixteen bytes is also an `Ipv6Addr`'s layout, so the notation is
            // the whole of what this detector decides.
            if expected {
                assert!(
                    matches!(
                        got,
                        Some(DisplayNode::Bytes {
                            notation: Notation::Uuid,
                            ..
                        })
                    ),
                    "{got:?}"
                );
            }
        }
    }

    /// Hex spells any run of bytes, so unlike a UUID its detector must accept
    /// every length — and still decline an empty array, which spells nothing.
    #[test]
    fn test_a_digest_is_hex_at_any_nonzero_length() {
        for (count, expected) in [(32, true), (20, true), (1, true), (0, false)] {
            let mut reader = DwReader::default();
            let m0 = reader.strings.intern("__0");
            let byte_name = reader.strings.intern("u8");
            let hash_name = reader.strings.intern("ArtifactHash");
            let (byte, array, hash) = (type_id(1), type_id(2), type_id(3));
            reader
                .types
                .insert(byte, base(byte_name, 1, Encoding::Unsigned));
            reader.types.insert(
                array,
                crate::raw_types::RawArray {
                    elem_type_id: byte,
                    count,
                }
                .into(),
            );
            reader.types.insert(
                hash,
                ns_struct(
                    None,
                    hash_name,
                    count,
                    vec![RawMember {
                        name: Some(m0),
                        offset: 0,
                        type_id: array,
                        source_loc: None,
                    }],
                ),
            );

            let got = detect_by_name(&reader, hash, "tufaceous_artifact::artifact::ArtifactHash");
            assert_eq!(
                got.is_some(),
                expected,
                "a {count}-byte digest should{} render as hex, got {got:?}",
                if expected { "" } else { " not" },
            );
        }
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
            detect_alias_by_name(&reader, mutex_id, "tokio::loom::std::parking_lot::Mutex<T>")
                .as_deref(),
            Some("__1")
        );
        // The namespace is the dispatch table's screen: the same layout under a
        // name outside the loom shims reaches no detector.
        assert_eq!(
            detect_by_name(
                &reader,
                mutex_id,
                "lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, T>"
            ),
            None
        );
    }

    #[test]
    fn test_nonzero_layers_are_transparent_over_the_integer() {
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
            detect_alias_by_name(&reader, nonzero_id, "core::num::nonzero::NonZero<i32>")
                .as_deref(),
            Some("__0")
        );
        assert_eq!(
            detect_alias_by_name(&reader, inner_id, "core::num::niche_types::NonZeroI32Inner")
                .as_deref(),
            Some("__0")
        );

        // The niche-types row is keyed by prefix, so it is offered every
        // `NonZero*` in that module; only the `*Inner` wrappers are transparent
        // over an integer, and one that is not is left alone.
        let bare_id = type_id(4);
        let bare_name = reader.strings.intern("NonZeroU32");
        reader.types.insert(
            bare_id,
            ns_struct(Some(niche_ns), bare_name, 4, vec![member(int_id)]),
        );
        assert_eq!(
            detect_by_name(&reader, bare_id, "core::num::niche_types::NonZeroU32"),
            None
        );
    }

    #[test]
    fn test_scalar_newtype_is_transparent_over_its_value() {
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
            detect_alias(&reader, scalar_newtype_node, epoch_id).as_deref(),
            Some("__0")
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
        assert_eq!(detect(&reader, scalar_newtype_node, pair_id), None);

        // Wrapping a non-scalar (a struct) is left alone.
        let wrapn = reader.strings.intern("Wrap");
        let wrap_id = type_id(4);
        reader.types.insert(
            wrap_id,
            ns_struct(None, wrapn, 8, vec![member(m0, epoch_id, 0)]),
        );
        assert_eq!(detect(&reader, scalar_newtype_node, wrap_id), None);
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

    /// A member reaching past its parent means DWARF gave us offsets and sizes
    /// that disagree, so the type is emitted as an opaque of the same size
    /// rather than as fields nothing can safely read. Sound types, and types
    /// whose size is unknown rather than zero, are left as they are.
    #[test]
    fn test_demote_types_with_members_out_of_bounds() {
        use crate::bundle::{
            BundleTypeId, DiscrDef, MemberDef, StringInterner, TypeDef, TypeTable, VariantDef,
            VariantShape,
        };
        use std::collections::BTreeMap;

        let mut strings = StringInterner::new();
        let mut s = |n: &str| strings.intern(n);
        let (u32n, soundn, oobn, unsizedn, enumn, varn) = (
            s("u32"),
            s("Sound"),
            s("Oob"),
            s("Unsized"),
            s("Enum"),
            s("V"),
        );
        let u32t = BundleTypeId(0);
        let m = |name, ty, offset| MemberDef { name, ty, offset };

        let mut types = TypeTable {
            types: vec![
                // 0: u32
                TypeDef::Base {
                    name: u32n,
                    size: 4,
                    encoding: crate::Encoding::Unsigned,
                },
                // 1: Sound { a: u32 @0, b: u32 @4 } -- fits exactly.
                TypeDef::Struct {
                    name: soundn,
                    size: 8,
                    members: vec![m(u32n, u32t, 0), m(u32n, u32t, 4)],
                },
                // 2: Oob { a: u32 @0, b: u32 @6 } -- b runs two bytes over.
                TypeDef::Struct {
                    name: oobn,
                    size: 8,
                    members: vec![m(u32n, u32t, 0), m(u32n, u32t, 6)],
                },
                // 3: Unsized { inner: u32 @0 } with no recorded size -- a DST
                // or a declaration-only DIE, which there is nothing to bound.
                TypeDef::Struct {
                    name: unsizedn,
                    size: 0,
                    members: vec![m(u32n, u32t, 0)],
                },
                // 4: an enum whose variant payload runs past its size.
                TypeDef::Enum {
                    name: enumn,
                    size: 4,
                    shape: VariantShape {
                        discr: Some(DiscrDef {
                            offset: 0,
                            ty: u32t,
                        }),
                        variants: vec![VariantDef {
                            name: varn,
                            discr_values: None,
                            payload: m(varn, u32t, 2),
                            decl: None,
                            await_site: None,
                        }],
                    },
                },
            ],
            debug_formats: BTreeMap::new(),
            name_index: vec![],
        };
        let names = vec![
            Some("u32".to_owned()),
            Some("Sound".to_owned()),
            Some("Oob".to_owned()),
            Some("Unsized".to_owned()),
            Some("Enum".to_owned()),
        ];

        assert_eq!(
            demote_types_with_members_out_of_bounds(&mut types, &names),
            2
        );

        // The sound struct and the sizeless one keep their members.
        assert!(matches!(types.types[1], TypeDef::Struct { .. }));
        assert!(matches!(types.types[3], TypeDef::Struct { .. }));

        // The two bad ones become opaques that keep their name and byte size,
        // so anything embedding or pointing at them still lays out correctly.
        assert!(matches!(
            types.types[2],
            TypeDef::Opaque {
                name,
                size: Some(8)
            } if name == oobn
        ));
        assert!(matches!(
            types.types[4],
            TypeDef::Opaque {
                name,
                size: Some(4)
            } if name == enumn
        ));

        // Running again finds nothing left to demote.
        assert_eq!(
            demote_types_with_members_out_of_bounds(&mut types, &names),
            0
        );
    }

    /// rustc lists an `async fn`'s arguments in every one of a coroutine's
    /// states. Where the argument is still live the listing is relocated to
    /// its saved-local slot (and doubled); where it is dead it is left at the
    /// slot it had in `Unresumed`, which is another state's storage and reads
    /// as whatever the coroutine last left there.
    #[test]
    fn test_drop_members_of_other_states() {
        use crate::bundle::{
            BundleTypeId, MemberDef, StringInterner, TypeDef, TypeTable, VariantDef, VariantShape,
        };
        use std::collections::BTreeMap;

        let mut strings = StringInterner::new();
        let mut s = |n: &str| strings.intern(n);
        let (argn, localn, envn) = (s("ready"), s("count"), s("env"));
        let u32t = BundleTypeId(0);
        let m = |name, offset| MemberDef {
            name,
            ty: u32t,
            offset,
        };
        let state = |name, members| TypeDef::Struct {
            name,
            size: 32,
            members,
        };
        let variant = |ty| VariantDef {
            name: envn,
            discr_values: None,
            payload: MemberDef {
                name: envn,
                ty,
                offset: 0,
            },
            decl: None,
            await_site: None,
        };

        let mut types = TypeTable {
            types: vec![
                TypeDef::Base {
                    name: s("u32"),
                    size: 4,
                    encoding: crate::Encoding::Unsigned,
                },
                // 1: Unresumed holds the argument at its own slot.
                state(argn, vec![m(argn, 0)]),
                // 2: Suspend0, where the argument is still live: relocated
                // off slot 0, and listed twice over.
                state(argn, vec![m(argn, 16), m(argn, 16), m(localn, 8)]),
                // 3: Suspend1, where it is dead: left pointing at slot 0.
                state(argn, vec![m(argn, 0), m(localn, 8)]),
                // 4: Returned, a terminal state that cannot hold it at all.
                state(argn, vec![m(argn, 0)]),
                TypeDef::Enum {
                    name: envn,
                    size: 32,
                    shape: VariantShape {
                        discr: None,
                        variants: (1..=4).map(|i| variant(BundleTypeId(i))).collect(),
                    },
                },
            ],
            debug_formats: BTreeMap::new(),
            name_index: vec![],
        };
        let names: Vec<Option<String>> = ["u32", "E::Unresumed", "E::Suspend0", "E::Suspend1"]
            .iter()
            .map(|n| Some((*n).to_owned()))
            .chain([Some("E::Returned".to_owned()), Some("E".to_owned())])
            .collect();

        assert_eq!(
            drop_members_of_other_states(&mut types, &names),
            StatePass {
                coroutines_seen: 1,
                coroutines_matched: 1,
                members_dropped: 2,
                members_deduplicated: 1,
            }
        );

        let members = |i: usize| match &types.types[i] {
            TypeDef::Struct { members, .. } => members.clone(),
            other => panic!("{other:?} is not a struct"),
        };
        // Unresumed is the state that owns them, and keeps them.
        assert_eq!(members(1), vec![m(argn, 0)]);
        // Suspend0's copy is live, so only the repeat goes.
        assert_eq!(members(2), vec![m(argn, 16), m(localn, 8)]);
        // Suspend1 and Returned keep only what is theirs.
        assert_eq!(members(3), vec![m(localn, 8)]);
        assert_eq!(members(4), vec![]);

        // Running again still recognizes the coroutine, and finds nothing
        // left to drop in it.
        assert_eq!(
            drop_members_of_other_states(&mut types, &names),
            StatePass {
                coroutines_seen: 1,
                coroutines_matched: 1,
                ..Default::default()
            }
        );

        // A coroutine rustc has renamed the states of is still counted as
        // one, and reported as unmatched rather than passed over in silence.
        let renamed: Vec<Option<String>> = names
            .iter()
            .map(|n| n.as_deref().map(|n| n.replace("Unresumed", "Start")))
            .collect();
        let found = drop_members_of_other_states(&mut types, &renamed);
        assert_eq!(found.coroutines_seen, 1);
        assert_eq!(found.coroutines_matched, 0);
    }
}

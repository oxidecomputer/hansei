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
    BinaryIdent, Bundle, BundleTypeId, DiscrDef, DiscrValue, DiscrValues, DisplayNode,
    DynFutureTable, FutureKind, InfraTypes, MemberDef, MemberRef, Meta, Provenance,
    ProvenanceTable, SourceLoc, StaticDef, StaticRole, StaticsTable, StrRef, StringInterner,
    TaskEntryId, TaskFutureEntry, TaskTable, TypeDef, TypeTable, VariantDef, VariantShape,
    WalksTable, strip_build_prefix,
};
use crate::detect::{Family, FormatExplanation, struct_of, trace, unique_member};
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
    /// The producer's rustc version when it predates [`RUSTC_FLOOR`].
    /// Extraction proceeds — the layouts may well still line up — but
    /// nothing has ever been verified against an older toolchain, so
    /// the caller is warned rather than left to find out downstream.
    pub rustc_below_floor: Option<String>,
    /// The family name version-dependent formatters ran as when no tokio
    /// version could be recovered from the target — the newest supported
    /// family, a guess worth a warning. `None` when the version was
    /// recovered or no versioned detector was consulted.
    pub tokio_family_guessed: Option<String>,
}

/// The oldest rustc whose output the extraction contracts are held
/// against. Binaries from older toolchains extract with a warning, not
/// a refusal.
pub const RUSTC_FLOOR: &str = "1.97.0";

/// `Some(version)` when the producer string names a rustc older than
/// [`RUSTC_FLOOR`]. A producer that carries no parseable version (a
/// non-rustc binary, say) is not "below" anything — no warning.
fn rustc_below_floor(rustc_version: &str) -> Option<String> {
    let floor = semver::Version::parse(RUSTC_FLOOR).expect("RUSTC_FLOOR parses");
    let ver = semver::Version::parse(rustc_version.split_whitespace().next()?).ok()?;
    (ver < floor).then(|| ver.to_string())
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
        if let Some(v) = &self.rustc_below_floor {
            writeln!(
                f,
                "  WARNING: producer rustc {v} predates the supported floor {RUSTC_FLOOR}"
            )?;
        }
        if let Some(family) = &self.tokio_family_guessed {
            writeln!(
                f,
                "  WARNING: no tokio version recovered; version-dependent \
                 formatters assumed the newest family ({family})"
            )?;
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

pub(crate) fn raw_type_size(reader: &DwReader<'_>, id: TypeId) -> Option<u64> {
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
                                        comp_dir: loc
                                            .and_then(|l| l.comp_dir)
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

    // Whether the target was built with `--cfg tokio_unstable`, decided
    // structurally: the task `Vtable`'s `spawn_location_offset` member is
    // behind that cfg (tokio 1.50 through 1.53), so its presence in an
    // otherwise-resolved vtable is the build flavor. Unknown when the
    // vtable type itself is missing.
    let vtable_slot = infra_paths
        .iter()
        .position(|(key, _)| *key == "vtable")
        .expect("infra_paths names a vtable slot");
    let tokio_unstable = infra_ids[vtable_slot].map(|vtable| {
        struct_of(reader, vtable).is_some_and(|st| {
            st.members
                .iter()
                .any(|m| m.name.map(|n| reader.strings.get(n)) == Some("spawn_location_offset"))
        })
    });

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

    // The recovered tokio version selects the detector family before any
    // type is emitted, so every versioned dispatch in this bundle answers
    // from one coherent family.
    let tokio_version = bound
        .iter()
        .filter_map(|t| t.poll_func_loc.as_ref())
        .find_map(tokio_version_of);

    let mut em = Emitter::new(
        reader,
        resume_awaitees,
        opts.explain_format.clone(),
        tokio_version.clone(),
    );

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
    stats.rustc_below_floor = rustc_below_floor(&rustc_version);

    let meta = Meta {
        format_version: crate::bundle::FORMAT_VERSION,
        rustc_version,
        tokio_version,
        tokio_unstable,
        debug_binary: ident,
        extract_args: opts.extract_args.clone(),
        symbol_fingerprint: fingerprint.into_iter().collect(),
    };

    stats.unresolved_refs = em.unresolved_refs;
    stats.cenum_synth_repr = em.cenum_synth_repr;
    stats.format_explanations = std::mem::take(&mut em.explanations);
    stats.tokio_family_guessed = (em.versioned_dispatch && em.tokio_version.is_none())
        .then(|| Family::select(None).name().to_owned());
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
        walks: WalksTable::default(),
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
pub(crate) struct OwnedLoc {
    file: Option<String>,
    dir: Option<String>,
    comp_dir: Option<String>,
    line: Option<u64>,
}

fn owned_loc(l: &SourceLocView<'_>) -> OwnedLoc {
    OwnedLoc {
        file: l.file().map(str::to_owned),
        dir: l.dir().map(str::to_owned),
        comp_dir: l.comp_dir().map(str::to_owned),
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
pub(crate) fn fq_name(reader: &DwReader<'_>, id: TypeId) -> Option<String> {
    let raw = reader.canonical_type(id)?;
    let name = raw.name().map(|n| reader.strings.get(n))?;
    Some(match raw.namespace() {
        Some(ns) => format!("{}::{name}", ns_path(reader, ns)),
        None => name.to_owned(),
    })
}

/// The `a::b::c` path of a namespace.
pub(crate) fn ns_path(reader: &DwReader<'_>, ns: NsId) -> String {
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
            file: em.interner.intern(&display_path(
                loc.comp_dir.as_deref(),
                loc.dir.as_deref(),
                file,
            )),
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
                        file: em
                            .interner
                            .intern(&display_path(loc.comp_dir(), loc.dir(), file)),
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

/// The display path for a source location: the file joined onto its
/// line-table directory, cut down by [`strip_build_prefix`] to the tail a
/// reader can use.
///
/// A relative directory is relative to the unit's `DW_AT_comp_dir`, and
/// rustc gives each crate its own: the crate root for a dependency, the
/// workspace root for a member. Taking the directory alone therefore drops
/// the crate a dependency's file belongs to — `src/resolvers/dns.rs` for a
/// type emitted in qorb's own unit, where the same file reached from a
/// crate that monomorphized it is named in full. So the path is rooted at
/// `comp_dir` and offered to [`strip_build_prefix`], and the result is
/// taken only if it recognized the root: a workspace root is nobody's
/// crate cache, and `/data/omicron/nexus/src/app/…` is worse than the
/// `nexus/src/app/…` the directory already gave.
fn display_path(comp_dir: Option<&str>, dir: Option<&str>, file: &str) -> String {
    let joined = match dir {
        Some(dir) if !dir.is_empty() && !file.starts_with('/') => format!("{dir}/{file}"),
        _ => file.to_owned(),
    };
    if joined.starts_with('/') {
        return strip_build_prefix(&joined).into_owned();
    }
    let Some(comp_dir) = comp_dir.filter(|d| d.starts_with('/')) else {
        return joined;
    };
    let rooted = format!("{comp_dir}/{joined}");
    let cut = strip_build_prefix(&rooted);
    // Every root it knows takes something off, so an unchanged length is
    // how "not recognized" comes back.
    match cut.len() < rooted.len() {
        true => cut.into_owned(),
        false => joined,
    }
}

/// Converts reachable DWARF types into bundle [`TypeDef`]s: assigns dense
/// ids up front, then drains a worklist so deep type graphs cannot
/// overflow the stack.
pub(crate) struct Emitter<'a> {
    pub(crate) reader: &'a DwReader<'a>,
    /// Coroutine env → the `__awaitee` locals of its resume fn, used to
    /// report an await at the place it is written rather than the place a
    /// macro expanded it.
    resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
    pub(crate) interner: StringInterner,
    /// Report formatter attachment for types whose name contains this
    /// substring; see [`crate::detect::trace`].
    pub(crate) explain_format: Option<String>,
    /// The tokio version recovered from the target's DWARF, as the family
    /// dispatch and its `--explain-format` lines report it.
    pub(crate) tokio_version: Option<semver::Version>,
    /// The [`Family`] the version selects, applied to every versioned
    /// dispatch row for this target.
    pub(crate) family: Family,
    /// Whether any versioned row was consulted — what turns an unrecovered
    /// tokio version into a warning, since only then did the family guess
    /// affect output.
    pub(crate) versioned_dispatch: bool,
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
    pub(crate) fn new(
        reader: &'a DwReader<'a>,
        resume_awaitees: BTreeMap<TypeId, Vec<(Option<TypeId>, OwnedLoc)>>,
        explain_format: Option<String>,
        tokio_version: Option<semver::Version>,
    ) -> Self {
        Self {
            reader,
            resume_awaitees,
            interner: StringInterner::new(),
            explain_format,
            family: Family::select(tokio_version.as_ref()),
            tokio_version,
            versioned_dispatch: false,
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
    pub(crate) fn intern(&mut self, s: &str) -> StrRef {
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
    pub(crate) fn address(
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
                        trace::capture(|| self.debug_format_of(tid, name.as_deref()));
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

    /// Assign a bundle id for a type, queueing its conversion if new.
    pub(crate) fn reserve(&mut self, id: TypeId) -> BundleTypeId {
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
        let dir = loc.dir.map(|d| self.reader.strings.get(d));
        let comp_dir = loc.comp_dir.map(|d| self.reader.strings.get(d));
        let file = self.interner.intern(&display_path(comp_dir, dir, file));
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
            let file = self.interner.intern(&display_path(
                loc.comp_dir.as_deref(),
                loc.dir.as_deref(),
                file,
            ));
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
            ..Default::default()
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
        let strings = self.interner.finish();
        types.build_normalized_index(&strings);
        (types, strings, counts)
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
        StatePass, StaticRole, VtableTypeHint, demote_types_with_members_out_of_bounds,
        display_path, drop_members_of_other_states, match_static_symbol, scan_vtable_section,
    };
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn test_rustc_floor_warning() {
        use super::rustc_below_floor;
        // The version as `rustc_version_of` records it: number first,
        // hash and date trailing.
        assert_eq!(
            rustc_below_floor("1.96.0 (0000aaaa 2026-01-01)"),
            Some("1.96.0".to_owned())
        );
        assert_eq!(rustc_below_floor("1.97.0 (2d8144b78 2026-07-07)"), None);
        assert_eq!(rustc_below_floor("1.97.1 (8bab26f4f 2026-07-14)"), None);
        assert_eq!(rustc_below_floor("1.98.0"), None);
        // A producer that names no rustc version is unknown, not old.
        assert_eq!(rustc_below_floor("GNU C 12.2.0"), None);
        assert_eq!(rustc_below_floor(""), None);
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
            ..Default::default()
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
            ..Default::default()
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

    #[test]
    fn test_display_path_plain() {
        // No dir, an empty dir, or an absolute file passes through.
        assert_eq!(display_path(None, None, "lib.rs"), "lib.rs");
        assert_eq!(display_path(None, Some(""), "lib.rs"), "lib.rs");
        assert_eq!(
            display_path(None, Some("ignored"), "/abs/path/lib.rs"),
            "/abs/path/lib.rs"
        );
    }

    #[test]
    fn test_display_path_relative_dir() {
        assert_eq!(
            display_path(None, Some("nexus/reconfigurator/preparation/src"), "lib.rs"),
            "nexus/reconfigurator/preparation/src/lib.rs"
        );
    }

    #[test]
    fn test_display_path_registry() {
        // The file component may itself carry a path.
        assert_eq!(
            display_path(
                None,
                Some("/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.50.0"),
                "src/sync/watch.rs"
            ),
            "tokio-1.50.0/src/sync/watch.rs"
        );
        assert_eq!(
            display_path(
                None,
                Some(
                    "/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_core-1.0.228/src/de"
                ),
                "mod.rs"
            ),
            "serde_core-1.0.228/src/de/mod.rs"
        );
    }

    #[test]
    fn test_display_path_git_checkout() {
        assert_eq!(
            display_path(
                None,
                Some(
                    "/home/wfc/.cargo/git/checkouts/dendrite-ae9f1715c17fc765/cc0c307/dpd-client/src"
                ),
                "lib.rs"
            ),
            "dendrite/cc0c307/dpd-client/src/lib.rs"
        );
        // A checkout dir that does not end in a cache hash is kept whole.
        assert_eq!(
            display_path(
                None,
                Some("/home/x/.cargo/git/checkouts/odd-layout/src"),
                "lib.rs"
            ),
            "odd-layout/src/lib.rs"
        );
    }

    #[test]
    fn test_display_path_toolchain() {
        assert_eq!(
            display_path(
                None,
                Some("/rustc/ed61e7d7e242494fb7057f2657300d9e77bb4fcb/library/std/src/thread"),
                "mod.rs"
            ),
            "library/std/src/thread/mod.rs"
        );
        assert_eq!(
            display_path(
                None,
                Some(
                    "/Users/wfc/.rustup/toolchains/1.97.0-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ptr"
                ),
                "non_null.rs"
            ),
            "library/core/src/ptr/non_null.rs"
        );
        assert_eq!(
            display_path(None, Some("/rust/deps/hashbrown-0.15.5/src/raw"), "mod.rs"),
            "hashbrown-0.15.5/src/raw/mod.rs"
        );
    }

    #[test]
    fn test_display_path_unknown_absolute() {
        // Unrecognized absolute dirs join unmodified rather than truncate.
        assert_eq!(
            display_path(None, Some("/opt/vendored/foo/src"), "lib.rs"),
            "/opt/vendored/foo/src/lib.rs"
        );
    }

    /// Both spellings a dependency's file gets, from the two units that
    /// name it in one nexus binary: qorb's own, which writes the directory
    /// relative to its crate root, and the crate that monomorphized a qorb
    /// generic, which has to write it in full. Rooting the first at its
    /// compilation directory is what makes them agree.
    #[test]
    fn test_display_path_comp_dir_names_the_crate() {
        const QORB: &str =
            "/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/qorb-0.4.1";
        assert_eq!(
            display_path(Some(QORB), Some("src/resolvers"), "dns.rs"),
            "qorb-0.4.1/src/resolvers/dns.rs"
        );
        assert_eq!(
            display_path(Some("/data/omicron"), Some(QORB), "src/pool.rs"),
            "qorb-0.4.1/src/pool.rs"
        );
    }

    /// A workspace member's compilation directory is the workspace root,
    /// which names no crate cache — rooting there would only prepend the
    /// build machine, so the directory's own answer stands.
    #[test]
    fn test_display_path_comp_dir_declined() {
        assert_eq!(
            display_path(Some("/data/omicron"), Some("nexus/src/app"), "mod.rs"),
            "nexus/src/app/mod.rs"
        );
        // A relative compilation directory cannot root anything.
        assert_eq!(
            display_path(Some("omicron"), Some("nexus/src/app"), "mod.rs"),
            "nexus/src/app/mod.rs"
        );
        // An absolute directory is already whole; comp_dir does not apply.
        assert_eq!(
            display_path(Some("/data/omicron"), Some("/opt/vendored/src"), "lib.rs"),
            "/opt/vendored/src/lib.rs"
        );
    }
}

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
    BinaryIdent, Bundle, BundleTypeId, DebugFormat, DiscrDef, DiscrValue, DiscrValues,
    DynFutureTable, FutureKind, InfraTypes, MemberDef, Meta, Provenance, ProvenanceTable,
    SourceLoc, StaticDef, StaticRole, StaticsTable, StrRef, StringInterner, TaskEntryId,
    TaskFutureEntry, TaskTable, TypeDef, TypeTable, VariantDef, VariantShape,
};
use crate::raw_types::{NsId, RawType, VariantShape as RawVariantShape};
use crate::view::{DwView, Func, SourceLocView};
use crate::{DwReader, Encoding, TypeId};
use crate::symbols::normalized_value_index;

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use sha2::Digest;
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
        writeln!(f, "  missing linkage names:  {}", self.vtable_missing_linkage)?;
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
        writeln!(f, "  ambiguous:              {}", self.vtable_types_ambiguous)?;
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
            writeln!(
                f,
                "  statics via symtab:     {}",
                self.statics_from_symtab
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
        let Some(name) = symbol.name().ok() else { continue };
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
        if !matches!(section.kind(), SectionKind::Data | SectionKind::ReadOnlyData) {
            continue;
        }
        let Ok(data) = section.uncompressed_data() else { continue };
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
        hints.extend(concrete.into_iter().map(|name| VtableTypeHint { name, size }));
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

fn resolve_vtable_type_hints(
    reader: &DwReader<'_>,
    hints: &[VtableTypeHint],
    stats: &mut ExtractStats,
) -> BTreeSet<TypeId> {
    let mut by_name: BTreeMap<String, Vec<(TypeId, u64)>> = BTreeMap::new();
    for (id, _) in reader.canonical_types() {
        let Some(name) = fq_name(reader, id) else { continue };
        let Some(size) = raw_type_size(reader, id) else { continue };
        by_name
            .entry(crate::symbols::normalized_rust_type_name(&name))
            .or_default()
            .push((id, size));
    }

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
        RawType::Array(array) => raw_type_size(reader, array.elem_type_id)?.checked_mul(array.count),
    }
}

/// Extract a bundle from a debug binary (or any DWARF-bearing object).
pub fn extract_file(path: &Path, opts: &ExtractOptions) -> Result<(Bundle, ExtractStats)> {
    let f = std::fs::File::open(path)?;
    let obj_bytes = unsafe { memmap2::Mmap::map(&f) }?;

    let obj = object::File::parse(&*obj_bytes)?;
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

    let reader = DwReader::read_types(&dwarf, Default::default())?;
    let view = reader.view();

    let ident = BinaryIdent {
        basename: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        build_id: obj.build_id().ok().flatten().map(|b| b.to_vec()),
        sha256: sha2::Sha256::digest(&*obj_bytes).into(),
    };

    // Named statics can be absent from `.debug_info` yet present in the
    // symbol table (§5.4): illumos release builds emit no `DW_TAG_variable`
    // DIE for tokio/std dependency statics such as `WAKER_VTABLE`, but keep
    // the symbol in `.symtab`/`.dynsym`. Gather both symbol tables so
    // `find_statics` can fall back to a mangled-name match.
    let symbols: Vec<&str> = obj
        .symbols()
        .chain(obj.dynamic_symbols())
        .filter_map(|s| s.name().ok())
        .collect();

    let vtable_types = discover_vtable_types(&obj);

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

    // (T, S) → accumulating seed.
    let mut seeds: BTreeMap<(TypeId, TypeId), TaskSeed> = BTreeMap::new();
    // Canonical T → mangled `<T as Future>::poll` symbols.
    let mut fut_polls: BTreeMap<TypeId, BTreeSet<String>> = BTreeMap::new();
    // Canonical T → mangled `drop_glue::<T>` symbols.
    let mut drop_glues: BTreeMap<TypeId, BTreeSet<String>> = BTreeMap::new();
    // `drop_glue<T>` display name's inner text → symbols, for glue DIEs
    // without a template-parameter reference (release builds omit it on
    // out-of-line definitions).
    let mut glue_by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Coroutine env → its resume fn's declaration coordinates. The resume
    // fn carries the async fn/block's own decl coords, which the env type
    // DIE lacks (§5.5) and which survive even when the constructing
    // wrapper fn was MIR-inlined out of the debug info entirely.
    let mut resume_locs: BTreeMap<TypeId, OwnedLoc> = BTreeMap::new();

    for (_, func) in view.functions() {
        let Some(name) = func.name() else { continue };

        if func.namespace_id() == raw_ns && raw_ns.is_some() {
            let Some(vtable_fn) = VTABLE_FNS
                .iter()
                .find(|v| name.strip_prefix(*v).is_some_and(|r| r.starts_with('<')))
            else {
                continue;
            };
            let Some(linkage) = func.linkage_name() else {
                stats.vtable_missing_linkage += 1;
                continue;
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
                continue;
            };
            let seed = seeds.entry((t, s)).or_default();
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
        } else if func.namespace_id() == glue_ns
            && glue_ns.is_some()
            && name.starts_with("drop_glue<")
        {
            let Some(linkage) = func.linkage_name() else {
                continue;
            };
            let params: Vec<_> = func.template_params().collect();
            if let [p] = params.as_slice() {
                drop_glues
                    .entry(reader.canonicalize(p.type_id()))
                    .or_default()
                    .insert(strip(linkage).to_owned());
            } else if let Some(inner) = name
                .strip_prefix("drop_glue<")
                .and_then(|r| r.strip_suffix('>'))
            {
                glue_by_name
                    .entry(inner.to_owned())
                    .or_default()
                    .insert(strip(linkage).to_owned());
            }
        } else if name.starts_with("{async_fn#")
            || name.starts_with("{async_block#")
            || name.starts_with("{closure#")
        {
            // Coroutine resume functions are the compiler-generated
            // `<env as Future>::poll` bodies — the symbols `dyn Future`
            // vtables actually point at for async fn/block awaitees.
            // Recognized by shape: `fn(Pin<&mut T>) -> Poll<…>` with a
            // coroutine-env self type.
            let Some(linkage) = func.linkage_name() else {
                continue;
            };
            let poll_shaped = func
                .return_type()
                .and_then(|t| t.name())
                .is_some_and(|n| n.starts_with("Poll<"));
            if !poll_shaped {
                continue;
            }
            match future_poll_self_type(reader, &func) {
                Ok(t) if is_coroutine_env(reader, t) => {
                    fut_polls
                        .entry(t)
                        .or_default()
                        .insert(strip(linkage).to_owned());
                    if let Some(loc) = func.source_loc() {
                        resume_locs.entry(t).or_insert_with(|| owned_loc(&loc));
                    }
                }
                _ => {}
            }
        } else if let Some(linkage) = func.linkage_name() {
            // `<T as Future>::poll` impls live in `{impl#N}` namespaces;
            // the trait path is only visible in the mangled name.
            if !name.starts_with("poll") {
                continue;
            }
            let demangled = format!("{:#}", rustc_demangle::demangle(linkage));
            if !demangled.ends_with(FUTURE_POLL_SUFFIX) {
                continue;
            }
            match future_poll_self_type(reader, &func) {
                Ok(t) => {
                    fut_polls
                        .entry(t)
                        .or_default()
                        .insert(strip(linkage).to_owned());
                }
                Err(SelfRecovery::DeclOnly) => {
                    // Fully-inlined blanket impls (`Pin<P>`, `&mut F`)
                    // whose self type DIE is a bare declaration. Those
                    // types never back a `dyn Future` vtable, so nothing
                    // is lost.
                    debug!("declaration-only Future::poll self type: {demangled}");
                    stats.dyn_decl_only_self += 1;
                }
                Err(SelfRecovery::Unresolved) => {
                    debug!("cannot recover T from Future::poll self param: {demangled}");
                    stats.dyn_unresolved_self += 1;
                }
            }
        }
    }

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
        .or_else(|| unsafe_cell_debug_format(reader, id))
        .or_else(|| loom_unsafe_cell_debug_format(reader, id))
        .or_else(|| loom_atomic_debug_format(reader, id))
        .or_else(|| unique_debug_format(reader, id))
        .or_else(|| non_null_debug_format(reader, id))
        .or_else(|| usize_no_high_bit_debug_format(reader, id))
        .or_else(|| atomic_debug_format(reader, id))
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

/// Recognize the private node layout of `BTreeMap<K, V, A>`. Unlike the
/// simpler known formats, this retains a few referenced types until emission
/// so they can be translated to bundle ids.
fn btree_map_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<RawBTreeMapFormat> {
    if fq_name(reader, id)?.split('<').next()? != "alloc::collections::btree::map::BTreeMap" {
        return None;
    }
    let RawType::Struct(map) = reader.canonical_type(id)? else { return None };
    let [key_param, value_param, alloc_param] = map.template_params.as_ref() else { return None };
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
    let [(root_node, node_ref)] = node_refs.as_slice() else { return None };
    let RawType::Struct(node_ref_ty) = reader.canonical_type(*node_ref)? else { return None };
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
    let [(node_tail, leaf)] = node_pointers.as_slice() else { return None };
    let mut node = vec![node_member_index as u32];
    node.extend_from_slice(node_tail);

    let RawType::Struct(leaf_ty) = reader.canonical_type(*leaf)? else { return None };
    let (leaf_len, leaf_len_member) = unique_member(reader, &leaf_ty.members, "len")?;
    if !is_unsigned_integer(reader, leaf_len_member.type_id, 2) {
        return None;
    }
    let (leaf_keys, keys_member) = unique_member(reader, &leaf_ty.members, "keys")?;
    let (leaf_values, values_member) = unique_member(reader, &leaf_ty.members, "vals")?;
    let RawType::Array(keys) = reader.canonical_type(keys_member.type_id)? else { return None };
    let RawType::Array(values) = reader.canonical_type(values_member.type_id)? else { return None };
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
    let [(_, internal)] = parent_pointers.as_slice() else { return None };
    let RawType::Struct(internal_ty) = reader.canonical_type(*internal)? else { return None };
    let (internal_data, data_member) = unique_member(reader, &internal_ty.members, "data")?;
    if reader.canonicalize(data_member.type_id) != *leaf || data_member.offset != 0 {
        return None;
    }
    let (internal_edges, edges_member) = unique_member(reader, &internal_ty.members, "edges")?;
    let RawType::Array(edges) = reader.canonical_type(edges_member.type_id)? else { return None };
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
    let [(edge, _)] = edge_pointers.as_slice() else { return None };

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
    let mut matches = members.iter().enumerate().filter(|(_, member)| {
        member.name.map(|name| reader.strings.get(name)) == Some(expected)
    });
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
        RawVariantShape::Many { variants, .. } => {
            variants.iter().map(|(_, variant)| &variant.member).collect()
        }
        RawVariantShape::Zero | RawVariantShape::CStyle { .. } => return None,
    };
    let mut matches = variants.into_iter().filter(|member| {
        member.name.map(|name| reader.strings.get(name)) == Some(expected)
    });
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
    let Some(RawType::Struct(st)) = reader.canonical_type(id) else { return false };
    fq_name(reader, id)
        .is_some_and(|name| name.split('<').next() == Some("alloc::collections::btree::node::NodeRef"))
        && st.template_params.len() == 4
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
    let Some(RawType::Struct(st)) = reader.canonical_type(id) else { return false };
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
    let RawType::Union(union) = reader.canonical_type(id)? else { return None };
    if fq_name(reader, id)?.split('<').next()? != "core::mem::maybe_uninit::MaybeUninit" {
        return None;
    }
    let [param] = union.template_params.as_ref() else { return None };
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
    for (index, member) in members.iter().enumerate().filter(|(_, member)| member.offset == 0) {
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
    for (index, member) in members.iter().enumerate().filter(|(_, member)| member.offset == 0) {
        path.push(index as u32);
        find_pointer_paths(reader, member.type_id, matches, path, seen, found);
        path.pop();
    }
    seen.pop();
}

fn function_pointer_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Pointer(pointer) = reader.canonical_type(id)? else { return None };
    reader
        .is_subroutine_type(pointer.target_type_id)
        .then_some(DebugFormat::Known(crate::bundle::KnownFormat::FunctionPointer))
}

fn raw_waker_vtable_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    if fq_name(reader, id).as_deref() != Some("core::task::wake::RawWakerVTable") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let member = |expected: &str| {
        let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
            member.name.map(|name| reader.strings.get(name)) == Some(expected)
                && matches!(reader.canonical_type(member.type_id), Some(RawType::Pointer(_)))
        });
        let (index, _) = matches.next()?;
        matches.next().is_none().then_some(index as u32)
    };
    Some(DebugFormat::Known(crate::bundle::KnownFormat::RawWakerVTable {
        clone: member("clone")?,
        wake: member("wake")?,
        wake_by_ref: member("wake_by_ref")?,
        drop: member("drop")?,
    }))
}

/// Recognize rustc's DWARF representation of a Rust trait-object wide
/// pointer. The bundle records both member indices and the vtable header
/// ordering so reify never guesses from the private field name or bakes in
/// rustc's slot numbers independently.
fn dyn_pointer_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };

    let mut data_matches = st.members.iter().enumerate().filter(|(_, member)| {
        if member.name.map(|name| reader.strings.get(name)) != Some("pointer") {
            return false;
        }
        let Some(RawType::Pointer(pointer)) = reader.canonical_type(member.type_id) else {
            return false;
        };
        has_dyn_tail(reader, pointer.target_type_id, &mut Vec::new())
    });
    let (pointer_index, _) = data_matches.next()?;
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
    }))
}

/// Whether `id` is a `dyn Trait` type or an unsized aggregate whose final
/// field recursively contains that dyn tail, such as `ArcInner<dyn Trait>`.
/// Rust wide pointers carry metadata for either shape.
fn has_dyn_tail(reader: &DwReader<'_>, id: TypeId, seen: &mut Vec<TypeId>) -> bool {
    let id = reader.canonicalize(id);
    if seen.len() >= 8 || seen.contains(&id) {
        return false;
    }
    let Some(raw) = reader.canonical_type(id) else {
        return false;
    };
    if fq_name(reader, id)
        .is_some_and(|name| name.starts_with("dyn ") || name.starts_with("(dyn "))
    {
        return true;
    }
    let RawType::Struct(st) = raw else {
        return false;
    };
    let Some(tail) = st.members.last() else {
        return false;
    };
    seen.push(id);
    let found = has_dyn_tail(reader, tail.type_id, seen);
    seen.pop();
    found
}

fn unsafe_cell_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let (member, _) = unsafe_cell_layout(reader, id)?;
    Some(DebugFormat::Transparent { member })
}

fn unsafe_cell_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::cell" || !name.starts_with("UnsafeCell<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else { return None };
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
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "tokio::loom::std::unsafe_cell"
        || !name.starts_with("UnsafeCell<")
        || !name.ends_with('>')
    {
        return None;
    }

    let [param] = st.template_params.as_ref() else { return None };
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
    Some(DebugFormat::Transparent { member: index as u32 })
}

fn loom_atomic_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
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
        if member.offset != 0
            || member.name.map(|name| reader.strings.get(name)) != Some("inner")
        {
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
    Some(DebugFormat::Transparent { member: index as u32 })
}

fn non_null_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let (member, _) = non_null_layout(reader, id)?;
    Some(DebugFormat::Transparent { member })
}

fn non_null_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::ptr::non_null" || !name.starts_with("NonNull<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else { return None };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let target = reader.canonicalize(param.type_id);
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        if member.offset != 0
            || member.name.map(|name| reader.strings.get(name)) != Some("pointer")
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
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::ptr::unique" || !name.starts_with("Unique<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else { return None };
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
    Some(DebugFormat::Transparent { member: index as u32 })
}

fn usize_no_high_bit_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    if fq_name(reader, id).as_deref() != Some("core::num::niche_types::UsizeNoHighBit") {
        return None;
    }
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let mut matches = st.members.iter().enumerate().filter(|(_, member)| {
        member.offset == 0
            && member.name.map(|name| reader.strings.get(name)) == Some("__0")
            && is_unsigned_integer(reader, member.type_id, crate::bundle::POINTER_SIZE)
    });
    let (index, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(DebugFormat::Transparent { member: index as u32 })
}

fn atomic_debug_format(reader: &DwReader<'_>, id: TypeId) -> Option<DebugFormat> {
    let RawType::Struct(st) = reader.canonical_type(id)? else { return None };
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::sync::atomic" || !name.starts_with("Atomic<") || !name.ends_with('>') {
        return None;
    }

    let [param] = st.template_params.as_ref() else { return None };
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
    let [value] = paths.as_slice() else { return None };
    Some(DebugFormat::Known(crate::bundle::KnownFormat::Atomic {
        value: value.clone(),
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
    for (index, member) in members.iter().enumerate().filter(|(_, member)| member.offset == 0) {
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
    for part in [loc.dir.as_deref(), loc.file.as_deref()].into_iter().flatten() {
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

    /// Emit a type (and, transitively, everything it references),
    /// returning its bundle id.
    fn emit(&mut self, id: TypeId) -> BundleTypeId {
        let root = self.reserve(id);
        while let Some((tid, bid)) = self.pending.pop_front() {
            let def = self.convert(tid);
            self.defs[bid.0 as usize] = def;
            if let Some(format) = btree_map_debug_format(self.reader, tid) {
                let format = crate::bundle::KnownFormat::BTreeMap {
                    root: format.root,
                    length: format.length,
                    root_node: format.root_node,
                    height: format.height,
                    node: format.node,
                    key: self.reserve(format.key),
                    value: self.reserve(format.value),
                    leaf: self.reserve(format.leaf),
                    leaf_len: format.leaf_len,
                    leaf_keys: format.leaf_keys,
                    leaf_values: format.leaf_values,
                    internal: self.reserve(format.internal),
                    internal_data: format.internal_data,
                    internal_edges: format.internal_edges,
                    edge: format.edge,
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
        self.defs.push(TypeDef::Opaque { name: n, size: None });
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
    fn member_decl(
        &mut self,
        m: &crate::raw_types::RawMember<crate::StrId>,
    ) -> Option<SourceLoc> {
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
                let name = self
                    .fq_name(id)
                    .unwrap_or_else(|| "<anon>".to_owned());
                TypeDef::Struct {
                    name: self.interner.intern(&name),
                    size: st.size,
                    members: st.members.iter().map(|m| self.convert_member(m)).collect(),
                }
            }
            RawType::Union(u) => {
                let name = self
                    .fq_name(id)
                    .unwrap_or_else(|| "<anon>".to_owned());
                TypeDef::Union {
                    name: self.interner.intern(&name),
                    size: u.size,
                    members: u.members.iter().map(|m| self.convert_member(m)).collect(),
                }
            }
            RawType::Enum(e) => {
                let name = self
                    .fq_name(id)
                    .unwrap_or_else(|| "<anon>".to_owned());
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
            .filter_map(|(i, n)| {
                n.as_ref()
                    .map(|n| (n.clone(), BundleTypeId(i as u32)))
            })
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
        has_dyn_tail, match_static_symbol, scan_vtable_section, StaticRole, VtableTypeHint,
    };
    use crate::raw_types::{RawMember, RawStruct, RawType};
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
        let inner_name = reader.strings.intern("alloc::sync::ArcInner<dyn app::Trait>");
        let outer_name = reader.strings.intern("app::Outer<alloc::sync::ArcInner<dyn app::Trait>>");
        let plain_name = reader.strings.intern("app::Plain");
        reader.types.insert(dyn_id, empty_struct(dyn_name));
        reader.types.insert(inner_id, wrapper(inner_name, dyn_id));
        reader.types.insert(outer_id, wrapper(outer_name, inner_id));
        reader.types.insert(plain_id, empty_struct(plain_name));

        assert!(has_dyn_tail(&reader, dyn_id, &mut Vec::new()));
        assert!(has_dyn_tail(&reader, inner_id, &mut Vec::new()));
        assert!(has_dyn_tail(&reader, outer_id, &mut Vec::new()));
        assert!(!has_dyn_tail(&reader, plain_id, &mut Vec::new()));
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
        let mpmc_context =
            "_RNvNCNvNvMNtNtNtCsijgp68BdGXk_3std4sync4mpmc7contextNtB8_7Context4with7CONTEXT023___RUST_STD_INTERNAL_VAL";
        let tokio_local =
            "_RNvNCNvNtNtCsjd01hASgEtw_5tokio4task5local7CURRENT023___RUST_STD_INTERNAL_VAL";
        let parking_lot =
            "_RNvNCNvNvNtCs6eIw0jaMQft_16parking_lot_core11parking_lot16with_thread_data11THREAD_DATA023___RUST_STD_INTERNAL_VAL";
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

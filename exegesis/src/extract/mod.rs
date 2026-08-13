//! The extraction pipeline (`exegesis extract`): turn a debug
//! binary's DWARF into a [`Bundle`].
//!
//! The pipeline has three phases:
//!
//! 1. **Seed discovery**: one sweep over all subprograms finds the
//!    `tokio::runtime::task::raw` vtable-fn instantiations (grouped per
//!    `(T, S)` by the DIE references of their template parameters),
//!    `<T as Future>::poll` impls, and `core::ptr::drop_glue::<T>`
//!    instantiations; separate lookups resolve the infra types and
//!    the named statics.
//! 2. **Type binding**: `Cell<T, S>` is recovered structurally from
//!    `dealloc`'s `NonNull<Cell<T, S>>` parameter (falling back to a
//!    namespace scan matched on template parameters — never on
//!    reconstructed name strings), and `Stage<T>` by walking the member
//!    graph from `Cell`.
//! 3. **Closure and emission**: a worklist over DIE references
//!    converts every reachable type into a [`TypeDef`], interning strings
//!    and remapping DWARF offsets to dense [`BundleTypeId`]s. Anything
//!    unmodelable becomes an explicit `Opaque` entry and a stats counter —
//!    no silent omissions.

mod emitter;
mod passes;
mod paths;
mod statics;
mod sweep;
mod vtables;

pub(crate) use emitter::Emitter;

use self::paths::{OwnedLoc, display_path, rustc_below_floor, rustc_version_of, tokio_version_of};
use self::statics::find_statics;
use self::sweep::{Sweep, cell_from_dealloc_param, find_stage, sweep_functions};
use self::vtables::{VtableTypeHint, discover_vtable_types, resolve_vtable_type_hints};
use crate::bundle::{
    BinaryIdent, Bundle, BundleTypeId, DynFutureTable, FutureKind, InfraTypes, Meta, Provenance,
    ProvenanceTable, SourceLoc, StaticsTable, TaskEntryId, TaskFutureEntry, TaskTable,
};
use crate::detect::{Family, FormatExplanation, struct_of};
use crate::raw_types::{NsId, RawType};
use crate::symbols::normalized_value_index;
use crate::view::DwView;
use crate::{DwReader, TypeId};

use object::{Object, ObjectSymbol};
use tracing::warn;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

const TASK_RAW_NS: &str = "tokio::runtime::task::raw";
const TASK_CORE_NS: &str = "tokio::runtime::task::core";
const DROP_GLUE_NS: &str = "core::ptr";

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
    /// Report how the walk binder resolved each contract role whose name
    /// contains this substring (`--explain-walk`).
    pub explain_walk: Option<String>,
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
    /// Walk-binder traces requested with [`ExtractOptions::explain_walk`],
    /// one per matching role. Like the formatter traces, rendered by the
    /// CLI rather than by the `Display` form.
    pub walk_explanations: Vec<crate::detect::walk::WalkExplanation>,
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
            // The named statics are recovered from the symbol table alone
            // (see `find_statics`), and a symbol can live in either table —
            // illumos release builds keep `WAKER_VTABLE` only in
            // `.symtab`/`.dynsym` — so gather both.
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

    extract_from_view(&view, &symbols, ident, opts, &vtable_types)
}

/// One infra type's slot: the DWARF path it is found under, and the type
/// the lookup resolved — `None` when the target has no such type.
struct InfraSlot {
    path: &'static str,
    id: Option<TypeId>,
}

/// The infra types extraction locates, one named field per role, so
/// the lookup, the tokio_unstable probe, the walk roots, and the bundle's
/// [`InfraTypes`] all address a slot by name — a reorder here cannot
/// quietly relabel one. Declaration order is emission order: the bundle
/// ids the slots emit under are sequential, so it must not change without
/// a reason.
struct InfraIds {
    header: InfraSlot,
    vtable: InfraSlot,
    trailer: InfraSlot,
    context: InfraSlot,
    scheduler_handle: InfraSlot,
    mt_handle: InfraSlot,
    ct_handle: InfraSlot,
    location: InfraSlot,
    raw_waker_vtable: InfraSlot,
}

impl InfraIds {
    /// Look every role up in the target's DWARF, recording each miss.
    ///
    /// The two scheduler-flavor handles are an at-least-one group: which
    /// flavors a target compiles in is a build fact (`rt-multi-thread`
    /// off leaves no multi_thread types), so one flavor missing is an
    /// expected shape the walk binder records per row, and only both
    /// missing is a missing-infra failure.
    fn resolve(view: &DwView<'_>, reader: &DwReader<'_>, stats: &mut ExtractStats) -> InfraIds {
        let lookup = |path: &'static str| InfraSlot {
            path,
            id: view
                .find_all_ids(path)
                .first()
                .map(|&id| reader.canonicalize(id)),
        };
        let mut slot = |path: &'static str| {
            let slot = lookup(path);
            if slot.id.is_none() {
                stats.infra_missing.push(path.to_owned());
            }
            slot
        };
        let ids = InfraIds {
            header: slot("tokio::runtime::task::core::Header"),
            vtable: slot("tokio::runtime::task::raw::Vtable"),
            trailer: slot("tokio::runtime::task::core::Trailer"),
            context: slot("tokio::runtime::context::Context"),
            scheduler_handle: slot("tokio::runtime::scheduler::Handle"),
            mt_handle: lookup("tokio::runtime::scheduler::multi_thread::handle::Handle"),
            ct_handle: lookup("tokio::runtime::scheduler::current_thread::Handle"),
            location: slot("core::panic::location::Location"),
            raw_waker_vtable: slot("core::task::wake::RawWakerVTable"),
        };
        if ids.mt_handle.id.is_none() && ids.ct_handle.id.is_none() {
            for slot in [&ids.mt_handle, &ids.ct_handle] {
                stats.infra_missing.push(slot.path.to_owned());
            }
        }
        ids
    }
}

fn extract_from_view(
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

    // --- Phase 1: one sweep over all subprograms. ---
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

    // --- Phase 2: per-instantiation type binding. ---

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
    for ((t, s), seed) in seeds {
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
            symbols: seed.symbols,
            poll_symbols: seed.poll_symbols,
            poll_func_loc: seed.poll_func_loc,
        });
    }

    // Dyn-future table: every `<T as Future>::poll` impl, plus the
    // matching `drop_glue::<T>` instantiations. drop_glue exists
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

    // Infra types and statics.
    let infra = InfraIds::resolve(view, reader, &mut stats);

    // Whether the target was built with `--cfg tokio_unstable`, decided
    // structurally: the task `Vtable`'s `spawn_location_offset` member is
    // behind that cfg (tokio 1.50 through 1.53), so its presence in an
    // otherwise-resolved vtable is the build flavor. Unknown when the
    // vtable type itself is missing.
    let tokio_unstable = infra.vtable.id.map(|vtable| {
        struct_of(reader, vtable).is_some_and(|st| {
            st.members
                .iter()
                .any(|m| m.name.map(|n| reader.strings.get(n)) == Some("spawn_location_offset"))
        })
    });

    let statics = find_statics(symbols, &mut stats);

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

    // --- Phase 3: transitive closure and emission. ---

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
    let mut walk_cells: Vec<(String, Option<TypeId>)> = Vec::new();

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
        walk_cells.push((display.clone(), task.cell));
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

    let mut emit_infra = |slot: &InfraSlot| match slot.id {
        Some(id) => em.emit(id),
        None => em.placeholder(&format!("<missing: {}>", slot.path)),
    };
    let infra_types = InfraTypes {
        header: emit_infra(&infra.header),
        vtable: emit_infra(&infra.vtable),
        trailer: emit_infra(&infra.trailer),
        context: emit_infra(&infra.context),
        scheduler_handle: emit_infra(&infra.scheduler_handle),
        mt_handle: emit_infra(&infra.mt_handle),
        ct_handle: emit_infra(&infra.ct_handle),
        location: emit_infra(&infra.location),
        raw_waker_vtable: emit_infra(&infra.raw_waker_vtable),
    };

    for id in include_ids {
        em.emit(id);
    }
    for id in vtable_type_ids {
        em.emit(id);
    }

    // Bind the walk contract against this target's DWARF. Runs after every
    // root above is emitted — the binder's leaf scan reads the emitted-type
    // map, and its recorded roots are bundle ids — and before `em.finish()`,
    // since it interns the names its steps address. Failure is recorded in
    // the outcomes, never fatal here.
    let walk_roots = crate::detect::walk::WalkRoots {
        context: infra.context.id,
        header: infra.header.id,
        trailer: infra.trailer.id,
        vtable: infra.vtable.id,
        location: infra.location.id,
        mt_handle: infra.mt_handle.id,
        ct_handle: infra.ct_handle.id,
        cells: &walk_cells,
        tokio_unstable,
    };
    let (walks, walk_explanations) =
        crate::detect::walk::bind_walks(&mut em, &walk_roots, opts.explain_walk.as_deref());
    stats.walk_explanations = walk_explanations;

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
        walks,
        infra: infra_types,
        provenance: ProvenanceTable {
            entries: provenance,
        },
    };

    Ok((bundle, stats))
}

/// Strip a `.llvm.<decimal>` suffix; symbol-table keys are stored
/// unsuffixed. DWARF linkage names are unsuffixed in practice, so
/// this is insurance.
fn strip(symbol: &str) -> &str {
    crate::bundle::strip_llvm_suffix(symbol)
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

/// Determine a task future's provenance: coroutine env types name
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
        let path = raw.namespace().map(|ns| ns_path(reader, ns));
        let root = path.as_deref().and_then(|path| path.split("::").next());
        match root {
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
            if !leaf.starts_with('{')
                && let Some(func) = view.find_func(&ns_path(reader, id))
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

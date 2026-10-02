// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The extraction pipeline (`hansei tokio-info extract`): turn a debug
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
mod labels;
mod passes;
mod paths;
mod releases;
mod semantics;
mod sources;
mod statics;
mod sweep;
mod vtables;

pub(crate) use emitter::Emitter;
pub use semantics::{UnreviewedRelease, UnreviewedReleases};
pub use sources::DebugFlavor;

use self::paths::{
    Agreement, OwnedLoc, agreed_site, display_path, owned_loc, rustc_below_floor, rustc_version_of,
    tokio_version_of,
};
use self::statics::find_statics;
use self::sweep::{PollTrait, Sweep, cell_from_dealloc_param, find_stage, sweep_functions};
use self::vtables::{
    VtableImage, VtableTypeHint, discover_vtable_types, resolve_vtable_type_hints,
};
use crate::bundle::{
    BinaryIdent, Bundle, DebugSourceIdent, DynFutureTable, FamilyCeiling, FutureKind, InfraTypes,
    Meta, Provenance, ProvenanceTable, SourceLoc, StaticsTable, TaskEntryId, TaskFutureEntry,
    TaskTable, VtableDataSource,
};
use crate::detect::semantics::{RustcConvention, rustc_conventions_outgrown};
use crate::detect::{Family, FormatExplanation, struct_of};
use crate::raw_types::{NsId, RawType};
use crate::symbols::{normalized_candidate_index, symbol_candidate_index};
use crate::view::{DwView, Func, SourceLocView};
use crate::{DwReader, TypeId};

use object::{Object, ObjectSymbol};
use tracing::{debug, warn};

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
    /// extraction command line, reduced to the inputs that shape the
    /// bundle so that re-extracting writes the same bytes).
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
    /// `--stats` summary; `hansei tokio-info extract --explain-format` renders these
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
    /// Emitted types whose `Future::poll` or `Stream::poll_next`
    /// declaration the bundle records the line of.
    pub poll_decls: usize,
    /// Emitted types whose declarations of one poll method disagreed on
    /// where it is written, so no line was recorded for that method.
    /// A toolchain that starts spelling one `poll` two ways shows up
    /// here rather than as silence.
    pub poll_decls_declined: usize,
    /// Frame-resident locals of emitted coroutines whose declaration
    /// the bundle records the line of.
    pub local_decls: usize,
    /// Payload members of emitted coroutines whose resume-function
    /// locals of that name disagreed on where they are declared — a
    /// name shadowed across scopes — so no line was recorded for them.
    pub local_decls_declined: usize,
    /// Emitted types whose own declarations name their crate's
    /// release, so the bundle labels them with it.
    pub crate_labels: usize,
    /// Of those, types two releases declare with one layout, so the
    /// label names both.
    pub crate_labels_several_releases: usize,
    /// Emitted types whose declarations named two different packages
    /// that both spell the type's crate, so no label was recorded.
    pub crate_labels_declined: usize,
    /// Plain types of crates the binary links at several releases
    /// that those releases lay out at different sizes.
    pub release_sizes: usize,
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
    /// Partition passes the reader ran over the named types before
    /// their identities settled.
    pub identity_passes: usize,
    /// Group partitions the reader computed over those passes.
    pub groups_repartitioned: usize,
    /// Declarations the reader placed in a definition class by the
    /// evidence of their unit.
    pub declarations_placed: usize,
    /// Declarations no unit evidence placed, left as types of their own.
    pub declarations_unresolved: usize,
    /// Of those, the ones the bundle reached and emitted: the reads that
    /// actually go through a declaration nothing placed, each declined
    /// as a type of its own.
    pub declarations_unresolved_emitted: usize,
    /// Each declined declaration the bundle emits, by name, unit and
    /// classes: what the summary names, where the count alone would
    /// hide which read lands on a type with no layout.
    pub declined_declarations: Vec<String>,
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
    /// Members matching `Unresumed`'s that a block's suspended state kept
    /// as its captures.
    pub state_captures_kept: usize,
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
    /// The producer's rustc version when it is newer than the review of
    /// some compiler convention, with each convention it outgrew: those
    /// bind nothing the compiler emitted.
    pub rustc_outgrown: Option<(String, Vec<&'static RustcConvention>)>,
    /// The crate releases no review covers that some record names a
    /// rule declining over, each with the families that declined.
    pub unreviewed_releases: UnreviewedReleases,
}

impl ExtractStats {
    /// What the reviews could not vouch for, one sentence per subject:
    /// the compiler conventions a newer rustc outgrew, by range, and
    /// each crate release a rule declined over. The `--stats` form and
    /// the extract verb's warnings both say these.
    pub fn review_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some((version, outgrown)) = &self.rustc_outgrown {
            let mut by_range: BTreeMap<String, Vec<&str>> = BTreeMap::new();
            for convention in outgrown {
                by_range
                    .entry(convention.range())
                    .or_default()
                    .push(convention.family);
            }
            for (range, families) in by_range {
                out.push(format!(
                    "rustc {version} is newer than the reviewed range {range} of {}, \
                     whose rules decline over it",
                    conjoin(&families)
                ));
            }
        }
        for (release, families) in &self.unreviewed_releases {
            let families: Vec<&str> = families.iter().copied().collect();
            out.push(format!(
                "{release} of {}, whose rules decline over it",
                conjoin(&families)
            ));
        }
        out
    }
}

/// `a`, `a and b`, `a, b and c`.
fn conjoin(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
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
        writeln!(f, "  poll decls:             {}", self.poll_decls)?;
        writeln!(f, "  poll decls declined:    {}", self.poll_decls_declined)?;
        writeln!(f, "  local decls:            {}", self.local_decls)?;
        writeln!(f, "  local decls declined:   {}", self.local_decls_declined)?;
        writeln!(f, "  crate labels:           {}", self.crate_labels)?;
        writeln!(
            f,
            "  of which two releases:  {}",
            self.crate_labels_several_releases
        )?;
        writeln!(
            f,
            "  crate labels declined:  {}",
            self.crate_labels_declined
        )?;
        writeln!(f, "  release sizes:          {}", self.release_sizes)?;
        writeln!(f, "types:")?;
        writeln!(f, "  emitted:                {}", self.types_emitted)?;
        writeln!(f, "  opaque:                 {}", self.opaque_types)?;
        writeln!(f, "  identity passes:        {}", self.identity_passes)?;
        writeln!(f, "  groups repartitioned:   {}", self.groups_repartitioned)?;
        writeln!(f, "  decls placed by unit:   {}", self.declarations_placed)?;
        writeln!(
            f,
            "  decls unresolved:       {}",
            self.declarations_unresolved
        )?;
        writeln!(
            f,
            "  of which emitted:       {}",
            self.declarations_unresolved_emitted
        )?;
        for declined in &self.declined_declarations {
            writeln!(f, "    declined: {declined}")?;
        }
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
        writeln!(f, "  captures kept:          {}", self.state_captures_kept)?;
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
        for warning in self.review_warnings() {
            writeln!(f, "  WARNING: {warning}")?;
        }
        Ok(())
    }
}

/// Why an extraction failed.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to read an extraction input")]
    Io(#[from] std::io::Error),
    #[error("failed to parse an extraction input")]
    Object(#[from] object::read::Error),
    #[error("failed to read DWARF")]
    Dwarf(#[from] crate::Error),
    #[error(
        "{path} is {flavor}, which holds no program contents; extraction \
         also needs the binary it was split from — pass that binary, with \
         {path} as --debug-info"
    )]
    SplitAlone { path: String, flavor: DebugFlavor },
    #[error("no debug info in {path}: it carries no DWARF")]
    NoDebugInfo { path: String },
    #[error(
        "the debug info in {path} was split out at build time \
         (-C split-debuginfo): its units are skeletons whose DIEs live \
         in a DWARF package — pass the .dwp as --debug-info"
    )]
    SplitOutDwarf { path: String },
    #[error(
        "{debug_info} was not split from {binary}: {reason}. A separate \
         debug build is not a sibling — extract from it alone."
    )]
    SiblingMismatch {
        binary: String,
        debug_info: String,
        reason: String,
    },
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
    #[error("extracted bundle failed validation: {0}")]
    InvalidBundle(#[from] hansei_bundle::Error),
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

/// Read a parsed object's DWARF sections, and the endianness they are
/// to be read with. Borrowing them into a `gimli::Dwarf` stays with the
/// caller: that borrow lives no longer than the caller's frame.
fn load_dwarf_sections<'data>(
    obj: &object::File<'data>,
) -> Result<(
    gimli::DwarfSections<std::borrow::Cow<'data, [u8]>>,
    gimli::RunTimeEndian,
)> {
    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load_section = |id: gimli::SectionId| -> std::result::Result<
        std::borrow::Cow<'data, [u8]>,
        Box<dyn std::error::Error>,
    > {
        use object::ObjectSection;
        Ok(match obj.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => std::borrow::Cow::Borrowed(&[]),
        })
    };
    let sections = gimli::DwarfSections::load(&load_section)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok((sections, endian))
}

/// Whether this DWARF's leading units are fission skeletons, their
/// DIEs split out into a `.dwo`/`.dwp`. Probes only the first few
/// units: rustc's split builds make every unit a skeleton, and probing
/// them all would tax every normal extraction for the sake of an error
/// message.
fn references_split_dwarf<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
) -> std::result::Result<bool, gimli::Error> {
    let mut units = dwarf.units();
    for _ in 0..8 {
        let Some(header) = units.next()? else {
            break;
        };
        if dwarf.unit(header)?.dwo_id.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read a parsed dwp's `.dwo` sections and unit indexes, by the dwo
/// spellings of their names. Like [`load_dwarf_sections`], borrowing
/// them into a [`gimli::DwarfPackage`] stays with the caller.
fn load_dwarf_package_sections<'data>(
    obj: &object::File<'data>,
) -> Result<gimli::DwarfPackageSections<std::borrow::Cow<'data, [u8]>>> {
    let load_section = |id: gimli::SectionId| -> std::result::Result<
        std::borrow::Cow<'data, [u8]>,
        Box<dyn std::error::Error>,
    > {
        use object::ObjectSection;
        let name = id.dwo_name().expect("every dwp section has a dwo name");
        Ok(match obj.section_by_name(name) {
            Some(section) => section.uncompressed_data()?,
            None => std::borrow::Cow::Borrowed(&[]),
        })
    };
    gimli::DwarfPackageSections::load(&load_section)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))
}

/// What a binary's DWARF holds before extraction selects anything out of
/// it. A count of zero types says the parse found nothing to read, which
/// is the question this answers that a failed extraction cannot: whether
/// the binary carries debug info at all.
pub struct DwarfSummary {
    pub types: usize,
    pub statics: usize,
    pub duplicate_strings: usize,
    pub strings: usize,
}

/// Parse a binary's DWARF and count what came out of it, without
/// selecting anything or building a bundle.
pub fn dwarf_summary(path: &Path) -> Result<DwarfSummary> {
    let f = std::fs::File::open(path)?;
    let obj_bytes = unsafe { memmap2::Mmap::map(&f) }?;
    let obj = object::File::parse(&obj_bytes[..])?;
    let (sections, endian) = load_dwarf_sections(&obj)?;
    let borrow_section =
        |section| gimli::EndianSlice::new(std::borrow::Cow::as_ref(section), endian);
    let dwarf = sections.borrow(borrow_section);

    let dw = DwReader::read_types(&dwarf, Default::default())?;
    Ok(DwarfSummary {
        types: dw.types.len(),
        statics: dw.variables.len(),
        duplicate_strings: dw.strings.dups_found(),
        strings: dw.strings.len(),
    })
}

/// One extraction input, mapped: the `Arc` is what lets a hashing
/// thread hold the bytes independently of the parse's borrows.
struct Input {
    basename: String,
    display: String,
    bytes: std::sync::Arc<memmap2::Mmap>,
}

impl Input {
    fn open(path: &Path) -> Result<Input> {
        let f = std::fs::File::open(path)?;
        let bytes = std::sync::Arc::new(unsafe { memmap2::Mmap::map(&f) }?);
        Ok(Input {
            basename: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            display: path.display().to_string(),
            bytes,
        })
    }

    /// Hash the whole file for the bundle's identity on a background
    /// thread, over the pool: BLAKE3 over a multi-gigabyte binary is
    /// pure overhead on the critical path, and one thread's pass takes
    /// longer than the parse it was meant to hide behind, whose own
    /// workers mostly wait on the collector anyway.
    ///
    /// The mapping is advised first that all of it is wanted. Warm, that
    /// is free; cold, it turns the parse's random faults into read-ahead
    /// the kernel runs beside them — a page the parse reaches is then
    /// already on its way — and the hash's own sequential pass follows
    /// behind. Advice is advice: a system that ignores it loses nothing.
    fn hash(&self) -> std::thread::JoinHandle<blake3::Hash> {
        let bytes = std::sync::Arc::clone(&self.bytes);
        std::thread::spawn(move || {
            let _ = bytes.advise(memmap2::Advice::WillNeed);
            blake3::Hasher::new().update_rayon(&bytes[..]).finalize()
        })
    }
}

/// What extraction reads: the binary, and optionally a separate
/// debug-info file its DWARF comes from.
pub struct DebugSources<'a> {
    /// The binary that ran (and will run): program contents, identity,
    /// and symbols come from here.
    pub binary: &'a Path,
    /// Separate debug info — a companion file, a dSYM, a dwp, or a
    /// full debug binary split after this pair's shared link. Supplies
    /// the DWARF (and more symbols) when given.
    pub debug_info: Option<&'a Path>,
}

/// Extract a bundle under the full input contract: flavors detected by
/// content, split debug info refused without its sibling binary, and
/// the pair verified to be two halves of one link. This is the entry
/// point behind every user-facing extraction; [`extract_file`] is the
/// permissive single-file form.
pub fn extract_sources(
    sources: &DebugSources<'_>,
    opts: &ExtractOptions,
) -> Result<(Bundle, ExtractStats)> {
    extract_sources_with(sources, opts, ParsedDwarf::Free, |bundle, stats| {
        (bundle, stats)
    })
}

/// What becomes of the parsed DWARF once the bundle is built from it.
///
/// Freeing it is not cheap: the parse leaves millions of small
/// allocations behind, and dropping them serially takes a second on a
/// fast allocator and several on a slow one — time the bundle's
/// consumer need not wait for, because nothing of the bundle borrows
/// from the parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParsedDwarf {
    /// Freed on a helper thread while the continuation runs; the call
    /// returns once both are done.
    Free,
    /// Never freed. For a process that exits as soon as the continuation
    /// returns, whose exit reclaims the whole address space at once.
    Leak,
}

/// [`extract_sources`], with what happens next overlapped with freeing
/// the parsed DWARF: `then` runs with the bundle as soon as it is built,
/// and the parse's memory is disposed of per `parsed` in the meantime.
pub fn extract_sources_with<R>(
    sources: &DebugSources<'_>,
    opts: &ExtractOptions,
    parsed: ParsedDwarf,
    then: impl FnOnce(Bundle, ExtractStats) -> R,
) -> Result<R> {
    let binary = Input::open(sources.binary)?;
    let binary_obj = object::File::parse(&binary.bytes[..])?;
    let flavor = sources::classify(&binary_obj);

    // Whatever else was passed, the binary role must be filled by a
    // file with program contents in it.
    if flavor.is_split() {
        return Err(Error::SplitAlone {
            path: binary.display.clone(),
            flavor,
        });
    }

    let Some(debug_path) = sources.debug_info else {
        return match flavor {
            DebugFlavor::Full => extract_parsed(&binary, &binary_obj, None, opts, parsed, then),
            DebugFlavor::NoDebugInfo => Err(Error::NoDebugInfo {
                path: binary.display.clone(),
            }),
            DebugFlavor::Companion | DebugFlavor::Dwp => unreachable!("refused above"),
        };
    };

    let debug = Input::open(debug_path)?;
    let debug_obj = object::File::parse(&debug.bytes[..])?;
    match sources::classify(&debug_obj) {
        DebugFlavor::NoDebugInfo => Err(Error::NoDebugInfo {
            path: debug.display.clone(),
        }),
        // A dwp carries no build-id and no placed sections to compare;
        // the dwo-id join inside the read is the pairing check.
        DebugFlavor::Dwp => extract_parsed(
            &binary,
            &binary_obj,
            Some((&debug, &debug_obj)),
            opts,
            parsed,
            then,
        ),
        DebugFlavor::Full | DebugFlavor::Companion => {
            if let Some(reason) = sources::sibling_mismatch(&binary_obj, &debug_obj) {
                return Err(Error::SiblingMismatch {
                    binary: binary.display.clone(),
                    debug_info: debug.display.clone(),
                    reason,
                });
            }
            extract_parsed(
                &binary,
                &binary_obj,
                Some((&debug, &debug_obj)),
                opts,
                parsed,
                then,
            )
        }
    }
}

/// Classify a file by content, the way [`extract_sources`] will see it.
/// This is what lets a caller decide up front whether a `--debug-info`
/// file needs its sibling binary passed alongside.
pub fn classify_file(path: &Path) -> Result<DebugFlavor> {
    let input = Input::open(path)?;
    let obj = object::File::parse(&input.bytes[..])?;
    Ok(sources::classify(&obj))
}

/// Extract a bundle from one DWARF-bearing object, with none of the
/// input contract enforced: a companion alone extracts (with nothing
/// for the vtable scan to read, which the bundle records), and a
/// DWARF-less binary extracts to an empty bundle. The tests' entry
/// point; user-facing callers go through [`extract_sources`].
pub fn extract_file(path: &Path, opts: &ExtractOptions) -> Result<(Bundle, ExtractStats)> {
    let input = Input::open(path)?;
    let obj = object::File::parse(&input.bytes[..])?;
    extract_parsed(
        &input,
        &obj,
        None,
        opts,
        ParsedDwarf::Free,
        |bundle, stats| (bundle, stats),
    )
}

/// The pipeline behind both entry points: DWARF from the debug-info
/// file when given (else the binary), symbols from every input, data
/// sections and identity from the binary.
fn extract_parsed<R>(
    binary: &Input,
    binary_obj: &object::File<'_>,
    debug: Option<(&Input, &object::File<'_>)>,
    opts: &ExtractOptions,
    parsed: ParsedDwarf,
    then: impl FnOnce(Bundle, ExtractStats) -> R,
) -> Result<R> {
    let binary_hash = binary.hash();
    let debug_hash = debug.map(|(input, _)| input.hash());

    // A dwp holds only the split-out halves of the binary's units, so
    // the `Dwarf` proper — skeletons, `.debug_addr`, the skeleton line
    // tables — is loaded from the *binary*, and the package is resolved
    // against it one skeleton at a time inside the reader. Every other
    // debug-info flavor is itself the DWARF to read.
    let package_obj = debug
        .map(|(_, obj)| obj)
        .filter(|obj| sources::classify(obj) == DebugFlavor::Dwp);
    let dwarf_obj = match package_obj {
        Some(_) => binary_obj,
        None => debug.map(|(_, obj)| obj).unwrap_or(binary_obj),
    };
    let (sections, endian) = load_dwarf_sections(dwarf_obj)?;
    let borrow_section =
        |section| gimli::EndianSlice::new(std::borrow::Cow::as_ref(section), endian);
    let dwarf = sections.borrow(borrow_section);
    let package_sections = package_obj.map(load_dwarf_package_sections).transpose()?;
    let package = package_sections
        .as_ref()
        .map(|s| s.borrow(borrow_section, gimli::EndianSlice::new(&[], endian)))
        .transpose()
        .map_err(crate::Error::from)?;

    // A packed-split binary classifies as full — it has DWARF sections
    // with contents — but its units are skeletons whose DIEs live in
    // the dwp. Extracting from it alone would find nothing and blame
    // the target ("is this a tokio debug binary?"), so name the real
    // problem instead.
    if debug.is_none() && references_split_dwarf(&dwarf).map_err(crate::Error::from)? {
        return Err(Error::SplitOutDwarf {
            path: binary.display.clone(),
        });
    }

    // The vtable scan wants file bytes for the data sections, which a
    // companion (or dSYM) does not have — its program sections claim
    // memory no file range backs. Never read those as empty data
    // silently: scan only a file with contents, and record in the
    // bundle which file that was, or that there was none.
    let vtable_source = match sources::classify(binary_obj) {
        DebugFlavor::Companion => VtableDataSource::None,
        _ => VtableDataSource::File(binary.basename.clone()),
    };

    // Gathering the symbol tables and the vtable-type hints depends only
    // on the parsed objects, not on the DWARF, so run it on a helper
    // thread that overlaps the (parallel) parse. Serially it is ~0.4s of
    // scanning `.symtab`/`.dynsym` after the read has already finished;
    // overlapped, it is free.
    let (reader, symbols, vtable_types) = std::thread::scope(|scope| {
        let aux = scope.spawn(|| {
            // The named statics are recovered from the symbol table alone
            // (see `find_statics`), and a symbol can live in either table —
            // illumos release builds keep `WAKER_VTABLE` only in
            // `.symtab`/`.dynsym` — so gather both, from both files,
            // deduplicated: a split pair carries two copies of one table.
            let mut merged: BTreeSet<&str> = object_symbols(binary_obj).collect();
            if let Some((_, debug_obj)) = debug {
                merged.extend(object_symbols(debug_obj));
            }
            let symbols: Vec<&str> = merged.into_iter().collect();
            let vtable_types = match vtable_source {
                VtableDataSource::None => Vec::new(),
                VtableDataSource::File(_) => {
                    let image = VtableImage::read(binary_obj);
                    discover_vtable_types(binary_obj, &image)
                }
            };
            (symbols, vtable_types)
        });
        let reader = match package.as_ref() {
            Some(package) => DwReader::read_types_package(&dwarf, package, Default::default())?,
            None => DwReader::read_types(&dwarf, Default::default())?,
        };
        let (symbols, vtable_types) = aux.join().expect("symbol-gathering thread panicked");
        Ok::<_, Error>((reader, symbols, vtable_types))
    })?;

    let view = reader.view();

    let join_hash = |handle: std::thread::JoinHandle<blake3::Hash>| -> [u8; 32] {
        handle
            .join()
            .expect("BLAKE3 hashing thread panicked")
            .into()
    };
    let ident = Identity {
        binary: BinaryIdent {
            basename: binary.basename.clone(),
            build_id: sources::file_id(binary_obj),
            blake3: join_hash(binary_hash),
        },
        debug_info: debug.map(|(input, _)| DebugSourceIdent {
            basename: input.basename.clone(),
            blake3: join_hash(debug_hash.expect("hash handle exists with the input")),
        }),
        vtable_data: vtable_source,
    };

    let (bundle, stats) = extract_from_view(&view, &symbols, ident, opts, &vtable_types)?;
    // The bundle owns everything it carries, so the parse is dead
    // weight from here on. Freeing it is a second or more of serial
    // deallocation the continuation would otherwise wait behind.
    Ok(match parsed {
        ParsedDwarf::Leak => {
            std::mem::forget(reader);
            then(bundle, stats)
        }
        ParsedDwarf::Free => std::thread::scope(|scope| {
            scope.spawn(move || drop(reader));
            then(bundle, stats)
        }),
    })
}

/// Every symbol-table name in an object, spelled the way DWARF linkage
/// names — and any target the bundle is later resolved against — spell
/// it. Mach-O's linker prefixes every global symbol with an underscore
/// (`__RNv…` for a Rust v0 name `_RNv…`); undo it here, at the one
/// place symbols enter per file format, so every lookup downstream
/// compares like with like. Left alone, a bundle extracted on macOS
/// carries an empty fingerprint and statics under names no target
/// answers to.
fn object_symbols<'data: 'file, 'file>(
    obj: &'file object::File<'data>,
) -> impl Iterator<Item = &'data str> + 'file {
    let underscore_prefixed = obj.format() == object::BinaryFormat::MachO;
    obj.symbols()
        .chain(obj.dynamic_symbols())
        .filter_map(|s| s.name().ok())
        .map(move |name| match underscore_prefixed {
            true => name.strip_prefix('_').unwrap_or(name),
            false => name,
        })
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

/// What extraction records about its inputs: per-input identity, and
/// where the vtable scan read from.
struct Identity {
    binary: BinaryIdent,
    debug_info: Option<DebugSourceIdent>,
    vtable_data: VtableDataSource,
}

fn extract_from_view(
    view: &DwView<'_>,
    symbols: &[&str],
    ident: Identity,
    opts: &ExtractOptions,
    vtable_types: &[VtableTypeHint],
) -> Result<(Bundle, ExtractStats)> {
    let mut stats = ExtractStats::default();
    let reader = view.collector();
    stats.identity_passes = reader.identity.passes;
    stats.groups_repartitioned = reader.identity.groups_repartitioned;
    stats.declarations_placed = reader.identity.placed_declarations;
    stats.declarations_unresolved = reader.identity.unresolved_declarations.len();

    // Namespace ids for the sweep's membership tests. A missing namespace
    // (e.g. a binary without tokio) simply yields no matches.
    let raw_ns = view.find_ns(TASK_RAW_NS).map(|n| n.id());
    let core_ns = view.find_ns(TASK_CORE_NS).map(|n| n.id());
    let glue_ns = view.find_ns(DROP_GLUE_NS).map(|n| n.id());

    // --- Phase 1: one sweep over all subprograms. ---
    let Sweep {
        seeds,
        fut_polls,
        explicit_polls,
        stream_reads,
        extra_sets,
        poll_sources,
        poll_decls,
        coroutine_candidates,
        drop_glues,
        glue_by_name,
        resume_awaitees,
        resume_locals,
        vtable_missing_linkage,
        dyn_decl_only_self,
        dyn_unresolved_self,
        impl_selfs,
    } = sweep_functions(view, raw_ns, glue_ns);
    stats.vtable_missing_linkage += vtable_missing_linkage;
    stats.dyn_decl_only_self += dyn_decl_only_self;
    stats.dyn_unresolved_self += dyn_unresolved_self;

    // The same resolutions the other way, self type → its impl
    // namespaces, for the rules whose origin is a type's own method
    // declarations rather than a `poll`'s (a stream has none).
    let mut impls_by_self: BTreeMap<String, Vec<NsId>> = BTreeMap::new();
    for (ns, self_type) in &impl_selfs {
        if let Some(self_type) = self_type {
            impls_by_self
                .entry(self_type.clone())
                .or_default()
                .push(*ns);
        }
    }
    // The sweep's impl resolutions, keyed by namespace path — the
    // spelling names mention them by — for the emit-side filter.
    let impl_selfs: BTreeMap<String, String> = impl_selfs
        .into_iter()
        .filter_map(|(ns, self_type)| Some((ns_path(reader, ns), self_type?)))
        .collect();

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
    let mut dyn_symbols = Vec::new();
    for (&t, symbols) in &fut_polls {
        for sym in symbols {
            dyn_symbols.push((sym.clone(), t));
            stats.dyn_poll_symbols += 1;
        }
        if let Some(glue) = drop_glues.get(&t) {
            for sym in glue {
                dyn_symbols.push((sym.clone(), t));
                stats.dyn_glue_symbols += 1;
            }
        } else if let Some(glue) = fq_name(reader, t).and_then(|n| glue_by_name.get(&n)) {
            for sym in glue {
                dyn_symbols.push((sym.clone(), t));
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
    // Types the walk contract roots at that nothing a task holds
    // reaches: the blocking pool's queue element. Quietly absent where
    // the DWARF has none — the walk then records its own absence.
    let pool_task = view.find_all_ids("tokio::runtime::blocking::pool::Task");
    include_ids.extend(pool_task.iter().map(|&id| reader.canonicalize(id)));

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
    let mut task_symbols = Vec::new();
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
            scheduler_binding: None,
            display_name,
        });
        provenance.push(classify_future(
            reader,
            view,
            task.future,
            &mut em,
            &mut stats,
        ));

        for sym in &task.symbols {
            task_symbols.push((sym.clone(), entry_id));
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
    let by_symbol = symbol_candidate_index(task_symbols);
    stats.task_symbols = by_symbol.len();

    let dyn_by_symbol = symbol_candidate_index(dyn_symbols);
    let dyn_table = symbol_candidate_index(
        dyn_by_symbol
            .into_iter()
            .flat_map(|(sym, types)| types.into_iter().map(move |ty| (sym.clone(), ty)))
            .map(|(sym, ty)| (sym, em.emit(ty))),
    );

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
    // The concrete extras a hyper-util `Connected` may hold: reached only
    // through its trait object's vtable, so no member emits them, and a
    // case the table does not carry is no case.
    for &id in extra_sets.keys() {
        em.emit(id);
    }

    // The local-set types the walk binder's leaf rows root at.
    // `local::Shared` is normally swept in through the local task cells'
    // scheduler parameter; emitting it — and the `CURRENT` thread-local's
    // `LocalData`, which nothing else references — by name also covers a
    // target holding a `LocalSet` nothing was spawned onto. The emission
    // is keyed on the `CURRENT` static having been found in the symtab,
    // not on the types existing in DWARF: type DIEs for tokio's local
    // module survive in most binaries whether or not any LocalSet code is
    // linked, and rows bound against a type no code uses would turn the
    // static's expected absence into reported breakage. The symbol is
    // linked exactly when the machinery is.
    if statics.contains_key(&crate::bundle::StaticRole::TlsLocalSetKey) {
        for name in [
            "tokio::task::local::Shared",
            "tokio::task::local::LocalData",
        ] {
            for id in view.find_all_ids(name) {
                em.emit(reader.canonicalize(id));
            }
        }
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
    stats.rustc_outgrown = rustc_conventions_outgrown(producer)
        .map(|(version, outgrown)| (version.to_string(), outgrown));

    let newest = *Family::ALL.last().expect("at least one family");
    let (newest_major, newest_minor) = newest.floor();
    let meta = Meta {
        format_version: crate::bundle::FORMAT_VERSION,
        rustc_version,
        tokio_version,
        tokio_unstable,
        binary: ident.binary,
        debug_info: ident.debug_info,
        vtable_data: ident.vtable_data,
        extract_args: opts.extract_args.clone(),
        symbol_fingerprint: fingerprint.into_iter().collect(),
        newest_family: Some(FamilyCeiling {
            name: newest.name().to_owned(),
            major: newest_major,
            minor: newest_minor,
        }),
    };

    stats.unresolved_refs = em.unresolved_refs;
    stats.cenum_synth_repr = em.cenum_synth_repr;
    stats.format_explanations = std::mem::take(&mut em.explanations);
    stats.tokio_family_guessed = (em.versioned_dispatch && em.tokio_version.is_none())
        .then(|| Family::select(None).name().to_owned());
    // Declaration sites for every emitted closure/coroutine environment
    // type — the anchor behind a coroutine's `type defined at` line.
    // `env_decl_site` is the rule task provenance uses too, so a task's
    // `Defined at` and a frame holding the same env agree. Recorded for
    // closure envs as well as coroutine ones: nothing prints a closure's
    // today, and the site is a fact about the type either way.
    const ENV_MARKERS: [&str; 5] = [
        "{closure_env#",
        "{async_fn_env#",
        "{async_block_env#",
        "{async_closure_env#",
        "{coroutine_env#",
    ];
    let mut env_types: Vec<(TypeId, crate::bundle::BundleTypeId)> = em
        .emitted_named()
        .filter_map(|(tid, _)| {
            let raw = reader.canonical_type(tid)?;
            let name = reader.strings.get(raw.name()?);
            if !ENV_MARKERS.iter().any(|m| name.starts_with(m)) {
                return None;
            }
            Some((tid, em.bundle_id_of(tid)?))
        })
        .collect();
    // In bundle-id order, not DIE order: the sites' files are interned
    // as they are met, and a bundle's string table has to come out the
    // same whether its DWARF arrived packed or in place.
    env_types.sort_by_key(|&(_, bid)| bid);
    for (tid, bid) in env_types {
        if let Some(loc) = env_decl_site(reader, view, tid)
            && let Some(loc) = intern_loc(&mut em, &loc)
        {
            em.record_env_decl(bid, loc);
        }
    }

    // Where each emitted hand-written future's or stream's poll method
    // is written — the `defined at` of a trace frame or a wait-set
    // member of that type. Per trait, agree-or-nothing: a generic
    // `poll` instantiated in several units spells its file several
    // ways and agrees under the display path; two different `poll`s
    // for one self type would not, and a wrong line is worse than
    // none. A type that is both a future and a stream records the
    // future's line, since a chain is where its line prints most.
    // Bundle-id order again, for the same string-table reason.
    let mut poll_types: Vec<(TypeId, crate::bundle::BundleTypeId)> = poll_decls
        .keys()
        .filter_map(|&tid| Some((tid, em.bundle_id_of(tid)?)))
        .collect();
    poll_types.sort_by_key(|&(_, bid)| bid);
    for (tid, bid) in poll_types {
        let name = reader
            .canonical_type(tid)
            .and_then(|t| t.name())
            .map(|n| reader.strings.get(n))
            .unwrap_or("<anon>");
        if let Some(site) = poll_site(name, &poll_decls[&tid], &mut stats)
            && let Some(loc) = site.bundle_loc(&mut em.interner)
        {
            em.record_poll_decl(bid, loc);
        }
    }

    // The crate release each emitted type's own declarations name — what
    // tells two same-named types apart where the target links their
    // crate at two releases. Bundle-id order, for the string-table
    // reason above. The declarations are gathered once for these and
    // for the release sizes below.
    let mut labeled = releases::candidates(reader);
    labeled.extend(em.emitted_ids().map(|(tid, _)| tid));
    let declared = labels::declared_releases(reader, &labeled);
    let labels = labels::crate_labels(&em, &declared);
    stats.crate_labels = labels.labels.len();
    stats.crate_labels_several_releases = labels.several_releases();
    stats.crate_labels_declined = labels.declined;
    for (bid, (package, versions)) in &labels.labels {
        em.record_crate_label(*bid, package, versions);
    }

    // What tells a target's crate hashes apart when it links a crate
    // at two releases and was built apart from this binary: the sizes
    // the releases give the types they disagree on.
    let release_sizes = releases::release_sizes(reader, &declared);
    stats.release_sizes = release_sizes.len();
    em.record_release_sizes(&release_sizes);

    // Where each emitted coroutine's frame-resident locals are declared
    // — the `declared at` a task block prints under a value held in one.
    // The candidates are the coroutine's payload members' names: a
    // local that never crosses an await is in no payload, and no slot
    // path can step through it, so nothing is recorded for it. Per
    // name, agree-or-nothing once more: a `let` the compiler duplicated
    // agrees with itself, two `let x` in two scopes do not, and the
    // member does not say which scope's `x` it is. Bundle-id order, for
    // the string-table reason above.
    let mut coroutines: Vec<(TypeId, crate::bundle::BundleTypeId)> = resume_locals
        .keys()
        .filter_map(|&tid| Some((tid, em.bundle_id_of(tid)?)))
        .collect();
    coroutines.sort_by_key(|&(_, bid)| bid);
    for (tid, bid) in coroutines {
        let coroutine = reader
            .canonical_type(tid)
            .and_then(|t| t.name())
            .map(|n| reader.strings.get(n))
            .unwrap_or("<anon>");
        let locals = &resume_locals[&tid];
        let mut decls = Vec::new();
        for member in coroutine_payload_names(reader, tid) {
            let name = reader.strings.get(member);
            let sites: Vec<OwnedLoc> = locals
                .iter()
                .filter(|(n, _)| *n == member)
                .map(|(_, loc)| owned_loc(&SourceLocView::new(loc, reader)))
                .collect();
            if let Some(site) = local_decl_site(coroutine, name, &sites, &mut stats)
                && let Some(loc) = site.bundle_loc(&mut em.interner)
            {
                decls.push((em.intern(name), loc));
            }
        }
        em.record_local_decls(bid, decls);
    }

    // Which reviewed compiler convention, if any, a candidate's defining
    // units agree on — the coroutine convention for a coroutine, the
    // adapter or vtable one for a std pointer. Decided here, where the
    // reader's unit origins are at hand; the binder sees only verdicts.
    let compiler_verdict = |raw: TypeId, reviewed: semantics::Reviewed| {
        let convention = reader.type_convention(raw, |_, origin| {
            origin
                .producer
                .map(|p| reader.strings.get(p))
                .and_then(|producer| reviewed.select(producer))
        });
        match convention {
            Ok(convention) => {
                let producer = reader
                    .type_definitions(raw)
                    .next()
                    .and_then(|die| reader.die_origin(die.0))
                    .and_then(|(_, origin)| origin.producer)
                    .map(|p| reader.strings.get(p).to_owned());
                match producer {
                    Some(producer) => semantics::CompilerVerdict::Supported {
                        producer,
                        convention,
                    },
                    None => semantics::CompilerVerdict::Declined(
                        "the canonical definition records no producer".to_owned(),
                    ),
                }
            }
            Err(decline) => semantics::CompilerVerdict::Declined(format!("{decline:?}")),
        }
    };
    // Where a closure environment was declared, as the `select!` rule
    // reads its origin: the body fn's declaration file, joined the way
    // a poll declaration's is, so the same registry-path check applies.
    // Beside the origin, the arms of a `select!` as the closure its
    // environment belongs to recorded them: each anchor's pointee — the
    // `&mut` the macro took of a branch future, resolved to the
    // branch's own type, canonical like the layout's tuple members —
    // with the arm's pattern bindings. An anchor that is no pointer is
    // nothing the join can key on and is dropped.
    let env_facts = |env: TypeId| -> semantics::EnvFacts {
        let body = env_decl_func(reader, view, env);
        let arms = body
            .iter()
            .flat_map(|body| body.raw().select_arms.iter())
            .filter_map(|arm| {
                let Some(RawType::Pointer(p)) = reader.canonical_type(arm.anchor) else {
                    return None;
                };
                let bindings = arm
                    .bindings
                    .iter()
                    .map(|loc| paths::owned_loc(&SourceLocView::new(loc, reader)))
                    .collect();
                Some((reader.canonicalize(p.target_type_id), bindings))
            })
            .collect();
        semantics::EnvFacts {
            source: body.as_ref().and_then(|f| sweep::poll_source(reader, f)),
            arms,
        }
    };
    // Where a type's own methods were declared, for a rule over a type
    // that is no future and so has no poll: every subprogram under an
    // impl of that type, or under the type's own DIE, that records a
    // file, joined the way a poll declaration's is. rustc puts no
    // declaration file on the type DIE itself, so the methods are
    // where the file is recorded — trait impls in an `{impl#N}`
    // namespace the sweep resolved to the type, inherent methods as
    // declarations inside the type DIE, which the unit pass files
    // under a namespace named after the type.
    //
    // A rule asks this of hundreds of types, so the function table is
    // filed by namespace once, beside the namespace tree's child edges,
    // and each question walks only its roots' subtrees.
    let declared_under = DeclaredUnder::new(view);
    let type_sources = |ty: TypeId| -> BTreeSet<sweep::PollSource> {
        let Some(name) = fq_name(reader, ty) else {
            return BTreeSet::new();
        };
        let path = name.split('<').next().unwrap_or(&name);
        let mut roots: Vec<NsId> = impls_by_self.get(path).cloned().unwrap_or_default();
        if let Some(RawType::Struct(st)) = reader.canonical_type(ty)
            && let Some(own) = st.name
            && let Some(node) = reader.namespaces.find(st.namespace, own)
        {
            roots.push(node);
        }
        if roots.is_empty() {
            return BTreeSet::new();
        }
        // The methods themselves are small and generic, and a release
        // build inlines them away; what survives out of line is a
        // body nested under one — an `async` block's, a closure's, an
        // inner fn's — in a namespace of its own below the impl, or
        // the declaration the type DIE keeps of the method whatever
        // became of its body. So every function anywhere below a root
        // counts.
        declared_under
            .below(roots)
            .filter_map(|f| sweep::poll_source(reader, f))
            .collect()
    };
    let seeds = semantics::collect_semantic_seeds(
        &em,
        &explicit_polls,
        &stream_reads,
        &extra_sets,
        &poll_sources,
        &coroutine_candidates,
        compiler_verdict,
        env_facts,
        type_sources,
    );
    // A declaration nothing placed matters only where a read goes
    // through it, which is where the bundle reached it: each of those
    // is declined — it stays a type of its own, with no layout to read
    // — and named here; the rest are counted.
    stats.declined_declarations = reader
        .identity
        .unresolved_declarations
        .iter()
        .filter(|unresolved| em.bundle_id_of(unresolved.declaration).is_some())
        .map(|unresolved| {
            let declined = reader.describe_unresolved(unresolved);
            warn!("{declined}; the bundle reads through it, and it stays a type of its own");
            declined
        })
        .collect();
    stats.declarations_unresolved_emitted = stats.declined_declarations.len();
    let emitter::Finished {
        types,
        strings,
        impls,
        counts,
        semantics,
        unreviewed,
    } = em.finish(&impl_selfs, seeds, &mut entries, &walks);
    stats.unreviewed_releases = unreviewed;
    stats.types_emitted = types.types.len();
    stats.opaque_types = counts.opaque;
    stats.types_demoted_out_of_bounds = counts.demoted;
    stats.coroutines_seen = counts.states.coroutines_seen;
    stats.coroutines_matched = counts.states.coroutines_matched;
    stats.state_members_dropped = counts.states.members_dropped;
    stats.state_members_deduplicated = counts.states.members_deduplicated;
    stats.state_captures_kept = counts.states.captures_kept;

    let task_normalized = normalized_candidate_index(&by_symbol);
    let dyn_normalized = normalized_candidate_index(&dyn_table);
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
        impls,
        semantics,
    };

    // Every caller receives a validated bundle; the extract verb writes
    // it without validating it a second time.
    bundle.validate()?;
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

/// The functions that record a location, filed under the namespace
/// that declares them, beside the namespace tree's child edges: what a
/// question about everything declared below some namespaces walks,
/// rather than the whole function table.
struct DeclaredUnder<'a> {
    children: foldhash::HashMap<NsId, Vec<NsId>>,
    functions: foldhash::HashMap<NsId, Vec<Func<'a>>>,
}

impl<'a> DeclaredUnder<'a> {
    fn new(view: &DwView<'a>) -> Self {
        let mut children: foldhash::HashMap<NsId, Vec<NsId>> = foldhash::HashMap::default();
        for (id, entry) in view.collector().namespaces.iter() {
            if let Some(parent) = entry.parent {
                children.entry(parent).or_default().push(id);
            }
        }
        let mut functions: foldhash::HashMap<NsId, Vec<Func<'a>>> = foldhash::HashMap::default();
        for (_, f) in view.functions() {
            if let Some(ns) = f.namespace_id()
                && f.raw().source_loc.is_some()
            {
                functions.entry(ns).or_default().push(f);
            }
        }
        Self {
            children,
            functions,
        }
    }

    /// Every function declared in one of `roots` or anywhere below one,
    /// each once however the roots nest.
    fn below(&self, roots: Vec<NsId>) -> impl Iterator<Item = &Func<'a>> {
        let mut seen = BTreeSet::new();
        let mut stack = roots;
        std::iter::from_fn(move || {
            while let Some(ns) = stack.pop() {
                if !seen.insert(ns) {
                    continue;
                }
                stack.extend(self.children.get(&ns).into_iter().flatten());
                return Some(self.functions.get(&ns).into_iter().flatten());
            }
            None
        })
        .flatten()
    }
}

/// Where a closure or coroutine environment was written. The env DIE
/// carries no coordinates of its own; rustc places it beside the fn
/// that runs its body — `{closure#N}` for `{closure_env#N}`,
/// `{async_block#N}` for `{async_block_env#N}`, and so on — inside the
/// namespace of whatever contains it, and that sibling's decl line is
/// the block's own line. Walking up to the containing fn instead lands
/// on the wrong site: the enclosing fn's line for a block written
/// somewhere inside it.
///
/// An async fn has one more source: the fn its env's namespace is
/// named after, declared at the `fn` line, where the sibling
/// `{async_fn#N}` is declared at the body's `{` — several lines below
/// on a multi-line signature. The fn is preferred where it exists and
/// the sibling covers one inlined away. A generic fn misses the
/// name-keyed lookup (its DIE spells the parameters) and takes the
/// sibling too. Absent both, `None`: no site beats a definite wrong one.
fn env_decl_site<'a>(
    reader: &DwReader<'a>,
    view: &DwView<'a>,
    env: TypeId,
) -> Option<SourceLocView<'a>> {
    env_decl_func(reader, view, env).and_then(|f| f.source_loc())
}

/// The subprogram whose declaration coordinates are an environment's
/// ([`env_decl_site`]): the fn an async fn's env is named after where
/// it exists, else the sibling that runs the body. Only a function
/// that records both a file and a line counts.
fn env_decl_func<'a>(reader: &DwReader<'a>, view: &DwView<'a>, env: TypeId) -> Option<Func<'a>> {
    let raw = reader.canonical_type(env)?;
    let leaf = reader.strings.get(raw.name()?);
    let ns = raw.namespace();
    let located = |func: Option<Func<'a>>| {
        func.filter(|f| {
            f.source_loc()
                .is_some_and(|loc| loc.file().is_some() && loc.line().is_some())
        })
    };
    if leaf.starts_with("{async_fn_env#")
        && let Some(id) = ns
    {
        let entry = reader.namespaces.get(id);
        let outer = view.find_func_in(entry.parent, reader.strings.get(entry.name));
        if let Some(func) = located(outer) {
            return Some(func);
        }
    }
    let body = leaf.replacen("_env#", "#", 1);
    if body == leaf {
        return None;
    }
    located(view.find_func_in(ns, &body))
}

/// The site the type `name`'s poll declarations settle on, counted
/// into `stats`: per trait, agree-or-nothing, and the `Future` line
/// where a type has both, since a chain is where its line prints
/// most. A trait whose declarations disagree records nothing for that
/// trait and is counted; the other trait may still answer.
fn poll_site<'a>(
    name: &str,
    decls: &'a [(PollTrait, OwnedLoc)],
    stats: &mut ExtractStats,
) -> Option<&'a OwnedLoc> {
    for kind in [PollTrait::Future, PollTrait::Stream] {
        let of_kind = decls.iter().filter(|(k, _)| *k == kind).map(|(_, loc)| loc);
        match agreed_site(of_kind) {
            Agreement::Site(site) => {
                stats.poll_decls += 1;
                return Some(site);
            }
            Agreement::Unplaced => {}
            Agreement::Disagreed => {
                stats.poll_decls_declined += 1;
                debug!("{kind:?} poll declarations of {name} disagree; recording none");
            }
        }
    }
    None
}

/// The declaration the resume-function locals of one name settle on —
/// `decls`, the copies of `name` in `coroutine`'s resume function —
/// counted into `stats`: agree-or-nothing, like [`poll_site`]. `None`
/// with no placed copy, which is neither recorded nor declined; `None`
/// and counted where two placed copies disagree, since the payload
/// member the name lands on cannot say which scope's local it is.
fn local_decl_site<'a>(
    coroutine: &str,
    name: &str,
    decls: &'a [OwnedLoc],
    stats: &mut ExtractStats,
) -> Option<&'a OwnedLoc> {
    match agreed_site(decls) {
        Agreement::Site(site) => {
            stats.local_decls += 1;
            Some(site)
        }
        Agreement::Unplaced => None,
        Agreement::Disagreed => {
            stats.local_decls_declined += 1;
            debug!("declarations of local `{name}` in {coroutine} disagree; recording none");
            None
        }
    }
}

/// The names a coroutine env's payload members carry, across every
/// variant, minus the compiler's own (`__awaitee`, `__state`, …): the
/// names a slot path can step through, and so the only ones worth a
/// declaration. A local held across two awaits is in two payloads and
/// named once here.
fn coroutine_payload_names(reader: &DwReader<'_>, env: TypeId) -> BTreeSet<crate::StrId> {
    use crate::raw_types::VariantShape;
    let mut names = BTreeSet::new();
    let Some(RawType::Enum(e)) = reader.canonical_type(env) else {
        return names;
    };
    let payloads: Vec<TypeId> = match &e.shape {
        VariantShape::One(v) => vec![v.member.type_id],
        VariantShape::Many { variants, .. } => {
            variants.iter().map(|(_, v)| v.member.type_id).collect()
        }
        VariantShape::Zero | VariantShape::CStyle { .. } => Vec::new(),
    };
    for payload in payloads {
        let Some(RawType::Struct(s)) = reader.canonical_type(payload) else {
            continue;
        };
        names.extend(
            s.members
                .iter()
                .filter_map(|m| m.name)
                .filter(|&n| !reader.strings.get(n).starts_with("__")),
        );
    }
    names
}

/// A subprogram's coordinates as the bundle records them.
fn intern_loc(em: &mut Emitter<'_>, loc: &SourceLocView<'_>) -> Option<SourceLoc> {
    let (file, line) = (loc.file()?, loc.line()?);
    Some(SourceLoc {
        file: em
            .interner
            .intern(&display_path(loc.comp_dir(), loc.dir(), file)),
        line: line.get() as u32,
    })
}

/// Determine a task future's provenance: coroutine env types name
/// their defining async fn/block in their namespace path, and the
/// declaration site is the env's ([`env_decl_site`]).
fn classify_future(
    reader: &DwReader<'_>,
    view: &DwView<'_>,
    future: TypeId,
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

    let decl = match kind {
        FutureKind::AsyncFn | FutureKind::AsyncBlock => {
            env_decl_site(reader, view, future).and_then(|loc| intern_loc(em, &loc))
        }
        FutureKind::Combinator | FutureKind::Manual => None,
    };

    if decl.is_some() {
        stats.provenance_located += 1;
    }
    Provenance { decl, kind }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_types::{
        NsId, RawBase, RawEnum, RawFunc, RawGenericParameter, RawMember, RawPointer, RawStruct,
        RawSubParameter, RawType, SourceLoc as RawSourceLoc, VariantShape,
    };
    use crate::view::DwView;
    use crate::{DwReader, Encoding, FuncId, StrId};

    use gimli::UnitSectionOffset;

    use std::collections::BTreeMap;
    use std::num::NonZero;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset(offset))
    }

    fn func_id(offset: usize) -> FuncId {
        FuncId(UnitSectionOffset(offset))
    }

    /// A poll declaration in a registry crate, at `line`.
    fn decl(kind: PollTrait, line: u64) -> (PollTrait, OwnedLoc) {
        (
            kind,
            OwnedLoc {
                file: Some("http1.rs".to_owned()),
                dir: Some("src/client/conn".to_owned()),
                comp_dir: Some(
                    "/home/wfc/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-1.10.1"
                        .to_owned(),
                ),
                line: Some(line),
            },
        )
    }

    /// Per trait, agree-or-nothing, and the future's line where a type
    /// has both: a disagreement in one trait is counted and leaves the
    /// other to answer.
    #[test]
    fn test_poll_site_prefers_the_future_and_counts_declines() {
        use PollTrait::{Future, Stream};
        let line = |site: Option<&OwnedLoc>| site.and_then(|s| s.line);

        let mut stats = ExtractStats::default();
        assert_eq!(
            line(poll_site("app::Manual", &[decl(Future, 40)], &mut stats)),
            Some(40)
        );
        assert_eq!(
            line(poll_site("app::Manual", &[decl(Stream, 104)], &mut stats)),
            Some(104)
        );
        assert_eq!(
            line(poll_site(
                "app::Manual",
                &[decl(Stream, 104), decl(Future, 40), decl(Future, 40)],
                &mut stats
            )),
            Some(40),
            "a type that is both records the future's line"
        );
        assert_eq!((stats.poll_decls, stats.poll_decls_declined), (3, 0));

        assert_eq!(
            line(poll_site(
                "app::Manual",
                &[decl(Future, 40), decl(Future, 64), decl(Stream, 104)],
                &mut stats
            )),
            Some(104),
            "a disagreeing future leaves the stream to answer"
        );
        assert_eq!((stats.poll_decls, stats.poll_decls_declined), (4, 1));

        assert_eq!(
            line(poll_site(
                "app::Manual",
                &[
                    decl(Future, 40),
                    decl(Future, 64),
                    decl(Stream, 104),
                    decl(Stream, 105)
                ],
                &mut stats
            )),
            None
        );
        assert_eq!((stats.poll_decls, stats.poll_decls_declined), (4, 3));

        let mut unplaced = decl(Future, 40);
        unplaced.1.line = None;
        assert_eq!(
            line(poll_site("app::Manual", &[unplaced], &mut stats)),
            None
        );
        assert_eq!(line(poll_site("app::Manual", &[], &mut stats)), None);
        assert_eq!(
            (stats.poll_decls, stats.poll_decls_declined),
            (4, 3),
            "an unplaced declaration is neither recorded nor declined"
        );
    }

    /// A local's declaration is recorded where its copies agree — a
    /// `let` in a loop body the compiler duplicated — and declined,
    /// counted, where two placed copies disagree: a name shadowed
    /// across scopes, which the payload member cannot tell apart. A
    /// copy with no line neither records nor declines.
    #[test]
    fn test_local_decl_site_records_agreement_and_counts_shadowing() {
        let at = |line: u64| OwnedLoc {
            file: Some("src/bin/joinset.rs".to_owned()),
            dir: None,
            comp_dir: Some("/crate".to_owned()),
            line: Some(line),
        };
        let line = |site: Option<&OwnedLoc>| site.and_then(|s| s.line);

        let mut stats = ExtractStats::default();
        assert_eq!(
            line(local_decl_site("driver", "set", &[at(52)], &mut stats)),
            Some(52)
        );
        assert_eq!(
            line(local_decl_site(
                "driver",
                "set",
                &[at(52), at(52)],
                &mut stats
            )),
            Some(52)
        );
        assert_eq!((stats.local_decls, stats.local_decls_declined), (2, 0));

        assert_eq!(
            line(local_decl_site(
                "selector",
                "recv",
                &[at(37), at(40)],
                &mut stats
            )),
            None
        );
        assert_eq!((stats.local_decls, stats.local_decls_declined), (2, 1));

        let mut unplaced = at(52);
        unplaced.line = None;
        assert_eq!(
            line(local_decl_site("driver", "set", &[unplaced], &mut stats)),
            None
        );
        assert_eq!(
            line(local_decl_site("driver", "set", &[], &mut stats)),
            None
        );
        assert_eq!(
            (stats.local_decls, stats.local_decls_declined),
            (2, 1),
            "an unplaced declaration is neither recorded nor declined"
        );
    }

    #[derive(Default)]
    struct Fx {
        reader: DwReader<'static>,
    }

    impl Fx {
        fn ns(&mut self, path: &'static str) -> NsId {
            self.ns_under(None, path)
        }

        fn ns_under(&mut self, parent: Option<NsId>, path: &'static str) -> NsId {
            let mut ns = parent;
            for seg in path.split("::") {
                let name = self.reader.strings.intern(seg);
                ns = Some(self.reader.namespaces.insert(ns, name));
            }
            ns.unwrap()
        }

        fn base(&mut self, id: TypeId, name: &'static str, encoding: Encoding, size: u64) {
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Base(RawBase {
                    name,
                    namespace: None,
                    encoding,
                    size,
                    alignment: None,
                }),
            );
        }

        fn strukt(
            &mut self,
            id: TypeId,
            namespace: Option<NsId>,
            name: &'static str,
            members: &[(&'static str, TypeId, u64)],
            params: &[(&'static str, TypeId)],
        ) {
            let members: Box<[RawMember<StrId>]> = members
                .iter()
                .map(|&(name, type_id, offset)| RawMember {
                    name: Some(self.reader.strings.intern(name)),
                    offset,
                    type_id,
                    source_loc: None,
                })
                .collect();
            let template_params: Box<[RawGenericParameter<StrId>]> = params
                .iter()
                .map(|&(name, type_id)| RawGenericParameter {
                    name: Some(self.reader.strings.intern(name)),
                    type_id,
                })
                .collect();
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Struct(RawStruct {
                    name,
                    namespace,
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        }

        fn stage_enum(&mut self, id: TypeId, namespace: NsId, name: &'static str) {
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Enum(RawEnum {
                    name,
                    namespace: Some(namespace),
                    size: 8,
                    alignment: None,
                    shape: VariantShape::Zero,
                    template_params: Box::new([]),
                    source_loc: None,
                }),
            );
        }

        fn pointer(&mut self, id: TypeId, target: TypeId) {
            self.reader.types.insert(
                id,
                RawType::Pointer(RawPointer {
                    name: None,
                    target_type_id: target,
                }),
            );
        }

        #[allow(clippy::too_many_arguments)]
        fn func(
            &mut self,
            id: FuncId,
            namespace: Option<NsId>,
            name: &'static str,
            linkage: Option<&'static str>,
            template_params: &[(&'static str, TypeId)],
            params: &[TypeId],
            return_type_id: Option<TypeId>,
            source_line: Option<u64>,
        ) {
            let template_params = template_params
                .iter()
                .map(|&(name, type_id)| RawGenericParameter {
                    name: Some(self.reader.strings.intern(name)),
                    type_id,
                })
                .collect();
            let formal_parameters = params
                .iter()
                .map(|&type_id| RawSubParameter {
                    name: None,
                    type_id: Some(type_id),
                    abstract_origin: None,
                    const_value: None,
                    source_loc: None,
                })
                .collect();
            let source_loc = source_line.map(|line| {
                Box::new(RawSourceLoc {
                    file_id: None,
                    file: Some(self.reader.strings.intern("main.rs")),
                    dir: None,
                    comp_dir: None,
                    line: NonZero::new(line),
                    column: None,
                })
            });
            self.reader.functions.insert(
                id,
                RawFunc {
                    name: Some(self.reader.strings.intern(name)),
                    namespace,
                    source_loc,
                    return_type_id,
                    formal_parameters,
                    abstract_origin: None,
                    linkage_name: linkage.map(|l| self.reader.strings.intern(l)),
                    template_params,
                    noreturn: false,
                    awaitees: Box::new([]),
                    locals: Box::new([]),
                    select_arms: Box::new([]),
                },
            );
        }

        /// A `Pin<&mut T>` chain: the Pin struct, its pointer, the target.
        fn pin_of(&mut self, pin: TypeId, pointer: TypeId, target: TypeId) -> TypeId {
            self.pointer(pointer, target);
            self.strukt(pin, None, "Pin<&mut T>", &[("__pointer", pointer, 0)], &[]);
            pin
        }
    }

    /// A synthetic target: three task seeds (a Cell via dealloc with a
    /// Stage, a Cell via scan without one, no Cell at all), two dyn
    /// futures (glue matched by template param and by display name), and
    /// one of each self-recovery failure. With `infra` the nine infra
    /// types exist; `unstable` gives the Vtable its unstable-only member.
    fn world(infra: bool, unstable: bool) -> Fx {
        let mut fx = Fx::default();
        let tokio_runtime = fx.ns("tokio::runtime");
        let task = fx.ns_under(Some(tokio_runtime), "task");
        let raw_ns = fx.ns_under(Some(task), "raw");
        let core_ns = fx.ns_under(Some(task), "core");
        let core_ptr = fx.ns("core::ptr");
        let app = fx.ns("app");

        let word = type_id(1);
        let sched = type_id(2);
        fx.base(word, "u64", Encoding::Unsigned, 8);
        fx.strukt(sched, None, "Sched", &[], &[]);

        let fut_a = type_id(0x10);
        let fut_b = type_id(0x11);
        let fut_c = type_id(0x12);
        fx.strukt(fut_a, Some(app), "FutA", &[], &[]);
        fx.strukt(fut_b, Some(app), "FutB", &[], &[]);
        fx.strukt(fut_c, Some(app), "FutC", &[], &[]);

        // Seed A: Cell via dealloc's NonNull parameter, with a Stage.
        let stage_a = type_id(0x13);
        fx.stage_enum(stage_a, core_ns, "Stage<app::FutA>");
        let cell_a = type_id(0x14);
        fx.strukt(
            cell_a,
            Some(core_ns),
            "Cell<app::FutA, Sched>",
            &[("stage", stage_a, 0)],
            &[],
        );
        let cell_a_ptr = type_id(0x15);
        fx.pointer(cell_a_ptr, cell_a);
        let non_null_a = type_id(0x16);
        fx.strukt(
            non_null_a,
            None,
            "NonNull<Cell<app::FutA, Sched>>",
            &[("pointer", cell_a_ptr, 0)],
            &[],
        );
        // Seed B: Cell found by the scan index, holding no Stage.
        let cell_b = type_id(0x17);
        fx.strukt(
            cell_b,
            Some(core_ns),
            "Cell<app::FutB, Sched>",
            &[("len", word, 0)],
            &[("T", fut_b), ("S", sched)],
        );

        let t_s_a: &[(&str, TypeId)] = &[("T", fut_a), ("S", sched)];
        let t_s_b: &[(&str, TypeId)] = &[("T", fut_b), ("S", sched)];
        let t_s_c: &[(&str, TypeId)] = &[("T", fut_c), ("S", sched)];
        fx.func(
            func_id(0x100),
            Some(raw_ns),
            "poll<app::FutA, Sched>",
            Some("poll_a"),
            t_s_a,
            &[],
            None,
            None,
        );
        fx.func(
            func_id(0x110),
            Some(raw_ns),
            "dealloc<app::FutA, Sched>",
            Some("dealloc_a"),
            t_s_a,
            &[non_null_a],
            None,
            None,
        );
        fx.func(
            func_id(0x120),
            Some(raw_ns),
            "poll<app::FutB, Sched>",
            Some("poll_b"),
            t_s_b,
            &[],
            None,
            None,
        );
        fx.func(
            func_id(0x130),
            Some(raw_ns),
            "poll<app::FutC, Sched>",
            Some("poll_c"),
            t_s_c,
            &[],
            None,
            None,
        );
        // A vtable fn with no linkage name is counted, not seeded.
        fx.func(
            func_id(0x140),
            Some(raw_ns),
            "shutdown<app::FutA, Sched>",
            None,
            t_s_a,
            &[],
            None,
            None,
        );

        // A coroutine resume fn, its env, and glue matched by parameter.
        let poll_ret = type_id(0x20);
        fx.strukt(poll_ret, None, "Poll<()>", &[], &[]);
        let env = type_id(0x21);
        fx.strukt(env, None, "{async_fn_env#0}", &[], &[]);
        let env_pin = fx.pin_of(type_id(0x22), type_id(0x23), env);
        fx.func(
            func_id(0x150),
            None,
            "{async_fn#0}",
            Some("resume_e1"),
            &[],
            &[env_pin],
            Some(poll_ret),
            None,
        );
        fx.func(
            func_id(0x160),
            Some(core_ptr),
            "drop_glue<{async_fn_env#0}>",
            Some("glue_e1"),
            &[("T", env)],
            &[],
            None,
            None,
        );

        // A Future::poll impl and glue matched by display name.
        let f2 = type_id(0x24);
        fx.strukt(f2, Some(app), "F2", &[], &[]);
        let f2_pin = fx.pin_of(type_id(0x25), type_id(0x26), f2);
        fx.func(
            func_id(0x170),
            None,
            "poll",
            Some("<app::F2 as core::future::future::Future>::poll"),
            &[],
            &[f2_pin],
            None,
            None,
        );
        fx.func(
            func_id(0x180),
            Some(core_ptr),
            "drop_glue<app::F2>",
            Some("glue_f2"),
            &[],
            &[],
            None,
            None,
        );

        // One declaration-only self type, one unrecoverable.
        let bare_pin = type_id(0x27);
        fx.strukt(bare_pin, None, "Pin<&mut X>", &[], &[]);
        fx.func(
            func_id(0x190),
            None,
            "poll",
            Some("<X as core::future::future::Future>::poll"),
            &[],
            &[bare_pin],
            None,
            None,
        );
        fx.func(
            func_id(0x1a0),
            None,
            "poll",
            Some("<Y as core::future::future::Future>::poll"),
            &[],
            &[],
            None,
            None,
        );

        if infra {
            let context_ns = fx.ns_under(Some(tokio_runtime), "context");
            let scheduler_ns = fx.ns_under(Some(tokio_runtime), "scheduler");
            let mt_ns = fx.ns_under(Some(scheduler_ns), "multi_thread::handle");
            let location_ns = fx.ns("core::panic::location");
            let wake_ns = fx.ns("core::task::wake");
            fx.strukt(type_id(0x30), Some(core_ns), "Header", &[], &[]);
            let vtable_members: &[(&str, TypeId, u64)] = if unstable {
                &[("spawn_location_offset", word, 0)]
            } else {
                &[("poll", word, 0)]
            };
            fx.strukt(type_id(0x31), Some(raw_ns), "Vtable", vtable_members, &[]);
            fx.strukt(type_id(0x32), Some(core_ns), "Trailer", &[], &[]);
            fx.strukt(type_id(0x33), Some(context_ns), "Context", &[], &[]);
            fx.strukt(type_id(0x34), Some(scheduler_ns), "Handle", &[], &[]);
            fx.strukt(type_id(0x35), Some(mt_ns), "Handle", &[], &[]);
            fx.strukt(type_id(0x36), Some(location_ns), "Location", &[], &[]);
            fx.strukt(type_id(0x37), Some(wake_ns), "RawWakerVTable", &[], &[]);
        }
        fx
    }

    fn run(fx: &mut Fx, allow_missing_infra: bool) -> Result<(Bundle, ExtractStats)> {
        let opts = ExtractOptions {
            allow_missing_infra,
            ..Default::default()
        };
        run_with(fx, opts)
    }

    fn run_with(fx: &mut Fx, opts: ExtractOptions) -> Result<(Bundle, ExtractStats)> {
        fx.reader.index_names();
        let view = DwView::new(&fx.reader);
        let ident = Identity {
            binary: BinaryIdent {
                basename: "synthetic".to_owned(),
                build_id: None,
                blake3: [0; 32],
            },
            debug_info: None,
            vtable_data: VtableDataSource::None,
        };
        extract_from_view(&view, &[], ident, &opts, &[])
    }

    #[test]
    fn test_extraction_retains_exact_task_poll_and_glue_collisions() {
        let mut expected_semantics = None;
        for reverse in [false, true] {
            let mut fx = world(false, false);
            let raw_ns = fx.ns("tokio::runtime::task::raw");
            let core_ptr = fx.ns("core::ptr");
            let mut tasks = [type_id(0x10), type_id(0x10), type_id(0x11)];
            if reverse {
                tasks.reverse();
            }
            for (i, future) in tasks.into_iter().enumerate() {
                fx.func(
                    func_id(0x200 + i),
                    Some(raw_ns),
                    "shutdown<T, Sched>",
                    Some(if i == 1 {
                        "shared_task.llvm.123"
                    } else {
                        "shared_task"
                    }),
                    &[("T", future), ("S", type_id(2))],
                    &[],
                    None,
                    None,
                );
            }
            let mut futures = [type_id(0x21), type_id(0x24)];
            if reverse {
                futures.reverse();
            }
            for (i, future) in futures.into_iter().enumerate() {
                let pin = fx.pin_of(type_id(0x40 + i * 2), type_id(0x41 + i * 2), future);
                fx.func(
                    func_id(0x210 + i),
                    None,
                    "poll",
                    Some("<app::F2 as core::future::future::Future>::poll"),
                    &[],
                    &[pin],
                    None,
                    None,
                );
                fx.func(
                    func_id(0x220 + i),
                    Some(core_ptr),
                    "drop_glue<T>",
                    Some(if i == 0 {
                        "shared_glue"
                    } else {
                        "shared_glue.llvm.321"
                    }),
                    &[("T", future)],
                    &[],
                    None,
                    None,
                );
            }
            let (bundle, stats) = run(&mut fx, true).unwrap();
            bundle.validate().unwrap();
            if let Some(expected) = &expected_semantics {
                assert_eq!(&bundle.semantics, expected);
            } else {
                expected_semantics = Some(bundle.semantics.clone());
            }
            assert_eq!(
                stats.task_entries, 3,
                "repeated evidence must not create entries"
            );
            let task_ids = bundle.tasks.candidates("shared_task.llvm.456");
            assert_eq!(task_ids.len(), 2);
            let task_names: BTreeSet<_> = task_ids
                .iter()
                .map(|id| {
                    bundle
                        .strings
                        .get(bundle.tasks.entries[id.0 as usize].display_name)
                        .unwrap()
                })
                .collect();
            assert_eq!(task_names, BTreeSet::from(["app::FutA", "app::FutB"]));
            assert!(bundle.tasks.lookup("shared_task").is_none());
            let poll = "<app::F2 as core::future::future::Future>::poll";
            let ids = bundle.dyn_futures.candidates(poll);
            assert_eq!(ids.len(), 2);
            assert_eq!(bundle.dyn_futures.candidates("shared_glue"), ids);
            let view = hansei_bundle::BundleView::new(&bundle);
            let names: BTreeSet<_> = ids.iter().map(|id| view.ty(*id).unwrap().name()).collect();
            assert_eq!(names, BTreeSet::from(["{async_fn_env#0}", "app::F2"]));
            assert!(bundle.dyn_futures.lookup(poll).is_none());
            let mut bytes = Vec::new();
            bundle.write_to(&mut bytes).unwrap();
            assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), bundle);
        }
    }

    #[test]
    fn test_extraction_counts_what_it_skipped_and_bound() {
        let mut fx = world(false, false);
        let (_bundle, stats) = run(&mut fx, true).expect("a permissive extraction succeeds");

        assert_eq!(stats.vtable_missing_linkage, 1);
        assert_eq!(stats.dyn_decl_only_self, 1);
        assert_eq!(stats.dyn_unresolved_self, 1);
        assert_eq!(stats.cells_from_dealloc, 1);
        assert_eq!(stats.cells_by_scan, 1);
        assert_eq!(stats.cells_missing, 1);
        assert_eq!(stats.stages_missing, 1);
        assert_eq!(stats.dyn_futures, 2);
        assert_eq!(stats.dyn_poll_symbols, 2);
        assert_eq!(stats.dyn_glue_symbols, 2);
        assert_eq!(stats.dyn_glue_by_name, 1);
        assert_eq!(stats.task_entries, 3);
        assert_eq!(stats.poll_instantiations, 3);
        assert_eq!(stats.task_symbols, 4);
        // No versioned detector ran, so no family was guessed.
        assert_eq!(stats.tokio_family_guessed, None);
        let display = format!("{stats}");
        assert!(display.contains("task table:"), "{display}");
        assert!(display.contains("  entries:                3"), "{display}");
    }

    #[test]
    fn test_semantic_seeds_keep_identity_separate_from_compiler_candidates() {
        use crate::bundle::{Continuation, FutureEvidence, SemanticIssueKind, StoragePolicy};

        let mut fx = world(false, false);
        // A normal wrapper, pointer, and compiler env without a resume symbol
        // are reachable storage, but only the compiler env is a candidate.
        fx.strukt(
            type_id(0x50),
            None,
            "Holder",
            &[("child", type_id(0x24), 0)],
            &[],
        );
        fx.pointer(type_id(0x51), type_id(0x24));
        fx.strukt(type_id(0x52), None, "{async_block_env#1}", &[], &[]);
        fx.strukt(
            type_id(0x10),
            None,
            "FutA",
            &[
                ("wrapper", type_id(0x50), 0),
                ("pointer", type_id(0x51), 8),
                ("unpolled", type_id(0x52), 16),
            ],
            &[],
        );
        let (bundle, _) = run(&mut fx, true).unwrap();
        let view = hansei_bundle::BundleView::new(&bundle);
        let facts = |name| {
            bundle
                .semantics
                .types
                .iter()
                .find(|record| view.ty(record.ty).unwrap().name() == name)
        };
        for (id, task) in bundle.tasks.entries.iter().enumerate() {
            let record = bundle
                .semantics
                .types
                .iter()
                .find(|r| r.ty == task.future)
                .unwrap();
            assert!(
                record
                    .future
                    .as_ref()
                    .unwrap()
                    .evidence
                    .contains(&FutureEvidence::TaskEntry(TaskEntryId(id as u32)))
            );
        }
        assert!(
            facts("FutA")
                .unwrap()
                .future
                .as_ref()
                .unwrap()
                .evidence
                .iter()
                .all(|e| matches!(e, FutureEvidence::TaskEntry(_)))
        );
        let manual = facts("app::F2").unwrap();
        let FutureEvidence::PollSymbol(symbol) = manual.future.as_ref().unwrap().evidence[0] else {
            panic!("explicit poll evidence")
        };
        assert_eq!(
            bundle.strings.get(symbol),
            Some("<app::F2 as core::future::future::Future>::poll")
        );
        for name in ["{async_fn_env#0}", "{async_block_env#1}"] {
            let candidate = facts(name).unwrap();
            assert!(
                candidate.future.is_none(),
                "shape cannot supply future identity"
            );
            assert!(
                matches!(candidate.storage, StoragePolicy::Unavailable(ref issue) if issue.kind == SemanticIssueKind::UnsupportedOrigin)
            );
        }
        assert!(facts("Holder").is_none());
        let demoted = facts("FutA").unwrap();
        assert!(matches!(
            bundle.types.get(demoted.ty),
            Some(crate::bundle::TypeDef::Opaque { .. })
        ));
        assert!(
            matches!(demoted.storage, StoragePolicy::Unavailable(ref issue) if issue.kind == SemanticIssueKind::MissingLayout)
        );
        assert!(bundle.semantics.origins.is_empty());
        assert!(bundle.semantics.rules.is_empty());
        assert!(bundle.semantics.types.iter().all(|r| {
            r.access.is_none()
                && r.resource.is_none()
                && r.container.is_none()
                && r.future
                    .as_ref()
                    .is_none_or(|f| matches!(f.continuation, Continuation::Unknown(_)))
        }));
        let mut other = bundle.clone();
        other.types.debug_formats.clear();
        other.validate().unwrap();
        assert_eq!(other.semantics, bundle.semantics);
    }

    #[test]
    fn test_missing_statics_alone_refuse_a_strict_extraction() {
        let mut fx = world(true, false);
        let err = match run(&mut fx, false) {
            Err(Error::MissingInfra(missing)) => missing,
            other => panic!("expected MissingInfra, got {other:?}"),
        };
        // Every infra type resolves (one scheduler flavor is enough), so
        // what refuses the extraction is the statics alone.
        assert!(err.iter().all(|path| !path.contains("Handle")), "{err:?}");

        let (_bundle, stats) = run(&mut fx, true).expect("the permissive form proceeds");
        assert_eq!(stats.infra_missing, Vec::<String>::new());
        assert!(!stats.statics_missing.is_empty());
    }

    #[test]
    fn test_tokio_unstable_is_read_from_the_vtable_layout() {
        let mut fx = world(true, true);
        let (bundle, _) = run(&mut fx, true).expect("a permissive extraction succeeds");
        assert_eq!(bundle.meta.tokio_unstable, Some(true));

        let mut fx = world(true, false);
        let (bundle, _) = run(&mut fx, true).expect("a permissive extraction succeeds");
        assert_eq!(bundle.meta.tokio_unstable, Some(false));

        let mut fx = world(false, false);
        let (bundle, _) = run(&mut fx, true).expect("a permissive extraction succeeds");
        assert_eq!(bundle.meta.tokio_unstable, None);
    }

    /// A declaration nothing placed is declined wherever the bundle
    /// reads through it — a type of its own, counted as emitted — and
    /// one nothing reaches is counted and let be; neither stops the
    /// extraction.
    #[test]
    fn test_unresolved_declarations_are_declined_where_emitted() {
        use crate::reader::{DeclarationEvidence, UnresolvedDeclaration};
        let unresolved = |declaration| UnresolvedDeclaration {
            declaration,
            unit: None,
            classes: Vec::new(),
            evidence: DeclarationEvidence::None,
        };

        // A declaration the bundle never reaches.
        let mut fx = world(true, false);
        fx.reader.identity.unresolved_declarations = vec![unresolved(type_id(0xdead))];
        let (_, stats) = run(&mut fx, true).expect("an unreached declaration changes nothing");
        assert_eq!(stats.declarations_unresolved, 1);
        assert_eq!(stats.declarations_unresolved_emitted, 0);

        // A task's own future is emitted, and a read goes through it.
        let mut fx = world(true, false);
        fx.reader.identity.unresolved_declarations = vec![unresolved(type_id(0x10))];
        let (bundle, stats) = run(&mut fx, true).expect("an emitted declaration is declined");
        assert_eq!(stats.declarations_unresolved, 1);
        assert_eq!(stats.declarations_unresolved_emitted, 1);
        assert_eq!(stats.declined_declarations.len(), 1);
        assert!(
            stats.declined_declarations[0].contains("`app::FutA` declared in no unit (0x10)"),
            "{:?}",
            stats.declined_declarations
        );
        assert!(
            stats.to_string().contains("declined: `app::FutA`"),
            "{stats}"
        );
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_futures_classify_by_their_root_namespace() {
        let mut fx = Fx::default();
        let combinators = fx.ns("futures_util::future");
        let app = fx.ns("app");
        let join_all = type_id(1);
        let my_fut = type_id(2);
        fx.strukt(join_all, Some(combinators), "JoinAll<F>", &[], &[]);
        fx.strukt(my_fut, Some(app), "MyFut", &[], &[]);

        fx.reader.index_names();
        let view = DwView::new(&fx.reader);
        let mut em = Emitter::new(&fx.reader, BTreeMap::new(), None, None);
        let mut stats = ExtractStats::default();
        let p = classify_future(&fx.reader, &view, join_all, &mut em, &mut stats);
        assert!(matches!(p.kind, FutureKind::Combinator));
        let p = classify_future(&fx.reader, &view, my_fut, &mut em, &mut stats);
        assert!(matches!(p.kind, FutureKind::Manual));
        assert_eq!(stats.provenance_located, 0);
    }

    /// An async fn's env beside both of its sources: the fn itself at
    /// the `fn` line and the resume fn `{async_fn#0}` at the body's
    /// `{`, four lines down on a multi-line signature.
    fn async_fn_fixture(with_outer: bool) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let app = fx.ns("app");
        let outer = fx.ns_under(Some(app), "outer");
        let env = type_id(1);
        fx.strukt(env, Some(outer), "{async_fn_env#0}", &[], &[]);
        if with_outer {
            fx.func(
                func_id(0x100),
                Some(app),
                "outer",
                None,
                &[],
                &[],
                None,
                Some(42),
            );
        }
        fx.func(
            func_id(0x200),
            Some(outer),
            "{async_fn#0}",
            None,
            &[],
            &[],
            None,
            Some(46),
        );
        (fx, env)
    }

    fn provenance_of(fx: &mut Fx, env: TypeId) -> (Provenance, ExtractStats) {
        fx.reader.index_names();
        let view = DwView::new(&fx.reader);
        let mut em = Emitter::new(&fx.reader, BTreeMap::new(), None, None);
        let mut stats = ExtractStats::default();
        let p = classify_future(&fx.reader, &view, env, &mut em, &mut stats);
        (p, stats)
    }

    #[test]
    fn test_an_async_fn_declares_at_its_fn_line() {
        let (mut fx, env) = async_fn_fixture(true);
        let (p, stats) = provenance_of(&mut fx, env);
        assert!(matches!(p.kind, FutureKind::AsyncFn));
        let decl = p.decl.expect("the fn names the declaration");
        assert_eq!(decl.line, 42, "the fn line, not the resume fn's `{{` line");
        assert_eq!(stats.provenance_located, 1);
    }

    #[test]
    fn test_an_inlined_async_fn_declares_at_its_resume_fn() {
        // The outer fn inlined away leaves only the resume fn, whose
        // line is the body's `{`: a site, where the enclosing fn's
        // would be a wrong one and none would lose the fn entirely.
        let (mut fx, env) = async_fn_fixture(false);
        let (p, stats) = provenance_of(&mut fx, env);
        let decl = p.decl.expect("the resume fn names the declaration");
        assert_eq!(decl.line, 46);
        assert_eq!(stats.provenance_located, 1);
    }

    #[test]
    fn test_a_fn_without_a_line_yields_to_its_resume_fn() {
        // The fn is there but its coordinates are incomplete — a file
        // and no line — so it names no site, and the resume fn's is
        // taken rather than nothing.
        let (mut fx, env) = async_fn_fixture(false);
        let app = fx.ns("app");
        fx.func(
            func_id(0x100),
            Some(app),
            "outer",
            None,
            &[],
            &[],
            None,
            Some(0),
        );
        let (p, _) = provenance_of(&mut fx, env);
        assert_eq!(p.decl.expect("the resume fn's site").line, 46);
    }

    #[test]
    fn test_an_async_block_declares_at_its_own_line_not_its_fns() {
        // rustc places `{async_block_env#0}` beside the `{async_block#0}`
        // that runs it, inside the containing fn's namespace. The
        // block's line is the sibling's; the fn's line — the first hit
        // of a walk up the namespace chain — is where the block is
        // *not*.
        let mut fx = Fx::default();
        let app = fx.ns("app");
        let outer = fx.ns_under(Some(app), "outer");
        let env = type_id(1);
        fx.strukt(env, Some(outer), "{async_block_env#0}", &[], &[]);
        fx.func(
            func_id(0x100),
            Some(app),
            "outer",
            None,
            &[],
            &[],
            None,
            Some(42),
        );
        fx.func(
            func_id(0x200),
            Some(outer),
            "{async_block#0}",
            None,
            &[],
            &[],
            None,
            Some(48),
        );
        let (p, stats) = provenance_of(&mut fx, env);
        assert!(matches!(p.kind, FutureKind::AsyncBlock));
        assert_eq!(p.decl.expect("the block's body fn names it").line, 48);
        assert_eq!(stats.provenance_located, 1);
    }

    #[test]
    fn test_a_block_without_its_body_fn_declares_nowhere() {
        // Only the containing fn is left: its line is not the block's,
        // so the block gets no site rather than that one.
        let mut fx = Fx::default();
        let app = fx.ns("app");
        let outer = fx.ns_under(Some(app), "outer");
        let env = type_id(1);
        fx.strukt(env, Some(outer), "{async_block_env#0}", &[], &[]);
        fx.func(
            func_id(0x100),
            Some(app),
            "outer",
            None,
            &[],
            &[],
            None,
            Some(42),
        );
        let (p, stats) = provenance_of(&mut fx, env);
        assert!(p.decl.is_none());
        assert_eq!(stats.provenance_located, 0);
    }

    #[test]
    fn test_a_generic_closure_env_finds_its_body_fn_by_its_whole_name() {
        // A closure inside a generic fn spells the parameters on both
        // the env and its body fn — arguments that carry `::` of their
        // own, so the lookup goes by name inside the namespace, never
        // by path. The env sits in `{closure#0}`'s namespace when the
        // closure is itself nested in another, and its sibling there is
        // that namespace's own `{closure#0}`.
        let mut fx = Fx::default();
        let app = fx.ns("app");
        let outer = fx.ns_under(Some(app), "outer");
        let closure = fx.ns_under(Some(outer), "{closure#0}");
        let env = type_id(1);
        fx.strukt(
            env,
            Some(closure),
            "{closure_env#0}<app::types::Item>",
            &[],
            &[],
        );
        fx.func(
            func_id(0x100),
            Some(app),
            "outer<T>",
            None,
            &[],
            &[],
            None,
            Some(10),
        );
        fx.func(
            func_id(0x200),
            Some(outer),
            "{closure#0}<app::types::Item>",
            None,
            &[],
            &[],
            None,
            Some(20),
        );
        fx.func(
            func_id(0x300),
            Some(closure),
            "{closure#0}<app::types::Item>",
            None,
            &[],
            &[],
            None,
            Some(24),
        );
        fx.reader.index_names();
        let view = DwView::new(&fx.reader);
        let loc = env_decl_site(&fx.reader, &view, env).expect("the inner closure's body fn");
        assert_eq!(loc.line().map(|l| l.get()), Some(24));
    }
}

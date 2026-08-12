use crate::cgu::CodegenUnit;
use crate::raw_types::{
    NamespaceTable, NsId, RawAwaitee, RawBase, RawEnum, RawEnumerator, RawFunc,
    RawGenericParameter, RawMember, RawPointer, RawStaticVariable, RawStruct, RawSubParameter,
    RawType, RawUnion, RawVariant, SourceLoc, VariantShape,
};
use crate::string_table::{FrozenStrings, ShardedInterner, StrId};
use crate::{Error, FuncId, Result, Slice};
use crate::{TypeId, VarId};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use gimli::{Dwarf, UnitRef};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use tracing::debug;

use std::collections::BTreeSet;
use std::num::NonZero;

/// Below this many named-type groups, the parallel layout partitioning in
/// [`DwReader::named_aliases`] is not worth spawning threads for; run it inline.
const PARALLEL_ALIAS_GROUP_THRESHOLD: usize = 256;

/// Cap on how few named-type groups a rayon split may carry, amortizing
/// scheduling over the many trivial (size-one) groups.
const ALIAS_BATCH: usize = 32;

/// The thread count used when the caller leaves [`ReadArgs::cgu_parallelism`]
/// unset, for both the CGU parse pool and the parallel finalization.
fn default_parallelism() -> usize {
    std::thread::available_parallelism().map_or(1, NonZero::get)
}

/// A global, deduplicated view of all types from the DWARF debug information.
///
/// CGUs are ingested as they finish parsing via [`DwReader::ingest`], then
/// reconciled after every type is available. Canonical IDs prefer complete
/// definitions and otherwise use the lowest compatible DWARF offset.
#[derive(Default, Debug)]
pub struct DwReader<'dw> {
    /// All types from all CGUs, keyed by their original TypeId.
    pub types: HashMap<TypeId, RawType<StrId>>,
    /// `DW_TAG_subroutine_type` DIEs. We retain only their identity so
    /// pointers can be classified as function pointers.
    subroutine_types: HashSet<TypeId>,
    /// Substitution map: non-canonical TypeId → canonical TypeId.
    subs: HashMap<TypeId, TypeId>,
    /// Type DIEs marked with `DW_AT_declaration`.
    type_declarations: HashSet<TypeId>,
    /// Type DIE → declaration DIE from `DW_AT_specification`.
    type_specifications: HashMap<TypeId, TypeId>,
    /// All static variables, keyed by their VarId.
    pub variables: HashMap<VarId, RawStaticVariable<StrId>>,
    /// All functions, keyed by their FuncId.
    pub functions: HashMap<FuncId, RawFunc<StrId>>,
    /// Global namespace table.
    pub namespaces: NamespaceTable<StrId>,
    /// Interned string table for all strings found in types and variables.
    pub strings: FrozenStrings<'dw>,
    /// The `DW_AT_producer` of the first compile unit that carries one
    /// (compiler identification, e.g. the rustc version).
    pub producer: Option<StrId>,
}

/// Configuration for [`DwarfReader::read_types`].
#[derive(Default)]
pub struct ReadArgs {
    /// Number of worker threads for parsing CGUs in parallel; also bounds the
    /// parallel type finalization. Defaults to [`thread::available_parallelism`].
    pub cgu_parallelism: Option<NonZero<usize>>,
    /// Maximum number of CGUs that may be in-flight (parsed but not yet
    /// ingested by the collector). Defaults to `4 * cgu_parallelism`.
    pub cgus_in_flight: Option<NonZero<usize>>,
}

impl<'dw> DwReader<'dw> {
    /// Build an indexed view for efficient lookups.
    pub fn view(&self) -> crate::view::DwView<'_> {
        crate::view::DwView::new(self)
    }

    /// Parse all DWARF compilation units and produce a deduplicated global
    /// type collection.
    ///
    /// This is the main entry point for reading types out of DWARF debug
    /// information. It iterates over every compilation unit (CGU) in the
    /// `.debug_info` section, parses each one into a [`CodegenUnit`] on a
    /// worker thread, and folds the results into a single [`DwReader`] **as
    /// they finish**. Arrival order does not matter: references are global
    /// section offsets and dedup is deferred, so after collection a final
    /// reconciliation pass resolves declarations to definitions, partitions
    /// same-named types by compatible layout, and deduplicates anonymous
    /// pointers and arrays. The lowest DWARF offset remains the deterministic
    /// tie-breaker between equally complete definitions.
    ///
    /// # Arguments
    ///
    /// * `dwarf` — The parsed DWARF data, typically produced by `gimli`.
    ///   The lifetime `'dw` ties borrowed string data (type names, etc.)
    ///   to the underlying section buffers, so the returned `DwReader`
    ///   borrows from the same backing storage.
    ///
    /// * `args` — Controls parallelism and filtering:
    ///
    ///   - [`ReadArgs::cgu_parallelism`]: The number of worker threads that
    ///     parse CGUs concurrently, and the fan-out of the parallel type
    ///     finalization that follows. Defaults to
    ///     [`std::thread::available_parallelism`]. Higher values speed up
    ///     parsing on machines with many cores, but each worker holds a
    ///     fully-parsed [`CodegenUnit`] in memory until it is ingested by
    ///     the collector.
    ///
    ///   - [`ReadArgs::cgus_in_flight`]: The maximum number of parsed CGUs
    ///     that may be buffered between the worker threads and the collector
    ///     at any given time — the memory ceiling, since each is a large,
    ///     fully-parsed unit. Defaults to `4 × cgu_parallelism`. Because CGUs
    ///     are ingested as they complete rather than buffered for reordering,
    ///     this needs no slack for out-of-order results and can be lowered
    ///     to tighten peak memory; it only throttles throughput once it is
    ///     too small to keep the collector fed.
    pub fn read_types(dwarf: &Dwarf<Slice<'dw>>, args: ReadArgs) -> Result<DwReader<'dw>> {
        // Unit headers carry only offsets, so enumerating them up front is
        // cheap and gives the parallel walk an indexable work list.
        let mut headers = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            headers.push(header);
        }

        // Interning is the single most expensive part of collection (tens of
        // millions of strings), so it runs on the parallel workers via a
        // sharded, lock-striped interner. Namespace assignment and type-map
        // insertion stay on the serial collector, keyed by unique DIE ids.
        let interner = ShardedInterner::new();

        let parallelism = args
            .cgu_parallelism
            .map_or_else(default_parallelism, NonZero::get);
        // Default buffer: the old bounded fold budgeted `2 × parallelism` for
        // parsing *and* queued units together, gating workers before they
        // pulled a unit; the channel bounds only the queue, and a worker
        // blocks holding a finished unit. `4 × parallelism` restores the
        // slack: measured on a 413 MB-.debug_info target, `2p` costs ~15%
        // of the parse phase in send-blocking stalls while `4p` is at
        // parity with the old fold, for ~1% of peak RSS on a 4.4 GB one.
        let in_flight = args.cgus_in_flight.map_or(4 * parallelism, NonZero::get);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallelism)
            .build()
            .expect("failed to build the CGU parse pool");

        // Pool workers parse and intern CGUs; one collector thread ingests
        // them in whatever order they finish. Arrival order cannot affect the
        // result: every cross-DIE reference is a global section offset
        // resolved after the whole program is collected, and dedup is
        // deferred to `finalize_types`. The bounded channel is the memory
        // ceiling — a worker with a finished CGU blocks until the collector
        // frees a slot, so at most `in_flight` parsed-but-uningested CGUs
        // are ever buffered (the workers' own in-progress units come on top).
        let (tx, rx) = std::sync::mpsc::sync_channel::<InternedCgu>(in_flight);
        let (mut collector, parsed) = std::thread::scope(|scope| {
            let collector = scope.spawn(move || {
                let mut collector = DwReader::new();
                for cgu in rx {
                    collector.ingest(cgu);
                }
                collector
            });
            // `with_max_len(1)` forces one unit per job. CGU sizes are
            // skewed by orders of magnitude, and rayon's default splitting
            // hands each thread a contiguous chunk — a giant unit then
            // serializes behind its chunk-mates instead of starting the
            // moment a thread frees up (measured ~2× on the parse phase).
            let parsed = pool.install(|| {
                headers
                    .into_par_iter()
                    .with_max_len(1)
                    .try_for_each_with(tx, |tx, header| {
                        let unit = dwarf.unit(header)?;
                        let unit_ref = UnitRef::new(dwarf, &unit);
                        let mut cursor = unit.entries();
                        cursor.next_entry()?;
                        let cgu = CodegenUnit::from_cursor(&unit_ref, &mut cursor)?;
                        debug!("processed unit {}", cgu.name);
                        // The collector hangs up only after every sender is
                        // dropped, so a failed send can only follow its panic —
                        // which the join below propagates.
                        tx.send(intern_cgu(&interner, cgu)).ok();
                        Ok::<_, Error>(())
                    })
            });
            // `install` returning dropped the last sender, so the collector's
            // receive loop has ended; on a parse error it ingested whatever
            // was already in the channel, and the partial result is dropped
            // with the error return below.
            let collector = collector.join().expect("CGU collector thread panicked");
            (collector, parsed)
        });
        parsed?;

        // Workers have released their borrows now that the parse is done;
        // take ownership of the interned strings.
        collector.strings = interner.freeze();
        pool.install(|| collector.finalize_types());
        Ok(collector)
    }

    fn new() -> Self {
        Self {
            types: HashMap::new(),
            subroutine_types: HashSet::new(),
            subs: HashMap::new(),
            type_declarations: HashSet::new(),
            type_specifications: HashMap::new(),
            variables: HashMap::new(),
            functions: HashMap::new(),
            namespaces: NamespaceTable::new(),
            strings: FrozenStrings::default(),
            producer: None,
        }
    }

    /// Ingest an already-interned CGU into the global type space. The worker
    /// (see [`intern_cgu`]) interned every string, but its namespaces and type
    /// references still carry CGU-local ids; the collector remaps namespaces
    /// into the global table here. CGUs may be ingested in any order: types,
    /// statics, and functions are keyed by globally-unique DIE offsets, and
    /// deduplication is deferred to [`Self::finalize_types`], so neither
    /// forward references nor arrival order can affect the result.
    fn ingest(&mut self, cgu: InternedCgu) {
        let ns_remap = self.remap_namespaces(&cgu.namespaces);

        if self.producer.is_none() {
            self.producer = cgu.producer;
        }

        for (type_id, mut ty) in cgu.types {
            remap_ns_in_place(&mut ty, &ns_remap);
            self.types.insert(type_id, ty);
        }

        self.subroutine_types.extend(cgu.subroutine_types);
        self.type_declarations.extend(cgu.type_declarations);
        self.type_specifications.extend(cgu.type_specifications);

        // Static variables are unique by address, functions by DIE — no dedup
        // needed. Type references are canonicalized on access after the final
        // alias map has been built.
        for (var_id, mut var) in cgu.variables {
            if let Some(id) = var.namespace {
                var.namespace = Some(ns_remap[&id]);
            }
            self.variables.insert(var_id, var);
        }
        for (func_id, mut func) in cgu.funcs {
            if let Some(id) = func.namespace {
                func.namespace = Some(ns_remap[&id]);
            }
            self.functions.insert(func_id, func);
        }
    }

    /// Merge a CGU's local namespace table into the global one, returning a
    /// map from each local [`NsId`] to its global id. Names are already
    /// interned; the global table dedups by `(parent, name)`.
    fn remap_namespaces(&mut self, local: &NamespaceTable<StrId>) -> HashMap<NsId, NsId> {
        let mut ns_remap: HashMap<NsId, NsId> = HashMap::new();
        for (local_id, entry) in local.iter() {
            let global_parent = entry.parent.map(|p| ns_remap[&p]);
            let global_id = self.namespaces.insert(global_parent, entry.name);
            ns_remap.insert(local_id, global_id);
        }
        ns_remap
    }

    /// Build the global alias map after every CGU has been collected.
    ///
    /// Named types are grouped by kind, namespace, and name, then partitioned
    /// by compatible layout so name collisions are not silently collapsed.
    /// Anonymous pointers and arrays are deduplicated structurally. That pass
    /// repeats because an outer pointer may only become equal after its
    /// pointee was deduplicated in an earlier pass.
    fn finalize_types(&mut self) {
        self.subs.clear();

        let specifications: Vec<_> = self
            .type_specifications
            .iter()
            .map(|(&definition, &declaration)| (definition, declaration))
            .collect();
        for (definition, declaration) in specifications {
            self.inherit_type_identity(definition, declaration);
            let canonical = match (
                self.type_declarations.contains(&definition),
                self.type_declarations.contains(&declaration),
            ) {
                (false, true) => definition,
                (true, false) => declaration,
                _ => definition.min(declaration),
            };
            let duplicate = if canonical == definition {
                declaration
            } else {
                definition
            };
            self.subs.insert(duplicate, canonical);
        }

        // Grouping key order does not matter: each type id lands in exactly one
        // group, and every group's canonical is chosen independently (by layout
        // detail then lowest id), so a hash map is both correct and faster than
        // the ordered map here.
        let mut named: HashMap<(u8, Option<NsId>, StrId), Vec<TypeId>> = HashMap::new();
        for (&id, ty) in &self.types {
            if let Some(name) = ty.name() {
                named
                    .entry((raw_type_kind(ty), ty.namespace(), name))
                    .or_default()
                    .push(id);
            }
        }
        let groups: Vec<&[TypeId]> = named.values().map(Vec::as_slice).collect();
        for (duplicate, canonical) in self.named_aliases(&groups) {
            self.subs.insert(duplicate, canonical);
        }

        loop {
            let old_len = self.subs.len();
            let mut pointers: HashMap<TypeId, Vec<TypeId>> = HashMap::new();
            let mut arrays: HashMap<(TypeId, u64), Vec<TypeId>> = HashMap::new();

            for (&id, ty) in &self.types {
                match ty {
                    RawType::Pointer(p) if p.name.is_none() => pointers
                        .entry(self.canonicalize(p.target_type_id))
                        .or_default()
                        .push(id),
                    RawType::Array(a) => arrays
                        .entry((self.canonicalize(a.elem_type_id), a.count))
                        .or_default()
                        .push(id),
                    _ => {}
                }
            }
            for ids in pointers.values().chain(arrays.values()) {
                self.alias_to_lowest(ids);
            }

            if self.subs.len() == old_len {
                break;
            }
        }
    }

    /// Partition every named-type group into layout-compatible classes and
    /// collect the resulting `(duplicate, canonical)` aliases.
    ///
    /// The groups are independent and [`Self::compatible_named_aliases`] only
    /// reads `self` (the `subs` map is not mutated until every group has been
    /// processed), so the work is spread across the rayon pool. Each type id
    /// belongs to exactly one group, so a `duplicate` is produced by exactly
    /// one group and the merged result does not depend on the order in which
    /// batches finish. This is the dominant cost of finalization on large
    /// binaries, and the layout comparisons are CPU-bound and allocation-light,
    /// so it scales well. Group sizes vary by orders of magnitude (a handful
    /// of ubiquitous types dominate), so splitting is capped at [`ALIAS_BATCH`]
    /// groups and work stealing keeps every core busy to the end.
    fn named_aliases(&self, groups: &[&[TypeId]]) -> Vec<(TypeId, TypeId)> {
        if groups.len() < PARALLEL_ALIAS_GROUP_THRESHOLD {
            return groups
                .iter()
                .flat_map(|ids| self.compatible_named_aliases(ids))
                .collect();
        }

        groups
            .par_iter()
            .with_max_len(ALIAS_BATCH)
            .flat_map_iter(|ids| self.compatible_named_aliases(ids))
            .collect()
    }

    fn alias_to_lowest(&mut self, ids: &[TypeId]) {
        let Some(&canonical) = ids.iter().min() else {
            return;
        };
        for &id in ids {
            if id != canonical {
                self.subs.insert(id, canonical);
            }
        }
    }

    /// Partition one named-type group by its own layout and the identities of
    /// referenced types. Complete, incompatible definitions remain separate.
    /// An unlinked declaration is attached only when the name identifies one
    /// compatible definition class; otherwise retaining it is safer than
    /// guessing.
    fn compatible_named_aliases(&self, ids: &[TypeId]) -> Vec<(TypeId, TypeId)> {
        let resolved: BTreeSet<_> = ids.iter().map(|&id| self.canonicalize(id)).collect();
        let mut definitions: Vec<_> = resolved
            .iter()
            .copied()
            .filter(|id| !self.type_declarations.contains(id))
            .collect();
        definitions.sort_by(|left, right| {
            self.layout_detail(*right)
                .cmp(&self.layout_detail(*left))
                .then_with(|| left.cmp(right))
        });
        let declarations: Vec<_> = resolved
            .iter()
            .copied()
            .filter(|id| self.type_declarations.contains(id))
            .collect();

        let mut classes: Vec<Vec<TypeId>> = Vec::new();
        for id in definitions {
            if let Some(class) = classes
                .iter_mut()
                .find(|class| self.types_have_compatible_layout(class[0], id))
            {
                class.push(id);
            } else {
                classes.push(vec![id]);
            }
        }

        let mut aliases = Vec::new();
        for class in &classes {
            let canonical = class[0];
            aliases.extend(
                class
                    .iter()
                    .copied()
                    .filter(|&id| id != canonical)
                    .map(|id| (id, canonical)),
            );
        }

        match classes.as_slice() {
            [class] => {
                let canonical = class[0];
                aliases.extend(
                    declarations
                        .into_iter()
                        .filter(|&id| id != canonical)
                        .map(|id| (id, canonical)),
                );
            }
            [] => {
                if let Some(&canonical) = declarations.first() {
                    aliases.extend(
                        declarations
                            .iter()
                            .copied()
                            .filter(|&id| id != canonical)
                            .map(|id| (id, canonical)),
                    );
                }
            }
            _ => {}
        }

        aliases
    }

    fn layout_detail(&self, id: TypeId) -> usize {
        match self.types.get(&self.canonicalize(id)) {
            Some(RawType::Base(_)) => 1,
            Some(RawType::Pointer(_)) | Some(RawType::Array(_)) => 2,
            Some(RawType::Struct(ty)) => ty.members.len() * 2 + ty.template_params.len() + 1,
            Some(RawType::Union(ty)) => ty.members.len() * 2 + ty.template_params.len() + 1,
            Some(RawType::Enum(ty)) => {
                let variants = match &ty.shape {
                    VariantShape::Zero => 0,
                    VariantShape::One(_) => 1,
                    VariantShape::Many { discr, variants } => {
                        variants.len() * 2 + usize::from(discr.is_some())
                    }
                    VariantShape::CStyle { enumerators, .. } => enumerators.len(),
                };
                variants + ty.template_params.len() + 1
            }
            None => 0,
        }
    }

    fn types_have_compatible_layout(&self, left: TypeId, right: TypeId) -> bool {
        let left = self.canonicalize(left);
        let right = self.canonicalize(right);
        if left == right {
            return true;
        }

        match (self.types.get(&left), self.types.get(&right)) {
            (Some(RawType::Base(a)), Some(RawType::Base(b))) => {
                a.encoding == b.encoding
                    && a.size == b.size
                    && compatible_alignment(a.alignment, b.alignment)
            }
            (Some(RawType::Pointer(a)), Some(RawType::Pointer(b))) => self
                .type_references_have_same_identity(
                    a.target_type_id,
                    b.target_type_id,
                    &mut HashSet::new(),
                ),
            (Some(RawType::Array(a)), Some(RawType::Array(b))) => {
                a.count == b.count
                    && self.type_references_have_same_identity(
                        a.elem_type_id,
                        b.elem_type_id,
                        &mut HashSet::new(),
                    )
            }
            (Some(RawType::Struct(a)), Some(RawType::Struct(b))) => {
                a.size == b.size
                    && self.members_have_compatible_layout(&a.members, &b.members)
                    && self.params_have_compatible_layout(&a.template_params, &b.template_params)
            }
            (Some(RawType::Union(a)), Some(RawType::Union(b))) => {
                a.size == b.size
                    && self.members_have_compatible_layout(&a.members, &b.members)
                    && self.params_have_compatible_layout(&a.template_params, &b.template_params)
            }
            (Some(RawType::Enum(a)), Some(RawType::Enum(b))) => {
                a.size == b.size
                    && compatible_alignment(a.alignment, b.alignment)
                    && self.variant_shapes_have_compatible_layout(&a.shape, &b.shape)
                    && self.params_have_compatible_layout(&a.template_params, &b.template_params)
            }
            _ => false,
        }
    }

    /// Compare referenced types by semantic identity rather than requiring
    /// every duplicate DIE below them to carry equally complete layout data.
    /// Each named child is reconciled independently in its own collision
    /// group; anonymous pointers and arrays retain their structural identity.
    fn type_references_have_same_identity(
        &self,
        left: TypeId,
        right: TypeId,
        visiting: &mut HashSet<(TypeId, TypeId)>,
    ) -> bool {
        let left = self.canonicalize(left);
        let right = self.canonicalize(right);
        if left == right {
            return true;
        }
        let pair = ordered_pair(left, right);
        if !visiting.insert(pair) {
            return true;
        }

        let result = match (self.types.get(&left), self.types.get(&right)) {
            (Some(left), Some(right)) if left.name().is_some() && right.name().is_some() => {
                raw_type_kind(left) == raw_type_kind(right)
                    && left.namespace() == right.namespace()
                    && left.name() == right.name()
            }
            (Some(RawType::Pointer(left)), Some(RawType::Pointer(right))) => self
                .type_references_have_same_identity(
                    left.target_type_id,
                    right.target_type_id,
                    visiting,
                ),
            (Some(RawType::Array(left)), Some(RawType::Array(right))) => {
                left.count == right.count
                    && self.type_references_have_same_identity(
                        left.elem_type_id,
                        right.elem_type_id,
                        visiting,
                    )
            }
            (None, None) => {
                self.subroutine_types.contains(&left) && self.subroutine_types.contains(&right)
            }
            _ => false,
        };
        visiting.remove(&pair);
        result
    }

    fn members_have_compatible_layout(
        &self,
        left: &[RawMember<StrId>],
        right: &[RawMember<StrId>],
    ) -> bool {
        if left.is_empty() || right.is_empty() {
            return true;
        }
        left.len() == right.len()
            && left.iter().zip(right).all(|(left, right)| {
                left.name == right.name
                    && left.offset == right.offset
                    && self.type_references_have_same_identity(
                        left.type_id,
                        right.type_id,
                        &mut HashSet::new(),
                    )
            })
    }

    fn params_have_compatible_layout(
        &self,
        left: &[RawGenericParameter<StrId>],
        right: &[RawGenericParameter<StrId>],
    ) -> bool {
        if left.is_empty() || right.is_empty() {
            return true;
        }
        left.len() == right.len()
            && left.iter().zip(right).all(|(left, right)| {
                left.name == right.name
                    && self.type_references_have_same_identity(
                        left.type_id,
                        right.type_id,
                        &mut HashSet::new(),
                    )
            })
    }

    fn variant_shapes_have_compatible_layout(
        &self,
        left: &VariantShape<StrId>,
        right: &VariantShape<StrId>,
    ) -> bool {
        match (left, right) {
            (VariantShape::Zero, VariantShape::Zero) => true,
            (VariantShape::One(left), VariantShape::One(right)) => self
                .members_have_compatible_layout(
                    std::slice::from_ref(&left.member),
                    std::slice::from_ref(&right.member),
                ),
            (
                VariantShape::Many {
                    discr: left_discr,
                    variants: left_variants,
                },
                VariantShape::Many {
                    discr: right_discr,
                    variants: right_variants,
                },
            ) => {
                left_variants.is_empty()
                    || right_variants.is_empty()
                    || (optional_members_have_compatible_layout(
                        self,
                        left_discr.as_ref(),
                        right_discr.as_ref(),
                    ) && left_variants.len() == right_variants.len()
                        && left_variants.iter().zip(right_variants).all(
                            |((left_discr, left), (right_discr, right))| {
                                left_discr == right_discr
                                    && self.members_have_compatible_layout(
                                        std::slice::from_ref(&left.member),
                                        std::slice::from_ref(&right.member),
                                    )
                            },
                        ))
            }
            (
                VariantShape::CStyle {
                    repr_type_id: left_repr,
                    enumerators: left_enumerators,
                },
                VariantShape::CStyle {
                    repr_type_id: right_repr,
                    enumerators: right_enumerators,
                },
            ) => {
                optional_type_ids_have_compatible_layout(self, *left_repr, *right_repr)
                    && (left_enumerators.is_empty()
                        || right_enumerators.is_empty()
                        || left_enumerators == right_enumerators)
            }
            _ => false,
        }
    }

    /// Definitions linked through `DW_AT_specification` may omit their name,
    /// namespace, and declaration coordinates. Carry those descriptive fields
    /// over while retaining the definition's complete layout.
    fn inherit_type_identity(&mut self, definition: TypeId, declaration: TypeId) {
        let Some(declaration) = self.types.get(&declaration).cloned() else {
            return;
        };
        let Some(definition) = self.types.get_mut(&definition) else {
            return;
        };

        match (definition, declaration) {
            (RawType::Base(def), RawType::Base(decl)) => {
                def.name = def.name.or(decl.name);
                def.namespace = def.namespace.or(decl.namespace);
            }
            (RawType::Pointer(def), RawType::Pointer(decl)) => {
                def.name = def.name.or(decl.name);
            }
            (RawType::Enum(def), RawType::Enum(decl)) => {
                def.name = def.name.or(decl.name);
                def.namespace = def.namespace.or(decl.namespace);
                if def.source_loc.is_none() {
                    def.source_loc = decl.source_loc;
                }
            }
            (RawType::Struct(def), RawType::Struct(decl)) => {
                def.name = def.name.or(decl.name);
                def.namespace = def.namespace.or(decl.namespace);
                if def.source_loc.is_none() {
                    def.source_loc = decl.source_loc;
                }
            }
            (RawType::Union(def), RawType::Union(decl)) => {
                def.name = def.name.or(decl.name);
                def.namespace = def.namespace.or(decl.namespace);
                if def.source_loc.is_none() {
                    def.source_loc = decl.source_loc;
                }
            }
            (RawType::Array(_), RawType::Array(_)) => {}
            _ => {}
        }
    }

    /// Resolve a [`TypeId`] to its canonical form by following the
    /// substitution chain.
    pub fn canonicalize(&self, id: TypeId) -> TypeId {
        let mut result = id;
        while let Some(&next) = self.subs.get(&result) {
            result = next;
        }
        result
    }

    /// Returns the canonical type for a given [`TypeId`].
    pub fn canonical_type(&self, id: TypeId) -> Option<&RawType<StrId>> {
        self.types.get(&self.canonicalize(id))
    }

    /// Whether `id` names a DWARF function-signature DIE.
    pub(crate) fn is_subroutine_type(&self, id: TypeId) -> bool {
        self.subroutine_types.contains(&self.canonicalize(id))
    }

    /// Produces an iterator over only the canonical types.
    pub fn canonical_types(&self) -> impl Iterator<Item = (TypeId, &RawType<StrId>)> {
        self.types
            .iter()
            .filter(|(id, _)| !self.subs.contains_key(id))
            .map(|(&id, ty)| (id, ty))
    }
}

/// A fully-interned CGU, produced by [`intern_cgu`] on a worker thread and
/// merged by the collector in [`DwReader::ingest`]. Every string has been
/// replaced by a [`StrId`], so this carries no borrow of the DWARF and the
/// fold's in-flight buffer no longer pins the underlying section pages. Type
/// references and namespaces are still CGU-local; the collector remaps them.
struct InternedCgu {
    producer: Option<StrId>,
    /// This CGU's namespace table with interned names, in the original local
    /// id order so the collector can remap references against it.
    namespaces: NamespaceTable<StrId>,
    types: HashMap<TypeId, RawType<StrId>>,
    subroutine_types: HashSet<TypeId>,
    variables: HashMap<VarId, RawStaticVariable<StrId>>,
    type_declarations: HashSet<TypeId>,
    type_specifications: HashMap<TypeId, TypeId>,
    funcs: HashMap<FuncId, RawFunc<StrId>>,
}

/// Intern a freshly-parsed CGU on a worker thread, replacing every borrowed
/// `&str` with a [`StrId`]. Interning tens of millions of strings is the
/// dominant cost of collection, so doing it here spreads it across the worker
/// pool instead of serializing it through the collector. Namespaces and type
/// references keep their CGU-local ids; the collector remaps them in
/// [`DwReader::ingest`].
fn intern_cgu<'dw>(global: &ShardedInterner<'dw>, cgu: CodegenUnit<'dw>) -> InternedCgu {
    let interner = &CguInterner::new(global);
    // Rebuild the CGU's namespace table with interned names. Namespaces are
    // listed parent-first and interning is injective on name content, so the
    // rebuilt table reproduces the original local ids one-for-one.
    let mut namespaces = NamespaceTable::<StrId>::new();
    for (_local_id, entry) in cgu.namespaces.iter() {
        namespaces.insert(entry.parent, interner.intern(entry.name));
    }

    let types = cgu
        .types
        .into_iter()
        .map(|(id, ty)| (id, intern_type(interner, ty)))
        .collect();
    let variables = cgu
        .variables
        .into_iter()
        .map(|(id, var)| (id, intern_var(interner, var)))
        .collect();
    let funcs = cgu
        .funcs
        .into_iter()
        .map(|(id, func)| (id, intern_func(interner, func)))
        .collect();

    InternedCgu {
        producer: cgu.producer.map(|p| interner.intern(p)),
        namespaces,
        types,
        subroutine_types: cgu.subroutine_types,
        variables,
        type_declarations: cgu.type_declarations,
        type_specifications: cgu.type_specifications,
        funcs,
    }
}

fn raw_type_kind(ty: &RawType<StrId>) -> u8 {
    match ty {
        RawType::Base(_) => 0,
        RawType::Pointer(_) => 1,
        RawType::Enum(_) => 2,
        RawType::Struct(_) => 3,
        RawType::Union(_) => 4,
        RawType::Array(_) => 5,
    }
}

fn ordered_pair(left: TypeId, right: TypeId) -> (TypeId, TypeId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn compatible_alignment(left: Option<NonZero<u64>>, right: Option<NonZero<u64>>) -> bool {
    left.is_none() || right.is_none() || left == right
}

fn optional_members_have_compatible_layout(
    reader: &DwReader<'_>,
    left: Option<&RawMember<StrId>>,
    right: Option<&RawMember<StrId>>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => reader.members_have_compatible_layout(
            std::slice::from_ref(left),
            std::slice::from_ref(right),
        ),
        (None, None) => true,
        _ => false,
    }
}

fn optional_type_ids_have_compatible_layout(
    reader: &DwReader<'_>,
    left: Option<TypeId>,
    right: Option<TypeId>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            reader.type_references_have_same_identity(left, right, &mut HashSet::new())
        }
        (None, None) => true,
        _ => false,
    }
}

/// A per-CGU front for the shared [`ShardedInterner`]. A single CGU interns the
/// same string enormously often (common namespace, module, and type-name
/// fragments recur across nearly every DIE), and each global intern takes a
/// shard lock. Caching the ids seen within this CGU turns those repeats into
/// lock-free local hits, which is the difference between the workers scaling and
/// serializing on hot shards. The cache lives only as long as the CGU, so it
/// stays small and needs no eviction.
struct CguInterner<'a, 'dw> {
    global: &'a ShardedInterner<'dw>,
    cache: std::cell::RefCell<HashMap<&'dw str, StrId>>,
}

impl<'a, 'dw> CguInterner<'a, 'dw> {
    fn new(global: &'a ShardedInterner<'dw>) -> Self {
        Self {
            global,
            cache: std::cell::RefCell::new(HashMap::new()),
        }
    }

    fn intern(&self, s: &'dw str) -> StrId {
        if let Some(&id) = self.cache.borrow().get(s) {
            return id;
        }
        let id = self.global.intern(s);
        self.cache.borrow_mut().insert(s, id);
        id
    }
}

/// Convert a `RawType<&'dw str>` into a `RawType<StrId>` by interning all strings.
fn intern_type<'dw>(strings: &CguInterner<'_, 'dw>, ty: RawType<&'dw str>) -> RawType<StrId> {
    let intern = |s: Option<&'dw str>| s.map(|s| strings.intern(s));
    match ty {
        RawType::Base(b) => RawType::Base(RawBase {
            name: intern(b.name),
            namespace: b.namespace,
            encoding: b.encoding,
            size: b.size,
            alignment: b.alignment,
        }),
        RawType::Pointer(p) => RawType::Pointer(RawPointer {
            name: intern(p.name),
            target_type_id: p.target_type_id,
        }),
        RawType::Enum(e) => RawType::Enum(RawEnum {
            name: intern(e.name),
            namespace: e.namespace,
            size: e.size,
            alignment: e.alignment,
            shape: intern_variant_shape(strings, e.shape),
            template_params: intern_generic_params(strings, e.template_params),
            source_loc: e
                .source_loc
                .map(|loc| Box::new(intern_source_loc(strings, *loc))),
        }),
        RawType::Struct(s) => RawType::Struct(RawStruct {
            name: intern(s.name),
            namespace: s.namespace,
            size: s.size,
            members: s
                .members
                .into_vec()
                .into_iter()
                .map(|m| intern_member(strings, m))
                .collect(),
            template_params: intern_generic_params(strings, s.template_params),
            source_loc: s
                .source_loc
                .map(|loc| Box::new(intern_source_loc(strings, *loc))),
        }),
        RawType::Union(u) => RawType::Union(RawUnion {
            name: intern(u.name),
            namespace: u.namespace,
            size: u.size,
            members: u
                .members
                .into_vec()
                .into_iter()
                .map(|m| intern_member(strings, m))
                .collect(),
            template_params: intern_generic_params(strings, u.template_params),
            source_loc: u
                .source_loc
                .map(|loc| Box::new(intern_source_loc(strings, *loc))),
        }),
        RawType::Array(a) => RawType::Array(a),
    }
}

/// Convert a boxed slice of `RawGenericParameter<&'dw str>` into interned form.
fn intern_generic_params<'dw>(
    strings: &CguInterner<'_, 'dw>,
    params: Box<[RawGenericParameter<&'dw str>]>,
) -> Box<[RawGenericParameter<StrId>]> {
    params
        .into_vec()
        .into_iter()
        .map(|p| RawGenericParameter {
            name: p.name.map(|s| strings.intern(s)),
            type_id: p.type_id,
        })
        .collect()
}

fn intern_member<'dw>(strings: &CguInterner<'_, 'dw>, m: RawMember<&'dw str>) -> RawMember<StrId> {
    RawMember {
        name: m.name.map(|s| strings.intern(s)),
        offset: m.offset,
        type_id: m.type_id,
        source_loc: m
            .source_loc
            .map(|loc| Box::new(intern_source_loc(strings, *loc))),
    }
}

fn intern_variant_shape<'dw>(
    strings: &CguInterner<'_, 'dw>,
    shape: VariantShape<&'dw str>,
) -> VariantShape<StrId> {
    match shape {
        VariantShape::Zero => VariantShape::Zero,
        VariantShape::One(v) => VariantShape::One(intern_variant(strings, v)),
        VariantShape::Many { discr, variants } => VariantShape::Many {
            discr: discr.map(|d| intern_member(strings, d)),
            variants: variants
                .into_vec()
                .into_iter()
                .map(|(dv, v)| (dv, intern_variant(strings, v)))
                .collect(),
        },
        VariantShape::CStyle {
            repr_type_id,
            enumerators,
        } => VariantShape::CStyle {
            repr_type_id,
            enumerators: enumerators
                .into_vec()
                .into_iter()
                .map(|e| RawEnumerator {
                    name: strings.intern(e.name),
                    value: e.value,
                })
                .collect(),
        },
    }
}

fn intern_variant<'dw>(
    strings: &CguInterner<'_, 'dw>,
    v: RawVariant<&'dw str>,
) -> RawVariant<StrId> {
    RawVariant {
        member: intern_member(strings, v.member),
    }
}

/// Convert a `RawStaticVariable<&'dw str>` into a `RawStaticVariable<StrId>` by interning all strings.
fn intern_var<'dw>(
    strings: &CguInterner<'_, 'dw>,
    var: RawStaticVariable<&'dw str>,
) -> RawStaticVariable<StrId> {
    let intern = |s: Option<&'dw str>| s.map(|s| strings.intern(s));
    RawStaticVariable {
        name: intern(var.name),
        namespace: var.namespace,
        type_id: var.type_id,
        addr: var.addr,
        linkage_name: intern(var.linkage_name),
        source_loc: SourceLoc {
            file: intern(var.source_loc.file),
            dir: intern(var.source_loc.dir),
            comp_dir: intern(var.source_loc.comp_dir),
            line: var.source_loc.line,
            column: var.source_loc.column,
        },
    }
}

/// Intern an optional string.
fn intern_opt<'dw>(strings: &CguInterner<'_, 'dw>, s: Option<&'dw str>) -> Option<StrId> {
    s.map(|s| strings.intern(s))
}

/// Convert a `SourceLoc<&'dw str>` into a `SourceLoc<StrId>` by interning all strings.
fn intern_source_loc<'dw>(
    strings: &CguInterner<'_, 'dw>,
    loc: SourceLoc<&'dw str>,
) -> SourceLoc<StrId> {
    SourceLoc {
        file: intern_opt(strings, loc.file),
        dir: intern_opt(strings, loc.dir),
        comp_dir: intern_opt(strings, loc.comp_dir),
        line: loc.line,
        column: loc.column,
    }
}

/// Convert a `RawSubParameter<&'dw str>` into a `RawSubParameter<StrId>` by interning all strings.
fn intern_param<'dw>(
    strings: &CguInterner<'_, 'dw>,
    param: RawSubParameter<&'dw str>,
) -> RawSubParameter<StrId> {
    RawSubParameter {
        name: intern_opt(strings, param.name),
        type_id: param.type_id,
        abstract_origin: param.abstract_origin,
        const_value: param.const_value,
        source_loc: param
            .source_loc
            .map(|loc| Box::new(intern_source_loc(strings, *loc))),
    }
}

/// Convert a `RawFunc<&'dw str>` into a `RawFunc<StrId>` by interning all strings.
fn intern_func<'dw>(strings: &CguInterner<'_, 'dw>, func: RawFunc<&'dw str>) -> RawFunc<StrId> {
    RawFunc {
        name: intern_opt(strings, func.name),
        namespace: func.namespace,
        source_loc: func
            .source_loc
            .map(|loc| Box::new(intern_source_loc(strings, *loc))),
        return_type_id: func.return_type_id,
        formal_parameters: func
            .formal_parameters
            .into_vec()
            .into_iter()
            .map(|p| intern_param(strings, p))
            .collect(),
        abstract_origin: func.abstract_origin,
        linkage_name: intern_opt(strings, func.linkage_name),
        template_params: intern_generic_params(strings, func.template_params),
        noreturn: func.noreturn,
        awaitees: func
            .awaitees
            .into_vec()
            .into_iter()
            .map(|a| RawAwaitee {
                source_loc: a
                    .source_loc
                    .map(|loc| Box::new(intern_source_loc(strings, *loc))),
                type_id: a.type_id,
            })
            .collect(),
    }
}

/// Rewrite namespace references on a type in place. Generic over the string
/// representation: it touches only the `NsId` fields, so it runs after
/// interning on `RawType<StrId>` just as well as on the borrowed form.
fn remap_ns_in_place<S>(ty: &mut RawType<S>, ns_remap: &HashMap<NsId, NsId>) {
    let remap = |ns: &mut Option<NsId>| {
        if let Some(id) = ns {
            *id = ns_remap[id];
        }
    };
    match ty {
        RawType::Base(b) => remap(&mut b.namespace),
        RawType::Enum(e) => remap(&mut e.namespace),
        RawType::Struct(s) => remap(&mut s.namespace),
        RawType::Union(u) => remap(&mut u.namespace),
        RawType::Pointer(_) | RawType::Array(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_types::RawArray;
    use gimli::{DebugInfoOffset, UnitSectionOffset};

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(offset)))
    }

    fn insert_struct(
        reader: &mut DwReader<'static>,
        id: TypeId,
        name: Option<&'static str>,
        size: u64,
    ) {
        let name = name.map(|name| reader.strings.intern(name));
        reader.types.insert(
            id,
            RawType::Struct(RawStruct {
                name,
                namespace: None,
                size,
                members: Box::new([]),
                template_params: Box::new([]),
                source_loc: None,
            }),
        );
    }

    fn insert_pointer(reader: &mut DwReader<'static>, id: TypeId, target: TypeId) {
        reader.types.insert(
            id,
            RawType::Pointer(RawPointer {
                name: None,
                target_type_id: target,
            }),
        );
    }

    #[test]
    fn finalization_resolves_forward_references_to_a_fixed_point() {
        let mut reader = DwReader::new();
        let canonical = type_id(0x10);
        let duplicate = type_id(0x50);
        let pointer = type_id(0x20);
        let duplicate_pointer = type_id(0x60);
        let outer_pointer = type_id(0x30);
        let duplicate_outer_pointer = type_id(0x40);

        insert_struct(&mut reader, canonical, Some("Value"), 1);
        insert_struct(&mut reader, duplicate, Some("Value"), 1);
        insert_pointer(&mut reader, pointer, canonical);
        insert_pointer(&mut reader, duplicate_pointer, duplicate);
        insert_pointer(&mut reader, outer_pointer, pointer);
        insert_pointer(&mut reader, duplicate_outer_pointer, duplicate_pointer);

        reader.finalize_types();

        assert_eq!(reader.canonicalize(duplicate), canonical);
        assert_eq!(reader.canonicalize(duplicate_pointer), pointer);
        assert_eq!(reader.canonicalize(duplicate_outer_pointer), outer_pointer);
    }

    #[test]
    fn finalization_deduplicates_arrays_after_their_elements() {
        let mut reader = DwReader::new();
        let canonical = type_id(0x10);
        let duplicate = type_id(0x50);
        let array = type_id(0x20);
        let duplicate_array = type_id(0x60);

        insert_struct(&mut reader, canonical, Some("Value"), 1);
        insert_struct(&mut reader, duplicate, Some("Value"), 1);
        reader.types.insert(
            array,
            RawType::Array(RawArray {
                elem_type_id: canonical,
                count: 4,
            }),
        );
        reader.types.insert(
            duplicate_array,
            RawType::Array(RawArray {
                elem_type_id: duplicate,
                count: 4,
            }),
        );

        reader.finalize_types();

        assert_eq!(reader.canonicalize(duplicate_array), array);
    }

    #[test]
    fn finalization_prefers_a_definition_to_an_earlier_declaration() {
        let mut reader = DwReader::new();
        let declaration = type_id(0x10);
        let definition = type_id(0x50);

        insert_struct(&mut reader, declaration, Some("Value"), 0);
        insert_struct(&mut reader, definition, Some("Value"), 8);
        reader.type_declarations.insert(declaration);

        reader.finalize_types();

        assert_eq!(reader.canonicalize(declaration), definition);
        assert_eq!(reader.canonicalize(definition), definition);
        let RawType::Struct(canonical) = reader.canonical_type(declaration).unwrap() else {
            panic!("expected struct definition");
        };
        assert_eq!(canonical.size, 8);
    }

    #[test]
    fn finalization_follows_type_specifications() {
        let mut reader = DwReader::new();
        let declaration = type_id(0x10);
        let duplicate_declaration = type_id(0x20);
        let definition = type_id(0x50);

        insert_struct(&mut reader, declaration, Some("Value"), 0);
        insert_struct(&mut reader, duplicate_declaration, Some("Value"), 0);
        insert_struct(&mut reader, definition, None, 8);
        reader.type_declarations.insert(declaration);
        reader.type_declarations.insert(duplicate_declaration);
        reader.type_specifications.insert(definition, declaration);

        reader.finalize_types();

        assert_eq!(reader.canonicalize(declaration), definition);
        assert_eq!(reader.canonicalize(duplicate_declaration), definition);
        assert_eq!(
            reader
                .canonical_type(definition)
                .and_then(RawType::name)
                .map(|name| reader.strings.get(name)),
            Some("Value")
        );
    }

    #[test]
    fn finalization_unifies_matching_named_layouts() {
        let mut reader = DwReader::new();
        let canonical = type_id(0x10);
        let duplicate = type_id(0x20);

        insert_struct(&mut reader, canonical, Some("Value"), 8);
        insert_struct(&mut reader, duplicate, Some("Value"), 8);

        reader.finalize_types();

        assert_eq!(reader.canonicalize(duplicate), canonical);
    }

    #[test]
    fn finalization_preserves_incompatible_name_collisions() {
        let mut reader = DwReader::new();
        let declaration = type_id(0x10);
        let small = type_id(0x20);
        let large = type_id(0x30);
        let duplicate_small = type_id(0x40);

        insert_struct(&mut reader, declaration, Some("Value"), 0);
        insert_struct(&mut reader, small, Some("Value"), 4);
        insert_struct(&mut reader, large, Some("Value"), 8);
        insert_struct(&mut reader, duplicate_small, Some("Value"), 4);
        reader.type_declarations.insert(declaration);

        reader.finalize_types();

        assert_eq!(reader.canonicalize(duplicate_small), small);
        assert_eq!(reader.canonicalize(small), small);
        assert_eq!(reader.canonicalize(large), large);
        assert_eq!(reader.canonicalize(declaration), declaration);
    }

    #[test]
    fn finalization_does_not_merge_anonymous_or_different_kind_types() {
        let mut reader = DwReader::new();
        let anonymous_a = type_id(0x10);
        let anonymous_b = type_id(0x20);
        let named_struct = type_id(0x30);
        let named_union = type_id(0x40);

        insert_struct(&mut reader, anonymous_a, None, 8);
        insert_struct(&mut reader, anonymous_b, None, 8);
        insert_struct(&mut reader, named_struct, Some("Value"), 8);
        let name = reader.strings.intern("Value");
        reader.types.insert(
            named_union,
            RawType::Union(RawUnion {
                name: Some(name),
                namespace: None,
                size: 8,
                members: Box::new([]),
                template_params: Box::new([]),
                source_loc: None,
            }),
        );

        reader.finalize_types();

        assert_eq!(reader.canonicalize(anonymous_a), anonymous_a);
        assert_eq!(reader.canonicalize(anonymous_b), anonymous_b);
        assert_eq!(reader.canonicalize(named_struct), named_struct);
        assert_eq!(reader.canonicalize(named_union), named_union);
    }
}

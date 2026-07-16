use crate::cgu::CodegenUnit;
use crate::parallel_fold::OrderedParallelFold;
use crate::raw_types::{
    NamespaceTable, NsId, RawBase, RawEnum, RawEnumerator, RawFunc, RawGenericParameter, RawMember,
    RawPointer, RawStaticVariable, RawStruct, RawSubParameter, RawType, RawUnion, RawVariant,
    SourceLoc, VariantShape,
};
use crate::string_table::{StrId, StringTable};
use crate::{Error, FuncId, Result, Slice};
use crate::{TypeId, VarId};

use foldhash::{HashMap, HashMapExt, HashSet, HashSetExt};
use gimli::{Dwarf, UnitRef};
use regex::Regex;
use tracing::debug;

use std::num::NonZero;

/// A global, deduplicated view of all types from the DWARF debug information.
///
/// CGUs are ingested in `.debug_info` order via [`DwReader::ingest`]. This
/// guarantees that the canonical [`TypeId`] for each deduplicated type is
/// always the lowest DWARF offset.
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
    pub strings: StringTable<'dw>,
    /// The `DW_AT_producer` of the first compile unit that carries one
    /// (compiler identification, e.g. the rustc version).
    pub producer: Option<StrId>,
}

/// The namespaces and targets to collect from the DWARF.
#[derive(Default, Debug)]
pub struct Targets {
    /// The top-level namespaces to capture, e.g., `tokio`.
    pub namespaces: Vec<String>,
    /// The type name patterns to capture, e.g., `Foo.*`, `.*async_fn.*`.
    pub type_patterns: Vec<Regex>,
}

/// Configuration for [`DwarfReader::read_types`].
#[derive(Default)]
pub struct ReadArgs {
    /// The namespaces and types to collect.
    pub targets: Option<Targets>,
    /// Number of worker threads for parsing CGUs in parallel.
    /// Defaults to [`thread::available_parallelism`].
    pub cgu_parallelism: Option<NonZero<usize>>,
    /// Maximum number of CGUs that may be in-flight (parsed but not yet
    /// ingested by the collector). Defaults to `2 * cgu_parallelism`.
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
    /// worker thread, and folds the results into a single [`DwReader`]
    /// **in `.debug_info` order**. That ordering guarantee is critical:
    /// because types are deduplicated by `(namespace, name)`, the first
    /// occurrence wins, and processing in section order ensures the
    /// canonical [`TypeId`] for every deduplicated type is always the
    /// lowest DWARF offset. Changing the ingestion order would silently
    /// reassign canonical IDs and break any downstream consumers that
    /// persist or compare them.
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
    ///     parse CGUs concurrently. Defaults to
    ///     [`std::thread::available_parallelism`]. Higher values speed up
    ///     parsing on machines with many cores, but each worker holds a
    ///     fully-parsed [`CodegenUnit`] in memory until it is ingested by
    ///     the collector.
    ///
    ///   - [`ReadArgs::cgus_in_flight`]: The maximum number of parsed CGUs
    ///     that may exist between the worker threads and the collector at
    ///     any given time. Defaults to `2 × cgu_parallelism`. This is the
    ///     backpressure knob: lowering it reduces peak memory usage (fewer
    ///     large `CodegenUnit` objects alive simultaneously) at the cost of
    ///     potentially stalling workers that finish before the collector
    ///     catches up. Setting it to `1` serialises ingestion entirely.
    ///
    ///   - [`ReadArgs::targets`]: Reserved for future namespace/type
    ///     filtering. Currently unused — all types are collected.
    pub fn read_types(dwarf: &Dwarf<Slice<'dw>>, args: ReadArgs) -> Result<DwReader<'dw>> {
        let mut units = dwarf.units();

        let mut fold = OrderedParallelFold::new(
            || Ok(units.next()?),
            |header| {
                let unit = dwarf.unit(header)?;
                let unit_ref = UnitRef::new(dwarf, &unit);
                let mut cursor = unit.entries();
                cursor.next_entry()?;
                let cgu = CodegenUnit::from_cursor(&unit_ref, &mut cursor)?;
                debug!("processed unit {}", cgu.name);
                Ok::<_, Error>(cgu)
            },
            DwReader::new(),
            |c: &mut DwReader<'_>, cgu| {
                c.ingest(cgu);
            },
        );

        if let Some(n) = args.cgu_parallelism {
            fold = fold.parallelism(n.get());
        }
        if let Some(n) = args.cgus_in_flight {
            fold = fold.max_in_flight(n.get());
        }

        let mut collector = fold.run()?;
        collector.finalize_types();
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
            strings: StringTable::new(),
            producer: None,
        }
    }

    /// Ingest all types from a [`CodegenUnit`] into the global type space.
    /// CGUs must be ingested in `.debug_info` order. Deduplication is deferred
    /// until every CGU has been collected so forward references cannot make
    /// the result depend on ingestion order.
    fn ingest(&mut self, mut cgu: CodegenUnit<'dw>) {
        let ns_remap = self.remap_namespaces(&cgu.namespaces);

        if self.producer.is_none() {
            self.producer = cgu.producer.map(|p| self.strings.intern(p));
        }

        for (type_id, mut ty) in cgu.types.drain() {
            remap_ns_in_place(&mut ty, &ns_remap);
            let ty = intern_type(&mut self.strings, ty);

            self.types.insert(type_id, ty);
        }

        self.subroutine_types.extend(cgu.subroutine_types.drain());
        self.type_declarations.extend(cgu.type_declarations.drain());
        self.type_specifications
            .extend(cgu.type_specifications.drain());

        // Static variables are unique by address — no dedup needed.
        // Remap namespaces now; type references are canonicalized on access
        // after the final alias map has been built.
        for (var_id, mut var) in cgu.variables.drain() {
            if let Some(id) = var.namespace {
                var.namespace = Some(ns_remap[&id]);
            }
            let var = intern_var(&mut self.strings, var);
            self.variables.insert(var_id, var);
        }

        // Functions — remap namespaces and intern strings. Type references
        // are canonicalized on access after finalization.
        for (func_id, mut func) in cgu.funcs.drain() {
            if let Some(id) = func.namespace {
                func.namespace = Some(ns_remap[&id]);
            }
            let func = intern_func(&mut self.strings, func);
            self.functions.insert(func_id, func);
        }
    }

    /// Build the global alias map after every CGU has been collected.
    ///
    /// Named types retain the historical `(namespace, name)` identity rule.
    /// Anonymous pointers and arrays are then deduplicated structurally. The
    /// structural pass repeats because an outer pointer may only become equal
    /// after its pointee was deduplicated in an earlier pass.
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

        let mut named: HashMap<(Option<NsId>, Option<StrId>), Vec<TypeId>> = HashMap::new();
        for (&id, ty) in &self.types {
            if !matches!(ty, RawType::Pointer(p) if p.name.is_none())
                && !matches!(ty, RawType::Array(_))
            {
                named.entry(type_name_key(ty)).or_default().push(id);
            }
        }
        for ids in named.values() {
            self.alias_named_types(ids);
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

    fn alias_named_types(&mut self, ids: &[TypeId]) {
        let resolved: Vec<_> = ids.iter().map(|&id| self.canonicalize(id)).collect();
        let canonical = resolved
            .iter()
            .copied()
            .filter(|id| !self.type_declarations.contains(id))
            .min()
            .or_else(|| resolved.iter().copied().min());
        let Some(canonical) = canonical else {
            return;
        };
        for id in resolved {
            if id != canonical {
                self.subs.insert(id, canonical);
            }
        }
        for &id in ids {
            if id != canonical {
                self.subs.insert(id, canonical);
            }
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

    /// The number of canonical (deduplicated) types.
    pub fn canonical_type_count(&self) -> usize {
        self.types.len() - self.subs.len()
    }

    /// Re-intern all namespaces from a CGU's local table into the global
    /// table, returning a mapping from local [`NsId`] to global [`NsId`].
    /// Namespace names are interned into the string table along the way.
    fn remap_namespaces(&mut self, local: &NamespaceTable<&'dw str>) -> HashMap<NsId, NsId> {
        let mut ns_remap: HashMap<NsId, NsId> = HashMap::new();
        for (local_id, entry) in local.iter() {
            let global_parent = entry.parent.map(|p| ns_remap[&p]);
            let name_id = self.strings.intern(entry.name);
            let global_id = self.namespaces.insert(global_parent, name_id);
            ns_remap.insert(local_id, global_id);
        }
        ns_remap
    }
}

/// Extract the name index key from a type.
fn type_name_key(ty: &RawType<StrId>) -> (Option<NsId>, Option<StrId>) {
    match ty {
        RawType::Base(b) => (b.namespace, b.name),
        RawType::Enum(e) => (e.namespace, e.name),
        RawType::Pointer(p) => (None, p.name),
        RawType::Struct(s) => (s.namespace, s.name),
        RawType::Union(u) => (u.namespace, u.name),
        // Arrays never reach the named-dedup path (see `ingest`).
        RawType::Array(_) => (None, None),
    }
}

/// Convert a `RawType<&'dw str>` into a `RawType<StrId>` by interning all strings.
fn intern_type<'dw>(strings: &mut StringTable<'dw>, ty: RawType<&'dw str>) -> RawType<StrId> {
    let mut intern = |s: Option<&'dw str>| s.map(|s| strings.intern(s));
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
    strings: &mut StringTable<'dw>,
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

fn intern_member<'dw>(strings: &mut StringTable<'dw>, m: RawMember<&'dw str>) -> RawMember<StrId> {
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
    strings: &mut StringTable<'dw>,
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
    strings: &mut StringTable<'dw>,
    v: RawVariant<&'dw str>,
) -> RawVariant<StrId> {
    RawVariant {
        member: intern_member(strings, v.member),
    }
}

/// Convert a `RawStaticVariable<&'dw str>` into a `RawStaticVariable<StrId>` by interning all strings.
fn intern_var<'dw>(
    strings: &mut StringTable<'dw>,
    var: RawStaticVariable<&'dw str>,
) -> RawStaticVariable<StrId> {
    let mut intern = |s: Option<&'dw str>| s.map(|s| strings.intern(s));
    RawStaticVariable {
        name: intern(var.name),
        namespace: var.namespace,
        type_id: var.type_id,
        addr: var.addr,
        linkage_name: intern(var.linkage_name),
        source_loc: SourceLoc {
            file: intern(var.source_loc.file),
            dir: intern(var.source_loc.dir),
            line: var.source_loc.line,
            column: var.source_loc.column,
        },
    }
}

/// Intern an optional string.
fn intern_opt<'dw>(strings: &mut StringTable<'dw>, s: Option<&'dw str>) -> Option<StrId> {
    s.map(|s| strings.intern(s))
}

/// Convert a `SourceLoc<&'dw str>` into a `SourceLoc<StrId>` by interning all strings.
fn intern_source_loc<'dw>(
    strings: &mut StringTable<'dw>,
    loc: SourceLoc<&'dw str>,
) -> SourceLoc<StrId> {
    SourceLoc {
        file: intern_opt(strings, loc.file),
        dir: intern_opt(strings, loc.dir),
        line: loc.line,
        column: loc.column,
    }
}

/// Convert a `RawSubParameter<&'dw str>` into a `RawSubParameter<StrId>` by interning all strings.
fn intern_param<'dw>(
    strings: &mut StringTable<'dw>,
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
fn intern_func<'dw>(strings: &mut StringTable<'dw>, func: RawFunc<&'dw str>) -> RawFunc<StrId> {
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
    }
}

/// Rewrite namespace references on a type in place.
fn remap_ns_in_place(ty: &mut RawType<&str>, ns_remap: &HashMap<NsId, NsId>) {
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
}

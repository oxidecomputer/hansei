use crate::cgu::CodegenUnit;
use crate::parallel_fold::OrderedParallelFold;
use crate::raw_types::{
    NamespaceTable, NsId, RawBase, RawEnum, RawEnumerator, RawMember, RawPointer,
    RawStaticVariable, RawStruct, RawSubParameter, RawFunc, RawType, RawVariant, SourceLoc,
    VariantShape,
};
use crate::string_table::{StrId, StringTable};
use crate::{Error, FuncId, Result, Slice};
use crate::{TypeId, VarId};

use foldhash::{HashMap, HashMapExt};
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
    /// Name index for named types: (namespace, name) → canonical TypeId.
    name_index: HashMap<(Option<NsId>, Option<StrId>), TypeId>,
    /// Pointer dedup index: canonical target TypeId → canonical pointer TypeId.
    pointer_index: HashMap<TypeId, TypeId>,
    /// Substitution map: non-canonical TypeId → canonical TypeId.
    subs: HashMap<TypeId, TypeId>,
    /// All static variables, keyed by their VarId.
    pub variables: HashMap<VarId, RawStaticVariable<StrId>>,
    /// All functions, keyed by their FuncId.
    pub functions: HashMap<FuncId, RawFunc<StrId>>,
    /// Global namespace table.
    pub namespaces: NamespaceTable<StrId>,
    /// Interned string table for all strings found in types and variables.
    pub strings: StringTable<'dw>,
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

        let collector = fold.run()?;
        Ok(collector)
    }

    fn new() -> Self {
        Self {
            types: HashMap::new(),
            name_index: HashMap::new(),
            pointer_index: HashMap::new(),
            subs: HashMap::new(),
            variables: HashMap::new(),
            functions: HashMap::new(),
            namespaces: NamespaceTable::new(),
            strings: StringTable::new(),
        }
    }

    /// Ingest all types from a [`CodegenUnit`], deduplicating them into the
    /// global type space. CGUs must be ingested in `.debug_info` order.
    ///
    /// Named types are deduplicated by `(namespace, name)`. Unnamed pointer
    /// types are deduplicated by the canonical TypeId of their target.
    fn ingest(&mut self, mut cgu: CodegenUnit<'dw>) {
        let ns_remap = self.remap_namespaces(&cgu.namespaces);

        for (type_id, mut ty) in cgu.types.drain() {
            remap_ns_in_place(&mut ty, &ns_remap);
            let ty = intern_type(&mut self.strings, ty);

            match &ty {
                RawType::Pointer(p) if p.name.is_none() => {
                    // Unnamed pointers: dedup by canonical target type.
                    let canonical_target = self.canonicalize(p.target_type_id);
                    self.types.insert(type_id, ty);
                    if let Some(&canonical_ptr) = self.pointer_index.get(&canonical_target) {
                        self.subs.insert(type_id, canonical_ptr);
                    } else {
                        self.pointer_index.insert(canonical_target, type_id);
                    }
                }
                _ => {
                    // Named types: dedup by (namespace, name).
                    let key = type_name_key(&ty);
                    self.types.insert(type_id, ty);
                    match self.name_index.entry(key) {
                        std::collections::hash_map::Entry::Occupied(e) => {
                            self.subs.insert(type_id, *e.get());
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(type_id);
                        }
                    }
                }
            }
        }

        // Static variables are unique by address — no dedup needed.
        // Remap namespace and canonicalize type references.
        for (var_id, mut var) in cgu.variables.drain() {
            if let Some(id) = var.namespace {
                var.namespace = Some(ns_remap[&id]);
            }
            var.type_id = self.canonicalize(var.type_id);
            let var = intern_var(&mut self.strings, var);
            self.variables.insert(var_id, var);
        }

        // Functions — remap namespaces, canonicalize type refs, intern strings.
        for (func_id, mut func) in cgu.funcs.drain() {
            if let Some(id) = func.namespace {
                func.namespace = Some(ns_remap[&id]);
            }
            func.return_type_id = func.return_type_id.map(|id| self.canonicalize(id));
            for param in func.formal_parameters.iter_mut() {
                param.type_id = param.type_id.map(|id| self.canonicalize(id));
            }
            let func = intern_func(&mut self.strings, func);
            self.functions.insert(func_id, func);
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
        }),
        RawType::Struct(s) => RawType::Struct(RawStruct {
            name: intern(s.name),
            namespace: s.namespace,
            size: s.size,
            members: s
                .members
                .into_vec()
                .into_iter()
                .map(|m| RawMember {
                    name: intern(m.name),
                    offset: m.offset,
                    type_id: m.type_id,
                })
                .collect(),
        }),
    }
}

fn intern_member<'dw>(strings: &mut StringTable<'dw>, m: RawMember<&'dw str>) -> RawMember<StrId> {
    RawMember {
        name: m.name.map(|s| strings.intern(s)),
        offset: m.offset,
        type_id: m.type_id,
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
fn intern_func<'dw>(
    strings: &mut StringTable<'dw>,
    func: RawFunc<&'dw str>,
) -> RawFunc<StrId> {
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
        RawType::Pointer(_) => {}
    }
}

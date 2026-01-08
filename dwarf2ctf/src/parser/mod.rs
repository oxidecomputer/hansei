use crate::GlobalTypeOffset;
use crate::ctf::CtfWriter;

use anyhow::{Context, Result};
use gimli::{
    AttributeValue, DW_TAG_formal_parameter, DW_TAG_subprogram, DebugInfoOffset,
    DebuggingInformationEntry, DwTag, Dwarf, Reader, UnitOffset, UnitRef,
};
use petgraph::prelude::DiGraphMap;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::Range;

pub struct DwarfParser<'a, R: Reader<Offset = usize>> {
    pub dwarf: &'a Dwarf<R>,
    /// Index of unit ranges for cross-unit reference resolution
    unit_ranges: Vec<Range<usize>>,
}

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    /// Collect type dependencies starting from multiple root offsets.
    /// This batches dependency collection to avoid redundant work.
    pub fn collect_type_deps_from_roots(
        &self,
        unit: &UnitRef<R>,
        root_offsets: &[UnitOffset],
    ) -> Result<TypeDependencies> {
        let collector = DependencyCollector::new(self.dwarf, &self.unit_ranges);
        collector.collect_deps_from_roots(unit, root_offsets)
    }

    pub fn build(dwarf: &'a Dwarf<R>) -> Result<Self> {
        // Build index of unit ranges for cross-unit reference resolution
        let mut unit_ranges = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let start = match header.offset() {
                gimli::UnitSectionOffset::DebugInfoOffset(off) => off.0,
                gimli::UnitSectionOffset::DebugTypesOffset(off) => off.0,
            };
            let end = start + header.length_including_self();
            unit_ranges.push(start..end);
        }

        Ok(DwarfParser { dwarf, unit_ranges })
    }

    /// Pass 1: Find matching function offsets.
    /// Returns offsets along with the name and return type for each match.
    fn find_matching_subprograms(
        &self,
        unit: &UnitRef<R>,
        functions: &mut HashMap<String, bool>,
    ) -> Result<Vec<(UnitOffset, String, Option<UnitOffset>)>> {
        let mut matches = Vec::new();

        let mut entries = unit.entries();
        while let Some((_delta_depth, entry)) = entries.next_dfs()? {
            if functions.values().all(|&found| found) {
                break;
            }

            if entry.tag() != DW_TAG_subprogram {
                continue;
            }

            // Skip inline instances
            let is_inline = entry
                .attr(gimli::DW_AT_inline)?
                .and_then(|attr| attr.value().udata_value())
                .unwrap_or(0)
                != 0;

            // Skip declarations
            let is_declaration = entry
                .attr(gimli::DW_AT_declaration)?
                .and_then(|attr| attr.value().udata_value())
                .unwrap_or(0)
                != 0;

            if is_inline || is_declaration {
                continue;
            }

            if let Some(attr) = entry.attr(gimli::DW_AT_linkage_name)?
                && let Ok(name) = unit.dwarf.attr_string(unit, attr.value())
                && let Ok(name_str) = name.to_string_lossy()
                && let Some(found) = functions.get_mut(name_str.as_ref())
            {
                if *found {
                    continue;
                }

                *found = true;
                let return_type_offset = get_type_offset(unit, entry)?;
                matches.push((entry.offset(), name_str.to_string(), return_type_offset));
            }
        }

        Ok(matches)
    }

    /// Pass 2: Extract parameters for matched functions.
    fn extract_function_params(
        &self,
        unit: &UnitRef<R>,
        matches: Vec<(UnitOffset, String, Option<UnitOffset>)>,
        function_info: &mut Vec<FunctionInfo>,
        type_roots: &mut Vec<UnitOffset>,
    ) -> Result<()> {
        // Get the unit's header offset for converting UnitOffset to GlobalTypeId
        let header_offset = unit
            .header
            .offset()
            .as_debug_info_offset()
            .expect("unit should have debug_info offset");

        for (offset, name, return_type_offset) in matches {
            let unit_name = unit
                .name
                .as_ref()
                .and_then(|n| n.to_string_lossy().ok())
                .unwrap_or_default();
            println!("Found {name} in unit {unit_name}");

            // Collect return type as a root for dependency collection
            if let Some(ret_offset) = return_type_offset {
                type_roots.push(ret_offset);
            }

            let mut args = Vec::new();
            let mut tree = unit
                .entries_tree(Some(offset))
                .context("failed to get function entry tree")?;
            let root = tree
                .root()
                .context("failed to get function entry tree root")?;

            let mut children = root.children();
            while let Some(child) = children.next().context("failed to get function child")? {
                if child.entry().tag() == DW_TAG_formal_parameter {
                    let param_name = get_param_name(unit, child.entry())?;

                    if let Some(type_offset) = get_type_offset(unit, child.entry())? {
                        type_roots.push(type_offset);
                        // Convert UnitOffset to GlobalTypeId
                        let global_id = DebugInfoOffset(header_offset.0 + type_offset.0);
                        args.push((param_name, global_id));
                    }
                }
            }

            // Convert return type UnitOffset to GlobalTypeId
            let return_type_global =
                return_type_offset.map(|off| DebugInfoOffset(header_offset.0 + off.0));

            function_info.push(FunctionInfo {
                name,
                return_type_offset: return_type_global,
                args,
            });
        }

        Ok(())
    }

    /// Find types by their fully qualified names (e.g., "tokio::runtime::scheduler::Handle").
    /// Returns the collected type dependencies for all matching types.
    pub fn find_types_by_name(
        &self,
        type_names: &mut HashMap<String, bool>,
    ) -> Result<TypeDependencies> {
        let mut type_deps = TypeDependencies::new();

        if type_names.is_empty() {
            return Ok(type_deps);
        }

        let mut iter = self.dwarf.units();
        while let Some(header) = iter.next().context("failed to get next unit header")? {
            let unit = self.dwarf.unit(header).context("failed to read unit")?;
            let unit_ref = UnitRef::new(self.dwarf, &unit);

            // Find matching types in this unit
            let type_roots = self.find_matching_types(&unit_ref, type_names)?;

            // If we found types in this unit, collect their dependencies
            if !type_roots.is_empty() {
                let unit_deps = self.collect_type_deps_from_roots(&unit_ref, &type_roots)?;
                // Merge into all_type_deps
                type_deps.all_types.extend(unit_deps.all_types);
                type_deps.stubs.extend(unit_deps.stubs);
                type_deps.deps.extend(unit_deps.deps);
                type_deps.type_locations.extend(unit_deps.type_locations);
            }

            // Early exit if all types found
            if type_names.values().all(|&found| found) {
                break;
            }
        }

        Ok(type_deps)
    }

    /// Find types matching the given fully qualified names in a single compilation unit.
    fn find_matching_types(
        &self,
        unit: &UnitRef<R>,
        type_names: &mut HashMap<String, bool>,
    ) -> Result<Vec<UnitOffset>> {
        let mut matches = Vec::new();
        let collector = DependencyCollector::new(self.dwarf, &self.unit_ranges);

        let mut entries = unit.entries();
        while let Some((_delta_depth, entry)) = entries.next_dfs()? {
            // Early exit if all types found
            if type_names.values().all(|&found| found) {
                break;
            }

            // Only check type-defining tags
            match entry.tag() {
                gimli::DW_TAG_structure_type
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_enumeration_type
                | gimli::DW_TAG_typedef => {}
                _ => continue,
            }

            // Get the entry's name
            let Some(name_attr) = entry.attr(gimli::DW_AT_name)? else {
                continue;
            };
            let name = match name_attr.value() {
                AttributeValue::DebugStrRef(offset) => {
                    unit.string(offset)?.to_string()?.into_owned()
                }
                AttributeValue::String(s) => s.to_string()?.into_owned(),
                _ => continue,
            };

            if name.is_empty() {
                continue;
            }

            // Build fully qualified name using namespace path from DWARF hierarchy
            let qualified_name = collector.get_qualified_name(unit, entry.offset(), &name)?;

            // Check if this matches any requested type
            if let Some(found) = type_names.get_mut(&qualified_name) {
                if !*found {
                    *found = true;
                    let unit_name = unit
                        .name
                        .as_ref()
                        .and_then(|n| n.to_string_lossy().ok())
                        .unwrap_or_default();
                    println!("Found type {qualified_name} in unit {unit_name}");
                    matches.push(entry.offset());
                }
            }
        }

        Ok(matches)
    }

    /// Find functions by name and collect all type dependencies.
    pub fn find_functions_and_collect_types(
        &self,
        functions: &mut HashMap<String, bool>,
    ) -> Result<(Vec<FunctionInfo>, TypeDependencies)> {
        let mut function_info = Vec::new();
        let mut type_deps = TypeDependencies::new();

        let mut iter = self.dwarf.units();
        while let Some(header) = iter.next().context("failed to get next unit header")? {
            let unit = self.dwarf.unit(header).context("failed to read unit")?;
            let unit_ref = UnitRef::new(self.dwarf, &unit);

            // Find function offsets in DWARF.
            let matches = self.find_matching_subprograms(&unit_ref, functions)?;

            // Extract parameters for matched functions.
            let mut type_roots = Vec::new();
            self.extract_function_params(&unit_ref, matches, &mut function_info, &mut type_roots)?;

            // If we found functions in this unit, collect their type dependencies
            if !type_roots.is_empty() {
                let unit_deps = self.collect_type_deps_from_roots(&unit_ref, &type_roots)?;
                // Merge into all_type_deps
                type_deps.all_types.extend(unit_deps.all_types);
                type_deps.stubs.extend(unit_deps.stubs);
                type_deps.deps.extend(unit_deps.deps);
                type_deps.type_locations.extend(unit_deps.type_locations);
            }

            if functions.values().all(|&found| found) {
                break;
            }
        }

        Ok((function_info, type_deps))
    }

    /// Build types from pre-collected dependencies and return parsed function info.
    /// This is the efficient path that uses dependencies collected during function finding.
    pub fn build_fn_info_from_deps(
        &mut self,
        funcs: &[FunctionInfo],
        type_deps: &TypeDependencies,
        writer: &mut CtfWriter,
    ) -> Result<HashMap<String, CtfFunctionInfo>> {
        // Build all types from the collected dependencies
        build_types_from_deps(type_deps, writer)?;

        // Now look up the type IDs for each function
        let mut parsed_funcs = HashMap::new();

        for func in funcs {
            println!("Function: {}", func.name);
            println!("  Arguments: {:?}", func.args);
            println!("  Return Type: {:?}", func.return_type_offset);

            let return_type = if let Some(ret_offset) = func.return_type_offset {
                writer
                    .type_map
                    .get(&ret_offset)
                    .copied()
                    .context("return type not found after building types")?
            } else {
                0 // void
            };

            let mut args = Vec::new();
            for (arg_name, arg_offset) in &func.args {
                let arg_type_id = writer
                    .type_map
                    .get(arg_offset)
                    .copied()
                    .context("arg type not found after building types")?;
                println!("  Arg '{}': type ID {:?}", arg_name, arg_type_id);
                args.push(arg_type_id);
            }

            parsed_funcs.insert(func.name.to_string(), CtfFunctionInfo { return_type, args });
        }

        Ok(parsed_funcs)
    }
}

/// Information about a function collected during DWARF scanning.
#[derive(Clone, Debug)]
pub struct FunctionInfo {
    pub name: String,
    pub return_type_offset: Option<GlobalTypeOffset>,
    pub args: Vec<(String, GlobalTypeOffset)>,
}

/// Parsed function info with CTF type IDs.
#[derive(Clone, Debug)]
pub struct CtfFunctionInfo {
    pub return_type: u16,
    pub args: Vec<u16>,
}

/// Get the type offset from an entry's DW_AT_type attribute.
fn get_type_offset<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<Option<UnitOffset>> {
    if let Some(type_attr) = entry
        .attr(gimli::DW_AT_type)
        .context("failed to get DW_AT_type offset")?
    {
        match type_attr.value() {
            AttributeValue::UnitRef(offset) => return Ok(Some(offset)),
            AttributeValue::DebugInfoRef(debug_info_offset) => {
                return Ok(debug_info_offset.to_unit_offset(&unit.header));
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Get the name of a parameter from its entry.
fn get_param_name<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    entry: &DebuggingInformationEntry<R>,
) -> Result<String> {
    if let Some(attr) = entry
        .attr(gimli::DW_AT_name)
        .context("failed to get DW_AT_name offset")?
        && let Ok(name) = unit.attr_string(attr.value())
    {
        return Ok(name.to_string_lossy()?.into_owned());
    }
    Ok(String::from("<unnamed>"))
}

/// Represents a type reference that may be in the same unit or a different unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRef {
    /// Reference within the same compilation unit (will be converted to GlobalTypeId).
    SameUnit(UnitOffset),
    /// Reference to a different compilation unit (already a GlobalTypeId).
    CrossUnit(DebugInfoOffset<usize>),
}

impl TypeRef {
    /// Convert to a GlobalTypeId given the unit's header offset.
    pub fn to_global(self, header_offset: DebugInfoOffset<usize>) -> GlobalTypeOffset {
        match self {
            TypeRef::SameUnit(unit_offset) => {
                // Convert unit-relative offset to absolute offset
                DebugInfoOffset(header_offset.0 + unit_offset.0)
            }
            TypeRef::CrossUnit(abs_offset) => abs_offset,
        }
    }
}

/// Stub information for a struct/union member collected during Phase 1.
#[derive(Debug, Clone)]
pub struct MemberStub {
    pub name: String,
    /// Type reference (stored as TypeRef during extraction, converted to GlobalTypeId for lookup)
    pub type_ref: Option<TypeRef>,
    pub offset_bytes: u64,
}

/// Stub information for an enum variant collected during Phase 1.
#[derive(Debug, Clone)]
pub struct EnumeratorStub {
    pub name: String,
    pub value: i32,
}

/// Stub information for a function parameter collected during Phase 1.
#[derive(Debug, Clone)]
pub struct ParamStub {
    pub type_ref: Option<TypeRef>,
}

/// Stub information for a single variant (enum case with payload) collected during Phase 1.
#[derive(Debug, Clone)]
pub struct VariantStub {
    /// Variant name (e.g., "Some", "Ok", "Err")
    pub name: String,
    /// Members of this variant's payload
    pub members: Vec<MemberStub>,
    /// Discriminant value from DW_AT_discr_value (if present)
    pub discriminant_value: Option<i64>,
}

/// Stub information for a DW_TAG_variant_part (Rust enum representation) collected during Phase 1.
#[derive(Debug, Clone)]
pub struct VariantPartStub {
    /// The discriminant member (tag field)
    pub discriminant: Option<MemberStub>,
    /// All variants with payloads
    pub variants: Vec<VariantStub>,
}

/// Cached metadata about a type entry, avoiding re-reading DWARF in Phase 2.
#[derive(Debug, Clone)]
pub enum TypeStub {
    /// DW_TAG_base_type - no dependencies
    Base {
        name: String,
        byte_size: u32,
        encoding: gimli::DwAte,
    },
    /// DW_TAG_pointer_type, DW_TAG_reference_type, DW_TAG_rvalue_reference_type
    Pointer {
        name: String,
        target: Option<TypeRef>,
    },
    /// DW_TAG_typedef
    Typedef {
        name: String,
        target: Option<TypeRef>,
    },
    /// DW_TAG_const_type
    Const {
        name: String,
        target: Option<TypeRef>,
    },
    /// DW_TAG_volatile_type
    Volatile {
        name: String,
        target: Option<TypeRef>,
    },
    /// DW_TAG_restrict_type
    Restrict {
        name: String,
        target: Option<TypeRef>,
    },
    /// DW_TAG_array_type
    Array {
        name: String,
        element_type: Option<TypeRef>,
        index_type: Option<TypeRef>,
        count: Option<u32>,
    },
    /// DW_TAG_subroutine_type
    Function {
        name: String,
        return_type: Option<TypeRef>,
        params: Vec<ParamStub>,
        is_varargs: bool,
    },
    /// DW_TAG_structure_type
    Struct {
        name: String,
        byte_size: u32,
        members: Vec<MemberStub>,
        /// Rust enum variant parts (DW_TAG_variant_part children).
        variant_parts: Vec<VariantPartStub>,
    },
    /// DW_TAG_union_type
    Union {
        name: String,
        byte_size: u32,
        members: Vec<MemberStub>,
    },
    /// DW_TAG_enumeration_type
    Enum {
        name: String,
        byte_size: u32,
        enumerators: Vec<EnumeratorStub>,
    },
    /// Unknown/unhandled tag - will become void
    Unknown { _tag: DwTag },
}

/// Collected dependency information for all types reachable from a root.
#[derive(Debug)]
pub struct TypeDependencies {
    /// Global type ID mapping to types it depends on.
    pub deps: HashMap<GlobalTypeOffset, Vec<GlobalTypeOffset>>,
    /// Cached stub data for each type.
    pub stubs: HashMap<GlobalTypeOffset, TypeStub>,
    /// Set of all discovered global type IDs.
    pub all_types: HashSet<GlobalTypeOffset>,
    /// Maps global type ID to (unit header offset, unit-relative offset) for loading.
    pub type_locations: HashMap<GlobalTypeOffset, (DebugInfoOffset<usize>, UnitOffset)>,
}

impl TypeDependencies {
    pub fn new() -> Self {
        Self {
            deps: HashMap::new(),
            stubs: HashMap::new(),
            all_types: HashSet::new(),
            type_locations: HashMap::new(),
        }
    }
}

impl Default for TypeDependencies {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache mapping DIE offset to its namespace path (list of namespace names).
type NamespaceMap = HashMap<UnitOffset, Vec<String>>;

/// Dependency collector that walks DWARF without constructing CTF types.
pub struct DependencyCollector<'a, R: Reader<Offset = usize>> {
    dwarf: &'a gimli::Dwarf<R>,
    /// Index of unit ranges for cross-unit reference resolution
    unit_ranges: &'a [Range<usize>],
    /// Cache of namespace paths per unit (unit header offset -> namespace map).
    /// Built lazily on first access per unit, then reused for O(1) lookups.
    namespace_cache: RefCell<HashMap<DebugInfoOffset<usize>, NamespaceMap>>,
}

impl<'a, R: Reader<Offset = usize>> DependencyCollector<'a, R> {
    pub fn new(dwarf: &'a gimli::Dwarf<R>, unit_ranges: &'a [Range<usize>]) -> Self {
        Self {
            dwarf,
            unit_ranges,
            namespace_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Collect all type dependencies starting from multiple root offsets.
    /// Returns the complete dependency graph, including cross-unit references.
    pub fn collect_deps_from_roots(
        &self,
        unit: &UnitRef<R>,
        root_offsets: &[UnitOffset],
    ) -> Result<TypeDependencies> {
        let mut result = TypeDependencies::new();

        let mut work_queue: VecDeque<(GlobalTypeOffset, DebugInfoOffset<usize>, UnitOffset)> =
            VecDeque::new();

        let unit_header_offset = unit.header.offset().as_debug_info_offset().unwrap();
        for &root_offset in root_offsets {
            let root_global = TypeRef::SameUnit(root_offset).to_global(unit_header_offset);
            work_queue.push_back((root_global, unit_header_offset, root_offset));
        }

        // Cache loaded units to avoid reloading.
        let mut unit_cache: HashMap<DebugInfoOffset<usize>, gimli::Unit<R>> = HashMap::new();

        while let Some((global_id, header_offset, unit_offset)) = work_queue.pop_front() {
            // Skip if already processed
            if result.all_types.contains(&global_id) {
                continue;
            }
            result.all_types.insert(global_id);
            result
                .type_locations
                .insert(global_id, (header_offset, unit_offset));

            // Get or load the unit for this type
            let is_root_unit = header_offset == unit_header_offset;
            if !is_root_unit && !unit_cache.contains_key(&header_offset) {
                let header = self.dwarf.debug_info.header_from_offset(header_offset)?;
                let loaded_unit = self.dwarf.unit(header)?;
                unit_cache.insert(header_offset, loaded_unit);
            }

            // Read the DWARF entry
            let (stub, type_refs) = if is_root_unit {
                self.extract_type_from_unit(unit, unit_offset)?
            } else {
                let cached_unit = unit_cache.get(&header_offset).unwrap();
                let unit_ref = UnitRef::new(self.dwarf, cached_unit);
                self.extract_type_from_unit(&unit_ref, unit_offset)?
            };

            // Convert TypeRefs to GlobalTypeIds and queue dependencies
            let mut global_deps = Vec::new();
            for type_ref in type_refs {
                let (dep_global, dep_header, dep_unit_offset) = match type_ref {
                    TypeRef::SameUnit(offset) => {
                        // Convert to global using the current type's header offset
                        let global = TypeRef::SameUnit(offset).to_global(header_offset);
                        (global, header_offset, offset)
                    }
                    TypeRef::CrossUnit(abs_offset) => {
                        // Find which unit contains this offset
                        if let Some((target_header, target_unit_offset)) =
                            self.resolve_cross_unit_offset(abs_offset)?
                        {
                            (abs_offset, target_header, target_unit_offset)
                        } else {
                            // Could not resolve - skip this dependency
                            continue;
                        }
                    }
                };

                global_deps.push(dep_global);

                if !result.all_types.contains(&dep_global) {
                    work_queue.push_back((dep_global, dep_header, dep_unit_offset));
                }
            }

            result.stubs.insert(global_id, stub);
            result.deps.insert(global_id, global_deps);
        }

        Ok(result)
    }

    /// Extract type info from a specific unit.
    fn extract_type_from_unit(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let Ok(mut entries) = unit.entries_at_offset(offset) else {
            return Ok((TypeStub::Unknown { _tag: DwTag(0) }, vec![]));
        };

        let Some((_, entry)) = entries.next_dfs()? else {
            return Ok((TypeStub::Unknown { _tag: DwTag(0) }, vec![]));
        };

        self.extract_type_info(unit, offset, entry)
    }

    /// Resolve a cross-unit reference to (unit_header_offset, unit_offset).
    fn resolve_cross_unit_offset(
        &self,
        abs_offset: DebugInfoOffset<usize>,
    ) -> Result<Option<(DebugInfoOffset<usize>, UnitOffset)>> {
        let target = abs_offset.0;

        // Find which unit range contains this offset
        for range in self.unit_ranges {
            if range.contains(&target) {
                let unit_header_offset = DebugInfoOffset(range.start);
                // Load the unit header to get the header size
                let header = self
                    .dwarf
                    .debug_info
                    .header_from_offset(unit_header_offset)?;
                // Convert absolute offset to unit-relative offset
                if let Some(unit_offset) = abs_offset.to_unit_offset(&header) {
                    return Ok(Some((unit_header_offset, unit_offset)));
                }
            }
        }

        Ok(None)
    }

    /// Extract stub information and dependencies from a DWARF entry.
    fn extract_type_info(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        match entry.tag() {
            gimli::DW_TAG_base_type => self.extract_base_type(unit, entry),
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type => self.extract_pointer_type(unit, entry),
            gimli::DW_TAG_typedef => self.extract_typedef(unit, offset, entry),
            gimli::DW_TAG_const_type => self.extract_const_type(unit, entry),
            gimli::DW_TAG_volatile_type => self.extract_volatile_type(unit, entry),
            gimli::DW_TAG_restrict_type => self.extract_restrict_type(unit, entry),
            gimli::DW_TAG_array_type => self.extract_array_type(unit, offset, entry),
            gimli::DW_TAG_subroutine_type => self.extract_function_type(unit, offset, entry),
            gimli::DW_TAG_structure_type => self.extract_struct_type(unit, offset, entry),
            gimli::DW_TAG_union_type => self.extract_union_type(unit, offset, entry),
            gimli::DW_TAG_enumeration_type => self.extract_enum_type(unit, offset, entry),
            other => Ok((TypeStub::Unknown { _tag: other }, vec![])),
        }
    }

    fn extract_base_type(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut byte_size = 0u32;
        let mut encoding = gimli::DW_ATE_signed; // default

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    byte_size = self.get_udata(&attr).unwrap_or(0) as u32;
                }
                gimli::DW_AT_encoding => {
                    if let AttributeValue::Encoding(enc) = attr.value() {
                        encoding = enc;
                    }
                }
                _ => {}
            }
        }

        Ok((
            TypeStub::Base {
                name,
                byte_size,
                encoding,
            },
            vec![], // Base types have no dependencies
        ))
    }

    fn extract_pointer_type(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut target = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        let deps = target.iter().copied().collect();
        Ok((TypeStub::Pointer { name, target }, deps))
    }

    fn extract_typedef(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut target = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let name = self.get_qualified_name(unit, offset, &name)?;

        let deps = target.iter().copied().collect();
        Ok((TypeStub::Typedef { name, target }, deps))
    }

    fn extract_const_type(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut target = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        let deps = target.iter().copied().collect();
        Ok((TypeStub::Const { name, target }, deps))
    }

    fn extract_volatile_type(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut target = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        let deps = target.iter().copied().collect();
        Ok((TypeStub::Volatile { name, target }, deps))
    }

    fn extract_restrict_type(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut target = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        let deps = target.iter().copied().collect();
        Ok((TypeStub::Restrict { name, target }, deps))
    }

    fn extract_array_type(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut element_type = None;
        let mut index_type = None;
        let mut count = None;

        // Parse array attributes
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    element_type = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        // Parse subrange children to get index type and count
        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_subrange_type {
                let mut child_attrs = child.entry().attrs();
                while let Some(attr) = child_attrs.next()? {
                    match attr.name() {
                        gimli::DW_AT_type => {
                            index_type = self.get_type_ref(unit, &attr);
                        }
                        gimli::DW_AT_count => {
                            count = self.get_udata(&attr).map(|v| v as u32);
                        }
                        _ => {}
                    }
                }
            }
        }

        let mut deps = Vec::new();
        if let Some(elem) = element_type {
            deps.push(elem);
        }
        if let Some(idx) = index_type {
            deps.push(idx);
        }

        Ok((
            TypeStub::Array {
                name,
                element_type,
                index_type,
                count,
            },
            deps,
        ))
    }

    fn extract_function_type(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut return_type = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    return_type = self.get_type_ref(unit, &attr);
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let name = self.get_qualified_name(unit, offset, &name)?;

        // Parse parameter children
        let mut params = Vec::new();
        let mut is_varargs = false;

        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            match child.entry().tag() {
                gimli::DW_TAG_formal_parameter => {
                    let mut type_ref = None;
                    let mut child_attrs = child.entry().attrs();
                    while let Some(attr) = child_attrs.next()? {
                        if attr.name() == gimli::DW_AT_type {
                            type_ref = self.get_type_ref(unit, &attr);
                        }
                    }
                    params.push(ParamStub { type_ref });
                }
                gimli::DW_TAG_unspecified_parameters => {
                    is_varargs = true;
                }
                _ => {}
            }
        }

        let mut deps = Vec::new();
        if let Some(ret) = return_type {
            deps.push(ret);
        }
        for param in &params {
            if let Some(ptype) = param.type_ref {
                deps.push(ptype);
            }
        }

        Ok((
            TypeStub::Function {
                name,
                return_type,
                params,
                is_varargs,
            },
            deps,
        ))
    }

    fn extract_struct_type(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    byte_size = self.get_udata(&attr).unwrap_or(0) as u32;
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix (e.g., "tokio::runtime::Handle")
        let name = self.get_qualified_name(unit, offset, &name)?;

        let mut members = Vec::new();
        let mut variant_parts = Vec::new();
        let mut deps = Vec::new();

        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            match child.entry().tag() {
                gimli::DW_TAG_member => {
                    let member = self.extract_member_stub(unit, child.entry())?;
                    if let Some(type_ref) = member.type_ref {
                        deps.push(type_ref);
                    }
                    members.push(member);
                }
                gimli::DW_TAG_variant_part => {
                    // Extract full variant part stub and collect dependencies
                    let variant_part = self.extract_variant_part_stub(unit, child, &mut deps)?;
                    variant_parts.push(variant_part);
                }
                _ => {}
            }
        }

        Ok((
            TypeStub::Struct {
                name,
                byte_size,
                members,
                variant_parts,
            },
            deps,
        ))
    }

    fn extract_union_type(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    byte_size = self.get_udata(&attr).unwrap_or(0) as u32;
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let name = self.get_qualified_name(unit, offset, &name)?;

        let mut members = Vec::new();
        let mut deps = Vec::new();

        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_member {
                let member = self.extract_member_stub(unit, child.entry())?;
                if let Some(type_ref) = member.type_ref {
                    deps.push(type_ref);
                }
                members.push(member);
            }
        }

        Ok((
            TypeStub::Union {
                name,
                byte_size,
                members,
            },
            deps,
        ))
    }

    fn extract_enum_type(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(TypeStub, Vec<TypeRef>)> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    byte_size = self.get_udata(&attr).unwrap_or(0) as u32;
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let name = self.get_qualified_name(unit, offset, &name)?;

        let mut enumerators = Vec::new();

        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_enumerator {
                let mut enum_name = String::new();
                let mut enum_value: i32 = 0;

                let mut child_attrs = child.entry().attrs();
                while let Some(attr) = child_attrs.next()? {
                    match attr.name() {
                        gimli::DW_AT_name => {
                            enum_name = self.get_string(unit, &attr)?;
                        }
                        gimli::DW_AT_const_value => {
                            enum_value = self.get_sdata(&attr).unwrap_or(0) as i32;
                        }
                        _ => {}
                    }
                }

                enumerators.push(EnumeratorStub {
                    name: enum_name,
                    value: enum_value,
                });
            }
        }

        // Enums have no type dependencies
        Ok((
            TypeStub::Enum {
                name,
                byte_size,
                enumerators,
            },
            vec![],
        ))
    }

    /// Extract member stub from a DW_TAG_member entry.
    fn extract_member_stub(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MemberStub> {
        let mut name = String::new();
        let mut type_ref = None;
        let mut offset_bytes = 0u64;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    type_ref = self.get_type_ref(unit, &attr);
                }
                gimli::DW_AT_data_member_location => {
                    offset_bytes = self.get_udata(&attr).unwrap_or(0);
                }
                _ => {}
            }
        }

        Ok(MemberStub {
            name,
            type_ref,
            offset_bytes,
        })
    }

    /// Extract a VariantPartStub from a DW_TAG_variant_part and collect dependencies.
    fn extract_variant_part_stub(
        &self,
        unit: &UnitRef<R>,
        variant_part_node: gimli::EntriesTreeNode<R>,
        deps: &mut Vec<TypeRef>,
    ) -> Result<VariantPartStub> {
        let entry = variant_part_node.entry();

        // Check for explicit discriminant (DW_AT_discr points to a DW_TAG_member child)
        let mut discr_offset = None;
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_discr
                && let AttributeValue::UnitRef(off) = attr.value()
            {
                discr_offset = Some(off);
            }
        }

        let mut discriminant: Option<MemberStub> = None;
        let mut variants: Vec<VariantStub> = Vec::new();

        let mut children = variant_part_node.children();
        while let Some(child) = children.next()? {
            match child.entry().tag() {
                gimli::DW_TAG_member => {
                    // Only treat this as the discriminant if DW_AT_discr pointed to it.
                    // For niche-optimized enums, DW_AT_discr is absent and there is no
                    // separate discriminant member - the discriminant is stored in the
                    // niche of one of the variant's fields.
                    let is_discr = discr_offset.is_some_and(|off| child.entry().offset() == off);
                    if is_discr {
                        let mut member = self.extract_member_stub(unit, child.entry())?;
                        if member.name.is_empty() {
                            member.name = "__discr".to_string();
                        }
                        if let Some(type_ref) = member.type_ref {
                            deps.push(type_ref);
                        }
                        discriminant = Some(member);
                    }
                }
                gimli::DW_TAG_variant => {
                    // Extract variant stub and collect its dependencies
                    if let Some(variant) = self.extract_variant_stub(unit, child, deps)? {
                        variants.push(variant);
                    }
                }
                _ => {}
            }
        }

        Ok(VariantPartStub {
            discriminant,
            variants,
        })
    }

    /// Extract a VariantStub from a DW_TAG_variant.
    /// Returns None for unit variants (no payload).
    fn extract_variant_stub(
        &self,
        unit: &UnitRef<R>,
        variant_node: gimli::EntriesTreeNode<R>,
        deps: &mut Vec<TypeRef>,
    ) -> Result<Option<VariantStub>> {
        let entry = variant_node.entry();

        // Get variant name from DW_AT_name and discriminant value from DW_AT_discr_value
        let mut variant_name = String::new();
        let mut discriminant_value = None;
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_name {
                variant_name = self.get_string(unit, &attr)?;
            } else if attr.name() == gimli::DW_AT_discr_value {
                discriminant_value = match attr.value() {
                    gimli::AttributeValue::Sdata(v) => Some(v),
                    gimli::AttributeValue::Udata(v) => Some(v as i64),
                    gimli::AttributeValue::Data1(v) => Some(v as i64),
                    gimli::AttributeValue::Data2(v) => Some(v as i64),
                    gimli::AttributeValue::Data4(v) => Some(v as i64),
                    gimli::AttributeValue::Data8(v) => Some(v as i64),
                    _ => None,
                };
            }
        }

        // Collect members of this variant
        let mut members = Vec::new();
        let mut children = variant_node.children();

        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_member {
                let member = self.extract_member_stub(unit, child.entry())?;

                // In Rust's DWARF, the variant name is typically on the first
                // DW_TAG_member child, not on the DW_TAG_variant itself.
                if variant_name.is_empty() && !member.name.is_empty() {
                    variant_name = member.name.clone();
                }

                if let Some(type_ref) = member.type_ref {
                    deps.push(type_ref);
                }
                members.push(member);
            }
        }

        // Skip unit variants (no payload)
        if members.is_empty() {
            return Ok(None);
        }

        Ok(Some(VariantStub {
            name: variant_name,
            members,
            discriminant_value,
        }))
    }

    // --- Helper methods ---

    /// Build namespace paths for all entries in a unit in a single DFS pass.
    /// Returns a map from DIE offset to namespace path (list of ancestor namespace names).
    fn build_namespace_map(&self, unit: &UnitRef<R>) -> Result<NamespaceMap> {
        let mut map = HashMap::new();
        let mut cursor = unit.entries();

        // Stack tracking namespace contribution at each depth level.
        // Some(name) for namespace/module entries, None for others.
        let mut depth_stack: Vec<Option<String>> = Vec::new();

        while let Some((depth_delta, entry)) = cursor.next_dfs()? {
            // Adjust stack based on depth change (pop when moving up/sideways)
            if depth_delta <= 0 {
                for _ in 0..(-depth_delta + 1) {
                    depth_stack.pop();
                }
            }

            // Current namespace path is all Some values from ancestors
            let namespace_path: Vec<String> =
                depth_stack.iter().filter_map(|s| s.clone()).collect();

            // Record namespace path for this entry
            map.insert(entry.offset(), namespace_path);

            // Determine if this entry contributes a namespace name.
            // Include structure/union/class types so that nested types (like Rust enum
            // variant structs) get properly qualified names, e.g. Option<u32>::Some
            // instead of just Some.
            let name = match entry.tag() {
                gimli::DW_TAG_namespace
                | gimli::DW_TAG_module
                | gimli::DW_TAG_structure_type
                | gimli::DW_TAG_union_type
                | gimli::DW_TAG_class_type => {
                    if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
                        Some(self.get_string(unit, &attr)?)
                    } else {
                        None
                    }
                }
                _ => None,
            };

            // Push this entry's contribution (None for non-namespace entries)
            depth_stack.push(name);
        }

        Ok(map)
    }

    /// Get the namespace path for a DIE, using cached data.
    /// Returns the full path components like ["tokio", "runtime", "scheduler"].
    fn get_namespace_path(&self, unit: &UnitRef<R>, offset: UnitOffset) -> Result<Vec<String>> {
        let unit_header_offset = unit.header.offset().as_debug_info_offset().unwrap();

        // Check if we already have a cached map for this unit
        {
            let cache = self.namespace_cache.borrow();
            if let Some(unit_map) = cache.get(&unit_header_offset) {
                return Ok(unit_map.get(&offset).cloned().unwrap_or_default());
            }
        }

        // Build the namespace map for this unit (single DFS pass)
        let unit_map = self.build_namespace_map(unit)?;
        let result = unit_map.get(&offset).cloned().unwrap_or_default();

        // Cache it for future lookups in this unit
        self.namespace_cache
            .borrow_mut()
            .insert(unit_header_offset, unit_map);

        Ok(result)
    }

    /// Get a fully qualified type name by prepending namespace path.
    pub fn get_qualified_name(
        &self,
        unit: &UnitRef<R>,
        offset: UnitOffset,
        name: &str,
    ) -> Result<String> {
        if name.is_empty() {
            return Ok(String::new());
        }

        let namespace = self.get_namespace_path(unit, offset)?;
        if namespace.is_empty() {
            Ok(name.to_string())
        } else {
            Ok(format!("{}::{}", namespace.join("::"), name))
        }
    }

    /// Get a type reference from a DW_AT_type attribute.
    fn get_type_ref(&self, unit: &UnitRef<R>, attr: &gimli::Attribute<R>) -> Option<TypeRef> {
        match attr.value() {
            AttributeValue::UnitRef(offset) => Some(TypeRef::SameUnit(offset)),
            AttributeValue::DebugInfoRef(debug_info_offset) => {
                // Check if this is actually in the same unit
                if let Some(unit_offset) = debug_info_offset.to_unit_offset(&unit.header) {
                    Some(TypeRef::SameUnit(unit_offset))
                } else {
                    Some(TypeRef::CrossUnit(debug_info_offset))
                }
            }
            _ => None,
        }
    }

    /// Get a string from an attribute.
    fn get_string(&self, unit: &UnitRef<R>, attr: &gimli::Attribute<R>) -> Result<String> {
        match attr.value() {
            AttributeValue::DebugStrRef(offset) => {
                let s = unit.string(offset)?;
                Ok(s.to_string()?.into_owned())
            }
            AttributeValue::String(s) => Ok(s.to_string()?.into_owned()),
            _ => Ok(String::new()),
        }
    }

    /// Get unsigned data from an attribute.
    fn get_udata(&self, attr: &gimli::Attribute<R>) -> Option<u64> {
        match attr.value() {
            AttributeValue::Udata(v) => Some(v),
            AttributeValue::Data1(v) => Some(v as u64),
            AttributeValue::Data2(v) => Some(v as u64),
            AttributeValue::Data4(v) => Some(v as u64),
            AttributeValue::Data8(v) => Some(v),
            AttributeValue::Sdata(v) => Some(v as u64),
            _ => None,
        }
    }

    /// Get signed data from an attribute.
    fn get_sdata(&self, attr: &gimli::Attribute<R>) -> Option<i64> {
        match attr.value() {
            AttributeValue::Sdata(v) => Some(v),
            AttributeValue::Udata(v) => Some(v as i64),
            AttributeValue::Data1(v) => Some(v as i64),
            AttributeValue::Data2(v) => Some(v as i64),
            AttributeValue::Data4(v) => Some(v as i64),
            AttributeValue::Data8(v) => Some(v as i64),
            _ => None,
        }
    }
}

// ============================================================================
// Phase 2: Topological Processing
// ============================================================================

/// Result of topological sort with SCC detection.
#[derive(Debug)]
pub struct TopologicalOrder {
    /// Types in processing order. Each entry is either:
    /// - A single type (no cycle)
    /// - Multiple types (an SCC - strongly connected component / cycle)
    pub sccs: Vec<Vec<GlobalTypeOffset>>,
}

/// Compute topological order with SCC detection using petgraph's Tarjan algorithm.
/// Returns SCCs in reverse topological order (dependencies before dependents).
pub fn topological_sort(deps: &TypeDependencies) -> TopologicalOrder {
    let mut graph: DiGraphMap<GlobalTypeOffset, ()> = DiGraphMap::new();

    // Add all nodes (needed for types with no dependencies)
    for &global_id in &deps.all_types {
        graph.add_node(global_id);
    }

    // Add all edges
    for (&from_id, to_ids) in &deps.deps {
        for &to_id in to_ids {
            graph.add_edge(from_id, to_id, ());
        }
    }

    // Run Tarjan's SCC algorithm
    let sccs = petgraph::algo::tarjan_scc(&graph);

    TopologicalOrder { sccs }
}

// ============================================================================
// Phase 2: Type Builder
// ============================================================================

use crate::ctf::types::{
    CTF_INT_BOOL, CTF_INT_CHAR, CTF_INT_SIGNED, CtfEnumerator, CtfMember, CtfType, MaybeOffset,
    ctf_int_data,
};

/// Build CTF types from collected dependencies in topological order.
/// This is the main entry point for Phase 2.
pub fn build_types_from_deps(deps: &TypeDependencies, writer: &mut CtfWriter) -> Result<()> {
    let order = topological_sort(deps);

    // Map from GlobalTypeId to CTF type ID
    let mut global_type_map: HashMap<GlobalTypeOffset, u16> = HashMap::new();

    for scc in &order.sccs {
        build_scc_types(scc, deps, writer, &mut global_type_map)?;
    }

    // Populate writer.type_map directly with GlobalTypeIds
    for (global_id, &type_id) in &global_type_map {
        writer.type_map.insert(*global_id, type_id);
    }

    Ok(())
}

/// Build types for a single SCC (strongly connected component).
/// For single-type SCCs, this is straightforward.
/// For multi-type SCCs (cycles), we use MaybeOffset::Pending for back-references.
fn build_scc_types(
    scc: &[GlobalTypeOffset],
    deps: &TypeDependencies,
    writer: &mut CtfWriter,
    global_type_map: &mut HashMap<GlobalTypeOffset, u16>,
) -> Result<()> {
    for &global_id in scc {
        let Some(stub) = deps.stubs.get(&global_id) else {
            continue;
        };

        let ctf_type = stub_to_ctf_type(stub, global_id, deps, writer, global_type_map)?;

        let type_id = writer.add_type(global_id, ctf_type);
        global_type_map.insert(global_id, type_id);
    }

    Ok(())
}

/// Convert a TypeStub to a CtfType.
fn stub_to_ctf_type(
    stub: &TypeStub,
    global_id: GlobalTypeOffset,
    deps: &TypeDependencies,
    writer: &mut CtfWriter,
    global_type_map: &HashMap<GlobalTypeOffset, u16>,
) -> Result<CtfType> {
    // Get the header offset for this type to convert TypeRefs to GlobalTypeIds
    let header_offset = deps
        .type_locations
        .get(&global_id)
        .map(|&(header, _)| header)
        .unwrap_or(DebugInfoOffset(0));

    match stub {
        TypeStub::Base {
            name,
            byte_size,
            encoding,
        } => Ok(build_base_type(name, *byte_size, *encoding)),

        TypeStub::Pointer { name, target } => {
            let target_type = resolve_type_ref(target.as_ref(), header_offset, global_type_map);
            Ok(CtfType::Pointer {
                name: name.clone(),
                target_type,
            })
        }

        TypeStub::Typedef { name, target } => {
            let target_type = resolve_type_ref(target.as_ref(), header_offset, global_type_map);
            Ok(CtfType::Typedef {
                name: name.clone(),
                target_type,
            })
        }

        TypeStub::Const { name, target } => {
            let target_type = resolve_type_ref(target.as_ref(), header_offset, global_type_map);
            Ok(CtfType::Const {
                name: name.clone(),
                target_type,
            })
        }

        TypeStub::Volatile { name, target } => {
            let target_type = resolve_type_ref(target.as_ref(), header_offset, global_type_map);
            Ok(CtfType::Volatile {
                name: name.clone(),
                target_type,
            })
        }

        TypeStub::Restrict { name, target } => {
            let target_type = resolve_type_ref(target.as_ref(), header_offset, global_type_map);
            Ok(CtfType::Restrict {
                name: name.clone(),
                target_type,
            })
        }

        TypeStub::Array {
            name,
            element_type,
            index_type,
            count,
        } => {
            let element = resolve_type_ref(element_type.as_ref(), header_offset, global_type_map);
            let index = resolve_type_ref(index_type.as_ref(), header_offset, global_type_map);
            Ok(CtfType::Array {
                name: name.clone(),
                element_type: element,
                index_type: index,
                nelems: count.unwrap_or(0),
            })
        }

        TypeStub::Function {
            name,
            return_type,
            params,
            is_varargs,
        } => {
            let ret = resolve_type_ref(return_type.as_ref(), header_offset, global_type_map);
            let args: Vec<MaybeOffset> = params
                .iter()
                .map(|p| resolve_type_ref(p.type_ref.as_ref(), header_offset, global_type_map))
                .collect();
            // DW_TAG_subroutine_type entries typically don't have names in DWARF,
            // but illumos ctfdump expects CTF_K_FUNCTION types to have names.
            // Use a synthetic name for anonymous function types.
            let fn_name = if name.is_empty() {
                "<anon_fn>".to_string()
            } else {
                name.clone()
            };
            Ok(CtfType::Function {
                name: fn_name,
                return_type: ret,
                args,
                is_varargs: *is_varargs,
            })
        }

        TypeStub::Struct {
            name,
            byte_size,
            members,
            variant_parts,
        } => {
            // Convert regular members
            let mut ctf_members: Vec<CtfMember> = members
                .iter()
                .map(|m| CtfMember {
                    name: m.name.clone(),
                    type_id: resolve_type_ref(m.type_ref.as_ref(), header_offset, global_type_map),
                    offset_bits: m.offset_bytes * 8,
                })
                .collect();

            // Process variant parts (Rust enum representations)
            for variant_part in variant_parts {
                build_variant_part_members(
                    variant_part,
                    &mut ctf_members,
                    name,
                    *byte_size,
                    header_offset,
                    writer,
                    global_type_map,
                );
            }

            // Sort members by offset for consistent CTF output
            ctf_members.sort_by_key(|m| m.offset_bits);

            Ok(CtfType::Struct {
                name: name.clone(),
                size: *byte_size,
                members: ctf_members,
            })
        }

        TypeStub::Union {
            name,
            byte_size,
            members,
        } => {
            let mut ctf_members: Vec<CtfMember> = members
                .iter()
                .map(|m| CtfMember {
                    name: m.name.clone(),
                    type_id: resolve_type_ref(m.type_ref.as_ref(), header_offset, global_type_map),
                    offset_bits: m.offset_bytes * 8,
                })
                .collect();

            // Sort members by offset for consistent CTF output
            ctf_members.sort_by_key(|m| m.offset_bits);

            Ok(CtfType::Union {
                name: name.clone(),
                size: *byte_size,
                members: ctf_members,
            })
        }

        TypeStub::Enum {
            name,
            byte_size,
            enumerators,
        } => {
            // CTF enums must be 4 bytes (like C enums). For Rust enums with
            // smaller discriminants, emit an integer type instead.
            if *byte_size != 4 {
                let bit_size = *byte_size * 8;
                return Ok(CtfType::Integer {
                    name: name.clone(),
                    size: *byte_size,
                    encoding: ctf_int_data(0, 0, bit_size),
                });
            }

            let ctf_enumerators: Vec<CtfEnumerator> = enumerators
                .iter()
                .map(|e| CtfEnumerator {
                    name: e.name.clone(),
                    value: e.value,
                })
                .collect();

            Ok(CtfType::Enum {
                name: name.clone(),
                size: *byte_size,
                enumerators: ctf_enumerators,
            })
        }

        TypeStub::Unknown { _tag: _ } => Ok(CtfType::Unknown),
    }
}

/// Build CTF members from enum variant parts.
/// This creates the discriminant member and a union of variant payloads.
fn build_variant_part_members(
    variant_part: &VariantPartStub,
    members: &mut Vec<CtfMember>,
    parent_struct_name: &str,
    parent_struct_size: u32,
    header_offset: DebugInfoOffset<usize>,
    writer: &mut CtfWriter,
    global_type_map: &HashMap<GlobalTypeOffset, u16>,
) {
    // If there are no variants with payloads, just add the discriminant
    if variant_part.variants.is_empty() {
        if let Some(discr) = &variant_part.discriminant {
            members.push(CtfMember {
                name: discr.name.clone(),
                type_id: resolve_type_ref(discr.type_ref.as_ref(), header_offset, global_type_map),
                offset_bits: discr.offset_bytes * 8,
            });
        }
        return;
    }

    // Find the minimum offset among all variant members to determine union placement
    let union_offset_bits = variant_part
        .variants
        .iter()
        .flat_map(|v| v.members.iter())
        .map(|m| m.offset_bytes * 8)
        .min()
        .unwrap_or(0);

    let is_niche_optimized = if variant_part.discriminant.is_some() {
        // Enums using a niche optimization, e.g., `Option<NonZero<u32>>`, do not have
        // a separate discriminant. However, the DWARF still lists a discriminant, even
        // though it overlaps with the value:
        //
        //   < 3><0x0000e0a4>        DW_TAG_structure_type
        //                             DW_AT_name                  Option<core::num::nonzero::NonZero<u64>>
        //                             DW_AT_byte_size             0x00000008
        //                             DW_AT_accessibility         DW_ACCESS_public
        //                             DW_AT_alignment             0x00000008
        //   < 4><0x0000e0ac>          DW_TAG_variant_part
        //                             DW_AT_discr                 <0x0000e0b1>
        //
        // To distinguish if a discriminant struct member is needed, we check if any
        // of the variant type references have a `DW_AT_data_member_location` at offset
        // 0, which would overlap with the discriminant if that were present. If there
        // is an overlap, then we know that niche optimization is being used.
        let member_at_zero = variant_part.variants.iter().any(|v| {
            v.members.iter().any(|m| {
                let type_id = resolve_type_ref(m.type_ref.as_ref(), header_offset, global_type_map);
                match type_id {
                    MaybeOffset::Found(id) => writer
                        .types
                        .get(id as usize)
                        .map(|t| t.has_member_with_zero_offset())
                        .unwrap_or_default(),
                    _ => false,
                }
            })
        });
        member_at_zero
    } else {
        false
    };

    // Add the discriminant member only if not niche-optimized
    if !is_niche_optimized {
        if let Some(discr) = &variant_part.discriminant {
            // Collect discriminant values from variants to create a synthetic enum type
            let enumerators: Vec<CtfEnumerator> = variant_part
                .variants
                .iter()
                .filter_map(|v| {
                    v.discriminant_value.map(|val| CtfEnumerator {
                        name: v.name.clone(),
                        value: val as i32,
                    })
                })
                .collect();

            // If we have discriminant values, create a synthetic enum type
            let discr_type_id = if !enumerators.is_empty() {
                let enum_name = if parent_struct_name.is_empty() {
                    "__discr_ty".to_string()
                } else {
                    format!("{}::__discr_ty", parent_struct_name)
                };
                let enum_type = CtfType::Enum {
                    name: enum_name,
                    size: 4, // Standard CTF enum size
                    enumerators,
                };
                MaybeOffset::Found(writer.add_synthetic_type(enum_type))
            } else {
                // Fall back to original type if no discriminant values available
                resolve_type_ref(discr.type_ref.as_ref(), header_offset, global_type_map)
            };

            members.push(CtfMember {
                name: discr.name.clone(),
                type_id: discr_type_id,
                offset_bits: discr.offset_bytes * 8,
            });
        }
    }

    // Create struct types for each variant and collect as union members
    let mut union_members: Vec<CtfMember> = Vec::new();
    let mut max_variant_size: u32 = 0;

    for variant in &variant_part.variants {
        // Adjust member offsets to be relative to the union start
        let adjusted_members: Vec<CtfMember> = variant
            .members
            .iter()
            .map(|m| CtfMember {
                name: m.name.clone(),
                type_id: resolve_type_ref(m.type_ref.as_ref(), header_offset, global_type_map),
                offset_bits: (m.offset_bytes * 8).saturating_sub(union_offset_bits),
            })
            .collect();

        // Calculate variant struct size
        let variant_size = parent_struct_size.saturating_sub((union_offset_bits / 8) as u32);
        max_variant_size = max_variant_size.max(variant_size);

        // For single-member variants at offset 0, use the type directly
        let variant_type_id = if adjusted_members.len() == 1
            && adjusted_members[0].offset_bits == 0
            && (adjusted_members[0].name.is_empty() || adjusted_members[0].name == variant.name)
        {
            adjusted_members[0].type_id
        } else {
            // Create a struct for this variant's payload
            let variant_struct_name = if parent_struct_name.is_empty() {
                variant.name.clone()
            } else {
                format!("{}::{}", parent_struct_name, variant.name)
            };

            let variant_struct = CtfType::Struct {
                name: variant_struct_name,
                size: variant_size,
                members: adjusted_members,
            };
            MaybeOffset::Found(writer.add_synthetic_type(variant_struct))
        };

        union_members.push(CtfMember {
            name: variant.name.clone(),
            type_id: variant_type_id,
            offset_bits: 0, // All union members are at offset 0
        });
    }

    // Create the union type
    let union_name = if parent_struct_name.is_empty() {
        "__variants".to_string()
    } else {
        format!("{}::__variants", parent_struct_name)
    };

    let union_type = CtfType::Union {
        name: union_name,
        size: max_variant_size,
        members: union_members,
    };
    let union_type_id = writer.add_synthetic_type(union_type);

    // Add the union as a member of the parent struct
    members.push(CtfMember {
        name: "__variants".to_string(),
        type_id: MaybeOffset::Found(union_type_id),
        offset_bits: union_offset_bits,
    });
}

/// Resolve a type reference to a MaybeOffset.
/// Converts TypeRef to GlobalTypeId and looks up in global_type_map.
fn resolve_type_ref(
    type_ref: Option<&TypeRef>,
    header_offset: DebugInfoOffset<usize>,
    global_type_map: &HashMap<GlobalTypeOffset, u16>,
) -> MaybeOffset {
    let Some(type_ref) = type_ref else {
        // No type reference - use void (type ID 1)
        // Type 0 is Unknown/reserved, type 1 is the void type in CtfWriter
        return MaybeOffset::Found(1);
    };

    // Convert TypeRef to GlobalTypeId
    let global_id = match type_ref {
        TypeRef::SameUnit(unit_offset) => {
            // Convert unit-relative offset to absolute offset
            DebugInfoOffset(header_offset.0 + unit_offset.0)
        }
        TypeRef::CrossUnit(abs_offset) => *abs_offset,
    };

    // Check if already in global_type_map
    if let Some(&type_id) = global_type_map.get(&global_id) {
        return MaybeOffset::Found(type_id);
    }

    // Should have been processed already (topological order ensures this)
    // If not found, mark as pending
    MaybeOffset::Pending(global_id)
}

/// Build a base type (integer or float) from DWARF encoding.
fn build_base_type(name: &str, byte_size: u32, encoding: gimli::DwAte) -> CtfType {
    let bit_size = byte_size * 8;

    match encoding {
        gimli::DW_ATE_signed => CtfType::Integer {
            name: name.to_string(),
            size: byte_size,
            encoding: ctf_int_data(CTF_INT_SIGNED, 0, bit_size),
        },
        gimli::DW_ATE_unsigned => CtfType::Integer {
            name: name.to_string(),
            size: byte_size,
            encoding: ctf_int_data(0, 0, bit_size),
        },
        gimli::DW_ATE_boolean => CtfType::Integer {
            name: name.to_string(),
            size: byte_size,
            encoding: ctf_int_data(CTF_INT_BOOL, 0, bit_size),
        },
        gimli::DW_ATE_signed_char => CtfType::Integer {
            name: name.to_string(),
            size: byte_size,
            encoding: ctf_int_data(CTF_INT_SIGNED | CTF_INT_CHAR, 0, bit_size),
        },
        gimli::DW_ATE_unsigned_char => CtfType::Integer {
            name: name.to_string(),
            size: byte_size,
            encoding: ctf_int_data(CTF_INT_CHAR, 0, bit_size),
        },
        gimli::DW_ATE_float => {
            // Map float size to CTF float encoding
            let float_encoding = match byte_size {
                4 => ctf_int_data(1, 0, 32),   // CTF_FP_SINGLE
                8 => ctf_int_data(2, 0, 64),   // CTF_FP_DOUBLE
                16 => ctf_int_data(6, 0, 128), // CTF_FP_LDOUBLE
                _ => ctf_int_data(1, 0, bit_size),
            };
            CtfType::Float {
                name: name.to_string(),
                size: byte_size,
                encoding: float_encoding,
            }
        }
        _ => {
            // Unknown encoding - treat as unsigned integer
            CtfType::Integer {
                name: name.to_string(),
                size: byte_size,
                encoding: ctf_int_data(0, 0, bit_size),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topological_sort_single_type() {
        let mut deps = TypeDependencies::new();
        // Use GlobalTypeId (DebugInfoOffset) instead of UnitOffset
        let global_id = DebugInfoOffset(100);
        deps.all_types.insert(global_id);
        deps.deps.insert(global_id, vec![]);
        deps.stubs.insert(
            global_id,
            TypeStub::Base {
                name: "int".to_string(),
                byte_size: 4,
                encoding: gimli::DW_ATE_signed,
            },
        );

        let order = topological_sort(&deps);
        assert_eq!(order.sccs.len(), 1);
        assert_eq!(order.sccs[0], vec![global_id]);
    }

    #[test]
    fn test_topological_sort_chain() {
        // ptr -> typedef -> int
        let mut deps = TypeDependencies::new();

        // Use GlobalTypeId (DebugInfoOffset) instead of UnitOffset
        let int_id = DebugInfoOffset(100);
        let typedef_id = DebugInfoOffset(200);
        let ptr_id = DebugInfoOffset(300);

        deps.all_types.insert(int_id);
        deps.all_types.insert(typedef_id);
        deps.all_types.insert(ptr_id);

        deps.deps.insert(int_id, vec![]);
        deps.deps.insert(typedef_id, vec![int_id]);
        deps.deps.insert(ptr_id, vec![typedef_id]);

        // TypeRef inside stubs can still use SameUnit for internal representation
        // but for this test, we use UnitOffset(0) as a dummy since we won't actually resolve
        deps.stubs.insert(
            int_id,
            TypeStub::Base {
                name: "int".to_string(),
                byte_size: 4,
                encoding: gimli::DW_ATE_signed,
            },
        );
        deps.stubs.insert(
            typedef_id,
            TypeStub::Typedef {
                name: "myint".to_string(),
                target: Some(TypeRef::SameUnit(UnitOffset(100))), // raw offset within unit
            },
        );
        deps.stubs.insert(
            ptr_id,
            TypeStub::Pointer {
                name: "".to_string(),
                target: Some(TypeRef::SameUnit(UnitOffset(200))),
            },
        );

        let order = topological_sort(&deps);

        // Should have 3 SCCs (no cycles)
        assert_eq!(order.sccs.len(), 3);

        // Collect order
        let flat: Vec<GlobalTypeOffset> = order.sccs.iter().flatten().copied().collect();

        // int should come before typedef, typedef before ptr
        let int_pos = flat.iter().position(|&o| o == int_id).unwrap();
        let typedef_pos = flat.iter().position(|&o| o == typedef_id).unwrap();
        let ptr_pos = flat.iter().position(|&o| o == ptr_id).unwrap();

        assert!(int_pos < typedef_pos);
        assert!(typedef_pos < ptr_pos);
    }

    #[test]
    fn test_topological_sort_cycle() {
        // Node -> *Node (self-referential linked list)
        let mut deps = TypeDependencies::new();

        // Use GlobalTypeId (DebugInfoOffset) instead of UnitOffset
        let struct_id = DebugInfoOffset(100);
        let ptr_id = DebugInfoOffset(200);

        deps.all_types.insert(struct_id);
        deps.all_types.insert(ptr_id);

        // struct Node depends on *Node (for the 'next' field)
        deps.deps.insert(struct_id, vec![ptr_id]);
        // *Node depends on Node
        deps.deps.insert(ptr_id, vec![struct_id]);

        let order = topological_sort(&deps);

        // Should have 1 SCC containing both types (they form a cycle)
        assert_eq!(order.sccs.len(), 1);
        assert_eq!(order.sccs[0].len(), 2);

        let scc: HashSet<GlobalTypeOffset> = order.sccs[0].iter().copied().collect();
        assert!(scc.contains(&struct_id));
        assert!(scc.contains(&ptr_id));
    }

    #[test]
    fn test_build_base_type_signed() {
        let ctf = build_base_type("i32", 4, gimli::DW_ATE_signed);
        match ctf {
            CtfType::Integer {
                name,
                size,
                encoding,
            } => {
                assert_eq!(name, "i32");
                assert_eq!(size, 4);
                // Check encoding has signed flag
                assert_eq!(encoding >> 24, CTF_INT_SIGNED as u32);
            }
            _ => panic!("Expected Integer type"),
        }
    }

    #[test]
    fn test_build_base_type_float() {
        let ctf = build_base_type("f64", 8, gimli::DW_ATE_float);
        match ctf {
            CtfType::Float { name, size, .. } => {
                assert_eq!(name, "f64");
                assert_eq!(size, 8);
            }
            _ => panic!("Expected Float type"),
        }
    }

    /// Helper to simulate the member sorting logic used in stub_to_ctf_type
    /// for struct and union members.
    fn sort_members_by_offset(members: &mut [CtfMember]) {
        members.sort_by_key(|m| m.offset_bits);
    }

    #[test]
    fn test_struct_members_sorted_by_offset() {
        // Simulate members in reverse offset order (as might come from DWARF)
        let mut members = vec![
            CtfMember {
                name: "c".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 128, // 16 bytes * 8
            },
            CtfMember {
                name: "a".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 0,
            },
            CtfMember {
                name: "b".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 64, // 8 bytes * 8
            },
        ];

        sort_members_by_offset(&mut members);

        // Members should be sorted by offset_bits
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].name, "a");
        assert_eq!(members[0].offset_bits, 0);
        assert_eq!(members[1].name, "b");
        assert_eq!(members[1].offset_bits, 64);
        assert_eq!(members[2].name, "c");
        assert_eq!(members[2].offset_bits, 128);
    }

    #[test]
    fn test_union_members_sorted_by_offset() {
        // Union members typically have offset 0, verify stable sort behavior
        let mut members = vec![
            CtfMember {
                name: "z".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 0,
            },
            CtfMember {
                name: "y".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 0,
            },
            CtfMember {
                name: "x".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 0,
            },
        ];

        sort_members_by_offset(&mut members);

        // All offsets are 0, stable sort preserves original order
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].name, "z");
        assert_eq!(members[1].name, "y");
        assert_eq!(members[2].name, "x");
    }

    #[test]
    fn test_struct_members_with_mixed_offsets() {
        // Test with non-contiguous offsets (padding scenario)
        let mut members = vec![
            CtfMember {
                name: "field_at_24".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 192, // 24 * 8
            },
            CtfMember {
                name: "field_at_4".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 32, // 4 * 8
            },
            CtfMember {
                name: "field_at_0".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 0,
            },
            CtfMember {
                name: "field_at_12".to_string(),
                type_id: MaybeOffset::Found(1),
                offset_bits: 96, // 12 * 8
            },
        ];

        sort_members_by_offset(&mut members);

        // Verify ascending offset order
        assert_eq!(members.len(), 4);
        assert_eq!(members[0].name, "field_at_0");
        assert_eq!(members[0].offset_bits, 0);
        assert_eq!(members[1].name, "field_at_4");
        assert_eq!(members[1].offset_bits, 32);
        assert_eq!(members[2].name, "field_at_12");
        assert_eq!(members[2].offset_bits, 96);
        assert_eq!(members[3].name, "field_at_24");
        assert_eq!(members[3].offset_bits, 192);
    }

    #[test]
    fn test_single_member_struct() {
        // Edge case: single member should remain unchanged
        let mut members = vec![CtfMember {
            name: "only_field".to_string(),
            type_id: MaybeOffset::Found(1),
            offset_bits: 0,
        }];

        sort_members_by_offset(&mut members);

        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "only_field");
    }

    #[test]
    fn test_empty_struct() {
        // Edge case: empty struct should not panic
        let mut members: Vec<CtfMember> = vec![];

        sort_members_by_offset(&mut members);

        assert!(members.is_empty());
    }

    #[test]
    fn test_anonymous_function_type_gets_synthetic_name() {
        // DW_TAG_subroutine_type entries typically don't have names in DWARF.
        // illumos ctfdump expects CTF_K_FUNCTION types to have names, so we
        // generate a synthetic "<anon_fn>" name for anonymous function types.
        let mut deps = TypeDependencies::new();
        let func_id = DebugInfoOffset(100);
        let void_id = DebugInfoOffset(50);

        deps.all_types.insert(void_id);
        deps.all_types.insert(func_id);
        deps.deps.insert(void_id, vec![]);
        deps.deps.insert(func_id, vec![void_id]);
        deps.type_locations
            .insert(void_id, (DebugInfoOffset(0), UnitOffset(50)));
        deps.type_locations
            .insert(func_id, (DebugInfoOffset(0), UnitOffset(100)));

        // void base type for return type
        deps.stubs.insert(
            void_id,
            TypeStub::Base {
                name: "void".to_string(),
                byte_size: 0,
                encoding: gimli::DW_ATE_signed,
            },
        );

        // Anonymous function type (empty name, as comes from DWARF)
        deps.stubs.insert(
            func_id,
            TypeStub::Function {
                name: String::new(), // Empty name from DWARF
                return_type: Some(TypeRef::SameUnit(UnitOffset(50))),
                params: vec![],
                is_varargs: false,
            },
        );

        let mut writer = CtfWriter::new(None);

        // First add the void type
        let void_ctf = build_base_type("void", 0, gimli::DW_ATE_signed);
        let void_ctf_id = writer.add_type(void_id, void_ctf);

        // Build global type map
        let mut global_type_map = HashMap::new();
        global_type_map.insert(void_id, void_ctf_id);

        // Convert the function stub
        let func_stub = deps.stubs.get(&func_id).unwrap();
        let result = stub_to_ctf_type(func_stub, func_id, &deps, &mut writer, &global_type_map);

        let ctf_type = result.expect("Function type conversion should succeed");

        // Verify the function type has the synthetic name
        match ctf_type {
            CtfType::Function { name, .. } => {
                assert_eq!(
                    name, "<anon_fn>",
                    "Anonymous function type should get synthetic '<anon_fn>' name"
                );
            }
            _ => panic!("Expected Function type, got {:?}", ctf_type),
        }
    }

    #[test]
    fn test_void_return_type_uses_type_id_1() {
        // When a function has no return type (void), it should use type ID 1 (void),
        // not type ID 0 (unknown/reserved).
        let mut deps = TypeDependencies::new();
        let func_id = DebugInfoOffset(100);

        deps.all_types.insert(func_id);
        deps.deps.insert(func_id, vec![]);
        deps.type_locations
            .insert(func_id, (DebugInfoOffset(0), UnitOffset(100)));

        // Function type with NO return type (void)
        deps.stubs.insert(
            func_id,
            TypeStub::Function {
                name: String::new(),
                return_type: None, // No return type = void
                params: vec![],
                is_varargs: false,
            },
        );

        let mut writer = CtfWriter::new(None);

        let global_type_map = HashMap::new();

        let func_stub = deps.stubs.get(&func_id).unwrap();
        let result = stub_to_ctf_type(func_stub, func_id, &deps, &mut writer, &global_type_map);

        let ctf_type = result.expect("Function type conversion should succeed");

        match ctf_type {
            CtfType::Function { return_type, .. } => {
                assert_eq!(
                    return_type,
                    MaybeOffset::Found(1),
                    "Void return type should use type ID 1 (void), not 0 (unknown)"
                );
            }
            _ => panic!("Expected Function type, got {:?}", ctf_type),
        }
    }

    #[test]
    fn test_named_function_type_keeps_name() {
        // When a function type has a name from DWARF, it should be preserved
        let mut deps = TypeDependencies::new();
        let func_id = DebugInfoOffset(100);
        let void_id = DebugInfoOffset(50);

        deps.all_types.insert(void_id);
        deps.all_types.insert(func_id);
        deps.deps.insert(void_id, vec![]);
        deps.deps.insert(func_id, vec![void_id]);
        deps.type_locations
            .insert(void_id, (DebugInfoOffset(0), UnitOffset(50)));
        deps.type_locations
            .insert(func_id, (DebugInfoOffset(0), UnitOffset(100)));

        deps.stubs.insert(
            void_id,
            TypeStub::Base {
                name: "void".to_string(),
                byte_size: 0,
                encoding: gimli::DW_ATE_signed,
            },
        );

        // Named function type
        deps.stubs.insert(
            func_id,
            TypeStub::Function {
                name: "my_callback".to_string(),
                return_type: Some(TypeRef::SameUnit(UnitOffset(50))),
                params: vec![],
                is_varargs: false,
            },
        );

        let mut writer = CtfWriter::new(None);

        let void_ctf = build_base_type("void", 0, gimli::DW_ATE_signed);
        let void_ctf_id = writer.add_type(void_id, void_ctf);

        let mut global_type_map = HashMap::new();
        global_type_map.insert(void_id, void_ctf_id);

        let func_stub = deps.stubs.get(&func_id).unwrap();
        let result = stub_to_ctf_type(func_stub, func_id, &deps, &mut writer, &global_type_map);

        let ctf_type = result.expect("Function type conversion should succeed");

        match ctf_type {
            CtfType::Function { name, .. } => {
                assert_eq!(
                    name, "my_callback",
                    "Named function type should preserve its name"
                );
            }
            _ => panic!("Expected Function type, got {:?}", ctf_type),
        }
    }
}

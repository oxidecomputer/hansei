pub mod deps;

use std::collections::HashMap;
use std::ops::Range;

use anyhow::{Context, Result};
use gimli::{
    AttributeValue, DW_TAG_formal_parameter, DW_TAG_subprogram, DebugInfoOffset,
    DebuggingInformationEntry, Dwarf, Reader, UnitOffset, UnitRef,
};
use goblin::elf::Elf;

use crate::GlobalTypeOffset;
use crate::ctf::CtfWriter;
use deps::DependencyCollector;

pub struct DwarfParser<'a, R: Reader<Offset = usize>> {
    pub dwarf: &'a Dwarf<R>,
    pub writer: CtfWriter<'a>,
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
    ) -> Result<deps::TypeDependencies> {
        let collector = DependencyCollector::new(self.dwarf, &self.unit_ranges);
        collector.collect_deps_from_roots(unit, root_offsets)
    }

    pub fn build(elf: &'a Elf<'a>, dwarf: &'a Dwarf<R>) -> Result<Self> {
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

        Ok(DwarfParser {
            dwarf,
            writer: CtfWriter::new(elf),
            unit_ranges,
        })
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

    /// Find functions by name and collect all type dependencies.
    pub fn find_functions_and_collect_types(
        &self,
        functions: &mut HashMap<String, bool>,
    ) -> Result<(Vec<FunctionInfo>, deps::TypeDependencies)> {
        let mut function_info = Vec::new();
        let mut type_deps = deps::TypeDependencies::new();

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
        type_deps: &deps::TypeDependencies,
    ) -> Result<HashMap<String, CtfFunctionInfo>> {
        // Build all types from the collected dependencies
        deps::build_types_from_deps(type_deps, &mut self.writer)?;

        // Now look up the type IDs for each function
        let mut parsed_funcs = HashMap::new();

        for func in funcs {
            println!("Function: {}", func.name);
            println!("  Arguments: {:?}", func.args);
            println!("  Return Type: {:?}", func.return_type_offset);

            let return_type = if let Some(ret_offset) = func.return_type_offset {
                self.writer
                    .type_map
                    .get(&ret_offset)
                    .copied()
                    .context("return type not found after building types")?
            } else {
                0 // void
            };

            let mut args = Vec::new();
            for (arg_name, arg_offset) in &func.args {
                let arg_type_id = self
                    .writer
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

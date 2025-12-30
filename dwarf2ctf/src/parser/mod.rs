mod arrays;
mod composites;
mod primitives;

use std::collections::{HashMap, VecDeque};

use anyhow::{Context, Result};
use gimli::{
    Attribute, AttributeValue, DW_TAG_formal_parameter, DW_TAG_subprogram,
    DebuggingInformationEntry, Dwarf, Reader, UnitHeader, UnitOffset, UnitRef,
};
use goblin::elf::Elf;

use crate::ctf::CtfWriter;
use crate::ctf::types::{CtfType, MaybeOffset};

/// Represents a unit's offset range for quick lookups
struct UnitRange {
    start: usize,
    end: usize,
}

pub struct DwarfParser<'a, R: Reader<Offset = usize>> {
    pub dwarf: &'a Dwarf<R>,
    pub writer: CtfWriter<'a>,
    pub inflight_types: VecDeque<UnitOffset>,
    /// Index of unit ranges for cross-unit reference resolution
    unit_ranges: Vec<UnitRange>,
}

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    pub fn new(elf: &'a Elf<'a>, dwarf: &'a Dwarf<R>) -> Result<Self> {
        // Build index of unit ranges for cross-unit reference resolution
        let mut unit_ranges = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let start = match header.offset() {
                gimli::UnitSectionOffset::DebugInfoOffset(off) => off.0,
                gimli::UnitSectionOffset::DebugTypesOffset(off) => off.0,
            };
            let end = start + header.length_including_self();
            unit_ranges.push(UnitRange { start, end });
        }

        Ok(DwarfParser {
            dwarf,
            writer: CtfWriter::new(elf),
            inflight_types: VecDeque::new(),
            unit_ranges,
        })
    }

    fn find_functions_recursive(
        &self,
        node: gimli::EntriesTreeNode<R>,
        unit: &UnitRef<R>,
        functions: &mut HashMap<String, bool>,
        function_info: &mut Vec<FunctionInfo<R>>,
    ) -> Result<bool> {
        if functions.values().all(|&found| found) {
            return Ok(true);
        }

        let entry = node.entry();
        if entry.tag() == DW_TAG_subprogram {
            // TODO CORRECTNESS: Skip inline instances - only look at concrete or abstract instances
            let is_inline = entry
                .attr(gimli::DW_AT_inline)?
                .and_then(|attr| attr.value().udata_value())
                .unwrap_or(0)
                != 0;

            // TODO: DO THESE EVEN EXIST IN RUST? Skip declarations (forward declarations without definitions)
            let is_declaration = entry
                .attr(gimli::DW_AT_declaration)?
                .and_then(|attr| attr.value().udata_value())
                .unwrap_or(0)
                != 0;

            if is_inline || is_declaration {
                return Ok(false);
            }

            if let Some(attr) = entry.attr(gimli::DW_AT_linkage_name)?
                && let Ok(name) = unit.dwarf.attr_string(unit, attr.value())
                && let Ok(name_str) = name.to_string_lossy()
                && let Some(found) = functions.get_mut(name_str.as_ref())
            {
                if *found {
                    return Ok(false);
                }

                *found = true;
                let unit_name = unit
                    .name
                    .as_ref()
                    .and_then(|n| n.to_string_lossy().ok())
                    .unwrap_or_default();
                println!("Found {name_str} in unit {unit_name}",);

                let mut args = Vec::new();

                // DW_AT_type of a function is its return type
                let return_type_offset = get_type_offset(unit, entry)?;

                // Get parameters
                let mut tree = unit
                    .entries_tree(Some(entry.offset()))
                    .context("failed to get function entry tree")?;
                let root = tree
                    .root()
                    .context("failed to get function entry tree root")?;

                let mut children = root.children();
                while let Some(child) = children.next().context("failed to get function child")? {
                    if child.entry().tag() == DW_TAG_formal_parameter {
                        let param_name = get_param_name(unit, child.entry())?;

                        if let Some(type_offset) = get_type_offset(unit, child.entry())? {
                            args.push((param_name, type_offset));
                        }
                    }
                }

                function_info.push(FunctionInfo {
                    name: name_str.to_string(),
                    return_type_offset,
                    args,
                    unit_header: unit.header.clone(),
                });
                return Ok(true);
            }
        }

        // Recursively search children
        let mut children = node.children();
        while let Some(child) = children.next()? {
            if self.find_functions_recursive(child, unit, functions, function_info)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn find_functions_by_name(
        &self,
        functions: &mut HashMap<String, bool>,
    ) -> Result<Vec<FunctionInfo<R>>> {
        let mut function_info = Vec::new();

        let mut iter = self.dwarf.units();
        while let Some(header) = iter.next().context("failed to get next unit header")? {
            let unit = self.dwarf.unit(header).context("failed to read unit")?;
            let unit = UnitRef::new(self.dwarf, &unit);

            let mut tree = unit
                .entries_tree(None)
                .context("failed to get entries tree")?;
            let root = tree.root().context("failed to get entry tree root")?;

            self.find_functions_recursive(root, &unit, functions, &mut function_info)?;

            if functions.values().all(|&found| found) {
                break;
            }
        }

        if !self.inflight_types.is_empty() {
            anyhow::bail!(
                "{} types still marked as pending after parsing completed: {:?}",
                self.inflight_types.len(),
                self.inflight_types,
            );
        }

        Ok(function_info)
    }

    pub fn parse_fn_info(
        &mut self,
        funcs: Vec<FunctionInfo<R>>,
    ) -> Result<HashMap<String, ParsedFunctionInfo>> {
        let mut return_types = Vec::new();
        let mut parsed_funcs = HashMap::new();

        for func in funcs {
            println!("Function: {}", func.name);
            println!("  Arguments: {:?}", func.args);
            println!("  Return Type: {:?}", func.return_type_offset);

            let unit = self.dwarf.unit(func.unit_header)?;
            let unit_ref = UnitRef::new(self.dwarf, &unit);

            let return_type = if let Some(ret_offset) = func.return_type_offset {
                self.parse_type(&unit_ref, ret_offset)
                    .context("failed to parse return type")?
            } else {
                MaybeOffset::Found(0)
            };
            let return_type = match return_type {
                MaybeOffset::Found(f) => f,
                MaybeOffset::Pending(p) => panic!("return type offset {p:?} was not resolved"),
            };
            return_types.push(return_type);

            let mut args = Vec::new();
            for (arg_name, arg_offset) in &func.args {
                let arg_type_id = self
                    .parse_type(&unit_ref, *arg_offset)
                    .context("failed to parse arg type")?;
                let arg_type_id = match arg_type_id {
                    MaybeOffset::Found(f) => f,
                    MaybeOffset::Pending(p) => panic!("arg offset {p:?} was not resolved"),
                };
                println!("  Arg '{}': type ID {:?}", arg_name, arg_type_id);
                args.push(arg_type_id);
            }

            parsed_funcs.insert(
                func.name.to_string(),
                ParsedFunctionInfo { return_type, args },
            );
        }

        Ok(parsed_funcs)
    }

    pub fn parse_function_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_name {
                name = get_attr_string(unit, &attr)?;
            }
        }

        // DW_AT_type of a function is its return type
        let return_type_offset = get_type_offset(unit, entry)?;
        let return_type = if let Some(ret_off) = return_type_offset {
            self.parse_type(unit, ret_off)?
        } else {
            MaybeOffset::Found(1)
        };

        let mut tree = unit
            .entries_tree(Some(entry.offset()))
            .context("failed to get function entry tree")?;
        let root = tree
            .root()
            .context("failed to get function entry tree root")?;

        let mut args = Vec::new();
        let mut is_varargs = false;

        let mut children = root.children();
        while let Some(child) = children.next().context("failed to get function child")? {
            match child.entry().tag() {
                gimli::DW_TAG_formal_parameter => {
                    if let Some(type_offset) = get_type_offset(unit, child.entry())? {
                        let arg_ty = self.parse_type(unit, type_offset)?;
                        args.push(arg_ty);
                    }
                }
                gimli::DW_TAG_unspecified_parameters => {
                    is_varargs = true;
                }
                _ => {}
            }
        }

        let ctf_type = CtfType::Function {
            name,
            return_type,
            args,
            is_varargs,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub fn parse_type(&mut self, unit: &UnitRef<R>, offset: UnitOffset) -> Result<MaybeOffset> {
        // Check if we've already parsed this type
        if let Some(type_id) = self.writer.type_map.get(&offset) {
            return Ok(MaybeOffset::Found(*type_id));
        }

        // We're in a type with a member that refers to itself, e.g. a linked list.
        // We will resolve the index for this type when the first instance completes,
        // so mark it as pending for now and don't recurse into the type again.
        if self.inflight_types.contains(&offset) {
            return Ok(MaybeOffset::Pending(offset));
        }

        let Ok(mut entries) = unit.entries_at_offset(offset) else {
            anyhow::bail!("type offset {offset:?} not found");
        };

        // Track that we're in the process of adding this type.
        self.inflight_types.push_back(offset);

        let (_, entry) = entries.next_dfs()?.context("No entry at offset")?;

        let maybe_id = match entry.tag() {
            gimli::DW_TAG_base_type => self.parse_base_type(offset, unit, entry)?,
            gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type => {
                self.parse_pointer_type(offset, unit, entry)?
            }
            gimli::DW_TAG_typedef => self.parse_typedef(offset, unit, entry)?,
            gimli::DW_TAG_const_type => self.parse_const_type(offset, unit, entry)?,
            gimli::DW_TAG_volatile_type => self.parse_volatile_type(offset, unit, entry)?,
            gimli::DW_TAG_restrict_type => self.parse_restrict_type(offset, unit, entry)?,
            gimli::DW_TAG_array_type => self.parse_array_type(offset, unit, entry)?,
            gimli::DW_TAG_subroutine_type => self.parse_function_type(offset, unit, entry)?,
            gimli::DW_TAG_structure_type => self.parse_struct_type(offset, unit, entry)?,
            gimli::DW_TAG_union_type => self.parse_union_type(offset, unit, entry)?,
            gimli::DW_TAG_enumeration_type => self.parse_enum_type(offset, unit, entry)?,
            other => {
                // Unknown type - use void as placeholder since CTF_K_UNKNOWN
                // causes MDB to fail.
                eprintln!(
                    "Warning: unhandled DWARF tag {:?}, using void placeholder",
                    other
                );
                MaybeOffset::Found(1) // void type
            }
        };

        // Type has been fully parsed, pop it off the stack.
        self.inflight_types.pop_back();

        Ok(maybe_id)
    }
}

/// Information about a function collected during DWARF scanning.
#[derive(Clone, Debug)]
pub struct FunctionInfo<R: Reader<Offset = usize>> {
    pub name: String,
    pub return_type_offset: Option<UnitOffset>,
    pub args: Vec<(String, UnitOffset)>,
    pub unit_header: UnitHeader<R, R::Offset>,
}

/// Parsed function info with CTF type IDs.
#[derive(Clone, Debug)]
pub struct ParsedFunctionInfo {
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

/// Extract a string from a DWARF attribute.
fn get_attr_string<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    attr: &Attribute<R>,
) -> Result<String> {
    match attr.value() {
        AttributeValue::DebugStrRef(offset) => {
            let s = unit.string(offset)?;
            Ok(s.to_string()?.into_owned())
        }
        AttributeValue::String(s) => Ok(s.to_string()?.into_owned()),
        _ => Ok(String::new()),
    }
}

/// Extract a UnitOffset from a type reference attribute value.
/// Handles both UnitRef (unit-relative) and DebugInfoRef (absolute) references.
/// For cross-unit references, returns None - use resolve_type_attr for those.
fn get_attr_type_offset<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    attr: &Attribute<R>,
) -> Option<UnitOffset> {
    match attr.value() {
        AttributeValue::UnitRef(offset) => Some(offset),
        AttributeValue::DebugInfoRef(debug_info_offset) => {
            // Try to convert to unit offset (works if same unit)
            debug_info_offset.to_unit_offset(&unit.header)
        }
        _ => None,
    }
}

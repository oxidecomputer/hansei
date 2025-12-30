use anyhow::Result;
use gimli::{
    Attribute, AttributeValue, DebugInfoOffset, DebuggingInformationEntry, Reader, Unit,
    UnitOffset, UnitRef,
};

use super::get_attr_string;
use crate::ctf::types::{CtfEnumerator, CtfMember, CtfType, MaybeOffset, VariantInfo};
use crate::parser::DwarfParser;

/// Evaluate a simple DWARF location expression to get an offset.
/// Handles DW_OP_plus_uconst and DW_OP_constu.
fn eval_simple_location_expr<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    expr: gimli::Expression<R>,
) -> Result<u32> {
    let mut eval = expr.operations(unit.encoding());

    if let Ok(Some(op)) = eval.next() {
        match op {
            gimli::Operation::PlusConstant { value } => {
                return Ok(value as u32);
            }
            gimli::Operation::UnsignedConstant { value } => {
                return Ok(value as u32);
            }
            _ => {
                unimplemented!();
            }
        }
    }

    Ok(0)
}

/// Get a fully qualified type name by prepending namespace path.
fn get_qualified_name<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    offset: UnitOffset,
    name: &str,
) -> Result<String> {
    if name.is_empty() {
        return Ok(String::new());
    }

    let namespace = get_namespace_path(unit, offset)?;
    if namespace.is_empty() {
        Ok(name.to_string())
    } else {
        Ok(format!("{}::{}", namespace.join("::"), name))
    }
}

/// Build the namespace path for a DIE by walking up through parent DIEs.
/// Returns the full path like "tokio::runtime::scheduler::multi_thread::handle"
fn get_namespace_path<R: Reader<Offset = usize>>(
    unit: &UnitRef<R>,
    offset: UnitOffset,
) -> Result<Vec<String>> {
    let mut path = Vec::new();
    let mut cursor = unit.entries();

    // We need to track parent chain as we descend
    let mut parent_stack: Vec<(UnitOffset, Option<String>)> = Vec::new();
    let mut found_target = false;

    while let Some((depth_delta, entry)) = cursor.next_dfs()? {
        // Adjust parent stack based on depth
        if depth_delta <= 0 {
            for _ in 0..(-depth_delta + 1) {
                parent_stack.pop();
            }
        }

        // Get name for namespace-contributing tags
        let name = match entry.tag() {
            gimli::DW_TAG_namespace | gimli::DW_TAG_module => {
                if let Some(attr) = entry.attr(gimli::DW_AT_name)? {
                    Some(get_attr_string(unit, &attr)?)
                } else {
                    None
                }
            }
            _ => None,
        };

        if entry.offset() == offset {
            // Found our target - collect the namespace from parents
            for (_, parent_name) in &parent_stack {
                if let Some(n) = parent_name {
                    path.push(n.clone());
                }
            }
            found_target = true;
            break;
        }

        parent_stack.push((entry.offset(), name));
    }

    if !found_target {
        return Ok(Vec::new());
    }

    Ok(path)
}

/// Extract byte size from an attribute value.
fn get_byte_size(attr: &Attribute<impl Reader>) -> Option<u32> {
    match attr.value() {
        AttributeValue::Udata(size) => Some(size as u32),
        AttributeValue::Data1(size) => Some(size as u32),
        AttributeValue::Data2(size) => Some(size as u32),
        AttributeValue::Data4(size) => Some(size),
        AttributeValue::Data8(size) => Some(size as u32),
        AttributeValue::Sdata(size) => Some(size as u32),
        _ => None,
    }
}

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    pub fn parse_struct_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    if let Some(size) = get_byte_size(&attr) {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let qualified_name = get_qualified_name(unit, offset, &name)?;

        let mut members = Vec::new();
        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;

        let mut children = root.children();
        while let Some(child) = children.next()? {
            match child.entry().tag() {
                gimli::DW_TAG_member => {
                    if let Some(member) = self.parse_struct_member(unit, child.entry())? {
                        members.push(member);
                    }
                }
                gimli::DW_TAG_variant_part => {
                    self.parse_variant_part_members(
                        unit,
                        child,
                        &mut members,
                        &qualified_name,
                        byte_size,
                    )?;
                }
                _ => {}
            }
        }

        // Is this a trivial tuple struct wrapping a single field?
        // `mdb` won't show argument types in stacks if there are structs passed by value
        // with a size <= 16.
        if let Some(child) = members.first()
            && members.len() == 1
            && child.name == "__0"
        {
            return Ok(child.type_id);
        }
        let ctf_type = CtfType::Struct {
            name: qualified_name,
            size: byte_size,
            members,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub fn parse_union_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    if let Some(size) = get_byte_size(&attr) {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let qualified_name = get_qualified_name(unit, offset, &name)?;

        let mut members = Vec::new();
        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;

        let mut children = root.children();
        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_member
                && let Some(member) = self.parse_struct_member(unit, child.entry())?
            {
                members.push(member);
            }
        }

        let ctf_type = CtfType::Union {
            name: qualified_name,
            size: byte_size,
            members,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    /// Parse DW_TAG_enumeration_type - represent as an integer type since CTF enums
    /// are primarily for C-style enums. Rust enums with payloads are handled via
    /// DW_TAG_variant_part in struct parsing.
    pub fn parse_enum_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    if let Some(size) = get_byte_size(&attr) {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

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
                            enum_name = get_attr_string(unit, &attr)?;
                        }
                        gimli::DW_AT_const_value => {
                            enum_value = match attr.value() {
                                AttributeValue::Sdata(v) => v as i32,
                                AttributeValue::Udata(v) => v as i32,
                                AttributeValue::Data1(v) => v as i32,
                                AttributeValue::Data2(v) => v as i32,
                                AttributeValue::Data4(v) => v as i32,
                                AttributeValue::Data8(v) => v as i32,
                                _ => enum_value,
                            };
                        }
                        _ => {}
                    }
                }

                enumerators.push(CtfEnumerator {
                    name: enum_name,
                    value: enum_value,
                });
            }
        }

        let ctf_type = CtfType::Enum {
            name,
            size: byte_size,
            enumerators,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    /// Parse a DW_TAG_variant_part and create a proper tagged union representation.
    /// This creates:
    /// 1. The discriminant member
    /// 2. A union type containing all variant payloads
    /// 3. A member pointing to that union
    fn parse_variant_part_members(
        &mut self,
        unit: &UnitRef<R>,
        variant_part_node: gimli::EntriesTreeNode<R>,
        members: &mut Vec<CtfMember>,
        parent_struct_name: &str,
        parent_struct_size: u32,
    ) -> Result<()> {
        let entry = variant_part_node.entry();

        // Check for discriminant member (DW_AT_discr points to a DW_TAG_member child)
        let mut discr_offset = None;
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_discr
                && let AttributeValue::UnitRef(off) = attr.value()
            {
                discr_offset = Some(off);
            }
        }

        // Collect the discriminant and all variants
        let mut discr_member: Option<CtfMember> = None;
        let mut variants: Vec<VariantInfo> = Vec::new();

        let mut children = variant_part_node.children();
        while let Some(child) = children.next()? {
            match child.entry().tag() {
                gimli::DW_TAG_member => {
                    // This is the discriminant member
                    if let Some(member) = self.parse_struct_member(unit, child.entry())? {
                        let is_discr =
                            discr_offset.is_some_and(|off| child.entry().offset() == off);
                        let member = if is_discr && member.name.is_empty() {
                            CtfMember {
                                name: "__discr".to_string(),
                                ..member
                            }
                        } else {
                            member
                        };
                        discr_member = Some(member);
                    }
                }
                gimli::DW_TAG_variant => {
                    if let Some(variant_info) = self.parse_variant_members(unit, child)? {
                        variants.push(variant_info);
                    }
                }
                _ => {}
            }
        }

        // If there are no variants with payloads, we're done (but still add discriminant)
        if variants.is_empty() {
            if let Some(discr) = discr_member {
                members.push(discr);
            }
            return Ok(());
        }

        // Find the minimum offset among all variant members.
        // In Rust DWARF, variant member offsets may be 0 (relative to the variant start),
        // not relative to the struct start. We need to detect this case.
        let min_variant_member_offset = variants
            .iter()
            .flat_map(|v| v.members.iter())
            .map(|m| m.offset_bits)
            .min()
            .unwrap_or(0);

        // Get discriminant info to calculate where variant data actually starts
        let discr_offset_bits = discr_member.as_ref().map(|d| d.offset_bits).unwrap_or(0);

        // Calculate the discriminant size by looking up its CTF type
        let discr_size_bits = if let Some(ref discr) = discr_member {
            match &discr.type_id {
                MaybeOffset::Found(type_id) => {
                    // Look up the type to get its size
                    if let Some(CtfType::Integer { size, .. }) =
                        self.writer.types.get(*type_id as usize)
                    {
                        (*size as u64) * 8
                    } else {
                        0
                    }
                }
                MaybeOffset::Pending(_) => 0,
            }
        } else {
            0
        };

        // The union should start after the discriminant if variant offsets are 0
        // (which means they're relative to the variant, not the struct)
        let union_offset_bits =
            if min_variant_member_offset == 0 && discr_member.is_some() && discr_size_bits > 0 {
                // Variant member offsets are relative to variant start, not struct start
                // Place the union after the discriminant
                discr_offset_bits + discr_size_bits
            } else {
                // Variant member offsets are already relative to struct start
                min_variant_member_offset
            };

        // Add the discriminant member
        if let Some(discr) = discr_member {
            members.push(discr);
        }

        // Create struct types for each variant and collect as union members
        let mut union_members: Vec<CtfMember> = Vec::new();
        let mut max_variant_size: u32 = 0;

        for variant in &variants {
            // Adjust member offsets to be relative to the union start
            let adjusted_members: Vec<CtfMember> = variant
                .members
                .iter()
                .map(|m| CtfMember {
                    name: m.name.clone(),
                    type_id: m.type_id,
                    offset_bits: m.offset_bits.saturating_sub(union_offset_bits),
                })
                .collect();

            // Calculate variant struct size from the adjusted members
            // (This is an approximation - we use the parent struct size minus discriminant)
            let variant_size = parent_struct_size.saturating_sub((union_offset_bits / 8) as u32);
            max_variant_size = max_variant_size.max(variant_size);

            // For single-member variants, use the type directly to avoid double nesting
            // (e.g., CurrentThread = { CurrentThread = { ... } } becomes CurrentThread = { ... })
            let variant_type_id = if adjusted_members.len() == 1
                && adjusted_members[0].offset_bits == 0
                && (adjusted_members[0].name.is_empty() || adjusted_members[0].name == variant.name)
            {
                // Single member at offset 0 (unnamed or same name as variant) - use its type directly
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
                MaybeOffset::Found(self.writer.add_synthetic_type(variant_struct))
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
        let union_type_id = self.writer.add_synthetic_type(union_type);

        // Add the union as a member of the parent struct
        members.push(CtfMember {
            name: "__variants".to_string(),
            type_id: MaybeOffset::Found(union_type_id),
            offset_bits: union_offset_bits,
        });

        Ok(())
    }

    /// Parse a single DW_TAG_variant and return its info.
    /// Returns None for unit variants (variants with no payload).
    fn parse_variant_members(
        &mut self,
        unit: &UnitRef<R>,
        variant_node: gimli::EntriesTreeNode<R>,
    ) -> Result<Option<VariantInfo>> {
        // Get variant name from DW_AT_name if available on the variant itself
        let entry = variant_node.entry();
        let mut variant_name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_name {
                variant_name = get_attr_string(unit, &attr)?;
            }
        }

        // Collect members of this variant
        let mut members = Vec::new();
        let mut children = variant_node.children();
        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_member
                && let Some(member) = self.parse_struct_member(unit, child.entry())?
            {
                // In Rust's DWARF, the variant name is typically on the first
                // DW_TAG_member child, not on the DW_TAG_variant itself.
                // If we don't have a variant name yet, use the first member's name.
                if variant_name.is_empty() && !member.name.is_empty() {
                    variant_name = member.name.clone();
                }
                members.push(member);
            }
        }

        // Skip unit variants (no payload)
        if members.is_empty() {
            return Ok(None);
        }

        Ok(Some(VariantInfo {
            name: variant_name,
            members,
        }))
    }

    pub(crate) fn parse_struct_member(
        &mut self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<Option<CtfMember>> {
        let mut member_name = String::new();
        let mut member_type_id = None;
        let mut member_offset = 0u64;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    member_name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    // Use resolve_type_attr to handle cross-unit references
                    member_type_id = self.resolve_type_attr(unit, &attr)?;
                }
                gimli::DW_AT_data_member_location => {
                    match attr.value() {
                        AttributeValue::Udata(offset) => {
                            member_offset = offset;
                        }
                        AttributeValue::Sdata(offset) => {
                            member_offset = offset as u64;
                        }
                        AttributeValue::Data1(offset) => {
                            member_offset = offset as u64;
                        }
                        AttributeValue::Data2(offset) => {
                            member_offset = offset as u64;
                        }
                        AttributeValue::Data4(offset) => {
                            member_offset = offset as u64;
                        }
                        AttributeValue::Data8(offset) => {
                            member_offset = offset;
                        }
                        AttributeValue::Exprloc(expr) => {
                            // For simple offsets, the expression is often just DW_OP_plus_uconst
                            // This is a simplified handler - you might need more complex evaluation
                            if let Ok(offset) = eval_simple_location_expr(unit, expr) {
                                member_offset = offset as u64;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        if let Some(type_id) = member_type_id {
            Ok(Some(CtfMember {
                name: member_name,
                type_id,
                offset_bits: member_offset * 8, // DWARF offset is in bytes.
            }))
        } else {
            eprintln!(
                "Warning: skipping struct member '{}' - type not found (cross-unit reference?)",
                member_name
            );
            Ok(None)
        }
    }

    /// Find the unit that contains the given DebugInfoOffset
    fn find_unit_for_offset(
        &self,
        unit: &UnitRef<R>,
        offset: DebugInfoOffset<usize>,
    ) -> Result<Option<Unit<R>>> {
        let target = offset.0;

        // Find which unit range contains this offset
        for range in &self.unit_ranges {
            if target >= range.start && target < range.end {
                // Load the unit
                let header = unit
                    .dwarf
                    .debug_info
                    .header_from_offset(DebugInfoOffset(range.start))?;
                let unit = unit.dwarf.unit(header)?;
                return Ok(Some(unit));
            }
        }

        Ok(None)
    }

    /// Resolve a type reference attribute, handling cross-unit references.
    /// Returns the parsed type ID.
    fn resolve_type_attr(
        &mut self,
        unit: &UnitRef<R>,
        attr: &Attribute<R>,
    ) -> Result<Option<MaybeOffset>> {
        match attr.value() {
            AttributeValue::UnitRef(offset) => Ok(Some(self.parse_type(unit, offset)?)),
            AttributeValue::DebugInfoRef(debug_info_offset) => {
                // Try same unit first
                if let Some(unit_offset) = debug_info_offset.to_unit_offset(&unit.header) {
                    return Ok(Some(self.parse_type(unit, unit_offset)?));
                }

                // Cross-unit reference - find the right unit
                if let Some(target_unit) = self.find_unit_for_offset(unit, debug_info_offset)?
                    && let Some(unit_offset) = debug_info_offset.to_unit_offset(&target_unit.header)
                {
                    let unit_ref = UnitRef::new(unit.dwarf, &target_unit);
                    return Ok(Some(self.parse_type(&unit_ref, unit_offset)?));
                }

                // Could not resolve
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

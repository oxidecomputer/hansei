use anyhow::{Context, Result};
use gimli::{AttributeValue, DebuggingInformationEntry, Reader, UnitOffset, UnitRef};

use super::{get_attr_string, get_attr_type_offset};
use crate::ctf::types::{CtfType, MaybeOffset};
use crate::parser::DwarfParser;

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    pub fn parse_array_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();
        let mut element_type_offset = None;
        let mut index_type_offset = None;
        let mut count = None;

        // Parse attributes of the array_type DIE
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    element_type_offset = get_attr_type_offset(unit, &attr);
                }
                _ => {}
            }
        }

        let element_type = if let Some(off) = element_type_offset {
            self.parse_type(unit, off)?
        } else {
            anyhow::bail!("no element type for array");
        };

        // Parse subrange children to get array dimensions
        let mut tree = unit
            .entries_tree(Some(entry.offset()))
            .context("failed to get array entry tree")?;
        let root = tree.root().context("failed to get array entry tree root")?;

        let mut children = root.children();
        while let Some(child) = children.next().context("failed to get array child")? {
            // TODO handle multi-dimensional arrays
            if child.entry().tag() == gimli::DW_TAG_subrange_type {
                (count, index_type_offset) = self.parse_subrange_count(unit, child.entry())?;
            }
        }

        let count = count.ok_or_else(|| anyhow::anyhow!("no count for array"))?;
        let index_type = if let Some(off) = index_type_offset {
            self.parse_type(unit, off)?
        } else {
            anyhow::bail!("no index type for array");
        };

        let ctf_type = CtfType::Array {
            name,
            element_type,
            index_type,
            nelems: count,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_subrange_count(
        &self,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(Option<u32>, Option<UnitOffset>)> {
        let mut count = None;
        let mut index_type_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_type => {
                    index_type_offset = get_attr_type_offset(unit, &attr);
                }
                gimli::DW_AT_count => match attr.value() {
                    AttributeValue::Sdata(val) => count = Some(val as u32),
                    AttributeValue::Udata(val) => count = Some(val as u32),
                    AttributeValue::Data1(val) => count = Some(val as u32),
                    AttributeValue::Data2(val) => count = Some(val as u32),
                    AttributeValue::Data4(val) => count = Some(val),
                    AttributeValue::Data8(val) => count = Some(val as u32),
                    _ => {}
                },
                _ => {}
            }
        }

        Ok((count, index_type_offset))
    }
}

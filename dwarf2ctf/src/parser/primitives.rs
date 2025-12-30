use anyhow::Result;
use gimli::{AttributeValue, DebuggingInformationEntry, Reader, UnitOffset, UnitRef};

use super::{get_attr_string, get_attr_type_offset};
use crate::ctf::types::{
    CTF_INT_BOOL, CTF_INT_CHAR, CTF_INT_SIGNED, CtfType, MaybeOffset, ctf_int_data,
};
use crate::parser::DwarfParser;

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    pub(crate) fn parse_base_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        enum IntType {
            Signed,
            Unsigned,
            Bool,
            UnsignedChar,
            SignedChar,
        }

        let mut int_type = None;
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_byte_size => {
                    byte_size = match attr.value() {
                        AttributeValue::Udata(size) => size as u32,
                        AttributeValue::Data1(size) => size as u32,
                        AttributeValue::Data2(size) => size as u32,
                        AttributeValue::Data4(size) => size,
                        AttributeValue::Data8(size) => size as u32,
                        AttributeValue::Sdata(size) => size as u32,
                        _ => byte_size,
                    };
                }
                gimli::DW_AT_encoding => {
                    if let AttributeValue::Encoding(enc) = attr.value() {
                        // Map DWARF encoding to CTF encoding
                        int_type = match enc {
                            gimli::DW_ATE_signed => Some(IntType::Signed),
                            gimli::DW_ATE_unsigned => Some(IntType::Unsigned),
                            gimli::DW_ATE_boolean => Some(IntType::Bool),
                            gimli::DW_ATE_signed_char => Some(IntType::SignedChar),
                            gimli::DW_ATE_unsigned_char => Some(IntType::UnsignedChar),
                            gimli::DW_ATE_float => {
                                // For floats, we'll create a float type instead
                                return Ok(self.parse_float_type(offset, name, byte_size));
                            }
                            _ => todo!(),
                        };
                    }
                }
                _ => {}
            }
        }
        let bit_size = byte_size * 8;
        let Some(int_type) = int_type else {
            anyhow::bail!("could not determine integer type from DWARF");
        };
        let encoding = match int_type {
            IntType::Signed => ctf_int_data(CTF_INT_SIGNED, 0, bit_size),
            IntType::Unsigned => ctf_int_data(0, 0, bit_size),
            IntType::SignedChar => ctf_int_data(CTF_INT_SIGNED | CTF_INT_CHAR, 0, bit_size),
            IntType::UnsignedChar => ctf_int_data(CTF_INT_CHAR, 0, bit_size),
            IntType::Bool => ctf_int_data(CTF_INT_BOOL, 0, bit_size),
        };

        let ctf_type = CtfType::Integer {
            name,
            size: byte_size,
            encoding,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub(crate) fn parse_float_type(
        &mut self,
        offset: UnitOffset,
        name: String,
        byte_size: u32,
    ) -> MaybeOffset {
        // Map float size to CTF float encoding
        let encoding = match byte_size {
            4 => ctf_int_data(1, 0, 32),   // CTF_FP_SINGLE
            8 => ctf_int_data(2, 0, 64),   // CTF_FP_DOUBLE
            16 => ctf_int_data(6, 0, 128), // CTF_FP_LDOUBLE
            _ => ctf_int_data(1, 0, byte_size * 8),
        };

        let ctf_type = CtfType::Float {
            name,
            size: byte_size,
            encoding,
        };
        MaybeOffset::Found(self.writer.add_type(offset, ctf_type))
    }

    pub(crate) fn parse_pointer_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target_offset = get_attr_type_offset(unit, &attr);
                }
                _ => {}
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Pointer { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub(crate) fn parse_typedef(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();
        let mut target_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target_offset = get_attr_type_offset(unit, &attr);
                }
                _ => {}
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Typedef { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub(crate) fn parse_const_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target_offset = get_attr_type_offset(unit, &attr);
                }
                _ => {}
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Const { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub(crate) fn parse_volatile_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target_offset = get_attr_type_offset(unit, &attr);
                }
                _ => {}
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Volatile { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    pub(crate) fn parse_restrict_type(
        &mut self,
        offset: UnitOffset,
        unit: &UnitRef<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = get_attr_string(unit, &attr)?;
                }
                gimli::DW_AT_type => {
                    target_offset = get_attr_type_offset(unit, &attr);
                }
                _ => {}
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Restrict { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }
}

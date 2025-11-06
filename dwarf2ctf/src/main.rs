use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use clap::Parser;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use gimli::{
    Attribute, AttributeValue, DW_AT_name, DW_AT_type, DW_TAG_formal_parameter, DW_TAG_subprogram,
    DebuggingInformationEntry, Dwarf, EndianSlice, Reader, RunTimeEndian, Unit, UnitHeader,
};
use goblin::elf::{
    self as elf, Elf,
    header::{EI_CLASS, ELFCLASS64, Header},
    program_header::ProgramHeader,
    section_header::{
        SHN_LORESERVE, SHT_NOBITS, SHT_NULL, SHT_REL, SHT_RELA, SHT_SYMTAB, SectionHeader,
    },
    sym::Sym,
};
use object::elf::{SHN_UNDEF, STT_FUNC, STT_OBJECT};
use object::read::elf::ElfFile64;
use object::write::{self, Object as WriteObject, SectionId, SymbolId};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use object::{Object, ObjectSection, ObjectSymbol};
use scroll::{Pread, Pwrite, ctx::TryIntoCtx};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

// CTF Constants
const CTF_MAGIC: u16 = 0xcff1;
const CTF_VERSION: u8 = 2;
const CTF_F_COMPRESS: u8 = 0x01;

// CTF Type Kinds
const CTF_K_UNKNOWN: u16 = 0;
const CTF_K_INTEGER: u16 = 1;
const CTF_K_FLOAT: u16 = 2;
const CTF_K_POINTER: u16 = 3;
const CTF_K_ARRAY: u16 = 4;
const CTF_K_FUNCTION: u16 = 5;
const CTF_K_STRUCT: u16 = 6;
const CTF_K_UNION: u16 = 7;
const CTF_K_ENUM: u16 = 8;
const CTF_K_FORWARD: u16 = 9;
const CTF_K_TYPEDEF: u16 = 10;
const CTF_K_VOLATILE: u16 = 11;
const CTF_K_CONST: u16 = 12;
const CTF_K_RESTRICT: u16 = 13;

// CTF Integer Encoding Flags
const CTF_INT_SIGNED: u32 = 0x01;
const CTF_INT_CHAR: u32 = 0x02;
const CTF_INT_BOOL: u32 = 0x04;

// CTF Type Info Macros
fn ctf_type_info(kind: u16, is_root: bool, vlen: u16) -> u16 {
    ((kind & 0x1f) << 11) | (if is_root { 1 } else { 0 } << 10) | (vlen & 0x3ff)
}

fn ctf_int_data(encoding: u32, offset: u32, bits: u32) -> u32 {
    ((encoding & 0xff) << 24) | ((offset & 0xff) << 16) | (bits & 0xffff)
}

// CTF Structures
#[derive(Debug)]
#[repr(C)]
struct CtfPreamble {
    magic: u16,
    version: u8,
    flags: u8,
}

#[derive(Debug)]
#[repr(C)]
struct CtfHeader {
    preamble: CtfPreamble,
    parlabel: u32,
    parname: u32,
    lbloff: u32,
    objtoff: u32,
    funcoff: u32,
    typeoff: u32,
    stroff: u32,
    strlen: u32,
}

#[derive(Debug, Clone)]
enum CtfType {
    Integer {
        name: String,
        size: u32,
        encoding: u32,
    },
    Float {
        name: String,
        size: u32,
        encoding: u32,
    },
    Pointer {
        name: String,
        target_type: u16,
    },
    Typedef {
        name: String,
        target_type: u16,
    },
    Const {
        name: String,
        target_type: u16,
    },
    Volatile {
        name: String,
        target_type: u16,
    },
    Restrict {
        name: String,
        target_type: u16,
    },
    Struct {
        name: String,
        size: u32,
        members: Vec<CtfMember>,
    },
    Function {
        name: String,
        return_type: u16,
        args: Vec<u16>,
        is_varargs: bool,
    },
    Unknown,
}

impl CtfType {
    pub fn name(&self) -> &str {
        match self {
            Self::Integer { name, .. } => name,
            Self::Float { name, .. } => name,
            Self::Pointer { name, .. } => name,
            Self::Typedef { name, .. } => name,
            Self::Const { name, .. } => name,
            Self::Volatile { name, .. } => name,
            Self::Restrict { name, .. } => name,
            Self::Struct { name, .. } => name,
            Self::Function { name, .. } => name,
            Self::Unknown => "<unknown>",
        }
    }
}

#[derive(Clone, Debug)]
struct CtfMember {
    name: String,
    type_id: u16,
    offset_bits: u64,
}

#[derive(Clone, Debug)]
struct FunctionInfo<R: Reader<Offset = usize>> {
    name: String,
    return_type_offset: Option<gimli::UnitOffset>,
    args: Vec<(String, gimli::UnitOffset)>,
    unit_header: UnitHeader<R, R::Offset>,
}

#[derive(Clone, Debug)]
struct ParsedFunctionInfo {
    return_type: u16,
    args: Vec<u16>,
}

// String table builder
struct StringTable {
    strings: Vec<u8>,
    offsets: HashMap<String, u32>,
}

impl StringTable {
    fn new() -> Self {
        let mut table = StringTable {
            strings: Vec::new(),
            offsets: HashMap::new(),
        };
        // First byte is always null terminator
        table.strings.push(0);
        table
    }

    fn add_string(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }

        if let Some(&offset) = self.offsets.get(s) {
            return offset;
        }

        let offset = self.strings.len() as u32;
        self.offsets.insert(s.to_string(), offset);
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0); // null terminator
        offset
    }

    fn data(&self) -> &[u8] {
        &self.strings
    }
}

// CTF Writer
struct CtfWriter<'a> {
    elf: &'a ElfFile64<'a>,
    types: Vec<CtfType>,
    strings: StringTable,
    type_map: HashMap<gimli::UnitOffset, u16>, // DWARF offset to CTF type ID
}

impl<'a> CtfWriter<'a> {
    fn new(elf: &'a ElfFile64<'a>) -> Self {
        CtfWriter {
            elf,
            types: Vec::new(),
            strings: StringTable::new(),
            type_map: HashMap::new(),
        }
    }

    fn add_type(&mut self, dwarf_offset: gimli::UnitOffset, ctf_type: CtfType) -> u16 {
        let type_id = (self.types.len() + 1) as u16; // CTF type IDs start at 1
        self.types.push(ctf_type);
        self.type_map.insert(dwarf_offset, type_id);
        type_id
    }

    fn get_type_id(&self, dwarf_offset: gimli::UnitOffset) -> Option<u16> {
        self.type_map.get(&dwarf_offset).copied()
    }

    fn generate_ctf(&mut self, funcs: HashMap<String, ParsedFunctionInfo>) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        let lbloff = 0u32;

        // Calculate type section size and write to string table
        // TODO populate the string table first
        let mut type_data = Vec::new();
        let types = self.types.clone();
        for ctf_type in types {
            self.write_type(&mut type_data, &ctf_type)?;
        }

        let mut text_ct = 0usize;
        let mut data_ct = 0usize;
        let mut obj_data = Vec::new();
        let mut func_data = Vec::new();
        for symbol in self.elf.symbols() {
            let symbol_header = symbol.elf_symbol();
            let st_type = symbol_header.st_type();

            if !matches!(st_type, STT_OBJECT | STT_FUNC) {
                continue;
            }

            if symbol_header.st_shndx.get(Endianness::Little) == SHN_UNDEF {
                continue;
            }

            // Precisely match CTF requirements, a non-zero name should still be included even if
            // we can't retrieve it.
            if symbol_header.st_name.get(Endianness::Little) == 0 {
                continue;
            }
            let symbol_name = symbol.name().unwrap_or("<unknown>");

            if symbol_name == "_START_" || symbol_name == "_END_" {
                continue;
            }

            match st_type {
                STT_FUNC => {
                    text_ct += 1;
                    let Some(func_info) = funcs.get(symbol_name) else {
                        let info = ctf_type_info(CTF_K_UNKNOWN, false, 0);
                        func_data.write_u16::<LittleEndian>(info)?;
                        continue;
                    };

                    eprintln!("TARGET_FN AT IDX {}", text_ct - 1);
                    let vlen = func_info.args.len() as u16;
                    let info = ctf_type_info(CTF_K_FUNCTION, false, vlen);
                    func_data.write_u16::<LittleEndian>(info)?;
                    func_data.write_u16::<LittleEndian>(func_info.return_type)?;

                    // Write argument types
                    for &arg in &func_info.args {
                        func_data.write_u16::<LittleEndian>(dbg!(arg))?;
                    }
                }
                STT_OBJECT => {
                    data_ct += 1;
                    let Some((idx, _)) = self
                        .types
                        .iter()
                        .enumerate()
                        .find(|(_, t)| t.name() == symbol_name)
                    else {
                        obj_data.write_u16::<LittleEndian>(0)?;
                        continue;
                    };
                    obj_data.write_u16::<LittleEndian>(idx as u16)?;
                }
                _ => {}
            }
        }
        eprintln!("FUNCTIONS FOUND: {text_ct}");
        eprintln!("OBJECTS FOUND: {data_ct}");

        let objtoff = lbloff; // No labels
        let funcoff = objtoff + obj_data.len() as u32;
        let func_data_end = funcoff + func_data.len() as u32;
        let func_padding = func_data_end % 4;

        let typeoff = func_data_end + func_padding;
        let stroff = typeoff + type_data.len() as u32;
        let strlen = self.strings.data().len() as u32;

        // Write header
        let header = CtfHeader {
            preamble: CtfPreamble {
                magic: CTF_MAGIC,
                version: CTF_VERSION,
                flags: CTF_F_COMPRESS,
            },
            parlabel: 0,
            parname: 0,
            lbloff,
            objtoff,
            funcoff,
            typeoff,
            stroff,
            strlen,
        };

        // Write preamble
        buffer.write_u16::<LittleEndian>(header.preamble.magic)?;
        buffer.write_u8(header.preamble.version)?;
        buffer.write_u8(header.preamble.flags)?;

        // Write rest of header
        buffer.write_u32::<LittleEndian>(header.parlabel)?;
        buffer.write_u32::<LittleEndian>(header.parname)?;
        buffer.write_u32::<LittleEndian>(header.lbloff)?;
        buffer.write_u32::<LittleEndian>(header.objtoff)?;
        buffer.write_u32::<LittleEndian>(header.funcoff)?;
        buffer.write_u32::<LittleEndian>(header.typeoff)?;
        buffer.write_u32::<LittleEndian>(header.stroff)?;
        buffer.write_u32::<LittleEndian>(header.strlen)?;

        let mut encoder = ZlibEncoder::new(&mut buffer, Compression::fast());

        // Write object section
        encoder.write_all(&obj_data)?;

        // Write function section
        encoder.write_all(&func_data)?;

        // Write function padding
        encoder.write_all(&vec![0u8; func_padding as usize])?;

        // Write type section
        encoder.write_all(&type_data)?;

        // Write string section
        encoder.write_all(self.strings.data())?;

        encoder.finish()?;

        Ok(buffer)
    }

    fn write_type(&mut self, buffer: &mut Vec<u8>, ctf_type: &CtfType) -> Result<()> {
        match ctf_type {
            CtfType::Integer {
                name,
                size,
                encoding,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_INTEGER, true, 0);

                // Write ctf_stype_t
                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*size as u16)?;

                // Write integer encoding
                buffer.write_u32::<LittleEndian>(*encoding)?;
            }

            CtfType::Float {
                name,
                size,
                encoding,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_FLOAT, true, 0);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*size as u16)?;

                buffer.write_u32::<LittleEndian>(*encoding)?;
            }

            CtfType::Pointer { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_POINTER, false, 0);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*target_type)?;
            }

            CtfType::Typedef { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_TYPEDEF, false, 0);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*target_type)?;
            }

            CtfType::Const { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_CONST, false, 0);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*target_type)?;
            }

            CtfType::Volatile { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_VOLATILE, false, 0);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*target_type)?;
            }

            CtfType::Restrict { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_RESTRICT, false, 0);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*target_type)?;
            }

            CtfType::Function {
                name,
                return_type,
                args,
                is_varargs,
            } => {
                let name_offset = self.strings.add_string(name);
                let mut vlen = args.len() as u16;
                if *is_varargs {
                    vlen += 1;
                }
                let info = ctf_type_info(CTF_K_FUNCTION, true, vlen);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*return_type)?;

                // Write argument types
                for &arg in args {
                    buffer.write_u16::<LittleEndian>(arg)?;
                }

                // Write varargs marker if needed
                if *is_varargs {
                    buffer.write_u16::<LittleEndian>(0)?;
                }
            }

            CtfType::Struct {
                name,
                size,
                members,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_STRUCT, true, members.len() as u16);

                buffer.write_u32::<LittleEndian>(name_offset)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(*size as u16)?;

                // Write members
                for member in members {
                    let member_name_offset = self.strings.add_string(&member.name);
                    buffer.write_u32::<LittleEndian>(member_name_offset)?;
                    buffer.write_u16::<LittleEndian>(member.type_id)?;
                    buffer.write_u16::<LittleEndian>(member.offset_bits as u16)?;
                }
            }

            CtfType::Unknown => {
                let info = ctf_type_info(CTF_K_UNKNOWN, false, 0);
                buffer.write_u32::<LittleEndian>(0)?;
                buffer.write_u16::<LittleEndian>(info)?;
                buffer.write_u16::<LittleEndian>(0)?;
            }
        }

        Ok(())
    }
}

// DWARF Parser
struct DwarfParser<'a, R: Reader<Offset = usize>> {
    dwarf: &'a Dwarf<R>,
    writer: CtfWriter<'a>,
}

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    fn new(elf: &'a ElfFile64<'a>, dwarf: &'a Dwarf<R>) -> Self {
        DwarfParser {
            dwarf,
            writer: CtfWriter::new(elf),
        }
    }

    fn get_attr_string(&self, attr: &Attribute<R>) -> Result<String> {
        match attr.value() {
            AttributeValue::DebugStrRef(offset) => {
                let s = self.dwarf.string(offset)?;
                Ok(s.to_string()?.into_owned())
            }
            AttributeValue::String(s) => Ok(s.to_string()?.into_owned()),
            _ => Ok(String::new()),
        }
    }

    fn parse_type(&mut self, unit: &Unit<R>, offset: gimli::UnitOffset) -> Result<u16> {
        // Check if we've already parsed this type
        if let Some(type_id) = self.writer.get_type_id(offset) {
            return Ok(type_id);
        }

        let Ok(mut entries) = unit.entries_at_offset(offset) else {
            anyhow::bail!("type offset {offset:?} not found");
        };

        let (_, entry) = entries.next_dfs()?.context("No entry at offset")?;

        let type_id = match entry.tag() {
            gimli::DW_TAG_base_type => self.parse_base_type(unit, entry, offset)?,
            gimli::DW_TAG_pointer_type => self.parse_pointer_type(unit, entry, offset)?,
            gimli::DW_TAG_typedef => self.parse_typedef(unit, entry, offset)?,
            gimli::DW_TAG_const_type => self.parse_const_type(unit, entry, offset)?,
            gimli::DW_TAG_volatile_type => self.parse_volatile_type(unit, entry, offset)?,
            gimli::DW_TAG_restrict_type => self.parse_restrict_type(unit, entry, offset)?,
            gimli::DW_TAG_structure_type => self.parse_struct_type(unit, entry, offset)?,
            _ => {
                // Unknown type, add placeholder
                self.writer.add_type(offset, CtfType::Unknown)
            }
        };

        Ok(type_id)
    }

    fn parse_base_type(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
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
                    name = self.get_attr_string(&attr)?;
                }
                gimli::DW_AT_byte_size => {
                    if let AttributeValue::Udata(size) = attr.value() {
                        byte_size = size as u32;
                    }
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
                                return self.parse_float_type(entry, offset, name, byte_size);
                            }
                            _ => todo!(), //ctf_int_data(0, 0, byte_size * 8),
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

        let ctf_type = dbg!(CtfType::Integer {
            name,
            size: byte_size,
            encoding,
        });
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_float_type(
        &mut self,
        _entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
        name: String,
        byte_size: u32,
    ) -> Result<u16> {
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
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_pointer_type(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
        let mut target_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == DW_AT_type
                && let AttributeValue::UnitRef(off) = attr.value()
            {
                target_offset = Some(off);
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            0 // void pointer
        };

        let ctf_type = CtfType::Pointer {
            name: String::new(),
            target_type,
        };
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_typedef(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
        let mut name = String::new();
        let mut target_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_attr_string(&attr)?;
                }
                gimli::DW_AT_type => {
                    if let AttributeValue::UnitRef(off) = attr.value() {
                        target_offset = Some(off);
                    }
                }
                _ => {}
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            0
        };

        let ctf_type = CtfType::Typedef { name, target_type };
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_const_type(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
        let mut target_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == DW_AT_type
                && let AttributeValue::UnitRef(off) = attr.value()
            {
                target_offset = Some(off);
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            0
        };

        let ctf_type = CtfType::Const {
            name: String::new(),
            target_type,
        };
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_volatile_type(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
        let mut target_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == DW_AT_type
                && let AttributeValue::UnitRef(off) = attr.value()
            {
                target_offset = Some(off);
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            0
        };

        let ctf_type = CtfType::Volatile {
            name: String::new(),
            target_type,
        };
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_restrict_type(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
        let mut target_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == DW_AT_type
                && let AttributeValue::UnitRef(off) = attr.value()
            {
                target_offset = Some(off);
            }
        }

        let target_type = if let Some(off) = target_offset {
            self.parse_type(unit, off)?
        } else {
            0
        };

        let ctf_type = CtfType::Restrict {
            name: String::new(),
            target_type,
        };
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_struct_type(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
        offset: gimli::UnitOffset,
    ) -> Result<u16> {
        let mut name = String::new();
        let mut byte_size = 0u32;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = self.get_attr_string(&attr)?;
                }
                gimli::DW_AT_byte_size => {
                    if let AttributeValue::Udata(size) = attr.value() {
                        byte_size = size as u32;
                    }
                }
                _ => {}
            }
        }

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

        let ctf_type = CtfType::Struct {
            name,
            size: byte_size,
            members,
        };
        Ok(self.writer.add_type(offset, ctf_type))
    }

    fn parse_struct_member(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<Option<CtfMember>> {
        let mut member_name = String::new();
        let mut member_type_offset = None;
        let mut member_offset = 0u64;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    member_name = self.get_attr_string(&attr)?;
                }
                gimli::DW_AT_type => {
                    if let AttributeValue::UnitRef(type_offset) = attr.value() {
                        member_type_offset = Some(type_offset);
                    }
                }
                gimli::DW_AT_data_member_location => {
                    match attr.value() {
                        AttributeValue::Udata(offset) => {
                            member_offset = offset;
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
                            if let Ok(offset) = self.eval_simple_location_expr(unit, expr) {
                                member_offset = offset as u64;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        if let Some(type_offset) = member_type_offset {
            let type_id = self.parse_type(unit, type_offset)?;

            Ok(Some(CtfMember {
                name: member_name,
                type_id,
                offset_bits: member_offset * 8, // DWARF offset is in bytes.
            }))
        } else {
            Ok(None)
        }
    }

    fn eval_simple_location_expr(&self, unit: &Unit<R>, expr: gimli::Expression<R>) -> Result<u32> {
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
                    todo!();
                }
            }
        }

        Ok(0)
    }

    fn find_functions_recursive(
        &self,
        node: gimli::EntriesTreeNode<R>,
        unit: &gimli::Unit<R>,
        functions: &mut HashMap<String, Symbol>,
        function_info: &mut Vec<FunctionInfo<R>>,
    ) -> Result<bool> {
        if functions.values().all(|s| s.found) {
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
                && let Ok(name) = self.dwarf.attr_string(unit, attr.value())
                && let Ok(name_str) = name.to_string_lossy()
                && let Some(symbol) = functions.get_mut(trim_hash(name_str.as_ref()))
            {
                symbol.found = true;
                let unit_name = unit
                    .name
                    .as_ref()
                    .and_then(|n| n.to_string_lossy().ok())
                    .unwrap_or_default();
                println!("Found {} in unit {unit_name}", symbol.mangled);

                let mut args = Vec::new();

                // DW_AT_type of a function is its return type
                let return_type_offset = self.get_type_offset(entry)?;

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
                        let param_name = self.get_param_name(unit, child.entry())?;

                        if let Some(type_offset) = self.get_type_offset(child.entry())? {
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

    fn find_functions_by_name(
        &self,
        functions: &mut HashMap<String, Symbol>,
    ) -> Result<Vec<FunctionInfo<R>>> {
        let mut function_info = Vec::new();

        let mut iter = self.dwarf.units();
        while let Some(header) = iter.next().context("failed to get next unit header")? {
            let unit = self.dwarf.unit(header).context("failed to read unit")?;

            let mut tree = unit
                .entries_tree(None)
                .context("failed to get entries tree")?;
            let root = tree.root().context("failed to get entry tree root")?;

            self.find_functions_recursive(root, &unit, functions, &mut function_info)?;

            if functions.values().all(|s| s.found) {
                break;
            }
        }

        Ok(function_info)
    }

    fn get_param_name(
        &self,
        unit: &gimli::Unit<R>,
        entry: &gimli::DebuggingInformationEntry<R>,
    ) -> Result<String> {
        if let Some(attr) = entry
            .attr(gimli::DW_AT_name)
            .context("failed to get DW_AT_name offset")?
            && let Ok(name) = self.dwarf.attr_string(unit, attr.value())
        {
            return Ok(name.to_string_lossy()?.into_owned());
        }
        Ok(String::from("<unnamed>"))
    }

    fn get_type_offset(
        &self,
        entry: &gimli::DebuggingInformationEntry<R>,
    ) -> Result<Option<gimli::UnitOffset>> {
        if let Some(type_attr) = entry
            .attr(gimli::DW_AT_type)
            .context("failed to get DW_AT_type offset")?
            && let gimli::AttributeValue::UnitRef(offset) = type_attr.value()
        {
            return Ok(Some(offset));
        }
        Ok(None)
    }

    fn get_dwarf_offsets(
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

            let return_type = if let Some(ret_offset) = func.return_type_offset {
                self.parse_type(&unit, ret_offset)
                    .context("failed to parse return type")?
            } else {
                0 // void
            };
            return_types.push(return_type);

            let mut args = Vec::new();
            for (arg_name, arg_offset) in &func.args {
                let arg_type_id = self
                    .parse_type(&unit, *arg_offset)
                    .context("failed to parse arg type")?;
                println!("  Arg '{}': type ID {}", arg_name, arg_type_id);
                args.push(arg_type_id);
            }

            parsed_funcs.insert(func.name.clone(), ParsedFunctionInfo { return_type, args });
        }

        Ok(parsed_funcs)
    }
}

#[derive(clap::Parser)]
struct Args {
    // TODO: Handle core dumps
    /// The original binary that triggered the core dump.
    #[clap(long, short)]
    source_elf: PathBuf,

    /// The corresponding ELF file with debug symbols.
    #[clap(long, short)]
    debug_elf: PathBuf,

    /// Functions to generate CTF for.
    /// These will be read from stdin if this flag is not passed.
    #[clap(long, short)]
    fns: Vec<String>,

    /// Path to write updated ELF to.
    #[clap(long, short)]
    output: PathBuf,
}

fn trim_hash(sym: &str) -> &str {
    if !sym.ends_with('E') {
        return sym;
    }
    let Some(hash_start) = sym.rfind("17h") else {
        return sym;
    };
    &sym[..hash_start]
}

fn write_elf(ctf_buffer: &[u8], src_elf: &ElfFile64, src_bytes: &[u8]) -> Result<Vec<u8>> {
    //let mut builder = object::build::elf::Builder::read(src_bytes)?;
    //let ctf_section = builder.sections.add();

    //ctf_section.name = ".SUNW_ctf".into();
    //ctf_section.data = object::build::elf::SectionData::Data(ctf_buffer.into());
    //ctf_section.sh_addralign = 4;

    //let mut output = Vec::new();
    //builder.write(&mut output)?;

    // Create new output object
    let mut output = WriteObject::new(
        BinaryFormat::Elf,
        src_elf.architecture(),
        src_elf.endianness(),
    );

    // Map section indices: input -> output
    let mut sections = HashMap::new();

    // Copy all sections
    for section in src_elf.sections() {
        let name = section.name().unwrap_or("<unnamed>");

        // Skip sections that shouldn't be copied or are handled specially
        if name.is_empty() || name == "*UND*" {
            continue;
        }

        let name = section.name()?.as_bytes().to_vec();
        if name.is_empty() {
            continue;
        }

        let kind = section.kind();
        let id = output.add_section(
            vec![],
            name,
            kind,
            //match kind {
            //    object::SectionKind::Text => write::SectionKind::Text,
            //    object::SectionKind::Data => write::SectionKind::Data,
            //    object::SectionKind::ReadOnlyData => write::SectionKind::ReadOnlyData,
            //    object::SectionKind::UninitializedData => write::SectionKind::UninitializedData,
            //    object::SectionKind::Unknown => write::SectionKind::Unknown,
            //    object::SectionKind::ReadOnlyDataWithRel => write::SectionKind::ReadOnlyDataWithRel,
            //    object::SectionKind::Common => write::SectionKind::Common,
            //    object::SectionKind::Tls => write::SectionKind::Tls,
            //    object::SectionKind::TlsVariables => write::SectionKind::TlsVariables,
            //    object::SectionKind::UninitializedTls => write::SectionKind::UninitializedTls,
            //    object::SectionKind::ReadOnlyString => write::SectionKind::ReadOnlyString,
            //    object::SectionKind::Tls => write::SectionKind::Tls,
            //    object::SectionKind::Tls => write::SectionKind::Tls,
            //    _ => write::SectionKind::Other,
            //},
        );

        // BSS sections don't have data in the file, only at runtime
        if kind != object::SectionKind::UninitializedData {
            output
                .section_mut(id)
                .set_data(section.data()?.to_vec(), section.align());
        }
        sections.insert(section.index(), id);
    }

    for symbol in src_elf.symbols() {
        let name = symbol.name().unwrap_or("");

        // Skip undefined symbols (they'll be added as needed)
        if symbol.is_undefined() && name.is_empty() {
            continue;
        }

        if !name.is_empty() {
            println!("  Symbol: {} ({:?})", name, symbol.kind());
        }

        // Determine section
        let section = if let Some(section_index) = symbol.section_index() {
            let idx = sections[&section_index];
            write::SymbolSection::Section(idx)
        } else {
            write::SymbolSection::Undefined
        };

        output.add_symbol(write::Symbol {
            name: symbol
                .name()
                .context("failed to get symbol name")?
                .as_bytes()
                .to_vec(),
            value: symbol.address(),
            size: symbol.size(),
            kind: symbol.kind(),
            scope: symbol.scope(),
            weak: symbol.is_weak(),
            section,
            flags: write::SymbolFlags::None,
        });
    }
    //Copy segments (program headers)
    //Note: object crate handles this automatically when writing

    //Map to track section index translation
    // let mut section_map: HashMap<usize, SectionId> = HashMap::new();
    // let mut symtab_section: Option<SectionId> = None;

    // // First pass: create all sections except CTF
    // for (idx, section) in src_elf.sections().enumerate() {
    //     let name = section.name()?;

    //     let section_id = out_obj.add_section(
    //         Vec::new(),
    //         name.as_bytes().to_vec(),
    //         match section.kind() {
    //             SectionKind::Text => object::write::SectionKind::Text,
    //             SectionKind::Data => object::write::SectionKind::Data,
    //             SectionKind::ReadOnlyData => object::write::SectionKind::ReadOnlyData,
    //             SectionKind::UninitializedData => object::write::SectionKind::UninitializedData,
    //             SectionKind::Common => object::write::SectionKind::Common,
    //             SectionKind::Tls => object::write::SectionKind::Tls,
    //             SectionKind::TlsVariables => object::write::SectionKind::Tls,
    //             SectionKind::Note => object::write::SectionKind::Note,
    //             _ => object::write::SectionKind::Unknown,
    //         },
    //     );

    //     let out_section = out_obj.section_mut(section_id);

    //     // Set section data
    //     out_section.set_data(section.data()?.to_vec(), section.align());

    //     // Track section mapping
    //     section_map.insert(idx, section_id);

    //     // Track symbol table
    //     if section.kind() == SectionKind::Metadata && name == ".symtab" {
    //         symtab_section = Some(section_id);
    //     }
    // }

    // // Copy symbols and update their section indices
    // for symbol in src_elf.symbols() {
    //     let name = symbol.name()?;
    //     let section = symbol
    //         .section_index()
    //         .and_then(|idx| section_map.get(&idx.0).copied());

    //     let _symbol_id = out_obj.add_symbol(write::Symbol {
    //         name: name.as_bytes().to_vec(),
    //         value: symbol.address(),
    //         size: symbol.size(),
    //         kind: match symbol.kind() {
    //             SymbolKind::Text => SymbolKind::Text,
    //             SymbolKind::Data => SymbolKind::Data,
    //             SymbolKind::Section => SymbolKind::Section,
    //             SymbolKind::File => SymbolKind::File,
    //             SymbolKind::Tls => SymbolKind::Tls,
    //             _ => SymbolKind::Unknown,
    //         },
    //         scope: if symbol.is_global() {
    //             SymbolScope::Dynamic
    //         } else if symbol.is_local() {
    //             SymbolScope::Compilation
    //         } else {
    //             SymbolScope::Linkage
    //         },
    //         weak: symbol.is_weak(),
    //         section: write::SymbolSection::Section(section.unwrap()),
    //         flags: SymbolFlags::None,
    //     });
    // }

    // Add CTF section
    let ctf_section_id =
        output.add_section(Vec::new(), b".SUNW_ctf".to_vec(), write::SectionKind::Debug);

    let ctf_section = output.section_mut(ctf_section_id);
    ctf_section.set_data(ctf_buffer, 4);
    // Link to symbol table (note: object crate may handle this differently)

    // Write the ELF file
    let output = output.write().context("failed to write ELF")?;

    Ok(output)
}

/// Return the rewritten ELF bytes.
/// - `src`: source ELF file bytes
/// - `opts`: new CTF + compression flag
pub fn add_or_replace_sunw_ctf(src: &[u8], ctf_data: &[u8]) -> Result<Vec<u8>> {
    // Parse & basic checks
    let elf = Elf::parse(src).context("parsing ELF")?;
    if elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
        anyhow::bail!("Only ELF64 is implemented in this example");
    }
    if !elf.little_endian {
        anyhow::bail!("Only little-endian is implemented in this example");
    }

    let ehdr: Header = elf.header;
    let phdrs: Vec<ProgramHeader> = elf.program_headers.into_iter().collect();

    // Build translation map: drop existing .SUNW_ctf only; keep section order otherwise
    let mut sec_xlate = vec![-1i32; elf.section_headers.len()];
    let mut next_idx = 1i32; // 0 is the null section
    for (i, sh) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or_default();
        sec_xlate[i] = if name == ".SUNW_ctf" {
            -1
        } else {
            let r = next_idx;
            next_idx += 1;
            r
        };
    }

    // Locate .symtab / .dynsym by TYPE (not by entsize)
    let mut symtab_src_i: Option<usize> = None;
    let mut dynsym_src_i: Option<usize> = None;
    for (i, sh) in elf.section_headers.iter().enumerate() {
        match sh.sh_type {
            SHT_SYMTAB if symtab_src_i.is_none() => symtab_src_i = Some(i),
            elf::section_header::SHT_DYNSYM if dynsym_src_i.is_none() => dynsym_src_i = Some(i),
            _ => {}
        }
    }
    // Translate those indices to *destination* indices (post-drop)
    let symtab_dst_idx = symtab_src_i.and_then(|i| translate_index(&sec_xlate, i));
    let dynsym_dst_idx = dynsym_src_i.and_then(|i| translate_index(&sec_xlate, i));

    // Choose link target for .SUNW_ctf: prefer .symtab, else .dynsym
    let link_target: u32 = if let Some(s) = symtab_dst_idx {
        s
    } else if let Some(d) = dynsym_dst_idx {
        d
    } else {
        anyhow::bail!("no SHT_SYMTAB or SHT_DYNSYM present to link .SUNW_ctf");
    };

    // New shstrtab = old + ".SUNW_ctf\0"
    //let mut shstr_bytes = Vec::new();
    //for section in &elf.section_headers {
    //    let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
    //    shstr_bytes.extend_from_slice(name.as_bytes());
    //}
    //let ctf_name_off = shstr_bytes.len();
    //shstr_bytes.extend_from_slice(".SUNW_ctf\0".as_bytes());
    let shstr_src_i = elf.header.e_shstrndx as usize;
    let shstr_sh = elf
        .section_headers
        .get(shstr_src_i)
        .ok_or_else(|| anyhow::anyhow!("bad e_shstrndx: {}", shstr_src_i))?;

    let shstr_off = shstr_sh.sh_offset as usize;
    let shstr_len = shstr_sh.sh_size as usize;
    if shstr_off
        .checked_add(shstr_len)
        .is_none_or(|end| end > src.len())
    {
        anyhow::bail!(
            "original .shstrtab out of range: off={} len={} file={}",
            shstr_off,
            shstr_len,
            src.len()
        );
    }

    // Start with the *raw* .shstrtab contents (not goblin’s parsed view).
    let mut shstr_bytes = src[shstr_off..shstr_off + shstr_len].to_vec();

    // Append the new section name.
    let ctf_name_off = shstr_bytes.len();
    shstr_bytes.extend_from_slice(b".SUNW_ctf\0");

    // Collect kept sections; remap sh_link, sh_info (REL/RELA); capture data slices
    struct Keep<'a> {
        shdr: SectionHeader,
        data: Option<&'a [u8]>,
        name_off: usize,
    }
    let mut keep: Vec<Keep<'_>> = Vec::with_capacity(elf.section_headers.len());
    for (i, sh) in elf.section_headers.iter().enumerate() {
        if sec_xlate[i] < 0 {
            continue; // we're dropping .SUNW_ctf only
        }
        let mut new_sh = sh.clone();

        // Remap sh_link
        if new_sh.sh_link != 0 && (new_sh.sh_link as usize) < sec_xlate.len() {
            let mapped = sec_xlate[new_sh.sh_link as usize];
            new_sh.sh_link = if mapped < 0 { 1 } else { mapped as u32 };
        }
        // Remap REL/RELA sh_info
        if new_sh.sh_type == SHT_REL || new_sh.sh_type == SHT_RELA {
            if new_sh.sh_info != 0 && (new_sh.sh_info as usize) < sec_xlate.len() {
                let mapped = sec_xlate[new_sh.sh_info as usize];
                new_sh.sh_info = if mapped < 0 { 1 } else { mapped as u32 };
            }
        }

        // Capture section payload (if not NOBITS)
        let data = if new_sh.sh_type != SHT_NOBITS && new_sh.sh_size != 0 {
            let start = new_sh.sh_offset as usize;
            let end = start
                .checked_add(new_sh.sh_size as usize)
                .ok_or_else(|| anyhow::anyhow!("section size overflow"))?;
            Some(&src[start..end])
        } else {
            None
        };

        keep.push(Keep {
            shdr: new_sh.clone(),
            name_off: new_sh.sh_name,
            data,
        });
    }

    // ---- Lay out destination ------------------------------------------------
    // Layout: [Ehdr][Phdrs][kept sections...][.SUNW_ctf][.shstrtab(new)][pad][Shdrs]
    let mut out = vec![0; ehdr.e_ehsize as usize]; // space for Ehdr

    // Reserve PHDR bytes (unchanged content; we’ll write them later)
    if ehdr.e_phnum > 0 {
        let phdr_bytes = (ehdr.e_phentsize as usize) * (ehdr.e_phnum as usize);
        out.resize(out.len() + phdr_bytes, 0);
    }
    let mut cur_off = out.len();

    // Section header vector (index 0 = NULL)
    let mut new_shdrs: Vec<SectionHeader> = Vec::with_capacity(keep.len() + 2);
    new_shdrs.push(SectionHeader {
        sh_name: 0,
        sh_type: SHT_NULL,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 0,
        sh_entsize: 0,
    });

    // Copy kept sections' data; recompute sh_offset (packed)
    for sec in &keep {
        let mut sh = sec.shdr.clone();
        let addralign = sh.sh_addralign.max(1);
        align_up(addralign, &mut cur_off, &mut out);
        sh.sh_offset = cur_off as u64;

        if sh.sh_type != SHT_NOBITS
            && let Some(data) = sec.data
        {
            out.extend_from_slice(data);
            cur_off += data.len();
        }
        sh.sh_name = sec.name_off;
        new_shdrs.push(sh);
    }

    // Append new .SUNW_ctf
    let mut ctf_sh = SectionHeader {
        sh_name: ctf_name_off,
        sh_type: elf::section_header::SHT_PROGBITS,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0, // set below
        sh_size: ctf_data.len() as u64,
        sh_link: link_target,
        sh_info: 0,
        sh_addralign: 4,
        sh_entsize: 0,
    };
    align_up(ctf_sh.sh_addralign, &mut cur_off, &mut out);
    ctf_sh.sh_offset = cur_off as u64;
    out.extend_from_slice(ctf_data);
    cur_off += ctf_data.len();
    new_shdrs.push(ctf_sh);

    // Rewrite .shstrtab contents (translate index)
    let new_shstr_i = translate_index(&sec_xlate, elf.header.e_shstrndx as usize)
        .context("translating .shstrtab index")? as usize;
    let shstr_align = new_shdrs[new_shstr_i].sh_addralign.max(1);
    align_up(shstr_align, &mut cur_off, &mut out);
    new_shdrs[new_shstr_i].sh_offset = cur_off as u64;
    new_shdrs[new_shstr_i].sh_size = shstr_bytes.len() as u64;
    out.extend_from_slice(&shstr_bytes);
    cur_off += shstr_bytes.len();

    // Patch st_shndx in any present symbol tables (.symtab and/or .dynsym)
    if let Some(sym_i) = new_shdrs.iter().position(|sh| sh.sh_type == SHT_SYMTAB) {
        rewrite_symtab_section_indices(&mut out, &new_shdrs[sym_i], &sec_xlate)
            .context("patching st_shndx in .symtab")?;
    }
    if let Some(dyn_i) = new_shdrs
        .iter()
        .position(|sh| sh.sh_type == elf::section_header::SHT_DYNSYM)
    {
        rewrite_symtab_section_indices(&mut out, &new_shdrs[dyn_i], &sec_xlate)
            .context("patching st_shndx in .dynsym")?;
    }

    // Emit section header table (aligned)
    let align = core::mem::size_of::<u64>() as u64;
    align_up(align, &mut cur_off, &mut out);

    let shdr_size = size_of::<SectionHeader>();
    let shdr_bytes = new_shdrs.len() * shdr_size;
    let start = out.len();
    out.resize(start + shdr_bytes, 0);

    // Now write each SectionHeader into the reserved region.

    let e_shoff = cur_off as u64;
    let mut woff = start; // equals e_shoff as usize
    for sh in &new_shdrs {
        out.gwrite(sh.clone(), &mut cur_off)
            .context("writing section header")?;
    }

    // Patch ELF header and PHDRs
    {
        let mut new_ehdr = ehdr;
        new_ehdr.e_phoff = if phdrs.is_empty() {
            0
        } else {
            core::mem::size_of::<Header>() as u64
        };
        new_ehdr.e_shoff = e_shoff;
        new_ehdr.e_shnum = new_shdrs.len() as u16;
        new_ehdr.e_shstrndx = new_shstr_i as u16;

        out.pwrite_with(new_ehdr, 0, scroll::LE)
            .context("writing ELF header")?;
    }
    if !phdrs.is_empty() {
        let mut off = core::mem::size_of::<Header>();
        for ph in &phdrs {
            out.gwrite(ph.clone(), &mut off)
                .context("writing program header")?;
        }
    }

    Ok(out)
}

fn align_up(align: u64, cur_off: &mut usize, out: &mut Vec<u8>) {
    if align > 0 {
        let r = *cur_off as u64 % align;
        if r != 0 {
            let pad = (align - r) as usize;
            out.extend(std::iter::repeat_n(0u8, pad));
            *cur_off += pad;
        }
    }
}

fn translate_index(map: &[i32], old: usize) -> Option<u32> {
    let m = *map.get(old)?;
    Some(if m < 0 { 1 } else { m as u32 })
}

fn rewrite_symtab_section_indices(
    out: &mut [u8],
    symtab_sh: &SectionHeader,
    sec_xlate: &[i32],
) -> anyhow::Result<()> {
    use core::mem::size_of;

    // Compute a sane entry size. Some linkers set sh_entsize = 0 or odd values.
    let hard_sz = size_of::<Sym>();
    let entsize = {
        let es = symtab_sh.sh_entsize as usize;
        if es == 0 || es < hard_sz { hard_sz } else { es }
    };

    // Compute how many complete entries actually fit in the section payload.
    let sec_off = symtab_sh.sh_offset as usize;
    let sec_len = symtab_sh.sh_size as usize;
    if sec_off
        .checked_add(sec_len)
        .map_or_else(|| true, |end| end > out.len())
    {
        anyhow::bail!(
            "symbol table range out of bounds: off={} size={} out_len={}",
            sec_off,
            sec_len,
            out.len()
        );
    }
    let count = sec_len / entsize;

    // Walk symbols; only remap indices that are not reserved (like the C code).
    // Note: SHN_XINDEX (0xffff) is reserved and would need SHT_SYMTAB_SHNDX
    // handling; we mirror the C behavior and skip reserved values.
    for i in 0..count {
        let off = sec_off + i * entsize;

        // Read the fixed-size Sym at the start of this entry.
        // Even if entsize > size_of::<Sym>(), Sym is the leading layout.
        let mut sym: Sym = scroll::Pread::pread(out, off)
            .map_err(|e| anyhow::anyhow!("sym read @{}: {}", off, e))?;

        if sym.st_shndx < SHN_LORESERVE as usize {
            let old = sym.st_shndx;
            let mapped = sec_xlate.get(old).copied().unwrap_or(-1);
            sym.st_shndx = if mapped < 0 { 1 } else { mapped as usize };
            scroll::Pwrite::pwrite(out, sym, off)
                .map_err(|e| anyhow::anyhow!("sym write @{}: {}", off, e))?;
        }

        // If entsize > size_of::<Sym>(), there may be padding or vendor data.
        // We leave it untouched.
    }
    Ok(())
}

#[derive(Debug)]
struct Symbol {
    // The mangled name, with hash.
    mangled: String,
    // Did we find this symbol in the DWARF debug info.
    found: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let fns = if args.fns.is_empty() {
        io::read_to_string(io::stdin())?
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    } else {
        args.fns
    };

    let source_bytes = fs::read(&args.source_elf)
        .with_context(|| format!("failed to read {}", args.source_elf.display()))?;
    // let source_elf = object::File::parse(&*source_bytes)?;
    let source_elf = ElfFile64::<object::Endianness>::parse(&*source_bytes)?;
    let source_symbols: HashSet<_> = source_elf.symbols().filter_map(|s| s.name().ok()).collect();

    let missing_fns: Vec<_> = fns
        .iter()
        .filter(|f| !source_symbols.contains(f.as_str()))
        .collect();

    for missing in &missing_fns {
        eprintln!("'{missing}' was not found in {}", args.source_elf.display());
    }
    if !missing_fns.is_empty() {
        std::process::exit(1);
    }

    let mut symbols: HashMap<_, _> = fns
        .into_iter()
        .map(|mangled| {
            let no_hash = trim_hash(&mangled).to_string();

            (
                no_hash.to_string(),
                Symbol {
                    mangled,
                    found: false,
                },
            )
        })
        .collect();

    let debug_data = fs::read(&args.debug_elf)
        .with_context(|| format!("failed to read {}", args.debug_elf.display()))?;
    let debug_file = object::File::parse(&*debug_data)?;

    // Determine endianness from the object file
    let endian = if debug_file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<EndianSlice<RunTimeEndian>> {
        let data = debug_file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[][..]);
        Ok(EndianSlice::new(data, endian))
    };

    let dwarf = Dwarf::load(&load_section)?;
    let mut parser = DwarfParser::new(&source_elf, &dwarf);

    let function_info = parser
        .find_functions_by_name(&mut symbols)
        .context("error finding function in DWARF")?;

    let missing_symbols: Vec<_> = symbols.values().filter(|s| !s.found).collect();
    for missing in &missing_symbols {
        println!(
            "\nFunction '{}' not found in any compilation unit",
            missing.mangled,
        );
    }
    if !missing_symbols.is_empty() {
        std::process::exit(1);
    }

    let parsed_function_info = parser.get_dwarf_offsets(function_info)?;
    let ctf_buffer = parser.writer.generate_ctf(parsed_function_info)?;

    //let updated_elf = write_elf(&ctf_buffer, &source_elf, &source_bytes)?;
    let updated_elf = add_or_replace_sunw_ctf(&source_bytes, &ctf_buffer)?;

    fs::write(&args.output, &updated_elf)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&args.output, fs::Permissions::from_mode(0o755))?;
    }

    //let out_path = format!("{}_ctf.bin", args.source_elf.display());
    //fs::write(&out_path, &ctf_buffer)?;
    //println!("Wrote CTF to '{out_path}'");

    Ok(())
}

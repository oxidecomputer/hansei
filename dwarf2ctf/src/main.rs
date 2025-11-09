use anyhow::{Context, Result};
use clap::Parser;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use gimli::{
    Attribute, AttributeValue, DW_TAG_formal_parameter, DW_TAG_subprogram,
    DebuggingInformationEntry, Dwarf, EndianSlice, Reader, RunTimeEndian, Unit, UnitHeader,
    UnitOffset,
};
use goblin::elf::Elf;
use goblin::elf::header::{EI_CLASS, ELFCLASS64, Header};
use goblin::elf::section_header::{
    SHN_UNDEF, SHT_DYNSYM, SHT_NOBITS, SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SectionHeader,
};
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use memmap2::Mmap;
use scroll::{IOwrite, LE, Pwrite};

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

// CTF Constants
const CTF_MAGIC: u16 = 0xcff1;
const CTF_VERSION: u8 = 2;
const CTF_F_COMPRESS: u8 = 0x01;
const CTF_MAX_VLEN: u16 = 0x3ff;

// CTF Type Kinds
const CTF_K_UNKNOWN: u8 = 0;
const CTF_K_INTEGER: u8 = 1;
const CTF_K_FLOAT: u8 = 2;
const CTF_K_POINTER: u8 = 3;
const CTF_K_ARRAY: u8 = 4;
const CTF_K_FUNCTION: u8 = 5;
const CTF_K_STRUCT: u8 = 6;
const CTF_K_UNION: u8 = 7;
const CTF_K_ENUM: u8 = 8;
const CTF_K_FORWARD: u8 = 9;
const CTF_K_TYPEDEF: u8 = 10;
const CTF_K_VOLATILE: u8 = 11;
const CTF_K_CONST: u8 = 12;
const CTF_K_RESTRICT: u8 = 13;

// CTF Integer Encoding Flags
const CTF_INT_SIGNED: u8 = 0x01;
const CTF_INT_CHAR: u8 = 0x02;
const CTF_INT_BOOL: u8 = 0x04;

// CTF Type Info Macros
fn ctf_type_info(kind: u8, is_root: bool, vlen: u16) -> u16 {
    ((kind as u16) << 11) | (if is_root { 1 } else { 0 } << 10) | (vlen & CTF_MAX_VLEN)
}

fn ctf_int_data(encoding: u8, offset: u8, bits: u32) -> u32 {
    ((encoding as u32) << 24) | ((offset as u32) << 16) | bits
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

#[derive(Clone, Debug)]
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
        target_type: MaybeOffset,
    },
    Typedef {
        name: String,
        target_type: MaybeOffset,
    },
    Const {
        name: String,
        target_type: MaybeOffset,
    },
    Volatile {
        name: String,
        target_type: MaybeOffset,
    },
    Restrict {
        name: String,
        target_type: MaybeOffset,
    },
    Struct {
        name: String,
        size: u32,
        members: Vec<CtfMember>,
    },
    Function {
        name: String,
        return_type: MaybeOffset,
        args: Vec<MaybeOffset>,
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
    type_id: MaybeOffset,
    offset_bits: u64,
}

#[derive(Clone, Debug)]
struct FunctionInfo<R: Reader<Offset = usize>> {
    name: String,
    return_type_offset: Option<UnitOffset>,
    args: Vec<(String, UnitOffset)>,
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
    elf: &'a Elf<'a>,
    types: Vec<CtfType>,
    strings: StringTable,
    type_map: HashMap<UnitOffset, u16>, // DWARF offset to CTF type ID
}

impl<'a> CtfWriter<'a> {
    fn new(elf: &'a Elf<'a>) -> Self {
        CtfWriter {
            elf,
            types: Vec::new(),
            strings: StringTable::new(),
            type_map: HashMap::new(),
        }
    }

    fn add_type(&mut self, offset: UnitOffset, ctf_type: CtfType) -> u16 {
        let type_id = (self.types.len() + 1) as u16; // CTF type IDs start at 1
        self.types.push(ctf_type);
        self.type_map.insert(offset, type_id);
        type_id
    }

    fn generate_ctf(&mut self, funcs: HashMap<String, ParsedFunctionInfo>) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        // Calculate type section size and write to string table
        let mut type_data = Vec::new();
        let types = self.types.clone();

        for ctf_type in types {
            self.write_type(&mut type_data, &ctf_type)?;
        }

        for (name, func) in &funcs {
            println!("Function: {}", name);
            println!("  Arguments:");
            for arg in &func.args {
                let ty = &self.types[(*arg - 1) as usize];
                println!("    {ty:?}");
            }
            let ret_ty = &self.types[func.return_type as usize];
            println!("  Return Type: {ret_ty:?}");
        }

        let mut obj_data = Vec::new();
        let mut func_data = Vec::new();
        for sym in &self.elf.syms {
            if !matches!(sym.st_type(), STT_OBJECT | STT_FUNC) {
                continue;
            }

            if sym.st_shndx == SHN_UNDEF as usize {
                continue;
            }

            if sym.st_name == 0 {
                continue;
            }

            // A non-zero name should still be included even if we can't retrieve it.
            let symbol_name = self.elf.strtab.get_at(sym.st_name).unwrap_or("<unknown>");

            if symbol_name == "_START_" || symbol_name == "_END_" {
                continue;
            }

            match sym.st_type() {
                STT_FUNC => {
                    // Trim the hash to match against different builds.
                    let Some(func_info) = funcs.get(trim_hash(symbol_name)) else {
                        let info = ctf_type_info(CTF_K_UNKNOWN, false, 0);
                        func_data.iowrite_with(info, LE)?;
                        continue;
                    };

                    let vlen = func_info.args.len() as u16;
                    eprintln!("Argument count for {symbol_name}: {vlen}");
                    let info = ctf_type_info(CTF_K_FUNCTION, false, vlen);
                    func_data.iowrite_with(info, LE)?;
                    func_data.iowrite_with(func_info.return_type, LE)?;

                    // Write argument types
                    for &arg in &func_info.args {
                        func_data.iowrite_with(arg, LE)?;
                    }
                }
                STT_OBJECT => {
                    let Some((idx, _)) = self
                        .types
                        .iter()
                        .enumerate()
                        .find(|(_, t)| t.name() == symbol_name)
                    else {
                        obj_data.iowrite_with(0u16, LE)?;
                        continue;
                    };
                    // CTF index starts at one.
                    obj_data.iowrite_with((idx + 1) as u16, LE)?;
                }
                _ => {}
            }
        }

        let lbloff = 0u32;
        let objtoff = lbloff; // No labels

        // No need to pad funcoff, as the header and objects are naturally 2-byte
        // aligned.
        let funcoff = objtoff + obj_data.len() as u32;
        let func_data_end = funcoff + func_data.len() as u32;
        let func_padding = (4 - (func_data_end % 4)) % 4;

        let typeoff = func_data_end + func_padding;
        let stroff = typeoff + type_data.len() as u32;
        let strlen = self.strings.data().len() as u32;

        // Write header
        let header = CtfHeader {
            preamble: CtfPreamble {
                magic: CTF_MAGIC,
                version: CTF_VERSION,
                //flags: CTF_F_COMPRESS,
                flags: 0,
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

        out.iowrite_with(header.preamble.magic, LE)?;
        out.iowrite_with(header.preamble.version, LE)?;
        out.iowrite_with(header.preamble.flags, LE)?;

        out.iowrite_with(header.parlabel, LE)?;
        out.iowrite_with(header.parname, LE)?;
        out.iowrite_with(header.lbloff, LE)?;
        out.iowrite_with(header.objtoff, LE)?;
        out.iowrite_with(header.funcoff, LE)?;
        out.iowrite_with(header.typeoff, LE)?;
        out.iowrite_with(header.stroff, LE)?;
        out.iowrite_with(header.strlen, LE)?;

        //let mut encoder = ZlibEncoder::new(&mut out, Compression::fast());

        //encoder.write_all(&obj_data)?;
        //encoder.write_all(&func_data)?;
        //encoder.write_all(&vec![0u8; func_padding as usize])?;
        //encoder.write_all(&type_data)?;
        //encoder.write_all(self.strings.data())?;
        //encoder.finish()?;
        out.write_all(&obj_data)?;
        out.write_all(&func_data)?;
        out.write_all(&vec![0u8; func_padding as usize])?;
        out.write_all(&type_data)?;
        out.write_all(self.strings.data())?;

        Ok(out)
    }

    fn deref_maybe_type(&self, offset: &MaybeOffset) -> Result<u16> {
        match offset {
            MaybeOffset::Found(f) => Ok(*f),
            MaybeOffset::Pending(p) => self
                .type_map
                .get(p)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("no type index found for {offset:?}")),
        }
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

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;
                buffer.iowrite_with(*encoding, LE)?;
            }

            CtfType::Float {
                name,
                size,
                encoding,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_FLOAT, true, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;
                buffer.iowrite_with(*encoding, LE)?;
            }

            CtfType::Pointer { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_POINTER, false, 0);
                let target_type = self.deref_maybe_type(target_type)?;

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type, LE)?;
            }

            CtfType::Typedef { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_TYPEDEF, false, 0);
                let target_type = self.deref_maybe_type(target_type)?;

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type, LE)?;
            }

            CtfType::Const { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_CONST, false, 0);
                let target_type = self.deref_maybe_type(target_type)?;

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type, LE)?;
            }

            CtfType::Volatile { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_VOLATILE, false, 0);
                let target_type = self.deref_maybe_type(target_type)?;

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type, LE)?;
            }

            CtfType::Restrict { name, target_type } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_RESTRICT, false, 0);
                let target_type = self.deref_maybe_type(target_type)?;

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type, LE)?;
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
                let info = ctf_type_info(CTF_K_FUNCTION, false, vlen);
                let return_type = self.deref_maybe_type(return_type)?;

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(return_type, LE)?;

                // Write argument types
                for arg in args {
                    let arg = self.deref_maybe_type(arg)?;
                    buffer.iowrite_with(arg, LE)?;
                }

                // Write varargs marker if needed
                if *is_varargs {
                    buffer.iowrite_with(0u16, LE)?;
                }
            }

            CtfType::Struct {
                name,
                size,
                members,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_STRUCT, true, members.len() as u16);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;

                // Write members
                for member in members {
                    let type_id = self.deref_maybe_type(&member.type_id)?;
                    let member_name_offset = self.strings.add_string(&member.name);
                    buffer.iowrite_with(member_name_offset, LE)?;
                    buffer.iowrite_with(type_id, LE)?;
                    if *size < 8192 {
                        buffer.iowrite_with(member.offset_bits as u16, LE)?;
                    } else {
                        todo!("ctlm_offsethi/lo");
                    }
                }
            }

            CtfType::Unknown => {
                let info = ctf_type_info(CTF_K_UNKNOWN, false, 0);
                buffer.iowrite_with(0u32, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(0u16, LE)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
enum MaybeOffset {
    Found(u16),
    Pending(UnitOffset),
}

// DWARF Parser
struct DwarfParser<'a, R: Reader<Offset = usize>> {
    dwarf: &'a Dwarf<R>,
    writer: CtfWriter<'a>,
    inflight_types: VecDeque<UnitOffset>,
}

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    fn new(elf: &'a Elf<'a>, dwarf: &'a Dwarf<R>) -> Self {
        DwarfParser {
            dwarf,
            writer: CtfWriter::new(elf),
            inflight_types: VecDeque::new(),
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

    fn parse_type(&mut self, unit: &Unit<R>, offset: UnitOffset) -> Result<MaybeOffset> {
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
            gimli::DW_TAG_base_type => self.parse_base_type(offset, entry)?,
            gimli::DW_TAG_pointer_type => self.parse_pointer_type(offset, unit, entry)?,
            gimli::DW_TAG_typedef => self.parse_typedef(offset, unit, entry)?,
            gimli::DW_TAG_const_type => self.parse_const_type(offset, unit, entry)?,
            gimli::DW_TAG_volatile_type => self.parse_volatile_type(offset, unit, entry)?,
            gimli::DW_TAG_restrict_type => self.parse_restrict_type(offset, unit, entry)?,
            gimli::DW_TAG_subroutine_type => self.parse_function_type(offset, unit, entry)?,
            gimli::DW_TAG_structure_type => self.parse_struct_type(offset, unit, entry)?,
            _ => {
                // Unknown type, add placeholder
                MaybeOffset::Found(self.writer.add_type(offset, CtfType::Unknown))
            }
        };

        //let type_id = self.writer.add_type(offset, ctf_type);

        // Type has been fully parsed, pop it off the stack.
        self.inflight_types.pop_back();

        Ok(maybe_id)
    }

    fn parse_base_type(
        &mut self,
        offset: UnitOffset,
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
                                return Ok(self.parse_float_type(offset, name, byte_size));
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

        let ctf_type = CtfType::Integer {
            name,
            size: byte_size,
            encoding,
        };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_float_type(
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

    fn parse_pointer_type(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

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
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Pointer { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_typedef(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
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
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Typedef { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_const_type(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

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
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Const { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_volatile_type(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

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
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Volatile { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_restrict_type(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut target_offset = None;
        let mut name = String::new();

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
            MaybeOffset::Found(0)
        };

        let ctf_type = CtfType::Restrict { name, target_type };
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
    }

    fn parse_function_type(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
        let mut name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_name {
                name = self.get_attr_string(&attr)?;
            }
        }

        // DW_AT_type of a function is its return type
        let return_type_offset = self.get_type_offset(entry)?;
        let return_type = if let Some(ret_off) = return_type_offset {
            self.parse_type(unit, ret_off)?
        } else {
            MaybeOffset::Found(0)
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
                    if let Some(type_offset) = self.get_type_offset(child.entry())? {
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

    fn parse_struct_type(
        &mut self,
        offset: gimli::UnitOffset,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<MaybeOffset> {
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
        Ok(MaybeOffset::Found(self.writer.add_type(offset, ctf_type)))
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
                if symbol.found {
                    return Ok(false);
                }

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

        if !self.inflight_types.is_empty() {
            anyhow::bail!(
                "{} types still marked as pending after parsing completed: {:?}",
                self.inflight_types.len(),
                self.inflight_types,
            );
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
                    .parse_type(&unit, *arg_offset)
                    .context("failed to parse arg type")?;
                let arg_type_id = match arg_type_id {
                    MaybeOffset::Found(f) => f,
                    MaybeOffset::Pending(p) => panic!("arg offset {p:?} was not resolved"),
                };
                println!("  Arg '{}': type ID {:?}", arg_name, arg_type_id);
                args.push(arg_type_id);
            }

            // Trim hash so we can match against different build hashes.
            parsed_funcs.insert(
                trim_hash(&func.name).to_string(),
                ParsedFunctionInfo { return_type, args },
            );
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

/// Remove the build hash
fn trim_hash(sym: &str) -> &str {
    if !sym.starts_with("_ZN") || !sym.ends_with('E') {
        return sym;
    }

    let Some(hash_start) = sym.rfind("17h") else {
        return sym;
    };

    &sym[..hash_start]
}

/// Copy the source Elf and insert the CTF data into it.
pub fn add_sunw_ctf(src: &[u8], elf: &Elf, ctf_data: &[u8]) -> Result<Vec<u8>> {
    if elf
        .section_headers
        .iter()
        .any(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".SUNW_ctf"))
    {
        anyhow::bail!("source binary already has a .SUNW_ctf section");
    }

    let ehdr = elf.header;
    let phdrs = elf.program_headers.to_vec();

    // --- Prepare shstrtab: copy RAW bytes and append ".SUNW_ctf\0" ---
    let shstr_src_i = ehdr.e_shstrndx as usize;
    let shstr_sh = elf
        .section_headers
        .get(shstr_src_i)
        .ok_or_else(|| anyhow::anyhow!("bad e_shstrndx {}", shstr_src_i))?;

    let shstr_off = shstr_sh.sh_offset as usize;
    let shstr_len = shstr_sh.sh_size as usize;
    if shstr_off
        .checked_add(shstr_len)
        .is_none_or(|end| end > src.len())
    {
        anyhow::bail!(
            "original .shstrtab out of bounds: off={} len={} file={}",
            shstr_off,
            shstr_len,
            src.len()
        );
    }

    let mut shstr_bytes = src[shstr_off..shstr_off + shstr_len].to_vec();
    let ctf_name_off = shstr_bytes.len();
    shstr_bytes.extend_from_slice(b".SUNW_ctf\0");

    // --- Choose link target for .SUNW_ctf: prefer .symtab else .dynsym ---
    let symtab_idx = elf
        .section_headers
        .iter()
        .position(|sh| sh.sh_type == SHT_SYMTAB);
    let dynsym_idx = elf
        .section_headers
        .iter()
        .position(|sh| sh.sh_type == SHT_DYNSYM);

    let link_target = symtab_idx
        .or(dynsym_idx)
        .ok_or_else(|| anyhow::anyhow!("no SHT_SYMTAB or SHT_DYNSYM present to link .SUNW_ctf"))?
        as u32;

    // --- Lay out the new file ---
    // [Ehdr][Phdrs][all original sections (with updated .shstrtab)][.SUNW_ctf][padding][Shdrs]
    let mut out = vec![0; ehdr.e_ehsize as usize]; // reserve Ehdr

    if ehdr.e_phnum > 0 {
        let phdr_bytes = (ehdr.e_phentsize as usize) * (ehdr.e_phnum as usize);
        out.resize(out.len() + phdr_bytes, 0);
    }
    let cur_off = &mut out.len();

    // Build new section headers: index 0 = NULL, then every original section in the same order
    let mut new_shdrs = Vec::with_capacity(elf.section_headers.len() + 2);
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

    // Copy each original section's data (except .shstrtab, which we replace with new bytes)
    for (i, sh) in elf.section_headers.iter().enumerate().skip(1) {
        let mut nsh = sh.clone();
        let addralign = nsh.sh_addralign.max(1);
        align_up(addralign, cur_off, &mut out);
        nsh.sh_offset = *cur_off as u64;

        if nsh.sh_type != SHT_NOBITS {
            if i == shstr_src_i {
                // write our updated shstrtab
                nsh.sh_size = shstr_bytes.len() as u64;
                out.resize(out.len() + shstr_bytes.len(), 0);
                out.gwrite(&*shstr_bytes, cur_off)
                    .context("write new shstrtab")?;
            } else if nsh.sh_size != 0 {
                // copy original payload
                let start = sh.sh_offset as usize;
                let end = start
                    .checked_add(sh.sh_size as usize)
                    .ok_or_else(|| anyhow::anyhow!("section size overflow (index {})", i))?;
                if end > src.len() {
                    anyhow::bail!(
                        "section {} out of bounds: {}..{} > {}",
                        i,
                        start,
                        end,
                        src.len()
                    );
                }
                out.resize(out.len() + sh.sh_size as usize, 0);
                out.gwrite_with(&src[start..end], cur_off, ())
                    .context("write section header")?;
            }
        }
        // Keep sh_name as-is for existing sections (strings still valid; we only appended)
        new_shdrs.push(nsh);
    }

    // Append new .SUNW_ctf section (after all originals)
    let mut ctf_sh = SectionHeader {
        sh_name: ctf_name_off, // offset in *new* shstrtab
        sh_type: SHT_PROGBITS,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0, // set after alignment
        sh_size: ctf_data.len() as u64,
        sh_link: link_target, // point to symtab/dynsym (same index)
        sh_info: 0,
        sh_addralign: 4,
        sh_entsize: 0,
    };
    align_up(ctf_sh.sh_addralign, cur_off, &mut out);
    ctf_sh.sh_offset = *cur_off as u64;

    out.resize(out.len() + ctf_data.len(), 0);
    out.gwrite(ctf_data, cur_off)
        .context("failed to write CTF data")?;

    new_shdrs.push(ctf_sh);

    // Emit section header table at the end (aligned)
    let align = size_of::<u64>() as u64;
    align_up(align, cur_off, &mut out);
    let e_shoff = *cur_off;

    let shdr_size = size_of::<SectionHeader>();
    let shdr_len = new_shdrs.len() * shdr_size;
    let start = out.len();
    out.resize(start + shdr_len, 0);

    // Write section headers
    let woff = &mut start.clone();
    for sh in &new_shdrs {
        out.gwrite_with(sh.clone(), woff, LE.into())
            .context("write section header")?;
    }
    *cur_off = start + shdr_len;

    // Patch ELF header & PHDRs
    {
        let mut new_ehdr = ehdr;
        new_ehdr.e_phoff = if phdrs.is_empty() {
            0
        } else {
            size_of::<Header>() as u64
        };
        new_ehdr.e_shoff = e_shoff as u64;
        new_ehdr.e_shnum = new_shdrs.len() as u16;
        // e_shstrndx stays the SAME index (its content changed, not its position)
        new_ehdr.e_shstrndx = ehdr.e_shstrndx;

        out.pwrite_with(new_ehdr, 0, LE)
            .context("write ELF header")?;
    }

    if !phdrs.is_empty() {
        let off = &mut size_of::<Header>();
        for ph in &phdrs {
            out.gwrite_with(ph.clone(), off, LE.into())
                .context("write program header")?;
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
        // Input is not a pipe or file.
        if io::stdin().is_terminal() {
            eprintln!("WARNING: reading from stdin, which is a tty");
        }

        io::read_to_string(io::stdin())?
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    } else {
        args.fns
    };

    let source_file = File::open(&args.source_elf)
        .with_context(|| format!("failed to open {}", args.source_elf.display()))?;
    let source_bytes = unsafe {
        Mmap::map(&source_file)
            .with_context(|| format!("failed to mmap {}", args.source_elf.display()))?
    };
    let source_elf = Elf::parse(&source_bytes)
        .with_context(|| format!("failed to parse {} as ELF", args.source_elf.display()))?;

    if source_elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
        anyhow::bail!("Only ELF64 is supported");
    }
    if !source_elf.little_endian {
        anyhow::bail!("Only little-endian files are supported");
    }

    let source_symbols: HashSet<_> = source_elf
        .syms
        .iter()
        .filter_map(|sym| source_elf.strtab.get_at(sym.st_name))
        .collect();

    let missing_fns: Vec<_> = fns
        .iter()
        .filter(|f| !source_symbols.contains(f.as_str()))
        .collect();

    for missing in &missing_fns {
        eprintln!("'{missing}' was not found in {}", args.source_elf.display());
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

    let debug_file = File::open(&args.debug_elf)
        .with_context(|| format!("failed to open {}", args.debug_elf.display()))?;
    let debug_bytes = unsafe {
        Mmap::map(&debug_file)
            .with_context(|| format!("failed to mmap {}", args.debug_elf.display()))?
    };
    let debug_elf = Elf::parse(&debug_bytes)
        .with_context(|| format!("failed to parse {} as ELF", args.debug_elf.display()))?;

    if debug_elf.header.e_ident[EI_CLASS] != ELFCLASS64 {
        anyhow::bail!("Only ELF64 is supported");
    }
    if !debug_elf.little_endian {
        anyhow::bail!("Only little-endian files are supported");
    }
    let endian = RunTimeEndian::Little;

    let loader = |section_id: gimli::SectionId| -> Result<EndianSlice<RunTimeEndian>> {
        let name = section_id.name();

        for sh in &debug_elf.section_headers {
            if let Some(section_name) = debug_elf.shdr_strtab.get_at(sh.sh_name)
                && section_name == name
            {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                return Ok(EndianSlice::new(&debug_bytes[start..end], endian));
            }
        }

        // Section not found.
        Ok(EndianSlice::new(&[], endian))
    };

    let dwarf = Dwarf::load(&loader)
        .with_context(|| format!("failed to load DWARF from {}", args.debug_elf.display()))?;
    let mut parser = DwarfParser::new(&source_elf, &dwarf);

    let function_info = parser
        .find_functions_by_name(&mut symbols)
        .context("error finding function in DWARF")?;

    let missing_symbols: Vec<_> = symbols.values().filter(|s| !s.found).collect();
    for missing in &missing_symbols {
        eprintln!(
            "\nFunction '{}' not found in any compilation unit",
            missing.mangled,
        );
    }

    let parsed_function_info = parser
        .get_dwarf_offsets(function_info)
        .context("failed to parse DWARF debug data")?;

    let ctf_buffer = parser
        .writer
        .generate_ctf(parsed_function_info)
        .context("failed to generate CTF")?;

    fs::write("test.ctf", &ctf_buffer)?;

    let updated_elf = add_sunw_ctf(&source_bytes, &source_elf, &ctf_buffer)
        .context("failed to generate updated ELF")?;

    fs::write(&args.output, &updated_elf)
        .with_context(|| format!("failed to write updated ELF to {}", args.output.display()))?;

    let metadata = source_file
        .metadata()
        .with_context(|| format!("failed to stat {}", args.source_elf.display()))?;
    fs::set_permissions(&args.output, metadata.permissions()).with_context(|| {
        format!(
            "failed to set permissions on updated ELF {}",
            args.output.display()
        )
    })?;

    Ok(())
}

use anyhow::{Context, Result};
use clap::Parser;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use gimli::{
    Attribute, AttributeValue, DW_TAG_formal_parameter, DW_TAG_subprogram, DebugInfoOffset,
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
    ((kind as u16) << 11) | ((if is_root { 1u16 } else { 0 }) << 10) | (vlen & CTF_MAX_VLEN)
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
    Array {
        name: String,
        element_type: MaybeOffset,
        index_type: MaybeOffset,
        nelems: u32,
    },
    Struct {
        name: String,
        size: u32,
        members: Vec<CtfMember>,
    },
    Union {
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
            Self::Union { name, .. } => name,
            Self::Function { name, .. } => name,
            Self::Array { name, .. } => name,
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

/// Information about a single Rust enum variant, used when building the tagged union.
#[derive(Clone, Debug)]
struct VariantInfo {
    name: String,
    members: Vec<CtfMember>,
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
        if s.len() >= 1023 {
            // Truncate strings to 1 KiB.
            self.strings.extend_from_slice(&s.as_bytes()[..1020]);
            self.strings.extend_from_slice(b"...");
        } else {
            self.strings.extend_from_slice(s.as_bytes());
        }
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
    label: Option<String>,
}

impl<'a> CtfWriter<'a> {
    fn new(elf: &'a Elf<'a>) -> Self {
        CtfWriter {
            elf,
            // Start null type at index 0 and void type for functions without a return type.
            types: vec![
                CtfType::Unknown,
                CtfType::Integer {
                    name: "void".to_string(),
                    size: 0,
                    encoding: 0,
                },
            ],
            strings: StringTable::new(),
            type_map: HashMap::new(),
            label: None,
        }
    }

    fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }

    fn add_type(&mut self, offset: UnitOffset, ctf_type: CtfType) -> u16 {
        let type_id = (self.types.len()) as u16;
        self.types.push(ctf_type);
        self.type_map.insert(offset, type_id);
        type_id
    }

    /// Add a synthetic type that doesn't correspond to a DWARF entry.
    /// Used for creating anonymous unions/structs for Rust enum variants.
    fn add_synthetic_type(&mut self, ctf_type: CtfType) -> u16 {
        let type_id = (self.types.len()) as u16;
        self.types.push(ctf_type);
        type_id
    }

    fn generate_ctf(&mut self, funcs: HashMap<String, ParsedFunctionInfo>) -> Result<Vec<u8>> {
        let mut out = Vec::new();

        // Calculate type section size and write to string table
        let mut type_data = Vec::new();
        let types = self.types.clone();

        // Skip the initial placeholder item.
        for ctf_type in types.iter().skip(1) {
            self.write_type(&mut type_data, ctf_type)?;
        }

        for (name, func) in &funcs {
            println!("Function: {}", name);
            println!("  Arguments:");
            for arg in &func.args {
                let ty = &self.types[(*arg) as usize];
                println!("    {ty:?}");
            }
            let ret_ty = &self.types[func.return_type as usize];
            println!("  Return Type: {ret_ty:?}");
        }

        let mut lbl_data = Vec::new();
        if let Some(label) = &self.label {
            let label_name_off = self.strings.add_string(label);
            let last_type_idx = self.types.len() as u32;
            lbl_data.iowrite_with(label_name_off, LE)?;
            lbl_data.iowrite_with(last_type_idx, LE)?;
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
                    obj_data.iowrite_with(idx as u16, LE)?;
                }
                _ => {}
            }
        }

        let lbloff = 0u32;
        let objtoff = lbloff + lbl_data.len() as u32;

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

        //encoder.write_all(&lbl_data)?;
        //encoder.write_all(&obj_data)?;
        //encoder.write_all(&func_data)?;
        //encoder.write_all(&vec![0u8; func_padding as usize])?;
        //encoder.write_all(&type_data)?;
        //encoder.write_all(self.strings.data())?;
        //encoder.finish()?;
        out.write_all(&lbl_data)?;
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

                // Pad vlen to an even number for alignment.
                if !vlen.is_multiple_of(2) {
                    buffer.iowrite_with(0u16, LE)?;
                }
            }

            CtfType::Array {
                name,
                element_type,
                index_type,
                nelems,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_ARRAY, true, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(0u16, LE)?;
                let element_id = self.deref_maybe_type(element_type)?;
                buffer.iowrite_with(element_id, LE)?;
                let index_id = self.deref_maybe_type(index_type)?;
                buffer.iowrite_with(index_id, LE)?;
                buffer.iowrite_with(*nelems, LE)?;
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

            CtfType::Union {
                name,
                size,
                members,
            } => {
                let name_offset = self.strings.add_string(name);
                let info = ctf_type_info(CTF_K_UNION, true, members.len() as u16);

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

#[derive(Copy, Clone, Debug)]
enum MaybeOffset {
    Found(u16),
    Pending(UnitOffset),
}

// DWARF Parser
/// Represents a unit's offset range for quick lookups
struct UnitRange {
    start: usize,
    end: usize,
}

struct DwarfParser<'a, R: Reader<Offset = usize>> {
    dwarf: &'a Dwarf<R>,
    writer: CtfWriter<'a>,
    inflight_types: VecDeque<UnitOffset>,
    /// Index of unit ranges for cross-unit reference resolution
    unit_ranges: Vec<UnitRange>,
}

impl<'a, R: Reader<Offset = usize>> DwarfParser<'a, R> {
    fn new(elf: &'a Elf<'a>, dwarf: &'a Dwarf<R>) -> Result<Self> {
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

    /// Find the unit that contains the given DebugInfoOffset
    fn find_unit_for_offset(&self, offset: DebugInfoOffset<usize>) -> Result<Option<Unit<R>>> {
        let target = offset.0;

        // Find which unit range contains this offset
        for range in &self.unit_ranges {
            if target >= range.start && target < range.end {
                // Load the unit
                let header = self
                    .dwarf
                    .debug_info
                    .header_from_offset(DebugInfoOffset(range.start))?;
                let unit = self.dwarf.unit(header)?;
                return Ok(Some(unit));
            }
        }

        Ok(None)
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

    /// Build the namespace path for a DIE by walking up through parent DIEs.
    /// Returns the full path like "tokio::runtime::scheduler::multi_thread::handle"
    fn get_namespace_path(&self, unit: &Unit<R>, offset: UnitOffset) -> Result<Vec<String>> {
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
                        Some(self.get_attr_string(&attr)?)
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

    /// Get a fully qualified type name by prepending namespace path
    fn get_qualified_name(&self, unit: &Unit<R>, offset: UnitOffset, name: &str) -> Result<String> {
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

    /// Extract a UnitOffset from a type reference attribute value.
    /// Handles both UnitRef (unit-relative) and DebugInfoRef (absolute) references.
    /// For cross-unit references, returns None - use resolve_type_attr for those.
    fn get_attr_type_offset(&self, unit: &Unit<R>, attr: &Attribute<R>) -> Option<UnitOffset> {
        match attr.value() {
            AttributeValue::UnitRef(offset) => Some(offset),
            AttributeValue::DebugInfoRef(debug_info_offset) => {
                // Try to convert to unit offset (works if same unit)
                debug_info_offset.to_unit_offset(&unit.header)
            }
            _ => None,
        }
    }

    /// Resolve a type reference attribute, handling cross-unit references.
    /// Returns the parsed type ID.
    fn resolve_type_attr(
        &mut self,
        unit: &Unit<R>,
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
                if let Some(target_unit) = self.find_unit_for_offset(debug_info_offset)? {
                    if let Some(unit_offset) = debug_info_offset.to_unit_offset(&target_unit.header)
                    {
                        return Ok(Some(self.parse_type(&target_unit, unit_offset)?));
                    }
                }

                // Could not resolve
                Ok(None)
            }
            _ => Ok(None),
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
                    target_offset = self.get_attr_type_offset(unit, &attr);
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
                    target_offset = self.get_attr_type_offset(unit, &attr);
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
                    target_offset = self.get_attr_type_offset(unit, &attr);
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
                    target_offset = self.get_attr_type_offset(unit, &attr);
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
                    target_offset = self.get_attr_type_offset(unit, &attr);
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
        let return_type_offset = self.get_type_offset(unit, entry)?;
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
                    if let Some(type_offset) = self.get_type_offset(unit, child.entry())? {
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

    fn parse_array_type(
        &mut self,
        offset: UnitOffset,
        unit: &Unit<R>,
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
                    name = self.get_attr_string(&attr)?;
                }
                gimli::DW_AT_type => {
                    element_type_offset = self.get_attr_type_offset(unit, &attr);
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
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<(Option<u32>, Option<UnitOffset>)> {
        let mut count = None;
        let mut index_type_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_type => {
                    index_type_offset = self.get_attr_type_offset(unit, &attr);
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
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let qualified_name = self.get_qualified_name(unit, offset, &name)?;

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

    fn parse_union_type(
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
                _ => {}
            }
        }

        // Get qualified name with namespace prefix
        let qualified_name = self.get_qualified_name(unit, offset, &name)?;

        let mut members = Vec::new();
        let mut tree = unit.entries_tree(Some(offset))?;
        let root = tree.root()?;

        let mut children = root.children();
        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_member {
                if let Some(member) = self.parse_struct_member(unit, child.entry())? {
                    members.push(member);
                }
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
    fn parse_enum_type(
        &mut self,
        offset: UnitOffset,
        _unit: &Unit<R>,
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
                _ => {}
            }
        }

        // Represent the enum as an integer type with the same size.
        // This allows MDB to at least know the size and treat it as a value.
        let encoding = ctf_int_data(0, 0, byte_size * 8); // unsigned integer
        let ctf_type = CtfType::Integer {
            name,
            size: byte_size,
            encoding,
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
        unit: &Unit<R>,
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
            if attr.name() == gimli::DW_AT_discr {
                if let AttributeValue::UnitRef(off) = attr.value() {
                    discr_offset = Some(off);
                }
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
                    if let Some(ctf_type) = self.writer.types.get(*type_id as usize) {
                        match ctf_type {
                            CtfType::Integer { size, .. } => (*size as u64) * 8,
                            _ => 0,
                        }
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
        let union_offset_bits = if min_variant_member_offset == 0
            && discr_member.is_some()
            && discr_size_bits > 0
        {
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
                    type_id: m.type_id.clone(),
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
                && (adjusted_members[0].name.is_empty()
                    || adjusted_members[0].name == variant.name)
            {
                // Single member at offset 0 (unnamed or same name as variant) - use its type directly
                adjusted_members[0].type_id.clone()
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
        unit: &Unit<R>,
        variant_node: gimli::EntriesTreeNode<R>,
    ) -> Result<Option<VariantInfo>> {
        // Get variant name from DW_AT_name if available on the variant itself
        let entry = variant_node.entry();
        let mut variant_name = String::new();

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::DW_AT_name {
                variant_name = self.get_attr_string(&attr)?;
            }
        }

        // Collect members of this variant
        let mut members = Vec::new();
        let mut children = variant_node.children();
        while let Some(child) = children.next()? {
            if child.entry().tag() == gimli::DW_TAG_member {
                if let Some(member) = self.parse_struct_member(unit, child.entry())? {
                    // In Rust's DWARF, the variant name is typically on the first
                    // DW_TAG_member child, not on the DW_TAG_variant itself.
                    // If we don't have a variant name yet, use the first member's name.
                    if variant_name.is_empty() && !member.name.is_empty() {
                        variant_name = member.name.clone();
                    }
                    members.push(member);
                }
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

    fn parse_struct_member(
        &mut self,
        unit: &Unit<R>,
        entry: &DebuggingInformationEntry<R>,
    ) -> Result<Option<CtfMember>> {
        let mut member_name = String::new();
        let mut member_type_id = None;
        let mut member_offset = 0u64;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    member_name = self.get_attr_string(&attr)?;
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
                let return_type_offset = self.get_type_offset(unit, entry)?;

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

                        if let Some(type_offset) = self.get_type_offset(unit, child.entry())? {
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
        unit: &Unit<R>,
        entry: &gimli::DebuggingInformationEntry<R>,
    ) -> Result<Option<gimli::UnitOffset>> {
        if let Some(type_attr) = entry
            .attr(gimli::DW_AT_type)
            .context("failed to get DW_AT_type offset")?
        {
            match type_attr.value() {
                gimli::AttributeValue::UnitRef(offset) => return Ok(Some(offset)),
                gimli::AttributeValue::DebugInfoRef(debug_info_offset) => {
                    return Ok(debug_info_offset.to_unit_offset(&unit.header));
                }
                _ => {}
            }
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

    /// Path to write CTF to.
    #[clap(long, short)]
    ctf_output: Option<PathBuf>,

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
                    .ok_or_else(|| anyhow::anyhow!("section size overflow (index {i})"))?;
                if end > src.len() {
                    anyhow::bail!("section {i} out of bounds: {start}..{end} > {}", src.len());
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
    let mut parser = DwarfParser::new(&source_elf, &dwarf)?;

    let label = args
        .source_elf
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| args.source_elf.display().to_string());
    parser.writer.set_label(label);

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

    if let Some(ctf_path) = &args.ctf_output {
        fs::write(ctf_path, &ctf_buffer)?;
    }

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

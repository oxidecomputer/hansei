use crate::constants::*;
use crate::{IntegerEncoding, TypeId};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use goblin::elf::Elf;
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use scroll::{IOwrite, LE};

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write};

pub use error::Error;

mod error;

pub type Result<T> = std::result::Result<T, Error>;

pub fn ctf_type_info(kind: u8, is_root: bool, vlen: u16) -> u16 {
    ((kind as u16) << 11) | ((if is_root { 1u16 } else { 0 }) << 10) | (vlen & CTF_MAX_VLEN)
}

pub fn ctf_int_data(encoding: u8, offset: u8, bits: u32) -> u32 {
    ((encoding as u32) << 24) | ((offset as u32) << 16) | bits
}

// String table builder
pub struct StringTable {
    strings: Vec<u8>,
    offsets: HashMap<String, u32>,
    truncate_len: Option<usize>,
    replace_space: Option<&'static str>,
}

impl StringTable {
    pub fn new(truncate_len: Option<usize>, replace_space: Option<&'static str>) -> Self {
        let mut table = StringTable {
            strings: Vec::new(),
            offsets: HashMap::new(),
            truncate_len,
            replace_space,
        };
        // First byte is always null terminator
        table.strings.push(0);
        table
    }

    pub fn add_string(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }

        if let Some(&offset) = self.offsets.get(s) {
            return offset;
        }

        let offset = self.strings.len() as u32;
        self.offsets.insert(s.to_string(), offset);
        let mut updated = Cow::Borrowed(s);

        if let Some(replace) = self.replace_space {
            updated = s.replace(' ', replace).into();
        }

        if let Some(max_len) = self.truncate_len
            && updated.len() > max_len
        {
            self.strings
                .extend_from_slice(&updated.as_bytes()[..max_len]);
        } else {
            self.strings.extend_from_slice(updated.as_bytes());
        }

        self.strings.push(0); // null terminator
        offset
    }

    pub fn data(&self) -> &[u8] {
        &self.strings
    }
}

pub struct CtfWriter<'a> {
    pub types: Vec<CtfType>,
    pub strings: StringTable,
    elf: Option<&'a Elf<'a>>,
    label: Option<String>,
}

impl Default for CtfWriter<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CtfWriter<'a> {
    /// Construct a new `CtfWriter`.
    pub fn new() -> Self {
        Self::_new(Opts::default())
    }

    fn _new(opts: Opts<'a>) -> Self {
        CtfWriter {
            // Start null type at index 0 and void type for functions without a return type.
            types: vec![
                CtfType::Unknown,
                CtfType::Integer {
                    name: "void".to_string(),
                    size: 0,
                    encoding: IntegerEncoding::default(),
                },
            ],
            strings: StringTable::new(opts.truncate_str_len, opts.replace_spaces),
            elf: opts.elf,
            label: opts.label,
        }
    }

    /// Add a type to the writer. Returns the assigned type ID.
    pub fn add_type(&mut self, ctf_type: CtfType) -> TypeId {
        let type_offset = self.types.len() as u16;
        let type_id = TypeId::from_u16(type_offset).unwrap();

        self.types.push(ctf_type);
        type_id
    }

    /// Reserve a type ID by adding a placeholder. Returns the reserved ID.
    /// Use `set_type` to replace the placeholder with the actual type.
    pub fn reserve_type_id(&mut self) -> TypeId {
        let type_offset = self.types.len() as u16;
        let type_id = TypeId::from_u16(type_offset).unwrap();

        self.types.push(CtfType::Unknown); // placeholder
        type_id
    }

    /// Replace a placeholder type at the given ID with the actual type.
    /// The type_id must have been previously reserved with `reserve_type_id`.
    pub fn set_type(&mut self, type_id: TypeId, ctf_type: CtfType) {
        self.types[type_id.get() as usize] = ctf_type;
    }

    /// Add crate version markers as typedef types.
    ///
    /// Each crate version is encoded as a typedef named `__CRATE_<name-version>__`
    /// pointing to void. This allows consumers to extract dependency information.
    pub fn add_crate_versions<'b>(&mut self, crates: impl IntoIterator<Item = &'b String>) {
        for crate_id in crates {
            let name = format!("__CRATE_{crate_id}__");
            self.add_type(CtfType::Typedef {
                name,
                target_type: TypeId::void(),
            });
        }
    }

    pub fn generate_ctf(&mut self, funcs: HashMap<String, CtfFunctionInfo>) -> Result<Vec<u8>> {
        self._generate_ctf(funcs).map_err(Error::write)
    }

    fn _generate_ctf(&mut self, funcs: HashMap<String, CtfFunctionInfo>) -> io::Result<Vec<u8>> {
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
                let ty = &self.types[arg.get() as usize];
                println!("    {ty:?}");
            }
            let ret_ty = &self.types[func.return_type.get() as usize];
            println!("  Return Type: {ret_ty:?}");
        }

        let mut lbl_data = Vec::new();
        if let Some(label) = &self.label {
            let label_name_off = self.strings.add_string(label);
            let last_type_idx = (self.types.len() - 1) as u32;
            lbl_data.iowrite_with(label_name_off, LE)?;
            lbl_data.iowrite_with(last_type_idx, LE)?;
        }

        let mut obj_data = Vec::new();
        let mut func_data = Vec::new();
        if let Some(elf) = &self.elf {
            for sym in &elf.syms {
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
                let symbol_name = elf.strtab.get_at(sym.st_name).unwrap_or("<unknown>");

                if symbol_name == "_START_" || symbol_name == "_END_" {
                    continue;
                }

                match sym.st_type() {
                    STT_FUNC => {
                        let Some(func_info) = funcs.get(symbol_name) else {
                            let info = ctf_type_info(CTF_K_UNKNOWN, false, 0);
                            func_data.iowrite_with(info, LE)?;
                            continue;
                        };

                        let vlen = func_info.args.len() as u16;
                        eprintln!("Argument count for {symbol_name}: {vlen}");
                        let info = ctf_type_info(CTF_K_FUNCTION, false, vlen);
                        func_data.iowrite_with(info, LE)?;
                        func_data.iowrite_with(func_info.return_type.get(), LE)?;

                        // Write argument types
                        for &arg in &func_info.args {
                            func_data.iowrite_with(arg.get(), LE)?;
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

        let mut encoder = ZlibEncoder::new(&mut out, Compression::fast());

        encoder.write_all(&lbl_data)?;
        encoder.write_all(&obj_data)?;
        encoder.write_all(&func_data)?;
        encoder.write_all(&vec![0u8; func_padding as usize])?;
        encoder.write_all(&type_data)?;
        encoder.write_all(self.strings.data())?;
        encoder.finish()?;
        out.write_all(&lbl_data)?;
        out.write_all(&obj_data)?;
        out.write_all(&func_data)?;
        out.write_all(&vec![0u8; func_padding as usize])?;
        out.write_all(&type_data)?;
        out.write_all(self.strings.data())?;

        Ok(out)
    }

    fn write_type(&mut self, buffer: &mut Vec<u8>, ctf_type: &CtfType) -> io::Result<()> {
        Self::write_type_impl(buffer, &mut self.strings, ctf_type)
    }

    fn write_type_impl(
        buffer: &mut Vec<u8>,
        strings: &mut StringTable,
        ctf_type: &CtfType,
    ) -> io::Result<()> {
        match ctf_type {
            CtfType::Integer {
                name,
                size,
                encoding,
            } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_INTEGER, true, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;
                buffer.iowrite_with(encoding.as_u32(), LE)?;
            }
            CtfType::Float {
                name,
                size,
                encoding,
            } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_FLOAT, true, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;
                buffer.iowrite_with(*encoding, LE)?;
            }
            CtfType::Pointer { name, target_type } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_POINTER, false, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type.get(), LE)?;
            }
            CtfType::Typedef { name, target_type } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_TYPEDEF, false, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type.get(), LE)?;
            }
            CtfType::Const { name, target_type } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_CONST, false, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type.get(), LE)?;
            }
            CtfType::Volatile { name, target_type } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_VOLATILE, false, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type.get(), LE)?;
            }
            CtfType::Restrict { name, target_type } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_RESTRICT, false, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(target_type.get(), LE)?;
            }
            CtfType::Function {
                name,
                return_type,
                args,
                is_varargs,
            } => {
                let name_offset = strings.add_string(name);
                let mut vlen = args.len() as u16;
                if *is_varargs {
                    vlen += 1;
                }
                let info = ctf_type_info(CTF_K_FUNCTION, false, vlen);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(return_type.get(), LE)?;

                // Write argument types
                for arg in args {
                    buffer.iowrite_with(arg.get(), LE)?;
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
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_ARRAY, true, 0);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(0u16, LE)?;
                buffer.iowrite_with(element_type.get(), LE)?;
                buffer.iowrite_with(index_type.get(), LE)?;
                buffer.iowrite_with(*nelems, LE)?;
            }
            CtfType::Struct {
                name,
                size,
                members,
            } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_STRUCT, true, members.len() as u16);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;

                // Write members
                for member in members {
                    let member_name_offset = strings.add_string(&member.name);
                    buffer.iowrite_with(member_name_offset, LE)?;
                    buffer.iowrite_with(member.type_id.get(), LE)?;
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
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_UNION, true, members.len() as u16);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;

                // Write members
                for member in members {
                    let member_name_offset = strings.add_string(&member.name);
                    buffer.iowrite_with(member_name_offset, LE)?;
                    buffer.iowrite_with(member.type_id.get(), LE)?;
                    if *size < 8192 {
                        buffer.iowrite_with(member.offset_bits as u16, LE)?;
                    } else {
                        todo!("ctlm_offsethi/lo");
                    }
                }
            }
            CtfType::Enum {
                name,
                size,
                enumerators,
            } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type_info(CTF_K_ENUM, true, enumerators.len() as u16);

                buffer.iowrite_with(name_offset, LE)?;
                buffer.iowrite_with(info, LE)?;
                buffer.iowrite_with(*size as u16, LE)?;

                for enumerator in enumerators {
                    let enum_name_offset = strings.add_string(&enumerator.name);
                    buffer.iowrite_with(enum_name_offset, LE)?;
                    buffer.iowrite_with(enumerator.value, LE)?;
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

#[derive(Default, Debug)]
struct Opts<'a> {
    elf: Option<&'a Elf<'a>>,
    truncate_str_len: Option<usize>,
    replace_spaces: Option<&'static str>,
    label: Option<String>,
}

#[derive(Default, Debug)]
pub struct CtfWriterBuilder<'a> {
    opts: Opts<'a>,
}

impl<'a> CtfWriterBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> CtfWriter<'a> {
        CtfWriter::_new(self.opts)
    }

    /// The ELF file to pull symbols from. If present this will be used to
    /// generate function type info in the CTF file.
    pub fn with_elf(mut self, elf: &'a Elf<'a>) -> Self {
        self.opts.elf = Some(elf);
        self
    }

    /// Strings longer than this value will be truncated to this length.
    /// Some illumos CTF tooling will fail if a string is longer than their
    /// buffer length.
    pub fn with_truncate_str_len(mut self, len: usize) -> Self {
        self.opts.truncate_str_len = Some(len);
        self
    }

    /// The character to replace spaces with in type names.
    /// Some illumos CTF tooling cannot parse a type name that contains a
    /// space.
    pub fn with_replace_spaces(mut self, replace: &'static str) -> Self {
        self.opts.replace_spaces = Some(replace);
        self
    }

    /// The label to apply to the CTF file.
    pub fn with_label(mut self, label: String) -> Self {
        self.opts.label = Some(label);
        self
    }
}

/// Parsed function info with CTF type IDs.
#[derive(Clone, Debug)]
pub struct CtfFunctionInfo {
    pub return_type: TypeId,
    pub args: Vec<TypeId>,
}

#[derive(Clone, Debug)]
pub enum CtfType {
    Integer {
        name: String,
        size: u32,
        encoding: IntegerEncoding,
    },
    Float {
        name: String,
        size: u32,
        encoding: u32,
    },
    Pointer {
        name: String,
        target_type: TypeId,
    },
    Typedef {
        name: String,
        target_type: TypeId,
    },
    Const {
        name: String,
        target_type: TypeId,
    },
    Volatile {
        name: String,
        target_type: TypeId,
    },
    Restrict {
        name: String,
        target_type: TypeId,
    },
    Array {
        name: String,
        element_type: TypeId,
        index_type: TypeId,
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
    Enum {
        name: String,
        size: u32,
        enumerators: Vec<CtfEnumerator>,
    },
    Function {
        name: String,
        return_type: TypeId,
        args: Vec<TypeId>,
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
            Self::Enum { name, .. } => name,
            Self::Function { name, .. } => name,
            Self::Array { name, .. } => name,
            Self::Unknown => "<unknown>",
        }
    }

    /// Returns true if this is a struct with any member at offset 0.
    pub fn has_member_with_zero_offset(&self) -> bool {
        let Self::Struct { members, .. } = self else {
            return false;
        };
        members.iter().any(|m| m.offset_bits == 0)
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CtfPreamble {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct CtfHeader {
    pub preamble: CtfPreamble,
    pub parlabel: u32,
    pub parname: u32,
    pub lbloff: u32,
    pub objtoff: u32,
    pub funcoff: u32,
    pub typeoff: u32,
    pub stroff: u32,
    pub strlen: u32,
}

#[derive(Clone, Debug)]
pub struct CtfEnumerator {
    pub name: String,
    pub value: i32,
}

#[derive(Clone, Debug)]
pub struct CtfMember {
    pub name: String,
    pub type_id: TypeId,
    pub offset_bits: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::IntegerFlags;

    // Helper to write a type and return the buffer bytes
    fn write_type(ctf_type: &CtfType) -> Vec<u8> {
        let mut buffer = Vec::new();
        let mut strings = StringTable::new(None, None);
        CtfWriter::write_type_impl(&mut buffer, &mut strings, ctf_type).unwrap();
        buffer
    }

    #[test]
    fn test_string_table_starts_with_null() {
        let table = StringTable::new(None, None);
        assert_eq!(table.data(), &[0]);
    }

    #[test]
    fn test_string_table_empty_string_returns_zero() {
        let mut table = StringTable::new(None, None);
        let offset = table.add_string("");
        assert_eq!(offset, 0);
        // Table should still just have the null byte
        assert_eq!(table.data(), &[0]);
    }

    #[test]
    fn test_string_table_add_string() {
        let mut table = StringTable::new(None, None);
        let offset = table.add_string("foo");
        assert_eq!(offset, 1); // After initial null byte
        assert_eq!(table.data(), b"\0foo\0");
    }

    #[test]
    fn test_string_table_deduplication() {
        let mut table = StringTable::new(None, None);
        let off1 = table.add_string("foo");
        let off2 = table.add_string("bar");
        let off3 = table.add_string("foo"); // duplicate

        assert_eq!(off1, off3); // Same string, same offset
        assert_ne!(off1, off2); // Different strings, different offsets
        // "foo" should only appear once
        assert_eq!(table.data(), b"\0foo\0bar\0");
    }

    #[test]
    fn test_string_table_truncates_long_strings() {
        let mut table = StringTable::new(Some(1025), None);
        let long_string = "x".repeat(2000);
        let offset = table.add_string(&long_string);
        assert_eq!(offset, 1);

        let data = table.data();
        // initial 0, plus truncated len, plus trailing 0.
        assert_eq!(data.len(), 1027);
        assert!(data.ends_with(b"\0"));
    }

    #[test]
    fn test_write_integer_type() {
        let int_type = CtfType::Integer {
            name: "int".to_string(),
            size: 32,
            encoding: IntegerEncoding {
                bits: 32,
                offset: 0,
                flags: IntegerFlags::new().signed(),
            },
        };
        let bytes = write_type(&int_type);

        // Integer type: name_offset(4) + info(2) + size(2) + encoding(4) = 12 bytes
        assert_eq!(bytes.len(), 12);

        // Check info field (bytes 4-5): kind=INTEGER(1), root=true, vlen=0
        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_INTEGER, true, 0));
    }

    #[test]
    fn test_write_void_type() {
        let void_type = CtfType::Integer {
            name: "void".to_string(),
            size: 0,
            encoding: IntegerEncoding::default(),
        };
        let bytes = write_type(&void_type);

        // size field should be 0
        let size = u16::from_le_bytes([bytes[6], bytes[7]]);
        assert_eq!(size, 0);
    }

    #[test]
    fn test_write_float_type() {
        let float_type = CtfType::Float {
            name: "f32".to_string(),
            size: 32,
            encoding: 0,
        };
        let bytes = write_type(&float_type);

        assert_eq!(bytes.len(), 12);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_FLOAT, true, 0));
    }

    #[test]
    fn test_write_pointer_type() {
        let ptr_type = CtfType::Pointer {
            name: "".to_string(),
            target_type: TypeId::from_u16(5).unwrap(),
        };
        let bytes = write_type(&ptr_type);

        // Pointer: name_offset(4) + info(2) + target_type(2) = 8 bytes
        assert_eq!(bytes.len(), 8);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_POINTER, false, 0));

        let target = u16::from_le_bytes([bytes[6], bytes[7]]);
        assert_eq!(target, 5);
    }

    #[test]
    fn test_write_typedef() {
        let typedef = CtfType::Typedef {
            name: "size_t".to_string(),
            target_type: TypeId::from_u16(3).unwrap(),
        };
        let bytes = write_type(&typedef);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_TYPEDEF, false, 0));
    }

    #[test]
    fn test_write_const() {
        let const_type = CtfType::Const {
            name: "".to_string(),
            target_type: TypeId::from_u16(3).unwrap(),
        };
        let bytes = write_type(&const_type);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_CONST, false, 0));
    }

    #[test]
    fn test_write_array_type() {
        let array_type = CtfType::Array {
            name: "".to_string(),
            element_type: TypeId::from_u16(2).unwrap(),
            index_type: TypeId::from_u16(3).unwrap(),
            nelems: 10,
        };
        let bytes = write_type(&array_type);

        // Array: name(4) + info(2) + pad(2) + elem(2) + idx(2) + nelems(4) = 16 bytes
        assert_eq!(bytes.len(), 16);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_ARRAY, true, 0));

        let nelems = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(nelems, 10);
    }

    #[test]
    fn test_write_struct_empty() {
        let struct_type = CtfType::Struct {
            name: "Empty".to_string(),
            size: 0,
            members: vec![],
        };
        let bytes = write_type(&struct_type);

        // Struct header: name(4) + info(2) + size(2) = 8 bytes
        assert_eq!(bytes.len(), 8);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_STRUCT, true, 0));
    }

    #[test]
    fn test_write_struct_with_members() {
        let struct_type = CtfType::Struct {
            name: "Point".to_string(),
            size: 8,
            members: vec![
                CtfMember {
                    name: "x".to_string(),
                    type_id: TypeId::from_u16(1).unwrap(),
                    offset_bits: 0,
                },
                CtfMember {
                    name: "y".to_string(),
                    type_id: TypeId::from_u16(1).unwrap(),
                    offset_bits: 32,
                },
            ],
        };
        let bytes = write_type(&struct_type);

        // Header(8) + 2 members * (name(4) + type(2) + offset(2)) = 8 + 16 = 24
        assert_eq!(bytes.len(), 24);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_STRUCT, true, 2));
    }

    #[test]
    fn test_write_union() {
        let union_type = CtfType::Union {
            name: "Data".to_string(),
            size: 8,
            members: vec![
                CtfMember {
                    name: "i".to_string(),
                    type_id: TypeId::from_u16(1).unwrap(),
                    offset_bits: 0,
                },
                CtfMember {
                    name: "f".to_string(),
                    type_id: TypeId::from_u16(2).unwrap(),
                    offset_bits: 0,
                },
            ],
        };
        let bytes = write_type(&union_type);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_UNION, true, 2));
    }

    #[test]
    fn test_write_enum() {
        let enum_type = CtfType::Enum {
            name: "Color".to_string(),
            size: 4,
            enumerators: vec![
                CtfEnumerator {
                    name: "Red".to_string(),
                    value: 0,
                },
                CtfEnumerator {
                    name: "Green".to_string(),
                    value: 1,
                },
                CtfEnumerator {
                    name: "Blue".to_string(),
                    value: 2,
                },
            ],
        };
        let bytes = write_type(&enum_type);

        // Header(8) + 3 enumerators * (name(4) + value(4)) = 8 + 24 = 32
        assert_eq!(bytes.len(), 32);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_ENUM, true, 3));
    }

    #[test]
    fn test_write_function_no_args() {
        let func_type = CtfType::Function {
            name: "".to_string(),
            return_type: TypeId::from_u16(1).unwrap(),
            args: vec![],
            is_varargs: false,
        };
        let bytes = write_type(&func_type);

        // name(4) + info(2) + return(2) = 8 bytes
        assert_eq!(bytes.len(), 8);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_FUNCTION, false, 0));
    }

    #[test]
    fn test_write_function_with_args() {
        let id = TypeId::from_u16(1).unwrap();
        let func_type = CtfType::Function {
            name: "add".to_string(),
            return_type: id,
            args: vec![id, id],
            is_varargs: false,
        };
        let bytes = write_type(&func_type);

        // name(4) + info(2) + return(2) + 2 args(4) = 12 bytes
        assert_eq!(bytes.len(), 12);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_FUNCTION, false, 2));
    }

    #[test]
    fn test_write_function_odd_args_padded() {
        let func_type = CtfType::Function {
            name: "".to_string(),
            return_type: TypeId::from_u16(1).unwrap(),
            args: vec![TypeId::from_u16(2).unwrap()], // 1 arg = odd vlen
            is_varargs: false,
        };
        let bytes = write_type(&func_type);

        // name(4) + info(2) + return(2) + 1 arg(2) + padding(2) = 12 bytes
        assert_eq!(bytes.len(), 12);
    }

    #[test]
    fn test_write_function_varargs() {
        let func_type = CtfType::Function {
            name: "printf".to_string(),
            return_type: TypeId::from_u16(1).unwrap(),
            args: vec![TypeId::from_u16(2).unwrap()],
            is_varargs: true,
        };
        let bytes = write_type(&func_type);

        // vlen = 1 arg + 1 varargs marker = 2
        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_FUNCTION, false, 2));
    }

    #[test]
    fn test_write_unknown() {
        let bytes = write_type(&CtfType::Unknown);

        // name(4) + info(2) + pad(2) = 8 bytes
        assert_eq!(bytes.len(), 8);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, ctf_type_info(CTF_K_UNKNOWN, false, 0));
    }
}

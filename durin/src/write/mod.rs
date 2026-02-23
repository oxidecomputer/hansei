use crate::constants::*;
use crate::{
    CtfFlags, CtfHeader, CtfPreamble, CtfVersion, FloatEncoding, HEADER_SIZE, IntegerEncoding,
    LARGE_THRESHOLD, StrId, TypeId, TypeKind,
};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use goblin::elf::Elf;
use goblin::elf::section_header::SHN_UNDEF;
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};
use scroll::ctx::TryIntoCtx;
use scroll::{Endian, Pwrite};

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;

pub use error::Error;

mod error;

pub type Result<T> = std::result::Result<T, Error>;

fn ctf_type_info(kind: u8, is_root: bool, vlen: u16) -> u16 {
    ((kind as u16) << 11) | ((if is_root { 1 } else { 0 }) << 10) | (vlen & CTF_MAX_VLEN)
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
    pub funcs: HashMap<String, FuncInfo>,
    elf: Option<&'a Elf<'a>>,
    label: Option<String>,
    endian: Endian,
    compress: bool,
    truncate_str_len: Option<usize>,
    replace_spaces: Option<&'static str>,
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
            funcs: HashMap::new(),
            elf: opts.elf,
            label: opts.label,
            endian: opts.endian.unwrap_or_default().into(),
            compress: opts.compress.unwrap_or(true), // Use compression by default.
            truncate_str_len: opts.truncate_str_len,
            replace_spaces: opts.replace_spaces,
        }
    }

    /// Add a type to the writer. Returns the assigned type ID. Will fail if
    /// all available type IDs have been consumed.
    pub fn add_type(&mut self, ctf_type: CtfType) -> Result<TypeId> {
        let type_offset = self.types.len() as u16;
        let Ok(type_id) = TypeId::from_u16(type_offset) else {
            return Err(Error::type_ids_exhausted());
        };

        self.types.push(ctf_type);
        Ok(type_id)
    }

    /// Add a function to the writer. This will only be included in the the
    /// generated CTF if `CtfWriterBuilder::with_elf` was passed when
    /// constructing the `CtfWriter`.
    pub fn add_func(&mut self, name: String, func: FuncInfo) {
        self.funcs.insert(name, func);
    }

    /// Reserve a type ID by adding a placeholder. Returns the reserved ID.
    /// Use `set_type` to replace the placeholder with the actual type. Will
    /// fail if all available type IDs have been consumed.
    pub fn reserve_type_id(&mut self) -> Result<TypeId> {
        let type_offset = self.types.len() as u16;
        let Ok(type_id) = TypeId::from_u16(type_offset) else {
            return Err(Error::type_ids_exhausted());
        };

        self.types.push(CtfType::Unknown); // placeholder
        Ok(type_id)
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
    pub fn add_crate_versions<'b>(
        &mut self,
        crates: impl IntoIterator<Item = &'b String>,
    ) -> Result<()> {
        for crate_id in crates {
            let name = format!("__CRATE_{crate_id}__");
            self.add_type(CtfType::Typedef {
                name,
                target_type: TypeId::void(),
            })?;
        }

        Ok(())
    }

    pub fn generate_ctf(&mut self) -> Result<Vec<u8>> {
        self._generate_ctf().map_err(Error::write)
    }

    fn _generate_ctf(&mut self) -> scroll::Result<Vec<u8>> {
        let mut out = vec![0u8; HEADER_SIZE];
        let mut strings = StringTable::new(self.truncate_str_len, self.replace_spaces);

        let endian = self.endian;

        // This is the minimum size the serialized type could consume. The
        // actual data will certainly be larger than this, but this value is
        // trivial to calculate and gets us close enough to minimize
        // reallocations when appending.
        let mut type_data = Vec::with_capacity(self.types.len() * 8);

        // Skip the initial placeholder item.
        let ty_offset = &mut 0;
        for ctf_type in self.types.iter().skip(1) {
            // Ensure the buffer has space for the type.
            type_data.resize(type_data.len() + ctf_type.encoded_len(), 0);

            self.write_type(&mut type_data, ty_offset, &mut strings, ctf_type, endian)?;
        }

        let mut lbl_data = vec![0u8; 16];
        let lbl_offset = &mut 0;
        if let Some(label) = &self.label {
            let label_name_off = strings.add_string(label);
            let last_type_idx = (self.types.len() - 1) as u32;
            lbl_data.gwrite_with(label_name_off, lbl_offset, endian)?;
            lbl_data.gwrite_with(last_type_idx, lbl_offset, endian)?;
        }

        let mut obj_data = Vec::new();
        let mut func_data = Vec::new();
        if let Some(elf) = &self.elf {
            let func_offset = &mut 0;
            let obj_offset = &mut 0;

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
                        let Some(func_info) = self.funcs.get(symbol_name) else {
                            let info = CtfType::Unknown.type_info();
                            func_data.gwrite_with(info, func_offset, endian)?;
                            continue;
                        };

                        let vlen = func_info.args.len() as u16;
                        eprintln!("Argument count for {symbol_name}: {vlen}");
                        let info = ctf_type_info(CTF_K_FUNCTION, false, vlen);

                        let func_len = 4 + 2 * vlen as usize;
                        func_data.resize(func_data.len() + func_len, 0);

                        func_data.gwrite_with(info, func_offset, endian)?;
                        func_data.gwrite_with(func_info.return_type.get(), func_offset, endian)?;

                        // Write argument types
                        for &arg in &func_info.args {
                            func_data.gwrite_with(arg.get(), func_offset, endian)?;
                        }
                    }
                    STT_OBJECT => {
                        obj_data.resize(obj_data.len() + 2, 0);

                        let Some((idx, _)) = self
                            .types
                            .iter()
                            .enumerate()
                            .find(|(_, t)| t.name() == symbol_name)
                        else {
                            obj_data.gwrite_with(0u16, obj_offset, endian)?;
                            continue;
                        };
                        // CTF index starts at one.
                        obj_data.gwrite_with(idx as u16, obj_offset, endian)?;
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
        let strlen = strings.data().len() as u32;

        let preamble = CtfPreamble {
            vers: CtfVersion::V2,
            flags: CtfFlags::new(self.compress),
        };

        // TODO: support parents.
        let header = CtfHeader {
            parlabel: StrId::empty(),
            parname: StrId::empty(),
            lbloff,
            objtoff,
            funcoff,
            typeoff,
            stroff,
            strlen,
        };

        let data_len = (stroff + strlen) as usize;
        out.reserve(data_len);

        let offset = &mut 0;
        out.gwrite_with(CTF_MAGIC, offset, endian)?;
        out.gwrite_with(preamble, offset, endian)?;
        out.gwrite_with(header, offset, endian)?;

        if self.compress {
            let mut encoder = ZlibEncoder::new(&mut out, Compression::fast());
            encoder.write_all(&lbl_data)?;
            encoder.write_all(&obj_data)?;
            encoder.write_all(&func_data)?;
            encoder.write_all(&vec![0u8; func_padding as usize])?;
            encoder.write_all(&type_data)?;
            encoder.write_all(strings.data())?;
            encoder.finish()?;
        } else {
            out.extend_from_slice(&lbl_data);
            out.extend_from_slice(&obj_data);
            out.extend_from_slice(&func_data);
            out.extend_from_slice(&vec![0u8; func_padding as usize]);
            out.extend_from_slice(&type_data);
            out.extend_from_slice(strings.data());
        }

        out.shrink_to_fit();

        Ok(out)
    }

    fn write_type(
        &self,
        buffer: &mut [u8],
        offset: &mut usize,
        strings: &mut StringTable,
        ctf_type: &CtfType,
        endian: Endian,
    ) -> scroll::Result<()> {
        Self::write_type_impl(buffer, offset, strings, ctf_type, endian)
    }

    fn write_type_impl(
        buffer: &mut [u8],
        offset: &mut usize,
        strings: &mut StringTable,
        ctf_type: &CtfType,
        endian: Endian,
    ) -> scroll::Result<()> {
        let info = ctf_type.type_info();

        match ctf_type {
            CtfType::Integer {
                name,
                size,
                encoding,
            } => {
                let name_offset = strings.add_string(name);
                let info = ctf_type.type_info();

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(*size as u16, offset, endian)?;
                buffer.gwrite_with(encoding.as_u32(), offset, endian)?;
            }
            CtfType::Float {
                name,
                size,
                encoding,
            } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(*size as u16, offset, endian)?;
                buffer.gwrite_with(encoding.as_u32(), offset, endian)?;
            }
            CtfType::Pointer { name, target_type } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(target_type.get(), offset, endian)?;
            }
            CtfType::Typedef { name, target_type } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(target_type.get(), offset, endian)?;
            }
            CtfType::Const { name, target_type } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(target_type.get(), offset, endian)?;
            }
            CtfType::Volatile { name, target_type } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(target_type.get(), offset, endian)?;
            }
            CtfType::Restrict { name, target_type } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(target_type.get(), offset, endian)?;
            }
            CtfType::Function {
                name,
                return_type,
                args,
                is_varargs,
            } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(return_type.get(), offset, endian)?;

                // Write argument types
                for arg in args {
                    buffer.gwrite_with(arg.get(), offset, endian)?;
                }

                // Write varargs marker if needed
                if *is_varargs {
                    buffer.gwrite_with(0u16, offset, endian)?;
                }

                // Pad vlen to an even number for alignment.
                if !ctf_type.vlen().is_multiple_of(2) {
                    buffer.gwrite_with(0u16, offset, endian)?;
                }
            }
            CtfType::Array {
                name,
                element_type,
                index_type,
                nelems,
            } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(0u16, offset, endian)?;
                buffer.gwrite_with(element_type.get(), offset, endian)?;
                buffer.gwrite_with(index_type.get(), offset, endian)?;
                buffer.gwrite_with(*nelems, offset, endian)?;
            }
            CtfType::Struct {
                name,
                size,
                members,
            } => {
                let name_offset = strings.add_string(name);

                if *size > CTF_MAX_SIZE {
                    let sizehi: u32 = (size >> 32) as u32;
                    let sizelo: u32 = *size as u32;

                    buffer.gwrite_with(name_offset, offset, endian)?;
                    buffer.gwrite_with(info, offset, endian)?;
                    buffer.gwrite_with(CTF_LSIZE_SENT, offset, endian)?;
                    buffer.gwrite_with(sizehi, offset, endian)?;
                    buffer.gwrite_with(sizelo, offset, endian)?;
                } else {
                    buffer.gwrite_with(name_offset, offset, endian)?;
                    buffer.gwrite_with(info, offset, endian)?;
                    buffer.gwrite_with(*size as u16, offset, endian)?;
                }

                // Write members
                for member in members {
                    let member_name_offset = strings.add_string(&member.name);
                    buffer.gwrite_with(member_name_offset, offset, endian)?;
                    buffer.gwrite_with(member.type_id.get(), offset, endian)?;
                    if *size >= 8192 {
                        let offsethi: u32 = (member.offset_bits >> 32) as u32;
                        let offsetlo: u32 = member.offset_bits as u32;
                        buffer.gwrite_with(0u16, offset, endian)?; // Padding.
                        buffer.gwrite_with(offsethi, offset, endian)?;
                        buffer.gwrite_with(offsetlo, offset, endian)?;
                    } else {
                        buffer.gwrite_with(member.offset_bits as u16, offset, endian)?;
                    }
                }
            }
            CtfType::Union {
                name,
                size,
                members,
            } => {
                let name_offset = strings.add_string(name);

                if *size > CTF_MAX_SIZE {
                    let sizehi: u32 = (size >> 32) as u32;
                    let sizelo: u32 = *size as u32;

                    buffer.gwrite_with(name_offset, offset, endian)?;
                    buffer.gwrite_with(info, offset, endian)?;
                    buffer.gwrite_with(CTF_LSIZE_SENT, offset, endian)?;
                    buffer.gwrite_with(sizehi, offset, endian)?;
                    buffer.gwrite_with(sizelo, offset, endian)?;
                } else {
                    buffer.gwrite_with(name_offset, offset, endian)?;
                    buffer.gwrite_with(info, offset, endian)?;
                    buffer.gwrite_with(*size as u16, offset, endian)?;
                }

                // Write members
                for member in members {
                    let member_name_offset = strings.add_string(&member.name);
                    buffer.gwrite_with(member_name_offset, offset, endian)?;
                    buffer.gwrite_with(member.type_id.get(), offset, endian)?;
                    if *size >= 8192 {
                        let offsethi: u32 = (member.offset_bits >> 32) as u32;
                        let offsetlo: u32 = member.offset_bits as u32;
                        buffer.gwrite_with(0u16, offset, endian)?; // Padding.
                        buffer.gwrite_with(offsethi, offset, endian)?;
                        buffer.gwrite_with(offsetlo, offset, endian)?;
                    } else {
                        buffer.gwrite_with(member.offset_bits as u16, offset, endian)?;
                    }
                }
            }
            CtfType::Enum {
                name,
                size,
                enumerators,
            } => {
                let name_offset = strings.add_string(name);

                buffer.gwrite_with(name_offset, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(*size as u16, offset, endian)?;

                for enumerator in enumerators {
                    let enum_name_offset = strings.add_string(&enumerator.name);
                    buffer.gwrite_with(enum_name_offset, offset, endian)?;
                    buffer.gwrite_with(enumerator.value, offset, endian)?;
                }
            }
            CtfType::Unknown => {
                buffer.gwrite_with(0u32, offset, endian)?;
                buffer.gwrite_with(info, offset, endian)?;
                buffer.gwrite_with(0u16, offset, endian)?;
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
    endian: Option<crate::Endian>,
    compress: Option<bool>,
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

    /// The endianness to use when writing the CTF file.
    pub fn with_endianness(mut self, endian: crate::Endian) -> Self {
        self.opts.endian = Some(endian);
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

    /// Whether to compress the CTF data.
    pub fn with_compression(mut self, use_compression: bool) -> Self {
        self.opts.compress = Some(use_compression);
        self
    }
}

/// Parsed function info with CTF type IDs.
#[derive(Clone, Debug)]
pub struct FuncInfo {
    pub return_type: TypeId,
    pub args: Vec<TypeId>,
}

#[derive(Clone, Debug)]
pub enum CtfType {
    Integer {
        name: String,
        size: u64,
        encoding: IntegerEncoding,
    },
    Float {
        name: String,
        size: u64,
        encoding: FloatEncoding,
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
        size: u64,
        members: Vec<CtfMember>,
    },
    Union {
        name: String,
        size: u64,
        members: Vec<CtfMember>,
    },
    Enum {
        name: String,
        size: u64,
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
    /// The `u16` type info representation used in the CTF file format.
    pub fn type_info(&self) -> u16 {
        // TODO: Currently we assume all real types are directly referenced.
        let is_root = if self.kind() == TypeKind::Unknown {
            0
        } else {
            1
        };
        ((self.kind() as u16) << 11) | is_root << 10 | (self.vlen() & CTF_MAX_VLEN)
    }

    /// The name of this type.
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

    /// The `TypeKind` of this type.
    pub fn kind(&self) -> TypeKind {
        match self {
            Self::Integer { .. } => TypeKind::Integer,
            Self::Float { .. } => TypeKind::Float,
            Self::Pointer { .. } => TypeKind::Pointer,
            Self::Typedef { .. } => TypeKind::Typedef,
            Self::Const { .. } => TypeKind::Const,
            Self::Volatile { .. } => TypeKind::Volatile,
            Self::Restrict { .. } => TypeKind::Restrict,
            Self::Struct { .. } => TypeKind::Struct,
            Self::Union { .. } => TypeKind::Union,
            Self::Enum { .. } => TypeKind::Enum,
            Self::Function { .. } => TypeKind::Function,
            Self::Array { .. } => TypeKind::Array,
            Self::Unknown => TypeKind::Unknown,
        }
    }

    /// The number of dynamic elements in this type.
    pub fn vlen(&self) -> u16 {
        match self {
            Self::Struct { members, .. } => members.len() as u16,
            Self::Union { members, .. } => members.len() as u16,
            Self::Enum { enumerators, .. } => enumerators.len() as u16,
            Self::Function {
                args, is_varargs, ..
            } => {
                let mut vlen = args.len() as u16;
                if *is_varargs {
                    vlen += 1;
                }
                vlen
            }
            _ => 0,
        }
    }

    /// Returns true if this is a struct with any member at offset 0.
    pub fn has_member_with_zero_offset(&self) -> bool {
        let Self::Struct { members, .. } = self else {
            return false;
        };
        members.iter().any(|m| m.offset_bits == 0)
    }

    /// The size of this type when serialized into CTF.
    fn encoded_len(&self) -> usize {
        // The size of ctf_stype.
        const STYPE_SIZE: usize = 8;

        // The size of large ctf_type.
        const LTYPE_SIZE: usize = 16;

        match self {
            Self::Struct { size, .. } | Self::Union { size, .. } => {
                let base = if *size > CTF_MAX_SIZE {
                    LTYPE_SIZE
                } else {
                    STYPE_SIZE
                };
                let member_size = if *size >= LARGE_THRESHOLD as u64 {
                    16
                } else {
                    8
                };

                base + self.vlen() as usize * member_size
            }
            Self::Function { .. } => {
                let mut var = self.vlen() as usize * 2;
                if !self.vlen().is_multiple_of(2) {
                    var += 2;
                }
                STYPE_SIZE + var
            }
            Self::Enum { enumerators, .. } => STYPE_SIZE + enumerators.len() * 8,
            Self::Array { .. } => STYPE_SIZE + 8,
            Self::Integer { .. } | Self::Float { .. } => STYPE_SIZE + size_of::<IntegerEncoding>(),
            Self::Pointer { .. }
            | Self::Typedef { .. }
            | Self::Const { .. }
            | Self::Volatile { .. }
            | Self::Restrict { .. }
            | Self::Unknown => STYPE_SIZE,
        }
    }
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

impl TryIntoCtx<scroll::Endian> for StrId {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], en: scroll::Endian) -> scroll::Result<usize> {
        let offset = &mut 0;
        this.gwrite_with(self.0, offset, en)?;

        Ok(*offset)
    }
}

impl TryIntoCtx<scroll::Endian> for CtfPreamble {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], en: scroll::Endian) -> scroll::Result<usize> {
        let CtfPreamble { vers, flags } = self;

        let offset = &mut 0;
        this.gwrite_with(vers as u8, offset, en)?;
        this.gwrite_with(flags.0, offset, en)?;

        Ok(*offset)
    }
}

impl TryIntoCtx<scroll::Endian> for CtfHeader {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], en: scroll::Endian) -> scroll::Result<usize> {
        let CtfHeader {
            parlabel,
            parname,
            lbloff,
            objtoff,
            funcoff,
            typeoff,
            stroff,
            strlen,
        } = self;

        let offset = &mut 0;
        this.gwrite_with(parlabel, offset, en)?;
        this.gwrite_with(parname, offset, en)?;
        this.gwrite_with(lbloff, offset, en)?;
        this.gwrite_with(objtoff, offset, en)?;
        this.gwrite_with(funcoff, offset, en)?;
        this.gwrite_with(typeoff, offset, en)?;
        this.gwrite_with(stroff, offset, en)?;
        this.gwrite_with(strlen, offset, en)?;

        Ok(*offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{FloatType, IntegerFlags};

    // Helper to write a type and return the buffer bytes
    fn write_type(ctf_type: &CtfType) -> Vec<u8> {
        let mut buffer = vec![0u8; ctf_type.encoded_len()];
        let mut strings = StringTable::new(None, None);
        CtfWriter::write_type_impl(&mut buffer, &mut 0, &mut strings, ctf_type, scroll::NATIVE)
            .unwrap();
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
        assert_eq!(info, int_type.type_info());
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
            encoding: FloatEncoding {
                bits: 32,
                offset: 0,
                float_type: FloatType::Single,
            },
        };
        let bytes = write_type(&float_type);

        assert_eq!(bytes.len(), 12);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, float_type.type_info());
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
        assert_eq!(info, ptr_type.type_info());

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
        assert_eq!(info, typedef.type_info());
    }

    #[test]
    fn test_write_const() {
        let const_type = CtfType::Const {
            name: "".to_string(),
            target_type: TypeId::from_u16(3).unwrap(),
        };
        let bytes = write_type(&const_type);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, const_type.type_info());
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
        assert_eq!(info, array_type.type_info());

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
        assert_eq!(info, struct_type.type_info());
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
        assert_eq!(info, struct_type.type_info());
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
        assert_eq!(info, union_type.type_info());
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
        assert_eq!(info, enum_type.type_info());
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
        assert_eq!(info, func_type.type_info());
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
        assert_eq!(info, func_type.type_info());
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
        assert_eq!(info, func_type.type_info());
    }

    #[test]
    fn test_write_unknown() {
        let bytes = write_type(&CtfType::Unknown);

        // name(4) + info(2) + pad(2) = 8 bytes
        assert_eq!(bytes.len(), 8);

        let info = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(info, CtfType::Unknown.type_info());
    }

    #[test]
    fn test_write_large_struct() {
        let ty = CtfType::Struct {
            name: "very_large_struct".to_string(),
            size: CTF_MAX_SIZE + 1,
            members: vec![CtfMember {
                name: "first".to_string(),
                offset_bits: 0,
                type_id: TypeId::void(),
            }],
        };
        let mut writer = CtfWriter::new();
        writer.add_type(ty).unwrap();
        let bytes = writer.generate_ctf().unwrap();

        let reader = crate::read::CtfReader::load(&bytes).unwrap();
        let ty_read = reader
            .types()
            .iter()
            .find(|t| t.name(&reader) == "very_large_struct")
            .unwrap();
        assert_eq!(reader.ty_size(ty_read.id()), CTF_MAX_SIZE + 1);
    }

    #[test]
    fn test_write_large_member_struct() {
        let ty = CtfType::Struct {
            name: "somewhat_large_struct".to_string(),
            size: LARGE_THRESHOLD as u64 + 1,
            members: vec![CtfMember {
                name: "first".to_string(),
                offset_bits: 0,
                type_id: TypeId::void(),
            }],
        };
        let mut writer = CtfWriter::new();
        writer.add_type(ty).unwrap();
        let bytes = writer.generate_ctf().unwrap();

        let reader = crate::read::CtfReader::load(&bytes).unwrap();
        let ty_read = reader
            .types()
            .iter()
            .find(|t| t.name(&reader) == "somewhat_large_struct")
            .unwrap();
        assert_eq!(reader.ty_size(ty_read.id()), LARGE_THRESHOLD as u64 + 1);
    }

    #[test]
    fn test_encoded_size() {
        for (ty, size) in [
            (
                CtfType::Integer {
                    name: "int".to_string(),
                    size: 4,
                    encoding: IntegerEncoding {
                        bits: 32,
                        offset: 0,
                        flags: IntegerFlags::new(),
                    },
                },
                12,
            ),
            (
                CtfType::Float {
                    name: "float".to_string(),
                    size: 4,
                    encoding: FloatEncoding {
                        bits: 32,
                        offset: 0,
                        float_type: FloatType::Single,
                    },
                },
                12,
            ),
            (
                CtfType::Const {
                    name: "const".to_string(),
                    target_type: TypeId::unknown(),
                },
                8,
            ),
            (
                CtfType::Struct {
                    name: "struct_even_vlen".to_string(),
                    size: 4,
                    members: vec![
                        CtfMember {
                            name: "first".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "second".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                    ],
                },
                24,
            ),
            (
                CtfType::Union {
                    name: "union_odd_vlen_padded".to_string(),
                    size: 4,
                    members: vec![
                        CtfMember {
                            name: "first".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "second".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "third".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                    ],
                },
                32,
            ),
            (
                // This will use `ctf_stype` for the base type, and
                // `ctf_lmember` for the members.
                CtfType::Struct {
                    name: "struct_over_lmember_size".to_string(),
                    size: 10_000,
                    members: vec![
                        CtfMember {
                            name: "first".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "second".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "third".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                    ],
                },
                56,
            ),
            (
                // This will use `ctf_type` for the base type, and
                // `ctf_lmember` for the members.
                CtfType::Union {
                    name: "union_over_max_size".to_string(),
                    size: 0x1ffff,
                    members: vec![
                        CtfMember {
                            name: "first".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "second".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                        CtfMember {
                            name: "third".to_string(),
                            offset_bits: 0,
                            type_id: TypeId::unknown(),
                        },
                    ],
                },
                64,
            ),
            (
                CtfType::Function {
                    name: "func_single_arg".to_string(),
                    return_type: TypeId::unknown(),
                    args: vec![TypeId::unknown()],
                    is_varargs: false,
                },
                12,
            ),
            (
                CtfType::Function {
                    name: "func_four_args_varargs".to_string(),
                    return_type: TypeId::unknown(),
                    args: vec![TypeId::unknown(); 4],
                    is_varargs: true,
                },
                20,
            ),
            (
                CtfType::Enum {
                    name: "enum".to_string(),
                    size: 4,
                    enumerators: vec![
                        CtfEnumerator {
                            name: "FOO".to_string(),
                            value: 1,
                        },
                        CtfEnumerator {
                            name: "BAR".to_string(),
                            value: 2,
                        },
                    ],
                },
                24,
            ),
            (
                CtfType::Array {
                    name: "array".to_string(),
                    element_type: TypeId::unknown(),
                    index_type: TypeId::unknown(),
                    nelems: 16,
                },
                16,
            ),
        ] {
            assert_eq!(
                ty.encoded_len(),
                size,
                "unexpected encoded_len for type {}",
                ty.name()
            );
        }
    }

    #[test]
    fn test_write_be() {
        let mut writer = CtfWriterBuilder::new()
            .with_endianness(crate::Endian::Big)
            .build();
        writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let bytes = writer.generate_ctf().unwrap();

        let reader = crate::read::CtfReader::load(&bytes).unwrap();
        let int = reader
            .types()
            .iter()
            .find(|t| t.name(&reader) == "i32")
            .unwrap();
        assert_eq!(int.kind(), TypeKind::Integer);
    }

    #[test]
    fn test_write_le() {
        let mut writer = CtfWriterBuilder::new()
            .with_endianness(crate::Endian::Little)
            .build();
        writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let bytes = writer.generate_ctf().unwrap();

        let reader = crate::read::CtfReader::load(&bytes).unwrap();
        let int = reader
            .types()
            .iter()
            .find(|t| t.name(&reader) == "i32")
            .unwrap();
        assert_eq!(int.kind(), TypeKind::Integer);
    }

    #[test]
    fn test_exhaust_type_ids() {
        let mut writer = CtfWriter::new();
        for _ in 0..MAX_TYPES {
            writer.reserve_type_id().unwrap();
        }
        let next_ty = writer.reserve_type_id();
        assert_eq!(
            next_ty.unwrap_err().to_string(),
            Error::type_ids_exhausted().to_string()
        );
    }

    #[test]
    fn test_use_compression() {
        let mut writer = CtfWriterBuilder::new().with_compression(true).build();
        writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let bytes = writer.generate_ctf().unwrap();
        let reader = crate::read::CtfReader::load(&bytes).unwrap();
        assert!(reader.preamble.flags.is_compressed());
    }

    #[test]
    fn test_no_compression() {
        let mut writer = CtfWriterBuilder::new().with_compression(false).build();
        writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let bytes = writer.generate_ctf().unwrap();
        let reader = crate::read::CtfReader::load(&bytes).unwrap();
        assert!(!reader.preamble.flags.is_compressed());
    }
}

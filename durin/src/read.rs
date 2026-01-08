use crate::constants::*;
use crate::{CtfHeader, CtfPreamble, Error, Result, StrId, TypeId, TypeKind};

use flate2::read::ZlibDecoder;
use scroll::Pread;
use scroll::ctx::TryFromCtx;

use std::collections::HashMap;
use std::io::Read;
use std::str;

const HEADER_SIZE: usize = 36;

#[derive(Debug)]
pub struct CtfReader {
    pub preamble: CtfPreamble,
    pub header: CtfHeader,
    pub labels: Vec<CtfLabel>,
    pub objects: Vec<TypeId>,
    pub functions: Vec<TypeId>,
    types: TypeTable,
    strings: StringTable,
}

impl CtfReader {
    pub fn load(input: &[u8]) -> Result<Self> {
        let offset = &mut 0;

        if input.len() < HEADER_SIZE {
            return Err(Error::TooShort {
                actual: input.len() as u32,
                expected: HEADER_SIZE as u32,
            });
        }
        let preamble: CtfPreamble = input.gread(offset)?;
        let header: CtfHeader = input.gread(offset)?;

        let expected_len = header.stroff + header.strlen;
        let data = if preamble.flags.is_compressed() {
            let mut decompressor = ZlibDecoder::new(&input[HEADER_SIZE..]);
            let mut buf = Vec::new();

            decompressor
                .read_to_end(&mut buf)
                .map_err(|e| Error::Decompress { source: e })?;
            if expected_len as usize > buf.len() {
                return Err(Error::TooShort {
                    actual: buf.len() as u32,
                    expected: expected_len,
                });
            }
            buf
        } else {
            if expected_len as usize > input.len() {
                return Err(Error::TooShort {
                    actual: input.len() as u32,
                    expected: expected_len,
                });
            }
            let data = input.get(HEADER_SIZE..).unwrap();
            data.to_vec()
        };

        let labels = read_labels(&header, &data)?;
        let objects = read_objects(&header, &data)?;
        let functions = Vec::new(); // TODO
        let types = TypeTable::load(&header, &data)?;
        let strings = StringTable::new(&header, &data);

        // TODO how expensive is this check? Do we care?
        // If this is a real library we should make this optional.
        validate_types(&types, &strings)?;

        Ok(Self {
            preamble,
            header,
            labels,
            objects,
            functions,
            types,
            strings,
        })
    }

    pub fn ty<'a>(&'a self, id: TypeId) -> &'a CtfType {
        // UNWRAP: We validate all type ids are valid during construction.
        self.types.ty_checked(id).unwrap()
    }

    /// Return the size of bytes of the type by id, following referenced
    /// types as needed.
    pub fn ty_size(&self, id: TypeId) -> u16 {
        match self.ty(id) {
            CtfType::Unknown { .. } => 0,
            CtfType::Integer {
                ty: CtfInteger { size, .. },
                ..
            } => *size,
            CtfType::Float {
                ty: CtfFloat { size, .. },
                ..
            } => *size,
            CtfType::Pointer { .. } => 8,
            CtfType::Array {
                ty:
                    CtfArray {
                        element_type,
                        nelems,
                        ..
                    },
                ..
            } => {
                let elem_size = self.ty_size(*element_type);
                elem_size * *nelems as u16
            }
            CtfType::Function { .. } => 8,
            CtfType::Struct {
                ty: CtfStruct { size, .. },
                ..
            } => *size,
            CtfType::Union {
                ty: CtfUnion { size, .. },
                ..
            } => *size,
            CtfType::Enum {
                ty: CtfEnum { size, .. },
                ..
            } => *size,
            CtfType::Forward { .. } => 0,
            CtfType::Typedef {
                ty: CtfTypedef { target_type, .. },
                ..
            } => self.ty_size(*target_type),
            CtfType::Volatile {
                ty: CtfVolatile { target_type, .. },
                ..
            } => self.ty_size(*target_type),
            CtfType::Const {
                ty: CtfConst { target_type, .. },
                ..
            } => self.ty_size(*target_type),
            CtfType::Restrict {
                ty: CtfRestrict { target_type, .. },
                ..
            } => self.ty_size(*target_type),
        }
    }

    pub fn types<'a>(&'a self) -> &'a [CtfType] {
        self.types.as_slice()
    }

    pub fn str<'a>(&'a self, id: StrId) -> &'a str {
        self.strings.get(id)
    }
}

fn read_labels(header: &CtfHeader, data: &[u8]) -> Result<Vec<CtfLabel>> {
    let labels_start = header.lbloff as usize;
    let labels_end = header.objtoff as usize;
    let labels_data = &data[labels_start..labels_end];

    let offset = &mut 0;

    let mut labels = Vec::new();
    while *offset < labels_data.len() {
        let label = labels_data.gread(offset)?;
        labels.push(label);
    }

    Ok(labels)
}

fn read_objects(header: &CtfHeader, data: &[u8]) -> Result<Vec<TypeId>> {
    let obj_start = header.objtoff as usize;
    let obj_end = header.funcoff as usize;
    let obj_data = &data[obj_start..obj_end];

    let offset = &mut 0;

    let mut objects = Vec::new();
    while *offset < obj_data.len() {
        let object = obj_data.gread(offset)?;
        objects.push(object);
    }

    Ok(objects)
}

/// Iterate over types and confirm that all type and string references are
/// valid.
fn validate_types(types: &TypeTable, strings: &StringTable) -> Result<()> {
    for ty in types.as_slice() {
        let _ = ty.name_checked(strings)?;
        match ty {
            CtfType::Unknown { .. } => {}
            CtfType::Integer { .. } => {}
            CtfType::Float { .. } => {}
            CtfType::Pointer {
                ty: CtfPointer { target_type, .. },
                ..
            } => {
                let _ = types.ty_checked(*target_type)?;
            }
            CtfType::Array {
                ty:
                    CtfArray {
                        element_type,
                        index_type,
                        ..
                    },
                ..
            } => {
                let _ = types.ty_checked(*element_type)?;
                let _ = types.ty_checked(*index_type)?;
            }
            CtfType::Function {
                ty: CtfFunction {
                    return_type, args, ..
                },
                ..
            } => {
                let _ = types.ty_checked(*return_type)?;
                for arg in args {
                    let _ = types.ty_checked(*arg)?;
                }
            }
            CtfType::Struct {
                ty: CtfStruct { members, .. },
                ..
            } => {
                for CtfMember { name, type_id, .. } in members {
                    let _ = strings.get_checked(*name)?;
                    let _ = types.ty_checked(*type_id)?;
                }
            }
            CtfType::Union {
                ty: CtfUnion { members, .. },
                ..
            } => {
                for CtfMember { name, type_id, .. } in members {
                    let _ = strings.get_checked(*name)?;
                    let _ = types.ty_checked(*type_id)?;
                }
            }
            CtfType::Enum {
                ty: CtfEnum { enumerators, .. },
                ..
            } => {
                for CtfEnumerator { name, .. } in enumerators {
                    let _ = strings.get_checked(*name)?;
                }
            }
            CtfType::Forward { .. } => {}
            CtfType::Typedef {
                ty: CtfTypedef { target_type, .. },
                ..
            } => {
                let _ = types.ty_checked(*target_type)?;
            }
            CtfType::Volatile {
                ty: CtfVolatile { target_type, .. },
                ..
            } => {
                let _ = types.ty_checked(*target_type)?;
            }
            CtfType::Const {
                ty: CtfConst { target_type, .. },
                ..
            } => {
                let _ = types.ty_checked(*target_type)?;
            }
            CtfType::Restrict {
                ty: CtfRestrict { target_type, .. },
                ..
            } => {
                let _ = types.ty_checked(*target_type)?;
            }
        }
    }

    Ok(())
}

impl TryFromCtx<'_, ()> for CtfPreamble {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let magic: u16 = from.gread(offset)?;
        if magic != CTF_MAGIC {
            return Err(Error::InvalidMagic(magic));
        }
        let vers_int: u8 = from.gread(offset)?;
        let vers = vers_int.try_into()?;

        let flags_int: u8 = from.gread(offset)?;
        let flags = flags_int.try_into()?;

        Ok((Self { magic, vers, flags }, *offset))
    }
}

impl TryFromCtx<'_, ()> for CtfHeader {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let parlabel = from.gread(offset)?;
        let parname = from.gread(offset)?;
        let lbloff = from.gread(offset)?;
        if lbloff % 2 != 0 {
            return Err(Error::MisalignedLabelOffset(lbloff));
        }
        let objtoff = from.gread(offset)?;
        if objtoff % 2 != 0 {
            return Err(Error::MisalignedObjectOffset(objtoff));
        }
        let funcoff = from.gread(offset)?;
        if funcoff % 4 != 0 {
            return Err(Error::MisalignedFuncOffset(funcoff));
        }
        let typeoff = from.gread(offset)?;
        if typeoff % 4 != 0 {
            return Err(Error::MisalignedTypeOffset(typeoff));
        }
        let stroff = from.gread(offset)?;
        let stflen = from.gread(offset)?;

        Ok((
            Self {
                parlabel,
                parname,
                lbloff,
                objtoff,
                funcoff,
                typeoff,
                stroff,
                strlen: stflen,
            },
            *offset,
        ))
    }
}

impl TryFromCtx<'_, ()> for StrId {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let raw: u32 = from.pread(0)?;
        let val = Self::try_from(raw)?;

        Ok((val, size_of::<Self>()))
    }
}

impl TryFromCtx<'_, ()> for TypeId {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let raw: u16 = from.pread(0)?;
        let val = Self::try_from(raw)?;

        Ok((val, size_of::<Self>()))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfLabel {
    /// Ref to name of label.
    label: StrId,
    /// Last type associated with this label.
    typeidx: Option<TypeId>,
}

impl CtfLabel {
    pub fn label<'a>(&self, ctf: &'a CtfReader) -> &'a str {
        ctf.str(self.label)
    }
}

impl TryFromCtx<'_, ()> for CtfLabel {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let label = from.gread(offset)?;
        let idx_int: u32 = from.gread(offset)?;
        let typeidx = (idx_int as u16).try_into().ok();

        Ok((Self { label, typeidx }, *offset))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct TypeTable {
    types: Vec<CtfType>,
}

impl TypeTable {
    pub fn load(header: &CtfHeader, data: &[u8]) -> Result<Self> {
        let types_start = header.typeoff as usize;
        let types_end = header.stroff as usize;
        let types_data = &data[types_start..types_end];

        let offset = &mut 0;
        let mut id = TypeId::try_from(1).unwrap();

        let mut types = Vec::new();
        // First slot is empty, but we use Unknown as a placeholder
        types.push(CtfType::Unknown { id: id });

        while *offset < types_data.len() {
            let ty = types_data.gread_with(offset, id)?;
            types.push(ty);
            let new_id = TypeId::try_from(id.get() + 1)?;
            id = new_id;
        }

        Ok(Self { types })
    }

    pub fn ty_checked<'a>(&'a self, id: TypeId) -> Result<&'a CtfType> {
        let Some(ty) = self.types.get(id.get() as usize) else {
            return Err(Error::MissingType(id));
        };

        Ok(ty)
    }

    pub fn as_slice(&self) -> &[CtfType] {
        &self.types
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum StringTableType {
    Internal = 0,
    External = 1,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct StringTable {
    inner: Vec<u8>,
}

impl StringTable {
    fn new(header: &CtfHeader, data: &[u8]) -> Self {
        let str_start = header.stroff as usize;
        let str_end = str_start + header.strlen as usize;

        StringTable {
            inner: data[str_start..str_end].to_vec(),
        }
    }

    /// Retrieve a string from the string table.
    fn get<'a>(&'a self, id: StrId) -> &'a str {
        // UNWRAP: We confirm in `validate_types` that all referenced strings
        // are valid.
        self.get_checked(id).unwrap()
    }

    /// Retrieve a string from the string table, confirming it has a valid
    /// index and is correctly encoded.
    fn get_checked<'a>(&'a self, id: StrId) -> Result<&'a str> {
        let bytes = self
            .inner
            .get(id.offset() as usize..)
            .ok_or(Error::MissingStr(id))?;

        let Some(substr) = bytes.split(|&b| b == 0).next() else {
            return Err(Error::UnterminatedStr(id));
        };

        let s = str::from_utf8(substr).map_err(|_| Error::InvalidStrEncoding(id))?;
        Ok(s)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
struct CtfMetadata(u16);

impl CtfMetadata {
    pub fn type_kind(&self) -> Result<TypeKind> {
        ((self.0 & 0xf800) >> 11).try_into()
    }

    // TODO use this?
    pub fn is_root(&self) -> bool {
        (self.0 & 0x0400) >> 10 == 1
    }

    pub fn vlen(&self) -> u16 {
        self.0 & CTF_MAX_VLEN
    }
}

impl TryFromCtx<'_, ()> for CtfMetadata {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let raw = from.gread(offset)?;

        Ok((CtfMetadata(raw), *offset))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct CtfIntEncoding(u32);

impl CtfIntEncoding {
    pub fn is_signed(&self) -> bool {
        ((self.0 & 0xff00_0000) >> 24) & 0x1 > 0
    }

    pub fn is_char(&self) -> bool {
        ((self.0 & 0xff00_0000) >> 24) & 0x2 > 0
    }

    pub fn is_bool(&self) -> bool {
        ((self.0 & 0xff00_0000) >> 24) & 0x4 > 0
    }

    pub fn is_varargs(&self) -> bool {
        ((self.0 & 0xff00_0000) >> 24) & 0x8 > 0
    }

    pub fn offset_bits(&self) -> u32 {
        (self.0 & 0x00ff_0000) >> 16
    }

    pub fn size_bits(&self) -> u32 {
        self.0 & 0x0000_ffff
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct CtfFloatEncoding(u32);

impl CtfFloatEncoding {
    pub fn encoding(&self) -> CtfFloatEncodingType {
        let raw = ((self.0 & 0xff00_0000) >> 24) as u8;

        // We've validated the encoding is valid in the constructor.
        raw.try_into().unwrap()
    }

    pub fn offset_bits(&self) -> u32 {
        (self.0 & 0x00ff_0000) >> 16
    }

    pub fn size_bits(&self) -> u32 {
        self.0 & 0x0000_ffff
    }
}

impl TryFrom<u32> for CtfFloatEncoding {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        let enc = CtfFloatEncoding(value);

        // Validate encoding type.
        let raw = ((value & 0xff00_0000) >> 24) as u8;
        let _ = CtfFloatEncodingType::try_from(raw)?;

        Ok(enc)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum CtfFloatEncodingType {
    Single = 1,
    Double = 2,
    Complex = 3,
    DoubleComplex = 4,
    LongDoubleComplex = 5,
    LongDouble = 6,
    Interval = 7,
    DoubleInterval = 8,
    LongDoubleInterval = 9,
    Imaginary = 10,
    DoubleImaginary = 11,
    LongDoubleImaginary = 12,
}

impl TryFrom<u8> for CtfFloatEncodingType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        let enc = match value {
            1 => Self::Single,
            2 => Self::Double,
            3 => Self::Complex,
            4 => Self::DoubleComplex,
            5 => Self::LongDoubleComplex,
            6 => Self::LongDouble,
            7 => Self::Interval,
            8 => Self::DoubleInterval,
            9 => Self::LongDoubleInterval,
            10 => Self::Imaginary,
            11 => Self::DoubleImaginary,
            12 => Self::LongDoubleImaginary,
            v => return Err(Error::InvalidFloatEncoding(v)),
        };
        Ok(enc)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SizeOrType {
    Size(u16),
    Type(TypeId),
}

// TODO handle large structs
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CtfType {
    Unknown { id: TypeId },
    Integer { id: TypeId, ty: CtfInteger },
    Float { id: TypeId, ty: CtfFloat },
    Pointer { id: TypeId, ty: CtfPointer },
    Array { id: TypeId, ty: CtfArray },
    Function { id: TypeId, ty: CtfFunction },
    Struct { id: TypeId, ty: CtfStruct },
    Union { id: TypeId, ty: CtfUnion },
    Enum { id: TypeId, ty: CtfEnum },
    Forward { id: TypeId, ty: CtfForward },
    Typedef { id: TypeId, ty: CtfTypedef },
    Volatile { id: TypeId, ty: CtfVolatile },
    Const { id: TypeId, ty: CtfConst },
    Restrict { id: TypeId, ty: CtfRestrict },
}

impl CtfType {
    pub fn id<'a>(&self) -> TypeId {
        match self {
            Self::Unknown { id } => *id,
            Self::Integer { id, .. } => *id,
            Self::Float { id, .. } => *id,
            Self::Pointer { id, .. } => *id,
            Self::Array { id, .. } => *id,
            Self::Function { id, .. } => *id,
            Self::Struct { id, .. } => *id,
            Self::Union { id, .. } => *id,
            Self::Enum { id, .. } => *id,
            Self::Forward { id, .. } => *id,
            Self::Typedef { id, .. } => *id,
            Self::Volatile { id, .. } => *id,
            Self::Const { id, .. } => *id,
            Self::Restrict { id, .. } => *id,
        }
    }

    pub fn kind(&self) -> TypeKind {
        match self {
            Self::Unknown { .. } => TypeKind::Unknown,
            Self::Integer { .. } => TypeKind::Integer,
            Self::Float { .. } => TypeKind::Float,
            Self::Pointer { .. } => TypeKind::Pointer,
            Self::Array { .. } => TypeKind::Array,
            Self::Function { .. } => TypeKind::Function,
            Self::Struct { .. } => TypeKind::Struct,
            Self::Union { .. } => TypeKind::Union,
            Self::Enum { .. } => TypeKind::Enum,
            Self::Forward { .. } => TypeKind::Forward,
            Self::Typedef { .. } => TypeKind::Typedef,
            Self::Volatile { .. } => TypeKind::Volatile,
            Self::Const { .. } => TypeKind::Const,
            Self::Restrict { .. } => TypeKind::Restrict,
        }
    }

    pub fn members(&self) -> &[CtfMember] {
        match self {
            CtfType::Struct {
                ty: CtfStruct { members, .. },
                ..
            } => members.as_slice(),
            CtfType::Union {
                ty: CtfUnion { members, .. },
                ..
            } => members.as_slice(),
            _ => &[],
        }
    }

    /// Return all members of the `CtfType` resolved into full `CtfTypes`.
    pub fn members_resolved<'a>(&self, ctf: &'a CtfReader) -> Vec<(&'a str, &'a CtfType)> {
        let members = self.members();

        let mut resolved = Vec::with_capacity(members.len());
        for member in members {
            let mem_name = ctf.str(member.name);
            let mem_ty = ctf.ty(member.type_id);
            resolved.push((mem_name, mem_ty));
        }

        resolved
    }

    pub fn name<'a>(&self, ctf: &'a CtfReader) -> &'a str {
        let Some(id) = self.name_id() else {
            return "";
        };
        ctf.str(id)
    }

    fn name_checked<'a>(&self, strings: &'a StringTable) -> Result<&'a str> {
        let Some(id) = self.name_id() else {
            return Ok("");
        };
        strings.get_checked(id)
    }

    fn name_id<'a>(&self) -> Option<StrId> {
        let id = match self {
            Self::Unknown { .. } => return None,
            Self::Integer {
                ty: CtfInteger { name, .. },
                ..
            } => name,
            Self::Float {
                ty: CtfFloat { name, .. },
                ..
            } => name,
            Self::Pointer {
                ty: CtfPointer { name, .. },
                ..
            } => name,
            Self::Array {
                ty: CtfArray { name, .. },
                ..
            } => name,
            Self::Function {
                ty: CtfFunction { name, .. },
                ..
            } => name,
            Self::Struct {
                ty: CtfStruct { name, .. },
                ..
            } => name,
            Self::Union {
                ty: CtfUnion { name, .. },
                ..
            } => name,
            Self::Enum {
                ty: CtfEnum { name, .. },
                ..
            } => name,
            Self::Forward {
                ty: CtfForward { name },
                ..
            } => name,
            Self::Typedef {
                ty: CtfTypedef { name, .. },
                ..
            } => name,
            Self::Volatile {
                ty: CtfVolatile { name, .. },
                ..
            } => name,
            Self::Const {
                ty: CtfConst { name, .. },
                ..
            } => name,
            Self::Restrict {
                ty: CtfRestrict { name, .. },
                ..
            } => name,
        };
        Some(*id)
    }

    /// Return the size of bytes of the type by id, following referenced
    /// types as needed.
    pub fn size(&self, ctf: &CtfReader) -> u16 {
        match self {
            CtfType::Unknown { .. } => 0,
            CtfType::Integer {
                ty: CtfInteger { size, .. },
                ..
            } => *size,
            CtfType::Float {
                ty: CtfFloat { size, .. },
                ..
            } => *size,
            CtfType::Pointer { .. } => 8,
            CtfType::Array {
                ty:
                    CtfArray {
                        element_type,
                        nelems,
                        ..
                    },
                ..
            } => {
                let elem_size = ctf.ty(*element_type).size(ctf);
                elem_size * *nelems as u16
            }
            CtfType::Function { .. } => 8,
            CtfType::Struct {
                ty: CtfStruct { size, .. },
                ..
            } => *size,
            CtfType::Union {
                ty: CtfUnion { size, .. },
                ..
            } => *size,
            CtfType::Enum {
                ty: CtfEnum { size, .. },
                ..
            } => *size,
            CtfType::Forward { .. } => 0,
            CtfType::Typedef {
                ty: CtfTypedef { target_type, .. },
                ..
            } => ctf.ty(*target_type).size(ctf),
            CtfType::Volatile {
                ty: CtfVolatile { target_type, .. },
                ..
            } => ctf.ty(*target_type).size(ctf),
            CtfType::Const {
                ty: CtfConst { target_type, .. },
                ..
            } => ctf.ty(*target_type).size(ctf),
            CtfType::Restrict {
                ty: CtfRestrict { target_type, .. },
                ..
            } => ctf.ty(*target_type).size(ctf),
        }
    }
}

impl TryFromCtx<'_, TypeId> for CtfType {
    type Error = Error;

    fn try_from_ctx(from: &[u8], id: TypeId) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name: StrId = from.gread(offset)?;
        let meta: CtfMetadata = from.gread(offset)?;
        let size: u16 = from.gread(offset)?;

        let ty = match meta.type_kind()? {
            TypeKind::Unknown => Self::Unknown { id },
            TypeKind::Integer => {
                let encoding_int: u32 = from.gread(offset)?;
                Self::Integer {
                    id,
                    ty: CtfInteger {
                        name,
                        size,
                        encoding: CtfIntEncoding(encoding_int),
                    },
                }
            }
            TypeKind::Float => {
                let encoding_int: u32 = from.gread(offset)?;
                let encoding = encoding_int.try_into()?;
                Self::Float {
                    id,
                    ty: CtfFloat {
                        name,
                        size,
                        encoding,
                    },
                }
            }
            TypeKind::Pointer => {
                let target_type = TypeId::try_from(size)?;
                Self::Pointer {
                    id,
                    ty: CtfPointer { name, target_type },
                }
            }
            TypeKind::Array => {
                let element_type = from.gread(offset)?;
                let index_type = from.gread(offset)?;
                let nelems = from.gread(offset)?;
                Self::Array {
                    id,
                    ty: CtfArray {
                        name,
                        element_type,
                        index_type,
                        nelems,
                    },
                }
            }
            TypeKind::Function => {
                let return_type = TypeId::try_from(size)?;
                let vlen = meta.vlen();
                let mut args = Vec::new();
                for _ in 0..vlen {
                    let arg = from.gread(offset)?;
                    args.push(arg);
                }
                // TODO is this needed?
                if !vlen.is_multiple_of(2) {
                    *offset += size_of::<u16>();
                }
                Self::Function {
                    id,
                    ty: CtfFunction {
                        name,
                        return_type,
                        args,
                        is_varargs: false,
                    },
                }
            }
            TypeKind::Struct => {
                if size >= 8192 {
                    unimplemented!("large structs are no supported yet");
                }
                let vlen = meta.vlen();
                let mut members = Vec::new();
                for _ in 0..vlen {
                    let member = from.gread(offset)?;
                    members.push(member);
                }
                Self::Struct {
                    id,
                    ty: CtfStruct {
                        name,
                        size,
                        members,
                    },
                }
            }
            TypeKind::Union => {
                if size >= 8192 {
                    unimplemented!("large unions are no supported yet");
                }
                let vlen = meta.vlen();
                let mut members = Vec::new();
                for _ in 0..vlen {
                    let member = from.gread(offset)?;
                    members.push(member);
                }
                Self::Union {
                    id,
                    ty: CtfUnion {
                        name,
                        size,
                        members,
                    },
                }
            }
            TypeKind::Enum => {
                let vlen = meta.vlen();
                let mut enumerators = Vec::new();
                for _ in 0..vlen {
                    let en = from.gread(offset)?;
                    enumerators.push(en);
                }
                Self::Enum {
                    id,
                    ty: CtfEnum {
                        name,
                        size,
                        enumerators,
                    },
                }
            }
            TypeKind::Forward => Self::Forward {
                id,
                ty: CtfForward { name },
            },
            TypeKind::Typedef => {
                let target_type = TypeId::try_from(size)?;
                Self::Typedef {
                    id,
                    ty: CtfTypedef { name, target_type },
                }
            }
            TypeKind::Volatile => {
                let target_type = TypeId::try_from(size)?;
                Self::Volatile {
                    id,
                    ty: CtfVolatile { name, target_type },
                }
            }
            TypeKind::Const => {
                let target_type = TypeId::try_from(size)?;
                Self::Const {
                    id,
                    ty: CtfConst { name, target_type },
                }
            }
            TypeKind::Restrict => {
                let target_type = TypeId::try_from(size)?;
                Self::Restrict {
                    id,
                    ty: CtfRestrict { name, target_type },
                }
            }
        };

        Ok((ty, *offset))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfInteger {
    pub name: StrId,
    pub size: u16,
    pub encoding: CtfIntEncoding,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfFloat {
    pub name: StrId,
    pub size: u16,
    pub encoding: CtfFloatEncoding,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfPointer {
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfArray {
    pub name: StrId,
    pub element_type: TypeId,
    pub index_type: TypeId,
    pub nelems: u32,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfFunction {
    pub name: StrId,
    pub return_type: TypeId,
    pub args: Vec<TypeId>,
    pub is_varargs: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfStruct {
    pub name: StrId,
    pub size: u16,
    pub members: Vec<CtfMember>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfMember {
    pub name: StrId,
    pub type_id: TypeId,
    pub offset_bits: u16,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfUnion {
    pub name: StrId,
    pub size: u16,
    pub members: Vec<CtfMember>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfEnum {
    pub name: StrId,
    pub size: u16,
    pub enumerators: Vec<CtfEnumerator>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfEnumerator {
    pub name: StrId,
    pub value: i32,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfForward {
    pub name: StrId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfTypedef {
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfVolatile {
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfConst {
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfRestrict {
    pub name: StrId,
    pub target_type: TypeId,
}

impl CtfMember {
    pub fn name<'a>(&self, ctf: &'a CtfReader) -> &'a str {
        ctf.str(self.name)
    }

    pub fn ty<'a>(&self, ctf: &'a CtfReader) -> &'a CtfType {
        ctf.ty(self.type_id)
    }
}

impl TryFromCtx<'_, ()> for CtfMember {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name: StrId = from.gread(offset)?;
        // TODO this will fail on varargs
        let type_id = from.gread(offset)?;
        let offset_bits = from.gread(offset)?;

        Ok((
            CtfMember {
                name,
                type_id,
                offset_bits,
            },
            *offset,
        ))
    }
}

impl TryFromCtx<'_, ()> for CtfEnumerator {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name: StrId = from.gread(offset)?;
        let value = from.gread(offset)?;

        Ok((CtfEnumerator { name, value }, *offset))
    }
}

pub struct TypeReader {
    pub path: &'static [TypeInfo],
    pub target_member: &'static str,
}

pub struct TypeInfo {
    pub name: &'static str,
    pub type_kind: TypeKind,
}

/// Result of type traversal containing the resolved type and accumulated metadata.
#[derive(Clone, Debug)]
pub struct ResolvedType<'a> {
    /// The final resolved type after following the path.
    pub ty: &'a CtfType,
    /// Offset in bits from the initial type to the final type.
    pub offset_bits: u32,
    /// Size in bytes of the final resolved type.
    pub size_bytes: u16,
    /// All enum metadata encountered during traversal, in order.
    pub enums: Vec<EnumInfo<'a>>,
}

/// Complete metadata about a Rust enum encountered during type traversal.
#[derive(Clone, Debug)]
pub struct EnumInfo<'a> {
    /// The CTF struct type representing the enum.
    pub enum_struct: &'a CtfType,
    /// Name of the enum type.
    pub name: &'a str,
    /// Discriminant information.
    pub discriminant: DiscriminantInfo<'a>,
    /// All variants in this enum.
    pub variants: Vec<VariantInfo<'a>>,
    /// Offset in bits from the initial type to this enum.
    pub offset_bits: u32,
}

/// Discriminant layout information.
#[derive(Clone, Debug)]
pub enum DiscriminantInfo<'a> {
    /// Standard discriminant stored as a separate field.
    Separate {
        /// The __discr member type (Enum or Integer).
        ty: &'a CtfType,
        /// Offset in bits within the enum struct.
        offset_bits: u16,
        /// Size in bytes of the discriminant.
        size_bytes: u16,
    },
    /// Niche-optimized: no separate discriminant field.
    Niche,
}

/// Information about a single enum variant.
#[derive(Clone, Debug)]
pub struct VariantInfo<'a> {
    /// Variant name (from the union member name).
    pub name: &'a str,
    /// The struct type containing variant fields.
    pub ty: &'a CtfType,
    /// Discriminant value for this variant (from CtfEnumerator if available).
    pub discriminant_value: Option<i32>,
}

/// Check if a type represents a Rust enum (has __variants union member).
fn is_rust_enum(ty: &CtfType, ctf: &CtfReader) -> bool {
    ty.kind() == TypeKind::Struct && ty.members().iter().any(|m| m.name(ctf) == "__variants")
}

/// Extract enum metadata from a Rust enum struct.
fn extract_enum_info<'a>(
    enum_struct: &'a CtfType,
    ctf: &'a CtfReader,
    offset_bits: u32,
) -> Option<EnumInfo<'a>> {
    let members = enum_struct.members();

    // Find __variants union
    let variants_member = members.iter().find(|m| m.name(ctf) == "__variants")?;
    let variants_union = variants_member.ty(ctf);

    // Find __discr if present (non-niche)
    let discr_member = members.iter().find(|m| m.name(ctf) == "__discr");

    let discriminant = match discr_member {
        Some(discr) => {
            let discr_ty = discr.ty(ctf);
            DiscriminantInfo::Separate {
                ty: discr_ty,
                offset_bits: discr.offset_bits,
                size_bytes: discr_ty.size(ctf),
            }
        }
        None => DiscriminantInfo::Niche,
    };

    // Extract variants from union, with discriminant values from enum type
    let variants = extract_variants(variants_union, discr_member, ctf);

    Some(EnumInfo {
        enum_struct,
        name: enum_struct.name(ctf),
        discriminant,
        variants,
        offset_bits,
    })
}

/// Extract variant info from __variants union.
fn extract_variants<'a>(
    variants_union: &'a CtfType,
    discr_member: Option<&CtfMember>,
    ctf: &'a CtfReader,
) -> Vec<VariantInfo<'a>> {
    // If discriminant is an enum type, build name->value map
    let discr_values: HashMap<&str, i32> = discr_member
        .map(|m| m.ty(ctf))
        .and_then(|ty| match ty {
            CtfType::Enum {
                ty: CtfEnum { enumerators, .. },
                ..
            } => Some(
                enumerators
                    .iter()
                    .map(|e| (ctf.str(e.name), e.value))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    variants_union
        .members()
        .iter()
        .map(|m| {
            let name = m.name(ctf);
            VariantInfo {
                name,
                ty: m.ty(ctf),
                discriminant_value: discr_values.get(name).copied(),
            }
        })
        .collect()
}

impl TypeReader {
    /// Navigate through nested types, returning just the final type.
    /// Maintained for backward compatibility.
    pub fn read_type<'a>(&self, initial_type: &'a CtfType, ctf: &'a CtfReader) -> Option<&'a CtfType> {
        self.read_type_full(initial_type, ctf).map(|r| r.ty)
    }

    /// Navigate through nested types, returning full metadata including
    /// accumulated offset, size, and enum information.
    pub fn read_type_full<'a>(
        &self,
        initial_type: &'a CtfType,
        ctf: &'a CtfReader,
    ) -> Option<ResolvedType<'a>> {
        let mut accumulated_offset: u32 = 0;
        let mut enums_found: Vec<EnumInfo<'a>> = Vec::new();
        let mut the_members = initial_type.members();

        // Check if initial type is an enum
        if is_rust_enum(initial_type, ctf) {
            if let Some(info) = extract_enum_info(initial_type, ctf, 0) {
                enums_found.push(info);
            }
        }

        let mut iter = self.path.iter().peekable();
        while let Some(TypeInfo { name, type_kind }) = iter.next() {
            let member = the_members.iter().find(|m| m.name(ctf) == *name)?;
            accumulated_offset += member.offset_bits as u32;

            let child_ty = member.ty(ctf);

            // Check for enum at each step
            if is_rust_enum(child_ty, ctf) {
                if let Some(info) = extract_enum_info(child_ty, ctf, accumulated_offset) {
                    enums_found.push(info);
                }
            }

            if iter.peek().is_some() {
                if child_ty.kind() != *type_kind {
                    panic!("unexpected kind {:?}", child_ty.kind());
                }
                the_members = child_ty.members();
            } else {
                return Some(ResolvedType {
                    ty: child_ty,
                    offset_bits: accumulated_offset,
                    size_bytes: child_ty.size(ctf),
                    enums: enums_found,
                });
            }
        }

        None
    }
}

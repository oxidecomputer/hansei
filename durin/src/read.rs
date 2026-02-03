use crate::constants::*;
use crate::{CtfHeader, CtfPreamble, Error, Result, StrId, StringTableType, TypeId, TypeKind};

use flate2::read::ZlibDecoder;
use proc::Core;
use scroll::Pread;
use scroll::ctx::TryFromCtx;

use std::collections::HashMap;
use std::fmt;
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
            return Err(Error::too_short(input.len() as u32, HEADER_SIZE as u32));
        }
        let preamble: CtfPreamble = input.gread(offset)?;
        let header: CtfHeader = input.gread(offset)?;

        let expected_len = header.stroff + header.strlen;
        let data = if preamble.flags.is_compressed() {
            let mut decompressor = ZlibDecoder::new(&input[HEADER_SIZE..]);
            let mut buf = Vec::new();

            decompressor
                .read_to_end(&mut buf)
                .map_err(Error::decompress)?;
            if expected_len as usize > buf.len() {
                return Err(Error::too_short(buf.len() as u32, expected_len));
            }
            buf
        } else {
            if expected_len as usize > input.len() {
                return Err(Error::too_short(input.len() as u32, expected_len));
            }
            let data = input.get(HEADER_SIZE..).unwrap();
            data.to_vec()
        };

        let labels = read_labels(&header, &data)?;
        let objects = read_objects(&header, &data)?;
        let functions = Vec::new(); // TODO
        let mut types = TypeTable::load(&header, &data)?;
        let strings = StringTable::new(&header, &data);

        // TODO how expensive is this check? Do we care?
        // If this is a real library we should make this optional.
        validate_types(&types, &strings)?;

        update_large_enums(&mut types, &strings)?;

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

    pub fn ty<'ctf>(&'ctf self, id: TypeId) -> &'ctf CtfType {
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

    pub fn types<'ctf>(&'ctf self) -> &'ctf [CtfType] {
        self.types.as_slice()
    }

    pub fn find_ty<'ctf>(&'ctf self, name: &str, kind: TypeKind) -> Option<&'ctf CtfType> {
        self.types()
            .iter()
            .find(|t| t.kind() == kind && t.name(self) == name)
    }

    pub fn tys_by_name<'ctf>(&'ctf self) -> HashMap<&'ctf str, &'ctf CtfType> {
        self.types()
            .iter()
            .map(|t| {
                let name = t.name(&self);
                (name, t)
            })
            .collect()
    }

    pub fn str<'ctf>(&'ctf self, id: StrId) -> &'ctf str {
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

/// CTF requires that enum values be 4 bytes, but we're going to work around
/// this by passing longer values in the name. Parse the inline value as an
/// i32. Once all strings are parsed, take a second pass to update the values as
/// necessary.
fn update_large_enums(types: &mut TypeTable, strings: &StringTable) -> Result<()> {
    let iter = types.as_slice_mut().into_iter().filter_map(|t| match t {
        CtfType::Enum { ty, .. } => Some(ty),
        _ => None,
    });

    for ty in iter {
        for enm in &mut ty.enumerators {
            let name = strings.get(enm.name);
            if name.ends_with("@@") {
                let hex_num = name
                    .splitn(3, "@@")
                    .nth(1)
                    .ok_or_else(|| Error::invalid_enum_format(name.to_string()))?;
                let bare_hex = hex_num.trim_start_matches("0x");

                // The Rust standard says the default representation of
                // discriminants is isize, but top-bit niches will result in
                // a value > isize::MAX, so we use u64.
                let full_value = u64::from_str_radix(bare_hex, 16)
                    .map_err(|_| Error::invalid_enum_value(name.to_string()))?;
                enm.value = full_value
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
            return Err(Error::invalid_magic(magic));
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
            return Err(Error::misaligned_label_offset(lbloff));
        }
        let objtoff = from.gread(offset)?;
        if objtoff % 2 != 0 {
            return Err(Error::misaligned_object_offset(objtoff));
        }
        let funcoff = from.gread(offset)?;
        if funcoff % 4 != 0 {
            return Err(Error::misaligned_func_offset(funcoff));
        }
        let typeoff = from.gread(offset)?;
        if typeoff % 4 != 0 {
            return Err(Error::misaligned_type_offset(typeoff));
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

    pub fn ty_checked<'ctf>(&'ctf self, id: TypeId) -> Result<&'ctf CtfType> {
        let Some(ty) = self.types.get(id.get() as usize) else {
            return Err(Error::missing_type(id));
        };

        Ok(ty)
    }

    pub fn as_slice(&self) -> &[CtfType] {
        &self.types
    }

    pub fn as_slice_mut(&mut self) -> &mut [CtfType] {
        &mut self.types
    }
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
    /// index, is correctly encoded, and is in the expected table.
    fn get_checked<'a>(&'a self, id: StrId) -> Result<&'a str> {
        if matches!(id.table(), StringTableType::External) {
            return Err(Error::external_str(id));
        }

        let bytes = self
            .inner
            .get(id.offset() as usize..)
            .ok_or_else(|| Error::missing_str(id))?;

        let Some(substr) = bytes.split(|&b| b == 0).next() else {
            return Err(Error::unterminated_str(id));
        };

        let s = str::from_utf8(substr).map_err(|_| Error::invalid_str_encoding(id))?;
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
    // pub fn is_root(&self) -> bool {
    //     (self.0 & 0x0400) >> 10 == 1
    // }

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
            v => return Err(Error::invalid_float_encoding(v)),
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
    pub fn id(&self) -> TypeId {
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

    pub fn member(&self, name: &str, ctf: &CtfReader) -> Option<&CtfMember> {
        let members = match self {
            CtfType::Struct {
                ty: CtfStruct { members, .. },
                ..
            } => members.as_slice(),
            CtfType::Union {
                ty: CtfUnion { members, .. },
                ..
            } => members.as_slice(),
            _ => return None,
        };
        members.iter().find(|m| m.name(ctf) == name)
    }

    pub fn has_member(&self, name: &str, ctf: &CtfReader) -> bool {
        let members = match self {
            CtfType::Struct {
                ty: CtfStruct { members, .. },
                ..
            } => members.as_slice(),
            CtfType::Union {
                ty: CtfUnion { members, .. },
                ..
            } => members.as_slice(),
            _ => return false,
        };
        members.iter().any(|m| m.name(ctf) == name)
    }

    /// Return all members of the `CtfType` resolved into full `CtfTypes`.
    pub fn members_resolved<'ctf>(&self, ctf: &'ctf CtfReader) -> Vec<(&'ctf str, &'ctf CtfType)> {
        let members = self.members();

        let mut resolved = Vec::with_capacity(members.len());
        for member in members {
            let mem_name = ctf.str(member.name);
            let mem_ty = ctf.ty(member.type_id);
            resolved.push((mem_name, mem_ty));
        }

        resolved
    }

    pub fn name<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf str {
        let Some(id) = self.name_id() else {
            return "";
        };
        ctf.str(id)
    }

    fn name_checked<'ctf>(&self, strings: &'ctf StringTable) -> Result<&'ctf str> {
        let Some(id) = self.name_id() else {
            return Ok("");
        };
        strings.get_checked(id)
    }

    fn name_id(&self) -> Option<StrId> {
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
                match size {
                    1 | 2 | 4 | 8 => {}
                    _ => return Err(Error::invalid_enum_size(size)),
                }
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
    pub value: u64,
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
    pub fn name<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf str {
        ctf.str(self.name)
    }

    pub fn ty<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf CtfType {
        ctf.ty(self.type_id)
    }

    /// The member's offset in bytes.
    pub fn offset(&self) -> u64 {
        self.offset_bits as u64 / 8
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

impl CtfEnumerator {
    pub fn name<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf str {
        ctf.str(self.name)
    }
}

impl TryFromCtx<'_, ()> for CtfEnumerator {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name: StrId = from.gread(offset)?;
        // CTF requires that enum values be 4 bytes, but we're going to work
        // around this by passing long values in the name. Parse the inline
        // value as an i32. Once all strings are parsed we will take a second
        // pass to update the values as needed.
        let value: i32 = from.gread(offset)?;

        Ok((
            CtfEnumerator {
                name,
                value: value as u64,
            },
            *offset,
        ))
    }
}

#[derive(Clone)]
pub struct TypeInfo<'ctf> {
    pub ty: &'ctf CtfType,
    pub addr: u64,
    pub buf: Vec<u8>,
}

impl<'buf, 'ctf: 'buf> TypeInfo<'ctf> {
    /// Read the type directly at the address provided.
    /// Wrapper types will be unwrapped if present. TODO
    pub fn from_addr<Ctx: CtfContext<'ctf>>(
        ctx: Ctx,
        ty: &'ctf CtfType,
        addr: u64,
    ) -> Result<Option<Self>> {
        let Some(buf) = ctx.core().read_type(addr, ty, ctx.ctf())? else {
            return Ok(None);
        };
        Ok(Some(Self { ty, addr, buf }))
    }

    pub fn as_ref(&'buf self) -> TypeInfoRef<'buf, 'ctf> {
        self.into()
    }

    pub fn try_member<Ctx: CtfContext<'ctf>>(
        &'buf self,
        ctx: Ctx,
        name: &str,
    ) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        self.as_ref().try_member(ctx, name)
    }

    pub fn member<Ctx: CtfContext<'ctf>>(
        &'buf self,
        ctx: Ctx,
        name: &str,
    ) -> Result<TypeInfoRef<'buf, 'ctf>> {
        self.as_ref().member(ctx, name)
    }

    pub fn try_deref_ptr<Ctx: CtfContext<'ctf>>(&self, ctx: Ctx) -> Result<Option<TypeInfo<'ctf>>> {
        self.as_ref().try_deref_ptr(ctx)
    }

    pub fn deref_ptr<Ctx: CtfContext<'ctf>>(&self, ctx: Ctx) -> Result<TypeInfo<'ctf>> {
        self.as_ref().deref_ptr(ctx)
    }

    pub fn try_select_variant<Ctx: CtfContext<'ctf>>(
        &'buf self,
        ctx: Ctx,
        name: &str,
    ) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        self.as_ref().try_select_variant(ctx, name)
    }

    pub fn select_variant<Ctx: CtfContext<'ctf>>(
        &'buf self,
        ctx: Ctx,
        name: &str,
    ) -> Result<TypeInfoRef<'buf, 'ctf>> {
        self.as_ref().select_variant(ctx, name)
    }

    pub fn array_elements<Ctx: CtfContext<'ctf>>(
        &'buf self,
        ctx: Ctx,
    ) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
        array_elements(self.ty, self.addr, &self.buf, ctx)
    }

    pub fn parse<T, Ctx>(&self, ctx: Ctx) -> Result<T>
    where
        T: ParseWithCtf<'ctf, Ctx>,
        Ctx: CtfContext<'ctf>,
    {
        self.as_ref().parse(ctx)
    }

    pub fn box2<Ctx: CtfContext<'ctf>>(
        &'buf self,
        ctx: Ctx,
    ) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>>
    where
        'ctf: 'buf,
    {
        boxed_slice_elements(&self, ctx)
    }

    /// Parse the elements of a boxed slice, returning them in a Vec.
    pub fn boxed_slice_elements<T, Ctx, F>(&self, ctx: Ctx, mut f: F) -> Result<()>
    where
        F: FnMut(&TypeInfoRef<'_, '_>) -> Result<()>,
        Ctx: CtfContext<'ctf>,
    {
        let ctf = ctx.ctf();
        let core = ctx.core();

        let len: u64 = self.member(ctx, "length")?.parse(ctx)?;
        let ptr = self.member(ctx, "data_ptr")?;
        let CtfType::Pointer {
            ty: CtfPointer { target_type, .. },
            ..
        } = ptr.ty
        else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                self.ty.name(ctf).to_string(),
            ));
        };
        let param_ty = ctf.ty(*target_type);
        let elem_size = param_ty.size(ctf) as u64;

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size(ctf) as u64;

        let raw = core.read_bytes(p, total_len)?.unwrap();

        for (i, chunk) in raw.chunks(elem_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: p + (i as u64) * elem_size,
                bytes: chunk,
            }
            .peel(ctx);
            f(&item_info)?;
        }

        Ok(())
    }
}

impl<'buf, 'ctf: 'buf> From<TypeInfoRef<'buf, 'ctf>> for TypeInfo<'ctf> {
    #[inline]
    fn from(TypeInfoRef { ty, addr, bytes }: TypeInfoRef<'buf, 'ctf>) -> Self {
        Self {
            ty,
            addr,
            buf: bytes.to_vec(),
        }
    }
}

impl fmt::Debug for TypeInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeInfo")
            .field("ty", &format_args!("TypeId({})", self.ty.id().get()))
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("buf", &self.buf)
            .field("reader", &"&dyn BytesFromCore")
            .finish()
    }
}

#[derive(Clone)]
pub struct TypeInfoRef<'buf, 'ctf: 'buf> {
    pub ty: &'ctf CtfType,
    pub addr: u64,
    pub bytes: &'buf [u8],
}

impl Eq for TypeInfoRef<'_, '_> {}

impl PartialEq for TypeInfoRef<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty && self.addr == other.addr && self.bytes == other.bytes
    }
}

impl<'buf, 'ctf: 'buf> TypeInfoRef<'buf, 'ctf> {
    pub fn try_member<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
        name: &str,
    ) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        let ctf = ctx.ctf();

        let Some(member) = self.ty.member(name, ctf) else {
            return Ok(None);
        };
        let ty = ctf.ty(member.type_id);

        let start = member.offset() as u16;
        let end = start + ty.size(ctf);
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + member.offset();

        Ok(Some(TypeInfoRef { ty, addr, bytes }.peel(ctx)))
    }

    pub fn member<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
        name: &str,
    ) -> Result<TypeInfoRef<'buf, 'ctf>> {
        let Some(member) = self.try_member(ctx, name)? else {
            return Err(Error::no_member(self.ty.id(), name.to_string()));
        };

        Ok(member)
    }

    pub fn try_deref_ptr<Ctx: CtfContext<'ctf>>(&self, ctx: Ctx) -> Result<Option<TypeInfo<'ctf>>> {
        let ctf = ctx.ctf();
        let core = ctx.core();

        let peeled = self.clone().peel(ctx);
        let CtfType::Pointer {
            ty: CtfPointer { target_type, .. },
            ..
        } = peeled.ty
        else {
            return Err(Error::unexpected_type(
                self.ty.kind(),
                TypeKind::Pointer,
                format!("{} ({:?})", self.ty.name(ctf), self.ty.id()),
            ));
        };

        let Some(&bytes) = self.bytes.first_chunk::<8>() else {
            return Err(Error::too_short(self.bytes.len() as u32, 8));
        };

        let addr = u64::from_le_bytes(bytes);
        let target_ty = ctf.ty(*target_type);
        let Some(buf) = core.read_type(addr, target_ty, ctf)? else {
            return Ok(None);
        };
        let mut final_ty = target_ty;
        while let Some(unwrapped) = unwrap_wrapper_struct(final_ty, ctf) {
            final_ty = unwrapped;
        }

        Ok(Some(TypeInfo {
            ty: final_ty,
            addr,
            buf,
        }))
    }

    pub fn deref_ptr<Ctx: CtfContext<'ctf>>(&self, ctx: Ctx) -> Result<TypeInfo<'ctf>> {
        match self.try_deref_ptr(ctx) {
            Ok(Some(i)) => Ok(i),
            Ok(None) => Err(Error::null_ptr()),
            Err(e) => Err(Error::null_ptr().with_source(e)),
        }
    }

    pub fn try_select_variant<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
        name: &str,
    ) -> Result<Option<TypeInfoRef<'buf, 'ctf>>> {
        let ctf = ctx.ctf();
        let (discrim_value, enumerators) = self.read_discriminant(ctx)?;

        let Some(variants_member) = self.ty.member("__variants", ctf) else {
            return Err(Error::no_member(self.ty.id(), "__variants".to_string()));
        };
        let variants = variants_member.ty(ctf);

        // In niche-optimized enums only one enumerator will be defined, with two
        // possible variants.
        let is_niche_optimized = variants.members().len() == 2 && enumerators.len() == 1;

        // Find the enumerator whose name matches our expected value. It is common
        // common for our expected name to be missing due to niche-optimized enums.
        let enumerator = enumerators.iter().find(|e| e.name(ctf) == name);

        match (enumerator, is_niche_optimized) {
            (Some(e), _) => {
                if e.value != discrim_value {
                    return Ok(None);
                }
            }
            (None, true) => {
                // The single defined enumerator for a niche-optimized enum matches
                // the discriminant, but we're looking for an undefined variant. We
                // can deduce that we've hit the variant we don't want.
                if discrim_value == enumerators[0].value {
                    return Ok(None);
                }
            }
            (None, false) => {
                // Not a niche-optimized enum, so each variant should have a
                // matching enumerator, but we didn't find it. User error.
                return Err(Error::no_enumerator(variants.id(), name.to_string()));
            }
        }

        let Some(selected_variant) = variants.member(name, ctf) else {
            return Err(Error::no_member(self.ty.id(), name.to_string()));
        };
        let mut ty = selected_variant.ty(ctf);
        while let Some(unwrapped) = unwrap_wrapper_struct(ty, ctf) {
            ty = unwrapped;
        }

        let start = selected_variant.offset() as u16;
        let end = start + ty.size(ctf);
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + selected_variant.offset();

        Ok(Some(TypeInfoRef { ty, addr, bytes }.peel(ctx)))
    }

    pub fn select_variant<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
        name: &str,
    ) -> Result<TypeInfoRef<'buf, 'ctf>> {
        let Some(info) = self.try_select_variant(ctx, name)? else {
            return Err(Error::unexpected_variant(name.to_string()));
        };

        Ok(info)
    }

    pub fn parse<T: ParseWithCtf<'ctf, Ctx>, Ctx: CtfContext<'ctf>>(&self, ctx: Ctx) -> Result<T> {
        T::parse_with_ctf(ctx, &self)
            .map_err(|e| Error::parse_type(self.ty.name(ctx.ctf())).with_source(e))
    }

    pub fn to_owned(&self) -> TypeInfo<'ctf> {
        self.clone().into()
    }

    pub fn with_ty(mut self, ty: &'ctf CtfType) -> TypeInfoRef<'buf, 'ctf> {
        self.ty = ty;
        self
    }

    pub fn with_addr(mut self, addr: u64) -> TypeInfoRef<'buf, 'ctf> {
        self.addr = addr;
        self
    }

    pub fn with_buf(mut self, buf: &'buf [u8]) -> TypeInfoRef<'buf, 'ctf> {
        self.bytes = &buf;
        self
    }

    /// Get an iterator of `TypeInfoRef`s over the elements of an array.
    pub fn array_elements<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
    ) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
        array_elements(self.ty, self.addr, self.bytes, ctx)
    }

    /// Parse the elements of a boxed slice, returning them in a Vec.
    pub fn boxed_slice_elements<T, Ctx, F>(&self, ctx: Ctx, mut f: F) -> Result<Vec<T>>
    where
        F: FnMut(&TypeInfoRef<'_, '_>) -> Result<T>,
        Ctx: CtfContext<'ctf>,
    {
        let ctf = ctx.ctf();
        let core = ctx.core();

        let len: u64 = self.member(ctx, "length")?.parse(ctx)?;
        let ptr = self.member(ctx, "data_ptr")?;
        let CtfType::Pointer {
            ty: CtfPointer { target_type, .. },
            ..
        } = ptr.ty
        else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                self.ty.name(ctf).to_string(),
            ));
        };
        let param_ty = ctf.ty(*target_type);
        let elem_size = param_ty.size(ctf) as u64;

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size(ctf) as u64;

        let mut out = Vec::with_capacity(len as usize);
        let raw = core.read_bytes(p, total_len)?.unwrap();

        for (i, chunk) in raw.chunks(elem_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: p + (i as u64) * elem_size,
                bytes: chunk,
            }
            .peel(ctx);
            let item = f(&item_info)?;
            out.push(item);
        }

        Ok(out)
    }

    pub fn active_variant<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
    ) -> Result<(&'ctf str, TypeInfoRef<'buf, 'ctf>)> {
        let ctf = ctx.ctf();
        let (discrim, enumerators) = self.read_discriminant(ctx)?;

        let Some(variants_member) = self.ty.member("__variants", ctf) else {
            return Err(Error::no_member(self.ty.id(), "__variants".to_string()));
        };
        let variants = variants_member.ty(ctf);

        // In niche-optimized enums only one enumerator will be defined, with two
        // possible variants.
        let is_niche_optimized = variants.members().len() == 2 && enumerators.len() == 1;

        // Find the enumerator whose name matches our expected value. It is common
        // common for our expected name to be missing due to niche-optimized enums.
        let enumerator = enumerators.iter().find(|e| e.value == discrim);

        let name = match (enumerator, is_niche_optimized) {
            (Some(e), _) => e.name(ctf),
            (None, true) => {
                // UNWRAP: We know there are only two variants as this is
                // niche-optimized, so the one that doesn't match the only
                // enumerator must be active.
                let var = variants
                    .members()
                    .iter()
                    .find(|m| m.name(ctf) != enumerators.first().unwrap().name(ctf))
                    .unwrap();
                var.name(ctf)
            }
            (None, false) => {
                // Not a niche-optimized enum, so each variant should have a
                // matching enumerator, but we didn't find it. The discriminant
                // value is incorrect.
                return Err(Error::invalid_discriminant_value(self.ty.id(), discrim));
            }
        };

        // Remove any large discriminant values we've smuggled in via the
        // enumerator name.
        let name = name.splitn(2, "@@").next().unwrap_or_default();
        let Some(selected_variant) = variants.member(name, ctf) else {
            return Err(Error::no_member(self.ty.id(), name.to_string()));
        };
        let ty = selected_variant.ty(ctf);

        let start = selected_variant.offset() as u16;
        let end = start + ty.size(ctf);
        let Some(bytes) = self.bytes.get(start as usize..end as usize) else {
            let len = self.bytes.len() as u16;
            return Err(Error::invalid_member_range(start, end, len));
        };
        let addr = self.addr + selected_variant.offset();

        Ok((name, TypeInfoRef { ty, addr, bytes }.peel(ctx)))
    }

    /// Check if the type is a wrapper struct, and return its inner type is it
    /// is. This are defined as a struct with only a single sized member. The
    /// buffer will be adjusted if the member is smaller than the parent
    /// struct.
    pub fn peel<Ctx: CtfContext<'ctf>>(self, ctx: Ctx) -> TypeInfoRef<'buf, 'ctf> {
        let ctf = ctx.ctf();
        let mut info = self;

        loop {
            if info.ty.kind() != TypeKind::Struct {
                break;
            }

            let members = info.ty.members();

            // Zero-sized struct members have no impact on memory layout
            // and can be ignored. Check if there is only one sized member, and
            // peel to it if yes.
            let mut iter = members
                .iter()
                .map(|m| (m, m.ty(ctf)))
                .filter(|(_m, t)| t.size(ctf) > 0);

            let (member, mem_ty) = match (iter.next(), iter.next()) {
                (Some((member, mem_ty)), None) => (member, mem_ty),
                _ => break,
            };

            let start = member.offset() as usize;
            let end = start + mem_ty.size(ctf) as usize;

            // TODO VALIDATE AHEAD OF TIME
            info.bytes = info.bytes.get(start..end).unwrap();
            info.ty = mem_ty;
        }

        info
    }

    fn read_discriminant<Ctx: CtfContext<'ctf>>(
        &self,
        ctx: Ctx,
    ) -> Result<(u64, &[CtfEnumerator])> {
        let ctf = ctx.ctf();
        let size = self.ty.size(ctf);
        if self.bytes.len() < size as usize {
            return Err(Error::too_short(self.bytes.len() as u32, size as u32));
        }

        let Some(discriminant) = self.ty.member("__discr", ctf) else {
            return Err(Error::no_member(self.ty.id(), "__discr".to_string()));
        };

        let discr_enum = ctf.ty(discriminant.type_id);
        let CtfType::Enum {
            ty: CtfEnum { enumerators, .. },
            ..
        } = discr_enum
        else {
            return Err(Error::unexpected_type(
                self.ty.kind(),
                TypeKind::Enum,
                format!("{} ({:?})", self.ty.name(ctf), self.ty.id()),
            ));
        };
        let discrim_value = match discr_enum.size(ctf) as u64 {
            1 => self.bytes[0] as u64,
            2 => u16::from_le_bytes(*self.bytes.first_chunk::<2>().unwrap()) as u64,
            4 => u32::from_le_bytes(*self.bytes.first_chunk::<4>().unwrap()) as u64,
            8 => u64::from_le_bytes(*self.bytes.first_chunk::<8>().unwrap()),
            _ => unreachable!(), // validated during parsing
        };
        Ok((discrim_value, &enumerators))
    }
}

impl fmt::Debug for TypeInfoRef<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypeInfoRef")
            .field("ty", &format_args!("TypeId({})", self.ty.id().get()))
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("bytes", &self.bytes)
            .field("reader", &"&dyn BytesFromCore")
            .finish()
    }
}

impl<'buf, 'ctf: 'buf> From<&'buf TypeInfo<'ctf>> for TypeInfoRef<'buf, 'ctf> {
    #[inline]
    fn from(TypeInfo { ty, addr, buf }: &'buf TypeInfo<'ctf>) -> Self {
        Self {
            ty,
            addr: *addr,
            bytes: &buf,
        }
    }
}

pub trait CtfContext<'ctf>: Copy {
    fn ctf(&self) -> &'ctf CtfReader;
    fn core(&self) -> &'ctf Core;
}

pub trait BytesFromCore {
    /// Read the size of the provided type at address.
    /// The reader may return None if the address is unmapped.
    fn read_type(&self, addr: u64, ty: &CtfType, ctf: &CtfReader) -> Result<Option<Vec<u8>>>;

    /// Read `len` bytes at address.
    /// The reader may return None if the address is unmapped.
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Option<Vec<u8>>>;
}

/// Parse a byte slice as a type.
pub trait ParseWithCtf<'ctf, Ctx>: Sized
where
    Ctx: CtfContext<'ctf>,
{
    /// Attempt to read `Self` from the CTF type information.
    fn parse_with_ctf(ctx: Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self>;
}

impl<'ctf, Ctx: CtfContext<'ctf>> ParseWithCtf<'ctf, Ctx> for u8 {
    fn parse_with_ctf(_ctx: Ctx, info: &TypeInfoRef) -> Result<Self> {
        if info.bytes.len() < size_of::<Self>() {
            return Err(Error::too_short(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0])
    }
}

impl<'ctf, Ctx: CtfContext<'ctf>> ParseWithCtf<'ctf, Ctx> for i8 {
    fn parse_with_ctf(_ctx: Ctx, info: &TypeInfoRef) -> Result<Self> {
        if info.bytes.len() < size_of::<Self>() {
            return Err(Error::too_short(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] as i8)
    }
}

impl<'ctf, Ctx: CtfContext<'ctf>> ParseWithCtf<'ctf, Ctx> for bool {
    fn parse_with_ctf(_ctx: Ctx, info: &TypeInfoRef) -> Result<Self> {
        if info.bytes.len() < size_of::<Self>() {
            return Err(Error::too_short(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        Ok(info.bytes[0] == 1)
    }
}

macro_rules! ctf_num_impl {
    ($num_ty:ty) => {
        impl<'ctf, Ctx: CtfContext<'ctf>> ParseWithCtf<'ctf, Ctx> for $num_ty {
            fn parse_with_ctf(_ctx: Ctx, info: &TypeInfoRef) -> Result<Self> {
                if info.bytes.len() < size_of::<Self>() {
                    return Err(Error::too_short(
                        info.bytes.len() as u32,
                        size_of::<Self>() as u32,
                    ));
                }
                Ok(Self::from_le_bytes(info.bytes.try_into().unwrap()))
            }
        }
    };
}
ctf_num_impl!(u16);
ctf_num_impl!(u32);
ctf_num_impl!(u64);
ctf_num_impl!(i16);
ctf_num_impl!(i32);
ctf_num_impl!(i64);
ctf_num_impl!(f32);
ctf_num_impl!(f64);

impl<'ctf, T, Ctx> ParseWithCtf<'ctf, Ctx> for Option<T>
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: CtfContext<'ctf>,
{
    fn parse_with_ctf(ctx: Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let var = info.active_variant(ctx)?;
        let value = match var {
            ("Some", var_info) => T::parse_with_ctf(ctx, &var_info)?,
            ("None", _) => return Ok(None),
            (s, _) => {
                return Err(Error::no_enumerator(info.ty.id(), s.to_string()));
            }
        };

        Ok(Some(value))
    }
}

impl<'ctf, T, Ctx> ParseWithCtf<'ctf, Ctx> for Vec<T>
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: CtfContext<'ctf>,
{
    fn parse_with_ctf(ctx: Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let ctf = ctx.ctf();
        let core = ctx.core();

        let len: u64 = info.member(ctx, "len")?.parse(ctx)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let param_member = info.ty.member("__type_param_T", ctf).unwrap();
        let param_ty = param_member.ty(ctf);
        let param_size = param_ty.size(ctf) as u64;

        let ptr = info.member(ctx, "buf")?.member(ctx, "ptr")?;

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size(ctf) as u64;

        let raw = core.read_bytes(p, total_len)?.unwrap();
        let mut out = Vec::with_capacity(len as usize);
        for (i, chunk) in raw.chunks(param_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: info.addr + (i as u64) * param_size,
                bytes: chunk,
            };
            let item = T::parse_with_ctf(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out)
    }
}

impl<'ctf, T, Ctx> ParseWithCtf<'ctf, Ctx> for Box<[T]>
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: CtfContext<'ctf>,
{
    fn parse_with_ctf(ctx: Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let ctf = ctx.ctf();
        let core = ctx.core();

        let len: u64 = info.member(ctx, "length")?.parse(ctx)?;
        let ptr = info.member(ctx, "data_ptr")?;
        let CtfType::Pointer {
            ty: CtfPointer { target_type, .. },
            ..
        } = ptr.ty
        else {
            return Err(Error::unexpected_type(
                ptr.ty.kind(),
                TypeKind::Pointer,
                info.ty.name(ctf).to_string(),
            ));
        };
        let param_ty = ctf.ty(*target_type);
        let param_size = param_ty.size(ctf) as u64;

        let p: u64 = ptr.parse(ctx)?;
        let total_len = len * param_ty.size(ctf) as u64;

        let raw = core.read_bytes(p, total_len)?.unwrap();
        let mut out = Vec::with_capacity(len as usize);
        for (i, chunk) in raw.chunks(param_size as usize).enumerate() {
            let item_info = TypeInfoRef {
                ty: param_ty,
                addr: info.addr + (i as u64) * param_size,
                bytes: chunk,
            };
            let item = T::parse_with_ctf(ctx, &item_info)?;
            out.push(item);
        }

        Ok(out.into_boxed_slice())
    }
}

impl<'ctf, T, Ctx, const N: usize> ParseWithCtf<'ctf, Ctx> for [T; N]
where
    T: ParseWithCtf<'ctf, Ctx>,
    Ctx: CtfContext<'ctf>,
{
    fn parse_with_ctf(ctx: Ctx, info: &TypeInfoRef) -> Result<Self> {
        let ctf = ctx.ctf();

        if info.bytes.len() < size_of::<Self>() {
            return Err(Error::too_short(
                info.bytes.len() as u32,
                size_of::<Self>() as u32,
            ));
        }
        let CtfType::Array {
            ty:
                CtfArray {
                    element_type,
                    nelems,
                    ..
                },
            ..
        } = info.ty
        else {
            return Err(Error::unexpected_type(
                info.ty.kind(),
                TypeKind::Array,
                info.ty.name(ctf).to_string(),
            ));
        };

        let elem_ty = ctf.ty(*element_type);
        let size = elem_ty.size(ctf) as usize;
        let len = *nelems as usize;

        let mut items = Vec::with_capacity(len);
        for (i, slice) in info.bytes.chunks(size).enumerate() {
            let slice_info = TypeInfoRef {
                ty: elem_ty,
                addr: info.addr + (i * size) as u64,
                bytes: slice,
            };
            let item = T::parse_with_ctf(ctx, &slice_info)?;
            items.push(item);
        }
        let Ok(arr) = items.try_into() else {
            unreachable!();
        };
        Ok(arr)
    }
}

impl<'ctf, Ctx: CtfContext<'ctf>> ParseWithCtf<'ctf, Ctx> for String {
    fn parse_with_ctf(ctx: Ctx, info: &TypeInfoRef<'_, 'ctf>) -> Result<Self> {
        let core = ctx.core();

        let len: u64 = info.member(ctx, "length")?.parse(ctx)?;
        let ptr: u64 = info.member(ctx, "data_ptr")?.parse(ctx)?;
        let data = core.read_bytes(ptr, len)?.unwrap();

        let out = String::from_utf8_lossy(&data).to_string();

        Ok(out)
    }
}

/// Check if the type is a wrapper struct, and return its inner type is it is.
/// This are defined as a struct with one member whose offset is zero and its
/// contained type is same size as the wrapper type. In other words, they have
/// no effect on the memory layout of type.
/// Notably, a single member struct where that member is smaller than the
/// parent is _not_ considered a wrapper.
fn unwrap_wrapper_struct<'a>(ty: &'a CtfType, ctf: &'a CtfReader) -> Option<&'a CtfType> {
    if ty.kind() != TypeKind::Struct {
        return None;
    }

    let members = ty.members();
    let Some(member) = members.get(0) else {
        return None;
    };
    let mem_ty = member.ty(ctf);
    if mem_ty.size(ctf) == ty.size(ctf) && member.offset() == 0 {
        Some(mem_ty)
    } else {
        None
    }
}

// Split this into a free function to fix lifetime issues from calling
// `TypeInfoRef` methods from `TypeInfo`.
fn array_elements<'buf, 'ctf: 'buf, Ctx: CtfContext<'ctf>>(
    ty: &'ctf CtfType,
    addr: u64,
    bytes: &'buf [u8],
    ctx: Ctx,
) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
    let ctf = ctx.ctf();
    let CtfType::Array {
        ty: CtfArray { element_type, .. },
        ..
    } = ty
    else {
        return Err(Error::unexpected_type(
            ty.kind(),
            TypeKind::Array,
            ty.name(ctf).to_string(),
        ));
    };

    let elem_size = ctf.ty_size(*element_type) as usize;
    let iter = bytes
        .chunks_exact(elem_size)
        .enumerate()
        .map(move |(i, chunk)| {
            TypeInfoRef {
                ty: ctf.ty(*element_type),
                addr: addr + (i * elem_size) as u64,
                bytes: chunk,
            }
            .peel(ctx)
        });
    Ok(iter)
}

/// Parse the elements of a boxed slice, returning them in a Vec.
fn boxed_slice_elements<'buf, 'ctf: 'buf, Ctx: CtfContext<'ctf>>(
    ptr_info: &'buf TypeInfo<'ctf>,
    ctx: Ctx,
) -> Result<impl Iterator<Item = TypeInfoRef<'buf, 'ctf>>> {
    // todo check len?
    let elem_size = ptr_info.ty.size(ctx.ctf()) as u64;
    let iter = ptr_info
        .buf
        .chunks(elem_size as usize)
        .enumerate()
        .map(move |(i, chunk)| {
            TypeInfoRef {
                ty: ptr_info.ty,
                addr: ptr_info.addr + (i as u64) * elem_size,
                bytes: chunk,
            }
            .peel(ctx)
        });
    Ok(iter)
}

impl BytesFromCore for Core {
    fn read_type(&self, addr: u64, ty: &CtfType, ctf: &CtfReader) -> Result<Option<Vec<u8>>> {
        let mappings = self
            .mappings()
            .map_err(|e| Error::read_error(ty.id()).with_source(e))?;

        if !mappings
            .as_slice()
            .iter()
            .any(|m| m.range().contains(&addr))
        {
            return Ok(None);
        }

        let mut buf = vec![0u8; ty.size(ctf) as usize];
        self.pread_exact(&mut buf, addr)
            .map_err(|e| Error::read_error(ty.id()).with_source(e))?;
        Ok(Some(buf))
    }

    // TODO replace with method on Core?
    fn read_bytes(&self, addr: u64, len: u64) -> Result<Option<Vec<u8>>> {
        let mappings = self
            .mappings()
            .map_err(|e| Error::read_error(TypeId::try_from(1).unwrap()).with_source(e))?;

        if !mappings
            .as_slice()
            .iter()
            .any(|m| m.range().contains(&addr))
        {
            return Ok(None);
        }

        let mut buf = vec![0u8; len as usize];
        self.pread_exact(&mut buf, addr)
            .map_err(|e| Error::read_error(TypeId::try_from(1).unwrap()).with_source(e))?;
        Ok(Some(buf))
    }
}

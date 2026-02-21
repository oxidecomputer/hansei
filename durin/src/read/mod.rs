use crate::constants::*;
use crate::{
    CtfFlags, CtfHeader, CtfPreamble, CtfVersion, FloatEncoding, FloatType, HEADER_SIZE,
    IntegerEncoding, IntegerFlags, LARGE_THRESHOLD, StrId, TypeId, TypeKind, VARARGS_ID,
};
use strings::UncheckedStringTable;

use flate2::read::ZlibDecoder;
use scroll::ctx::TryFromCtx;
use scroll::{Endian, Pread};

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::str;

mod error;
mod strings;

pub use error::Error;
pub use strings::StringTable;

pub type Result<T> = std::result::Result<T, Error>;

const CTF_MAGIC_BYTES_BE: [u8; 2] = [0xcf, 0xf1];
const CTF_MAGIC_BYTES_LE: [u8; 2] = [0xf1, 0xcf];

pub struct CtfReader {
    pub preamble: CtfPreamble,
    pub header: CtfHeader,
    pub labels: Vec<CtfLabel>,
    pub objects: Vec<TypeId>,
    pub functions: Vec<TypeId>,
    types: TypeTable,
    strings: StringTable,
}

impl fmt::Debug for CtfReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct TypeWrapper<'a> {
            table: &'a TypeTable,
            ctf: &'a CtfReader,
        }

        impl fmt::Debug for TypeWrapper<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let iter = self.table.types.iter().map(|ty| (ty.name(self.ctf), ty));
                f.debug_map().entries(iter).finish()
            }
        }
        f.debug_struct("CtfReader")
            .field("preamble", &self.preamble)
            .field("header", &self.header)
            .field("labels", &self.labels)
            .field("objects", &self.objects)
            .field("functions", &self.functions)
            .field(
                "types",
                &TypeWrapper {
                    table: &self.types,
                    ctf: self,
                },
            )
            .field("strings", &self.strings)
            .finish()
    }
}

impl CtfReader {
    pub fn load(input: &[u8]) -> Result<Self> {
        let offset = &mut 0;

        if input.len() < HEADER_SIZE {
            return Err(Error::too_short(input.len() as u32, HEADER_SIZE as u32));
        }

        let magic: u16 = input.gread(offset)?;
        let endian = match magic.to_ne_bytes() {
            CTF_MAGIC_BYTES_BE => Endian::Big,
            CTF_MAGIC_BYTES_LE => Endian::Little,
            _ => return Err(Error::invalid_magic(magic)),
        };

        let preamble: CtfPreamble = input.gread_with(offset, endian)?;
        let header: CtfHeader = input.gread_with(offset, endian)?;

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

        let labels = read_labels(&header, &data, endian)?;
        let objects = read_objects(&header, &data, endian)?;
        let functions = Vec::new(); // TODO
        let mut types = TypeTable::load(&header, &data, endian)?;

        // Strings are endian-agnostic.
        let unchecked_strings = UncheckedStringTable::new(&header, &data);

        // TODO how expensive is this check? Do we care?
        // If this is a real library we should make this optional.
        validate_labels(&labels, &types, &unchecked_strings)?;
        validate_objects(&objects, &types)?;
        validate_functions(&functions, &types)?;
        validate_types(&types, &unchecked_strings)?;

        // We've now checked every source of StrIds and know that all
        // ids present point to a valid `&str`.
        let strings = StringTable::from(unchecked_strings);

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

    pub fn ty(&self, id: TypeId) -> &CtfType {
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

    pub fn types(&self) -> &[CtfType] {
        self.types.as_slice()
    }

    pub fn find_ty<'ctf>(&'ctf self, name: &str, kind: TypeKind) -> Option<&'ctf CtfType> {
        self.types()
            .iter()
            .find(|t| t.kind() == kind && t.name(self) == name)
    }

    pub fn tys_by_name(&self) -> HashMap<&str, &CtfType> {
        self.types()
            .iter()
            .map(|t| {
                let name = t.name(self);
                (name, t)
            })
            .collect()
    }

    pub fn str(&self, id: StrId) -> &str {
        self.strings.get(id)
    }
}

fn read_labels(header: &CtfHeader, data: &[u8], endian: Endian) -> Result<Vec<CtfLabel>> {
    let labels_start = header.lbloff as usize;
    let labels_end = header.objtoff as usize;
    let labels_data = &data[labels_start..labels_end];

    let offset = &mut 0;

    let mut labels = Vec::new();
    while *offset < labels_data.len() {
        let label = labels_data.gread_with(offset, endian)?;
        labels.push(label);
    }

    Ok(labels)
}

fn read_objects(header: &CtfHeader, data: &[u8], endian: Endian) -> Result<Vec<TypeId>> {
    let obj_start = header.objtoff as usize;
    let obj_end = header.funcoff as usize;
    let obj_data = &data[obj_start..obj_end];

    let offset = &mut 0;

    let mut objects = Vec::new();
    while *offset < obj_data.len() {
        let raw_id: u16 = obj_data.gread_with(offset, endian)?;
        let object = TypeId::from_u16(raw_id)?;

        objects.push(object);
    }

    Ok(objects)
}

/// Iterate over labels and confirm that all type and string references are
/// valid.
fn validate_labels(
    labels: &[CtfLabel],
    types: &TypeTable,
    strings: &UncheckedStringTable,
) -> Result<()> {
    for label in labels {
        strings.check(label.label)?;
        if let Some(ty) = label.typeidx {
            types.check(ty)?;
        }
    }

    Ok(())
}

/// Iterate over objects and confirm that all type references are valid.
fn validate_objects(objects: &[TypeId], types: &TypeTable) -> Result<()> {
    for ty in objects {
        types.check(*ty)?;
    }

    Ok(())
}

/// Iterate over functions and confirm that all type and string references are
/// valid.
fn validate_functions(functions: &[TypeId], _types: &TypeTable) -> Result<()> {
    // TODO
    for _func in functions {
        // TODO
    }

    Ok(())
}

/// Iterate over types and confirm that all type and string references are
/// valid.
fn validate_types(types: &TypeTable, strings: &UncheckedStringTable) -> Result<()> {
    for ty in types.as_slice() {
        if let Some(id) = ty.name_id() {
            strings.check(id)?;
        };
        match ty {
            CtfType::Unknown { .. } => {}
            CtfType::Integer { .. } => {}
            CtfType::Float { .. } => {}
            CtfType::Pointer {
                ty: CtfPointer { target_type, .. },
                ..
            } => {
                types.check(*target_type)?;
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
                types.check(*element_type)?;
                types.check(*index_type)?;
            }
            CtfType::Function {
                ty: CtfFunction {
                    return_type, args, ..
                },
                ..
            } => {
                types.check(*return_type)?;
                for arg in args {
                    types.check(*arg)?;
                }
            }
            CtfType::Struct {
                ty: CtfStruct { members, .. },
                ..
            } => {
                for CtfMember { name, type_id, .. } in members {
                    strings.check(*name)?;
                    types.check(*type_id)?;
                }
            }
            CtfType::Union {
                ty: CtfUnion { members, .. },
                ..
            } => {
                for CtfMember { name, type_id, .. } in members {
                    strings.check(*name)?;
                    types.check(*type_id)?;
                }
            }
            CtfType::Enum {
                ty: CtfEnum { enumerators, .. },
                ..
            } => {
                for CtfEnumerator { name, .. } in enumerators {
                    strings.check(*name)?;
                }
            }
            CtfType::Forward { .. } => {}
            CtfType::Typedef {
                ty: CtfTypedef { target_type, .. },
                ..
            } => {
                types.check(*target_type)?;
            }
            CtfType::Volatile {
                ty: CtfVolatile { target_type, .. },
                ..
            } => {
                types.check(*target_type)?;
            }
            CtfType::Const {
                ty: CtfConst { target_type, .. },
                ..
            } => {
                types.check(*target_type)?;
            }
            CtfType::Restrict {
                ty: CtfRestrict { target_type, .. },
                ..
            } => {
                types.check(*target_type)?;
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
    let iter = types.as_slice_mut().iter_mut().filter_map(|t| match t {
        CtfType::Enum { ty, .. } => Some(ty),
        _ => None,
    });

    for ty in iter {
        for enm in &mut ty.enumerators {
            let name = strings.get(enm.name);
            if name.ends_with("@@") {
                let hex_num = name
                    .split("@@")
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

impl TryFromCtx<'_, Endian> for CtfPreamble {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let vers_int: u8 = from.gread_with(offset, endian)?;
        let vers = vers_int.try_into()?;

        let flags_int: u8 = from.gread_with(offset, endian)?;
        let flags = flags_int.try_into()?;

        Ok((Self { vers, flags }, *offset))
    }
}

impl TryFromCtx<'_, Endian> for CtfHeader {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let parlabel_raw = from.gread_with(offset, endian)?;
        let parlabel = StrId::from_u32(parlabel_raw)?;
        let parname_raw = from.gread_with(offset, endian)?;
        let parname = StrId::from_u32(parname_raw)?;

        let lbloff = from.gread_with(offset, endian)?;
        if lbloff % 2 != 0 {
            return Err(Error::misaligned_label_offset(lbloff));
        }
        let objtoff = from.gread_with(offset, endian)?;
        if objtoff % 2 != 0 {
            return Err(Error::misaligned_object_offset(objtoff));
        }
        let funcoff = from.gread_with(offset, endian)?;
        if funcoff % 4 != 0 {
            return Err(Error::misaligned_func_offset(funcoff));
        }
        let typeoff = from.gread_with(offset, endian)?;
        if typeoff % 4 != 0 {
            return Err(Error::misaligned_type_offset(typeoff));
        }
        let stroff = from.gread_with(offset, endian)?;
        let stflen = from.gread_with(offset, endian)?;

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

impl TryFromCtx<'_, Endian> for CtfLabel {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let label_raw = from.gread_with(offset, endian)?;
        let label = StrId::from_u32(label_raw)?;
        let idx_int: u32 = from.gread_with(offset, endian)?;
        let typeidx = if idx_int == VARARGS_ID as u32 {
            None
        } else {
            let ty = TypeId::from_u16(idx_int as u16)?;
            Some(ty)
        };

        Ok((Self { label, typeidx }, *offset))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct TypeTable {
    types: Vec<CtfType>,
}

impl TypeTable {
    pub fn load(header: &CtfHeader, data: &[u8], endian: Endian) -> Result<Self> {
        let types_start = header.typeoff as usize;
        let types_end = header.stroff as usize;
        let types_data = &data[types_start..types_end];

        let offset = &mut 0;
        let mut id = TypeId::from_u16(1).unwrap();

        let mut types = Vec::new();
        // First slot is empty, but we use Unknown as a placeholder
        types.push(CtfType::Unknown { id });

        while *offset < types_data.len() {
            let ty = types_data.gread_with(offset, (id, endian))?;
            types.push(ty);
            let new_id = TypeId::from_u16(id.get() + 1)?;
            id = new_id;
        }

        Ok(Self { types })
    }

    pub fn ty_checked(&self, id: TypeId) -> Result<&CtfType> {
        let Some(ty) = self.types.get(id.get() as usize) else {
            return Err(Error::missing_type(id));
        };

        Ok(ty)
    }

    pub fn check(&self, id: TypeId) -> Result<()> {
        let _ = self.ty_checked(id)?;
        Ok(())
    }

    pub fn as_slice(&self) -> &[CtfType] {
        &self.types
    }

    pub fn as_slice_mut(&mut self) -> &mut [CtfType] {
        &mut self.types
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

impl TryFromCtx<'_, Endian> for CtfMetadata {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let raw = from.gread_with(offset, endian)?;

        Ok((CtfMetadata(raw), *offset))
    }
}

impl TryFromCtx<'_, Endian> for IntegerEncoding {
    type Error = Error;

    fn try_from_ctx(
        from: &'_ [u8],
        endian: Endian,
    ) -> std::result::Result<(Self, usize), Self::Error> {
        let off = &mut 0;
        let val: u32 = from.gread_with(off, endian)?;
        let raw_encoding = ((val & 0xff000000) >> 24) as u8;

        let encoding = raw_encoding.try_into()?;
        let offset = ((val & 0x00ff0000) >> 16) as u8;
        let bits = (val & 0x0000ffff) as u16;

        Ok((
            Self {
                bits,
                offset,
                flags: encoding,
            },
            *off,
        ))
    }
}

impl TryFrom<u8> for IntegerFlags {
    type Error = Error;

    fn try_from(raw: u8) -> Result<Self> {
        if raw > 0b0000_1111 {
            return Err(Error::invalid_integer_encoding(raw));
        }

        Ok(Self(raw))
    }
}

impl TryFromCtx<'_, Endian> for FloatEncoding {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let off = &mut 0;
        let val: u32 = from.gread_with(off, endian)?;
        let raw_encoding = ((val & 0xff000000) >> 24) as u8;

        let float_type = raw_encoding.try_into()?;
        let offset = ((val & 0x00ff0000) >> 16) as u8;
        let bits = (val & 0x0000ffff) as u16;

        Ok((
            Self {
                bits,
                offset,
                float_type,
            },
            *off,
        ))
    }
}

impl TryFrom<u8> for FloatType {
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

    pub fn enumerators(&self) -> &[CtfEnumerator] {
        match self {
            CtfType::Enum {
                ty: CtfEnum { enumerators, .. },
                ..
            } => enumerators,
            _ => &[],
        }
    }
}

impl TryFromCtx<'_, (TypeId, Endian)> for CtfType {
    type Error = Error;

    fn try_from_ctx(from: &[u8], ctx: (TypeId, Endian)) -> Result<(Self, usize)> {
        let (id, endian) = ctx;
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        let meta: CtfMetadata = from.gread_with(offset, endian)?;
        let size: u16 = from.gread_with(offset, endian)?;

        let ty = match meta.type_kind()? {
            TypeKind::Unknown => Self::Unknown { id },
            TypeKind::Integer => {
                let encoding = from.gread_with(offset, endian)?;
                Self::Integer {
                    id,
                    ty: CtfInteger {
                        name,
                        size,
                        encoding,
                    },
                }
            }
            TypeKind::Float => {
                let encoding = from.gread_with(offset, endian)?;
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
                let target_type = TypeId::from_u16(size)?;
                Self::Pointer {
                    id,
                    ty: CtfPointer { name, target_type },
                }
            }
            TypeKind::Array => {
                let element_type_raw = from.gread_with(offset, endian)?;
                let element_type = TypeId::from_u16(element_type_raw)?;

                let index_type_raw = from.gread_with(offset, endian)?;
                let index_type = TypeId::from_u16(index_type_raw)?;

                let nelems = from.gread_with(offset, endian)?;
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
                let return_type = TypeId::from_u16(size)?;
                let vlen = meta.vlen();
                let mut args = Vec::new();
                let mut is_varargs = false;

                for i in 0..vlen {
                    let arg_raw = from.gread_with(offset, endian)?;

                    // The final argument may a placeholder indicating varargs.
                    if i == vlen - 1 && arg_raw == VARARGS_ID {
                        is_varargs = true;
                        continue;
                    }

                    let arg = TypeId::from_u16(arg_raw)?;
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
                        is_varargs,
                    },
                }
            }
            TypeKind::Struct => {
                let vlen = meta.vlen();
                let mut members = Vec::new();
                if size >= LARGE_THRESHOLD {
                    for _ in 0..vlen {
                        let lmember: LargeCtfMember = from.gread_with(offset, endian)?;
                        members.push(lmember.into());
                    }
                } else {
                    for _ in 0..vlen {
                        let member = from.gread_with(offset, endian)?;
                        members.push(member);
                    }
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
                let vlen = meta.vlen();
                let mut members = Vec::new();
                if size >= LARGE_THRESHOLD {
                    for _ in 0..vlen {
                        let lmember: LargeCtfMember = from.gread_with(offset, endian)?;
                        members.push(lmember.into());
                    }
                } else {
                    for _ in 0..vlen {
                        let member = from.gread_with(offset, endian)?;
                        members.push(member);
                    }
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
                    let en = from.gread_with(offset, endian)?;
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
                let target_type = TypeId::from_u16(size)?;
                Self::Typedef {
                    id,
                    ty: CtfTypedef { name, target_type },
                }
            }
            TypeKind::Volatile => {
                let target_type = TypeId::from_u16(size)?;
                Self::Volatile {
                    id,
                    ty: CtfVolatile { name, target_type },
                }
            }
            TypeKind::Const => {
                let target_type = TypeId::from_u16(size)?;
                Self::Const {
                    id,
                    ty: CtfConst { name, target_type },
                }
            }
            TypeKind::Restrict => {
                let target_type = TypeId::from_u16(size)?;
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
    pub encoding: IntegerEncoding,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct CtfFloat {
    pub name: StrId,
    pub size: u16,
    pub encoding: FloatEncoding,
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
    pub offset_bits: u64,
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
        self.offset_bits / 8
    }
}

impl TryFromCtx<'_, Endian> for CtfMember {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        let type_id_raw = from.gread_with(offset, endian)?;
        let type_id = TypeId::from_u16(type_id_raw)?;

        let offset_bits = from.gread_with::<u16>(offset, endian)? as u64;

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

struct LargeCtfMember {
    pub name: StrId,
    pub type_id: TypeId,
    pub offset_bits: u64,
}

impl From<LargeCtfMember> for CtfMember {
    fn from(
        LargeCtfMember {
            name,
            type_id,
            offset_bits,
        }: LargeCtfMember,
    ) -> Self {
        Self {
            name,
            type_id,
            offset_bits,
        }
    }
}

impl TryFromCtx<'_, Endian> for LargeCtfMember {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        let type_id_raw = from.gread_with(offset, endian)?;
        let type_id = TypeId::from_u16(type_id_raw)?;

        let _padding: u16 = from.gread_with(offset, endian)?;

        let offset_hi: u32 = from.gread_with(offset, endian)?;
        let offset_lo: u32 = from.gread_with(offset, endian)?;

        let offset_bits = (offset_hi as u64) << 32 | offset_lo as u64;

        Ok((
            LargeCtfMember {
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

impl TryFromCtx<'_, Endian> for CtfEnumerator {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        // CTF requires that enum values be 4 bytes, but we're going to work
        // around this by passing long values in the name. Parse the inline
        // value as an i32. Once all strings are parsed we will take a second
        // pass to update the values as needed.
        let value: i32 = from.gread_with(offset, endian)?;

        Ok((
            CtfEnumerator {
                name,
                value: value as u64,
            },
            *offset,
        ))
    }
}

impl TryFrom<u8> for CtfVersion {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            CTF_VERSION => Ok(CtfVersion::V2),
            v => Err(Error::unsupported_version(v)),
        }
    }
}

impl TryFrom<u8> for CtfFlags {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            0 | CTF_F_COMPRESS => Ok(Self(val)),
            _ => Err(Error::invalid_flags(val)),
        }
    }
}

impl StrId {
    pub(crate) fn from_u32(value: u32) -> Result<Self> {
        if value > Self::MAX {
            return Err(Error::invalid_str_offset(value));
        }

        Ok(Self(value))
    }
}

impl TypeId {
    pub(crate) fn from_u16(value: u16) -> Result<Self> {
        if value == 0 {
            return Err(Error::invalid_type_index(value));
        }

        if value > MAX_TYPE_INDEX {
            return Err(Error::type_id_out_of_range(value));
        }

        Ok(Self(value))
    }
}

impl TryFrom<u16> for TypeKind {
    type Error = Error;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        let ty = match value {
            0 => Self::Unknown,
            1 => Self::Integer,
            2 => Self::Float,
            3 => Self::Pointer,
            4 => Self::Array,
            5 => Self::Function,
            6 => Self::Struct,
            7 => Self::Union,
            8 => Self::Enum,
            9 => Self::Forward,
            10 => Self::Typedef,
            11 => Self::Volatile,
            12 => Self::Const,
            13 => Self::Restrict,
            v => return Err(Error::invalid_type_kind(v)),
        };
        Ok(ty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::write::{self, CtfWriter};

    #[test]
    fn test_invalid_flags_caught() {
        let mut encoding = IntegerEncoding {
            offset: 0,
            bits: 32,
            flags: IntegerFlags::new(),
        };
        crate::testhelper::set_invalid_flags(&mut encoding);

        let mut writer = CtfWriter::new();
        writer
            .add_type(write::CtfType::Integer {
                name: "foo".to_string(),
                size: 32,
                encoding,
            })
            .unwrap();
        let data = writer.generate_ctf().unwrap();
        let ctf = CtfReader::load(&data);
        assert_eq!(
            ctf.unwrap_err().to_string(),
            Error::invalid_integer_encoding(0xff).to_string()
        );
    }
}

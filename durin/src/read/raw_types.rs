use crate::constants::{CTF_F_COMPRESS, CTF_LSIZE_SENT, CTF_MAX_VLEN, CTF_VERSION, MAX_TYPE_INDEX};
use crate::read::{CtfReader, Error, POINTER_SIZE, Result};
use crate::{
    CtfFlags, CtfHeader, CtfPreamble, CtfVersion, FloatEncoding, FloatType, IntegerEncoding,
    IntegerFlags, LARGE_THRESHOLD, StrId, TypeId, TypeKind, VARARGS_ID,
};

use scroll::ctx::TryFromCtx;
use scroll::{Endian, Pread};

use std::fmt;

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
    pub name: StrId,
    /// Last type associated with this label.
    pub typeidx: Option<TypeId>,
}

impl CtfLabel {
    pub fn name<'a>(&self, ctf: &'a CtfReader) -> &'a str {
        ctf.str(self.name)
    }
}

impl TryFromCtx<'_, Endian> for CtfLabel {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;
        let idx_int: u32 = from.gread_with(offset, endian)?;
        let typeidx = if idx_int == VARARGS_ID as u32 {
            None
        } else {
            let ty = TypeId::from_u16(idx_int as u16)?;
            Some(ty)
        };

        Ok((Self { name, typeidx }, *offset))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct CtfMetadata(u16);

impl CtfMetadata {
    pub fn type_kind(&self) -> Result<TypeKind> {
        ((self.0 & 0xf800) >> 11).try_into()
    }

    pub fn is_root(&self) -> bool {
        (self.0 & 0x0400) >> 10 == 1
    }

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

impl fmt::Debug for CtfMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfMetadata")
            .field("inner", &self.0)
            .field("type_kind", &self.type_kind())
            .field("vlen", &self.vlen())
            .field("is_root", &self.is_root())
            .finish()
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum RawCtfType {
    Unknown(RawCtfUnknown),
    Integer(RawCtfInteger),
    Float(RawCtfFloat),
    Pointer(RawCtfPointer),
    Array(RawCtfArray),
    Function(RawCtfFunction),
    Struct(RawCtfStruct),
    Union(RawCtfUnion),
    Enum(RawCtfEnum),
    Forward(RawCtfForward),
    Typedef(RawCtfTypedef),
    Volatile(RawCtfVolatile),
    Const(RawCtfConst),
    Restrict(RawCtfRestrict),
}

impl RawCtfType {
    pub fn id(&self) -> TypeId {
        match self {
            Self::Unknown(ty) => ty.id,
            Self::Integer(ty) => ty.id,
            Self::Float(ty) => ty.id,
            Self::Pointer(ty) => ty.id,
            Self::Array(ty) => ty.id,
            Self::Function(ty) => ty.id,
            Self::Struct(ty) => ty.id,
            Self::Union(ty) => ty.id,
            Self::Enum(ty) => ty.id,
            Self::Forward(ty) => ty.id,
            Self::Typedef(ty) => ty.id,
            Self::Volatile(ty) => ty.id,
            Self::Const(ty) => ty.id,
            Self::Restrict(ty) => ty.id,
        }
    }

    pub fn kind(&self) -> TypeKind {
        match self {
            Self::Unknown(..) => TypeKind::Unknown,
            Self::Integer(..) => TypeKind::Integer,
            Self::Float(..) => TypeKind::Float,
            Self::Pointer(..) => TypeKind::Pointer,
            Self::Array(..) => TypeKind::Array,
            Self::Function(..) => TypeKind::Function,
            Self::Struct(..) => TypeKind::Struct,
            Self::Union(..) => TypeKind::Union,
            Self::Enum(..) => TypeKind::Enum,
            Self::Forward(..) => TypeKind::Forward,
            Self::Typedef(..) => TypeKind::Typedef,
            Self::Volatile(..) => TypeKind::Volatile,
            Self::Const(..) => TypeKind::Const,
            Self::Restrict(..) => TypeKind::Restrict,
        }
    }

    pub fn members(&self) -> &[RawCtfMember] {
        match self {
            RawCtfType::Struct(RawCtfStruct { members, .. }) => members.as_slice(),
            RawCtfType::Union(RawCtfUnion { members, .. }) => members.as_slice(),
            _ => &[],
        }
    }

    pub fn member(&self, name: &str, ctf: &CtfReader) -> Option<&RawCtfMember> {
        let members = match self {
            RawCtfType::Struct(RawCtfStruct { members, .. }) => members.as_slice(),
            RawCtfType::Union(RawCtfUnion { members, .. }) => members.as_slice(),
            _ => return None,
        };
        members.iter().find(|m| m.name(ctf) == name)
    }

    pub fn name<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf str {
        let Some(id) = self.name_id() else {
            return "";
        };
        ctf.str(id)
    }

    pub(crate) fn name_id(&self) -> Option<StrId> {
        let id = match self {
            Self::Unknown(..) => return None,
            Self::Integer(RawCtfInteger { name, .. }) => name,
            Self::Float(RawCtfFloat { name, .. }) => name,
            Self::Pointer(RawCtfPointer { name, .. }) => name,
            Self::Array(RawCtfArray { name, .. }) => name,
            Self::Function(RawCtfFunction { name, .. }) => name,
            Self::Struct(RawCtfStruct { name, .. }) => name,
            Self::Union(RawCtfUnion { name, .. }) => name,
            Self::Enum(RawCtfEnum { name, .. }) => name,
            Self::Forward(RawCtfForward { name, .. }) => name,
            Self::Typedef(RawCtfTypedef { name, .. }) => name,
            Self::Volatile(RawCtfVolatile { name, .. }) => name,
            Self::Const(RawCtfConst { name, .. }) => name,
            Self::Restrict(RawCtfRestrict { name, .. }) => name,
        };
        Some(*id)
    }

    /// Return the size of bytes of the type by id, following referenced
    /// types as needed.
    pub fn size(&self, ctf: &CtfReader) -> u64 {
        match self {
            RawCtfType::Unknown(..) => 0,
            RawCtfType::Integer(RawCtfInteger { size, .. }) => *size,
            RawCtfType::Float(RawCtfFloat { size, .. }) => *size,
            RawCtfType::Pointer(..) => POINTER_SIZE,
            RawCtfType::Array(RawCtfArray {
                element_type,
                nelems,
                ..
            }) => {
                let elem_size = ctf.ty(*element_type).size(ctf);
                elem_size * *nelems as u64
            }
            RawCtfType::Function(..) => POINTER_SIZE,
            RawCtfType::Struct(RawCtfStruct { size, .. }) => *size,
            RawCtfType::Union(RawCtfUnion { size, .. }) => *size,
            RawCtfType::Enum(RawCtfEnum { size, .. }) => *size,
            RawCtfType::Forward(..) => 0,
            RawCtfType::Typedef(RawCtfTypedef { target_type, .. }) => {
                ctf.ty(*target_type).size(ctf)
            }
            RawCtfType::Volatile(RawCtfVolatile { target_type, .. }) => {
                ctf.ty(*target_type).size(ctf)
            }
            RawCtfType::Const(RawCtfConst { target_type, .. }) => ctf.ty(*target_type).size(ctf),
            RawCtfType::Restrict(RawCtfRestrict { target_type, .. }) => {
                ctf.ty(*target_type).size(ctf)
            }
        }
    }

    pub fn enumerators(&self) -> &[RawCtfEnumerator] {
        match self {
            RawCtfType::Enum(RawCtfEnum { enumerators, .. }) => enumerators,
            _ => &[],
        }
    }
}

impl TryFromCtx<'_, (TypeId, Endian)> for RawCtfType {
    type Error = Error;

    fn try_from_ctx(from: &[u8], ctx: (TypeId, Endian)) -> Result<(Self, usize)> {
        let (id, endian) = ctx;
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        let meta: CtfMetadata = from.gread_with(offset, endian)?;
        let size_or_ty: u16 = from.gread_with(offset, endian)?;
        let size = if size_or_ty == CTF_LSIZE_SENT {
            let sizehi: u32 = from.gread_with(offset, endian)?;
            let sizelo: u32 = from.gread_with(offset, endian)?;
            (sizehi as u64) << 32 | sizelo as u64
        } else {
            size_or_ty as u64
        };

        let ty = match meta.type_kind()? {
            TypeKind::Unknown => Self::Unknown(RawCtfUnknown { id }),
            TypeKind::Integer => {
                let encoding = from.gread_with(offset, endian)?;
                Self::Integer(RawCtfInteger {
                    id,
                    name,
                    size,
                    encoding,
                })
            }
            TypeKind::Float => {
                let encoding = from.gread_with(offset, endian)?;
                Self::Float(RawCtfFloat {
                    id,
                    name,
                    size,
                    encoding,
                })
            }
            TypeKind::Pointer => {
                let target_type = TypeId::from_u16(size_or_ty)?;
                Self::Pointer(RawCtfPointer {
                    id,
                    name,
                    target_type,
                })
            }
            TypeKind::Array => {
                let element_type_raw = from.gread_with(offset, endian)?;
                let element_type = TypeId::from_u16(element_type_raw)?;

                let index_type_raw = from.gread_with(offset, endian)?;
                let index_type = TypeId::from_u16(index_type_raw)?;

                let nelems = from.gread_with(offset, endian)?;
                Self::Array(RawCtfArray {
                    id,
                    name,
                    element_type,
                    index_type,
                    nelems,
                })
            }
            TypeKind::Function => {
                let return_type = TypeId::from_u16(size_or_ty)?;
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
                Self::Function(RawCtfFunction {
                    id,
                    name,
                    return_type,
                    args,
                    is_varargs,
                })
            }
            TypeKind::Struct => {
                let vlen = meta.vlen();
                let mut members = Vec::new();
                if size_or_ty >= LARGE_THRESHOLD {
                    for _ in 0..vlen {
                        let lmember: LargeRawCtfMember = from.gread_with(offset, endian)?;
                        members.push(lmember.into());
                    }
                } else {
                    for _ in 0..vlen {
                        let member = from.gread_with(offset, endian)?;
                        members.push(member);
                    }
                }
                Self::Struct(RawCtfStruct {
                    id,
                    name,
                    size,
                    members,
                })
            }
            TypeKind::Union => {
                let vlen = meta.vlen();
                let mut members = Vec::new();
                if size_or_ty >= LARGE_THRESHOLD {
                    for _ in 0..vlen {
                        let lmember: LargeRawCtfMember = from.gread_with(offset, endian)?;
                        members.push(lmember.into());
                    }
                } else {
                    for _ in 0..vlen {
                        let member = from.gread_with(offset, endian)?;
                        members.push(member);
                    }
                }
                Self::Union(RawCtfUnion {
                    id,
                    name,
                    size,
                    members,
                })
            }
            TypeKind::Enum => {
                match size {
                    1 | 2 | 4 | 8 => {}
                    _ => return Err(Error::invalid_enum_size(size_or_ty)),
                }
                let vlen = meta.vlen();
                let mut enumerators = Vec::new();
                for _ in 0..vlen {
                    let en = from.gread_with(offset, endian)?;
                    enumerators.push(en);
                }
                Self::Enum(RawCtfEnum {
                    id,
                    name,
                    size,
                    enumerators,
                })
            }
            TypeKind::Forward => Self::Forward(RawCtfForward { id, name }),
            TypeKind::Typedef => {
                let target_type = TypeId::from_u16(size_or_ty)?;
                Self::Typedef(RawCtfTypedef {
                    id,
                    name,
                    target_type,
                })
            }
            TypeKind::Volatile => {
                let target_type = TypeId::from_u16(size_or_ty)?;
                Self::Volatile(RawCtfVolatile {
                    id,
                    name,
                    target_type,
                })
            }
            TypeKind::Const => {
                let target_type = TypeId::from_u16(size_or_ty)?;
                Self::Const(RawCtfConst {
                    id,
                    name,
                    target_type,
                })
            }
            TypeKind::Restrict => {
                let target_type = TypeId::from_u16(size_or_ty)?;
                Self::Restrict(RawCtfRestrict {
                    id,
                    name,
                    target_type,
                })
            }
        };

        Ok((ty, *offset))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfUnknown {
    pub id: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfInteger {
    pub id: TypeId,
    pub name: StrId,
    pub size: u64,
    pub encoding: IntegerEncoding,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfFloat {
    pub id: TypeId,
    pub name: StrId,
    pub size: u64,
    pub encoding: FloatEncoding,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfPointer {
    pub id: TypeId,
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfArray {
    pub id: TypeId,
    pub name: StrId,
    pub element_type: TypeId,
    pub index_type: TypeId,
    pub nelems: u32,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfFunction {
    pub id: TypeId,
    pub name: StrId,
    pub return_type: TypeId,
    pub args: Vec<TypeId>,
    pub is_varargs: bool,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfStruct {
    pub id: TypeId,
    pub name: StrId,
    pub size: u64,
    pub members: Vec<RawCtfMember>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfMember {
    pub name: StrId,
    pub type_id: TypeId,
    pub offset_bits: u64,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfUnion {
    pub id: TypeId,
    pub name: StrId,
    pub size: u64,
    pub members: Vec<RawCtfMember>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfEnum {
    pub id: TypeId,
    pub name: StrId,
    pub size: u64,
    pub enumerators: Vec<RawCtfEnumerator>,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfEnumerator {
    pub name: StrId,
    pub value: i64,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfForward {
    pub id: TypeId,
    pub name: StrId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfTypedef {
    pub id: TypeId,
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfVolatile {
    pub id: TypeId,
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfConst {
    pub id: TypeId,
    pub name: StrId,
    pub target_type: TypeId,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawCtfRestrict {
    pub id: TypeId,
    pub name: StrId,
    pub target_type: TypeId,
}

impl RawCtfMember {
    pub fn name<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf str {
        ctf.str(self.name)
    }

    pub fn ty<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf RawCtfType {
        ctf.ty(self.type_id)
    }

    /// The member's offset in bytes.
    pub fn offset(&self) -> u64 {
        self.offset_bits / 8
    }
}

impl TryFromCtx<'_, Endian> for RawCtfMember {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        let type_id_raw = from.gread_with(offset, endian)?;
        let type_id = TypeId::from_u16(type_id_raw)?;

        let offset_bits = from.gread_with::<u16>(offset, endian)? as u64;

        Ok((
            RawCtfMember {
                name,
                type_id,
                offset_bits,
            },
            *offset,
        ))
    }
}

struct LargeRawCtfMember {
    pub name: StrId,
    pub type_id: TypeId,
    pub offset_bits: u64,
}

impl From<LargeRawCtfMember> for RawCtfMember {
    fn from(
        LargeRawCtfMember {
            name,
            type_id,
            offset_bits,
        }: LargeRawCtfMember,
    ) -> Self {
        Self {
            name,
            type_id,
            offset_bits,
        }
    }
}

impl TryFromCtx<'_, Endian> for LargeRawCtfMember {
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
            LargeRawCtfMember {
                name,
                type_id,
                offset_bits,
            },
            *offset,
        ))
    }
}

impl RawCtfEnumerator {
    pub fn name<'ctf>(&self, ctf: &'ctf CtfReader) -> &'ctf str {
        ctf.str(self.name)
    }
}

impl TryFromCtx<'_, Endian> for RawCtfEnumerator {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], endian: Endian) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let name_raw = from.gread_with(offset, endian)?;
        let name = StrId::from_u32(name_raw)?;

        // CTF requires that enum values be 4 bytes, but we're going to work
        // around this by passing larger values in the name. Parse the inline
        // value as an i32. Once all strings are parsed we will take a second
        // pass to update the values as needed.
        let value: i32 = from.gread_with(offset, endian)?;

        Ok((
            RawCtfEnumerator {
                name,
                value: value as i64,
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

macro_rules! impl_ord {
    ( $( $name:ty ),+) => {
        $(
        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &$name) -> std::cmp::Ordering {
                self.id.cmp(&other.id)
            }
        }

        impl std::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        )+
    };
}

impl_ord!(
    RawCtfUnknown,
    RawCtfInteger,
    RawCtfFloat,
    RawCtfPointer,
    RawCtfArray,
    RawCtfFunction,
    RawCtfStruct,
    RawCtfUnion,
    RawCtfEnum,
    RawCtfForward,
    RawCtfTypedef,
    RawCtfVolatile,
    RawCtfConst,
    RawCtfRestrict
);

#[cfg(test)]
mod tests {
    use super::*;

    use crate::write::{self, CtfWriter};
    use crate::{IntegerEncoding, IntegerFlags};

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

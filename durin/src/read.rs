use crate::constants::*;
use crate::{CtfHeader, CtfPreamble, Error, Result, StrId, TypeId, TypeKind};

use flate2::read::ZlibDecoder;
use scroll::Pread;
use scroll::ctx::TryFromCtx;

use std::io::Read;
use std::str;

const HEADER_SIZE: usize = 36;

#[derive(Debug)]
pub struct CtfReader {
    pub preamble: CtfPreamble,
    pub header: CtfHeader,
    data: Vec<u8>,
}

impl CtfReader {
    pub fn load(input: &[u8]) -> Result<Self> {
        let offset = &mut 0;
        let preamble: CtfPreamble = input.gread(offset)?;
        let header: CtfHeader = input.gread(offset)?;

        let expected_len = HEADER_SIZE as u32 + header.stroff + header.strlen;
        let data = if preamble.flags.is_compressed() {
            let mut decompressor = ZlibDecoder::new(input);
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

        Ok(Self {
            preamble,
            header,
            data,
        })
    }

    pub fn labels<'a>(&'a self) -> LabelIter<'a> {
        let label_start = self.header.lbloff as usize;
        let label_end = self.header.objtoff as usize;
        let data = &self.data[label_start..label_end];

        LabelIter { data, offset: 0 }
    }

    pub fn objects<'a>(&'a self) -> ObjectIter<'a> {
        let obj_start = self.header.objtoff as usize;
        let obj_end = self.header.funcoff as usize;
        let data = &self.data[obj_start..obj_end];

        ObjectIter { data, offset: 0 }
    }

    pub fn functions<'a>(&'a self) -> u32 {
        todo!();
    }

    pub fn types<'a>(&'a self) -> TypeIter<'a> {
        let types_start = self.header.typeoff as usize;
        let types_end = self.header.stroff as usize;
        let data = &self.data[types_start..types_end];

        TypeIter {
            data,
            offset: 0,
            index: TypeId::default(),
        }
    }

    pub fn string_table<'a>(&'a self) -> StringTable<'a> {
        let str_start = self.header.stroff as usize;
        let str_end = str_start + self.header.strlen as usize;

        StringTable {
            inner: &self.data[str_start..str_end],
        }
    }
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
pub struct Label {
    /// Ref to name of label.
    label: StrId,
    /// Last type associated with this label.
    typeidx: TypeId,
}

impl Label {
    pub fn label<'a>(&'a self, strings: &'a StringTable) -> Result<&'a str> {
        strings.get(self.label)
    }
}

impl TryFromCtx<'_, ()> for Label {
    type Error = Error;

    fn try_from_ctx(from: &'_ [u8], _ctx: ()) -> Result<(Self, usize)> {
        let offset = &mut 0;

        let label = from.gread(offset)?;
        let typeidx = from.gread(offset)?;

        Ok((Self { label, typeidx }, *offset))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum StringTableType {
    Internal = 0,
    External = 1,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct StringTable<'a> {
    inner: &'a [u8],
}

impl<'a> StringTable<'a> {
    pub fn get(&'a self, id: StrId) -> Result<&'a str> {
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
    pub fn name<'a>(&self, strings: &'a StringTable) -> Result<&'a str> {
        let index = match self {
            Self::Unknown { .. } => return Ok(""),
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
        strings.get(*index)
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

pub struct LabelIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Result<Label>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let label = match self.data.gread(&mut self.offset) {
            Ok(label) => label,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok(label))
    }
}

pub struct ObjectIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for ObjectIter<'a> {
    type Item = Result<TypeId>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let id = match self.data.gread(&mut self.offset) {
            Ok(id) => id,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok(id))
    }
}

pub struct TypeIter<'a> {
    data: &'a [u8],
    offset: usize,
    index: TypeId,
}

impl<'a> Iterator for TypeIter<'a> {
    type Item = Result<CtfType>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let ty = match self.data.gread_with(&mut self.offset, self.index) {
            Ok(ty) => ty,
            Err(e) => return Some(Err(e)),
        };
        let new_index = match TypeId::try_from(self.index.get() + 1) {
            Ok(i) => i,
            Err(e) => return Some(Err(e)),
        };

        self.index = new_index;

        Some(Ok(ty))
    }
}

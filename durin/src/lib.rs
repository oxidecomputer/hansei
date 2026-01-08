pub mod read;
pub mod write;

use std::io;

pub type Result<T> = std::result::Result<T, Error>;

pub mod constants {
    pub const CTF_F_COMPRESS: u8 = 0x01;

    pub const CTF_K_UNKNOWN: u8 = 0;
    pub const CTF_K_INTEGER: u8 = 1;
    pub const CTF_K_FLOAT: u8 = 2;
    pub const CTF_K_POINTER: u8 = 3;
    pub const CTF_K_ARRAY: u8 = 4;
    pub const CTF_K_FUNCTION: u8 = 5;
    pub const CTF_K_STRUCT: u8 = 6;
    pub const CTF_K_UNION: u8 = 7;
    pub const CTF_K_ENUM: u8 = 8;
    pub const CTF_K_FORWARD: u8 = 9;
    pub const CTF_K_TYPEDEF: u8 = 10;
    pub const CTF_K_VOLATILE: u8 = 11;
    pub const CTF_K_CONST: u8 = 12;
    pub const CTF_K_RESTRICT: u8 = 13;

    pub const CTF_MAX_VLEN: u16 = 0x3ff;

    pub const CTF_MAX_SIZE: u64 = 0xfffe;
    pub const CTF_LSIZE_SENT: u64 = 0xffff;
    pub const CTF_MAX_LSIZE: u64 = u64::MAX;

    // CTF Integer Encoding Flags
    pub const CTF_INT_SIGNED: u8 = 0x01;
    pub const CTF_INT_CHAR: u8 = 0x02;
    pub const CTF_INT_BOOL: u8 = 0x04;

    pub const CTF_MAGIC: u16 = 0xcff1;
    pub const CTF_VERSION: u8 = 2;

    pub const MAX_TYPES: u16 = 0x7fff;
    pub const MAX_TYPE_INDEX: u16 = 0x8000;

    pub const MAX_STR_INDEX: u32 = 0x7fff_ffff;
    pub const STR_INDEX_MASK: u32 = 0x8000_0000;
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(C)]
pub struct CtfPreamble {
    pub magic: u16,
    pub vers: CtfVersion,
    pub flags: CtfFlags,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum CtfVersion {
    V2 = constants::CTF_VERSION,
}

impl TryFrom<u8> for CtfVersion {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            constants::CTF_VERSION => Ok(CtfVersion::V2),
            v => Err(Error::UnsupportedVersion(v)),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct CtfFlags(u8);

impl CtfFlags {
    pub fn new(compress: bool) -> Self {
        if compress {
            Self(constants::CTF_F_COMPRESS)
        } else {
            Self(0)
        }
    }

    pub fn is_compressed(&self) -> bool {
        self.0 & constants::CTF_F_COMPRESS != 0
    }
}

impl TryFrom<u8> for CtfFlags {
    type Error = Error;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            0 | constants::CTF_F_COMPRESS => Ok(Self(val)),
            _ => Err(Error::InvalidFlags(val)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[repr(C)]
pub struct CtfHeader {
    /// Ref to name of parent label uniq'd against.
    pub parlabel: StrId,
    /// Ref to basename of parent.
    pub parname: StrId,
    /// Offset of label section. Must be four byte aligned.
    pub lbloff: u32,
    /// Offset of object section. Must be two byte aligned.
    pub objtoff: u32,
    /// Offset of function section. Must be two byte aligned.
    pub funcoff: u32,
    /// Offset of type section. Must be four byte aligned.
    pub typeoff: u32,
    /// Offset of string section. No required alignment.
    pub stroff: u32,
    /// Length of string section in bytes. No required alignment.
    pub strlen: u32,
}

// TODO refactor to more general error types, capture context
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to decompress CTF data")]
    Decompress { source: io::Error },
    #[error("invalid CTF flags {0:08b}")]
    InvalidFlags(u8),
    #[error("{0} is not a valid float encoding")]
    InvalidFloatEncoding(u8),
    #[error("invalid CTF magic number {0:02x}")]
    InvalidMagic(u16),
    #[error("{0} is not a valid string offset")]
    InvalidStrOffset(u32),
    #[error("{0} is not a valid type kind")]
    InvalidTypeKind(u16),
    #[error("{0} is not a valid type index")]
    InvalidTypeIndex(u16),
    #[error("string at index {0:?} was not valid UTF-8")]
    InvalidStrEncoding(StrId),
    #[error("type at index {0:?} not found")]
    MissingType(TypeId),
    #[error("string at index {0:?} not found")]
    MissingStr(StrId),
    #[error("function offset {0} is not two-byte aligned")]
    MisalignedFuncOffset(u32),
    #[error("label offset {0} is not four-byte aligned")]
    MisalignedLabelOffset(u32),
    #[error("object offset {0} is not two-byte aligned")]
    MisalignedObjectOffset(u32),
    #[error("type offset {0} is not four-byte aligned")]
    MisalignedTypeOffset(u32),
    #[error("failed to parse: {0}")]
    Parse(#[from] scroll::Error),
    #[error("data length {actual} is less than length {expected} in header")]
    TooShort { actual: u32, expected: u32 },
    #[error("unsupported CTF version {0}")]
    UnsupportedVersion(u8),
    #[error("string at index {0:?} is not null-terminated")]
    UnterminatedStr(StrId),
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum StringTableType {
    Internal = 0,
    External = 1,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct StrId(u32);

impl StrId {
    const MAX: u32 = constants::MAX_STR_INDEX;
    const TABLE_MASK: u32 = 0x8000_0000;

    pub fn offset(&self) -> u32 {
        self.0 & Self::MAX
    }

    pub fn table(&self) -> StringTableType {
        if self.0 & Self::TABLE_MASK == 0 {
            StringTableType::Internal
        } else {
            StringTableType::External
        }
    }
}

impl TryFrom<u32> for StrId {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if value > Self::MAX {
            return Err(Error::InvalidStrOffset(value));
        }

        Ok(Self(value))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct TypeId(u16);

impl Default for TypeId {
    fn default() -> Self {
        Self(1)
    }
}

impl TypeId {
    pub const MAX: u64 = u16::MAX as u64;

    pub fn get(&self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for TypeId {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        if value == 0 {
            return Err(Error::InvalidTypeIndex(value));
        }

        Ok(Self(value))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u16)]
pub enum TypeKind {
    Unknown = 0,
    Integer = 1,
    Float = 2,
    Pointer = 3,
    Array = 4,
    Function = 5,
    Struct = 6,
    Union = 7,
    Enum = 8,
    Forward = 9,
    Typedef = 10,
    Volatile = 11,
    Const = 12,
    Restrict = 13,
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
            v => return Err(Error::InvalidTypeKind(v)),
        };
        Ok(ty)
    }
}

pub enum SizeOrType {
    Size(u16),
    Type(TypeId),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        todo!();
    }
}

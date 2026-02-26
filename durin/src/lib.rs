use std::fmt;

pub mod read;
pub mod write;

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
    pub const CTF_LSIZE_SENT: u16 = 0xffff;
    pub const CTF_MAX_LSIZE: u64 = u64::MAX;

    // CTF Integer Encoding Flags
    pub const CTF_INT_SIGNED: u8 = 0x01;
    pub const CTF_INT_CHAR: u8 = 0x02;
    pub const CTF_INT_BOOL: u8 = 0x04;
    pub const CTF_INT_VARARGS: u8 = 0x08;

    pub const CTF_MAGIC: u16 = 0xcff1;
    pub const CTF_VERSION: u8 = 2;

    pub const MAX_TYPES: u16 = 0x7fff;
    pub const MAX_TYPE_INDEX: u16 = 0x8000;

    pub const MAX_STR_INDEX: u32 = 0x7fff_ffff;
    pub const STR_INDEX_MASK: u32 = 0x8000_0000;
}

const HEADER_SIZE: usize = 36;
const LARGE_THRESHOLD: u16 = 8192;

/// The byte order to use when reading or writing a CTF file.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Endian {
    Big,
    Little,
}

#[cfg(target_endian = "little")]
/// The hosts's native byte order
pub const NATIVE: Endian = Endian::Little;
#[cfg(target_endian = "big")]
/// The host's native byte order
pub const NATIVE: Endian = Endian::Big;

impl Default for Endian {
    fn default() -> Self {
        NATIVE
    }
}

impl From<Endian> for scroll::Endian {
    fn from(value: Endian) -> Self {
        match value {
            Endian::Big => scroll::Endian::Big,
            Endian::Little => scroll::Endian::Little,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(C)]
pub struct CtfPreamble {
    pub vers: CtfVersion,
    pub flags: CtfFlags,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum CtfVersion {
    V2 = constants::CTF_VERSION,
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

    pub fn get(&self) -> u8 {
        self.0
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

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum StringTableType {
    Internal = 0,
    External = 1,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
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

    /// The identifier for the empty string.
    pub fn empty() -> Self {
        // StrId 0 is always present and points to an empty string.
        Self::default()
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

    /// The `TypeId` for unknown types.
    pub fn unknown() -> Self {
        Self(0)
    }

    /// The `TypeId` for `void`.
    pub fn void() -> Self {
        Self::default()
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

pub(crate) const VARARGS_ID: u16 = 0;

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

#[derive(Copy, Clone, PartialEq, Eq, Hash, Default, Debug)]
pub struct IntegerEncoding {
    pub bits: u16,
    pub offset: u8,
    pub flags: IntegerFlags,
}

impl IntegerEncoding {
    pub fn as_u32(&self) -> u32 {
        ((self.flags.get() as u32) << 24) | ((self.offset as u32) << 16) | self.bits as u32
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct IntegerFlags(u8);

impl IntegerFlags {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> u8 {
        self.0
    }

    pub fn signed(self) -> Self {
        Self(self.0 | constants::CTF_INT_SIGNED)
    }

    pub fn char(self) -> Self {
        Self(self.0 | constants::CTF_INT_CHAR)
    }

    pub fn bool(self) -> Self {
        Self(self.0 | constants::CTF_INT_BOOL)
    }

    pub fn varargs(self) -> Self {
        Self(self.0 | constants::CTF_INT_VARARGS)
    }

    pub fn is_signed(&self) -> bool {
        self.0 & constants::CTF_INT_SIGNED != 0
    }

    pub fn is_char(&self) -> bool {
        self.0 & constants::CTF_INT_CHAR != 0
    }

    pub fn is_bool(&self) -> bool {
        self.0 & constants::CTF_INT_BOOL != 0
    }

    pub fn is_varargs(&self) -> bool {
        self.0 & constants::CTF_INT_VARARGS != 0
    }
}

impl fmt::Debug for IntegerFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegerFlags")
            .field("inner", &format_args!("{:08b}", self.0))
            .field("is_signed", &self.is_signed())
            .field("is_char", &self.is_char())
            .field("is_bool", &self.is_bool())
            .field("is_varargs", &self.is_varargs())
            .finish()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FloatEncoding {
    pub bits: u16,
    pub offset: u8,
    pub float_type: FloatType,
}

impl FloatEncoding {
    pub fn as_u32(&self) -> u32 {
        ((self.float_type as u32) << 24) | ((self.offset as u32) << 16) | self.bits as u32
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum FloatType {
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

#[cfg(test)]
mod testhelper {
    use crate::{IntegerEncoding, IntegerFlags};

    /// Set the `IntegerFlags` of the encoding to an invalid value.
    pub fn set_invalid_flags(encoding: &mut IntegerEncoding) {
        encoding.flags = IntegerFlags(0xff);
    }
}


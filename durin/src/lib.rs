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
            v => Err(Error::unsupported_version(v)),
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
            _ => Err(Error::invalid_flags(val)),
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

/// The error type for CTF parsing operations.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    backtrace: std::backtrace::Backtrace,
}

#[derive(thiserror::Error, Debug)]
enum ErrorKind {
    #[error("failed to decompress CTF data")]
    Decompress,
    #[error("str {0:?} located in external string table, which are not supported")]
    ExternalStr(StrId),
    #[error("invalid discriminant value {discrim} for type {ty:?}")]
    InvalidDiscriminantValue { ty: TypeId, discrim: u64 },
    #[error("invalid enum name format {0}")]
    InvalidEnumFormat(String),
    #[error("invalid enum name value encoding {0}")]
    InvalidEnumValue(String),
    #[error("invalid enum size {0}")]
    InvalidEnumSize(u16),
    #[error("invalid CTF flags {0:08b}")]
    InvalidFlags(u8),
    #[error("{0} is not a valid float encoding")]
    InvalidFloatEncoding(u8),
    #[error("invalid CTF magic number {0:02x}")]
    InvalidMagic(u16),
    #[error("unable to read member at range {start}..{end} from buf with len {len}")]
    InvalidMemberRange { start: u16, end: u16, len: u16 },
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
    #[error("no value found when parsing {0:?}")]
    MissingValue(TypeId),
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
    #[error("enumerator {enum_name} not found for type {ty:?}")]
    NoEnumerator { ty: TypeId, enum_name: String },
    #[error("member {member_name} not found for type {ty:?}")]
    NoMember { ty: TypeId, member_name: String },
    #[error("attempted to dereference an invalid pointer")]
    NullPtr,
    #[error("failed to parse CTF data")]
    Parse,
    #[error("failed to parse member {0}")]
    ParseMember(String),
    #[error("failed to parse type {0}")]
    ParseType(String),
    #[error("failed to read type {0:?}")]
    ReadError(TypeId),
    #[error("data length {actual} is less than {expected} length")]
    TooShort { actual: u32, expected: u32 },
    #[error("expected a {expected:?} but found a {actual:?} when parsing {name}")]
    UnexpectedType {
        actual: TypeKind,
        expected: TypeKind,
        name: String,
    },
    #[error("expected enum variant {expected} was not active")]
    UnexpectedVariant { expected: String },
    #[error("unsupported CTF version {0}")]
    UnsupportedVersion(u8),
    #[error("string at index {0:?} is not null-terminated")]
    UnterminatedStr(StrId),
}

impl Error {
    /// Creates a new error with backtrace capture.
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            backtrace: std::backtrace::Backtrace::capture(),
        }
    }

    /// Attaches a source error to this error.
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Returns the backtrace captured when the error was created.
    pub fn backtrace(&self) -> &std::backtrace::Backtrace {
        &self.backtrace
    }

    /// Returns true if this is a validation error (invalid magic, flags, etc.)
    pub fn is_validation(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::InvalidMagic(_)
                | ErrorKind::InvalidFlags(_)
                | ErrorKind::InvalidTypeKind(_)
                | ErrorKind::InvalidTypeIndex(_)
                | ErrorKind::InvalidStrOffset(_)
                | ErrorKind::InvalidFloatEncoding(_)
                | ErrorKind::InvalidEnumSize(_)
                | ErrorKind::InvalidEnumFormat(_)
                | ErrorKind::InvalidEnumValue(_)
                | ErrorKind::InvalidDiscriminantValue { .. }
                | ErrorKind::InvalidStrEncoding(_)
                | ErrorKind::InvalidMemberRange { .. }
        )
    }

    /// Returns true if this is an alignment error.
    pub fn is_alignment(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::MisalignedFuncOffset(_)
                | ErrorKind::MisalignedLabelOffset(_)
                | ErrorKind::MisalignedObjectOffset(_)
                | ErrorKind::MisalignedTypeOffset(_)
        )
    }

    /// Returns true if this is a lookup failure (missing type, string, member).
    pub fn is_not_found(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::MissingType(_)
                | ErrorKind::MissingStr(_)
                | ErrorKind::MissingValue(_)
                | ErrorKind::NoEnumerator { .. }
                | ErrorKind::NoMember { .. }
                | ErrorKind::NullPtr
        )
    }

    /// Returns true if this is a parsing/format error.
    pub fn is_parse(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Parse
                | ErrorKind::ParseMember(_)
                | ErrorKind::ParseType(_)
                | ErrorKind::TooShort { .. }
                | ErrorKind::UnterminatedStr(_)
        )
    }

    /// Returns true if this is a version/compatibility error.
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::UnsupportedVersion(_) | ErrorKind::ExternalStr(_)
        )
    }

    /// Returns true if this is a type mismatch error.
    pub fn is_type_mismatch(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::UnexpectedType { .. } | ErrorKind::UnexpectedVariant { .. }
        )
    }

    /// Returns true if this is an I/O error.
    pub fn is_io(&self) -> bool {
        matches!(self.kind, ErrorKind::Decompress | ErrorKind::ReadError(_))
    }

    // Public constructors for each variant

    pub fn decompress(source: io::Error) -> Self {
        Self::new(ErrorKind::Decompress).with_source(source)
    }

    pub fn external_str(id: StrId) -> Self {
        Self::new(ErrorKind::ExternalStr(id))
    }

    pub fn invalid_discriminant_value(ty: TypeId, discrim: u64) -> Self {
        Self::new(ErrorKind::InvalidDiscriminantValue { ty, discrim })
    }

    pub fn invalid_enum_format(name: String) -> Self {
        Self::new(ErrorKind::InvalidEnumFormat(name))
    }

    pub fn invalid_enum_value(name: String) -> Self {
        Self::new(ErrorKind::InvalidEnumValue(name))
    }

    pub fn invalid_enum_size(size: u16) -> Self {
        Self::new(ErrorKind::InvalidEnumSize(size))
    }

    pub fn invalid_flags(flags: u8) -> Self {
        Self::new(ErrorKind::InvalidFlags(flags))
    }

    pub fn invalid_float_encoding(encoding: u8) -> Self {
        Self::new(ErrorKind::InvalidFloatEncoding(encoding))
    }

    pub fn invalid_magic(magic: u16) -> Self {
        Self::new(ErrorKind::InvalidMagic(magic))
    }

    pub fn invalid_member_range(start: u16, end: u16, len: u16) -> Self {
        Self::new(ErrorKind::InvalidMemberRange { start, end, len })
    }

    pub fn invalid_str_offset(offset: u32) -> Self {
        Self::new(ErrorKind::InvalidStrOffset(offset))
    }

    pub fn invalid_type_kind(kind: u16) -> Self {
        Self::new(ErrorKind::InvalidTypeKind(kind))
    }

    pub fn invalid_type_index(index: u16) -> Self {
        Self::new(ErrorKind::InvalidTypeIndex(index))
    }

    pub fn invalid_str_encoding(id: StrId) -> Self {
        Self::new(ErrorKind::InvalidStrEncoding(id))
    }

    pub fn missing_type(ty: TypeId) -> Self {
        Self::new(ErrorKind::MissingType(ty))
    }

    pub fn missing_value(ty: TypeId) -> Self {
        Self::new(ErrorKind::MissingValue(ty))
    }

    pub fn missing_str(id: StrId) -> Self {
        Self::new(ErrorKind::MissingStr(id))
    }

    pub fn misaligned_func_offset(offset: u32) -> Self {
        Self::new(ErrorKind::MisalignedFuncOffset(offset))
    }

    pub fn misaligned_label_offset(offset: u32) -> Self {
        Self::new(ErrorKind::MisalignedLabelOffset(offset))
    }

    pub fn misaligned_object_offset(offset: u32) -> Self {
        Self::new(ErrorKind::MisalignedObjectOffset(offset))
    }

    pub fn misaligned_type_offset(offset: u32) -> Self {
        Self::new(ErrorKind::MisalignedTypeOffset(offset))
    }

    pub fn no_enumerator(ty: TypeId, enum_name: String) -> Self {
        Self::new(ErrorKind::NoEnumerator { ty, enum_name })
    }

    pub fn no_member(ty: TypeId, member_name: String) -> Self {
        Self::new(ErrorKind::NoMember { ty, member_name })
    }

    pub fn null_ptr() -> Self {
        Self::new(ErrorKind::NullPtr)
    }

    pub fn parse(source: scroll::Error) -> Self {
        Self::new(ErrorKind::Parse).with_source(source)
    }

    pub fn parse_member(member: impl Into<String>) -> Self {
        Self::new(ErrorKind::ParseMember(member.into()))
    }

    pub fn parse_type(ty: impl Into<String>) -> Self {
        Self::new(ErrorKind::ParseType(ty.into()))
    }

    pub fn read_error(ty: TypeId) -> Self {
        Self::new(ErrorKind::ReadError(ty))
    }

    pub fn too_short(actual: u32, expected: u32) -> Self {
        Self::new(ErrorKind::TooShort { actual, expected })
    }

    pub fn unexpected_type(actual: TypeKind, expected: TypeKind, name: String) -> Self {
        Self::new(ErrorKind::UnexpectedType {
            actual,
            expected,
            name,
        })
    }

    pub fn unexpected_variant(expected: String) -> Self {
        Self::new(ErrorKind::UnexpectedVariant { expected })
    }

    pub fn unsupported_version(version: u8) -> Self {
        Self::new(ErrorKind::UnsupportedVersion(version))
    }

    pub fn unterminated_str(id: StrId) -> Self {
        Self::new(ErrorKind::UnterminatedStr(id))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

impl From<scroll::Error> for Error {
    fn from(err: scroll::Error) -> Self {
        Self::parse(err)
    }
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
            return Err(Error::invalid_str_offset(value));
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
            return Err(Error::invalid_type_index(value));
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
            v => return Err(Error::invalid_type_kind(v)),
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

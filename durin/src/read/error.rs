use crate::{StrId, TypeId, TypeKind};

use std::io;

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
    #[error("{0:b} is not a valid float encoding")]
    InvalidFloatEncoding(u8),
    #[error("{0:b} is not a valid integer encoding")]
    InvalidIntegerEncoding(u8),
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
    #[error("{0} is outside range of valid type IDs")]
    TypeIdOutOfRange(u16),
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
                | ErrorKind::InvalidIntegerEncoding(_)
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

    pub fn invalid_integer_encoding(encoding: u8) -> Self {
        Self::new(ErrorKind::InvalidIntegerEncoding(encoding))
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

    pub fn type_id_out_of_range(id: u16) -> Self {
        Self::new(ErrorKind::TypeIdOutOfRange(id))
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

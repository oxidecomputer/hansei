use std::io;

pub mod read;
pub mod write;

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
    use crate::read::CtfReader;
    use crate::write::{CtfEnumerator, CtfMember, CtfType, CtfWriter, MaybeOffset, ctf_int_data};
    use std::collections::HashMap;

    /// Test helper to create CTF data and parse it back.
    fn round_trip_ctf(writer: &mut CtfWriter) -> CtfReader {
        let ctf_bytes = writer.generate_ctf(HashMap::new()).unwrap();
        CtfReader::load(&ctf_bytes).unwrap()
    }

    #[test]
    fn round_trip_integer_types() {
        let mut writer = CtfWriter::new(None);

        // Add signed 32-bit integer
        let offset = gimli::DebugInfoOffset(0x100);
        writer.add_type(
            offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add unsigned 64-bit integer
        let offset2 = gimli::DebugInfoOffset(0x200);
        writer.add_type(
            offset2,
            CtfType::Integer {
                name: "u64".to_string(),
                size: 8,
                encoding: ctf_int_data(0, 0, 64),
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Verify types were parsed correctly
        let types = reader.types();
        assert!(types.len() >= 3); // null type + void + our 2 types

        // Find and verify i32
        let i32_ty = reader.find_ty("i32", TypeKind::Integer);
        assert!(i32_ty.is_some(), "i32 type not found");
        let i32_ty = i32_ty.unwrap();
        assert_eq!(i32_ty.size(&reader), 4);

        // Find and verify u64
        let u64_ty = reader.find_ty("u64", TypeKind::Integer);
        assert!(u64_ty.is_some(), "u64 type not found");
        let u64_ty = u64_ty.unwrap();
        assert_eq!(u64_ty.size(&reader), 8);
    }

    #[test]
    fn round_trip_struct_type() {
        let mut writer = CtfWriter::new(None);

        // Add i32 type first (will be type id 2 after null and void)
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add struct with two i32 members
        let struct_offset = gimli::DebugInfoOffset(0x200);
        writer.add_type(
            struct_offset,
            CtfType::Struct {
                name: "Point".to_string(),
                size: 8,
                members: vec![
                    CtfMember {
                        name: "x".to_string(),
                        type_id: MaybeOffset::Found(int_id),
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "y".to_string(),
                        type_id: MaybeOffset::Found(int_id),
                        offset_bits: 32,
                    },
                ],
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find and verify struct
        let point = reader.find_ty("Point", TypeKind::Struct);
        assert!(point.is_some(), "Point struct not found");
        let point = point.unwrap();
        assert_eq!(point.size(&reader), 8);

        // Verify members
        let members = point.members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(&reader), "x");
        assert_eq!(members[0].offset(), 0);
        assert_eq!(members[1].name(&reader), "y");
        assert_eq!(members[1].offset(), 4);
    }

    #[test]
    fn round_trip_pointer_type() {
        let mut writer = CtfWriter::new(None);

        // Add i32 type
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add pointer to i32
        let ptr_offset = gimli::DebugInfoOffset(0x200);
        writer.add_type(
            ptr_offset,
            CtfType::Pointer {
                name: "".to_string(),
                target_type: MaybeOffset::Found(int_id),
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find pointer type (unnamed, so search by kind)
        let ptr = reader
            .types()
            .iter()
            .find(|t| t.kind() == TypeKind::Pointer);
        assert!(ptr.is_some(), "Pointer type not found");
        let ptr = ptr.unwrap();

        // Pointers are 8 bytes on 64-bit
        assert_eq!(ptr.size(&reader), 8);
    }

    #[test]
    fn round_trip_array_type() {
        let mut writer = CtfWriter::new(None);

        // Add i32 type
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add array of 10 i32s
        let array_offset = gimli::DebugInfoOffset(0x200);
        writer.add_type(
            array_offset,
            CtfType::Array {
                name: "".to_string(),
                element_type: MaybeOffset::Found(int_id),
                index_type: MaybeOffset::Found(int_id),
                nelems: 10,
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find array type
        let arr = reader.types().iter().find(|t| t.kind() == TypeKind::Array);
        assert!(arr.is_some(), "Array type not found");
        let arr = arr.unwrap();

        // Array of 10 i32s = 40 bytes
        assert_eq!(arr.size(&reader), 40);
    }

    #[test]
    fn round_trip_enum_type() {
        let mut writer = CtfWriter::new(None);

        let enum_offset = gimli::DebugInfoOffset(0x100);
        writer.add_type(
            enum_offset,
            CtfType::Enum {
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
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find and verify enum
        let color = reader.find_ty("Color", TypeKind::Enum);
        assert!(color.is_some(), "Color enum not found");
        let color = color.unwrap();
        assert_eq!(color.size(&reader), 4);

        // Verify enumerators
        if let read::CtfType::Enum {
            ty: read::CtfEnum { enumerators, .. },
            ..
        } = color
        {
            assert_eq!(enumerators.len(), 3);
            assert_eq!(enumerators[0].name(&reader), "Red");
            assert_eq!(enumerators[0].value, 0);
            assert_eq!(enumerators[1].name(&reader), "Green");
            assert_eq!(enumerators[1].value, 1);
            assert_eq!(enumerators[2].name(&reader), "Blue");
            assert_eq!(enumerators[2].value, 2);
        } else {
            panic!("Expected enum type");
        }
    }

    #[test]
    fn round_trip_typedef() {
        let mut writer = CtfWriter::new(None);

        // Add i32 type
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add typedef
        let typedef_offset = gimli::DebugInfoOffset(0x200);
        writer.add_type(
            typedef_offset,
            CtfType::Typedef {
                name: "MyInt".to_string(),
                target_type: MaybeOffset::Found(int_id),
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find and verify typedef
        let myint = reader.find_ty("MyInt", TypeKind::Typedef);
        assert!(myint.is_some(), "MyInt typedef not found");
        let myint = myint.unwrap();

        // Typedef should resolve to same size as target
        assert_eq!(myint.size(&reader), 4);
    }

    #[test]
    fn round_trip_union_type() {
        let mut writer = CtfWriter::new(None);

        // Add i32 type
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add f32 type
        let float_offset = gimli::DebugInfoOffset(0x150);
        let float_id = writer.add_type(
            float_offset,
            CtfType::Float {
                name: "f32".to_string(),
                size: 4,
                encoding: 0x01_00_0020, // Single precision, 32 bits
            },
        );

        // Add union with both members
        let union_offset = gimli::DebugInfoOffset(0x200);
        writer.add_type(
            union_offset,
            CtfType::Union {
                name: "IntOrFloat".to_string(),
                size: 4,
                members: vec![
                    CtfMember {
                        name: "i".to_string(),
                        type_id: MaybeOffset::Found(int_id),
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "f".to_string(),
                        type_id: MaybeOffset::Found(float_id),
                        offset_bits: 0,
                    },
                ],
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find and verify union
        let union_ty = reader.find_ty("IntOrFloat", TypeKind::Union);
        assert!(union_ty.is_some(), "IntOrFloat union not found");
        let union_ty = union_ty.unwrap();
        assert_eq!(union_ty.size(&reader), 4);

        // Verify members - both at offset 0
        let members = union_ty.members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(&reader), "i");
        assert_eq!(members[0].offset(), 0);
        assert_eq!(members[1].name(&reader), "f");
        assert_eq!(members[1].offset(), 0);
    }

    #[test]
    fn round_trip_nested_struct() {
        let mut writer = CtfWriter::new(None);

        // Add i32 type
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add inner Point struct
        let point_offset = gimli::DebugInfoOffset(0x200);
        let point_id = writer.add_type(
            point_offset,
            CtfType::Struct {
                name: "Point".to_string(),
                size: 8,
                members: vec![
                    CtfMember {
                        name: "x".to_string(),
                        type_id: MaybeOffset::Found(int_id),
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "y".to_string(),
                        type_id: MaybeOffset::Found(int_id),
                        offset_bits: 32,
                    },
                ],
            },
        );

        // Add outer Rect struct containing two Points
        let rect_offset = gimli::DebugInfoOffset(0x300);
        writer.add_type(
            rect_offset,
            CtfType::Struct {
                name: "Rect".to_string(),
                size: 16,
                members: vec![
                    CtfMember {
                        name: "top_left".to_string(),
                        type_id: MaybeOffset::Found(point_id),
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "bottom_right".to_string(),
                        type_id: MaybeOffset::Found(point_id),
                        offset_bits: 64,
                    },
                ],
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Verify Rect
        let rect = reader.find_ty("Rect", TypeKind::Struct).unwrap();
        assert_eq!(rect.size(&reader), 16);

        let members = rect.members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(&reader), "top_left");
        assert_eq!(members[0].offset(), 0);
        assert_eq!(members[1].name(&reader), "bottom_right");
        assert_eq!(members[1].offset(), 8);

        // Verify the member types reference Point
        let top_left_ty = members[0].ty(&reader);
        assert_eq!(top_left_ty.name(&reader), "Point");
    }

    #[test]
    fn round_trip_with_label() {
        let mut writer = CtfWriter::new(None);
        writer.set_label("test_binary".to_string());

        // Add a simple type
        let int_offset = gimli::DebugInfoOffset(0x100);
        writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Verify label was preserved
        assert!(!reader.labels.is_empty());
        assert_eq!(reader.labels[0].label(&reader), "test_binary");
    }

    #[test]
    fn round_trip_const_volatile_restrict() {
        let mut writer = CtfWriter::new(None);

        // Add base i32 type
        let int_offset = gimli::DebugInfoOffset(0x100);
        let int_id = writer.add_type(
            int_offset,
            CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: ctf_int_data(constants::CTF_INT_SIGNED, 0, 32),
            },
        );

        // Add const i32
        let const_offset = gimli::DebugInfoOffset(0x200);
        let const_id = writer.add_type(
            const_offset,
            CtfType::Const {
                name: "".to_string(),
                target_type: MaybeOffset::Found(int_id),
            },
        );

        // Add volatile const i32
        let volatile_offset = gimli::DebugInfoOffset(0x300);
        writer.add_type(
            volatile_offset,
            CtfType::Volatile {
                name: "".to_string(),
                target_type: MaybeOffset::Found(const_id),
            },
        );

        let reader = round_trip_ctf(&mut writer);

        // Find const type
        let const_ty = reader.types().iter().find(|t| t.kind() == TypeKind::Const);
        assert!(const_ty.is_some(), "Const type not found");

        // Find volatile type
        let volatile_ty = reader
            .types()
            .iter()
            .find(|t| t.kind() == TypeKind::Volatile);
        assert!(volatile_ty.is_some(), "Volatile type not found");

        // Volatile should resolve to same size as underlying type
        let volatile_ty = volatile_ty.unwrap();
        assert_eq!(volatile_ty.size(&reader), 4);
    }
}

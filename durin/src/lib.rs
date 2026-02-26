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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::CtfReader;
    use crate::write::{CtfEnumerator, CtfMember, CtfType, CtfWriter};

    /// Test helper to create CTF data, parse it back, and return an indexed view.
    fn round_trip_ctf(writer: &mut CtfWriter) -> CtfReader {
        let ctf_bytes = writer.generate_ctf().unwrap();
        CtfReader::load(&ctf_bytes).unwrap()
    }

    #[test]
    fn round_trip_integer_types() {
        let mut writer = CtfWriter::new();

        // Add signed 32-bit integer
        writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    offset: 0,
                    bits: 32,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        // Add unsigned 64-bit integer
        writer
            .add_type(CtfType::Integer {
                name: "u64".to_string(),
                size: 8,
                encoding: IntegerEncoding {
                    offset: 0,
                    bits: 64,
                    flags: IntegerFlags::new(),
                },
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Verify types were parsed correctly
        let types: Vec<_> = view.types().collect();
        assert!(types.len() == 4); // empty + void + our types

        // Find and verify i32
        let i32_ty = view.find("i32", TypeKind::Integer);
        assert!(i32_ty.is_some(), "i32 type not found");
        let i32_ty = i32_ty.unwrap();
        assert_eq!(i32_ty.size(), 4);

        // Find and verify u64
        let u64_ty = view.find("u64", TypeKind::Integer);
        assert!(u64_ty.is_some(), "u64 type not found");
        let u64_ty = u64_ty.unwrap();
        assert_eq!(u64_ty.size(), 8);
    }

    #[test]
    fn round_trip_struct_type() {
        let mut writer = CtfWriter::new();

        // Add i32 type first (will be type id 2 after null and void)
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        // Add struct with two i32 members
        writer
            .add_type(CtfType::Struct {
                name: "Point".to_string(),
                size: 8,
                members: vec![
                    CtfMember {
                        name: "x".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "y".to_string(),
                        type_id: int_id,
                        offset_bits: 32,
                    },
                ],
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Find and verify struct
        let point = view.find("Point", TypeKind::Struct);
        assert!(point.is_some(), "Point struct not found");
        let point = point.unwrap();
        assert_eq!(point.size(), 8);

        // Verify members using CtfView
        let members: Vec<_> = point.members().collect();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(), "x");
        assert_eq!(members[1].name(), "y");

        // Also verify via find_member
        let x = point.member("x");
        assert!(x.is_some());
        assert_eq!(x.unwrap().offset(), 0);

        let y = point.member("y");
        assert!(y.is_some());
        assert_eq!(y.unwrap().offset(), 4);
    }

    #[test]
    fn round_trip_enum_type() {
        let mut writer = CtfWriter::new();

        writer
            .add_type(CtfType::Enum {
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
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Find and verify enum
        let color = view.find("Color", TypeKind::Enum);
        assert!(color.is_some(), "Color enum not found");
        let color = color.unwrap();
        assert_eq!(color.size(), 4);

        // Verify enumerators using CtfView
        let enums: Vec<_> = color.as_enum().unwrap().enumerators().collect();
        assert_eq!(enums.len(), 3);
        assert_eq!(enums[0].name(), "Red");
        assert_eq!(enums[0].value(), 0);
        assert_eq!(enums[1].name(), "Green");
        assert_eq!(enums[1].value(), 1);
        assert_eq!(enums[2].name(), "Blue");
        assert_eq!(enums[2].value(), 2);
    }

    #[test]
    fn round_trip_typedef() {
        let mut writer = CtfWriter::new();

        // Add i32 type
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        // Add typedef
        writer
            .add_type(CtfType::Typedef {
                name: "MyInt".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Find and verify typedef
        let myint = view.find("MyInt", TypeKind::Typedef);
        assert!(myint.is_some(), "MyInt typedef not found");
        let myint = myint.unwrap();

        // Typedef should resolve to same size as target
        assert_eq!(myint.size(), 4);

        // Verify resolve_type follows the chain
        let resolved = myint.target().unwrap();
        assert_eq!(resolved.kind(), TypeKind::Integer);
        assert_eq!(resolved.name(), "i32");
    }

    #[test]
    fn round_trip_union_type() {
        let mut writer = CtfWriter::new();

        // Add i32 type
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        // Add f32 type
        let float_id = writer
            .add_type(CtfType::Float {
                name: "f32".to_string(),
                size: 4,
                encoding: FloatEncoding {
                    bits: 32,
                    offset: 0,
                    float_type: FloatType::Single,
                },
            })
            .unwrap();

        // Add union with both members
        writer
            .add_type(CtfType::Union {
                name: "IntOrFloat".to_string(),
                size: 4,
                members: vec![
                    CtfMember {
                        name: "i".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "f".to_string(),
                        type_id: float_id,
                        offset_bits: 0,
                    },
                ],
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Find and verify union
        let union_ty = view.find("IntOrFloat", TypeKind::Union);
        assert!(union_ty.is_some(), "IntOrFloat union not found");
        let union_ty = union_ty.unwrap();
        assert_eq!(union_ty.size(), 4);

        // Verify members using CtfView - both at offset 0
        let members: Vec<_> = union_ty.members().collect();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(), "i");
        assert_eq!(members[1].name(), "f");

        let i_member = union_ty.member("i").unwrap();
        let f_member = union_ty.member("f").unwrap();
        assert_eq!(i_member.offset(), 0);
        assert_eq!(f_member.offset(), 0);
    }

    #[test]
    fn round_trip_nested_struct() {
        let mut writer = CtfWriter::new();

        // Add i32 type
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        // Add inner Point struct
        let point_id = writer
            .add_type(CtfType::Struct {
                name: "Point".to_string(),
                size: 8,
                members: vec![
                    CtfMember {
                        name: "x".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "y".to_string(),
                        type_id: int_id,
                        offset_bits: 32,
                    },
                ],
            })
            .unwrap();

        // Add outer Rect struct containing two Points
        writer
            .add_type(CtfType::Struct {
                name: "Rect".to_string(),
                size: 16,
                members: vec![
                    CtfMember {
                        name: "top_left".to_string(),
                        type_id: point_id,
                        offset_bits: 0,
                    },
                    CtfMember {
                        name: "bottom_right".to_string(),
                        type_id: point_id,
                        offset_bits: 64,
                    },
                ],
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Verify Rect using CtfView
        let rect = view.find("Rect", TypeKind::Struct).unwrap();
        assert_eq!(rect.size(), 16);

        let members: Vec<_> = rect.members().collect();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name(), "top_left");
        assert_eq!(members[1].name(), "bottom_right");

        let top_left = rect.member("top_left").unwrap();
        let bottom_right = rect.member("bottom_right").unwrap();
        assert_eq!(top_left.offset(), 0);
        assert_eq!(bottom_right.offset(), 8);

        // Verify the member types reference Point
        assert_eq!(members[0].ty().name(), "Point");
    }

    #[test]
    fn round_trip_with_label() {
        let mut writer = CtfWriter::new();

        writer.add_label("test_binary".to_string());
        // Add a simple type
        writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);

        let labels = reader.labels();
        assert!(!labels.is_empty());
        assert_eq!(reader.str(labels[0].name), "test_binary");
    }

    #[test]
    fn round_trip_const_volatile_restrict() {
        let mut writer = CtfWriter::new();

        // Add base i32 type
        let int_id = writer
            .add_type(CtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        // Add const i32
        let const_id = writer
            .add_type(CtfType::Const {
                name: "FOO".to_string(),
                target_type: int_id,
            })
            .unwrap();

        // Add volatile const i32
        writer
            .add_type(CtfType::Volatile {
                name: "BAR".to_string(),
                target_type: const_id,
            })
            .unwrap();

        let reader = round_trip_ctf(&mut writer);
        let view = reader.view();

        // Find const type
        let const_ty = view.find("FOO", TypeKind::Const);
        assert!(const_ty.is_some(), "Const type not found");

        // Find volatile type
        let volatile_ty = view.find("BAR", TypeKind::Volatile);
        assert!(volatile_ty.is_some(), "Volatile type not found");

        let volatile = volatile_ty.unwrap();
        // Volatile should resolve to same size as underlying type
        assert_eq!(volatile.size(), 4);

        assert_eq!(volatile.kind(), TypeKind::Volatile);
        assert_eq!(volatile.name(), "BAR");
    }
}

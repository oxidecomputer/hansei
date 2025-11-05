pub mod cwrite;
pub mod error;

pub const CTF_F_COMPRESS: i32 = 0x01;

pub const CTF_K_UNKNOWN: i32 = 0;
pub const CTF_K_INTEGER: i32 = 1;
pub const CTF_K_FLOAT: i32 = 2;
pub const CTF_K_POINTER: i32 = 3;
pub const CTF_K_ARRAY: i32 = 4;
pub const CTF_K_FUNCTION: i32 = 5;
pub const CTF_K_STRUCT: i32 = 6;
pub const CTF_K_UNION: i32 = 7;
pub const CTF_K_ENUM: i32 = 8;
pub const CTF_K_FORWARD: i32 = 9;
pub const CTF_K_TYPEDEF: i32 = 10;
pub const CTF_K_VOLATILE: i32 = 11;
pub const CTF_K_CONST: i32 = 12;
pub const CTF_K_RESTRICT: i32 = 13;

pub const CTF_MAX_VLEN: usize = 0x3ff;

pub const CTF_MAX_SIZE: u64 = 0xfffe;
pub const CTF_LSIZE_SENT: u64 = 0xffff;
pub const CTF_MAX_LSIZE: u64 = u64::MAX;

pub const MAGIC: u16 = 0xcff1;
pub const CTF_VERSION: u8 = 2;

pub const MAX_TYPES: u32 = 0x7fff;
pub const MAX_TYPE_INDEX: u32 = 0x8000;

// TODO don't support 32bit hosts
const _IS_64BIT: () = const {
    assert!(usize::BITS == 64);
};

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    /// TODO
    pub const NATIVE: Endian = {
        match u16::from_ne_bytes([0, 1]) {
            1 => Self::Big,
            256 => Self::Little,
            _ => unreachable!(),
        }
    };
}

impl Default for Endian {
    fn default() -> Self {
        Self::NATIVE
    }
}

pub struct Ctf {
    preamble: Preamble,
    header: Header,
    labels: Vec<i32>,
    objects: Vec<i32>,
    functions: Vec<i32>,
    types: Vec<i32>,
    strings: Vec<i32>,
}

// TODO: We don't actually need this alignment here, since this is an intermediate representation.
#[repr(align(4))]
pub struct Preamble {
    magic: u16,
    vers: u8,
    flags: u8,
}

pub struct Header {
    /// Ref to name of parent label uniq'd against.
    parlabel: u32,
    /// Ref to basename of parent.
    parname: u32,
    /// Offset of label section. Must be four byte aligned.
    lbloff: u32,
    /// Offset of object section. Must be two byte aligned.
    objtoff: u32,
    /// Offset of function section. Must be two byte aligned.
    funcoff: u32,
    /// Offset of type section. Must be four byte aligned.
    typeoff: u32,
    /// Offset of string section. No required alignment.
    stroff: u32,
    /// Length of string section in bytes. No required alignment.
    stflen: u32,
}

pub struct Label {
    /// Ref to name of label.
    label: u32,
    /// Last type associated with this label.
    typeidx: u32,
}

pub trait Index {
    const MAX: usize;
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct StrOffset(u32);

impl Index for StrOffset {
    const MAX: usize = 0x7ffffffff;
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct TypeIndex(u16);

impl Index for TypeIndex {
    const MAX: usize = u16::MAX as usize;
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[repr(i32)]
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

pub enum TypeKind2 {
    Unknown,
    Integer { size: u16 },
    Float { size: u16 },
    Pointer { type_: TypeIndex },
    Array,
    Function,
    Struct,
    Union,
    Enum,
    Forward,
    Typedef,
    Volatile,
    Const,
    Restrict,
}

pub struct Metadata(u16);

pub enum SizeOrType {
    Size(u16),
    Type(TypeIndex),
}

pub struct Type {
    name: StrOffset,
    info: TypeKind,
}

pub struct Member {
    name: StrOffset,
    type_: TypeIndex,
    offset: u16,
}

pub struct LMember {
    name: StrOffset,
    type_: TypeIndex,
    offset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        todo!();
    }
}

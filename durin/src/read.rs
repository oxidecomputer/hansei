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

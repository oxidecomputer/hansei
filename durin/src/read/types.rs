//! Wrapper types for CTF data for convenient access.

use super::{
    CtfReader, POINTER_SIZE, RawCtfArray, RawCtfConst, RawCtfEnum, RawCtfEnumerator, RawCtfFloat,
    RawCtfForward, RawCtfFunction, RawCtfInteger, RawCtfMember, RawCtfPointer, RawCtfRestrict,
    RawCtfStruct, RawCtfType, RawCtfTypedef, RawCtfUnion, RawCtfUnknown, RawCtfVolatile,
};
use crate::{FloatEncoding, IntegerEncoding, TypeId, TypeKind};

use std::fmt;
use std::hash::Hasher;

/// CTF type data with strings and types fully resolved.
///
/// This wraps `RawCtfType` variants and provides method-based access
/// that automatically resolves `StrId` to `&str` and `TypeId` to types.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum CtfType<'a> {
    Unknown(CtfUnknown<'a>),
    Integer(CtfInteger<'a>),
    Float(CtfFloat<'a>),
    Pointer(CtfPointer<'a>),
    Array(CtfArray<'a>),
    Function(CtfFunction<'a>),
    Struct(CtfStruct<'a>),
    Union(CtfUnion<'a>),
    Enum(CtfEnum<'a>),
    Forward(CtfForward<'a>),
    Typedef(CtfTypedef<'a>),
    Volatile(CtfVolatile<'a>),
    Const(CtfConst<'a>),
    Restrict(CtfRestrict<'a>),
}

impl<'a> CtfType<'a> {
    /// Create a `CtfType` from a `RawCtfType`.
    pub fn from_raw(raw: &'a RawCtfType, reader: &'a CtfReader) -> Self {
        match raw {
            RawCtfType::Unknown(inner) => CtfType::Unknown(CtfUnknown { raw: inner, reader }),
            RawCtfType::Integer(inner) => CtfType::Integer(CtfInteger { raw: inner, reader }),
            RawCtfType::Float(inner) => CtfType::Float(CtfFloat { raw: inner, reader }),
            RawCtfType::Pointer(inner) => CtfType::Pointer(CtfPointer { raw: inner, reader }),
            RawCtfType::Array(inner) => CtfType::Array(CtfArray { raw: inner, reader }),
            RawCtfType::Function(inner) => CtfType::Function(CtfFunction { raw: inner, reader }),
            RawCtfType::Struct(inner) => CtfType::Struct(CtfStruct { raw: inner, reader }),
            RawCtfType::Union(inner) => CtfType::Union(CtfUnion { raw: inner, reader }),
            RawCtfType::Enum(inner) => CtfType::Enum(CtfEnum { raw: inner, reader }),
            RawCtfType::Forward(inner) => CtfType::Forward(CtfForward { raw: inner, reader }),
            RawCtfType::Typedef(inner) => CtfType::Typedef(CtfTypedef { raw: inner, reader }),
            RawCtfType::Volatile(inner) => CtfType::Volatile(CtfVolatile { raw: inner, reader }),
            RawCtfType::Const(inner) => CtfType::Const(CtfConst { raw: inner, reader }),
            RawCtfType::Restrict(inner) => CtfType::Restrict(CtfRestrict { raw: inner, reader }),
        }
    }

    /// Returns the type's ID.
    pub fn id(&self) -> TypeId {
        match self {
            CtfType::Unknown(t) => t.id(),
            CtfType::Integer(t) => t.id(),
            CtfType::Float(t) => t.id(),
            CtfType::Pointer(t) => t.id(),
            CtfType::Array(t) => t.id(),
            CtfType::Function(t) => t.id(),
            CtfType::Struct(t) => t.id(),
            CtfType::Union(t) => t.id(),
            CtfType::Enum(t) => t.id(),
            CtfType::Forward(t) => t.id(),
            CtfType::Typedef(t) => t.id(),
            CtfType::Volatile(t) => t.id(),
            CtfType::Const(t) => t.id(),
            CtfType::Restrict(t) => t.id(),
        }
    }

    /// Returns the type's kind.
    pub fn kind(&self) -> TypeKind {
        match self {
            CtfType::Unknown(_) => TypeKind::Unknown,
            CtfType::Integer(_) => TypeKind::Integer,
            CtfType::Float(_) => TypeKind::Float,
            CtfType::Pointer(_) => TypeKind::Pointer,
            CtfType::Array(_) => TypeKind::Array,
            CtfType::Function(_) => TypeKind::Function,
            CtfType::Struct(_) => TypeKind::Struct,
            CtfType::Union(_) => TypeKind::Union,
            CtfType::Enum(_) => TypeKind::Enum,
            CtfType::Forward(_) => TypeKind::Forward,
            CtfType::Typedef(_) => TypeKind::Typedef,
            CtfType::Volatile(_) => TypeKind::Volatile,
            CtfType::Const(_) => TypeKind::Const,
            CtfType::Restrict(_) => TypeKind::Restrict,
        }
    }

    /// Returns the type's name.
    pub fn name(&self) -> &'a str {
        match self {
            CtfType::Unknown(t) => t.name(),
            CtfType::Integer(t) => t.name(),
            CtfType::Float(t) => t.name(),
            CtfType::Pointer(t) => t.name(),
            CtfType::Array(t) => t.name(),
            CtfType::Function(t) => t.name(),
            CtfType::Struct(t) => t.name(),
            CtfType::Union(t) => t.name(),
            CtfType::Enum(t) => t.name(),
            CtfType::Forward(t) => t.name(),
            CtfType::Typedef(t) => t.name(),
            CtfType::Volatile(t) => t.name(),
            CtfType::Const(t) => t.name(),
            CtfType::Restrict(t) => t.name(),
        }
    }

    /// Returns the type's size in bytes.
    pub fn size(&self) -> u64 {
        match self {
            Self::Unknown(_) => 0,
            Self::Integer(inner) => inner.size(),
            Self::Float(inner) => inner.size(),
            Self::Pointer(_) => POINTER_SIZE,
            Self::Array(inner) => {
                let elem_size = inner.element_type().size();
                elem_size * inner.len() as u64
            }
            Self::Function(..) => POINTER_SIZE,
            Self::Struct(inner) => inner.size(),
            Self::Union(inner) => inner.size(),
            Self::Enum(inner) => inner.size(),
            Self::Forward(_) => 0,
            Self::Typedef(inner) => inner.target().size(),
            Self::Volatile(inner) => inner.target().size(),
            Self::Const(inner) => inner.target().size(),
            Self::Restrict(inner) => inner.target().size(),
        }
    }

    /// Returns an iterator over the members of `self` it is a
    /// `CtfType::Struct` or `CtfType::Union`, otherwise return an empty
    /// iterator.
    pub fn members(&self) -> CtfMemberIter<'a> {
        match self {
            Self::Struct(inner) => inner.members(),
            Self::Union(inner) => inner.members(),
            _ => CtfMemberIter {
                members: &[],
                index: 0,
                reader: self.reader(),
            },
        }
    }

    /// Attempt to access the named enumerator if `self` is a `CtfType::Struct`
    /// or `CtfType::Union`, otherwise returns `None`.
    pub fn member(&self, name: &str) -> Option<CtfMember<'a>> {
        match self {
            Self::Struct(inner) => inner.member(name),
            Self::Union(inner) => inner.member(name),
            _ => None,
        }
    }

    /// Returns an iterator over the enumerators of `self` it is a
    /// `CtfType::Enum`, otherwise returns an empty iterator.
    pub fn enumerators(&self) -> CtfEnumeratorIter<'a> {
        match self {
            Self::Enum(inner) => inner.enumerators(),
            _ => CtfEnumeratorIter {
                enumerators: &[],
                index: 0,
                reader: self.reader(),
            },
        }
    }

    /// Attempt to access the named enumerator if `self` is a `CtfType::Enum`,
    /// otherwise returns `None`.
    pub fn enumerator(&self, name: &str) -> Option<CtfEnumerator<'a>> {
        match self {
            Self::Enum(inner) => inner.enumerator(name),
            _ => None,
        }
    }

    /// Return the target type of `self` is a `CtfType::Pointer`,
    /// `CtfType::Typedef`, `CtfType::Volatile`, `CtfType::Const`,
    /// or `CtfType::Restrict`, otherwise returns `None`.
    pub fn target(&self) -> Option<CtfType<'a>> {
        let target = match self {
            Self::Pointer(inner) => inner.target(),
            Self::Typedef(inner) => inner.target(),
            Self::Volatile(inner) => inner.target(),
            Self::Const(inner) => inner.target(),
            Self::Restrict(inner) => inner.target(),
            _ => return None,
        };
        Some(target)
    }

    pub fn reader(&self) -> &'a CtfReader {
        match self {
            Self::Unknown(inner) => inner.reader,
            Self::Integer(inner) => inner.reader,
            Self::Float(inner) => inner.reader,
            Self::Pointer(inner) => inner.reader,
            Self::Array(inner) => inner.reader,
            Self::Function(inner) => inner.reader,
            Self::Struct(inner) => inner.reader,
            Self::Union(inner) => inner.reader,
            Self::Enum(inner) => inner.reader,
            Self::Forward(inner) => inner.reader,
            Self::Typedef(inner) => inner.reader,
            Self::Volatile(inner) => inner.reader,
            Self::Const(inner) => inner.reader,
            Self::Restrict(inner) => inner.reader,
        }
    }

    /// Try to convert to `CtfUnknown`.
    pub fn as_unknown(&self) -> Option<CtfUnknown<'a>> {
        match self {
            CtfType::Unknown(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfInteger`.
    pub fn as_integer(&self) -> Option<CtfInteger<'a>> {
        match self {
            CtfType::Integer(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfFloat`.
    pub fn as_float(&self) -> Option<CtfFloat<'a>> {
        match self {
            CtfType::Float(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfPointer`.
    pub fn as_pointer(&self) -> Option<CtfPointer<'a>> {
        match self {
            CtfType::Pointer(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfArray`.
    pub fn as_array(&self) -> Option<CtfArray<'a>> {
        match self {
            CtfType::Array(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfFunction`.
    pub fn as_function(&self) -> Option<CtfFunction<'a>> {
        match self {
            CtfType::Function(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfStruct`.
    pub fn as_struct(&self) -> Option<CtfStruct<'a>> {
        match self {
            CtfType::Struct(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfUnion`.
    pub fn as_union(&self) -> Option<CtfUnion<'a>> {
        match self {
            CtfType::Union(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfEnum`.
    pub fn as_enum(&self) -> Option<CtfEnum<'a>> {
        match self {
            CtfType::Enum(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfForward`.
    pub fn as_forward(&self) -> Option<CtfForward<'a>> {
        match self {
            CtfType::Forward(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfTypedef`.
    pub fn as_typedef(&self) -> Option<CtfTypedef<'a>> {
        match self {
            CtfType::Typedef(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfVolatile`.
    pub fn as_volatile(&self) -> Option<CtfVolatile<'a>> {
        match self {
            CtfType::Volatile(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfConst`.
    pub fn as_const(&self) -> Option<CtfConst<'a>> {
        match self {
            CtfType::Const(t) => Some(*t),
            _ => None,
        }
    }

    /// Try to convert to `CtfRestrict`.
    pub fn as_restrict(&self) -> Option<CtfRestrict<'a>> {
        match self {
            CtfType::Restrict(t) => Some(*t),
            _ => None,
        }
    }
}

/// An unknown CTF type.
#[derive(Copy, Clone)]
pub struct CtfUnknown<'a> {
    raw: &'a RawCtfUnknown,
    reader: &'a CtfReader,
}

impl<'a> CtfUnknown<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name (always empty for unknown types).
    pub fn name(&self) -> &'a str {
        ""
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfUnknown {
        self.raw
    }
}

impl<'a> From<CtfUnknown<'a>> for CtfType<'a> {
    fn from(val: CtfUnknown<'a>) -> Self {
        CtfType::Unknown(val)
    }
}

impl fmt::Debug for CtfUnknown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfUnknown")
            .field("id", &self.id())
            .finish()
    }
}

/// A CTF integer type.
#[derive(Copy, Clone)]
pub struct CtfInteger<'a> {
    raw: &'a RawCtfInteger,
    reader: &'a CtfReader,
}

impl<'a> CtfInteger<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the size in bytes.
    pub fn size(&self) -> u64 {
        self.raw.size
    }

    /// Return the integer encoding.
    pub fn encoding(&self) -> IntegerEncoding {
        self.raw.encoding
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfInteger {
        self.raw
    }
}

impl<'a> From<CtfInteger<'a>> for CtfType<'a> {
    fn from(val: CtfInteger<'a>) -> Self {
        CtfType::Integer(val)
    }
}

impl fmt::Debug for CtfInteger<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfInteger")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("size", &self.size())
            .field("encoding", &self.encoding())
            .finish()
    }
}

/// A CTF float type.
#[derive(Copy, Clone)]
pub struct CtfFloat<'a> {
    raw: &'a RawCtfFloat,
    reader: &'a CtfReader,
}

impl<'a> CtfFloat<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the size in bytes.
    pub fn size(&self) -> u64 {
        self.raw.size
    }

    /// Return the float encoding.
    pub fn encoding(&self) -> FloatEncoding {
        self.raw.encoding
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfFloat {
        self.raw
    }
}

impl<'a> From<CtfFloat<'a>> for CtfType<'a> {
    fn from(val: CtfFloat<'a>) -> Self {
        CtfType::Float(val)
    }
}

impl fmt::Debug for CtfFloat<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfFloat")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("size", &self.size())
            .field("encoding", &self.encoding())
            .finish()
    }
}

/// A CTF pointer type.
#[derive(Copy, Clone)]
pub struct CtfPointer<'a> {
    raw: &'a RawCtfPointer,
    reader: &'a CtfReader,
}

impl<'a> CtfPointer<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the target type.
    pub fn target(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.target_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfPointer {
        self.raw
    }
}

impl<'a> From<CtfPointer<'a>> for CtfType<'a> {
    fn from(val: CtfPointer<'a>) -> Self {
        CtfType::Pointer(val)
    }
}

impl fmt::Debug for CtfPointer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfPointer")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("target", &self.target())
            .finish()
    }
}

/// A CTF array type.
#[derive(Copy, Clone)]
pub struct CtfArray<'a> {
    raw: &'a RawCtfArray,
    reader: &'a CtfReader,
}

impl<'a> CtfArray<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the element type.
    pub fn element_type(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.element_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Return the index type.
    pub fn index_type(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.index_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Return the number of elements.
    pub fn len(&self) -> u32 {
        self.raw.nelems
    }

    /// Return whether the array is empty.
    pub fn is_empty(&self) -> bool {
        self.raw.nelems == 0
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfArray {
        self.raw
    }
}

impl<'a> From<CtfArray<'a>> for CtfType<'a> {
    fn from(val: CtfArray<'a>) -> Self {
        CtfType::Array(val)
    }
}

impl fmt::Debug for CtfArray<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfArray")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("element_type", &self.element_type())
            .field("index_type", &self.index_type())
            .field("len", &self.len())
            .finish()
    }
}

/// A CTF function type.
#[derive(Copy, Clone)]
pub struct CtfFunction<'a> {
    raw: &'a RawCtfFunction,
    reader: &'a CtfReader,
}

impl<'a> CtfFunction<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the return type.
    pub fn return_type(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.return_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Return the number of arguments.
    pub fn arg_count(&self) -> usize {
        self.raw.args.len()
    }

    /// Return an iterator over argument types.
    pub fn args(&self) -> CtfFunctionArgIter<'a> {
        CtfFunctionArgIter {
            args: &self.raw.args,
            index: 0,
            reader: self.reader,
        }
    }

    /// Return whether the function accepts variadic arguments.
    pub fn is_varargs(&self) -> bool {
        self.raw.is_varargs
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfFunction {
        self.raw
    }
}

impl<'a> From<CtfFunction<'a>> for CtfType<'a> {
    fn from(val: CtfFunction<'a>) -> Self {
        CtfType::Function(val)
    }
}

impl fmt::Debug for CtfFunction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let args: Vec<_> = self.args().collect();

        f.debug_struct("CtfFunction")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("return_type", &self.return_type())
            .field("args", &args)
            .field("is_varargs", &self.is_varargs())
            .finish()
    }
}

/// Iterator over function argument types.
#[derive(Clone, Debug)]
pub struct CtfFunctionArgIter<'a> {
    args: &'a [TypeId],
    index: usize,
    reader: &'a CtfReader,
}

impl<'a> Iterator for CtfFunctionArgIter<'a> {
    type Item = CtfType<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.args.len() {
            return None;
        }
        let type_id = self.args[self.index];
        self.index += 1;
        let raw = self.reader.ty(type_id);
        Some(CtfType::from_raw(raw, self.reader))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.args.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for CtfFunctionArgIter<'a> {}

/// A CTF struct type.
#[derive(Copy, Clone)]
pub struct CtfStruct<'a> {
    raw: &'a RawCtfStruct,
    reader: &'a CtfReader,
}

impl<'a> CtfStruct<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the size in bytes.
    pub fn size(&self) -> u64 {
        self.raw.size
    }

    /// Return the number of members.
    pub fn member_count(&self) -> usize {
        self.raw.members.len()
    }

    /// Return an iterator over members.
    pub fn members(&self) -> CtfMemberIter<'a> {
        CtfMemberIter {
            members: &self.raw.members,
            index: 0,
            reader: self.reader,
        }
    }

    /// Find a member by name.
    pub fn member(&self, name: &str) -> Option<CtfMember<'a>> {
        self.raw
            .members
            .iter()
            .find(|m| self.reader.str(m.name) == name)
            .map(|m| CtfMember {
                raw: m,
                reader: self.reader,
            })
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfStruct {
        self.raw
    }
}

impl<'a> From<CtfStruct<'a>> for CtfType<'a> {
    fn from(val: CtfStruct<'a>) -> Self {
        CtfType::Struct(val)
    }
}

impl fmt::Debug for CtfStruct<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let members: Vec<_> = self.members().collect();

        f.debug_struct("CtfStruct")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("members", &members)
            .finish()
    }
}

/// A CTF union type.
#[derive(Copy, Clone)]
pub struct CtfUnion<'a> {
    raw: &'a RawCtfUnion,
    reader: &'a CtfReader,
}

impl<'a> CtfUnion<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the size in bytes.
    pub fn size(&self) -> u64 {
        self.raw.size
    }

    /// Return the number of members.
    pub fn member_count(&self) -> usize {
        self.raw.members.len()
    }

    /// Return an iterator over members.
    pub fn members(&self) -> CtfMemberIter<'a> {
        CtfMemberIter {
            members: &self.raw.members,
            index: 0,
            reader: self.reader,
        }
    }

    /// Find a member by name.
    pub fn member(&self, name: &str) -> Option<CtfMember<'a>> {
        self.raw
            .members
            .iter()
            .find(|m| self.reader.str(m.name) == name)
            .map(|m| CtfMember {
                raw: m,
                reader: self.reader,
            })
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfUnion {
        self.raw
    }
}

impl<'a> From<CtfUnion<'a>> for CtfType<'a> {
    fn from(val: CtfUnion<'a>) -> Self {
        CtfType::Union(val)
    }
}

impl fmt::Debug for CtfUnion<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let members: Vec<_> = self.members().collect();

        f.debug_struct("CtfUnion")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("members", &members)
            .finish()
    }
}

/// A member of a `CtfStruct` or `CtfUnion`.
#[derive(Copy, Clone)]
pub struct CtfMember<'a> {
    raw: &'a RawCtfMember,
    reader: &'a CtfReader,
}

impl<'a> CtfMember<'a> {
    /// Return the member's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the member's type.
    pub fn ty(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.type_id);
        CtfType::from_raw(raw, self.reader)
    }

    /// Return the member's offset in bits.
    pub fn offset_bits(&self) -> u64 {
        self.raw.offset_bits
    }

    /// Return the member's offset in bytes.
    pub fn offset(&self) -> u64 {
        self.raw.offset_bits / 8
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfMember {
        self.raw
    }
}

impl fmt::Debug for CtfMember<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfMember")
            .field("name", &self.name())
            .field("type", &self.ty())
            .field("offset", &self.offset())
            .finish()
    }
}

/// Iterator over struct/union members.
#[derive(Clone, Debug)]
pub struct CtfMemberIter<'a> {
    members: &'a [RawCtfMember],
    index: usize,
    reader: &'a CtfReader,
}

impl<'a> Iterator for CtfMemberIter<'a> {
    type Item = CtfMember<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.members.len() {
            return None;
        }
        let member = &self.members[self.index];
        self.index += 1;
        Some(CtfMember {
            raw: member,
            reader: self.reader,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.members.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for CtfMemberIter<'a> {}

/// A CTF enum type.
#[derive(Copy, Clone)]
pub struct CtfEnum<'a> {
    raw: &'a RawCtfEnum,
    reader: &'a CtfReader,
}

impl<'a> CtfEnum<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the size in bytes.
    pub fn size(&self) -> u64 {
        self.raw.size
    }

    /// Return the number of enumerators.
    pub fn enumerator_count(&self) -> usize {
        self.raw.enumerators.len()
    }

    /// Return an iterator over enumerators.
    pub fn enumerators(&self) -> CtfEnumeratorIter<'a> {
        CtfEnumeratorIter {
            enumerators: &self.raw.enumerators,
            index: 0,
            reader: self.reader,
        }
    }

    /// Find an enumerator by name.
    pub fn enumerator(&self, name: &str) -> Option<CtfEnumerator<'a>> {
        self.raw
            .enumerators
            .iter()
            .find(|e| self.reader.str(e.name) == name)
            .map(|e| CtfEnumerator {
                raw: e,
                reader: self.reader,
            })
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfEnum {
        self.raw
    }
}

impl<'a> From<CtfEnum<'a>> for CtfType<'a> {
    fn from(val: CtfEnum<'a>) -> Self {
        CtfType::Enum(val)
    }
}

impl fmt::Debug for CtfEnum<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let enumerators: Vec<_> = self.enumerators().collect();

        f.debug_struct("CtfEnum")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("size", &self.size())
            .field("enumerators", &enumerators)
            .finish()
    }
}

/// A `CtfEnum` enumerator.
#[derive(Copy, Clone)]
pub struct CtfEnumerator<'a> {
    raw: &'a RawCtfEnumerator,
    reader: &'a CtfReader,
}

impl<'a> CtfEnumerator<'a> {
    /// Return the enumerator's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the enumerator's value.
    pub fn value(&self) -> u64 {
        self.raw.value
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfEnumerator {
        self.raw
    }
}

impl fmt::Debug for CtfEnumerator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfEnumerator")
            .field("name", &self.name())
            .field("value", &self.value())
            .finish()
    }
}

/// Iterator over enum enumerators.
#[derive(Clone, Debug)]
pub struct CtfEnumeratorIter<'a> {
    enumerators: &'a [RawCtfEnumerator],
    index: usize,
    reader: &'a CtfReader,
}

impl<'a> Iterator for CtfEnumeratorIter<'a> {
    type Item = CtfEnumerator<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.enumerators.len() {
            return None;
        }
        let enumerator = &self.enumerators[self.index];
        self.index += 1;
        Some(CtfEnumerator {
            raw: enumerator,
            reader: self.reader,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.enumerators.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for CtfEnumeratorIter<'a> {}

/// A CTF forward declaration type.
#[derive(Copy, Clone)]
pub struct CtfForward<'a> {
    raw: &'a RawCtfForward,
    reader: &'a CtfReader,
}

impl<'a> CtfForward<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfForward {
        self.raw
    }
}

impl<'a> From<CtfForward<'a>> for CtfType<'a> {
    fn from(val: CtfForward<'a>) -> Self {
        CtfType::Forward(val)
    }
}

impl fmt::Debug for CtfForward<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfForward")
            .field("id", &self.id())
            .field("name", &self.name())
            .finish()
    }
}

/// A CTF typedef type.
#[derive(Copy, Clone)]
pub struct CtfTypedef<'a> {
    raw: &'a RawCtfTypedef,
    reader: &'a CtfReader,
}

impl<'a> CtfTypedef<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the target type.
    pub fn target(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.target_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfTypedef {
        self.raw
    }
}

impl<'a> From<CtfTypedef<'a>> for CtfType<'a> {
    fn from(val: CtfTypedef<'a>) -> Self {
        CtfType::Typedef(val)
    }
}

impl fmt::Debug for CtfTypedef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfTypedef")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("target", &self.target())
            .finish()
    }
}

/// A CTF volatile type.
#[derive(Copy, Clone)]
pub struct CtfVolatile<'a> {
    raw: &'a RawCtfVolatile,
    reader: &'a CtfReader,
}

impl<'a> CtfVolatile<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the target type.
    pub fn target(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.target_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfVolatile {
        self.raw
    }
}

impl<'a> From<CtfVolatile<'a>> for CtfType<'a> {
    fn from(val: CtfVolatile<'a>) -> Self {
        CtfType::Volatile(val)
    }
}

impl fmt::Debug for CtfVolatile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfVolatile")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("target", &self.target())
            .finish()
    }
}

/// A CTF const type.
#[derive(Copy, Clone)]
pub struct CtfConst<'a> {
    raw: &'a RawCtfConst,
    reader: &'a CtfReader,
}

impl<'a> CtfConst<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the target type.
    pub fn target(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.target_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfConst {
        self.raw
    }
}

impl<'a> From<CtfConst<'a>> for CtfType<'a> {
    fn from(val: CtfConst<'a>) -> Self {
        CtfType::Const(val)
    }
}

impl fmt::Debug for CtfConst<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfConst")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("target", &self.target())
            .finish()
    }
}

/// A CTF restrict type.
#[derive(Copy, Clone)]
pub struct CtfRestrict<'a> {
    raw: &'a RawCtfRestrict,
    reader: &'a CtfReader,
}

impl<'a> CtfRestrict<'a> {
    /// Return the type's ID.
    pub fn id(&self) -> TypeId {
        self.raw.id
    }

    /// Return the type's name.
    pub fn name(&self) -> &'a str {
        self.reader.str(self.raw.name)
    }

    /// Return the target type.
    pub fn target(&self) -> CtfType<'a> {
        let raw = self.reader.ty(self.raw.target_type);
        CtfType::from_raw(raw, self.reader)
    }

    /// Converts `self` into a `CtfType`.
    pub fn into_ctf_type(self) -> CtfType<'a> {
        self.into()
    }

    /// Access the inner raw CTF value.
    pub fn raw(&self) -> &RawCtfRestrict {
        self.raw
    }
}

impl<'a> From<CtfRestrict<'a>> for CtfType<'a> {
    fn from(val: CtfRestrict<'a>) -> Self {
        CtfType::Restrict(val)
    }
}

impl fmt::Debug for CtfRestrict<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtfRestrict")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("target", &self.target())
            .finish()
    }
}

// Ignore the reader for comparisons and hashing.
macro_rules! impl_eq_and_hash {
    ( $( $name:ty ),+) => {
        $(
        impl std::cmp::PartialEq for $name {
            fn eq(&self, other: &$name) -> bool {
                self.raw == other.raw
            }
        }

        impl std::cmp::Eq for $name {}

        impl std::hash::Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.raw.hash(state);
            }
        }
        )+
    };
}

impl_eq_and_hash!(
    CtfUnknown<'_>,
    CtfInteger<'_>,
    CtfFloat<'_>,
    CtfPointer<'_>,
    CtfArray<'_>,
    CtfFunction<'_>,
    CtfStruct<'_>,
    CtfUnion<'_>,
    CtfEnum<'_>,
    CtfForward<'_>,
    CtfTypedef<'_>,
    CtfVolatile<'_>,
    CtfConst<'_>,
    CtfRestrict<'_>,
    CtfMember<'_>,
    CtfEnumerator<'_>
);

macro_rules! impl_ord {
    ( $( $name:ty ),+) => {
        $(
        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &$name) -> std::cmp::Ordering {
                self.raw.cmp(&other.raw)
            }
        }

        impl std::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &$name) -> Option<std::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }
        )+
    };
}

impl_ord!(
    CtfUnknown<'_>,
    CtfInteger<'_>,
    CtfFloat<'_>,
    CtfPointer<'_>,
    CtfArray<'_>,
    CtfFunction<'_>,
    CtfStruct<'_>,
    CtfUnion<'_>,
    CtfEnum<'_>,
    CtfForward<'_>,
    CtfTypedef<'_>,
    CtfVolatile<'_>,
    CtfConst<'_>,
    CtfRestrict<'_>
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::CtfReader;
    use crate::write::{
        CtfEnumerator as WriteCtfEnumerator, CtfMember as WriteCtfMember, CtfType as WriteCtfType,
        CtfWriter,
    };
    use crate::{FloatEncoding, FloatType, IntegerEncoding, IntegerFlags};

    fn create_reader(writer: &mut CtfWriter) -> CtfReader {
        let ctf_bytes = writer.generate_ctf().unwrap();
        CtfReader::load(&ctf_bytes).unwrap()
    }

    #[test]
    fn test_ctf_integer() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding {
                    bits: 32,
                    offset: 0,
                    flags: IntegerFlags::new().signed(),
                },
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("i32", TypeKind::Integer).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        assert_eq!(ty.kind(), TypeKind::Integer);
        assert_eq!(ty.name(), "i32");

        let int = ty.as_integer().unwrap();
        assert_eq!(int.name(), "i32");
        assert_eq!(int.size(), 4);
        assert!(int.encoding().flags.is_signed());
    }

    #[test]
    fn test_ctf_float() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(WriteCtfType::Float {
                name: "f64".to_string(),
                size: 8,
                encoding: FloatEncoding {
                    bits: 64,
                    offset: 0,
                    float_type: FloatType::Double,
                },
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("f64", TypeKind::Float).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let float = ty.as_float().unwrap();
        assert_eq!(float.name(), "f64");
        assert_eq!(float.size(), 8);
        assert_eq!(float.encoding().float_type, FloatType::Double);
    }

    #[test]
    fn test_ctf_pointer() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Pointer {
                name: "".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader
            .types()
            .iter()
            .find(|t| t.kind() == TypeKind::Pointer)
            .unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let ptr = ty.as_pointer().unwrap();
        assert_eq!(ptr.target().id(), int_id);
        assert_eq!(ptr.target().name(), "i32");
    }

    #[test]
    fn test_ctf_array() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Array {
                name: "".to_string(),
                element_type: int_id,
                index_type: int_id,
                nelems: 10,
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader
            .types()
            .iter()
            .find(|t| t.kind() == TypeKind::Array)
            .unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let arr = ty.as_array().unwrap();
        assert_eq!(arr.len(), 10);
        assert!(!arr.is_empty());
        assert_eq!(arr.element_type().name(), "i32");
    }

    #[test]
    fn test_ctf_struct() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Struct {
                name: "Point".to_string(),
                size: 8,
                members: vec![
                    WriteCtfMember {
                        name: "x".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    WriteCtfMember {
                        name: "y".to_string(),
                        type_id: int_id,
                        offset_bits: 32,
                    },
                ],
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("Point", TypeKind::Struct).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let s = ty.as_struct().unwrap();
        assert_eq!(s.name(), "Point");
        assert_eq!(s.size(), 8);
        assert_eq!(s.member_count(), 2);

        let members: Vec<_> = s.members().collect();
        assert_eq!(members[0].name(), "x");
        assert_eq!(members[0].offset(), 0);
        assert_eq!(members[1].name(), "y");
        assert_eq!(members[1].offset(), 4);

        let x = s.member("x").unwrap();
        assert_eq!(x.ty().name(), "i32");

        assert!(s.member("z").is_none());
    }

    #[test]
    fn test_ctf_union() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        let float_id = writer
            .add_type(WriteCtfType::Float {
                name: "f32".to_string(),
                size: 4,
                encoding: FloatEncoding {
                    bits: 32,
                    offset: 0,
                    float_type: FloatType::Single,
                },
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Union {
                name: "IntOrFloat".to_string(),
                size: 4,
                members: vec![
                    WriteCtfMember {
                        name: "i".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    WriteCtfMember {
                        name: "f".to_string(),
                        type_id: float_id,
                        offset_bits: 0,
                    },
                ],
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("IntOrFloat", TypeKind::Union).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let u = ty.as_union().unwrap();
        assert_eq!(u.name(), "IntOrFloat");
        assert_eq!(u.member_count(), 2);

        let i = u.member("i").unwrap();
        let f = u.member("f").unwrap();
        assert_eq!(i.offset(), 0);
        assert_eq!(f.offset(), 0);
    }

    #[test]
    fn test_ctf_enum() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(WriteCtfType::Enum {
                name: "Color".to_string(),
                size: 4,
                enumerators: vec![
                    WriteCtfEnumerator {
                        name: "Red".to_string(),
                        value: 0,
                    },
                    WriteCtfEnumerator {
                        name: "Green".to_string(),
                        value: 1,
                    },
                    WriteCtfEnumerator {
                        name: "Blue".to_string(),
                        value: 2,
                    },
                ],
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("Color", TypeKind::Enum).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let e = ty.as_enum().unwrap();
        assert_eq!(e.name(), "Color");
        assert_eq!(e.size(), 4);
        assert_eq!(e.enumerator_count(), 3);

        let enums: Vec<_> = e.enumerators().collect();
        assert_eq!(enums[0].name(), "Red");
        assert_eq!(enums[0].value(), 0);
        assert_eq!(enums[1].name(), "Green");
        assert_eq!(enums[1].value(), 1);

        let green = e.enumerator("Green").unwrap();
        assert_eq!(green.value(), 1);

        assert!(e.enumerator("Yellow").is_none());
    }

    #[test]
    fn test_ctf_typedef() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Typedef {
                name: "MyInt".to_string(),
                target_type: int_id,
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("MyInt", TypeKind::Typedef).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let td = ty.as_typedef().unwrap();
        assert_eq!(td.name(), "MyInt");
        assert_eq!(td.target().id(), int_id);
        assert_eq!(td.target().name(), "i32");
    }

    #[test]
    fn test_ctf_const_volatile_restrict() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        let const_id = writer
            .add_type(WriteCtfType::Const {
                name: "".to_string(),
                target_type: int_id,
            })
            .unwrap();
        let volatile_id = writer
            .add_type(WriteCtfType::Volatile {
                name: "".to_string(),
                target_type: const_id,
            })
            .unwrap();
        let ptr_id = writer
            .add_type(WriteCtfType::Pointer {
                name: "".to_string(),
                target_type: int_id,
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Restrict {
                name: "".to_string(),
                target_type: ptr_id,
            })
            .unwrap();

        let reader = create_reader(&mut writer);

        // Test const
        let const_raw = reader.ty(const_id);
        let const_ty = CtfType::from_raw(const_raw, &reader);
        let c = const_ty.as_const().unwrap();
        assert_eq!(c.target().name(), "i32");

        // Test volatile
        let volatile_raw = reader.ty(volatile_id);
        let volatile_ty = CtfType::from_raw(volatile_raw, &reader);
        let v = volatile_ty.as_volatile().unwrap();
        assert_eq!(v.target().kind(), TypeKind::Const);

        // Test restrict
        let restrict_raw = reader
            .types()
            .iter()
            .find(|t| t.kind() == TypeKind::Restrict)
            .unwrap();
        let restrict_ty = CtfType::from_raw(restrict_raw, &reader);
        let r = restrict_ty.as_restrict().unwrap();
        assert_eq!(r.target().kind(), TypeKind::Pointer);
    }

    #[test]
    fn test_ctf_forward() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(WriteCtfType::Forward {
                name: "ForwardStruct".to_string(),
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("ForwardStruct", TypeKind::Forward).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let f = ty.as_forward().unwrap();
        assert_eq!(f.name(), "ForwardStruct");
    }

    #[test]
    fn test_ctf_function() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Function {
                name: "add".to_string(),
                return_type: int_id,
                args: vec![int_id, int_id],
                is_varargs: false,
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("add", TypeKind::Function).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let f = ty.as_function().unwrap();
        assert_eq!(f.name(), "add");
        assert_eq!(f.return_type().name(), "i32");
        assert_eq!(f.arg_count(), 2);
        assert!(!f.is_varargs());

        let args: Vec<_> = f.args().collect();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name(), "i32");
        assert_eq!(args[1].name(), "i32");
    }

    #[test]
    fn test_ctf_function_varargs() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        let ptr_id = writer
            .add_type(WriteCtfType::Pointer {
                name: "".to_string(),
                target_type: int_id,
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Function {
                name: "printf".to_string(),
                return_type: int_id,
                args: vec![ptr_id],
                is_varargs: true,
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("printf", TypeKind::Function).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let f = ty.as_function().unwrap();
        assert!(f.is_varargs());
        assert_eq!(f.arg_count(), 1);
    }

    #[test]
    fn test_member_iter_exact_size() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Struct {
                name: "Test".to_string(),
                size: 12,
                members: vec![
                    WriteCtfMember {
                        name: "a".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    WriteCtfMember {
                        name: "b".to_string(),
                        type_id: int_id,
                        offset_bits: 32,
                    },
                    WriteCtfMember {
                        name: "c".to_string(),
                        type_id: int_id,
                        offset_bits: 64,
                    },
                ],
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("Test", TypeKind::Struct).unwrap();
        let ty = CtfType::from_raw(raw, &reader);
        let s = ty.as_struct().unwrap();

        let iter = s.members();
        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn test_enumerator_iter_exact_size() {
        let mut writer = CtfWriter::new();
        writer
            .add_type(WriteCtfType::Enum {
                name: "Test".to_string(),
                size: 4,
                enumerators: vec![
                    WriteCtfEnumerator {
                        name: "A".to_string(),
                        value: 0,
                    },
                    WriteCtfEnumerator {
                        name: "B".to_string(),
                        value: 1,
                    },
                ],
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("Test", TypeKind::Enum).unwrap();
        let ty = CtfType::from_raw(raw, &reader);
        let e = ty.as_enum().unwrap();

        let iter = e.enumerators();
        assert_eq!(iter.len(), 2);
    }

    #[test]
    fn test_function_arg_iter_exact_size() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();
        writer
            .add_type(WriteCtfType::Function {
                name: "test".to_string(),
                return_type: int_id,
                args: vec![int_id, int_id, int_id],
                is_varargs: false,
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("test", TypeKind::Function).unwrap();
        let ty = CtfType::from_raw(raw, &reader);
        let f = ty.as_function().unwrap();

        let iter = f.args();
        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn test_ctf_nested_struct() {
        let mut writer = CtfWriter::new();
        let int_id = writer
            .add_type(WriteCtfType::Integer {
                name: "i32".to_string(),
                size: 4,
                encoding: IntegerEncoding::default(),
            })
            .unwrap();

        let point_id = writer
            .add_type(WriteCtfType::Struct {
                name: "Point".to_string(),
                size: 8,
                members: vec![
                    WriteCtfMember {
                        name: "x".to_string(),
                        type_id: int_id,
                        offset_bits: 0,
                    },
                    WriteCtfMember {
                        name: "y".to_string(),
                        type_id: int_id,
                        offset_bits: 32,
                    },
                ],
            })
            .unwrap();

        writer
            .add_type(WriteCtfType::Struct {
                name: "Rect".to_string(),
                size: 16,
                members: vec![
                    WriteCtfMember {
                        name: "top_left".to_string(),
                        type_id: point_id,
                        offset_bits: 0,
                    },
                    WriteCtfMember {
                        name: "bottom_right".to_string(),
                        type_id: point_id,
                        offset_bits: 64,
                    },
                ],
            })
            .unwrap();

        let reader = create_reader(&mut writer);
        let raw = reader.find_ty("Rect", TypeKind::Struct).unwrap();
        let ty = CtfType::from_raw(raw, &reader);

        let rect = ty.as_struct().unwrap();
        assert_eq!(rect.name(), "Rect");
        assert_eq!(rect.size(), 16);
        assert_eq!(rect.member_count(), 2);

        let members: Vec<_> = rect.members().collect();
        assert_eq!(members[0].name(), "top_left");
        assert_eq!(members[0].offset(), 0);
        assert_eq!(members[1].name(), "bottom_right");
        assert_eq!(members[1].offset(), 8);

        // Verify the member types reference Point
        assert_eq!(members[0].ty().name(), "Point");
        assert_eq!(members[1].ty().name(), "Point");

        // Verify the nested struct's own members are accessible
        let point_ty = members[0].ty();
        let point = point_ty.as_struct().unwrap();
        assert_eq!(point.member_count(), 2);
        assert_eq!(point.member("x").unwrap().ty().name(), "i32");
    }
}

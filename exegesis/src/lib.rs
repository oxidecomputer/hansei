pub mod bundle;
mod cgu;
pub mod detect;
pub mod extract;
pub mod raw_types;
pub mod reader;
pub mod string_table;
pub mod summary;
pub mod symbols;
pub mod view;

#[cfg(test)]
mod testhelper;

pub use raw_types::{Encoding, NamespaceTable, NsEntry, NsId};
pub use reader::{DwReader, ReadArgs, Targets};
pub use string_table::StrId;
pub use view::{
    Array, Base, DwView, Enum, Enumerator, EnumeratorIter, Func, Member, MemberIter, Namespace,
    NsFuncIter, NsTypeIter, NsVarIter, Param, ParamIter, Pointer, SourceLocView, StaticVariable,
    Struct, TemplateParam, TemplateParamIter, Type, Union, Variant, VariantIter, VariantShapeView,
};

use gimli::{EndianSlice, RunTimeEndian, UnitSectionOffset};

/// The kind of a DWARF type.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum TypeKind {
    Base,
    Pointer,
    Enum,
    Struct,
    Union,
    Array,
}

use std::fmt;

type Slice<'a> = EndianSlice<'a, RunTimeEndian>;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to parse DWARF")]
    DwarfError(#[from] gimli::Error),
    #[error("expected string value for attribute {0}")]
    UnexpectedStrAttr(gimli::DwAt),
    #[error("item was not valid UTF-8")]
    InvalidUtf8,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub UnitSectionOffset);

impl From<gimli::UnitSectionOffset> for TypeId {
    fn from(offset: gimli::UnitSectionOffset) -> Self {
        Self(offset)
    }
}

impl fmt::Debug for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = match self.0 {
            UnitSectionOffset::DebugInfoOffset(o) => o.0,
            UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        write!(f, "{inner:#x}")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarId(pub UnitSectionOffset);

impl From<gimli::UnitSectionOffset> for VarId {
    fn from(offset: gimli::UnitSectionOffset) -> Self {
        Self(offset)
    }
}

impl fmt::Debug for VarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = match self.0 {
            UnitSectionOffset::DebugInfoOffset(o) => o.0,
            UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        write!(f, "{inner:#x}")
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuncId(pub UnitSectionOffset);

impl From<gimli::UnitSectionOffset> for FuncId {
    fn from(offset: gimli::UnitSectionOffset) -> Self {
        Self(offset)
    }
}

impl fmt::Debug for FuncId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = match self.0 {
            UnitSectionOffset::DebugInfoOffset(o) => o.0,
            UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        write!(f, "{inner:#x}")
    }
}

// trait DwU128 {
//     fn attr_u128(&self, unit: &UnitRef<Slice>) -> Option<u128>;
// }
//
// impl DwU128 for AttributeValue<Slice<'_>> {
//     fn attr_u128(&self, unit: &UnitRef<Slice>) -> Option<u128> {
//         Some(match *self {
//             AttributeValue::Data1(data) => u128::from(data),
//             AttributeValue::Data2(data) => u128::from(data),
//             AttributeValue::Data4(data) => u128::from(data),
//             AttributeValue::Data8(data) => u128::from(data),
//             AttributeValue::Udata(data) => u128::from(data),
//             AttributeValue::Sdata(data) => {
//                 if data < 0 {
//                     return None;
//                 }
//                 data as u128
//             }
//             _ => return None,
//         })
//     }
// }

mod cgu;
pub mod describe;
pub mod detect;
pub mod extract;
pub mod raw_types;
pub mod reader;
pub mod string_table;
pub mod summary;
pub mod view;

/// The bundle wire format lives in its own crate, which carries no DWARF
/// dependencies. Re-exported under the module paths it has always had.
pub use hansei_bundle as bundle;
pub use hansei_bundle::symbols;

#[cfg(test)]
mod testhelper;

pub use raw_types::{Encoding, NamespaceTable, NsEntry, NsId};
pub use reader::{DwReader, ReadArgs};
pub use string_table::StrId;
pub use view::{
    DwView, Func, Namespace, Param, ParamIter, SourceLocView, TemplateParam, TemplateParamIter,
};

use gimli::{EndianSlice, RunTimeEndian, UnitSectionOffset};

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

#[cfg(test)]
mod tests {
    use super::*;
    use gimli::{DebugInfoOffset, DebugTypesOffset};

    /// The id wrappers debug-print as the bare hex offset — what an
    /// operator pastes between `dump` output and `--include-type`.
    #[test]
    fn test_ids_debug_print_as_hex_offsets() {
        let info = UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(0x1f));
        let types = UnitSectionOffset::DebugTypesOffset(DebugTypesOffset(0x2c));
        assert_eq!(format!("{:?}", TypeId(info)), "0x1f");
        assert_eq!(format!("{:?}", TypeId(types)), "0x2c");
        assert_eq!(format!("{:?}", VarId(info)), "0x1f");
        assert_eq!(format!("{:?}", FuncId(info)), "0x1f");
    }
}

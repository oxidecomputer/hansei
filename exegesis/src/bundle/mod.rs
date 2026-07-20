//! The async debug bundle: a serialized description of a debug binary's
//! tokio runtime, keyed by v0 mangled symbol names so a separately-compiled
//! target binary can be interpreted without any address ever crossing
//! between the two (see `HANSEI_V0_MANGLING_PLAN.md` §5).

mod io;
mod schema;
mod strings;
mod view;

pub use io::{Error, FORMAT_VERSION, MAGIC, Result};
pub use schema::{
    BinaryIdent, BitField, Bundle, BundleTypeId, DebugFormat, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode, DynFutureTable, Field, FieldRender, FutureKind, InfraTypes, KnownFormat,
    MemberDef, Meta, Provenance, ProvenanceTable, ScalarDecode, Selector, SourceLoc, StaticDef,
    StaticRole, StaticsTable, Step, SymbolLookup, TaskEntryId, TaskFutureEntry, TaskTable, TypeDef,
    TypeTable, VariantDef, VariantShape, strip_llvm_suffix,
};
pub use strings::{StrRef, StringInterner, StringTable};
pub use view::{
    ActiveVariant, BundleMember, BundleMemberIter, BundleType, BundleView, DynPointer,
    POINTER_SIZE, VariantError,
};

#[cfg(test)]
mod tests;

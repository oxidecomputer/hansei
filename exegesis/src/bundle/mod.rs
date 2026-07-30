//! The async debug bundle: a serialized description of a debug binary's
//! tokio runtime, keyed by v0 mangled symbol names so a separately-compiled
//! target binary can be interpreted without any address ever crossing
//! between the two (see `HANSEI_V0_MANGLING_PLAN.md` §5).

mod describe;
mod io;
mod schema;
mod shape;
mod strings;
mod view;

pub use describe::{describe_debug_format, describe_node};
pub use io::{Error, FORMAT_VERSION, MAGIC, Result};
pub use schema::{
    Arm, BinaryIdent, BitField, Bundle, BundleTypeId, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode, DynFutureTable, Field, FieldRender, FutureKind, InfraTypes, MapEntries, MemberDef,
    MemberRef, Meta, Notation, Provenance, ProvenanceTable, ScalarDecode, Selector, SourceLoc,
    StaticDef, StaticRole, StaticsTable, Step, Stmt, SymbolLookup, TaskEntryId, TaskFutureEntry,
    TaskTable, TypeDef, TypeTable, ValueExpr, VariantDef, VariantShape, strip_llvm_suffix,
};
pub use shape::{Addressed, Shape};
pub use strings::{StrRef, StringInterner, StringTable};
pub use view::{
    ActiveVariant, BundleMember, BundleMemberIter, BundleType, BundleVariant, BundleView,
    DynPointer, POINTER_SIZE, VariantError, variant_name,
};

#[cfg(test)]
mod tests;

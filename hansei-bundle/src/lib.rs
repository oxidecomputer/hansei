//! The async debug bundle: a serialized description of a debug binary's
//! tokio runtime, keyed by v0 mangled symbol names so a separately-compiled
//! target binary can be interpreted without any address ever crossing
//! between the two.

mod io;
mod schema;
mod shape;
mod strings;
pub mod symbols;
mod view;

pub use io::{Error, FORMAT_VERSION, Result};
pub use schema::{
    Arm, BinaryIdent, BitField, Bundle, BundleTypeId, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode, DynFutureTable, FamilyCeiling, Field, FieldRender, FutureKind, InfraTypes,
    MapEntries, MemberDef, MemberRef, Meta, Notation, Provenance, ProvenanceTable, ScalarDecode,
    Selector, SourceLoc, StaticDef, StaticRole, StaticsTable, Step, Stmt, SymbolLookup,
    TaskEntryId, TaskFutureEntry, TaskTable, TypeDef, TypeTable, ValueExpr, VariantDef,
    VariantShape, WalkBinding, WalkOutcome, WalkRole, WalksTable, strip_build_prefix,
    strip_llvm_suffix,
};
pub use shape::Shape;
pub use strings::{StrRef, StringInterner, StringTable};
pub use view::{
    ActiveVariant, BundleMember, BundleMemberIter, BundleType, BundleVariant, BundleView,
    DynPointer, POINTER_SIZE, TypeClass, TypeKind, VariantError, variant_name,
};

/// The encoding of a `Base` type.
///
/// Serialized directly into bundles (inside [`TypeDef::Base`]), so the
/// bundle format version must be bumped if variants change.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum Encoding {
    /// Linear machine address.
    Address,
    /// True or false.
    Boolean,
    /// A floating-point number.
    Float,
    /// A signed integer.
    Signed,
    /// An unsigned integer.
    Unsigned,
    /// A signed character.
    SignedChar,
    /// An unsigned character.
    UnsignedChar,
    /// A UTF-encoded character. Not necessarily UTF-8.
    UtfChar,
}

#[cfg(test)]
mod tests;

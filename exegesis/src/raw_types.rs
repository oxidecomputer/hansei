use crate::cgu::DwString;
use crate::{Result, Slice, TypeId};

use foldhash::{HashMap, HashMapExt};
use gimli::{Attribute, AttributeValue, DebuggingInformationEntry, UnitRef, UnitSectionOffset};
use tracing::debug;

use std::fmt;
use std::num::NonZero;

/// An index into a [`NamespaceTable`].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NsId(NonZero<u64>);

/// A single namespace entry in a [`NamespaceTable`].
#[derive(Copy, Clone, Debug)]
pub struct NsEntry<S> {
    pub name: S,
    pub parent: Option<NsId>,
    pub depth: u32,
}

/// An arena-based table of interned namespaces.
///
/// Each namespace is stored as an [`NsEntry`] containing a name, optional
/// parent, and depth. Inserting the same `(parent, name)` pair twice returns
/// the same [`NsId`], giving pointer-free deduplication and O(1) equality
/// checks.
///
/// The type parameter `S` represents the string storage: `&str` during
/// parsing, or [`StrId`] in the collector.
#[derive(Debug)]
pub struct NamespaceTable<S> {
    entries: Vec<NsEntry<S>>,
    index: HashMap<(Option<NsId>, S), NsId>,
}

impl<S> Default for NamespaceTable<S> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }
}

impl<S: Copy> NamespaceTable<S> {
    /// Returns the [`NsEntry`] for a given [`NsId`].
    pub fn get(&self, id: NsId) -> NsEntry<S> {
        self.entries[id.0.get() as usize - 1]
    }

    /// Returns the depth of the namespace identified by `id`.
    pub fn depth(&self, id: NsId) -> u32 {
        self.get(id).depth
    }

    /// Iterates over all entries as `(NsId, NsEntry)` pairs, in insertion
    /// order.
    pub fn iter(&self) -> impl Iterator<Item = (NsId, NsEntry<S>)> + '_ {
        self.entries.iter().enumerate().map(|(i, &entry)| {
            let id = NsId(NonZero::new(i as u64 + 1).unwrap());
            (id, entry)
        })
    }
}

impl<S: Copy + Eq + std::hash::Hash> NamespaceTable<S> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a namespace by parent and name.
    pub(crate) fn find(&self, parent: Option<NsId>, name: S) -> Option<NsId> {
        self.index.get(&(parent, name)).copied()
    }

    /// Insert a namespace, returning its [`NsId`]. If the same
    /// `(parent, name)` pair has been inserted before, the existing id is
    /// returned.
    pub fn insert(&mut self, parent: Option<NsId>, name: S) -> NsId {
        if let Some(&id) = self.index.get(&(parent, name)) {
            return id;
        }
        let id = NsId(NonZero::new(self.entries.len() as u64 + 1).unwrap());
        let depth = parent.map_or(1, |p| self.entries[p.0.get() as usize - 1].depth + 1);
        self.entries.push(NsEntry {
            name,
            parent,
            depth,
        });
        self.index.insert((parent, name), id);
        id
    }
}

impl<S: Copy + fmt::Display> NamespaceTable<S> {
    /// Writes the fully-qualified namespace path for `id` to `f`.
    pub fn full_name(&self, id: NsId, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry = self.get(id);
        if let Some(parent) = entry.parent {
            self.full_name(parent, f)?;
        }
        write!(f, "{}::", entry.name)
    }
}

/// A data type defined in the DWARF debug information.
///
/// The type parameter `S` represents the string storage: `&str` for
/// borrowed strings during parsing, or [`StrId`] for interned strings
/// in the collector.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum RawType<S> {
    Base(RawBase<S>),
    Pointer(RawPointer<S>),
    Enum(RawEnum<S>),
    Struct(RawStruct<S>),
    Union(RawUnion<S>),
    Array(RawArray),
}

impl<S: Copy> RawType<S> {
    pub fn name(&self) -> Option<S> {
        match self {
            Self::Base(b) => b.name,
            Self::Pointer(p) => p.name,
            Self::Enum(e) => e.name,
            Self::Struct(s) => s.name,
            Self::Union(u) => u.name,
            Self::Array(_) => None,
        }
    }

    pub fn namespace(&self) -> Option<NsId> {
        match self {
            Self::Base(b) => b.namespace,
            Self::Pointer(_) => None,
            Self::Enum(e) => e.namespace,
            Self::Struct(s) => s.namespace,
            Self::Union(u) => u.namespace,
            Self::Array(_) => None,
        }
    }
}

impl<S> From<RawBase<S>> for RawType<S> {
    fn from(b: RawBase<S>) -> Self {
        Self::Base(b)
    }
}

impl<S> From<RawPointer<S>> for RawType<S> {
    fn from(p: RawPointer<S>) -> Self {
        Self::Pointer(p)
    }
}

impl<S> From<RawEnum<S>> for RawType<S> {
    fn from(e: RawEnum<S>) -> Self {
        Self::Enum(e)
    }
}

impl<S> From<RawStruct<S>> for RawType<S> {
    fn from(s: RawStruct<S>) -> Self {
        Self::Struct(s)
    }
}

impl<S> From<RawUnion<S>> for RawType<S> {
    fn from(u: RawUnion<S>) -> Self {
        Self::Union(u)
    }
}

impl<S> From<RawArray> for RawType<S> {
    fn from(a: RawArray) -> Self {
        Self::Array(a)
    }
}

/// A data type that is not defined in terms of other data types.
/// Section 5.1, page 103.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawBase<S> {
    /// The name of the type as it appears in the source program.
    /// Section 2.15, page 50.
    pub name: Option<S>,
    /// The namespace of the base type.
    pub namespace: Option<NsId>,
    /// The encoding of the `Base` type's value.
    /// Section 5.1.1, page 104.
    pub encoding: Encoding,
    /// The size of the type in bytes.
    /// Section 2.21, page 56.
    pub size: u64,
    /// The alignment requirement of the type, if present.
    /// Section 2.24, page 58.
    pub alignment: Option<NonZero<u64>>,
}

/// A pointer to another type.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawPointer<S> {
    /// Name of the pointer type.
    pub name: Option<S>,
    /// Type targeted by the pointer.
    pub target_type_id: TypeId,
}

/// The encoding of a `Base` type.
/// Section 5.1.1, page 104.
///
/// Also serialized directly into bundles (see [`crate::bundle`]); the
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

/// An enum type: either a Rust-style discriminated union (from
/// `DW_TAG_structure_type` with `DW_TAG_variant_part`) or a C-style
/// enumeration (from `DW_TAG_enumeration_type`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawEnum<S> {
    /// The name of the enum.
    pub name: Option<S>,
    /// The namespace of the Enum.
    pub namespace: Option<NsId>,
    /// The size of the enum in bytes.
    pub size: u64,
    /// The alignment requirement of the type, if present.
    pub alignment: Option<NonZero<u64>>,
    /// The variant layout of the enum.
    pub shape: VariantShape<S>,
    /// Generic type arguments of this instantiation
    /// (`DW_TAG_template_type_parameter` children), in declaration order.
    pub template_params: Box<[RawGenericParameter<S>]>,
    /// Location of the type's declaration in the source.
    pub source_loc: Option<Box<SourceLoc<S>>>,
}

/// The variant layout of an enum.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum VariantShape<S> {
    /// An uninhabited enum (e.g., `enum Void {}`). Zero variants.
    Zero,
    /// A single variant with no discriminant needed.
    One(RawVariant<S>),
    /// Multiple variants distinguished by a discriminant field.
    Many {
        /// The discriminant member, if present. Its offset gives the
        /// discriminant location within the enum (not always 0), and its
        /// `type_id` identifies the discriminant's integer type (e.g., u8,
        /// u64). `None` for niche-optimized enums where the discriminant
        /// is implicit (embedded in the variant data itself).
        discr: Option<RawMember<S>>,
        /// Variants keyed by discriminant value. `None` = default/niche
        /// variant (matched when no explicit value matches). `Some(val)` =
        /// variant selected when the discriminant equals `val`.
        variants: Box<[(Option<u128>, RawVariant<S>)]>,
    },
    /// A C-style enum (`DW_TAG_enumeration_type`): named integer constants
    /// with no variant payloads. The entire enum is the discriminant value.
    CStyle {
        /// The underlying integer representation type (from `DW_AT_type`),
        /// if specified. When absent, the representation is implied by
        /// `size`.
        repr_type_id: Option<TypeId>,
        /// The enumerators: `(name, value)` pairs.
        enumerators: Box<[RawEnumerator<S>]>,
    },
}

/// A single variant of a Rust enum.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawVariant<S> {
    /// The `DW_TAG_member` child of the `DW_TAG_variant`. Its name is the
    /// variant name (e.g., "Some", "None"), its `type_id` points to the
    /// payload type, and its offset is the payload's byte offset within
    /// the enum.
    pub member: RawMember<S>,
}

/// A named constant in a C-style enum (`DW_TAG_enumerator`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawEnumerator<S> {
    /// The enumerator name (e.g., "Red", "Green").
    pub name: S,
    /// The constant value (`DW_AT_const_value`), stored as u128 for
    /// uniformity. Signedness is determined by the enum's underlying type.
    pub value: u128,
}

/// A Rust struct.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawStruct<S> {
    /// The name of the struct.
    pub name: Option<S>,
    /// The namespace of the struct.
    pub namespace: Option<NsId>,
    /// The size of the struct in bytes.
    pub size: u64,
    /// The alignment requirement of the type, if present.
    // pub alignment: Option<NonZero<u64>>,
    /// The members of the struct.
    pub members: Box<[RawMember<S>]>,
    /// Generic type arguments of this instantiation
    /// (`DW_TAG_template_type_parameter` children), in declaration order.
    pub template_params: Box<[RawGenericParameter<S>]>,
    /// Location of the type's declaration in the source.
    pub source_loc: Option<Box<SourceLoc<S>>>,
}

/// A Rust union (`DW_TAG_union_type`), e.g. `MaybeUninit<T>`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawUnion<S> {
    /// The name of the union.
    pub name: Option<S>,
    /// The namespace of the union.
    pub namespace: Option<NsId>,
    /// The size of the union in bytes.
    pub size: u64,
    /// The members of the union. All share offset 0 in practice, but the
    /// DWARF offsets are preserved.
    pub members: Box<[RawMember<S>]>,
    /// Generic type arguments of this instantiation
    /// (`DW_TAG_template_type_parameter` children), in declaration order.
    pub template_params: Box<[RawGenericParameter<S>]>,
    /// Location of the type's declaration in the source.
    pub source_loc: Option<Box<SourceLoc<S>>>,
}

/// A fixed-length array (`DW_TAG_array_type`), e.g. `[u8; 16]`.
///
/// Arrays are anonymous in DWARF; the element type and count are their
/// identity.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawArray {
    /// The element type.
    pub elem_type_id: TypeId,
    /// The number of elements (`DW_AT_count` of the subrange child).
    pub count: u64,
}

/// Information on a type parameter binding for an instance of a generic type.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawGenericParameter<S> {
    /// Name of parameter.
    pub name: Option<S>,
    /// `TypeId` of the parameter.
    pub type_id: TypeId,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawMember<S> {
    /// The name of the member.
    pub name: Option<S>,
    /// The offset of the member in bytes.
    pub offset: u64,
    /// The `TypeId` of the member type.
    pub type_id: TypeId,
    /// Location of the member's declaration in the source. For coroutine
    /// enums the variant members carry the coordinates of the suspend
    /// point — i.e. the awaited expression itself.
    pub source_loc: Option<Box<SourceLoc<S>>>,
}

/// A function or subroutine in a program.
///
/// Note that this is different from `Subroutine`, which defines the _type_ of a
/// function; this defines the _identity_ of a function.
#[derive(Clone, Debug)]
pub struct RawFunc<S> {
    /// Name of the function. Not all functions have names. TODO: why not?
    pub name: Option<S>,
    /// The namespace of the function, if present.
    pub namespace: Option<NsId>,
    /// Location of the declaration of this function in the source.
    pub source_loc: Option<Box<SourceLoc<S>>>,
    /// Type returned by function, or `None` for `()`/`void`.
    pub return_type_id: Option<TypeId>,
    /// Information about parameters needed by this function.
    pub formal_parameters: Box<[RawSubParameter<S>]>,
    /// If this function represents a specialization of another, this provides
    /// a link to the prototype. The prototype may have information that this
    /// record does not, such as a valid name.
    pub abstract_origin: Option<gimli::UnitSectionOffset>,
    /// Actual symbol name used to refer to this function, if it is different
    /// from `name` -- which it tends to be in languages with hierarchical
    /// namespaces.
    pub linkage_name: Option<S>,
    /// Generic type arguments of this instantiation
    /// (`DW_TAG_template_type_parameter` children), in declaration order.
    /// For a monomorphized `poll::<T, S>` these bind `T` and `S` as type
    /// references rather than name strings.
    pub template_params: Box<[RawGenericParameter<S>]>,
    /// If `true`, this function is expected not to return, meaning that any
    /// code after a call to this function is theoretically unreachable.
    ///
    /// In Rust, `noreturn` functions tend to have `!` as their return type.
    pub noreturn: bool,
}

/// Parameter to a function.
///
/// This is more detailed than the `formal_parameters` used for function type
/// definitions.
///
/// Note that it's common for function parameters to be abstract. In that
/// case, most useful content will be missing from `RawSubParameter`, and you'll
/// need to go consult the `abstract_origin`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawSubParameter<S> {
    /// Name of parameter, if available.
    pub name: Option<S>,
    /// Type of the parameter, if available.
    pub type_id: Option<TypeId>,
    /// Reference to a different `RawSubParameter` that this specializes.
    pub abstract_origin: Option<gimli::UnitSectionOffset>,
    /// Fixed value for this parameter. This can happen in cases where a
    /// specialized `Func` fixes one or more parameter values to
    /// constants.
    ///
    /// TODO: type probably needs to be more general.
    pub const_value: Option<u64>,
    /// Location of declaration of this parameter in the source.
    pub source_loc: Option<Box<SourceLoc<S>>>,
}

/// Information about a subroutine that has been inlined into a function.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RawInlinedSubroutine<S> {
    /// Location of the function abstract root that defines this.
    pub abstract_origin: Option<gimli::UnitSectionOffset>,
    /// Ranges of PC values that are included in this inlined subroutine.
    pub pc_ranges: Box<[gimli::Range]>,
    /// Location of the callsite that was inlined.
    pub call_coord: Option<Box<SourceLoc<S>>>,
    /// Further inlined subroutines within this one.
    pub inlines: Box<[RawInlinedSubroutine<S>]>,
    /// Definition of the formal parameters to this inlined subroutine.
    pub formal_parameters: Box<[RawSubParameter<S>]>,
}

/// A static variable with a fixed address.
#[derive(Clone, Debug)]
pub struct RawStaticVariable<S> {
    /// Name of variable.
    pub name: Option<S>,
    /// TODO
    pub namespace: Option<NsId>,
    /// Type contained in variable.
    pub type_id: TypeId,
    /// Address in memory. `None` when the location is not a plain address
    /// (e.g. TLS statics, whose `DW_OP_form_tls_address` locations cannot
    /// be resolved statically) — such variables still matter for their
    /// linkage names.
    pub addr: Option<u64>,
    /// Mangled symbol name (`DW_AT_linkage_name`), when present.
    pub linkage_name: Option<S>,
    /// Location of variable declaration in the source code.
    pub source_loc: SourceLoc<S>,
}

/// Attributes common to most type DIEs.
pub(crate) struct CommonAttrs<'dw> {
    pub name: Option<&'dw str>,
    pub size: Option<u64>,
    pub alignment: Option<NonZero<u64>>,
    pub type_id: Option<UnitSectionOffset>,
    pub is_decl: bool,
    pub debug_offset: UnitSectionOffset,
    pub source_loc: SourceLoc<&'dw str>,
}

impl<'dw> CommonAttrs<'dw> {
    /// Parse common attributes from a DIE, forwarding unrecognized
    /// attributes to `other_attr` for type-specific handling.
    pub fn from_entry(
        unit: &UnitRef<Slice<'dw>>,
        entry: &DebuggingInformationEntry<Slice<'dw>>,
        mut other_attr: impl FnMut(&Attribute<Slice<'dw>>) -> Result<()>,
    ) -> Result<Self> {
        let mut name = None;
        let mut size = None;
        let mut alignment = None;
        let mut type_id = None;
        let mut is_decl = false;
        let mut source_loc = SourceLoc::default();
        let offset = entry.offset().to_unit_section_offset(unit);

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::DW_AT_name => {
                    name = Some(attr.attr_str(unit)?);
                }
                gimli::DW_AT_byte_size => {
                    size = attr.value().udata_value();
                }
                gimli::DW_AT_alignment => {
                    alignment = attr.value().udata_value().and_then(NonZero::new);
                }
                gimli::DW_AT_type => match attr.value() {
                    AttributeValue::UnitRef(o) => type_id = Some(o.to_unit_section_offset(unit)),
                    AttributeValue::DebugInfoRef(o) => type_id = Some(o.into()),
                    _ => panic!("unexpected type type: {:?}", attr.value()),
                },
                gimli::DW_AT_declaration => is_decl = true,
                gimli::DW_AT_decl_file => {
                    let AttributeValue::FileIndex(f) = attr.value() else {
                        debug!("unexpected decl_file type: {:?}", attr.value());
                        continue;
                    };

                    let Some(lp) = &unit.line_program else {
                        continue;
                    };

                    let Some(fent) = lp.header().file(f) else {
                        debug!(file_index = f, "invalid decl_file file index");
                        continue;
                    };

                    let raw = unit.dwarf.attr_string(unit.unit, fent.path_name())?;
                    source_loc.file = str::from_utf8(raw.slice()).ok();

                    if let Some(dv) = fent.directory(lp.header()) {
                        let raw_dir = unit.dwarf.attr_string(unit.unit, dv)?;
                        source_loc.dir = str::from_utf8(raw_dir.slice()).ok();
                    }
                }
                gimli::DW_AT_decl_line => {
                    source_loc.line = NonZero::new(attr.value().udata_value().unwrap());
                }
                gimli::DW_AT_decl_column => {
                    source_loc.column = NonZero::new(attr.value().udata_value().unwrap());
                }
                _ => other_attr(&attr)?,
            }
        }

        Ok(Self {
            name,
            size,
            alignment,
            type_id,
            is_decl,
            source_loc,
            debug_offset: offset,
        })
    }
}

/// Location in a source file for a type. Lines and columns are 1-indexed.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct SourceLoc<S> {
    /// Name of source file, if available.
    pub file: Option<S>,
    /// Directory of source file, if available.
    pub dir: Option<S>,
    /// Line number, if available.
    pub line: Option<NonZero<u64>>,
    /// Column number, if available.
    pub column: Option<NonZero<u64>>,
}

impl<S> Default for SourceLoc<S> {
    fn default() -> Self {
        Self {
            file: None,
            dir: None,
            line: None,
            column: None,
        }
    }
}

impl<S> SourceLoc<S> {
    /// Returns `true` if none of the `SourceLoc`'s fields are populated.
    pub fn is_empty(&self) -> bool {
        let Self {
            file,
            dir,
            line,
            column,
        } = self;
        file.is_none() && dir.is_none() && line.is_none() && column.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DwReader;
    use crate::Type;
    use crate::TypeKind;

    #[test]
    fn test_namespace_table_depth() {
        let mut table = NamespaceTable::<&str>::new();

        let root = table.insert(None, "root");
        assert_eq!(table.depth(root), 1);

        let child = table.insert(Some(root), "child");
        assert_eq!(table.depth(child), 2);

        let grandchild = table.insert(Some(child), "grandchild");
        assert_eq!(table.depth(grandchild), 3);

        // Deduplication preserves depth.
        let child_again = table.insert(Some(root), "child");
        assert_eq!(child, child_again);
        assert_eq!(table.depth(child_again), 2);
    }

    #[test]
    fn test_namespace_depth_from_dwarf() {
        let td = crate::testhelper::get_test_dwarf();
        let dwarf = td.dwarf();
        let types = DwReader::read_types(&dwarf, Default::default()).unwrap();
        let view = types.view();

        // testlib::qux::Foo<u64> lives in namespace testlib::qux (depth 2).
        let foo = view
            .find("testlib::qux::Foo<u64>", TypeKind::Struct)
            .expect("Foo<u64> should exist");
        let Type::Struct(s) = foo else {
            panic!("expected struct");
        };
        let ns = s.namespace().expect("Foo should have a namespace");
        assert_eq!(ns.full_name(), "testlib::qux");
        assert_eq!(ns.depth(), 2);

        // Walking to parent gives depth 1.
        let parent = ns.parent().expect("qux should have a parent");
        assert_eq!(parent.full_name(), "testlib");
        assert_eq!(parent.depth(), 1);

        // Root namespace has no parent.
        assert!(parent.parent().is_none());
    }
}

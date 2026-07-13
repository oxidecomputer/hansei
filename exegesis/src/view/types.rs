use crate::raw_types::{
    Encoding, NsId, RawBase, RawEnum, RawEnumerator, RawMember, RawPointer, RawStaticVariable,
    RawStruct, RawSubParameter, RawFunc, RawType, RawVariant, VariantShape,
};
use crate::reader::DwReader;
use crate::string_table::StrId;
use crate::{FuncId, TypeId, TypeKind, VarId};

use std::fmt;
use std::num::NonZero;

/// DWARF type data with strings resolved on demand.
///
/// This wraps [`RawType`] variants and provides method-based access
/// that automatically resolves [`StrId`] to `&str` via the collector's
/// string table.
#[derive(Copy, Clone)]
pub enum Type<'a> {
    Base(Base<'a>),
    Pointer(Pointer<'a>),
    Enum(Enum<'a>),
    Struct(Struct<'a>),
}

impl<'a> Type<'a> {
    /// Create a `Type` from a `RawType`.
    pub fn from_raw(raw: &'a RawType<StrId>, collector: &'a DwReader<'a>) -> Self {
        match raw {
            RawType::Base(inner) => Type::Base(Base {
                raw: inner,
                collector,
            }),
            RawType::Pointer(inner) => Type::Pointer(Pointer {
                raw: inner,
                collector,
            }),
            RawType::Enum(inner) => Type::Enum(Enum {
                raw: inner,
                collector,
            }),
            RawType::Struct(inner) => Type::Struct(Struct {
                raw: inner,
                collector,
            }),
        }
    }

    /// Returns the type's kind.
    pub fn kind(&self) -> TypeKind {
        match self {
            Type::Base(_) => TypeKind::Base,
            Type::Pointer(_) => TypeKind::Pointer,
            Type::Enum(_) => TypeKind::Enum,
            Type::Struct(_) => TypeKind::Struct,
        }
    }

    /// Returns the raw namespace ID, if any.
    pub(crate) fn namespace_id(&self) -> Option<NsId> {
        match self {
            Type::Base(t) => t.raw.namespace,
            Type::Pointer(_) => None,
            Type::Enum(t) => t.raw.namespace,
            Type::Struct(t) => t.raw.namespace,
        }
    }

    /// Returns the type's name, or `None` for anonymous types.
    pub fn name(&self) -> Option<&'a str> {
        match self {
            Type::Base(t) => t.name(),
            Type::Pointer(t) => t.name(),
            Type::Enum(t) => t.name(),
            Type::Struct(t) => t.name(),
        }
    }

    /// Returns an iterator over the type's members, if present.
    pub fn members(&'a self) -> MemberIter<'a> {
        match self {
            Type::Struct(t) => t.members(),
            _ => MemberIter {
                members: &[],
                index: 0,
                collector: self.collector(),
            },
        }
    }

    pub fn as_base(&self) -> Option<Base<'a>> {
        match self {
            Type::Base(t) => Some(*t),
            _ => None,
        }
    }

    pub fn as_pointer(&self) -> Option<Pointer<'a>> {
        match self {
            Type::Pointer(t) => Some(*t),
            _ => None,
        }
    }

    pub fn as_enum(&self) -> Option<Enum<'a>> {
        match self {
            Type::Enum(t) => Some(*t),
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<Struct<'a>> {
        match self {
            Type::Struct(t) => Some(*t),
            _ => None,
        }
    }

    fn collector(&self) -> &DwReader<'a> {
        match self {
            Self::Base(b) => b.collector,
            Self::Pointer(p) => p.collector,
            Self::Enum(e) => e.collector,
            Self::Struct(s) => s.collector,
        }
    }
}

impl fmt::Debug for Type<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Base(t) => fmt::Debug::fmt(t, f),
            Type::Pointer(t) => fmt::Debug::fmt(t, f),
            Type::Enum(t) => fmt::Debug::fmt(t, f),
            Type::Struct(t) => fmt::Debug::fmt(t, f),
        }
    }
}

// --- Base ---

#[derive(Copy, Clone)]
pub struct Base<'a> {
    raw: &'a RawBase<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Base<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn namespace(&self) -> Option<Namespace<'a>> {
        self.raw
            .namespace
            .map(|id| Namespace::new(id, self.collector))
    }

    pub fn encoding(&self) -> Encoding {
        self.raw.encoding
    }

    pub fn size(&self) -> u64 {
        self.raw.size
    }

    pub fn alignment(&self) -> Option<NonZero<u64>> {
        self.raw.alignment
    }

    pub fn raw(&self) -> &RawBase<StrId> {
        self.raw
    }
}

impl<'a> From<Base<'a>> for Type<'a> {
    fn from(val: Base<'a>) -> Self {
        Type::Base(val)
    }
}

impl fmt::Debug for Base<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Base")
            .field("name", &self.name())
            .field("encoding", &self.encoding())
            .field("size", &self.size())
            .finish()
    }
}

// --- Pointer ---

#[derive(Copy, Clone)]
pub struct Pointer<'a> {
    raw: &'a RawPointer<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Pointer<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    /// Returns the type this pointer points to.
    pub fn target(&self) -> Type<'a> {
        let canonical_id = self.collector.canonicalize(self.raw.target_type_id);
        let raw = self
            .collector
            .types
            .get(&canonical_id)
            .expect("pointer target TypeId not found in collector");
        Type::from_raw(raw, self.collector)
    }

    pub fn target_type_id(&self) -> TypeId {
        self.raw.target_type_id
    }

    pub fn raw(&self) -> &RawPointer<StrId> {
        self.raw
    }
}

impl<'a> From<Pointer<'a>> for Type<'a> {
    fn from(val: Pointer<'a>) -> Self {
        Type::Pointer(val)
    }
}

impl fmt::Debug for Pointer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pointer")
            .field("name", &self.name())
            .field("target_type_id", &self.target_type_id())
            .finish()
    }
}

// --- Enum ---

#[derive(Copy, Clone)]
pub struct Enum<'a> {
    raw: &'a RawEnum<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Enum<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn namespace(&self) -> Option<Namespace<'a>> {
        self.raw
            .namespace
            .map(|id| Namespace::new(id, self.collector))
    }

    pub fn size(&self) -> u64 {
        self.raw.size
    }

    pub fn alignment(&self) -> Option<NonZero<u64>> {
        self.raw.alignment
    }

    /// Returns the variant shape of this enum.
    pub fn shape(&self) -> VariantShapeView<'a> {
        match &self.raw.shape {
            VariantShape::Zero => VariantShapeView::Zero,
            VariantShape::One(v) => VariantShapeView::One(Variant {
                raw: v,
                collector: self.collector,
            }),
            VariantShape::Many { discr, variants } => VariantShapeView::Many {
                discr: discr.as_ref().map(|d| Member {
                    raw: d,
                    collector: self.collector,
                }),
                variants: VariantIter {
                    entries: variants,
                    index: 0,
                    collector: self.collector,
                },
            },
            VariantShape::CStyle {
                repr_type_id,
                enumerators,
            } => VariantShapeView::CStyle {
                repr_type_id: repr_type_id.map(|id| {
                    let canonical_id = self.collector.canonicalize(id);
                    let raw = self
                        .collector
                        .types
                        .get(&canonical_id)
                        .expect("repr type TypeId not found in collector");
                    Type::from_raw(raw, self.collector)
                }),
                enumerators: EnumeratorIter {
                    entries: enumerators,
                    index: 0,
                    collector: self.collector,
                },
            },
        }
    }

    /// Returns the number of variants/enumerators.
    pub fn variant_count(&self) -> usize {
        match &self.raw.shape {
            VariantShape::Zero => 0,
            VariantShape::One(_) => 1,
            VariantShape::Many { variants, .. } => variants.len(),
            VariantShape::CStyle { enumerators, .. } => enumerators.len(),
        }
    }

    /// Returns the discriminant member, if this is a Many-variant enum
    /// with an explicit discriminant. Returns `None` for niche-optimized
    /// enums and non-Many shapes.
    pub fn discriminant(&self) -> Option<Member<'a>> {
        match &self.raw.shape {
            VariantShape::Many {
                discr: Some(discr), ..
            } => Some(Member {
                raw: discr,
                collector: self.collector,
            }),
            _ => None,
        }
    }

    pub fn raw(&self) -> &RawEnum<StrId> {
        self.raw
    }
}

impl<'a> From<Enum<'a>> for Type<'a> {
    fn from(val: Enum<'a>) -> Self {
        Type::Enum(val)
    }
}

impl fmt::Debug for Enum<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enum")
            .field("name", &self.name())
            .field("size", &self.size())
            .field("variant_count", &self.variant_count())
            .finish()
    }
}

// --- VariantShapeView ---

/// View into an enum's variant layout.
pub enum VariantShapeView<'a> {
    /// Uninhabited enum (zero variants).
    Zero,
    /// Single variant, no discriminant.
    One(Variant<'a>),
    /// Multiple variants with a discriminant field.
    Many {
        /// The discriminant member, or `None` for niche-optimized enums.
        discr: Option<Member<'a>>,
        /// Iterator over the variants.
        variants: VariantIter<'a>,
    },
    /// C-style enum: named integer constants with no payloads.
    CStyle {
        /// The underlying integer representation type, if specified.
        repr_type_id: Option<Type<'a>>,
        /// Iterator over the enumerators.
        enumerators: EnumeratorIter<'a>,
    },
}

// --- Enumerator ---

/// A named constant in a C-style enum.
#[derive(Copy, Clone)]
pub struct Enumerator<'a> {
    raw: &'a RawEnumerator<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Enumerator<'a> {
    /// Returns the enumerator name (e.g., "Red", "Green").
    pub fn name(&self) -> &'a str {
        self.collector.strings.get(self.raw.name)
    }

    /// Returns the constant value.
    pub fn value(&self) -> u128 {
        self.raw.value
    }

    pub fn raw(&self) -> &RawEnumerator<StrId> {
        self.raw
    }
}

impl fmt::Debug for Enumerator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enumerator")
            .field("name", &self.name())
            .field("value", &self.value())
            .finish()
    }
}

// --- EnumeratorIter ---

/// Iterator over enumerators in a C-style enum.
#[derive(Clone)]
pub struct EnumeratorIter<'a> {
    entries: &'a [RawEnumerator<StrId>],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for EnumeratorIter<'a> {
    type Item = Enumerator<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.entries.get(self.index)?;
        self.index += 1;
        Some(Enumerator {
            raw,
            collector: self.collector,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.entries.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EnumeratorIter<'_> {}

impl fmt::Debug for EnumeratorIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnumeratorIter")
            .field("remaining", &(self.entries.len() - self.index))
            .finish()
    }
}

// --- Variant ---

/// A single variant of a Rust enum.
#[derive(Copy, Clone)]
pub struct Variant<'a> {
    raw: &'a RawVariant<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Variant<'a> {
    /// Returns the variant name (e.g., "Some", "None", "Red").
    pub fn name(&self) -> Option<&'a str> {
        self.raw
            .member
            .name
            .map(|id| self.collector.strings.get(id))
    }

    /// Returns the payload member of this variant.
    pub fn member(&self) -> Member<'a> {
        Member {
            raw: &self.raw.member,
            collector: self.collector,
        }
    }

    /// Shortcut: returns the payload type of this variant.
    pub fn ty(&self) -> Type<'a> {
        self.member().ty()
    }

    pub fn raw(&self) -> &RawVariant<StrId> {
        self.raw
    }
}

impl fmt::Debug for Variant<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Variant")
            .field("name", &self.name())
            .field("type_id", &self.raw.member.type_id)
            .finish()
    }
}

// --- VariantIter ---

/// Iterator over `(discriminant_value, Variant)` pairs.
#[derive(Clone)]
pub struct VariantIter<'a> {
    entries: &'a [(Option<u128>, RawVariant<StrId>)],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for VariantIter<'a> {
    type Item = (Option<u128>, Variant<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let (dv, raw) = self.entries.get(self.index)?;
        self.index += 1;
        Some((
            *dv,
            Variant {
                raw,
                collector: self.collector,
            },
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.entries.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for VariantIter<'_> {}

impl fmt::Debug for VariantIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VariantIter")
            .field("remaining", &(self.entries.len() - self.index))
            .finish()
    }
}

// --- Struct ---

#[derive(Copy, Clone)]
pub struct Struct<'a> {
    raw: &'a RawStruct<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Struct<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn namespace(&self) -> Option<Namespace<'a>> {
        self.raw
            .namespace
            .map(|id| Namespace::new(id, self.collector))
    }

    pub fn size(&self) -> u64 {
        self.raw.size
    }

    pub fn member_count(&self) -> usize {
        self.raw.members.len()
    }

    /// Return an iterator over members.
    pub fn members(&self) -> MemberIter<'a> {
        MemberIter {
            members: &self.raw.members,
            index: 0,
            collector: self.collector,
        }
    }

    /// Find a member by name.
    pub fn member(&self, name: &str) -> Option<Member<'a>> {
        self.raw
            .members
            .iter()
            .find(|m| m.name.map(|id| self.collector.strings.get(id)) == Some(name))
            .map(|m| Member {
                raw: m,
                collector: self.collector,
            })
    }

    pub fn raw(&self) -> &RawStruct<StrId> {
        self.raw
    }
}

impl<'a> From<Struct<'a>> for Type<'a> {
    fn from(val: Struct<'a>) -> Self {
        Type::Struct(val)
    }
}

impl fmt::Debug for Struct<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Struct")
            .field("name", &self.name())
            .field("size", &self.size())
            .field("member_count", &self.member_count())
            .finish()
    }
}

// --- Member ---

#[derive(Copy, Clone)]
pub struct Member<'a> {
    raw: &'a RawMember<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Member<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    /// Returns the type of this member.
    pub fn ty(&self) -> Type<'a> {
        let canonical_id = self.collector.canonicalize(self.raw.type_id);
        let raw = self
            .collector
            .types
            .get(&canonical_id)
            .expect("member type TypeId not found in collector");
        Type::from_raw(raw, self.collector)
    }

    pub fn type_id(&self) -> TypeId {
        self.raw.type_id
    }

    pub fn offset(&self) -> u64 {
        self.raw.offset
    }

    pub fn raw(&self) -> &RawMember<StrId> {
        self.raw
    }
}

impl fmt::Debug for Member<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("name", &self.name())
            .field("type_id", &self.type_id())
            .field("offset", &self.offset())
            .finish()
    }
}

// --- Namespace ---

#[derive(Copy, Clone)]
pub struct Namespace<'a> {
    id: NsId,
    collector: &'a DwReader<'a>,
}

impl<'a> Namespace<'a> {
    pub(crate) fn new(id: NsId, collector: &'a DwReader<'a>) -> Self {
        Self { id, collector }
    }

    /// Returns the [`NsId`] of this namespace.
    pub fn id(&self) -> NsId {
        self.id
    }

    /// Returns the direct name of this namespace segment.
    pub fn name(&self) -> &'a str {
        let entry = self.collector.namespaces.get(self.id);
        self.collector.strings.get(entry.name)
    }

    /// Returns the parent namespace, if any.
    pub fn parent(&self) -> Option<Namespace<'a>> {
        let entry = self.collector.namespaces.get(self.id);
        entry.parent.map(|id| Namespace {
            id,
            collector: self.collector,
        })
    }

    /// Returns the depth of this namespace (1 for a root namespace).
    pub fn depth(&self) -> u32 {
        self.collector.namespaces.depth(self.id)
    }

    /// Builds the fully-qualified namespace path, e.g. `"foo::bar::baz"`.
    pub fn full_name(&self) -> String {
        let depth = self.collector.namespaces.depth(self.id);
        let mut segments = Vec::with_capacity(depth as usize);
        let mut current = Some(*self);
        while let Some(ns) = current {
            segments.push(ns.name());
            current = ns.parent();
        }
        segments.reverse();
        segments.join("::")
    }
}

impl fmt::Debug for Namespace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Namespace")
            .field("id", &self.id)
            .field("name", &self.name())
            .field("full_name", &self.full_name())
            .finish()
    }
}

// --- MemberIter ---

#[derive(Clone, Debug)]
pub struct MemberIter<'a> {
    members: &'a [RawMember<StrId>],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for MemberIter<'a> {
    type Item = Member<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let member = self.members.get(self.index)?;
        self.index += 1;
        Some(Member {
            raw: member,
            collector: self.collector,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.members.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for MemberIter<'_> {}

// --- NsTypeIter ---

/// Iterator over canonical types within a namespace.
#[derive(Clone, Debug)]
pub struct NsTypeIter<'a> {
    ids: &'a [TypeId],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for NsTypeIter<'a> {
    type Item = Type<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let &id = self.ids.get(self.index)?;
        self.index += 1;
        let raw = self
            .collector
            .types
            .get(&id)
            .expect("indexed TypeId not in collector");
        Some(Type::from_raw(raw, self.collector))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.ids.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for NsTypeIter<'_> {}

// --- NsVarIter ---

/// Iterator over static variables within a namespace.
#[derive(Clone, Debug)]
pub struct NsVarIter<'a> {
    ids: &'a [VarId],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for NsVarIter<'a> {
    type Item = StaticVariable<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let &id = self.ids.get(self.index)?;
        self.index += 1;
        let raw = self
            .collector
            .variables
            .get(&id)
            .expect("indexed VarId not in collector");
        Some(StaticVariable::new(raw, self.collector))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.ids.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for NsVarIter<'_> {}

// --- NsFuncIter ---

/// Iterator over functions within a namespace.
#[derive(Clone, Debug)]
pub struct NsFuncIter<'a> {
    ids: &'a [FuncId],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for NsFuncIter<'a> {
    type Item = Func<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let &id = self.ids.get(self.index)?;
        self.index += 1;
        let raw = self
            .collector
            .functions
            .get(&id)
            .expect("indexed FuncId not in collector");
        Some(Func::new(raw, self.collector))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.ids.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for NsFuncIter<'_> {}

// --- StaticVariable ---

#[derive(Copy, Clone)]
pub struct StaticVariable<'a> {
    raw: &'a RawStaticVariable<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> StaticVariable<'a> {
    pub(crate) fn new(raw: &'a RawStaticVariable<StrId>, collector: &'a DwReader<'a>) -> Self {
        Self { raw, collector }
    }

    pub(crate) fn namespace_id(&self) -> Option<NsId> {
        self.raw.namespace
    }

    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn namespace(&self) -> Option<Namespace<'a>> {
        self.raw
            .namespace
            .map(|id| Namespace::new(id, self.collector))
    }

    /// Returns the type of this variable.
    pub fn ty(&self) -> Type<'a> {
        let canonical_id = self.collector.canonicalize(self.raw.type_id);
        let raw = self
            .collector
            .types
            .get(&canonical_id)
            .expect("variable type TypeId not found in collector");
        Type::from_raw(raw, self.collector)
    }

    pub fn type_id(&self) -> TypeId {
        self.raw.type_id
    }

    pub fn addr(&self) -> u64 {
        self.raw.addr
    }

    pub fn raw(&self) -> &RawStaticVariable<StrId> {
        self.raw
    }
}

impl fmt::Debug for StaticVariable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticVariable")
            .field("name", &self.name())
            .field("type_id", &self.type_id())
            .field("type_name", &self.ty().name())
            .field("addr", &format_args!("{:#x}", self.addr()))
            .finish()
    }
}

// --- Func ---

#[derive(Copy, Clone)]
pub struct Func<'a> {
    raw: &'a RawFunc<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Func<'a> {
    pub(crate) fn new(raw: &'a RawFunc<StrId>, collector: &'a DwReader<'a>) -> Self {
        Self { raw, collector }
    }

    pub(crate) fn namespace_id(&self) -> Option<NsId> {
        self.raw.namespace
    }

    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    pub fn namespace(&self) -> Option<Namespace<'a>> {
        self.raw
            .namespace
            .map(|id| Namespace::new(id, self.collector))
    }

    pub fn linkage_name(&self) -> Option<&'a str> {
        self.raw
            .linkage_name
            .map(|id| self.collector.strings.get(id))
    }

    /// Returns the return type, or `None` for `()`/`void`.
    pub fn return_type(&self) -> Option<Type<'a>> {
        self.raw.return_type_id.map(|id| {
            let canonical_id = self.collector.canonicalize(id);
            let raw = self
                .collector
                .types
                .get(&canonical_id)
                .expect("function return type TypeId not found in collector");
            Type::from_raw(raw, self.collector)
        })
    }

    /// Return an iterator over formal parameters.
    pub fn params(&self) -> ParamIter<'a> {
        ParamIter {
            params: &self.raw.formal_parameters,
            index: 0,
            collector: self.collector,
        }
    }

    pub fn noreturn(&self) -> bool {
        self.raw.noreturn
    }

    pub fn raw(&self) -> &RawFunc<StrId> {
        self.raw
    }
}

impl fmt::Debug for Func<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Func")
            .field("name", &self.name())
            .field("linkage_name", &self.linkage_name())
            .field("noreturn", &self.noreturn())
            .finish()
    }
}

// --- Param ---

#[derive(Copy, Clone)]
pub struct Param<'a> {
    raw: &'a RawSubParameter<StrId>,
    collector: &'a DwReader<'a>,
}

impl<'a> Param<'a> {
    pub fn name(&self) -> Option<&'a str> {
        self.raw.name.map(|id| self.collector.strings.get(id))
    }

    /// Returns the type of this parameter, if available.
    pub fn ty(&self) -> Option<Type<'a>> {
        self.raw.type_id.map(|id| {
            let canonical_id = self.collector.canonicalize(id);
            let raw = self
                .collector
                .types
                .get(&canonical_id)
                .expect("parameter type TypeId not found in collector");
            Type::from_raw(raw, self.collector)
        })
    }

    pub fn raw(&self) -> &RawSubParameter<StrId> {
        self.raw
    }
}

impl fmt::Debug for Param<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Param").field("name", &self.name()).finish()
    }
}

// --- ParamIter ---

#[derive(Clone, Debug)]
pub struct ParamIter<'a> {
    params: &'a [RawSubParameter<StrId>],
    index: usize,
    collector: &'a DwReader<'a>,
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = Param<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let param = self.params.get(self.index)?;
        self.index += 1;
        Some(Param {
            raw: param,
            collector: self.collector,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.params.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ParamIter<'_> {}

#[cfg(test)]
mod tests {
    use crate::raw_types::Encoding;
    use crate::reader::DwReader;
    use crate::{TypeKind, testhelper};

    /// Set up the view test fixture. Object bytes are cached across calls;
    /// only DWARF parsing and collection run per test.
    fn setup() -> (testhelper::TestDwarf,) {
        (testhelper::get_test_dwarf(),)
    }

    macro_rules! with_view {
        ($view:ident => $body:block) => {{
            let (td,) = setup();
            let dwarf = td.dwarf();
            let collector = DwReader::read_types(&dwarf, Default::default()).unwrap();
            let $view = collector.view();
            $body
        }};
    }

    // ---- A. Base types & encoding ----

    #[test]
    fn test_base_type_bool() {
        with_view!(view => {
            let ty = view.find("bool", TypeKind::Base).expect("bool not found");
            let base = ty.as_base().expect("expected Base");
            assert_eq!(base.encoding(), Encoding::Boolean);
            assert_eq!(base.size(), 1);
            assert_eq!(base.name(), Some("bool"));
        });
    }

    #[test]
    fn test_base_type_unsigned() {
        with_view!(view => {
            let ty = view.find("u32", TypeKind::Base).expect("u32 not found");
            let base = ty.as_base().unwrap();
            assert_eq!(base.encoding(), Encoding::Unsigned);
            assert_eq!(base.size(), 4);
        });
    }

    #[test]
    fn test_base_type_signed() {
        with_view!(view => {
            let ty = view.find("i32", TypeKind::Base).expect("i32 not found");
            let base = ty.as_base().unwrap();
            assert_eq!(base.encoding(), Encoding::Signed);
            assert_eq!(base.size(), 4);
        });
    }

    #[test]
    fn test_base_type_float() {
        with_view!(view => {
            let ty = view.find("f64", TypeKind::Base).expect("f64 not found");
            let base = ty.as_base().unwrap();
            assert_eq!(base.encoding(), Encoding::Float);
            assert_eq!(base.size(), 8);
        });
    }

    #[test]
    fn test_base_type_u8() {
        with_view!(view => {
            let ty = view.find("u8", TypeKind::Base).expect("u8 not found");
            let base = ty.as_base().unwrap();
            assert_eq!(base.encoding(), Encoding::Unsigned);
            assert_eq!(base.size(), 1);
        });
    }

    // ---- B. Type enum & kind dispatch ----

    #[test]
    fn test_type_kind() {
        with_view!(view => {
            let base = view.find("u32", TypeKind::Base).unwrap();
            assert_eq!(base.kind(), TypeKind::Base);

            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap();
            assert_eq!(s.kind(), TypeKind::Struct);
        });
    }

    #[test]
    fn test_type_as_conversions() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap();
            assert!(s.as_struct().is_some());
            assert!(s.as_base().is_none());
            assert!(s.as_pointer().is_none());
            assert!(s.as_enum().is_none());
        });
    }

    #[test]
    fn test_type_name() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap();
            assert_eq!(s.name(), Some("Point"));
        });
    }

    #[test]
    fn test_type_members_empty_for_non_struct() {
        with_view!(view => {
            let base = view.find("u32", TypeKind::Base).unwrap();
            assert_eq!(base.members().len(), 0);
        });
    }

    // ---- C. Struct & Member ----

    #[test]
    fn test_struct_properties() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            assert_eq!(s.name(), Some("Point"));
            assert_eq!(s.size(), 8); // repr(C): two i32s
            assert_eq!(s.member_count(), 2);
        });
    }

    #[test]
    fn test_struct_member_by_name() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();

            let x = s.member("x").expect("member x not found");
            assert_eq!(x.name(), Some("x"));
            assert_eq!(x.offset(), 0);

            let y = s.member("y").expect("member y not found");
            assert_eq!(y.name(), Some("y"));
            assert_eq!(y.offset(), 4);

            assert!(s.member("nonexistent").is_none());
        });
    }

    #[test]
    fn test_struct_member_type_resolution() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Mixed", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();

            let count = s.member("count").unwrap();
            let ty = count.ty();
            assert_eq!(ty.kind(), TypeKind::Base);
            assert_eq!(ty.name(), Some("u32"));
        });
    }

    #[test]
    fn test_struct_member_offsets_repr_c() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Mixed", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();

            // #[repr(C)] layout: bool(1) pad(3) u32(4) f64(8) u8(1) pad(7) = 24
            let flag = s.member("flag").unwrap();
            assert_eq!(flag.offset(), 0);

            let count = s.member("count").unwrap();
            assert_eq!(count.offset(), 4);

            let value = s.member("value").unwrap();
            assert_eq!(value.offset(), 8);

            let letter = s.member("letter").unwrap();
            assert_eq!(letter.offset(), 16);
        });
    }

    #[test]
    fn test_struct_empty() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Empty", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            assert_eq!(s.member_count(), 0);
            assert_eq!(s.members().len(), 0);
            assert_eq!(s.size(), 0);
        });
    }

    #[test]
    fn test_struct_namespace() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let ns = s.namespace().expect("Point should have a namespace");
            assert_eq!(ns.full_name(), "testlib::shapes");
            assert_eq!(ns.depth(), 2);
        });
    }

    // ---- D. MemberIter ----

    #[test]
    fn test_member_iter_exact_size() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let mut iter = s.members();
            assert_eq!(iter.len(), 2);
            iter.next();
            assert_eq!(iter.len(), 1);
            iter.next();
            assert_eq!(iter.len(), 0);
            assert!(iter.next().is_none());
        });
    }

    #[test]
    fn test_member_iter_collects_all() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Mixed", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let members: Vec<_> = s.members().collect();
            assert_eq!(members.len(), s.member_count());
            let names: Vec<_> = members.iter().filter_map(|m| m.name()).collect();
            assert!(names.contains(&"flag"));
            assert!(names.contains(&"count"));
            assert!(names.contains(&"value"));
            assert!(names.contains(&"letter"));
        });
    }

    // ---- E. Pointer ----

    #[test]
    fn test_pointer_target_resolution() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Wrapper", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let inner = s.member("inner").expect("inner member not found");
            let ptr_ty = inner.ty();
            assert_eq!(ptr_ty.kind(), TypeKind::Pointer);

            let ptr = ptr_ty.as_pointer().unwrap();
            let target = ptr.target();
            assert_eq!(target.kind(), TypeKind::Struct);
            assert_eq!(target.name(), Some("Point"));
        });
    }

    #[test]
    fn test_pointer_has_name() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Wrapper", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let inner = s.member("inner").unwrap();
            let ptr = inner.ty().as_pointer().unwrap();
            // Rust emits DW_AT_name for pointer types (e.g. "*const Point").
            let name = ptr.name().expect("Rust pointer types have names");
            assert!(
                name.contains("Point"),
                "pointer name {name:?} should reference Point"
            );
        });
    }

    // ---- F. Namespace ----

    #[test]
    fn test_namespace_depth_and_parent_chain() {
        with_view!(view => {
            let s = view
                .find("testlib::outer::inner::Deep", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let ns = s.namespace().expect("Deep should have a namespace");
            assert_eq!(ns.full_name(), "testlib::outer::inner");
            assert_eq!(ns.depth(), 3);

            // Walk parent chain.
            let outer = ns.parent().expect("inner should have parent");
            assert_eq!(outer.name(), "outer");
            assert_eq!(outer.depth(), 2);

            let root = outer.parent().expect("outer should have parent");
            assert_eq!(root.name(), "testlib");
            assert_eq!(root.depth(), 1);

            assert!(root.parent().is_none());
        });
    }

    #[test]
    fn test_namespace_full_name() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let ns = s.namespace().unwrap();
            assert_eq!(ns.full_name(), "testlib::shapes");
        });
    }

    #[test]
    fn test_namespace_root_has_no_parent() {
        with_view!(view => {
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let ns = s.namespace().unwrap();
            let root = ns.parent().unwrap(); // "testlib"
            assert!(root.parent().is_none());
        });
    }

    // ---- G. StaticVariable ----

    #[test]
    fn test_static_variable_properties() {
        with_view!(view => {
            let v = view
                .find_var("testlib::shapes::GLOBAL_COUNT")
                .expect("GLOBAL_COUNT not found");
            assert_eq!(v.name(), Some("GLOBAL_COUNT"));
        });
    }

    #[test]
    fn test_static_variable_type() {
        with_view!(view => {
            let v = view
                .find_var("testlib::shapes::GLOBAL_COUNT")
                .unwrap();
            let ty = v.ty();
            assert_eq!(ty.kind(), TypeKind::Base);
            assert_eq!(ty.name(), Some("u32"));
        });
    }

    #[test]
    fn test_static_variable_namespace() {
        with_view!(view => {
            let v = view
                .find_var("testlib::shapes::GLOBAL_COUNT")
                .unwrap();
            let ns = v.namespace().expect("GLOBAL_COUNT should have namespace");
            assert_eq!(ns.full_name(), "testlib::shapes");
        });
    }

    // ---- H. Func & Param ----

    #[test]
    fn test_function_basic() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::add_points")
                .expect("add_points not found");
            assert_eq!(f.name(), Some("add_points"));
            assert!(!f.noreturn());
        });
    }

    #[test]
    fn test_function_return_type() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::add_points")
                .unwrap();
            let ret = f.return_type().expect("add_points should have return type");
            assert_eq!(ret.kind(), TypeKind::Struct);
            assert_eq!(ret.name(), Some("Point"));
        });
    }

    #[test]
    fn test_function_void_return() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::noop")
                .expect("noop not found");
            assert!(f.return_type().is_none());
        });
    }

    #[test]
    fn test_function_params() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::add_points")
                .unwrap();
            let params: Vec<_> = f.params().collect();
            assert_eq!(params.len(), 2);

            let names: Vec<_> = params.iter().filter_map(|p| p.name()).collect();
            assert!(names.contains(&"a"));
            assert!(names.contains(&"b"));

            // Parameters are &Point references, which appear as pointers in DWARF.
            for p in &params {
                let ty = p.ty().expect("param should have a type");
                assert_eq!(ty.kind(), TypeKind::Pointer);
            }
        });
    }

    #[test]
    fn test_function_linkage_name() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::add_points")
                .unwrap();
            let linkage = f.linkage_name().expect("should have linkage name");
            assert!(
                linkage.contains("add_points"),
                "linkage name {linkage:?} should contain 'add_points'"
            );
        });
    }

    // ---- I. ParamIter ----

    #[test]
    fn test_param_iter_exact_size() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::multi_param")
                .unwrap();
            let mut iter = f.params();
            assert_eq!(iter.len(), 3);
            iter.next();
            assert_eq!(iter.len(), 2);
        });
    }

    #[test]
    fn test_param_iter_types() {
        with_view!(view => {
            let f = view
                .find_func("testlib::shapes::multi_param")
                .unwrap();
            for p in f.params() {
                assert!(p.ty().is_some(), "param {:?} should have a type", p.name());
            }
        });
    }

    // ---- J. DwView lookups ----

    #[test]
    fn test_view_find_qualified() {
        with_view!(view => {
            assert!(view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .is_some());
        });
    }

    #[test]
    fn test_view_find_bare_name_misses_namespaced() {
        with_view!(view => {
            // Bare name lookup requires namespace_id == None, so a
            // namespaced type like Point won't match.
            assert!(view.find("Point", TypeKind::Struct).is_none());
        });
    }

    #[test]
    fn test_view_find_nonexistent() {
        with_view!(view => {
            assert!(view.find("DoesNotExist", TypeKind::Struct).is_none());
        });
    }

    #[test]
    fn test_view_find_wrong_kind() {
        with_view!(view => {
            assert!(view
                .find("testlib::shapes::Point", TypeKind::Base)
                .is_none());
        });
    }

    #[test]
    fn test_view_find_all() {
        with_view!(view => {
            let results = view.find_all("testlib::shapes::Point");
            assert!(!results.is_empty());
            for ty in &results {
                assert_eq!(ty.name(), Some("Point"));
            }
        });
    }

    // ---- K. Debug formatting ----

    #[test]
    fn test_debug_does_not_panic() {
        with_view!(view => {
            // Type / Struct / Member
            let s = view
                .find("testlib::shapes::Point", TypeKind::Struct)
                .unwrap();
            let dbg = format!("{s:?}");
            assert!(!dbg.is_empty());

            let st = s.as_struct().unwrap();
            let dbg = format!("{st:?}");
            assert!(!dbg.is_empty());

            for m in st.members() {
                let dbg = format!("{m:?}");
                assert!(!dbg.is_empty());
            }

            // Namespace
            let ns = st.namespace().unwrap();
            let dbg = format!("{ns:?}");
            assert!(!dbg.is_empty());

            // Base
            let base = view.find("u32", TypeKind::Base).unwrap();
            let dbg = format!("{base:?}");
            assert!(!dbg.is_empty());

            // StaticVariable
            let v = view.find_var("testlib::shapes::GLOBAL_COUNT").unwrap();
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());

            // Func / Param
            let f = view.find_func("testlib::shapes::add_points").unwrap();
            let dbg = format!("{f:?}");
            assert!(!dbg.is_empty());

            for p in f.params() {
                let dbg = format!("{p:?}");
                assert!(!dbg.is_empty());
            }
        });
    }

    // ---- L. Enum ----

    #[test]
    fn test_enum_shape_is_enum() {
        with_view!(view => {
            let ty = view
                .find("testlib::enums::Shape", TypeKind::Enum)
                .expect("Shape should be found as Enum");
            assert_eq!(ty.kind(), TypeKind::Enum);
            let e = ty.as_enum().unwrap();
            assert_eq!(e.name(), Some("Shape"));
        });
    }

    #[test]
    fn test_enum_not_struct() {
        with_view!(view => {
            assert!(
                view.find("testlib::enums::Shape", TypeKind::Struct).is_none(),
                "Shape should not be found as Struct"
            );
        });
    }

    #[test]
    fn test_enum_message_variant_count() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Message", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            assert_eq!(e.variant_count(), 3);
        });
    }

    #[test]
    fn test_enum_message_shape_many() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Message", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let super::VariantShapeView::Many { discr, variants } = e.shape() else {
                panic!("expected Many shape");
            };
            // Discriminant should exist and have an integer type.
            let discr = discr.expect("Message should have an explicit discriminant");
            let discr_ty = discr.ty();
            assert_eq!(discr_ty.kind(), TypeKind::Base);

            // Collect variant names.
            let names: Vec<_> = variants.map(|(_, v)| v.name().unwrap().to_string()).collect();
            assert!(names.contains(&"Quit".to_string()));
            assert!(names.contains(&"Echo".to_string()));
            assert!(names.contains(&"Move".to_string()));
        });
    }

    #[test]
    fn test_enum_message_discr_values() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Message", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let super::VariantShapeView::Many { variants, .. } = e.shape() else {
                panic!("expected Many shape");
            };
            // All variants should have explicit discriminant values.
            for (dv, _) in variants {
                assert!(dv.is_some(), "all Message variants should have explicit discriminants");
            }
        });
    }

    #[test]
    fn test_enum_message_large_enum() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Large", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let super::VariantShapeView::Many { discr, variants } = e.shape() else {
                panic!("expected Many shape");
            };
            // Discriminant should exist and have an integer type.
            let discr = discr.expect("Message should have an explicit discriminant");
            let discr_ty = discr.ty();
            assert_eq!(discr_ty.kind(), TypeKind::Base);
            assert_eq!(discr_ty.name(), Some("u128"));

            // Collect variant names.
            let names: Vec<_> = variants.map(|(_, v)| v.name().unwrap().to_string()).collect();
            assert!(names.contains(&"Big".to_string()));
            assert!(names.contains(&"Empty".to_string()));
        });
    }

    #[test]
    fn test_enum_message_discriminant_member() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Message", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let discr = e.discriminant().expect("Message should have a discriminant");
            let discr_ty = discr.ty();
            assert_eq!(discr_ty.kind(), TypeKind::Base);
        });
    }

    #[test]
    fn test_enum_shape_payloads() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Shape", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            assert_eq!(e.variant_count(), 2);

            let super::VariantShapeView::Many { variants, .. } = e.shape() else {
                panic!("expected Many shape");
            };

            let vars: Vec<_> = variants.collect();
            let names: Vec<_> = vars.iter().map(|(_, v)| v.name().unwrap()).collect();
            assert!(names.contains(&"Circle"));
            assert!(names.contains(&"Rect"));
        });
    }

    #[test]
    fn test_enum_single_variant() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Single", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            // Single-variant enums may be One or Many depending on the
            // compiler. Just verify it is found as an enum with 1 variant.
            assert_eq!(e.variant_count(), 1);
        });
    }

    #[test]
    fn test_enum_repr_u8_discr_type() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::SmallTagged", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let discr = e.discriminant().expect("SmallTagged should have a discriminant");
            let discr_ty = discr.ty().as_base().expect("discriminant should be a base type");
            assert_eq!(discr_ty.size(), 1, "repr(u8) discriminant should be 1 byte");
        });
    }

    #[test]
    fn test_enum_namespace() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Shape", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let ns = e.namespace().expect("Shape should have a namespace");
            assert_eq!(ns.full_name(), "testlib::enums");
        });
    }

    // ---- M. Niche-optimized Enum ----

    #[test]
    fn test_niche_enum_is_enum() {
        with_view!(view => {
            // Option<NonZeroU64> is niche-optimized; the compiler embeds
            // it in NicheHolder.opt_ref as a structure_type with a
            // variant_part that has NO discriminant member.
            let holder = view
                .find("testlib::enums::NicheHolder", TypeKind::Struct)
                .expect("NicheHolder should exist")
                .as_struct()
                .unwrap();
            let opt_ref = holder.member("opt_ref").expect("opt_ref member should exist");
            let opt_ty = opt_ref.ty();
            assert_eq!(opt_ty.kind(), TypeKind::Enum, "Option<NonZeroU64> should be Enum");
        });
    }

    #[test]
    fn test_niche_enum_is_many_with_two_variants() {
        with_view!(view => {
            let holder = view
                .find("testlib::enums::NicheHolder", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let opt_ty = holder.member("opt_ref").unwrap().ty();
            let e = opt_ty.as_enum().unwrap();
            assert_eq!(e.variant_count(), 2);

            let super::VariantShapeView::Many { discr, variants } = e.shape() else {
                panic!("expected Many shape for niche-optimized enum");
            };
            // Niche-optimized: discriminant overlaps with payload data.
            let discr = discr.expect("Option<NonZeroU64> should have a discriminant member");
            assert_eq!(discr.offset(), 0);

            let names: Vec<_> = variants.map(|(_, v)| v.name().unwrap().to_string()).collect();
            assert!(names.contains(&"Some".to_string()));
            assert!(names.contains(&"None".to_string()));
        });
    }

    #[test]
    fn test_niche_enum_has_default_variant() {
        with_view!(view => {
            let holder = view
                .find("testlib::enums::NicheHolder", TypeKind::Struct)
                .unwrap()
                .as_struct()
                .unwrap();
            let opt_ty = holder.member("opt_ref").unwrap().ty();
            let e = opt_ty.as_enum().unwrap();
            let super::VariantShapeView::Many { variants, .. } = e.shape() else {
                panic!("expected Many shape");
            };
            // Niche optimization: one variant has an explicit discriminant
            // value (None=0), the other is the default (Some, matched when
            // the discriminant doesn't equal any explicit value).
            let vals: Vec<_> = variants.map(|(dv, _)| dv).collect();
            let has_default = vals.iter().any(|dv| dv.is_none());
            let has_explicit = vals.iter().any(|dv| dv.is_some());
            assert!(has_default, "niche enum should have a default variant");
            assert!(has_explicit, "niche enum should have an explicit variant");
        });
    }

    // ---- N. C-style Enum ----

    #[test]
    fn test_clike_enum_color_is_enum() {
        with_view!(view => {
            let ty = view
                .find("testlib::enums::Color", TypeKind::Enum)
                .expect("Color should be found as Enum");
            assert_eq!(ty.kind(), TypeKind::Enum);
            let e = ty.as_enum().unwrap();
            assert_eq!(e.name(), Some("Color"));
        });
    }

    #[test]
    fn test_clike_enum_color_not_struct() {
        with_view!(view => {
            assert!(
                view.find("testlib::enums::Color", TypeKind::Struct).is_none(),
                "Color should not be found as Struct"
            );
        });
    }

    #[test]
    fn test_clike_enum_color_shape() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Color", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let super::VariantShapeView::CStyle { enumerators, .. } = e.shape() else {
                panic!("expected CStyle shape for Color");
            };
            let names: Vec<_> = enumerators.map(|e| e.name().to_string()).collect();
            assert!(names.contains(&"Red".to_string()));
            assert!(names.contains(&"Green".to_string()));
            assert!(names.contains(&"Blue".to_string()));
        });
    }

    #[test]
    fn test_clike_enum_color_variant_count() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Color", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            assert_eq!(e.variant_count(), 3);
        });
    }

    #[test]
    fn test_clike_enum_color_values() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Color", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let super::VariantShapeView::CStyle { enumerators, .. } = e.shape() else {
                panic!("expected CStyle shape");
            };
            let pairs: Vec<_> = enumerators.map(|e| (e.name().to_string(), e.value())).collect();
            assert!(pairs.contains(&("Red".to_string(), 0)));
            assert!(pairs.contains(&("Green".to_string(), 1)));
            assert!(pairs.contains(&("Blue".to_string(), 2)));
        });
    }

    #[test]
    fn test_clike_enum_small_repr_u8() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::SmallEnum", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            assert_eq!(e.size(), 1, "repr(u8) enum should be 1 byte");
            assert_eq!(e.variant_count(), 3);
        });
    }

    #[test]
    fn test_clike_enum_namespace() {
        with_view!(view => {
            let e = view
                .find("testlib::enums::Color", TypeKind::Enum)
                .unwrap()
                .as_enum()
                .unwrap();
            let ns = e.namespace().expect("Color should have a namespace");
            assert_eq!(ns.full_name(), "testlib::enums");
        });
    }

    // ---- N. Namespace queries ----

    #[test]
    fn test_find_ns() {
        with_view!(view => {
            let ns = view.find_ns("testlib::shapes").expect("shapes ns not found");
            assert_eq!(ns.full_name(), "testlib::shapes");
            assert_eq!(ns.depth(), 2);

            assert!(view.find_ns("nonexistent").is_none());
            assert!(view.find_ns("testlib::nonexistent").is_none());
        });
    }

    #[test]
    fn test_find_ns_deep() {
        with_view!(view => {
            let ns = view.find_ns("testlib::outer::inner").expect("inner ns not found");
            assert_eq!(ns.full_name(), "testlib::outer::inner");
            assert_eq!(ns.depth(), 3);
        });
    }
}

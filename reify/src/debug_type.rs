use crate::Result;

use std::fmt;

/// Reify's own TypeKind — the union of kinds reify cares about.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Integer,
    Float,
    Pointer,
    Array,
    Struct,
    Union,
    Enum,
    /// Typedef, const, volatile, restrict, forward, unknown, etc.
    Other,
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Pointer => "pointer",
            Self::Array => "array",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Other => "other",
        };
        f.write_str(desc)
    }
}

/// Core trait: a type from debug information.
///
/// Both `durin::read::CtfType<'a>` and `exegesis::view::Type<'a>` implement
/// this, allowing `TypeInfo` and `TypeInfoRef` to work with either backend.
pub trait DebugType<'a>: Copy + Clone + Sized + fmt::Debug {
    type Member: DebugMember<'a, Type = Self>;
    type MemberIter: ExactSizeIterator<Item = Self::Member>;

    // --- Core metadata ---

    fn size(&self) -> u64;

    fn name(&self) -> &'a str;

    fn kind(&self) -> TypeKind;

    // --- Structural access (struct/union members) ---

    /// Look up a member by name. Returns `None` if this type has no members
    /// or if no member with the given name exists.
    fn member(&self, name: &str) -> Option<Self::Member>;

    /// Iterate over members. Returns an empty iterator for non-struct/union
    /// types.
    fn members(&self) -> Self::MemberIter;

    // --- Pointer: get the target type ---

    /// If this is a pointer type, return the type it points to.
    fn pointer_target(&self) -> Option<Self>;

    // --- Array: get element type and count ---

    /// If this is an array type, return `(element_type, count)`.
    fn array_info(&self) -> Option<(Self, u64)>;

    // --- Wrapper type unwrapping ---

    /// Unwrap transparent wrapper types (typedef, const, volatile, restrict)
    /// to the underlying type. Returns `self` if not a wrapper.
    fn peel_wrappers(&self) -> Self;

    // --- Enum variant operations ---
    //
    // These encapsulate CTF's __discr/__variants pattern and DWARF's
    // VariantShape behind a common interface.

    /// If this type represents a Rust enum, determine the active variant
    /// from `bytes`. Returns `(variant_name, variant_payload_type,
    /// payload_byte_offset)`.
    ///
    /// Returns `None` if this is not an enum-like type.
    /// Returns `Some(Err(..))` if it is an enum but the discriminant is
    /// invalid.
    fn active_variant(&self, bytes: &[u8]) -> Option<Result<(&'a str, Self, u64)>>;

    /// If this type represents a Rust enum, check whether the named variant
    /// is active. Returns `(payload_type, payload_byte_offset)` if active,
    /// `Ok(None)` if a different variant is active.
    ///
    /// Returns `None` (outer) if this is not an enum-like type.
    fn check_variant(&self, bytes: &[u8], name: &str) -> Option<Result<Option<(Self, u64)>>>;

    // --- Display support ---

    /// Classify this type for display formatting.
    fn classify(&self) -> TypeClass<Self>;

    /// Custom display instructions supplied by the debug-info backend.
    fn debug_format(&self) -> Option<DebugFormat<Self>> {
        None
    }
}

/// Backend-independent, fully resolved custom display instructions.
#[derive(Copy, Clone, Debug)]
pub enum DebugFormat<T> {
    /// Display `target` at `offset` as though it were the containing value.
    Transparent { target: T, offset: u64 },
    /// Apply semantics for a known family of types.
    Known(KnownFormat<T>),
}

/// Closed set of semantic formatters understood by reify.
#[derive(Copy, Clone, Debug)]
pub enum KnownFormat<T> {
    /// Display an atomic's stored value without following pointer values.
    Atomic { value: T, offset: u64 },
}

/// A member (field) of a struct, union, or enum variant payload.
pub trait DebugMember<'a>: Copy + Clone + Sized {
    type Type: DebugType<'a>;

    fn name(&self) -> &'a str;
    fn ty(&self) -> Self::Type;
    /// The byte offset of this member within its parent type.
    fn offset(&self) -> u64;
}

/// Classification of a debug type for display formatting.
///
/// Reify's display code matches on this instead of backend-specific type
/// enums.
pub enum TypeClass<T> {
    /// An integer type with encoding info for display.
    Integer {
        size: u64,
        is_signed: bool,
        is_bool: bool,
        is_char: bool,
    },
    /// A floating point type.
    Float { size: u64 },
    /// A pointer. `target` is the pointee type.
    Pointer { target: T },
    /// A fixed-size array.
    Array { element: T, count: u64 },
    /// A plain struct — display its fields.
    Struct,
    /// A plain union — hex dump.
    Union,
    /// A Rust discriminated enum — use active_variant() for display.
    RustEnum,
    /// A C-style enum (named integer constants).
    CEnum,
    /// A transparent wrapper (typedef, const, volatile, restrict) — recurse
    /// into the inner type.
    Wrapper(T),
    /// Opaque / unknown — hex dump.
    Opaque,
}

// ---------------------------------------------------------------------------
// CTF implementation
// ---------------------------------------------------------------------------

use durin::read::{CtfEnum, CtfMember, CtfMemberIter, CtfType};

impl<'a> DebugType<'a> for CtfType<'a> {
    type Member = CtfMember<'a>;
    type MemberIter = CtfMemberIter<'a>;

    fn size(&self) -> u64 {
        CtfType::size(self)
    }

    fn name(&self) -> &'a str {
        CtfType::name(self)
    }

    fn kind(&self) -> TypeKind {
        match CtfType::kind(self) {
            durin::TypeKind::Integer => TypeKind::Integer,
            durin::TypeKind::Float => TypeKind::Float,
            durin::TypeKind::Pointer => TypeKind::Pointer,
            durin::TypeKind::Array => TypeKind::Array,
            durin::TypeKind::Struct => TypeKind::Struct,
            durin::TypeKind::Union => TypeKind::Union,
            durin::TypeKind::Enum => TypeKind::Enum,
            _ => TypeKind::Other,
        }
    }

    fn member(&self, name: &str) -> Option<Self::Member> {
        CtfType::member(self, name)
    }

    fn members(&self) -> Self::MemberIter {
        CtfType::members(self)
    }

    fn pointer_target(&self) -> Option<Self> {
        self.as_pointer().map(|p| p.target())
    }

    fn array_info(&self) -> Option<(Self, u64)> {
        self.as_array().map(|a| (a.element_type(), a.len() as u64))
    }

    fn peel_wrappers(&self) -> Self {
        match self {
            CtfType::Typedef(_)
            | CtfType::Volatile(_)
            | CtfType::Const(_)
            | CtfType::Restrict(_) => match self.target() {
                Some(target) => target.peel_wrappers(),
                None => *self,
            },
            _ => *self,
        }
    }

    fn active_variant(&self, bytes: &[u8]) -> Option<Result<(&'a str, Self, u64)>> {
        // CTF represents Rust enums as structs (or unions) with __discr and
        // __variants members.
        let discr_member = CtfType::member(self, "__discr")?;
        let variants_member = CtfType::member(self, "__variants")?;
        Some(ctf_active_variant(
            *self,
            bytes,
            discr_member,
            variants_member,
        ))
    }

    fn check_variant(&self, bytes: &[u8], name: &str) -> Option<Result<Option<(Self, u64)>>> {
        let discr_member = CtfType::member(self, "__discr")?;
        let variants_member = CtfType::member(self, "__variants")?;
        Some(ctf_check_variant(
            *self,
            bytes,
            name,
            discr_member,
            variants_member,
        ))
    }

    fn classify(&self) -> TypeClass<Self> {
        match self {
            CtfType::Integer(int_ty) => {
                let enc = int_ty.encoding();
                TypeClass::Integer {
                    size: int_ty.size(),
                    is_signed: enc.flags.is_signed(),
                    is_bool: enc.flags.is_bool(),
                    is_char: enc.flags.is_char(),
                }
            }
            CtfType::Float(float_ty) => TypeClass::Float {
                size: float_ty.size(),
            },
            CtfType::Pointer(ptr) => TypeClass::Pointer {
                target: ptr.target(),
            },
            CtfType::Array(arr) => TypeClass::Array {
                element: arr.element_type(),
                count: arr.len() as u64,
            },
            CtfType::Struct(_) => {
                // Check for Rust enum pattern.
                if CtfType::member(self, "__discr").is_some()
                    && CtfType::member(self, "__variants").is_some()
                {
                    TypeClass::RustEnum
                } else {
                    TypeClass::Struct
                }
            }
            CtfType::Union(_) => {
                if CtfType::member(self, "__discr").is_some()
                    && CtfType::member(self, "__variants").is_some()
                {
                    TypeClass::RustEnum
                } else {
                    TypeClass::Union
                }
            }
            CtfType::Enum(_) => TypeClass::CEnum,
            CtfType::Typedef(td) => TypeClass::Wrapper(td.target()),
            CtfType::Volatile(v) => TypeClass::Wrapper(v.target()),
            CtfType::Const(c) => TypeClass::Wrapper(c.target()),
            CtfType::Restrict(r) => TypeClass::Wrapper(r.target()),
            _ => TypeClass::Opaque,
        }
    }
}

impl<'a> DebugMember<'a> for CtfMember<'a> {
    type Type = CtfType<'a>;

    fn name(&self) -> &'a str {
        CtfMember::name(self)
    }

    fn ty(&self) -> CtfType<'a> {
        CtfMember::ty(self)
    }

    fn offset(&self) -> u64 {
        CtfMember::offset(self)
    }
}

// ---------------------------------------------------------------------------
// Bundle implementation
// ---------------------------------------------------------------------------

use exegesis::Encoding;
use exegesis::bundle::{BundleMember, BundleMemberIter, BundleType, TypeDef, VariantError};

impl<'a> DebugType<'a> for BundleType<'a> {
    type Member = BundleMember<'a>;
    type MemberIter = BundleMemberIter<'a>;

    fn size(&self) -> u64 {
        BundleType::size(self)
    }

    fn name(&self) -> &'a str {
        BundleType::name(self)
    }

    fn kind(&self) -> TypeKind {
        match self.def() {
            TypeDef::Base { encoding, .. } => match encoding {
                Encoding::Float => TypeKind::Float,
                _ => TypeKind::Integer,
            },
            TypeDef::Pointer { .. } => TypeKind::Pointer,
            TypeDef::Array { .. } => TypeKind::Array,
            TypeDef::Struct { .. } => TypeKind::Struct,
            TypeDef::Union { .. } => TypeKind::Union,
            TypeDef::Enum { .. } | TypeDef::CEnum { .. } => TypeKind::Enum,
            TypeDef::Opaque { .. } => TypeKind::Other,
        }
    }

    fn member(&self, name: &str) -> Option<Self::Member> {
        BundleType::member(self, name)
    }

    fn members(&self) -> Self::MemberIter {
        BundleType::members(self)
    }

    fn pointer_target(&self) -> Option<Self> {
        BundleType::pointer_target(self)
    }

    fn array_info(&self) -> Option<(Self, u64)> {
        BundleType::array_info(self)
    }

    fn peel_wrappers(&self) -> Self {
        // Wrapper kinds (typedef/const/volatile) are resolved away at
        // extraction time and never appear in bundles.
        *self
    }

    fn active_variant(&self, bytes: &[u8]) -> Option<Result<(&'a str, Self, u64)>> {
        let decoded = BundleType::active_variant(self, bytes)?;
        Some(
            decoded
                .map(|v| (v.name, v.ty, v.offset))
                .map_err(|e| bundle_variant_error(self, e)),
        )
    }

    fn check_variant(&self, bytes: &[u8], name: &str) -> Option<Result<Option<(Self, u64)>>> {
        let checked = BundleType::check_variant(self, bytes, name)?;
        Some(checked.map_err(|e| match e {
            VariantError::NoSuchVariant => {
                crate::Error::no_enumerator(self.name().to_string(), name.to_string())
            }
            other => bundle_variant_error(self, other),
        }))
    }

    fn classify(&self) -> TypeClass<Self> {
        match self.def() {
            TypeDef::Base { size, encoding, .. } => match encoding {
                Encoding::Float => TypeClass::Float { size: *size },
                _ => TypeClass::Integer {
                    size: *size,
                    is_signed: matches!(encoding, Encoding::Signed | Encoding::SignedChar),
                    is_bool: matches!(encoding, Encoding::Boolean),
                    is_char: matches!(
                        encoding,
                        Encoding::SignedChar | Encoding::UnsignedChar | Encoding::UtfChar
                    ),
                },
            },
            TypeDef::Pointer { .. } => TypeClass::Pointer {
                target: self.pointer_target().expect("pointer has a target"),
            },
            TypeDef::Array { .. } => {
                let (element, count) = self.array_info().expect("array has element info");
                TypeClass::Array { element, count }
            }
            TypeDef::Struct { .. } => TypeClass::Struct,
            TypeDef::Union { .. } => TypeClass::Union,
            TypeDef::Enum { .. } => TypeClass::RustEnum,
            TypeDef::CEnum { .. } => TypeClass::CEnum,
            TypeDef::Opaque { .. } => TypeClass::Opaque,
        }
    }

    fn debug_format(&self) -> Option<DebugFormat<Self>> {
        use exegesis::bundle::{DebugFormat as BundleFormat, KnownFormat as BundleKnownFormat};

        fn project<'a>(mut ty: BundleType<'a>, path: &[u32]) -> Option<(BundleType<'a>, u64)> {
            let mut offset = 0u64;
            for &index in path {
                let member = ty.members().nth(index as usize)?;
                offset = offset.checked_add(member.offset())?;
                ty = member.ty();
            }
            Some((ty, offset))
        }

        match BundleType::debug_format(self)? {
            BundleFormat::Transparent { member } => {
                let (target, offset) = project(*self, &[*member])?;
                Some(DebugFormat::Transparent { target, offset })
            }
            BundleFormat::Known(BundleKnownFormat::Atomic { value }) => {
                let (value, offset) = project(*self, value)?;
                Some(DebugFormat::Known(KnownFormat::Atomic { value, offset }))
            }
        }
    }
}

impl<'a> DebugMember<'a> for BundleMember<'a> {
    type Type = BundleType<'a>;

    fn name(&self) -> &'a str {
        BundleMember::name(self)
    }

    fn ty(&self) -> BundleType<'a> {
        BundleMember::ty(self)
    }

    fn offset(&self) -> u64 {
        BundleMember::offset(self)
    }
}

/// Map a bundle variant-decode failure onto reify's error type.
fn bundle_variant_error(ty: &BundleType<'_>, e: VariantError) -> crate::Error {
    match e {
        VariantError::ShortBuffer { needed, len } => {
            crate::Error::unexpected_len(len as u32, needed as u32)
        }
        VariantError::NoVariantMatch { raw } => {
            crate::Error::invalid_discriminant_value(ty.name().to_string(), raw as i64)
        }
        other => crate::Error::parse_type(format!("{}: {other}", ty.name())),
    }
}

// ---------------------------------------------------------------------------
// CTF enum helpers
// ---------------------------------------------------------------------------

/// Read the discriminant value from a CTF enum-like type.
fn ctf_read_discriminant<'a>(
    discr_member: CtfMember<'a>,
    bytes: &[u8],
) -> Result<(i64, CtfEnum<'a>)> {
    use crate::Error;

    let discr_ty = discr_member.ty();
    let Some(discr_enum) = discr_ty.as_enum() else {
        return Err(Error::unexpected_type(
            TypeKind::Other,
            TypeKind::Enum,
            format!("discriminant type {:?}", discr_ty),
        ));
    };

    let offset = discr_member.offset() as usize;
    let value = match discr_ty.size() {
        1 => *bytes
            .get(offset)
            .ok_or_else(|| Error::unexpected_len(bytes.len() as u32, (offset + 1) as u32))?
            as i64,
        2 => {
            let b = bytes
                .get(offset..offset + 2)
                .ok_or_else(|| Error::unexpected_len(bytes.len() as u32, (offset + 2) as u32))?;
            i16::from_le_bytes(b.try_into().unwrap()) as i64
        }
        4 => {
            let b = bytes
                .get(offset..offset + 4)
                .ok_or_else(|| Error::unexpected_len(bytes.len() as u32, (offset + 4) as u32))?;
            i32::from_le_bytes(b.try_into().unwrap()) as i64
        }
        8 => {
            let b = bytes
                .get(offset..offset + 8)
                .ok_or_else(|| Error::unexpected_len(bytes.len() as u32, (offset + 8) as u32))?;
            i64::from_le_bytes(b.try_into().unwrap())
        }
        _ => unreachable!(),
    };

    Ok((value, discr_enum))
}

/// Determine the active variant for a CTF Rust enum.
fn ctf_active_variant<'a>(
    parent: CtfType<'a>,
    bytes: &[u8],
    discr_member: CtfMember<'a>,
    variants_member: CtfMember<'a>,
) -> Result<(&'a str, CtfType<'a>, u64)> {
    use crate::Error;

    let (discrim, discr_ty) = ctf_read_discriminant(discr_member, bytes)?;
    let variants = variants_member.ty();

    let is_niche_optimized = variants.members().len() == 2 && discr_ty.enumerators().len() == 1;

    let enumerator = discr_ty.enumerators().find(|e| e.value() == discrim);

    let name = match (enumerator, is_niche_optimized) {
        (Some(e), _) => e.name(),
        (None, true) => {
            // The single defined enumerator doesn't match, so the other
            // variant must be active.
            let var = variants
                .members()
                .find(|m| m.name() != discr_ty.enumerators().nth(0).unwrap().name())
                .unwrap();
            var.name()
        }
        (None, false) => {
            return Err(Error::invalid_discriminant_value(
                parent.name().to_string(),
                discrim,
            ));
        }
    };

    let Some(selected) = variants.member(name) else {
        return Err(Error::no_member(
            parent.name().to_string(),
            name.to_string(),
        ));
    };
    let ty = selected.ty();
    let offset = selected.offset();

    Ok((name, ty, offset))
}

/// Check whether a specific named variant is active for a CTF Rust enum.
fn ctf_check_variant<'a>(
    parent: CtfType<'a>,
    bytes: &[u8],
    name: &str,
    discr_member: CtfMember<'a>,
    variants_member: CtfMember<'a>,
) -> Result<Option<(CtfType<'a>, u64)>> {
    use crate::Error;

    let (discrim, discr_ty) = ctf_read_discriminant(discr_member, bytes)?;
    let variants = variants_member.ty();

    let is_niche_optimized = variants.members().len() == 2 && discr_ty.enumerators().len() == 1;

    let enumerator = discr_ty.enumerators().find(|e| e.name() == name);

    match (enumerator, is_niche_optimized) {
        (Some(e), _) => {
            if e.value() != discrim {
                return Ok(None);
            }
        }
        (None, true) => {
            // Niche-optimized: the single enumerator matches the
            // discriminant but we're looking for an undefined variant.
            if discrim == discr_ty.enumerators().nth(0).unwrap().value() {
                return Ok(None);
            }
        }
        (None, false) => {
            return Err(Error::no_enumerator(
                variants.name().to_string(),
                name.to_string(),
            ));
        }
    }

    let Some(selected) = variants.member(name) else {
        return Err(Error::no_member(
            parent.name().to_string(),
            name.to_string(),
        ));
    };
    let ty = selected.ty();
    let offset = selected.offset();

    Ok(Some((ty, offset)))
}

// ---------------------------------------------------------------------------
// Bundle backend conformance tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bundle_tests {
    use super::{DebugType, TypeKind};
    use crate::{ReadFromProc, TypeInfoRef};

    use exegesis::Encoding;
    use exegesis::bundle::{
        Bundle, BundleTypeId, BundleView, DebugFormat as BundleDebugFormat, DiscrDef, DiscrValue,
        DiscrValues, DynFutureTable, FORMAT_VERSION, InfraTypes, KnownFormat as BundleKnownFormat,
        MemberDef, Meta, ProvenanceTable, StaticsTable, StringInterner, TaskTable, TypeDef,
        TypeTable, VariantDef, VariantShape,
    };

    const U32: BundleTypeId = BundleTypeId(0);
    const U64: BundleTypeId = BundleTypeId(1);
    const BOOL: BundleTypeId = BundleTypeId(2);
    const U8: BundleTypeId = BundleTypeId(3);
    const UNIT: BundleTypeId = BundleTypeId(4);
    const POINT: BundleTypeId = BundleTypeId(5);
    const MSG: BundleTypeId = BundleTypeId(6);
    const OPT: BundleTypeId = BundleTypeId(7);
    const WRAP: BundleTypeId = BundleTypeId(8);
    const PTR: BundleTypeId = BundleTypeId(9);
    const ARR: BundleTypeId = BundleTypeId(10);
    const NODE: BundleTypeId = BundleTypeId(11);
    const NODE_PTR: BundleTypeId = BundleTypeId(12);
    const VTABLE_ARRAY: BundleTypeId = BundleTypeId(13);
    const VTABLE_PTR: BundleTypeId = BundleTypeId(14);
    const FAT_PTR: BundleTypeId = BundleTypeId(15);
    const ATOMIC: BundleTypeId = BundleTypeId(16);
    const ATOMIC_STORAGE: BundleTypeId = BundleTypeId(17);
    const ATOMIC_PTR: BundleTypeId = BundleTypeId(18);
    const LOOM_ATOMIC: BundleTypeId = BundleTypeId(19);
    const LOOM_CELL: BundleTypeId = BundleTypeId(20);

    /// A hand-built mini-bundle exercising every TypeDef kind reify touches:
    ///
    /// - `Point { x: u32 @0, y: u32 @4 }`
    /// - `Msg` — tagged enum, u8 discr @0: `A(Point)@8 | B(u64)@8 | C(unit)@8`
    /// - `Opt` — niche enum, u64 discr @0: `None(unit)=0 | Some(u64) default`
    /// - `Wrap { inner: Point @0 }` — single-member wrapper for peel()
    /// - `*Point`, `[u32; 3]`
    fn test_bundle() -> Bundle {
        let mut strings = StringInterner::new();
        let mut s = |name: &str| strings.intern(name);

        let (u32n, u64n, booln, u8n, unitn) = (s("u32"), s("u64"), s("bool"), s("u8"), s("Unit"));
        let (pointn, xn, yn) = (s("Point"), s("x"), s("y"));
        let (msgn, an, bn, cn) = (s("Msg"), s("A"), s("B"), s("C"));
        let (optn, nonen, somen) = (s("Opt"), s("None"), s("Some"));
        let (wrapn, innern) = (s("Wrap"), s("inner"));
        let (noden, valuen, nextn) = (s("Node"), s("value"), s("next"));
        let (fatn, vtablen) = (s("FatPtr"), s("vtable"));
        let (atomicn, storagen, vn) = (s("Atomic<u32>"), s("AtomicStorage<u32>"), s("v"));
        let atomic_ptrn = s("Atomic<*mut Point>");
        let (loom_atomicn, loom_celln, tuple0n) =
            (s("AtomicU32"), s("LoomUnsafeCell<Point>"), s("__0"));

        let m = |name, ty, offset| MemberDef { name, ty, offset };
        let tag = |v: u128| Some(DiscrValues(vec![DiscrValue::Value(v)]));

        let types = vec![
            TypeDef::Base { name: u32n, size: 4, encoding: Encoding::Unsigned },
            TypeDef::Base { name: u64n, size: 8, encoding: Encoding::Unsigned },
            TypeDef::Base { name: booln, size: 1, encoding: Encoding::Boolean },
            TypeDef::Base { name: u8n, size: 1, encoding: Encoding::Unsigned },
            TypeDef::Struct { name: unitn, size: 0, members: vec![] },
            TypeDef::Struct {
                name: pointn,
                size: 8,
                members: vec![m(xn, U32, 0), m(yn, U32, 4)],
            },
            TypeDef::Enum {
                name: msgn,
                size: 16,
                shape: VariantShape {
                    discr: Some(DiscrDef { offset: 0, ty: U8 }),
                    variants: vec![
                        VariantDef { name: an, discr_values: tag(0), payload: m(an, POINT, 8), decl: None },
                        VariantDef { name: bn, discr_values: tag(1), payload: m(bn, U64, 8), decl: None },
                        VariantDef { name: cn, discr_values: tag(2), payload: m(cn, UNIT, 8), decl: None },
                    ],
                },
            },
            TypeDef::Enum {
                name: optn,
                size: 8,
                shape: VariantShape {
                    discr: Some(DiscrDef { offset: 0, ty: U64 }),
                    variants: vec![
                        VariantDef { name: nonen, discr_values: tag(0), payload: m(nonen, UNIT, 0), decl: None },
                        VariantDef { name: somen, discr_values: None, payload: m(somen, U64, 0), decl: None },
                    ],
                },
            },
            TypeDef::Struct { name: wrapn, size: 8, members: vec![m(innern, POINT, 0)] },
            TypeDef::Pointer { name: None, target: POINT },
            TypeDef::Array { elem: U32, count: 3 },
            TypeDef::Struct {
                name: noden,
                size: 16,
                members: vec![m(valuen, U32, 0), m(nextn, NODE_PTR, 8)],
            },
            TypeDef::Pointer { name: None, target: NODE },
            TypeDef::Array { elem: U64, count: 3 },
            TypeDef::Pointer { name: None, target: VTABLE_ARRAY },
            TypeDef::Struct { name: fatn, size: 8, members: vec![m(vtablen, VTABLE_PTR, 0)] },
            TypeDef::Struct {
                name: atomicn,
                size: 4,
                members: vec![m(vn, ATOMIC_STORAGE, 0)],
            },
            TypeDef::Struct {
                name: storagen,
                size: 4,
                members: vec![m(valuen, U32, 0)],
            },
            TypeDef::Struct {
                name: atomic_ptrn,
                size: 8,
                members: vec![m(vn, PTR, 0)],
            },
            TypeDef::Struct {
                name: loom_atomicn,
                size: 4,
                members: vec![m(innern, ATOMIC, 0)],
            },
            TypeDef::Struct {
                name: loom_celln,
                size: 8,
                members: vec![m(tuple0n, WRAP, 0)],
            },
        ];

        let b = Bundle {
            meta: Meta { format_version: FORMAT_VERSION, ..Default::default() },
            strings: strings.finish(),
            types: TypeTable {
                types,
                debug_formats: std::collections::BTreeMap::from([(
                    WRAP,
                    BundleDebugFormat::Transparent { member: 0 },
                ), (
                    ATOMIC,
                    BundleDebugFormat::Known(BundleKnownFormat::Atomic { value: vec![0, 0] }),
                ), (
                    ATOMIC_PTR,
                    BundleDebugFormat::Known(BundleKnownFormat::Atomic { value: vec![0] }),
                ), (
                    LOOM_ATOMIC,
                    BundleDebugFormat::Transparent { member: 0 },
                ), (
                    LOOM_CELL,
                    BundleDebugFormat::Transparent { member: 0 },
                )]),
                name_index: vec![],
            },
            tasks: TaskTable::default(),
            dyn_futures: DynFutureTable::default(),
            statics: StaticsTable::default(),
            infra: InfraTypes {
                header: U32,
                vtable: U32,
                trailer: U32,
                context: U32,
                scheduler_handle: U32,
                mt_handle: U32,
                location: U32,
                raw_waker_vtable: U32,
            },
            provenance: ProvenanceTable::default(),
        };
        b.validate().expect("test bundle must validate");
        b
    }

    #[test]
    fn test_kind_mapping() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let kind = |id| v.ty(id).unwrap().kind();
        assert_eq!(kind(U32), TypeKind::Integer);
        assert_eq!(kind(BOOL), TypeKind::Integer);
        assert_eq!(kind(POINT), TypeKind::Struct);
        assert_eq!(kind(MSG), TypeKind::Enum);
        assert_eq!(kind(PTR), TypeKind::Pointer);
        assert_eq!(kind(ARR), TypeKind::Array);
    }

    #[test]
    fn test_member_access_and_display() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let r = TypeInfoRef::new(v.ty(POINT).unwrap(), 0x1000, &bytes);

        let y = r.member("y").expect("member y");
        assert_eq!(y.addr, 0x1004);
        assert_eq!(format!("{}", y.display()), "2");
        assert!(r.try_member("z").expect("no error").is_none());

        let shown = format!("{}", r.display());
        assert!(shown.contains("x: 1") && shown.contains("y: 2"), "got {shown:?}");
    }

    #[test]
    fn test_active_variant_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let msg = v.ty(MSG).unwrap();

        let mut bytes = [0u8; 16];
        bytes[0] = 1;
        bytes[8..].copy_from_slice(&42u64.to_le_bytes());
        let r = TypeInfoRef::new(msg, 0, &bytes);
        assert!(r.is_enum());

        let (name, payload) = r.active_variant().expect("decode failed");
        assert_eq!(name, "B");
        assert_eq!(format!("{}", payload.display()), "42");

        // Struct payload: bytes window starts at the payload offset.
        bytes[0] = 0;
        bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&8u32.to_le_bytes());
        let r = TypeInfoRef::new(msg, 0, &bytes);
        let (name, payload) = r.active_variant().expect("decode failed");
        assert_eq!(name, "A");
        assert_eq!(format!("{}", payload.member("x").unwrap().display()), "7");

        // Struct types are not enums.
        let p = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &bytes[8..16]);
        assert!(!p.is_enum());
        assert!(p.active_variant().is_err());
    }

    #[test]
    fn test_select_variant_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 16];
        bytes[0] = 1;
        let r = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);

        assert!(r.try_select_variant("B").expect("no error").is_some());
        assert!(r.try_select_variant("A").expect("no error").is_none());
        // Unknown variant names are an error, not "inactive".
        assert!(r.try_select_variant("Nope").is_err());
    }

    #[test]
    fn test_niche_variant_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let opt = v.ty(OPT).unwrap();

        let bytes = 0u64.to_le_bytes();
        let (name, _) = TypeInfoRef::new(opt, 0, &bytes).active_variant().unwrap();
        assert_eq!(name, "None");

        let bytes = 0xdead_beefu64.to_le_bytes();
        let r = TypeInfoRef::new(opt, 0, &bytes);
        let (name, payload) = r.active_variant().unwrap();
        assert_eq!(name, "Some");
        assert_eq!(format!("{}", payload.display()), "3735928559");
    }

    #[test]
    fn test_invalid_discriminant_is_error() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 16];
        bytes[0] = 9;
        let r = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);
        let err = r.active_variant().expect_err("tag 9 must not decode");
        let msg = format!("{err}");
        assert!(msg.contains("discriminant") || msg.contains("Msg"), "got {msg:?}");
    }

    #[test]
    fn test_peel_single_member_wrapper() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let peeled = TypeInfoRef::new(v.ty(WRAP).unwrap(), 0, &bytes).peel();
        assert_eq!(DebugType::name(&peeled.ty), "Point");
        assert_eq!(format!("{}", peeled.member("y").unwrap().display()), "4");
    }

    #[test]
    fn test_transparent_debug_format_elides_wrapper() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let value = TypeInfoRef::new(v.ty(WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display_with_depth(2)), "Point { x: 3, y: 4 }");
    }

    #[test]
    fn test_atomic_debug_format_displays_stored_value() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 42u32.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(ATOMIC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display_with_depth(1)), "42");
    }

    #[test]
    fn test_nested_transparent_formats_do_not_consume_depth() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let bytes = 42u32.to_le_bytes();
        let atomic = TypeInfoRef::new(v.ty(LOOM_ATOMIC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", atomic.display_with_depth(1)), "42");

        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let cell = TypeInfoRef::new(v.ty(LOOM_CELL).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", cell.display_with_depth(2)), "Point { x: 3, y: 4 }");
    }

    #[test]
    fn test_atomic_pointer_does_not_dereference_stored_address() {
        struct NoReads;

        impl ReadFromProc for NoReads {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("atomic pointer formatter unexpectedly read {addr:#x}")
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(ATOMIC_PTR).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display_from_target(&NoReads, 8)), "0x1000");
    }

    #[test]
    fn test_array_elements_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [10u32, 20, 30].iter().flat_map(|x| x.to_le_bytes()).collect();
        let r = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
        let shown: Vec<String> = r
            .array_elements()
            .expect("array elements")
            .map(|e| format!("{}", e.display()))
            .collect();
        assert_eq!(shown, ["10", "20", "30"]);
    }

    #[test]
    fn test_target_display_recurses_through_pointers() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                let (value, next) = match addr {
                    0x1000 => (1u32, 0x2000u64),
                    0x2000 => (2u32, 0u64),
                    _ => return Err(crate::Error::invalid_addr(addr)),
                };
                let mut bytes = vec![0; 16];
                bytes[..4].copy_from_slice(&value.to_le_bytes());
                bytes[8..].copy_from_slice(&next.to_le_bytes());
                Ok(bytes)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let root = TypeInfoRef::new(v.ty(NODE_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", root.display_from_target(&Reader, 8));
        assert!(shown.contains("value: 1"), "{shown}");
        assert!(shown.contains("value: 2"), "{shown}");

        let shallow = format!("{:#}", root.display_from_target(&Reader, 1));
        assert_eq!(shallow, "0x1000 -> ...");
    }

    #[test]
    fn test_vtable_entries_display_in_hex() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x3000);
                Ok([0x2c557a0u64, 152, 8]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x3000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(shown.contains("0x0000000002c557a0,"), "{shown}");
        assert!(shown.contains("0x0000000000000098,"), "{shown}");
        assert!(shown.contains("0x0000000000000008,"), "{shown}");
    }
}

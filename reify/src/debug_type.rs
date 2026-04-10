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
/// Both `durin::read::CtfType<'a>` and `felak::view::Type<'a>` implement
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
    fn classify(&self) -> TypeClass<'a, Self>;
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
pub enum TypeClass<'a, T: DebugType<'a>> {
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

    fn classify(&self) -> TypeClass<'a, Self> {
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

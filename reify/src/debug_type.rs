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

    /// Look up the unique byte size of a fully-qualified type name in the
    /// same debug-info backend. Used only to corroborate a concrete type
    /// recovered from a vtable function symbol.
    fn size_by_name(&self, _name: &str) -> Option<u64> {
        None
    }

    /// Look up an unambiguous concrete type by its fully-qualified name in
    /// the same debug-info backend.
    fn type_by_name(&self, _name: &str) -> Option<Self> {
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
    /// Display a function pointer as an address and symbol without following
    /// the address as data.
    FunctionPointer,
    /// Display a Rust trait-object data pointer and vtable.
    ///
    /// `tail_offset` is added to the data-pointer address before reading the
    /// concrete pointee: it is the offset of the `dyn Trait` tail within the
    /// struct the pointer targets, so an `Arc`'s sized header (its strong and
    /// weak counts) is skipped. Zero for a bare `dyn Trait` pointee.
    DynPointer {
        pointer_offset: u64,
        vtable: T,
        vtable_offset: u64,
        drop_in_place: u32,
        size: u32,
        align: u32,
        tail_offset: u64,
    },
    /// Display the fields of `core::task::RawWakerVTable` as function
    /// addresses and symbols.
    RawWakerVTable {
        clone_offset: u64,
        wake_offset: u64,
        wake_by_ref_offset: u64,
        drop_offset: u64,
    },
    /// Display an IPv4 or IPv6 address in standard notation.
    IpAddress { octets: T, offset: u64 },
    /// Display the initialized elements of a Vec.
    Vec {
        pointer_offset: u64,
        length: T,
        length_offset: u64,
        capacity: T,
        capacity_offset: u64,
        element: T,
    },
    /// Display a borrowed string as quoted, escaped UTF-8.
    Str {
        pointer_offset: u64,
        length: T,
        length_offset: u64,
    },
    /// Display an owned string as quoted, escaped UTF-8.
    String {
        pointer_offset: u64,
        length: T,
        length_offset: u64,
        capacity: T,
        capacity_offset: u64,
    },
    /// Display a BTreeMap by walking its initialized nodes in key order.
    BTreeMap {
        root: T,
        root_offset: u64,
        root_node: T,
        root_node_offset: u64,
        length: T,
        length_offset: u64,
        height: T,
        height_offset: u64,
        node_offset: u64,
        key: T,
        value: T,
        leaf: T,
        leaf_len: T,
        leaf_len_offset: u64,
        keys_offset: u64,
        key_slots: u64,
        values_offset: u64,
        internal: T,
        edges_offset: u64,
        edge: T,
        edge_pointer_offset: u64,
    },
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
            BundleFormat::Known(BundleKnownFormat::FunctionPointer) => {
                Some(DebugFormat::Known(KnownFormat::FunctionPointer))
            }
            BundleFormat::Known(BundleKnownFormat::DynPointer {
                pointer,
                vtable,
                drop_in_place,
                size,
                align,
                tail_offset,
            }) => {
                let (_, pointer_offset) = project(*self, &[*pointer])?;
                let (vtable, vtable_offset) = project(*self, &[*vtable])?;
                Some(DebugFormat::Known(KnownFormat::DynPointer {
                    pointer_offset,
                    vtable,
                    vtable_offset,
                    drop_in_place: *drop_in_place,
                    size: *size,
                    align: *align,
                    tail_offset: *tail_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::RawWakerVTable {
                clone,
                wake,
                wake_by_ref,
                drop,
            }) => {
                let (_, clone_offset) = project(*self, &[*clone])?;
                let (_, wake_offset) = project(*self, &[*wake])?;
                let (_, wake_by_ref_offset) = project(*self, &[*wake_by_ref])?;
                let (_, drop_offset) = project(*self, &[*drop])?;
                Some(DebugFormat::Known(KnownFormat::RawWakerVTable {
                    clone_offset,
                    wake_offset,
                    wake_by_ref_offset,
                    drop_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::IpAddress { octets }) => {
                let (octets, offset) = project(*self, &[*octets])?;
                let (octet, count) = octets.array_info()?;
                if !matches!(count, 4 | 16)
                    || !matches!(
                        octet.classify(),
                        TypeClass::Integer {
                            size: 1,
                            is_signed: false,
                            is_bool: false,
                            is_char: false,
                        }
                    )
                {
                    return None;
                }
                Some(DebugFormat::Known(KnownFormat::IpAddress { octets, offset }))
            }
            BundleFormat::Known(BundleKnownFormat::Vec {
                pointer,
                length,
                capacity,
                element,
            }) => {
                let (pointer, pointer_offset) = project(*self, pointer)?;
                pointer.pointer_target()?;
                let (length, length_offset) = project(*self, length)?;
                let (capacity, capacity_offset) = project(*self, capacity)?;
                Some(DebugFormat::Known(KnownFormat::Vec {
                    pointer_offset,
                    length,
                    length_offset,
                    capacity,
                    capacity_offset,
                    element: self.related_type(*element),
                }))
            }
            BundleFormat::Known(BundleKnownFormat::Str { pointer, length }) => {
                let (pointer, pointer_offset) = project(*self, &[*pointer])?;
                pointer.pointer_target()?;
                let (length, length_offset) = project(*self, &[*length])?;
                Some(DebugFormat::Known(KnownFormat::Str {
                    pointer_offset,
                    length,
                    length_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::String {
                pointer,
                length,
                capacity,
            }) => {
                let (pointer, pointer_offset) = project(*self, pointer)?;
                pointer.pointer_target()?;
                let (length, length_offset) = project(*self, length)?;
                let (capacity, capacity_offset) = project(*self, capacity)?;
                Some(DebugFormat::Known(KnownFormat::String {
                    pointer_offset,
                    length,
                    length_offset,
                    capacity,
                    capacity_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::BTreeMap {
                root,
                length,
                root_node,
                height,
                node,
                key,
                value,
                leaf,
                leaf_len,
                leaf_keys,
                leaf_values,
                internal,
                internal_data: _,
                internal_edges,
                edge: edge_path,
            }) => {
                let (root, root_offset) = project(*self, &[*root])?;
                let (some, some_offset) = root.variant("Some")?;
                let (root_node, root_node_offset) = project(some, root_node)?;
                let (length, length_offset) = project(*self, &[*length])?;
                let (height, height_offset) = project(root_node, &[*height])?;
                let (node, node_offset) = project(root_node, node)?;
                node.pointer_target()?;

                let key = self.related_type(*key);
                let value = self.related_type(*value);
                let leaf = self.related_type(*leaf);
                let (leaf_len, leaf_len_offset) = project(leaf, &[*leaf_len])?;
                let (keys, keys_offset) = project(leaf, &[*leaf_keys])?;
                let (key_slot, key_slots) = keys.array_info()?;
                if key_slot.size() != key.size() {
                    return None;
                }
                let (values, values_offset) = project(leaf, &[*leaf_values])?;
                let (value_slot, value_slots) = values.array_info()?;
                if value_slot.size() != value.size() || value_slots != key_slots {
                    return None;
                }

                let internal = self.related_type(*internal);
                let (edges, edges_offset) = project(internal, &[*internal_edges])?;
                let (edge, edge_slots) = edges.array_info()?;
                if edge_slots != key_slots + 1 {
                    return None;
                }
                let (edge_pointer, edge_pointer_offset) = project(edge, edge_path)?;
                edge_pointer.pointer_target()?;

                Some(DebugFormat::Known(KnownFormat::BTreeMap {
                    root,
                    root_offset,
                    root_node,
                    root_node_offset: root_offset
                        .checked_add(some_offset)?
                        .checked_add(root_node_offset)?,
                    length,
                    length_offset,
                    height,
                    height_offset,
                    node_offset,
                    key,
                    value,
                    leaf,
                    leaf_len,
                    leaf_len_offset,
                    keys_offset,
                    key_slots,
                    values_offset,
                    internal,
                    edges_offset,
                    edge,
                    edge_pointer_offset,
                }))
            }
        }
    }

    fn size_by_name(&self, name: &str) -> Option<u64> {
        BundleType::size_by_name(self, name)
    }

    fn type_by_name(&self, name: &str) -> Option<Self> {
        BundleType::type_by_name(self, name)
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
    const DYN_TRAIT: BundleTypeId = BundleTypeId(21);
    const DYN_TRAIT_PTR: BundleTypeId = BundleTypeId(22);
    const RAW_WAKER_VTABLE: BundleTypeId = BundleTypeId(23);
    const FUNCTION_TARGET: BundleTypeId = BundleTypeId(24);
    const FUNCTION_PTR: BundleTypeId = BundleTypeId(25);
    const BTREE_MAP: BundleTypeId = BundleTypeId(26);
    const BTREE_ROOT: BundleTypeId = BundleTypeId(27);
    const BTREE_NODE_REF: BundleTypeId = BundleTypeId(28);
    const BTREE_LEAF_PTR: BundleTypeId = BundleTypeId(29);
    const BTREE_LEAF: BundleTypeId = BundleTypeId(30);
    const MAYBE_U32: BundleTypeId = BundleTypeId(31);
    const BTREE_SLOTS: BundleTypeId = BundleTypeId(32);
    const BTREE_INTERNAL: BundleTypeId = BundleTypeId(33);
    const BTREE_EDGES: BundleTypeId = BundleTypeId(34);
    const IPV4_OCTETS: BundleTypeId = BundleTypeId(35);
    const IPV4: BundleTypeId = BundleTypeId(36);
    const IPV6_OCTETS: BundleTypeId = BundleTypeId(37);
    const IPV6: BundleTypeId = BundleTypeId(38);
    const U8_PTR: BundleTypeId = BundleTypeId(39);
    const VEC: BundleTypeId = BundleTypeId(40);
    const STR: BundleTypeId = BundleTypeId(41);
    const STRING: BundleTypeId = BundleTypeId(42);

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
        let (fatn, pointern, vtablen) = (s("FatPtr"), s("pointer"), s("vtable"));
        let dyn_traitn = s("dyn app::Trait");
        let raw_waker_vtablen = s("core::task::wake::RawWakerVTable");
        let unresolvedn = s("<unresolved>");
        let (clonen, waken, wake_by_refn, dropn) =
            (s("clone"), s("wake"), s("wake_by_ref"), s("drop"));
        let (atomicn, storagen, vn) = (s("Atomic<u32>"), s("AtomicStorage<u32>"), s("v"));
        let atomic_ptrn = s("Atomic<*mut Point>");
        let (loom_atomicn, loom_celln, tuple0n) =
            (s("AtomicU32"), s("LoomUnsafeCell<Point>"), s("__0"));
        let btree_mapn = s("alloc::collections::btree::map::BTreeMap<u32, u32>");
        let btree_rootn = s("Option<NodeRef>");
        let btree_node_refn = s("NodeRef");
        let btree_leafn = s("LeafNode");
        let maybe_u32n = s("MaybeUninit<u32>");
        let btree_internaln = s("InternalNode");
        let (rootn, lengthn, heightn, noden2, lenn, keysn, valsn, datan, edgesn) = (
            s("root"),
            s("length"),
            s("height"),
            s("node"),
            s("len"),
            s("keys"),
            s("vals"),
            s("data"),
            s("edges"),
        );
        let (uninitn, some2n, none2n) = (s("uninit"), s("Some"), s("None"));
        let (ipv4n, ipv6n, octetsn) = (
            s("core::net::ip_addr::Ipv4Addr"),
            s("core::net::ip_addr::Ipv6Addr"),
            s("octets"),
        );
        let (vecn, ptrn, vec_lenn, capacityn) =
            (s("alloc::vec::Vec<u32>"), s("ptr"), s("len"), s("capacity"));
        let (strn, stringn, data_ptrn, length2n) =
            (s("&str"), s("alloc::string::String"), s("data_ptr"), s("length"));

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
            TypeDef::Struct {
                name: fatn,
                size: 16,
                members: vec![m(pointern, DYN_TRAIT_PTR, 0), m(vtablen, VTABLE_PTR, 8)],
            },
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
            TypeDef::Struct { name: dyn_traitn, size: 0, members: vec![] },
            TypeDef::Pointer { name: None, target: DYN_TRAIT },
            TypeDef::Struct {
                name: raw_waker_vtablen,
                size: 32,
                members: vec![
                    m(clonen, PTR, 0),
                    m(waken, PTR, 8),
                    m(wake_by_refn, PTR, 16),
                    m(dropn, PTR, 24),
                ],
            },
            TypeDef::Opaque { name: unresolvedn, size: None },
            TypeDef::Pointer { name: None, target: FUNCTION_TARGET },
            TypeDef::Struct {
                name: btree_mapn,
                size: 24,
                members: vec![m(rootn, BTREE_ROOT, 0), m(lengthn, U64, 16)],
            },
            TypeDef::Enum {
                name: btree_rootn,
                size: 16,
                shape: VariantShape {
                    discr: Some(DiscrDef { offset: 0, ty: U64 }),
                    variants: vec![
                        VariantDef {
                            name: none2n,
                            discr_values: tag(0),
                            payload: m(none2n, UNIT, 0),
                            decl: None,
                        },
                        VariantDef {
                            name: some2n,
                            discr_values: None,
                            payload: m(some2n, BTREE_NODE_REF, 0),
                            decl: None,
                        },
                    ],
                },
            },
            TypeDef::Struct {
                name: btree_node_refn,
                size: 16,
                members: vec![m(noden2, BTREE_LEAF_PTR, 0), m(heightn, U64, 8)],
            },
            TypeDef::Pointer { name: None, target: BTREE_LEAF },
            TypeDef::Struct {
                name: btree_leafn,
                size: 20,
                members: vec![
                    m(lenn, U8, 0),
                    m(keysn, BTREE_SLOTS, 4),
                    m(valsn, BTREE_SLOTS, 12),
                ],
            },
            TypeDef::Union {
                name: maybe_u32n,
                size: 4,
                members: vec![m(uninitn, UNIT, 0), m(valuen, U32, 0)],
            },
            TypeDef::Array { elem: MAYBE_U32, count: 2 },
            TypeDef::Struct {
                name: btree_internaln,
                size: 48,
                members: vec![m(datan, BTREE_LEAF, 0), m(edgesn, BTREE_EDGES, 24)],
            },
            TypeDef::Array { elem: BTREE_LEAF_PTR, count: 3 },
            TypeDef::Array { elem: U8, count: 4 },
            TypeDef::Struct {
                name: ipv4n,
                size: 4,
                members: vec![m(octetsn, IPV4_OCTETS, 0)],
            },
            TypeDef::Array { elem: U8, count: 16 },
            TypeDef::Struct {
                name: ipv6n,
                size: 16,
                members: vec![m(octetsn, IPV6_OCTETS, 0)],
            },
            TypeDef::Pointer { name: None, target: U8 },
            TypeDef::Struct {
                name: vecn,
                size: 24,
                members: vec![
                    m(ptrn, U8_PTR, 0),
                    m(vec_lenn, U64, 8),
                    m(capacityn, U64, 16),
                ],
            },
            TypeDef::Struct {
                name: strn,
                size: 16,
                members: vec![m(data_ptrn, U8_PTR, 0), m(length2n, U64, 8)],
            },
            TypeDef::Struct {
                name: stringn,
                size: 24,
                members: vec![
                    m(ptrn, U8_PTR, 0),
                    m(vec_lenn, U64, 8),
                    m(capacityn, U64, 16),
                ],
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
                ), (
                    FAT_PTR,
                    BundleDebugFormat::Known(BundleKnownFormat::DynPointer {
                        pointer: 0,
                        vtable: 1,
                        drop_in_place: 0,
                        size: 1,
                        align: 2,
                        tail_offset: 0,
                    }),
                ), (
                    RAW_WAKER_VTABLE,
                    BundleDebugFormat::Known(BundleKnownFormat::RawWakerVTable {
                        clone: 0,
                        wake: 1,
                        wake_by_ref: 2,
                        drop: 3,
                    }),
                ), (
                    FUNCTION_PTR,
                    BundleDebugFormat::Known(BundleKnownFormat::FunctionPointer),
                ), (
                    BTREE_MAP,
                    BundleDebugFormat::Known(BundleKnownFormat::BTreeMap {
                        root: 0,
                        length: 1,
                        root_node: vec![],
                        height: 1,
                        node: vec![0],
                        key: U32,
                        value: U32,
                        leaf: BTREE_LEAF,
                        leaf_len: 0,
                        leaf_keys: 1,
                        leaf_values: 2,
                        internal: BTREE_INTERNAL,
                        internal_data: 0,
                        internal_edges: 1,
                        edge: vec![],
                    }),
                ), (
                    IPV4,
                    BundleDebugFormat::Known(BundleKnownFormat::IpAddress { octets: 0 }),
                ), (
                    IPV6,
                    BundleDebugFormat::Known(BundleKnownFormat::IpAddress { octets: 0 }),
                ), (
                    VEC,
                    BundleDebugFormat::Known(BundleKnownFormat::Vec {
                        pointer: vec![0],
                        length: vec![1],
                        capacity: vec![2],
                        element: U32,
                    }),
                ), (
                    STR,
                    BundleDebugFormat::Known(BundleKnownFormat::Str {
                        pointer: 0,
                        length: 1,
                    }),
                ), (
                    STRING,
                    BundleDebugFormat::Known(BundleKnownFormat::String {
                        pointer: vec![0],
                        length: vec![1],
                        capacity: vec![2],
                    }),
                )]),
                name_index: vec![(pointn, POINT)],
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
                raw_waker_vtable: RAW_WAKER_VTABLE,
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
    fn test_ip_addresses_use_standard_notation() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ipv4 = [192, 0, 2, 1];
        assert_eq!(
            format!("{}", TypeInfoRef::new(v.ty(IPV4).unwrap(), 0, &ipv4).display()),
            "192.0.2.1"
        );

        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            format!("{}", TypeInfoRef::new(v.ty(IPV6).unwrap(), 0, &ipv6).display()),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_vec_displays_initialized_elements() {
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x2000);
                assert_eq!(len, 12);
                Ok([5u32, 8, 13].into_iter().flat_map(u32::to_le_bytes).collect())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x2000u64, 3, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display_from_target(&Reader, 8)), "[5, 8, 13]");
        assert_eq!(
            format!("{:#}", value.display_from_target(&Reader, 8)),
            "[\n    5,\n    8,\n    13,\n]"
        );

        let invalid: Vec<u8> = [0x2000u64, 5, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &invalid);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "<invalid Vec: length exceeds capacity>"
        );
    }

    #[test]
    fn test_str_and_string_display_quoted_utf8() {
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                let bytes: &[u8] = match addr {
                    0x3000 => b"hi\nthere",
                    0x4000 => b"owned\ttext",
                    _ => panic!("unexpected address 0x{addr:x}"),
                };
                assert_eq!(len, bytes.len() as u64);
                Ok(bytes.to_vec())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let str_bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(STR).unwrap(), 0, &str_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "\"hi\\nthere\""
        );

        let string_bytes: Vec<u8> = [0x4000u64, 10, 16]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(STRING).unwrap(), 0, &string_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "\"owned\\ttext\""
        );
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
    fn test_integer_arrays_display_as_zero_padded_hex() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let bytes: Vec<u8> = [1u32, 0xabcdef, u32::MAX]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let array = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", array.display()),
            "[0x00000001, 0x00abcdef, 0xffffffff]"
        );

        let bytes: Vec<u8> = [1u64, 0xabcdef, u64::MAX]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let array = TypeInfoRef::new(v.ty(VTABLE_ARRAY).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", array.display()),
            "[0x0000000000000001, 0x0000000000abcdef, 0xffffffffffffffff]"
        );
        assert_eq!(
            format!("{:#}", array.display()),
            "[\n    0x0000000000000001,\n    0x0000000000abcdef,\n    0xffffffffffffffff,\n]"
        );
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
    fn test_dyn_pointer_formats_unknown_concrete_type() {
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
        let bytes: Vec<u8> = [0x1234u64, 0x3000].into_iter().flat_map(u64::to_le_bytes).collect();
        let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert_eq!(
            shown,
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1234,\n",
                "    concrete type: <unknown>,\n",
                "    vtable: {\n",
                "        drop_in_place: 0x2c557a0,\n",
                "        size: 152,\n",
                "        align: 8,\n",
                "    },\n",
                "}"
            )
        );
    }

    #[test]
    fn test_dyn_pointer_infers_concrete_type_from_method_with_null_drop() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                match addr {
                    0x1234 => Ok([1u32, 2].into_iter().flat_map(u32::to_le_bytes).collect()),
                    0x3000 => Ok([0u64, 8, 8, 0x4000]
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect()),
                    _ => Err(crate::Error::invalid_addr(addr)),
                }
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                (addr == 0x4000).then(|| "<Point as app::Trait>::run".to_owned())
            }
        }

        let mut b = test_bundle();
        let TypeDef::Array { count, .. } = &mut b.types.types[VTABLE_ARRAY.0 as usize] else {
            panic!("vtable is not an array");
        };
        *count = 4;
        b.validate().expect("expanded vtable must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000].into_iter().flat_map(u64::to_le_bytes).collect();
        let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(
            shown.contains(
                "pointer: 0x1234 -> Point {\n         x: 1,\n         y: 2,\n    },"
            ),
            "{shown}"
        );
        assert!(shown.contains("concrete type: Point,"), "{shown}");
        assert!(shown.contains("drop_in_place: 0x0,"), "{shown}");
        assert!(
            shown.contains("method[3]: 0x4000 -> <Point as app::Trait>::run,"),
            "{shown}"
        );
    }

    #[test]
    fn test_dyn_pointer_format_is_preserved_in_enum_payload() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x3000);
                Ok([0u64, 8, 8]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect())
            }
        }

        let mut b = test_bundle();
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 16;
        shape.variants[1].payload.ty = FAT_PTR;
        b.validate().expect("modified enum bundle must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000].into_iter().flat_map(u64::to_le_bytes).collect();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(shown.starts_with("Opt::Some {"), "{shown}");
        assert!(!shown.contains("FatPtr"), "{shown}");
        assert!(shown.contains("concrete type: <unknown>,"), "{shown}");
    }

    #[test]
    fn test_str_payload_in_enum_renders_as_value() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x3000);
                assert_eq!(len, 8);
                Ok(b"hi\nthere".to_vec())
            }
        }

        // Point Opt::Some's payload at a `&str`; its `Str` display format
        // must win over dumping the fat pointer's raw fields, matching how a
        // `Cow<str>::Borrowed` key should read.
        let mut b = test_bundle();
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 16;
        shape.variants[1].payload.ty = STR;
        b.validate().expect("modified enum bundle must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x3000u64, 8].into_iter().flat_map(u64::to_le_bytes).collect();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "Opt::Some(\"hi\\nthere\")"
        );
    }

    #[test]
    fn test_raw_waker_vtable_resolves_function_symbols() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("function pointer at {addr:#x} must not be dereferenced")
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                match addr {
                    0x1000 => Some("tokio::runtime::task::waker::clone_waker".to_owned()),
                    0x2000 => Some("tokio::runtime::task::waker::wake_by_val".to_owned()),
                    0x3000 => Some("tokio::runtime::task::waker::wake_by_ref".to_owned()),
                    0x4000 => Some("tokio::runtime::task::waker::drop_waker".to_owned()),
                    _ => None,
                }
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1000u64, 0x2000, 0x3000, 0x4000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(RAW_WAKER_VTABLE).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert_eq!(
            shown,
            concat!(
                "core::task::wake::RawWakerVTable {\n",
                "    clone: 0x1000 -> tokio::runtime::task::waker::clone_waker,\n",
                "    wake: 0x2000 -> tokio::runtime::task::waker::wake_by_val,\n",
                "    wake_by_ref: 0x3000 -> tokio::runtime::task::waker::wake_by_ref,\n",
                "    drop: 0x4000 -> tokio::runtime::task::waker::drop_waker,\n",
                "}"
            )
        );
    }

    #[test]
    fn test_function_pointer_resolves_symbol_without_dereference() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("function pointer at {addr:#x} must not be dereferenced")
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                (addr == 0x5000).then(|| "app::callback".to_owned())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x5000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "0x5000 -> app::callback"
        );
        assert_eq!(format!("{}", value.display()), "0x5000");

        let null = 0u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &null);
        assert_eq!(format!("{}", value.display_from_target(&Reader, 8)), "null");
    }

    #[test]
    fn test_btree_map_displays_only_initialized_slots_in_order() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                let mut bytes = vec![0xaa; len as usize];
                match addr {
                    0x1000 => {
                        bytes[0] = 1;
                        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
                        bytes[12..16].copy_from_slice(&20u32.to_le_bytes());
                        bytes[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
                        bytes[32..40].copy_from_slice(&0x3000u64.to_le_bytes());
                    }
                    0x2000 => {
                        bytes[0] = 1;
                        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
                        bytes[12..16].copy_from_slice(&10u32.to_le_bytes());
                    }
                    0x3000 => {
                        bytes[0] = 1;
                        bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
                        bytes[12..16].copy_from_slice(&30u32.to_le_bytes());
                    }
                    _ => return Err(crate::Error::invalid_addr(addr)),
                }
                Ok(bytes)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&3u64.to_le_bytes());
        let value = TypeInfoRef::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);

        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "alloc::collections::btree::map::BTreeMap<u32, u32> { 1: 10, 2: 20, 3: 30 }"
        );
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(shown.contains("\n    1: 10,"), "{shown}");
        assert!(shown.contains("\n    2: 20,"), "{shown}");
        assert!(shown.contains("\n    3: 30,"), "{shown}");
        assert!(!shown.contains("2863311530"), "unused 0xaa slots leaked: {shown}");
    }
}

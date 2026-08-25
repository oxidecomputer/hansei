//! Read-only structural view over a loaded [`Bundle`].
//!
//! [`BundleType`] is a `Copy` handle borrowing from the loaded bundle.
//! Everything here is backend-side structure plus the variant decoding that
//! makes `active_variant` a direct decode with no heuristics.

use crate::Encoding;
use crate::schema::{
    Bundle, BundleTypeId, MemberDef, Provenance, SymbolLookup, TaskEntryId, TypeDef, VariantDef,
    VariantShape,
};

use std::fmt;

/// The pointer width of bundle targets. Bundles describe illumos amd64
/// binaries; if that ever changes this becomes a `Meta` field.
pub const POINTER_SIZE: u64 = 8;

/// Placeholder name for types the debug info leaves anonymous.
const ANON: &str = "<anon>";

/// A type's coarse kind, collapsing every [`TypeDef`] spelling onto the
/// handful of shapes a consumer distinguishes.
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

/// A type's kind with the detail that displaying a value of it needs.
/// Consumers match on this rather than on [`TypeDef`].
pub enum TypeClass<'a> {
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
    Pointer { target: BundleType<'a> },
    /// A fixed-size array.
    Array { element: BundleType<'a>, count: u64 },
    /// A plain struct — display its fields.
    Struct,
    /// A plain union — hex dump.
    Union,
    /// A Rust discriminated enum — use [`BundleType::active_variant`] for
    /// display.
    RustEnum,
    /// A C-style enum (named integer constants).
    CEnum,
    /// Opaque / unknown — hex dump.
    Opaque,
}

/// A read-only view over a loaded [`Bundle`].
#[derive(Copy, Clone)]
pub struct BundleView<'a> {
    bundle: &'a Bundle,
}

impl<'a> BundleView<'a> {
    pub fn new(bundle: &'a Bundle) -> Self {
        Self { bundle }
    }

    pub fn bundle(&self) -> &'a Bundle {
        self.bundle
    }

    /// Get a type handle by id.
    pub fn ty(&self, id: BundleTypeId) -> Option<BundleType<'a>> {
        self.bundle.types.get(id).map(|_| BundleType {
            bundle: self.bundle,
            id,
        })
    }

    /// All types whose fully-qualified name is exactly `name`.
    pub fn find_by_name(&self, name: &'a str) -> impl Iterator<Item = BundleType<'a>> + 'a {
        let bundle = self.bundle;
        bundle
            .types
            .find_by_name(&bundle.strings, name)
            .map(move |id| BundleType { bundle, id })
    }

    /// Every named type in the bundle, in name order.
    ///
    /// The index carries one entry per id, so a name recorded under
    /// several ids — identical instantiations from different CUs — is
    /// yielded once per id.
    pub fn named_types(&self) -> impl Iterator<Item = (&'a str, BundleType<'a>)> + 'a {
        let bundle = self.bundle;
        bundle
            .types
            .name_index
            .iter()
            .filter_map(move |&(r, id)| Some((bundle.strings.get(r)?, BundleType { bundle, id })))
    }

    /// Resolve a task symbol without discarding semantic ambiguity.
    pub fn task_ids_for_symbol(&self, symbol: &str) -> SymbolLookup<TaskEntryId> {
        self.bundle.tasks.lookup_id(symbol)
    }

    /// Source provenance for a task entry.
    pub fn provenance(&self, id: TaskEntryId) -> Option<&'a Provenance> {
        self.bundle.provenance.entries.get(id.0 as usize)
    }

    /// Resolve an interned string.
    pub fn str(&self, r: crate::strings::StrRef) -> Option<&'a str> {
        self.bundle.strings.get(r)
    }

    /// Resolve a dyn-future symbol without discarding semantic ambiguity.
    pub fn dyn_future_ids_for_symbol(&self, symbol: &str) -> SymbolLookup<BundleTypeId> {
        self.bundle.dyn_futures.lookup_id(symbol)
    }

    /// Every type extraction found a `<T as Future>::poll` impl for.
    ///
    /// The dyn-future table is keyed by symbol because resolving a trait
    /// object asks "which type is this vtable's"; this is the same table
    /// read the other way, as the set of types that implement `Future`.
    /// A consumer that needs to ask repeatedly should collect it once.
    ///
    /// It is a *floor*, not a census: a `poll` rustc inlined away
    /// entirely leaves no symbol and so no entry, which is why a caller
    /// must degrade rather than conclude a missing type is not a future.
    pub fn future_type_ids(&self) -> impl Iterator<Item = BundleTypeId> + 'a {
        let table = &self.bundle.dyn_futures;
        table
            .by_symbol
            .values()
            .copied()
            .chain(table.by_normalized_symbol.values().flatten().copied())
    }
}

impl fmt::Debug for BundleView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleView")
            .field("types", &self.bundle.types.types.len())
            .field("tasks", &self.bundle.tasks.entries.len())
            .finish()
    }
}

/// A type in a loaded bundle: a `Copy` handle borrowing from it.
#[derive(Copy, Clone)]
pub struct BundleType<'a> {
    bundle: &'a Bundle,
    id: BundleTypeId,
}

impl PartialEq for BundleType<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.bundle, other.bundle) && self.id == other.id
    }
}

impl Eq for BundleType<'_> {}

impl<'a> BundleType<'a> {
    pub fn id(&self) -> BundleTypeId {
        self.id
    }

    /// The unique size associated with a fully-qualified type name in this
    /// bundle. Duplicate DIEs with the same layout are benign; conflicting
    /// sizes make the lookup ambiguous.
    pub fn size_by_name(&self, name: &str) -> Option<u64> {
        let mut sizes = self
            .bundle
            .types
            .find_by_normalized_name(&self.bundle.strings, name)
            .map(|id| self.at(id).size());
        let size = sizes.next()?;
        sizes.all(|candidate| candidate == size).then_some(size)
    }

    /// Resolve a vtable function symbol against the bundle's glue
    /// table ([`crate::GlueTypeTable`]): the vtable join's fallback for
    /// dyn-erased concrete types whose demangled spelling matches no
    /// DWARF type name. Exact key first, then the normalized form —
    /// the target's symbols carry its own build's crate
    /// disambiguators, and only the normalized key joins across
    /// builds, the task table's precedent. Anything but a unique
    /// answer is a decline, never a pick.
    pub fn glue_ids_for_symbol(&self, symbol: &str) -> SymbolLookup<BundleTypeId> {
        self.bundle.glue_types.lookup_id(symbol)
    }

    /// The unique type associated with a fully-qualified name in this
    /// bundle. Conflicting same-named layouts make the lookup ambiguous.
    pub fn type_by_name(&self, name: &str) -> Option<BundleType<'a>> {
        let mut ids = self
            .bundle
            .types
            .find_by_normalized_name(&self.bundle.strings, name);
        let id = ids.next()?;
        ids.all(|candidate| candidate == id).then(|| self.at(id))
    }

    /// The underlying definition.
    ///
    /// Panics if the id is out of range, which cannot happen for bundles
    /// that passed [`Bundle::validate`] (load always validates).
    pub fn def(&self) -> &'a TypeDef {
        self.bundle
            .types
            .get(self.id)
            .expect("BundleTypeId out of range in validated bundle")
    }

    /// Custom display instructions resolved from this type's DWARF at
    /// extraction time.
    pub fn debug_format(&self) -> Option<&'a crate::DisplayNode> {
        let types = &self.bundle.types;
        let (positions, nodes) = types.format_index.0.get_or_init(|| {
            let mut positions = vec![u32::MAX; types.types.len()];
            let mut nodes = Vec::with_capacity(types.debug_formats.len());
            for (id, node) in &types.debug_formats {
                positions[id.0 as usize] = nodes.len() as u32;
                nodes.push(node.clone());
            }
            (positions, nodes)
        });
        // Out-of-range ids and the no-format sentinel both fall out here.
        nodes.get(*positions.get(self.id.0 as usize)? as usize)
    }

    /// Resolve another type id from the same validated bundle.
    pub fn related_type(&self, id: BundleTypeId) -> BundleType<'a> {
        self.at(id)
    }

    /// Return a named Rust enum variant's payload type and byte offset,
    /// without examining a value of the enum.
    pub fn variant(&self, name: &str) -> Option<(BundleType<'a>, u64)> {
        let shape = self.variant_shape()?;
        let variant = shape
            .variants
            .iter()
            .find(|variant| self.str(variant.name) == name)?;
        Some((self.at(variant.payload.ty), variant.payload.offset))
    }

    fn at(&self, id: BundleTypeId) -> BundleType<'a> {
        BundleType {
            bundle: self.bundle,
            id,
        }
    }

    fn str(&self, r: crate::strings::StrRef) -> &'a str {
        self.bundle.strings.get(r).unwrap_or(ANON)
    }

    /// Resolve an interned string ref against this type's bundle. Used by
    /// consumers (reify) to read the labels carried in a `ScalarDecode` table.
    pub fn resolve_str(&self, r: crate::strings::StrRef) -> &'a str {
        self.str(r)
    }

    /// The type's fully-qualified name, or a placeholder for anonymous
    /// pointer/array types.
    pub fn name(&self) -> &'a str {
        match self.def() {
            TypeDef::Base { name, .. }
            | TypeDef::Struct { name, .. }
            | TypeDef::Union { name, .. }
            | TypeDef::Enum { name, .. }
            | TypeDef::CEnum { name, .. }
            | TypeDef::Opaque { name, .. } => self.str(*name),
            TypeDef::Pointer { name, .. } => name.map(|n| self.str(n)).unwrap_or(ANON),
            TypeDef::Array { .. } => ANON,
        }
    }

    /// The type's size in bytes.
    pub fn size(&self) -> u64 {
        match self.def() {
            TypeDef::Base { size, .. }
            | TypeDef::Struct { size, .. }
            | TypeDef::Union { size, .. }
            | TypeDef::Enum { size, .. }
            | TypeDef::CEnum { size, .. } => *size,
            TypeDef::Pointer { .. } => POINTER_SIZE,
            TypeDef::Array { elem, count } => self.at(*elem).size() * count,
            TypeDef::Opaque { size, .. } => size.unwrap_or(0),
        }
    }

    /// The type's coarse kind — the shape a consumer switches on before it
    /// needs the detail [`classify`](BundleType::classify) carries.
    pub fn kind(&self) -> TypeKind {
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

    /// The type's kind together with everything displaying a value of it
    /// needs: an integer's signedness, a pointer's target, an array's element
    /// and count.
    pub fn classify(&self) -> TypeClass<'a> {
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

    /// Whether this type's display program renders it as a self-contained
    /// value that must not be unwrapped into its representation (a `Str`, a
    /// `Slice`, a `Map`, …). A transparent `Alias` program (an atomic, a
    /// newtype wrapper) is *not* a leaf — it renders as an inner member — so
    /// a consumer peeling wrappers keeps descending through it.
    pub fn is_display_leaf(&self) -> bool {
        matches!(
            self.debug_format(),
            Some(node) if !matches!(node, crate::DisplayNode::Alias { .. })
        )
    }

    /// The members of a struct or union; empty for other kinds (Rust enum
    /// payloads are reached through [`BundleType::active_variant`]).
    pub fn members(&self) -> BundleMemberIter<'a> {
        let members: &'a [MemberDef] = match self.def() {
            TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
            _ => &[],
        };
        BundleMemberIter {
            bundle: self.bundle,
            members,
            index: 0,
        }
    }

    /// Look up a struct/union member by name.
    pub fn member(&self, name: &str) -> Option<BundleMember<'a>> {
        self.members().find(|m| m.name() == name)
    }

    /// If this is a pointer, the type it points to.
    pub fn pointer_target(&self) -> Option<BundleType<'a>> {
        match self.def() {
            TypeDef::Pointer { target, .. } => Some(self.at(*target)),
            _ => None,
        }
    }

    /// If this is an array, `(element_type, count)`.
    pub fn array_info(&self) -> Option<(BundleType<'a>, u64)> {
        match self.def() {
            TypeDef::Array { elem, count } => Some((self.at(*elem), *count)),
            _ => None,
        }
    }

    /// The variant shape, if this is a Rust enum.
    pub fn variant_shape(&self) -> Option<&'a VariantShape> {
        match self.def() {
            TypeDef::Enum { shape, .. } => Some(shape),
            _ => None,
        }
    }

    /// Every variant of a Rust enum, in the order the debug info lists
    /// them; empty for other kinds.
    ///
    /// This reads the *type*, so no value is needed: for a coroutine
    /// state machine the variants are the future's suspend points, and
    /// this is how a caller enumerates every place it can park rather
    /// than only the one it is parked at. Note that a variant's payload
    /// can only be *read* when it is the active one — every variant
    /// shares the same storage.
    pub fn variants(&self) -> impl Iterator<Item = BundleVariant<'a>> + 'a {
        let me = *self;
        let variants: &'a [VariantDef] = match self.def() {
            TypeDef::Enum { shape, .. } => &shape.variants,
            _ => &[],
        };
        variants.iter().map(move |v| me.variant_of(v))
    }

    /// Whether this type is a coroutine state machine — an `async fn` or
    /// `async block` environment.
    ///
    /// rustc numbers a coroutine's variant members ("0", "1", …) and
    /// carries the state name on the payload struct, which is what tells
    /// them apart from an ordinary Rust enum whose variants are named in
    /// place. Only for these are [`BundleType::variants`] suspend points.
    pub fn is_coroutine(&self) -> bool {
        let Some(shape) = self.variant_shape() else {
            return false;
        };
        !shape.variants.is_empty()
            && shape.variants.iter().all(|v| {
                let name = self.str(v.name);
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())
            })
    }

    fn variant_of(&self, def: &'a VariantDef) -> BundleVariant<'a> {
        BundleVariant {
            name: self.str(def.name),
            ty: self.at(def.payload.ty),
            offset: def.payload.offset,
            decl: def
                .decl
                .and_then(|loc| Some((self.bundle.strings.get(loc.file)?, loc.line))),
            await_site: def
                .await_site
                .and_then(|loc| Some((self.bundle.strings.get(loc.file)?, loc.line))),
        }
    }

    /// If this is a Rust enum, decode which variant `bytes` holds.
    ///
    /// This is a direct decode of the explicit [`VariantShape`]: read the
    /// discriminant's raw bits at its recorded offset, match them against
    /// each variant's explicit values/ranges, and otherwise select the
    /// default (niche) variant. No heuristics.
    pub fn active_variant(&self, bytes: &[u8]) -> Option<Result<ActiveVariant<'a>, VariantError>> {
        let shape = self.variant_shape()?;
        Some(self.decode_variant(shape, bytes))
    }

    /// If this is a Rust enum, check whether the variant called `name` is
    /// the active one; returns its payload type and offset if so.
    pub fn check_variant(
        &self,
        bytes: &[u8],
        name: &str,
    ) -> Option<Result<Option<(BundleType<'a>, u64)>, VariantError>> {
        let shape = self.variant_shape()?;
        // An unknown variant name is a caller error, not "inactive".
        if !shape.variants.iter().any(|v| self.str(v.name) == name) {
            return Some(Err(VariantError::NoSuchVariant));
        }
        Some(
            self.decode_variant(shape, bytes)
                .map(|active| (active.name == name).then_some((active.ty, active.offset))),
        )
    }

    /// If this is a trait-object wide pointer (`&dyn Trait`,
    /// `Box<dyn Trait>`), decompose it into its data-pointer and vtable
    /// members.
    ///
    /// rustc's debuginfo spells every wide pointer as a struct with a
    /// `pointer` member targeting the unsized `dyn Trait` type itself
    /// (named `(dyn …)`) and a `vtable` member (`&[usize; N]`). The
    /// vtable's *contents* live in the target binary; only the member
    /// offsets come from here.
    pub fn dyn_pointer(&self) -> Option<DynPointer<'a>> {
        if !matches!(self.def(), TypeDef::Struct { .. }) {
            return None;
        }
        let data = self.member("pointer")?;
        let vtable = self.member("vtable")?;
        vtable.ty().pointer_target()?;
        let pointee = data.ty().pointer_target()?;
        let name = pointee.name();
        if !(name.starts_with("dyn ") || name.starts_with("(dyn ")) {
            return None;
        }
        Some(DynPointer {
            data_offset: data.offset(),
            vtable_offset: vtable.offset(),
            pointee,
        })
    }

    fn decode_variant(
        &self,
        shape: &'a VariantShape,
        bytes: &[u8],
    ) -> Result<ActiveVariant<'a>, VariantError> {
        let selected: &'a VariantDef = match &shape.discr {
            None => {
                // Univariant: no discriminant to read.
                match shape.variants.as_slice() {
                    [v] => v,
                    [] => return Err(VariantError::Uninhabited),
                    _ => return Err(VariantError::MissingDiscriminant),
                }
            }
            Some(discr) => {
                let size = self.at(discr.ty).size() as usize;
                if !matches!(size, 1 | 2 | 4 | 8 | 16) {
                    return Err(VariantError::BadDiscriminantSize { size });
                }
                let start = discr.offset as usize;
                let raw_bytes =
                    bytes
                        .get(start..start + size)
                        .ok_or(VariantError::ShortBuffer {
                            needed: start + size,
                            len: bytes.len(),
                        })?;
                // The discriminant's raw bits, zero-extended: DiscrValues
                // store the same representation (see schema docs).
                let mut raw: u128 = 0;
                for (i, b) in raw_bytes.iter().enumerate() {
                    raw |= (*b as u128) << (8 * i);
                }

                shape
                    .variants
                    .iter()
                    .find(|v| v.discr_values.as_ref().is_some_and(|dv| dv.matches(raw)))
                    .or_else(|| {
                        // No explicit value matched: the default (niche)
                        // variant, if any, is active.
                        shape.variants.iter().find(|v| v.discr_values.is_none())
                    })
                    .ok_or(VariantError::NoVariantMatch { raw })?
            }
        };

        Ok(self.variant_of(selected))
    }
}

impl fmt::Debug for BundleType<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleType")
            .field("id", &self.id.0)
            .field("name", &self.name())
            .finish()
    }
}

/// One variant of a Rust enum, resolved against the bundle.
#[derive(Copy, Clone, Debug)]
pub struct BundleVariant<'a> {
    /// The variant's name.
    pub name: &'a str,
    /// The variant's payload type.
    pub ty: BundleType<'a>,
    /// The payload's byte offset within the enum.
    pub offset: u64,
    /// The variant member's declaration coordinates — for coroutine
    /// suspend states, the awaited expression's source file and line.
    pub decl: Option<(&'a str, u32)>,
    /// Where a suspend point's await is written, when extraction found
    /// that `decl` names the macro it expanded from instead.
    pub await_site: Option<(&'a str, u32)>,
}

/// The result of decoding a Rust enum's discriminant: the one variant of
/// [`BundleType::variants`] that a value actually holds, and so the only
/// one whose payload bytes mean anything.
pub type ActiveVariant<'a> = BundleVariant<'a>;

impl<'a> BundleVariant<'a> {
    /// The variant's human-readable name.
    pub fn state_name(&self) -> &'a str {
        variant_name(self.name, self.ty)
    }

    /// Where a coroutine suspend point's await sits in source: the place
    /// it is written, falling back to the coordinates the variant member
    /// carries when nothing better was recovered.
    pub fn await_loc(&self) -> Option<(&'a str, u32)> {
        self.await_site.or(self.decl)
    }
}

/// The human-readable name of the variant a `(member name, payload type)`
/// pair describes.
///
/// Coroutine state machines number their variant members ("0", "1", …) and
/// carry the state name (`Unresumed`, `SuspendN`, …) on the payload struct
/// instead; ordinary enums name the variant member itself. Numbered
/// variants resolve to the payload name's trailing path segment.
pub fn variant_name<'a>(member: &'a str, payload: BundleType<'a>) -> &'a str {
    if !member.is_empty() && !member.bytes().all(|b| b.is_ascii_digit()) {
        return member;
    }
    match payload.name().rsplit("::").next() {
        Some(seg) if !seg.is_empty() && seg != ANON => seg,
        _ => member,
    }
}

/// A trait-object wide pointer decomposed into its parts.
#[derive(Copy, Clone, Debug)]
pub struct DynPointer<'a> {
    /// Byte offset of the data pointer within the wide-pointer struct.
    pub data_offset: u64,
    /// Byte offset of the vtable pointer.
    pub vtable_offset: u64,
    /// The unsized `dyn Trait` type the data pointer targets (display
    /// only — its layout is a zero-sized placeholder).
    pub pointee: BundleType<'a>,
}

/// Why a variant decode failed. The reify backend maps these onto
/// `reify::Error`; they exist separately so the decode logic (and its
/// tests) live with the format.
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum VariantError {
    #[error("buffer too short for discriminant: need {needed} bytes, have {len}")]
    ShortBuffer { needed: usize, len: usize },
    #[error("discriminant value {raw:#x} matches no variant")]
    NoVariantMatch { raw: u128 },
    #[error("no variant with the requested name")]
    NoSuchVariant,
    #[error("enum has no variants")]
    Uninhabited,
    #[error("multiple variants but no discriminant recorded")]
    MissingDiscriminant,
    #[error("unsupported discriminant size {size}")]
    BadDiscriminantSize { size: usize },
}

/// A struct/union member, resolved against the bundle.
#[derive(Copy, Clone)]
pub struct BundleMember<'a> {
    bundle: &'a Bundle,
    def: &'a MemberDef,
}

impl<'a> BundleMember<'a> {
    pub fn name(&self) -> &'a str {
        self.bundle.strings.get(self.def.name).unwrap_or(ANON)
    }

    pub fn ty(&self) -> BundleType<'a> {
        BundleType {
            bundle: self.bundle,
            id: self.def.ty,
        }
    }

    pub fn offset(&self) -> u64 {
        self.def.offset
    }
}

impl fmt::Debug for BundleMember<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleMember")
            .field("name", &self.name())
            .field("offset", &self.offset())
            .finish()
    }
}

/// Iterator over a type's members.
#[derive(Clone)]
pub struct BundleMemberIter<'a> {
    bundle: &'a Bundle,
    members: &'a [MemberDef],
    index: usize,
}

impl<'a> Iterator for BundleMemberIter<'a> {
    type Item = BundleMember<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let def = self.members.get(self.index)?;
        self.index += 1;
        Some(BundleMember {
            bundle: self.bundle,
            def,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.members.len() - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for BundleMemberIter<'_> {}

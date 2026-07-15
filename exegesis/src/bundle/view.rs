//! Read-only structural view over a loaded [`Bundle`].
//!
//! [`BundleType`] is the bundle-backed analogue of `durin::read::CtfType`:
//! a `Copy` handle borrowing from the loaded bundle. The `reify::DebugType`
//! implementation lives in `reify` (mirroring the reify→durin dependency
//! for CTF); everything here is backend-side structure plus the variant
//! decoding that makes `active_variant` a direct decode with no heuristics.

use crate::bundle::schema::{
    Bundle, BundleTypeId, MemberDef, Provenance, TaskEntryId, TaskFutureEntry, TypeDef, VariantDef,
    SymbolLookup, VariantShape,
};
use crate::raw_types::Encoding;

use std::fmt;

/// The pointer width of bundle targets. Bundles describe illumos amd64
/// binaries; if that ever changes this becomes a `Meta` field.
pub const POINTER_SIZE: u64 = 8;

/// Placeholder name for types the debug info leaves anonymous.
const ANON: &str = "<anon>";

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

    /// Look up a task vtable-fn symbol (as read from the target's symtab)
    /// in the task join table.
    pub fn task_for_symbol(&self, symbol: &str) -> Option<&'a TaskFutureEntry> {
        self.bundle.tasks.lookup(symbol)
    }

    /// Like [`BundleView::task_for_symbol`], but also returns the entry id,
    /// which indexes the parallel [`Provenance`] table.
    pub fn task_entry_for_symbol(
        &self,
        symbol: &str,
    ) -> Option<(TaskEntryId, &'a TaskFutureEntry)> {
        let SymbolLookup::Unique(id) = self.bundle.tasks.lookup_id(symbol) else { return None };
        let entry = self.bundle.tasks.entries.get(id.0 as usize)?;
        Some((id, entry))
    }

    /// Source provenance for a task entry.
    pub fn provenance(&self, id: TaskEntryId) -> Option<&'a Provenance> {
        self.bundle.provenance.entries.get(id.0 as usize)
    }

    /// Resolve an interned string.
    pub fn str(&self, r: crate::bundle::strings::StrRef) -> Option<&'a str> {
        self.bundle.strings.get(r)
    }

    /// Look up a dyn-future symbol (`<T as Future>::poll` or
    /// `drop_glue::<T>`) and return `T`.
    pub fn dyn_future_for_symbol(&self, symbol: &str) -> Option<BundleType<'a>> {
        let id = self.bundle.dyn_futures.lookup(symbol)?;
        self.ty(id)
    }

    /// Resolve a dyn-future symbol without discarding semantic ambiguity.
    pub fn dyn_future_ids_for_symbol(&self, symbol: &str) -> SymbolLookup<BundleTypeId> {
        self.bundle.dyn_futures.lookup_id(symbol)
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

/// A type in a loaded bundle: the bundle-backed analogue of `CtfType`.
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

    fn at(&self, id: BundleTypeId) -> BundleType<'a> {
        BundleType {
            bundle: self.bundle,
            id,
        }
    }

    fn str(&self, r: crate::bundle::strings::StrRef) -> &'a str {
        self.bundle.strings.get(r).unwrap_or(ANON)
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

    /// The base-type encoding, if this is a base type.
    pub fn encoding(&self) -> Option<Encoding> {
        match self.def() {
            TypeDef::Base { encoding, .. } => Some(*encoding),
            _ => None,
        }
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
        // An unknown variant name is an error, not "inactive" — matching
        // the CTF backend's behavior.
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
    /// offsets come from here (§3.5).
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

        Ok(ActiveVariant {
            name: self.str(selected.name),
            ty: self.at(selected.payload.ty),
            offset: selected.payload.offset,
            decl: selected
                .decl
                .and_then(|loc| Some((self.bundle.strings.get(loc.file)?, loc.line))),
        })
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

/// The result of decoding a Rust enum's discriminant.
#[derive(Copy, Clone, Debug)]
pub struct ActiveVariant<'a> {
    /// The active variant's name.
    pub name: &'a str,
    /// The variant's payload type.
    pub ty: BundleType<'a>,
    /// The payload's byte offset within the enum.
    pub offset: u64,
    /// The variant member's declaration coordinates — for coroutine
    /// suspend states, the awaited expression's source file and line
    /// (§13.5).
    pub decl: Option<(&'a str, u32)>,
}

impl<'a> ActiveVariant<'a> {
    /// The variant's human-readable name.
    ///
    /// Coroutine state machines number their variant members ("0", "1",
    /// …) and carry the state name (`Unresumed`, `SuspendN`, …) on the
    /// payload struct instead (§5.5); ordinary enums name the variant
    /// member itself. Numbered variants resolve to the payload name's
    /// trailing path segment.
    pub fn state_name(&self) -> &'a str {
        if !self.name.is_empty() && !self.name.bytes().all(|b| b.is_ascii_digit()) {
            return self.name;
        }
        match self.ty.name().rsplit("::").next() {
            Some(seg) if !seg.is_empty() && seg != ANON => seg,
            _ => self.name,
        }
    }
}

/// A trait-object wide pointer decomposed into its parts (§3.5).
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

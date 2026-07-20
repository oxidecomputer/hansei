//! Bundle framing and (de)serialization.
//!
//! On disk a bundle is a small uncompressed header — 8 magic bytes and a
//! little-endian u32 format version, so `file`-style sniffing and fast
//! rejection work without decompressing anything — followed by a single
//! zstd frame containing the postcard-encoded [`Bundle`].
//!
//! There is no cross-version compatibility: a bundle is read by the same
//! tool version that wrote it (`format_version` bumps freely).

use crate::bundle::schema::{
    Bundle, BundleTypeId, DisplayNode, Field, FieldRender, ScalarDecode, Selector, StaticsTable,
    Step, TypeDef, strip_llvm_suffix,
};
use crate::bundle::strings::StrRef;
use crate::symbols::normalized_value_index;

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Leading bytes of every bundle file.
pub const MAGIC: [u8; 8] = *b"exegesis";

/// The current bundle format version. Bump on any schema change, including
/// indirect ones (e.g. new [`crate::raw_types::Encoding`] variants).
pub const FORMAT_VERSION: u32 = 15;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("bundle i/o failed")]
    Io(#[from] std::io::Error),
    #[error("not a bundle file (bad magic)")]
    BadMagic,
    #[error("bundle format version {found} unsupported (this tool reads version {expected})")]
    VersionMismatch { found: u32, expected: u32 },
    #[error("failed to decode bundle payload")]
    Decode(#[source] postcard::Error),
    #[error("failed to encode bundle payload")]
    Encode(#[source] postcard::Error),
    #[error("corrupt bundle: {0}")]
    Corrupt(String),
}

/// What a resolved [`Selector`] is expected to land on. Each variant folds a
/// former open-coded post-walk check (`check_usize_format`,
/// `check_byte_pointer_format`, the inline state-byte / pointer-sized checks)
/// into one place.
enum Shape {
    /// A `usize`-sized unsigned base type: an atomic word, a length, a
    /// capacity, a permit count.
    Usize,
    /// A single unsigned byte: a parking_lot mutex state byte.
    StateByte,
    /// A single byte of any encoding: a boolean flag.
    Byte,
    /// A pointer to `u8`: a string/vec data pointer.
    BytePointer,
    /// Any type occupying exactly one pointer word: a niche-optimized
    /// `Option<NonNull<_>>` list head/next.
    PointerSized,
    /// Any pointer type.
    Pointer,
    /// Any array type.
    Array,
    /// No constraint on the landed type.
    Any,
}

/// Walk a [`Selector`] from `root`, returning the type it lands on.
///
/// [`Step::Member`] descends a struct/union member; [`Step::Deref`] follows a
/// pointer to its pointee. A cycle guard rejects a member run that revisits a
/// type (a nonsensical path); it resets across a `Deref`, since a legitimate
/// cross-pointer reach may re-enter a type (e.g. a linked-list node pointing
/// at its own type).
fn selector_target(
    bundle: &Bundle,
    root: BundleTypeId,
    sel: &Selector,
    what: &str,
) -> Result<BundleTypeId> {
    let mut current = root;
    let mut def = bundle.types.get(root).expect("root type validated before formats");
    let mut seen = vec![root];
    for (step, item) in sel.steps().iter().enumerate() {
        match item {
            Step::Member(member_index) => {
                let members = match def {
                    TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
                    _ => return Err(Error::Corrupt(format!(
                        "{what} for type {}: step {step} traverses a non-aggregate type", root.0))),
                };
                let member = members.get(*member_index as usize).ok_or_else(|| {
                    Error::Corrupt(format!(
                        "{what} for type {}: member index {member_index} out of range at step {step}",
                        root.0))
                })?;
                if seen.contains(&member.ty) {
                    return Err(Error::Corrupt(format!(
                        "{what} for type {} contains a type cycle at step {step}", root.0)));
                }
                seen.push(member.ty);
                current = member.ty;
                def = bundle.types.get(member.ty).expect("member type validated before formats");
            }
            Step::Deref => {
                let TypeDef::Pointer { target, .. } = def else {
                    return Err(Error::Corrupt(format!(
                        "{what} for type {}: step {step} dereferences a non-pointer type", root.0)));
                };
                current = *target;
                def = bundle.types.get(*target).expect("pointer target validated before formats");
                seen = vec![current];
            }
        }
    }
    Ok(current)
}

/// Resolve `sel` against `root` and check the landed type matches `expect`,
/// returning it. Rejects an empty selector: every formatter selector must
/// navigate at least one step away from the formatted value.
fn check_selector(
    bundle: &Bundle,
    root: BundleTypeId,
    sel: &Selector,
    expect: Shape,
    what: &str,
) -> Result<BundleTypeId> {
    if sel.is_empty() {
        return Err(Error::Corrupt(format!("{what} for type {} has an empty selector", root.0)));
    }
    let target = selector_target(bundle, root, sel, what)?;
    let landed = bundle.types.get(target);
    let ok = match expect {
        Shape::Usize => matches!(
            landed,
            Some(TypeDef::Base {
                size: crate::bundle::POINTER_SIZE,
                encoding: crate::raw_types::Encoding::Unsigned,
                ..
            })
        ),
        Shape::StateByte => matches!(
            landed,
            Some(TypeDef::Base {
                size: 1,
                encoding: crate::raw_types::Encoding::Unsigned,
                ..
            })
        ),
        Shape::Byte => matches!(landed, Some(TypeDef::Base { size: 1, .. })),
        Shape::BytePointer => matches!(
            landed,
            Some(TypeDef::Pointer { target, .. }) if matches!(
                bundle.types.get(*target),
                Some(TypeDef::Base {
                    size: 1,
                    encoding: crate::raw_types::Encoding::Unsigned,
                    ..
                })
            )
        ),
        Shape::PointerSized => {
            type_size(bundle, target, &mut Vec::new()) == Some(crate::bundle::POINTER_SIZE)
        }
        Shape::Pointer => matches!(landed, Some(TypeDef::Pointer { .. })),
        Shape::Array => matches!(landed, Some(TypeDef::Array { .. })),
        Shape::Any => true,
    };
    if !ok {
        return Err(Error::Corrupt(format!(
            "{what} for type {} lands on a type incompatible with the expected shape",
            root.0
        )));
    }
    Ok(target)
}

/// Validate a [`ScalarDecode`] table against a `word_bits`-wide word: every
/// label [`StrRef`] resolves, no two fields overlap, each field fits within the
/// word, and each `Enum` value fits its field. A malformed detector table
/// becomes a save/load-time error instead of garbage (or a panic) at render
/// time.
fn check_scalar_decode(
    bundle: &Bundle,
    decode: &ScalarDecode,
    word_bits: u8,
    what: &str,
) -> Result<()> {
    let corrupt = |msg: String| Err(Error::Corrupt(format!("{what}: {msg}")));
    let ScalarDecode::Bits(fields) = decode else {
        return Ok(());
    };
    if fields.is_empty() {
        return corrupt("Bits decode has no fields".into());
    }
    let mut covered: u64 = 0;
    for (i, field) in fields.iter().enumerate() {
        if bundle.strings.get(field.name).is_none() {
            return corrupt(format!("field {i} name string ref {} out of range", field.name.0));
        }
        if field.shift >= word_bits {
            return corrupt(format!(
                "field {i} shift {} is beyond the {word_bits}-bit word",
                field.shift
            ));
        }
        // `None` width means "all bits at and above `shift`".
        let width = match field.width {
            Some(w) => w.get(),
            None => word_bits - field.shift,
        };
        if u16::from(field.shift) + u16::from(width) > u16::from(word_bits) {
            return corrupt(format!(
                "field {i} (shift {}, width {width}) overflows the {word_bits}-bit word",
                field.shift
            ));
        }
        let value_mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
        let field_mask = value_mask << field.shift;
        if covered & field_mask != 0 {
            return corrupt(format!("field {i} overlaps an earlier field"));
        }
        covered |= field_mask;
        if let FieldRender::Enum(table) = &field.render {
            for (value, label) in table {
                if bundle.strings.get(*label).is_none() {
                    return corrupt(format!(
                        "field {i} enum label string ref {} out of range",
                        label.0
                    ));
                }
                if value & !value_mask != 0 {
                    return corrupt(format!(
                        "field {i} enum value {value} does not fit its {width}-bit field"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Recursively validate a [`DisplayNode`] tree rooted at type `scope` (the type
/// the node is rendered against): every [`Selector`] resolves to a compatible
/// shape, every referenced member index and type id is in range, and every
/// [`ScalarDecode`] table is well-formed for its word width. A malformed
/// detector tree becomes a save/load-time error rather than garbage at render.
fn check_node(bundle: &Bundle, scope: BundleTypeId, node: &DisplayNode, what: &str) -> Result<()> {
    let corrupt = |msg: String| Err(Error::Corrupt(format!("{what}: {msg}")));
    match node {
        DisplayNode::Scalar { at, decode } => {
            let landed = check_selector(bundle, scope, at, Shape::Any, what)?;
            let size = type_size(bundle, landed, &mut Vec::new())
                .ok_or_else(|| Error::Corrupt(format!("{what}: scalar lands on an unsized type")))?;
            if size == 0 || size > 8 {
                return corrupt(format!("scalar word size {size} is not in 1..=8 bytes"));
            }
            check_scalar_decode(bundle, decode, (size * 8) as u8, what)?;
        }
        DisplayNode::Struct { fields } => {
            let members = match bundle.types.get(scope) {
                Some(TypeDef::Struct { members, .. } | TypeDef::Union { members, .. }) => {
                    Some(members)
                }
                _ => None,
            };
            let member_in_range = |index: u32, kind: &str| {
                let members = members.ok_or_else(|| {
                    Error::Corrupt(format!(
                        "{what}: {kind} field on non-aggregate type {}",
                        scope.0
                    ))
                })?;
                if members.get(index as usize).is_none() {
                    return Err(Error::Corrupt(format!(
                        "{what}: {kind} member index {index} out of range"
                    )));
                }
                Ok(())
            };
            for (i, field) in fields.iter().enumerate() {
                match field {
                    Field::Member(index) => member_in_range(*index, "Member")?,
                    Field::Named { label, node } => {
                        if bundle.strings.get(*label).is_none() {
                            return corrupt(format!(
                                "field {i} label string ref {} out of range",
                                label.0
                            ));
                        }
                        check_node(bundle, scope, node, what)?;
                    }
                    Field::Override { index, node } => {
                        member_in_range(*index, "Override")?;
                        check_node(bundle, scope, node, what)?;
                    }
                }
            }
        }
        DisplayNode::List { head, next, node, node_ty } => {
            check_selector(bundle, scope, head, Shape::PointerSized, what)?;
            if bundle.types.get(*node_ty).is_none() {
                return corrupt(format!("list node type id {} out of range", node_ty.0));
            }
            check_selector(bundle, *node_ty, next, Shape::PointerSized, what)?;
            check_node(bundle, *node_ty, node, what)?;
        }
    }
    Ok(())
}

/// Bit width of a `usize` word, for [`check_scalar_decode`].
const USIZE_BITS: u8 = (crate::bundle::POINTER_SIZE * 8) as u8;
/// Bit width of a single state byte, for [`check_scalar_decode`].
const BYTE_BITS: u8 = 8;

fn type_size(bundle: &Bundle, id: BundleTypeId, seen: &mut Vec<BundleTypeId>) -> Option<u64> {
    if seen.contains(&id) {
        return None;
    }
    match bundle.types.get(id)? {
        TypeDef::Base { size, .. }
        | TypeDef::Struct { size, .. }
        | TypeDef::Union { size, .. }
        | TypeDef::Enum { size, .. }
        | TypeDef::CEnum { size, .. } => Some(*size),
        TypeDef::Pointer { .. } => Some(crate::bundle::POINTER_SIZE),
        TypeDef::Array { elem, count } => {
            seen.push(id);
            let size = type_size(bundle, *elem, seen)?.checked_mul(*count);
            seen.pop();
            size
        }
        TypeDef::Opaque { .. } => None,
    }
}

fn has_dyn_tail(bundle: &Bundle, id: BundleTypeId, seen: &mut Vec<BundleTypeId>) -> bool {
    if seen.len() >= 8 || seen.contains(&id) {
        return false;
    }
    let Some(def) = bundle.types.get(id) else {
        return false;
    };
    let name = match def {
        TypeDef::Struct { name, .. } | TypeDef::Opaque { name, .. } => {
            bundle.strings.get(*name)
        }
        _ => None,
    };
    if name.is_some_and(|name| name.starts_with("dyn ") || name.starts_with("(dyn ")) {
        return true;
    }
    let TypeDef::Struct { members, .. } = def else {
        return false;
    };
    let Some(tail) = members.last() else {
        return false;
    };
    seen.push(id);
    let found = has_dyn_tail(bundle, tail.ty, seen);
    seen.pop();
    found
}

impl Bundle {
    /// Serialize into `w`: header, then zstd-compressed postcard payload.
    ///
    /// Performs no validation, so tests can craft intentionally-broken
    /// bundles; use [`Bundle::save`] for the checked path.
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&FORMAT_VERSION.to_le_bytes())?;
        let payload = postcard::to_allocvec(self).map_err(Error::Encode)?;
        zstd::stream::copy_encode(payload.as_slice(), &mut w, zstd::DEFAULT_COMPRESSION_LEVEL)?;
        Ok(())
    }

    /// Validate and write the bundle to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut w = BufWriter::new(File::create(path)?);
        self.write_to(&mut w)?;
        w.flush()?;
        Ok(())
    }

    /// Deserialize a bundle from `r`, verifying framing, format version,
    /// and internal consistency ([`Bundle::validate`]).
    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut header = [0u8; MAGIC.len() + size_of::<u32>()];
        r.read_exact(&mut header)?;
        if header[..MAGIC.len()] != MAGIC {
            return Err(Error::BadMagic);
        }
        let found = u32::from_le_bytes(header[MAGIC.len()..].try_into().unwrap());
        if found != FORMAT_VERSION {
            return Err(Error::VersionMismatch { found, expected: FORMAT_VERSION });
        }
        let payload = zstd::stream::decode_all(r)?;
        let bundle: Bundle = postcard::from_bytes(&payload).map_err(Error::Decode)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Load a bundle from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        Self::read_from(BufReader::new(File::open(path)?))
    }

    /// Check every cross-reference in the bundle, so that readers may index
    /// tables without per-access bounds checks. A failure here means the
    /// bundle is corrupt or was produced by a buggy extractor; the error
    /// says which table and index.
    pub fn validate(&self) -> Result<()> {
        let corrupt = |msg: String| Err(Error::Corrupt(msg));

        if self.meta.format_version != FORMAT_VERSION {
            return corrupt(format!(
                "meta.format_version {} != framing version {FORMAT_VERSION}",
                self.meta.format_version
            ));
        }
        if !self.strings.is_well_formed() {
            return corrupt("string table offsets malformed".into());
        }

        let check_str = |what: &str, r: StrRef| match self.strings.get(r) {
            Some(_) => Ok(()),
            None => corrupt(format!("{what}: string ref {} out of range", r.0)),
        };
        let check_ty = |what: &str, id: BundleTypeId| {
            if (id.0 as usize) < self.types.types.len() {
                Ok(())
            } else {
                corrupt(format!("{what}: type id {} out of range", id.0))
            }
        };
        let check_member =
            |what: &str, m: &crate::bundle::schema::MemberDef| -> Result<()> {
                check_str(what, m.name)?;
                check_ty(what, m.ty)
            };

        for (i, def) in self.types.types.iter().enumerate() {
            let what = &format!("type {i}");
            match def {
                TypeDef::Base { name, .. } | TypeDef::Opaque { name, .. } => {
                    check_str(what, *name)?;
                }
                TypeDef::Pointer { name, target } => {
                    if let Some(name) = name {
                        check_str(what, *name)?;
                    }
                    check_ty(what, *target)?;
                }
                TypeDef::Array { elem, .. } => check_ty(what, *elem)?,
                TypeDef::Struct { name, members, .. }
                | TypeDef::Union { name, members, .. } => {
                    check_str(what, *name)?;
                    for m in members {
                        check_member(what, m)?;
                    }
                }
                TypeDef::Enum { name, shape, .. } => {
                    check_str(what, *name)?;
                    if let Some(d) = &shape.discr {
                        check_ty(what, d.ty)?;
                    }
                    for v in &shape.variants {
                        check_str(what, v.name)?;
                        check_member(what, &v.payload)?;
                        if let Some(loc) = &v.decl {
                            check_str(what, loc.file)?;
                        }
                    }
                }
                TypeDef::CEnum { name, repr, enumerators, .. } => {
                    check_str(what, *name)?;
                    check_ty(what, *repr)?;
                    for (ename, _) in enumerators {
                        check_str(what, *ename)?;
                    }
                }
            }
        }

        for (&id, format) in &self.types.debug_formats {
            check_ty("debug format", id)?;
            let def = self.types.get(id).expect("checked above");
            match format {
                crate::bundle::schema::DebugFormat::Transparent { member } => {
                    check_selector(self, id, member, Shape::Any, "transparent debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Atomic { value },
                ) => {
                    check_selector(self, id, value, Shape::Any, "atomic debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::FunctionPointer,
                ) => {
                    if !matches!(def, TypeDef::Pointer { .. }) {
                        return corrupt(format!(
                            "function-pointer debug format for type {} is not a pointer",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::DynPointer {
                        pointer,
                        vtable,
                        drop_in_place,
                        size,
                        align,
                        tail_offset: _,
                    },
                ) => {
                    let aggregate_members = match def {
                        TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
                        _ => {
                            return corrupt(format!(
                                "dyn-pointer debug format for type {} is not an aggregate",
                                id.0
                            ));
                        }
                    };
                    let data = aggregate_members.get(*pointer as usize).ok_or_else(|| {
                        Error::Corrupt(format!(
                            "dyn-pointer debug format for type {}: pointer member index {} out of range",
                            id.0, pointer
                        ))
                    })?;
                    let vtable_member = aggregate_members.get(*vtable as usize).ok_or_else(|| {
                        Error::Corrupt(format!(
                            "dyn-pointer debug format for type {}: vtable member index {} out of range",
                            id.0, vtable
                        ))
                    })?;
                    if pointer == vtable {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {} reuses one member",
                            id.0
                        ));
                    }
                    let data_target_id = match self.types.get(data.ty) {
                        Some(TypeDef::Pointer { target, .. }) => Some(*target),
                        _ => None,
                    };
                    if !data_target_id
                        .is_some_and(|target| has_dyn_tail(self, target, &mut Vec::new()))
                    {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {}: data member does not target dyn",
                            id.0
                        ));
                    }
                    let array = match self.types.get(vtable_member.ty) {
                        Some(TypeDef::Pointer { target, .. }) => self.types.get(*target),
                        _ => None,
                    };
                    let Some(TypeDef::Array { elem, count }) = array else {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {}: vtable member does not point to an array",
                            id.0
                        ));
                    };
                    let Some(TypeDef::Base { size: word_size, encoding, .. }) = self.types.get(*elem)
                    else {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {}: vtable element is not an integer",
                            id.0
                        ));
                    };
                    if *word_size != crate::bundle::POINTER_SIZE
                        || !matches!(encoding, crate::raw_types::Encoding::Unsigned)
                    {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {}: vtable element is not usize-sized",
                            id.0
                        ));
                    }
                    let slots = [*drop_in_place, *size, *align];
                    if slots.iter().any(|&slot| u64::from(slot) >= *count) {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {} has a header slot outside its {count}-entry vtable",
                            id.0
                        ));
                    }
                    if slots[0] == slots[1] || slots[0] == slots[2] || slots[1] == slots[2] {
                        return corrupt(format!(
                            "dyn-pointer debug format for type {} reuses a header slot",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::RawWakerVTable {
                        clone,
                        wake,
                        wake_by_ref,
                        drop,
                    },
                ) => {
                    let members = match def {
                        TypeDef::Struct { members, .. } => members,
                        _ => {
                            return corrupt(format!(
                                "RawWakerVTable debug format for type {} is not a struct",
                                id.0
                            ));
                        }
                    };
                    let fields = [*clone, *wake, *wake_by_ref, *drop];
                    for &field in &fields {
                        let Some(member) = members.get(field as usize) else {
                            return corrupt(format!(
                                "RawWakerVTable debug format for type {} has member index {field} out of range",
                                id.0
                            ));
                        };
                        if !matches!(self.types.get(member.ty), Some(TypeDef::Pointer { .. })) {
                            return corrupt(format!(
                                "RawWakerVTable debug format for type {} has a non-pointer member",
                                id.0
                            ));
                        }
                    }
                    if fields
                        .iter()
                        .enumerate()
                        .any(|(index, field)| fields[..index].contains(field))
                    {
                        return corrupt(format!(
                            "RawWakerVTable debug format for type {} reuses a member",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::RawMutex { state, state_decode },
                ) => {
                    check_selector(self, id, state, Shape::StateByte, "RawMutex state debug format")?;
                    check_scalar_decode(self, state_decode, BYTE_BITS, "RawMutex state decode")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Notify {
                        state,
                        state_decode,
                        mutex,
                        mutex_decode,
                        head,
                        waiter,
                        waiter_notification,
                        waiter_notification_decode,
                        waiter_next,
                    },
                ) => {
                    check_selector(self, id, state, Shape::Usize, "Notify state debug format")?;
                    check_scalar_decode(self, state_decode, USIZE_BITS, "Notify state decode")?;
                    // The waiter mutex's single state byte.
                    check_selector(self, id, mutex, Shape::StateByte, "Notify mutex debug format")?;
                    check_scalar_decode(self, mutex_decode, BYTE_BITS, "Notify mutex decode")?;
                    // `head` reaches the queue's head word, an
                    // `Option<NonNull<Waiter>>` niche-optimized to a pointer.
                    check_selector(self, id, head, Shape::PointerSized, "Notify head debug format")?;
                    // The `waiter_*` selectors are rooted at the `Waiter` node type.
                    check_ty("Notify waiter", *waiter)?;
                    check_selector(
                        self,
                        *waiter,
                        waiter_notification,
                        Shape::Usize,
                        "Notify waiter_notification debug format",
                    )?;
                    check_scalar_decode(
                        self,
                        waiter_notification_decode,
                        USIZE_BITS,
                        "Notify waiter_notification decode",
                    )?;
                    check_selector(
                        self,
                        *waiter,
                        waiter_next,
                        Shape::PointerSized,
                        "Notify waiter_next debug format",
                    )?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Semaphore { permits, permits_decode },
                ) => {
                    check_selector(self, id, permits, Shape::Usize, "Semaphore permits debug format")?;
                    check_scalar_decode(self, permits_decode, USIZE_BITS, "Semaphore permits decode")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::WatchState { state, state_decode },
                ) => {
                    check_selector(self, id, state, Shape::Usize, "WatchState state debug format")?;
                    check_scalar_decode(self, state_decode, USIZE_BITS, "WatchState state decode")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::MpscChan {
                        tail,
                        index,
                        head,
                        start_index,
                        next,
                        values,
                        element,
                    },
                ) => {
                    check_selector(self, id, tail, Shape::Usize, "MpscChan tail debug format")?;
                    check_selector(self, id, index, Shape::Usize, "MpscChan index debug format")?;
                    // `head` reaches a pointer to the block type; the remaining
                    // selectors are rooted there.
                    let head_ptr =
                        check_selector(self, id, head, Shape::Pointer, "MpscChan head debug format")?;
                    let Some(TypeDef::Pointer { target: block, .. }) = self.types.get(head_ptr)
                    else {
                        unreachable!("check_selector verified a pointer");
                    };
                    let block = *block;
                    check_selector(
                        self,
                        block,
                        start_index,
                        Shape::Usize,
                        "MpscChan start_index debug format",
                    )?;
                    check_selector(self, block, next, Shape::Pointer, "MpscChan next debug format")?;
                    check_selector(self, block, values, Shape::Array, "MpscChan values debug format")?;
                    check_ty("MpscChan element", *element)?;
                    if type_size(self, *element, &mut Vec::new()).is_none() {
                        return corrupt(format!(
                            "MpscChan debug format for type {} has an unsized element",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::MpscBlock { ready_slots, values },
                ) => {
                    check_selector(
                        self,
                        id,
                        ready_slots,
                        Shape::Usize,
                        "MpscBlock ready_slots debug format",
                    )?;
                    check_selector(self, id, values, Shape::Array, "MpscBlock values debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::MpscRx {
                        chan_pointer,
                        chan,
                        bound,
                        permits,
                        permits_decode,
                    },
                ) => {
                    // `chan_pointer` reaches the raw pointer inside the Arc; it
                    // targets the `ArcInner` allocation.
                    let ptr = check_selector(
                        self,
                        id,
                        chan_pointer,
                        Shape::Pointer,
                        "MpscRx chan_pointer debug format",
                    )?;
                    let Some(TypeDef::Pointer { target: arcinner, .. }) = self.types.get(ptr)
                    else {
                        unreachable!("check_selector verified a pointer");
                    };
                    // `chan` is rooted at the allocation and reaches the `Chan`;
                    // `bound` and `permits` are rooted at that `Chan`.
                    let chan_ty =
                        check_selector(self, *arcinner, chan, Shape::Any, "MpscRx chan debug format")?;
                    check_selector(self, chan_ty, bound, Shape::Usize, "MpscRx bound debug format")?;
                    check_selector(
                        self,
                        chan_ty,
                        permits,
                        Shape::Usize,
                        "MpscRx permits debug format",
                    )?;
                    check_scalar_decode(self, permits_decode, USIZE_BITS, "MpscRx permits decode")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::BoundedSemaphore {
                        mutex,
                        mutex_decode,
                        closed,
                        permits,
                        permits_decode,
                        bound,
                        head,
                        waiter,
                        waiter_state,
                        waiter_next,
                    },
                ) => {
                    // The waiter mutex's single state byte.
                    check_selector(self, id, mutex, Shape::StateByte, "BoundedSemaphore mutex debug format")?;
                    check_scalar_decode(self, mutex_decode, BYTE_BITS, "BoundedSemaphore mutex decode")?;
                    // The `Waitlist.closed` flag: a single byte.
                    check_selector(self, id, closed, Shape::Byte, "BoundedSemaphore closed debug format")?;
                    check_selector(self, id, permits, Shape::Usize, "BoundedSemaphore permits debug format")?;
                    check_scalar_decode(self, permits_decode, USIZE_BITS, "BoundedSemaphore permits decode")?;
                    check_selector(self, id, bound, Shape::Usize, "BoundedSemaphore bound debug format")?;
                    // `head` reaches the queue's head word, an
                    // `Option<NonNull<Waiter>>` niche-optimized to a pointer.
                    check_selector(self, id, head, Shape::PointerSized, "BoundedSemaphore head debug format")?;
                    // The `waiter_*` selectors are rooted at the `Waiter` node type.
                    check_ty("BoundedSemaphore waiter", *waiter)?;
                    check_selector(
                        self,
                        *waiter,
                        waiter_state,
                        Shape::Usize,
                        "BoundedSemaphore waiter_state debug format",
                    )?;
                    check_selector(
                        self,
                        *waiter,
                        waiter_next,
                        Shape::PointerSized,
                        "BoundedSemaphore waiter_next debug format",
                    )?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::IpAddress { octets },
                ) => {
                    let target =
                        check_selector(self, id, octets, Shape::Array, "IP-address debug format")?;
                    let Some(TypeDef::Array { elem, count }) = self.types.get(target) else {
                        return corrupt(format!(
                            "IP-address debug format for type {} does not target an array",
                            id.0
                        ));
                    };
                    let Some(TypeDef::Base { size, encoding, .. }) = self.types.get(*elem) else {
                        return corrupt(format!(
                            "IP-address debug format for type {} does not contain base-type octets",
                            id.0
                        ));
                    };
                    if *size != 1
                        || !matches!(encoding, crate::raw_types::Encoding::Unsigned)
                        || !matches!(count, 4 | 16)
                    {
                        return corrupt(format!(
                            "IP-address debug format for type {} does not contain 4 or 16 u8 octets",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Vec {
                        pointer,
                        length,
                        capacity,
                        element,
                    },
                ) => {
                    check_ty("Vec element", *element)?;
                    if type_size(self, *element, &mut Vec::new()).is_none() {
                        return corrupt(format!(
                            "Vec debug format for type {} has an unsized element",
                            id.0
                        ));
                    }
                    check_selector(self, id, pointer, Shape::BytePointer, "Vec pointer debug format")?;
                    for (path, field) in [(length, "length"), (capacity, "capacity")] {
                        check_selector(self, id, path, Shape::Usize, &format!("Vec {field} debug format"))?;
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Str { pointer, length },
                ) => {
                    check_selector(self, id, pointer, Shape::BytePointer, "str pointer debug format")?;
                    check_selector(self, id, length, Shape::Usize, "str length debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::String {
                        pointer,
                        length,
                        capacity,
                    },
                ) => {
                    check_selector(self, id, pointer, Shape::BytePointer, "String pointer debug format")?;
                    check_selector(self, id, length, Shape::Usize, "String length debug format")?;
                    check_selector(self, id, capacity, Shape::Usize, "String capacity debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::BTreeMap {
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
                        internal_data,
                        internal_edges,
                        edge,
                    },
                ) => {
                    let map_members = match def {
                        TypeDef::Struct { members, .. } => members,
                        _ => {
                            return corrupt(format!(
                                "BTreeMap debug format for type {} is not a struct",
                                id.0
                            ));
                        }
                    };
                    let member = |index: u32, field: &str| {
                        map_members.get(index as usize).ok_or_else(|| {
                            Error::Corrupt(format!(
                                "BTreeMap debug format for type {}: {field} member index {index} out of range",
                                id.0
                            ))
                        })
                    };
                    let root_member = member(*root, "root")?;
                    let length_member = member(*length, "length")?;
                    if root == length {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} reuses root as length",
                            id.0
                        ));
                    }
                    let TypeDef::Enum { shape, .. } = self
                        .types
                        .get(root_member.ty)
                        .expect("member type validated before formats")
                    else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} has a non-enum root",
                            id.0
                        ));
                    };
                    let some = shape
                        .variants
                        .iter()
                        .find(|variant| self.strings.get(variant.name) == Some("Some"))
                        .ok_or_else(|| Error::Corrupt(format!(
                            "BTreeMap debug format for type {} root has no Some variant",
                            id.0
                        )))?;
                    let node_ref =
                        selector_target(self, some.payload.ty, root_node, "BTreeMap root-node path")?;
                    let node_ref_def = self.types.get(node_ref).expect("path type validated");
                    let TypeDef::Struct { members: node_members, .. } = node_ref_def else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} has a non-struct node ref",
                            id.0
                        ));
                    };
                    let height_member = node_members.get(*height as usize).ok_or_else(|| {
                        Error::Corrupt(format!(
                            "BTreeMap debug format for type {}: height member index {height} out of range",
                            id.0
                        ))
                    })?;
                    let node_pointer =
                        selector_target(self, node_ref, node, "BTreeMap node-pointer path")?;
                    if !matches!(self.types.get(node_pointer), Some(TypeDef::Pointer { target, .. }) if target == leaf)
                    {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} node path does not point to its leaf type",
                            id.0
                        ));
                    }

                    for (field, referenced) in [("key", *key), ("value", *value), ("leaf", *leaf), ("internal", *internal)] {
                        check_ty(&format!("BTreeMap debug format {} {field}", id.0), referenced)?;
                    }
                    let is_unsigned = |member_ty: BundleTypeId, max_size: u64| {
                        matches!(
                            self.types.get(member_ty),
                            Some(TypeDef::Base { size, encoding: crate::raw_types::Encoding::Unsigned, .. })
                                if *size > 0 && *size <= max_size
                        )
                    };
                    if !is_unsigned(length_member.ty, 8) || !is_unsigned(height_member.ty, 8) {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} has a non-integer length or height",
                            id.0
                        ));
                    }

                    let TypeDef::Struct { members: leaf_members, .. } =
                        self.types.get(*leaf).expect("leaf id checked")
                    else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} leaf is not a struct",
                            id.0
                        ));
                    };
                    let leaf_member = |index: u32, field: &str| {
                        leaf_members.get(index as usize).ok_or_else(|| Error::Corrupt(format!(
                            "BTreeMap debug format for type {}: leaf {field} member index {index} out of range",
                            id.0
                        )))
                    };
                    let len_member = leaf_member(*leaf_len, "len")?;
                    let keys_member = leaf_member(*leaf_keys, "keys")?;
                    let values_member = leaf_member(*leaf_values, "values")?;
                    if !is_unsigned(len_member.ty, 8) {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} has a non-integer leaf length",
                            id.0
                        ));
                    }
                    let Some(TypeDef::Array { elem: key_slot, count: key_slots }) =
                        self.types.get(keys_member.ty)
                    else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} keys are not an array",
                            id.0
                        ));
                    };
                    let Some(TypeDef::Array { elem: value_slot, count: value_slots }) =
                        self.types.get(values_member.ty)
                    else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} values are not an array",
                            id.0
                        ));
                    };
                    let key_sizes = (
                        type_size(self, *key_slot, &mut Vec::new()),
                        type_size(self, *key, &mut Vec::new()),
                    );
                    let value_sizes = (
                        type_size(self, *value_slot, &mut Vec::new()),
                        type_size(self, *value, &mut Vec::new()),
                    );
                    if *key_slots == 0
                        || key_slots != value_slots
                        || !matches!(key_sizes, (Some(slot), Some(value)) if slot == value)
                        || !matches!(value_sizes, (Some(slot), Some(value)) if slot == value)
                    {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} has incompatible key/value slots",
                            id.0
                        ));
                    }

                    let TypeDef::Struct { members: internal_members, .. } =
                        self.types.get(*internal).expect("internal id checked")
                    else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} internal node is not a struct",
                            id.0
                        ));
                    };
                    let data = internal_members.get(*internal_data as usize);
                    if !data.is_some_and(|member| member.offset == 0 && member.ty == *leaf) {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} internal data is not its leaf prefix",
                            id.0
                        ));
                    }
                    let edges_member = internal_members.get(*internal_edges as usize).ok_or_else(|| {
                        Error::Corrupt(format!(
                            "BTreeMap debug format for type {}: internal edges member index {internal_edges} out of range",
                            id.0
                        ))
                    })?;
                    let Some(TypeDef::Array { elem: edge_elem, count: edge_slots }) =
                        self.types.get(edges_member.ty)
                    else {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} edges are not an array",
                            id.0
                        ));
                    };
                    if *edge_slots != key_slots + 1 {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} has the wrong edge capacity",
                            id.0
                        ));
                    }
                    let edge_pointer =
                        selector_target(self, *edge_elem, edge, "BTreeMap edge-pointer path")?;
                    if !matches!(self.types.get(edge_pointer), Some(TypeDef::Pointer { target, .. }) if target == leaf)
                    {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} edge does not point to its leaf type",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Node(node) => {
                    check_node(self, id, node, "node debug format")?;
                }
            }
        }

        let mut prev: Option<&str> = None;
        for &(r, id) in &self.types.name_index {
            check_str("name index", r)?;
            check_ty("name index", id)?;
            let name = self.strings.get(r).unwrap();
            if prev.is_some_and(|p| p > name) {
                return corrupt(format!("name index not sorted at {name:?}"));
            }
            prev = Some(name);
        }

        for (sym, id) in &self.tasks.by_symbol {
            if sym != strip_llvm_suffix(sym) {
                return corrupt(format!("task table key {sym:?} has .llvm suffix"));
            }
            if (id.0 as usize) >= self.tasks.entries.len() {
                return corrupt(format!("task table: entry id {} out of range", id.0));
            }
        }
        for (sym, ids) in &self.tasks.by_normalized_symbol {
            if ids.is_empty() {
                return corrupt(format!("normalized task key {sym:?} has no entries"));
            }
            for id in ids {
                if (id.0 as usize) >= self.tasks.entries.len() {
                    return corrupt(format!("normalized task table: entry id {} out of range", id.0));
                }
            }
        }
        if self.tasks.by_normalized_symbol != normalized_value_index(&self.tasks.by_symbol) {
            return corrupt("normalized task table is inconsistent with raw symbols".to_owned());
        }
        for (i, e) in self.tasks.entries.iter().enumerate() {
            let what = &format!("task entry {i}");
            check_ty(what, e.future)?;
            check_ty(what, e.cell)?;
            check_ty(what, e.stage)?;
            check_ty(what, e.scheduler)?;
            check_str(what, e.display_name)?;
        }

        for (sym, id) in &self.dyn_futures.by_symbol {
            if sym != strip_llvm_suffix(sym) {
                return corrupt(format!("dyn future key {sym:?} has .llvm suffix"));
            }
            check_ty("dyn future table", *id)?;
        }
        for (sym, ids) in &self.dyn_futures.by_normalized_symbol {
            if ids.is_empty() {
                return corrupt(format!("normalized dyn future key {sym:?} has no entries"));
            }
            for id in ids {
                check_ty("normalized dyn future table", *id)?;
            }
        }
        if self.dyn_futures.by_normalized_symbol
            != normalized_value_index(&self.dyn_futures.by_symbol)
        {
            return corrupt(
                "normalized dyn future table is inconsistent with raw symbols".to_owned(),
            );
        }

        let StaticsTable { entries: _ } = &self.statics; // plain strings, nothing to check

        let infra = &self.infra;
        for (what, id) in [
            ("infra.header", infra.header),
            ("infra.vtable", infra.vtable),
            ("infra.trailer", infra.trailer),
            ("infra.context", infra.context),
            ("infra.scheduler_handle", infra.scheduler_handle),
            ("infra.mt_handle", infra.mt_handle),
            ("infra.location", infra.location),
            ("infra.raw_waker_vtable", infra.raw_waker_vtable),
        ] {
            check_ty(what, id)?;
        }

        if self.provenance.entries.len() != self.tasks.entries.len() {
            return corrupt(format!(
                "provenance has {} entries for {} task entries",
                self.provenance.entries.len(),
                self.tasks.entries.len()
            ));
        }
        for (i, p) in self.provenance.entries.iter().enumerate() {
            if let Some(loc) = &p.decl {
                check_str(&format!("provenance {i}"), loc.file)?;
            }
        }

        Ok(())
    }
}

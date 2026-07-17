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
    Bundle, BundleTypeId, StaticsTable, TypeDef, strip_llvm_suffix,
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
pub const FORMAT_VERSION: u32 = 11;

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

fn check_format_path<'a>(
    bundle: &'a Bundle,
    root: BundleTypeId,
    def: &'a TypeDef,
    path: &[u32],
    what: &str,
) -> Result<()> {
    format_path_target(bundle, root, def, path, what).map(|_| ())
}

fn format_path_target<'a>(
    bundle: &'a Bundle,
    root: BundleTypeId,
    mut def: &'a TypeDef,
    path: &[u32],
    what: &str,
) -> Result<BundleTypeId> {
    let mut seen = vec![root];
    let mut current = root;
    for (step, &member_index) in path.iter().enumerate() {
        let members = match def {
            TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
            _ => return Err(Error::Corrupt(format!(
                "{what} for type {}: step {step} traverses a non-aggregate type", root.0))),
        };
        let member = members.get(member_index as usize).ok_or_else(|| Error::Corrupt(format!(
            "{what} for type {}: member index {member_index} out of range at step {step}",
            root.0)))?;
        if seen.contains(&member.ty) {
            return Err(Error::Corrupt(format!(
                "{what} for type {} contains a type cycle at step {step}", root.0)));
        }
        seen.push(member.ty);
        current = member.ty;
        def = bundle.types.get(member.ty).expect("member type validated before formats");
    }
    Ok(current)
}

fn check_byte_pointer_format(
    bundle: &Bundle,
    root: BundleTypeId,
    def: &TypeDef,
    path: &[u32],
    what: &str,
) -> Result<()> {
    let pointer = format_path_target(bundle, root, def, path, what)?;
    let Some(TypeDef::Pointer { target, .. }) = bundle.types.get(pointer) else {
        return Err(Error::Corrupt(format!(
            "{what} for type {} does not end at a pointer",
            root.0
        )));
    };
    if !matches!(
        bundle.types.get(*target),
        Some(TypeDef::Base {
            size: 1,
            encoding: crate::raw_types::Encoding::Unsigned,
            ..
        })
    ) {
        return Err(Error::Corrupt(format!(
            "{what} for type {} does not target u8",
            root.0
        )));
    }
    Ok(())
}

fn check_usize_format(
    bundle: &Bundle,
    root: BundleTypeId,
    def: &TypeDef,
    path: &[u32],
    what: &str,
) -> Result<()> {
    let target = format_path_target(bundle, root, def, path, what)?;
    if !matches!(
        bundle.types.get(target),
        Some(TypeDef::Base {
            size: crate::bundle::POINTER_SIZE,
            encoding: crate::raw_types::Encoding::Unsigned,
            ..
        })
    ) {
        return Err(Error::Corrupt(format!(
            "{what} for type {} does not end at usize",
            root.0
        )));
    }
    Ok(())
}

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
                    check_format_path(self, id, def, &[*member], "transparent debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Atomic { value },
                ) => {
                    if value.is_empty() {
                        return corrupt(format!(
                            "atomic debug format for type {} has an empty member path", id.0));
                    }
                    check_format_path(self, id, def, value, "atomic debug format")?;
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
                    crate::bundle::schema::KnownFormat::RawMutex { state },
                ) => {
                    let target =
                        format_path_target(self, id, def, state, "RawMutex state debug format")?;
                    if !matches!(
                        self.types.get(target),
                        Some(TypeDef::Base {
                            size: 1,
                            encoding: crate::raw_types::Encoding::Unsigned,
                            ..
                        })
                    ) {
                        return corrupt(format!(
                            "RawMutex debug format for type {} does not end at a u8 state byte",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Notify { state },
                ) => {
                    if state.is_empty() {
                        return corrupt(format!(
                            "Notify debug format for type {} has an empty state path",
                            id.0
                        ));
                    }
                    check_usize_format(self, id, def, state, "Notify state debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Semaphore { permits },
                ) => {
                    if permits.is_empty() {
                        return corrupt(format!(
                            "Semaphore debug format for type {} has an empty permits path",
                            id.0
                        ));
                    }
                    check_usize_format(self, id, def, permits, "Semaphore permits debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::WatchState { state },
                ) => {
                    if state.is_empty() {
                        return corrupt(format!(
                            "WatchState debug format for type {} has an empty state path",
                            id.0
                        ));
                    }
                    check_usize_format(self, id, def, state, "WatchState state debug format")?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::MpscBlock { ready_slots, values, element },
                ) => {
                    if ready_slots.is_empty() || values.is_empty() {
                        return corrupt(format!(
                            "MpscBlock debug format for type {} has an empty path",
                            id.0
                        ));
                    }
                    check_usize_format(
                        self,
                        id,
                        def,
                        ready_slots,
                        "MpscBlock ready_slots debug format",
                    )?;
                    let array =
                        format_path_target(self, id, def, values, "MpscBlock values debug format")?;
                    if !matches!(self.types.get(array), Some(TypeDef::Array { .. })) {
                        return corrupt(format!(
                            "MpscBlock debug format for type {} values path does not end at an array",
                            id.0
                        ));
                    }
                    check_ty("MpscBlock element", *element)?;
                    if type_size(self, *element, &mut Vec::new()).is_none() {
                        return corrupt(format!(
                            "MpscBlock debug format for type {} has an unsized element",
                            id.0
                        ));
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::IpAddress { octets },
                ) => {
                    let target = format_path_target(
                        self,
                        id,
                        def,
                        &[*octets],
                        "IP-address debug format",
                    )?;
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
                    check_byte_pointer_format(
                        self,
                        id,
                        def,
                        pointer,
                        "Vec pointer debug format",
                    )?;
                    for (path, field) in [(length, "length"), (capacity, "capacity")] {
                        check_usize_format(
                            self,
                            id,
                            def,
                            path,
                            &format!("Vec {field} debug format"),
                        )?;
                    }
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::Str { pointer, length },
                ) => {
                    check_byte_pointer_format(
                        self,
                        id,
                        def,
                        &[*pointer],
                        "str pointer debug format",
                    )?;
                    check_usize_format(
                        self,
                        id,
                        def,
                        &[*length],
                        "str length debug format",
                    )?;
                }
                crate::bundle::schema::DebugFormat::Known(
                    crate::bundle::schema::KnownFormat::String {
                        pointer,
                        length,
                        capacity,
                    },
                ) => {
                    check_byte_pointer_format(
                        self,
                        id,
                        def,
                        pointer,
                        "String pointer debug format",
                    )?;
                    check_usize_format(
                        self,
                        id,
                        def,
                        length,
                        "String length debug format",
                    )?;
                    check_usize_format(
                        self,
                        id,
                        def,
                        capacity,
                        "String capacity debug format",
                    )?;
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
                    let some_def = self.types.get(some.payload.ty).expect("variant type validated");
                    let node_ref = format_path_target(
                        self,
                        some.payload.ty,
                        some_def,
                        root_node,
                        "BTreeMap root-node path",
                    )?;
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
                    let node_pointer = format_path_target(
                        self,
                        node_ref,
                        node_ref_def,
                        node,
                        "BTreeMap node-pointer path",
                    )?;
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
                    let edge_def = self.types.get(*edge_elem).expect("array elem validated");
                    let edge_pointer = format_path_target(
                        self,
                        *edge_elem,
                        edge_def,
                        edge,
                        "BTreeMap edge-pointer path",
                    )?;
                    if !matches!(self.types.get(edge_pointer), Some(TypeDef::Pointer { target, .. }) if target == leaf)
                    {
                        return corrupt(format!(
                            "BTreeMap debug format for type {} edge does not point to its leaf type",
                            id.0
                        ));
                    }
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

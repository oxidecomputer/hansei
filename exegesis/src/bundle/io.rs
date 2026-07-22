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
    Bundle, BundleTypeId, DisplayNode, Field, FieldRender, MapEntries, ScalarDecode, Selector,
    StaticsTable, Step, TypeDef, ValueExpr, strip_llvm_suffix,
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
pub const FORMAT_VERSION: u32 = 20;

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
    let mut def = bundle
        .types
        .get(root)
        .expect("root type validated before formats");
    let mut seen = vec![root];
    for (step, item) in sel.steps().iter().enumerate() {
        match item {
            Step::Member(member_index) => {
                let members = match def {
                    TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
                    _ => {
                        return Err(Error::Corrupt(format!(
                            "{what} for type {}: step {step} traverses a non-aggregate type",
                            root.0
                        )));
                    }
                };
                let member = members.get(*member_index as usize).ok_or_else(|| {
                    Error::Corrupt(format!(
                        "{what} for type {}: member index {member_index} out of range at step {step}",
                        root.0))
                })?;
                if seen.contains(&member.ty) {
                    return Err(Error::Corrupt(format!(
                        "{what} for type {} contains a type cycle at step {step}",
                        root.0
                    )));
                }
                seen.push(member.ty);
                current = member.ty;
                def = bundle
                    .types
                    .get(member.ty)
                    .expect("member type validated before formats");
            }
            Step::Deref => {
                let TypeDef::Pointer { target, .. } = def else {
                    return Err(Error::Corrupt(format!(
                        "{what} for type {}: step {step} dereferences a non-pointer type",
                        root.0
                    )));
                };
                current = *target;
                def = bundle
                    .types
                    .get(*target)
                    .expect("pointer target validated before formats");
                seen = vec![current];
            }
        }
    }
    Ok(current)
}

/// Resolve a selector that stays within one allocation to its byte offset.
/// Returns `None` for a pointer crossing, whose post-dereference offset is not
/// relative to the original value.
fn selector_offset(bundle: &Bundle, root: BundleTypeId, sel: &Selector) -> Option<u64> {
    let mut def = bundle.types.get(root)?;
    let mut offset = 0u64;
    for step in sel.steps() {
        let Step::Member(index) = step else {
            return None;
        };
        let members = match def {
            TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
            _ => return None,
        };
        let member = members.get(*index as usize)?;
        offset = offset.checked_add(member.offset)?;
        def = bundle.types.get(member.ty)?;
    }
    Some(offset)
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
        return Err(Error::Corrupt(format!(
            "{what} for type {} has an empty selector",
            root.0
        )));
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
            return corrupt(format!(
                "field {i} name string ref {} out of range",
                field.name.0
            ));
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
        let value_mask = if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
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
            let size = type_size(bundle, landed, &mut Vec::new()).ok_or_else(|| {
                Error::Corrupt(format!("{what}: scalar lands on an unsized type"))
            })?;
            if size == 0 || size > 8 {
                return corrupt(format!("scalar word size {size} is not in 1..=8 bytes"));
            }
            check_scalar_decode(bundle, decode, (size * 8) as u8, what)?;
        }
        DisplayNode::Symbol { at } => {
            // `at` may be empty (the value itself is the code pointer, as for a
            // bare function pointer), which `check_selector` forbids, so resolve
            // the landed type directly. A symbol is rendered from a pointer word
            // and never followed as data, so the target must be a pointer.
            let landed = selector_target(bundle, scope, at, what)?;
            if !matches!(bundle.types.get(landed), Some(TypeDef::Pointer { .. })) {
                return corrupt(format!(
                    "symbol node lands on type {} which is not a pointer",
                    landed.0
                ));
            }
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
        DisplayNode::List {
            head,
            next,
            node,
            node_ty,
        } => {
            check_selector(bundle, scope, head, Shape::PointerSized, what)?;
            if bundle.types.get(*node_ty).is_none() {
                return corrupt(format!("list node type id {} out of range", node_ty.0));
            }
            check_selector(bundle, *node_ty, next, Shape::PointerSized, what)?;
            check_node(bundle, *node_ty, node, what)?;
        }
        DisplayNode::Str {
            pointer,
            length,
            capacity,
        } => {
            check_selector(bundle, scope, pointer, Shape::BytePointer, what)?;
            check_selector(bundle, scope, length, Shape::Usize, what)?;
            if let Some(capacity) = capacity {
                check_selector(bundle, scope, capacity, Shape::Usize, what)?;
            }
        }
        DisplayNode::Slice {
            pointer,
            length,
            capacity,
            element,
        } => {
            if bundle.types.get(*element).is_none() {
                return corrupt(format!(
                    "slice node element type id {} out of range",
                    element.0
                ));
            }
            if type_size(bundle, *element, &mut Vec::new()).is_none() {
                return corrupt(format!(
                    "slice node has an unsized element type {}",
                    element.0
                ));
            }
            // A `Vec`'s pointer is byte-erased (`*u8`), but a `&[T]`/`Box<[T]>`
            // data pointer is typed (`*T`), so accept any pointer, not just a
            // byte pointer.
            check_selector(bundle, scope, pointer, Shape::Pointer, what)?;
            check_selector(bundle, scope, length, Shape::Usize, what)?;
            if let Some(capacity) = capacity {
                check_selector(bundle, scope, capacity, Shape::Usize, what)?;
            }
        }
        DisplayNode::IpAddr { octets } => {
            let target = check_selector(bundle, scope, octets, Shape::Array, what)?;
            let Some(TypeDef::Array { elem, count }) = bundle.types.get(target) else {
                return corrupt("IP-address octets do not target an array".to_string());
            };
            let Some(TypeDef::Base { size, encoding, .. }) = bundle.types.get(*elem) else {
                return corrupt("IP-address octets are not a base type".to_string());
            };
            if *size != 1
                || !matches!(encoding, crate::raw_types::Encoding::Unsigned)
                || !matches!(count, 4 | 16)
            {
                return corrupt("IP-address octets are not 4 or 16 unsigned bytes".to_string());
            }
        }
        DisplayNode::Alias {
            at,
            follow_pointers: _,
        } => {
            // The aliased value may have any type — an atomic peels to a plain
            // integer, a pointer, or a small struct — so only require that the
            // selector resolves.
            check_selector(bundle, scope, at, Shape::Any, what)?;
        }
        DisplayNode::SlotCount { bitmap, slots } => {
            // The readiness word is a `usize`; `slots` is the inline array
            // whose length bounds which of its bits count as slots.
            check_selector(bundle, scope, bitmap, Shape::Usize, what)?;
            check_selector(bundle, scope, slots, Shape::Array, what)?;
        }
        DisplayNode::Pointer { at, via, then } => {
            // `at` reaches the pointer; `via` is rooted at its pointee and
            // reaches the rendered target, against which `then` is rooted.
            let ptr = check_selector(bundle, scope, at, Shape::Pointer, what)?;
            let Some(TypeDef::Pointer {
                target: pointee, ..
            }) = bundle.types.get(ptr)
            else {
                unreachable!("check_selector verified a pointer");
            };
            let target = check_selector(bundle, *pointee, via, Shape::Any, what)?;
            check_node(bundle, target, then, what)?;
        }
        DisplayNode::DynPointer {
            pointer,
            vtable,
            drop_in_place,
            size,
            align,
            tail_offset: _,
        } => {
            if pointer == vtable {
                return corrupt("dyn pointer reuses one selector".to_string());
            }
            let data_ptr = check_selector(bundle, scope, pointer, Shape::Pointer, what)?;
            let Some(TypeDef::Pointer {
                target: data_target,
                ..
            }) = bundle.types.get(data_ptr)
            else {
                unreachable!("check_selector verified a pointer");
            };
            if !has_dyn_tail(bundle, *data_target, &mut Vec::new()) {
                return corrupt("dyn-pointer data selector does not target dyn".to_string());
            }

            let vtable_ptr = check_selector(bundle, scope, vtable, Shape::Pointer, what)?;
            let Some(TypeDef::Pointer {
                target: vtable_array,
                ..
            }) = bundle.types.get(vtable_ptr)
            else {
                unreachable!("check_selector verified a pointer");
            };
            let Some(TypeDef::Array { elem, count }) = bundle.types.get(*vtable_array) else {
                return corrupt(
                    "dyn-pointer vtable selector does not point to an array".to_string(),
                );
            };
            let Some(TypeDef::Base {
                size: word_size,
                encoding,
                ..
            }) = bundle.types.get(*elem)
            else {
                return corrupt("dyn-pointer vtable element is not an integer".to_string());
            };
            if *word_size != crate::bundle::POINTER_SIZE
                || !matches!(encoding, crate::raw_types::Encoding::Unsigned)
            {
                return corrupt("dyn-pointer vtable element is not usize-sized".to_string());
            }
            let slots = [*drop_in_place, *size, *align];
            if slots.iter().any(|&slot| u64::from(slot) >= *count) {
                return corrupt(format!(
                    "dyn pointer has a header slot outside its {count}-entry vtable"
                ));
            }
            if slots[0] == slots[1] || slots[0] == slots[2] || slots[1] == slots[2] {
                return corrupt("dyn pointer reuses a header slot".to_string());
            }
        }
        DisplayNode::MpscChan {
            tail,
            index,
            head,
            start_index,
            next,
            values,
            element,
        } => {
            check_selector(bundle, scope, tail, Shape::Usize, what)?;
            check_selector(bundle, scope, index, Shape::Usize, what)?;
            // `head` reaches a pointer to the block type; the remaining
            // selectors are rooted there.
            let head_ptr = check_selector(bundle, scope, head, Shape::Pointer, what)?;
            let Some(TypeDef::Pointer { target: block, .. }) = bundle.types.get(head_ptr) else {
                unreachable!("check_selector verified a pointer");
            };
            let block = *block;
            check_selector(bundle, block, start_index, Shape::Usize, what)?;
            check_selector(bundle, block, next, Shape::Pointer, what)?;
            check_selector(bundle, block, values, Shape::Array, what)?;
            if bundle.types.get(*element).is_none() {
                return corrupt(format!(
                    "MpscChan element type id {} out of range",
                    element.0
                ));
            }
            if type_size(bundle, *element, &mut Vec::new()).is_none() {
                return corrupt(format!(
                    "MpscChan has an unsized element type {}",
                    element.0
                ));
            }
        }
        DisplayNode::Map {
            length,
            key,
            value,
            entries,
        } => {
            check_selector(bundle, scope, length, Shape::Usize, what)?;
            let MapEntries::BTree { root, .. } = entries.as_ref();
            if root == length {
                return corrupt("B-tree map reuses root as length".to_string());
            }
            for (kind, ty) in [("key", *key), ("value", *value)] {
                if bundle.types.get(ty).is_none() {
                    return corrupt(format!("map {kind} type id {} out of range", ty.0));
                }
                if type_size(bundle, ty, &mut Vec::new()).is_none() {
                    return corrupt(format!("map has an unsized {kind} type {}", ty.0));
                }
            }
            check_map_entries(bundle, scope, *key, *value, entries, what)?;
        }
        DisplayNode::Variant {
            discriminant,
            arms,
            default,
        } => {
            check_value_expr(bundle, scope, discriminant, what)?;
            for (i, arm) in arms.iter().enumerate() {
                if let Some(label) = arm.label
                    && bundle.strings.get(label).is_none()
                {
                    return corrupt(format!(
                        "variant arm {i} label string ref {} out of range",
                        label.0
                    ));
                }
                if arm.label.is_none() && arm.payload.is_none() {
                    return corrupt(format!("variant arm {i} has neither a label nor a payload"));
                }
                if let Some(payload) = &arm.payload {
                    check_node(bundle, scope, payload, what)?;
                }
            }
            if let Some(default) = default {
                check_node(bundle, scope, default, what)?;
            }
        }
    }
    Ok(())
}

/// Validate a [`ValueExpr`] rooted at `scope`: every `Read` selector resolves
/// (crossing any [`Step::Deref`]) and lands on a machine word (≤ 8 bytes), and
/// every sub-expression is well-formed.
fn check_value_expr(
    bundle: &Bundle,
    scope: BundleTypeId,
    expr: &ValueExpr,
    what: &str,
) -> Result<()> {
    match expr {
        ValueExpr::Const(_) => Ok(()),
        ValueExpr::Read(sel) => {
            let target = check_selector(bundle, scope, sel, Shape::Any, what)?;
            match type_size(bundle, target, &mut Vec::new()) {
                Some(size) if size <= 8 => Ok(()),
                _ => Err(Error::Corrupt(format!(
                    "{what}: value-expression read does not land on a machine word"
                ))),
            }
        }
        ValueExpr::Not(inner) => check_value_expr(bundle, scope, inner, what),
        ValueExpr::And(a, b) | ValueExpr::Ne(a, b) => {
            check_value_expr(bundle, scope, a, what)?;
            check_value_expr(bundle, scope, b, what)
        }
    }
}

fn check_map_entries(
    bundle: &Bundle,
    scope: BundleTypeId,
    key: BundleTypeId,
    value: BundleTypeId,
    entries: &MapEntries,
    what: &str,
) -> Result<()> {
    let corrupt = |msg: String| Err(Error::Corrupt(format!("{what}: {msg}")));
    let MapEntries::BTree {
        root,
        root_node,
        height,
        node,
        leaf,
        leaf_len,
        leaf_keys,
        leaf_values,
        internal,
        internal_data,
        internal_edges,
        edge,
    } = entries;

    let root = check_selector(bundle, scope, root, Shape::Any, what)?;
    let Some(TypeDef::Enum { shape, .. }) = bundle.types.get(root) else {
        return corrupt("B-tree root is not an enum".to_string());
    };
    let some = shape
        .variants
        .iter()
        .find(|variant| bundle.strings.get(variant.name) == Some("Some"))
        .ok_or_else(|| Error::Corrupt(format!("{what}: B-tree root has no Some variant")))?;
    // The `Some` payload may itself be the node-reference type, and an edge
    // element may itself be the pointer, so these auxiliary-root selectors
    // intentionally permit an empty path.
    let node_ref = selector_target(bundle, some.payload.ty, root_node, what)?;
    let height_ty = check_selector(bundle, node_ref, height, Shape::Any, what)?;
    let node_ptr = check_selector(bundle, node_ref, node, Shape::Pointer, what)?;

    for (kind, ty) in [("leaf", *leaf), ("internal", *internal)] {
        if bundle.types.get(ty).is_none() {
            return corrupt(format!("B-tree {kind} type id {} out of range", ty.0));
        }
    }
    let is_unsigned = |ty| {
        matches!(
            bundle.types.get(ty),
            Some(TypeDef::Base {
                size,
                encoding: crate::raw_types::Encoding::Unsigned,
                ..
            }) if *size > 0 && *size <= 8
        )
    };
    if !is_unsigned(height_ty) {
        return corrupt("B-tree height is not an unsigned integer".to_string());
    }
    if !matches!(bundle.types.get(node_ptr), Some(TypeDef::Pointer { target, .. }) if target == leaf)
    {
        return corrupt("B-tree node selector does not point to its leaf type".to_string());
    }

    let len_ty = check_selector(bundle, *leaf, leaf_len, Shape::Any, what)?;
    if !is_unsigned(len_ty) {
        return corrupt("B-tree leaf length is not an unsigned integer".to_string());
    }
    let keys_ty = check_selector(bundle, *leaf, leaf_keys, Shape::Array, what)?;
    let values_ty = check_selector(bundle, *leaf, leaf_values, Shape::Array, what)?;
    let Some(TypeDef::Array {
        elem: key_slot,
        count: key_slots,
    }) = bundle.types.get(keys_ty)
    else {
        unreachable!("check_selector verified an array");
    };
    let Some(TypeDef::Array {
        elem: value_slot,
        count: value_slots,
    }) = bundle.types.get(values_ty)
    else {
        unreachable!("check_selector verified an array");
    };
    let key_sizes = (
        type_size(bundle, *key_slot, &mut Vec::new()),
        type_size(bundle, key, &mut Vec::new()),
    );
    let value_sizes = (
        type_size(bundle, *value_slot, &mut Vec::new()),
        type_size(bundle, value, &mut Vec::new()),
    );
    if *key_slots == 0
        || key_slots != value_slots
        || !matches!(key_sizes, (Some(slot), Some(value)) if slot == value)
        || !matches!(value_sizes, (Some(slot), Some(value)) if slot == value)
    {
        return corrupt("B-tree has incompatible key/value slots".to_string());
    }

    let data_ty = check_selector(bundle, *internal, internal_data, Shape::Any, what)?;
    if data_ty != *leaf || selector_offset(bundle, *internal, internal_data) != Some(0) {
        return corrupt("B-tree internal data is not its leaf prefix".to_string());
    }
    let edges_ty = check_selector(bundle, *internal, internal_edges, Shape::Array, what)?;
    let Some(TypeDef::Array {
        elem: edge_elem,
        count: edge_slots,
    }) = bundle.types.get(edges_ty)
    else {
        unreachable!("check_selector verified an array");
    };
    if *edge_slots != key_slots + 1 {
        return corrupt("B-tree has the wrong edge capacity".to_string());
    }
    let edge_ptr = selector_target(bundle, *edge_elem, edge, what)?;
    if !matches!(bundle.types.get(edge_ptr), Some(TypeDef::Pointer { target, .. }) if target == leaf)
    {
        return corrupt("B-tree edge does not point to its leaf type".to_string());
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
        TypeDef::Struct { name, .. } | TypeDef::Opaque { name, .. } => bundle.strings.get(*name),
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
            return Err(Error::VersionMismatch {
                found,
                expected: FORMAT_VERSION,
            });
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
        let check_member = |what: &str, m: &crate::bundle::schema::MemberDef| -> Result<()> {
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
                TypeDef::Struct { name, members, .. } | TypeDef::Union { name, members, .. } => {
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
                TypeDef::CEnum {
                    name,
                    repr,
                    enumerators,
                    ..
                } => {
                    check_str(what, *name)?;
                    check_ty(what, *repr)?;
                    for (ename, _) in enumerators {
                        check_str(what, *ename)?;
                    }
                }
            }
        }

        for (&id, node) in &self.types.debug_formats {
            check_ty("debug format", id)?;
            check_node(self, id, node, "debug format")?;
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
                    return corrupt(format!(
                        "normalized task table: entry id {} out of range",
                        id.0
                    ));
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

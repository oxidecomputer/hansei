// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Detectors for std/core/alloc types, plus the shape-keyed structural
//! chain (trait-object and function pointers, the bare scalar newtype).
//! Everything here describes a layout the *toolchain* owns: a rustc or
//! std release is what moves it, so a red toolchain matrix cell starts
//! here.

use super::ReachStep::{Deref, Named, PeelToParam, Resolved};
use super::crates::allocator_api2_vec_shape;
use super::{
    Reach, ReachStep, Through, Want, find_unique, is_byte_array, is_unsigned_integer, raw_variant,
    reach, sole_param_target, struct_of, transparent, unique_member, zero_offset_member,
};
use crate::bundle::{DisplayNode, Field, MapEntries, Notation, Selector, Step};
use crate::extract::{Emitter, fq_name, ns_path};
use crate::raw_types::RawType;
use crate::{DwReader, Encoding, TypeId};

/// A tuple newtype wrapping a single scalar (`Version(usize)`, `Epoch(u64)`,
/// an id, …) is displayed as that inner value. The scalar must fill the whole
/// struct (any other members are zero-sized), so this only ever collapses a
/// genuine wrapper, never a struct that also carries data. Semantic wrappers
/// (atomics, `NonZero`, …) are claimed by their name-keyed detector first, so
/// this only sees a type no table named.
pub(super) fn scalar_newtype_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    let scalar = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        matches!(reader.canonical_type(ty), Some(RawType::Base(base))
            if base.size != 0 && base.size == st.size)
    })?;
    transparent(emitter, &st.members, scalar)
}

/// Where a `Vec`-shaped owned buffer keeps its data pointer, length, capacity,
/// and element type. Shared by the two `Vec` spellings [`vec_node`] renders,
/// whose buffers differ in shape but whose display program is identical.
#[derive(Clone, Debug)]
pub(super) struct VecShape {
    pub(super) pointer: Selector,
    pub(super) length: Selector,
    pub(super) capacity: Selector,
    pub(super) element: TypeId,
}

/// A `Vec<T, A>`, in either spelling, renders through the `Slice` node: an owned
/// buffer that supplies its capacity for the length check.
pub(super) fn vec_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let shape = vec_shape(emitter, id).or_else(|| allocator_api2_vec_shape(emitter, id))?;
    Some(DisplayNode::Slice {
        pointer: shape.pointer,
        length: shape.length,
        capacity: Some(shape.capacity),
        element: emitter.reserve(shape.element),
    })
}

pub(super) fn vec_shape(emitter: &mut Emitter<'_>, id: TypeId) -> Option<VecShape> {
    let reader = emitter.reader;
    let vec = struct_of(reader, id)?;
    if fq_name(reader, id)?.split('<').next()? != "alloc::vec::Vec" {
        return None;
    }
    let [element_param, alloc_param] = vec.template_params.as_ref() else {
        return None;
    };
    if element_param.name.map(|name| reader.strings.get(name)) != Some("T")
        || alloc_param.name.map(|name| reader.strings.get(name)) != Some("A")
    {
        return None;
    }
    let element = reader.canonicalize(element_param.type_id);
    let alloc = reader.canonicalize(alloc_param.type_id);

    let (_, buf_member) = unique_member(reader, &vec.members, "buf")?;
    unique_member(reader, &vec.members, "len")?;

    let raw_vec = struct_of(reader, buf_member.type_id)?;
    if fq_name(reader, buf_member.type_id)?.split('<').next()? != "alloc::raw_vec::RawVec" {
        return None;
    }
    let [raw_element, raw_alloc] = raw_vec.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(raw_element.type_id) != element
        || reader.canonicalize(raw_alloc.type_id) != alloc
    {
        return None;
    }

    let (_, inner_member) = unique_member(reader, &raw_vec.members, "inner")?;
    let inner = struct_of(reader, inner_member.type_id)?;
    if fq_name(reader, inner_member.type_id)?.split('<').next()? != "alloc::raw_vec::RawVecInner" {
        return None;
    }
    let [inner_alloc] = inner.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(inner_alloc.type_id) != alloc {
        return None;
    }

    let is_byte = |target| is_unsigned_integer(reader, target, 1);
    let (pointer_path, _) = find_unique(
        reader,
        inner_member.type_id,
        Want::PointerTo(&is_byte),
        Through::AnyOffset,
    )?;

    let (_, cap_member) = unique_member(reader, &inner.members, "cap")?;
    let (cap_value, _) = usize_no_high_bit_layout(reader, cap_member.type_id)?;

    // The buffer walk is by name; the pointer was found by shape and the niche
    // newtype's field by position, so both are spliced in and re-addressed.
    let buf = || reach![Named("buf"), Named("inner")];
    let mut pointer = buf();
    pointer.push(Resolved(pointer_path));
    let mut capacity = buf();
    capacity.push(Named("cap"));
    capacity.push(Resolved(Selector::member(cap_value)));
    Some(VecShape {
        pointer: emitter.walk(id, &pointer)?.0,
        length: emitter.walk(id, &reach![Named("len")])?.0,
        capacity: emitter.walk(id, &capacity)?.0,
        element,
    })
}

/// Recognize the private node layout of `BTreeMap<K, V, A>` and render it as a
/// `Map` whose entries come from the B-tree walk. The key, value, leaf, and
/// internal node types are all reserved, since the walk renders keys and values
/// and reads both node shapes.
pub(super) fn btree_map_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    let map = struct_of(reader, id)?;
    let [key_param, value_param, alloc_param] = map.template_params.as_ref() else {
        return None;
    };
    if key_param.name.map(|name| reader.strings.get(name)) != Some("K")
        || value_param.name.map(|name| reader.strings.get(name)) != Some("V")
        || alloc_param.name.map(|name| reader.strings.get(name)) != Some("A")
    {
        return None;
    }
    let key = reader.canonicalize(key_param.type_id);
    let value = reader.canonicalize(value_param.type_id);

    let (root, root_member) = unique_member(reader, &map.members, "root")?;
    let (length, length_member) = unique_member(reader, &map.members, "length")?;
    if root == length || !is_unsigned_integer(reader, length_member.type_id, 8) {
        return None;
    }

    let RawType::Enum(root_option) = reader.canonical_type(root_member.type_id)? else {
        return None;
    };
    if fq_name(reader, root_member.type_id)?.split('<').next()? != "core::option::Option" {
        return None;
    }
    let some = raw_variant(reader, root_option, "Some")?;
    let is_node_ref = |candidate| is_btree_node_ref(reader, candidate, key, value);
    let (root_node, node_ref) = find_unique(
        reader,
        some.type_id,
        Want::Type(&is_node_ref),
        Through::ZeroOffset,
    )?;
    let node_ref_ty = struct_of(reader, node_ref)?;
    let (_, height_member) = unique_member(reader, &node_ref_ty.members, "height")?;
    if !is_unsigned_integer(reader, height_member.type_id, 8) {
        return None;
    }

    let (_, node_member) = unique_member(reader, &node_ref_ty.members, "node")?;
    let is_leaf_node = |target| is_btree_node(reader, target, "LeafNode", key, value);
    let (node_tail, leaf) = find_unique(
        reader,
        node_member.type_id,
        Want::PointerTo(&is_leaf_node),
        Through::ZeroOffset,
    )?;

    let leaf_ty = struct_of(reader, leaf)?;
    let (_, leaf_len_member) = unique_member(reader, &leaf_ty.members, "len")?;
    if !is_unsigned_integer(reader, leaf_len_member.type_id, 2) {
        return None;
    }
    let (_, keys_member) = unique_member(reader, &leaf_ty.members, "keys")?;
    let (_, values_member) = unique_member(reader, &leaf_ty.members, "vals")?;
    let RawType::Array(keys) = reader.canonical_type(keys_member.type_id)? else {
        return None;
    };
    let RawType::Array(values) = reader.canonical_type(values_member.type_id)? else {
        return None;
    };
    if keys.count == 0
        || keys.count != values.count
        || maybe_uninit_target(reader, keys.elem_type_id) != Some(key)
        || maybe_uninit_target(reader, values.elem_type_id) != Some(value)
    {
        return None;
    }

    let (_, parent_member) = unique_member(reader, &leaf_ty.members, "parent")?;
    let RawType::Enum(parent_option) = reader.canonical_type(parent_member.type_id)? else {
        return None;
    };
    let parent_some = raw_variant(reader, parent_option, "Some")?;
    let is_internal_node = |target| is_btree_node(reader, target, "InternalNode", key, value);
    let (_, internal) = find_unique(
        reader,
        parent_some.type_id,
        Want::PointerTo(&is_internal_node),
        Through::ZeroOffset,
    )?;
    let internal_ty = struct_of(reader, internal)?;
    let (_, data_member) = unique_member(reader, &internal_ty.members, "data")?;
    if reader.canonicalize(data_member.type_id) != leaf || data_member.offset != 0 {
        return None;
    }
    let (_, edges_member) = unique_member(reader, &internal_ty.members, "edges")?;
    let RawType::Array(edges) = reader.canonical_type(edges_member.type_id)? else {
        return None;
    };
    if edges.count != keys.count + 1 {
        return None;
    }
    let is_leaf = |target| target == leaf;
    let (edge, _) = find_unique(
        reader,
        edges.elem_type_id,
        Want::PointerTo(&is_leaf),
        Through::ZeroOffset,
    )?;

    // Each of the twelve reaches is rooted at whichever type the walk had got
    // to; the three found by shape are spliced in and re-addressed with the
    // rest. Nothing here records a position.
    let mut node_path = reach![Named("node")];
    node_path.push(Resolved(node_tail));
    Some(DisplayNode::Map {
        length: emitter.walk(id, &reach![Named("length")])?.0,
        key: emitter.reserve(key),
        value: emitter.reserve(value),
        entries: Box::new(MapEntries::BTree {
            root: emitter.walk(id, &reach![Named("root")])?.0,
            root_node: emitter.readdress(some.type_id, &root_node)?,
            height: emitter.walk(node_ref, &reach![Named("height")])?.0,
            node: emitter.walk(node_ref, &node_path)?.0,
            leaf: emitter.reserve(leaf),
            leaf_len: emitter.walk(leaf, &reach![Named("len")])?.0,
            leaf_keys: emitter.walk(leaf, &reach![Named("keys")])?.0,
            leaf_values: emitter.walk(leaf, &reach![Named("vals")])?.0,
            internal: emitter.reserve(internal),
            internal_data: emitter.walk(internal, &reach![Named("data")])?.0,
            internal_edges: emitter.walk(internal, &reach![Named("edges")])?.0,
            edge: emitter.readdress(edges.elem_type_id, &edge)?,
        }),
    })
}

pub(super) fn is_btree_node_ref(
    reader: &DwReader<'_>,
    id: TypeId,
    key: TypeId,
    value: TypeId,
) -> bool {
    let Some(RawType::Struct(st)) = reader.canonical_type(id) else {
        return false;
    };
    fq_name(reader, id).is_some_and(|name| {
        name.split('<').next() == Some("alloc::collections::btree::node::NodeRef")
    }) && st.template_params.len() == 4
        && reader.canonicalize(st.template_params[1].type_id) == key
        && reader.canonicalize(st.template_params[2].type_id) == value
}

pub(super) fn is_btree_node(
    reader: &DwReader<'_>,
    id: TypeId,
    kind: &str,
    key: TypeId,
    value: TypeId,
) -> bool {
    let Some(RawType::Struct(st)) = reader.canonical_type(id) else {
        return false;
    };
    let expected = match kind {
        "LeafNode" => "alloc::collections::btree::node::LeafNode",
        "InternalNode" => "alloc::collections::btree::node::InternalNode",
        _ => return false,
    };
    fq_name(reader, id).is_some_and(|name| name.split('<').next() == Some(expected))
        && st.template_params.len() == 2
        && reader.canonicalize(st.template_params[0].type_id) == key
        && reader.canonicalize(st.template_params[1].type_id) == value
}

pub(super) fn maybe_uninit_target(reader: &DwReader<'_>, id: TypeId) -> Option<TypeId> {
    let RawType::Union(union) = reader.canonical_type(id)? else {
        return None;
    };
    if fq_name(reader, id)?.split('<').next()? != "core::mem::maybe_uninit::MaybeUninit" {
        return None;
    }
    let [param] = union.template_params.as_ref() else {
        return None;
    };
    (param.name.map(|name| reader.strings.get(name)) == Some("T"))
        .then(|| reader.canonicalize(param.type_id))
}

pub(super) fn function_pointer_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let RawType::Pointer(pointer) = reader.canonical_type(id)? else {
        return None;
    };
    reader
        .is_subroutine_type(pointer.target_type_id)
        .then_some(DisplayNode::Symbol {
            at: Selector::default(),
        })
}

pub(super) fn raw_waker_vtable_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // Render the whole struct, replacing each function-pointer member's value
    // with a `Symbol` node (its address and resolved name) while keeping the
    // member's own name. That each member really is a pointer is the `Symbol`
    // node's own requirement, checked once the program is built. The fields are
    // emitted in RawWakerVTable's declared order (clone, wake, wake_by_ref,
    // drop) regardless of DWARF member order.
    let mut fields = Vec::new();
    for name in ["clone", "wake", "wake_by_ref", "drop"] {
        let at = emitter.member_named(id, name)?;
        let node = DisplayNode::Symbol {
            at: emitter.walk(id, &reach![Named(name)])?.0,
        };
        fields.push(Field::computed(at, node));
    }
    Some(DisplayNode::Struct { fields })
}

/// Render a `core::task::wake::Waker` as its RawWaker's `data` word — the one
/// datum that identifies what it wakes. For a tokio task waker that is the
/// task's Header pointer, which `hansei whatis` resolves and `trace -v`
/// labels with the task id; the vtable it travels with is internal detail
/// (`--ugly` shows both).
pub(super) fn waker_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Alias {
        at: emitter.walk(id, &reach![Named("waker"), Named("data")])?.0,
        follow_pointers: false,
    })
}

/// `RawWaker` reduces the same way as the `Waker` around it — and needs its
/// own row: an enum payload (`Option<Waker>::Some`) is peeled before its
/// formatter is looked up, which dissolves the single-member `Waker` into
/// the `RawWaker` it wraps.
pub(super) fn raw_waker_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Alias {
        at: emitter.walk(id, &reach![Named("data")])?.0,
        follow_pointers: false,
    })
}

pub(super) fn ip_address_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // Both addresses reach this detector; the name says how wide the array is.
    let expected_octets = match fq_name(reader, id).as_deref()? {
        "core::net::ip_addr::Ipv4Addr" => 4,
        "core::net::ip_addr::Ipv6Addr" => 16,
        _ => return None,
    };
    // The octet count is what tells the two apart, and the node's own
    // requirement is only that the path reaches an array.
    let octets = || reach![Named("octets")];
    if !is_byte_array(emitter, id, &octets(), Some(expected_octets)) {
        return None;
    }
    Some(DisplayNode::Bytes {
        at: emitter.walk(id, &octets())?.0,
        notation: Notation::IpAddr,
    })
}

pub(super) fn str_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // The `Str` node accepts any data pointer, since camino's is typed; a `&str`
    // is the byte-erased one, and screening for that here is what keeps this
    // detector from claiming a fat pointer over something else.
    let bytes = emitter.landed(id, &reach![Named("data_ptr"), Deref])?;
    if !is_unsigned_integer(emitter.reader, bytes, 1) {
        return None;
    }
    Some(DisplayNode::Str {
        pointer: emitter.walk(id, &reach![Named("data_ptr")])?.0,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
        nul_terminated: false,
    })
}

/// A `&core::ffi::c_str::CStr` is a `{ data_ptr, length }` fat pointer like
/// `&str`, but over bytes that need not be UTF-8 (they render lossily) and
/// with a length that counts the trailing NUL. The data pointer is typed
/// `*CStr` — the DST itself — so there is no byte pointee to screen for; the
/// name key is the screen.
pub(super) fn cstr_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Str {
        pointer: emitter.walk(id, &reach![Named("data_ptr")])?.0,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
        nul_terminated: true,
    })
}

/// An owned `CString` keeps its bytes — NUL terminator included — in a
/// `Box<[u8]>` behind its `inner` member, so its data pointer and length are
/// the box's own fat-pointer words anchored there. Like `&CStr` it renders
/// as a NUL-trimmed, lossily-escaped string; a box carries no capacity.
pub(super) fn cstring_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let bytes = emitter.landed(id, &reach![Named("inner"), Named("data_ptr"), Deref])?;
    if !is_unsigned_integer(emitter.reader, bytes, 1) {
        return None;
    }
    Some(DisplayNode::Str {
        pointer: emitter
            .walk(id, &reach![Named("inner"), Named("data_ptr")])?
            .0,
        length: emitter
            .walk(id, &reach![Named("inner"), Named("length")])?
            .0,
        capacity: None,
        nul_terminated: true,
    })
}

/// A `&[T]` slice reference or a `Box<[T]>` boxed slice. Both are laid out as a
/// `{ data_ptr: *T, length: usize }` fat pointer — identical to `&str` but with
/// an arbitrary element type and no capacity — so both render through the
/// `Slice` node with `capacity: None`, the borrowed counterpart to an owned
/// `Vec`.
pub(super) fn slice_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // The dispatch table screens by name (`&[` / `alloc::boxed::Box<[`); a thin
    // `Box<T>` has no `[` and `&str`/`String` are UTF-8, so neither reaches
    // here. This describes only the fat-pointer structure.
    let (pointer, ptr_ty) = emitter.walk(id, &reach![Named("data_ptr")])?;
    Some(DisplayNode::Slice {
        pointer,
        length: emitter.walk(id, &reach![Named("length")])?.0,
        capacity: None,
        element: emitter.behind(ptr_ty)?,
    })
}

pub(super) fn string_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // A `String` is a `Vec<u8>` behind a single member, so its data pointer,
    // length, and capacity are the Vec's own paths anchored at the `vec`
    // member. It renders exactly as a `&str` with the capacity checked, so it
    // reuses the `Str` node with the capacity supplied.
    let vec = emitter.landed(id, &reach![Named("vec")])?;
    let shape = vec_shape(emitter, vec)?;
    if !is_unsigned_integer(emitter.reader, shape.element, 1) {
        return None;
    }
    buffer_node(emitter, id, &reach![Named("vec")], shape)
}

/// The `Str` program an owned UTF-8 buffer renders through: a `Vec<u8>`'s own
/// paths, anchored under the walk that reaches the vector.
pub(super) fn buffer_node(
    emitter: &mut Emitter<'_>,
    root: TypeId,
    prefix: &Reach<'_>,
    shape: VecShape,
) -> Option<DisplayNode> {
    let under = |emitter: &mut Emitter<'_>, sel| {
        let mut path: Reach<'_> = prefix.iter().map(ReachStep::clone).collect();
        path.push(Resolved(sel));
        Some(emitter.walk(root, &path)?.0)
    };
    Some(DisplayNode::Str {
        pointer: under(emitter, shape.pointer)?,
        length: under(emitter, shape.length)?,
        capacity: Some(under(emitter, shape.capacity)?),
        nul_terminated: false,
    })
}

/// The `Instant` wrapper chain — tokio's `Instant { std }`, the std
/// `Instant(sys)` tuple, and the unix `Instant { t }` — is three newtype
/// levels around the one `Timespec` worth reading, so each aliases its sole
/// member and a deadline renders as the `Timespec` directly.
pub(super) fn instant_alias_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let inner = match fq_name(reader, id).as_deref()? {
        "tokio::time::instant::Instant" => "std",
        "std::time::Instant" => "__0",
        "std::sys::time::unix::Instant" => "t",
        _ => return None,
    };
    let st = struct_of(reader, id)?;
    let member = zero_offset_member(reader, &st.members, Some(inner), |_| true)?;
    transparent(emitter, &st.members, member)
}

/// Recognize rustc's DWARF representation of a Rust trait-object wide
/// pointer. The bundle records both member indices and the vtable header
/// ordering so reify never guesses from the private field name or bakes in
/// rustc's slot numbers independently.
pub(super) fn dyn_pointer_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;

    let mut data_matches = st.members.iter().enumerate().filter_map(|(index, member)| {
        if member.name.map(|name| reader.strings.get(name)) != Some("pointer") {
            return None;
        }
        let RawType::Pointer(pointer) = reader.canonical_type(member.type_id)? else {
            return None;
        };
        let tail_offset = dyn_tail_offset(reader, pointer.target_type_id, &mut Vec::new())?;
        Some((index, tail_offset))
    });
    let (pointer_index, tail_offset) = data_matches.next()?;
    if data_matches.next().is_some() {
        return None;
    }

    let mut vtable_matches = st.members.iter().enumerate().filter(|(_, member)| {
        if member.name.map(|name| reader.strings.get(name)) != Some("vtable") {
            return false;
        }
        let Some(RawType::Pointer(pointer)) = reader.canonical_type(member.type_id) else {
            return false;
        };
        let Some(RawType::Array(array)) = reader.canonical_type(pointer.target_type_id) else {
            return false;
        };
        if array.count < 3 {
            return false;
        }
        let Some(RawType::Base(base)) = reader.canonical_type(array.elem_type_id) else {
            return false;
        };
        base.size == crate::bundle::POINTER_SIZE
            && base.encoding == Encoding::Unsigned
            && base.name.map(|name| reader.strings.get(name)) == Some("usize")
    });
    let (vtable_index, _) = vtable_matches.next()?;
    if vtable_matches.next().is_some() || pointer_index == vtable_index {
        return None;
    }

    // Both members were found by shape — the screens above are what identify
    // them — so their addresses come from the one place a found member becomes
    // an address.
    let pointer = emitter.address(&st.members, pointer_index as u32);
    let vtable = emitter.address(&st.members, vtable_index as u32);
    Some(DisplayNode::DynPointer {
        pointer: Selector(vec![Step::Member(pointer)]),
        vtable: Selector(vec![Step::Member(vtable)]),
        drop_in_place: 0,
        size: 1,
        align: 2,
        tail_offset,
    })
}

/// The byte offset of the `dyn Trait` tail within `id`, if `id` is a
/// `dyn Trait` type or an unsized aggregate whose final field recursively
/// contains that dyn tail (such as `ArcInner<dyn Trait>`). Rust wide
/// pointers carry metadata for either shape.
///
/// A bare `dyn Trait` has offset zero; a wrapper contributes the offset of
/// its final member and recurses into it. Returns `None` when there is no
/// dyn tail. Consumers add this to the data-pointer address to reach the
/// erased value, skipping any sized header (e.g. an `Arc`'s refcounts).
pub(super) fn dyn_tail_offset(
    reader: &DwReader<'_>,
    id: TypeId,
    seen: &mut Vec<TypeId>,
) -> Option<u64> {
    let id = reader.canonicalize(id);
    if seen.len() >= 8 || seen.contains(&id) {
        return None;
    }
    let raw = reader.canonical_type(id)?;
    if fq_name(reader, id).is_some_and(|name| name.starts_with("dyn ") || name.starts_with("(dyn "))
    {
        return Some(0);
    }
    let RawType::Struct(st) = raw else {
        return None;
    };
    let tail = st.members.last()?;
    seen.push(id);
    let inner = dyn_tail_offset(reader, tail.type_id, seen);
    seen.pop();
    tail.offset.checked_add(inner?)
}

/// Whether `id` has a `dyn Trait` tail (see [`dyn_tail_offset`]).
#[cfg(test)]
pub(super) fn has_dyn_tail(reader: &DwReader<'_>, id: TypeId, seen: &mut Vec<TypeId>) -> bool {
    dyn_tail_offset(reader, id, seen).is_some()
}

pub(super) fn unsafe_cell_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let st = struct_of(emitter.reader, id)?;
    let (member, _) = unsafe_cell_layout(emitter.reader, id)?;
    transparent(emitter, &st.members, member)
}

/// The member index and `T` of a `core::cell::UnsafeCell<T>`, or `None` if `id`
/// is not one. The name check stays here because the loom shims reach a cell as
/// their own member, where no dispatch table has screened it for them.
pub(super) fn unsafe_cell_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let st = struct_of(reader, id)?;
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::cell" || !name.starts_with("UnsafeCell<") || !name.ends_with('>') {
        return None;
    }
    let target = sole_param_target(reader, st)?;
    let member = zero_offset_member(reader, &st.members, Some("value"), |ty| {
        reader.canonicalize(ty) == target
    })?;
    Some((member, target))
}

pub(super) fn non_null_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let st = struct_of(emitter.reader, id)?;
    let (member, _) = non_null_layout(emitter.reader, id)?;
    transparent(emitter, &st.members, member)
}

/// The member index and `T` of a `core::ptr::non_null::NonNull<T>`, or `None` if
/// `id` is not one. Like [`unsafe_cell_layout`] this keeps its name check, for
/// [`unique_node`], which reaches a `NonNull` as its own member.
pub(super) fn non_null_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    let st = struct_of(reader, id)?;
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let name = st.name.map(|name| reader.strings.get(name))?;
    if namespace != "core::ptr::non_null" || !name.starts_with("NonNull<") || !name.ends_with('>') {
        return None;
    }
    let target = sole_param_target(reader, st)?;
    let member = zero_offset_member(reader, &st.members, Some("pointer"), |ty| {
        matches!(reader.canonical_type(ty), Some(RawType::Pointer(pointer))
            if reader.canonicalize(pointer.target_type_id) == target)
    })?;
    Some((member, target))
}

/// `core::ptr::unique::Unique<T>` wraps a `NonNull<T>`, itself transparent over
/// the pointer.
pub(super) fn unique_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    let target = sole_param_target(reader, st)?;
    let pointer = zero_offset_member(reader, &st.members, Some("pointer"), |ty| {
        non_null_layout(reader, ty).is_some_and(|(_, inner)| inner == target)
    })?;
    transparent(emitter, &st.members, pointer)
}

pub(super) fn usize_no_high_bit_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let st = struct_of(emitter.reader, id)?;
    let (member, _) = usize_no_high_bit_layout(emitter.reader, id)?;
    transparent(emitter, &st.members, member)
}

/// The member index and integer type of a `core::num::niche_types::UsizeNoHighBit`,
/// or `None` if `id` is not one. Keeps its name check for
/// [`allocator_api2_vec_shape`], which reaches one as a capacity member.
pub(super) fn usize_no_high_bit_layout(reader: &DwReader<'_>, id: TypeId) -> Option<(u32, TypeId)> {
    if fq_name(reader, id).as_deref() != Some("core::num::niche_types::UsizeNoHighBit") {
        return None;
    }
    let st = struct_of(reader, id)?;
    let member = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        is_unsigned_integer(reader, ty, crate::bundle::POINTER_SIZE)
    })?;
    let integer = reader.canonicalize(st.members[member as usize].type_id);
    Some((member, integer))
}

pub(super) fn is_integer(reader: &DwReader<'_>, id: TypeId) -> bool {
    matches!(
        reader.canonical_type(id),
        Some(RawType::Base(base)) if matches!(base.encoding, Encoding::Signed | Encoding::Unsigned)
    )
}

/// `core::num::nonzero::NonZero<T>` is a newtype over a niche-typed integer
/// wrapper (`NonZero{U,I}<width>Inner`). Display it as the wrapped integer;
/// paired with [`nonzero_inner_node`] the two layers collapse to the
/// value. Handles every width and signedness.
pub(super) fn nonzero_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // Whatever the width, the wrapped inner is the whole value.
    let inner = zero_offset_member(reader, &st.members, Some("__0"), |_| true)?;
    transparent(emitter, &st.members, inner)
}

/// The niche-typed inner of a `NonZero<T>`
/// (`core::num::niche_types::NonZero{U,I}<width>Inner`), transparent over its
/// integer field.
pub(super) fn nonzero_inner_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // The prefix key admits any `niche_types::NonZero*`; only the `*Inner`
    // wrappers are transparent over an integer.
    let name = st.name.map(|name| reader.strings.get(name))?;
    if !name.ends_with("Inner") {
        return None;
    }
    let value = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        is_integer(reader, ty)
    })?;
    transparent(emitter, &st.members, value)
}

pub(super) fn atomic_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // An atomic aliases its stored value but does not chase it: an `AtomicPtr`'s
    // `Debug` reports the address it holds, so `follow_pointers` is false.
    Some(DisplayNode::Alias {
        at: emitter.walk(id, &reach![PeelToParam])?.0,
        follow_pointers: false,
    })
}

/// Whether `id` is the generic `core::sync::atomic::Atomic<T>` spelling, the
/// one tokio's loom shim wraps. A binary also emits concrete `AtomicU8` and
/// `AtomicUsize` types, which declare no `T`; a caller after the word one of
/// those stores peels to a shape instead.
pub(super) fn is_generic_atomic(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(st) = struct_of(reader, id) else {
        return false;
    };
    let (Some(namespace), Some(name)) = (
        st.namespace.map(|ns| ns_path(reader, ns)),
        st.name.map(|name| reader.strings.get(name)),
    ) else {
        return false;
    };
    namespace == "core::sync::atomic"
        && name.starts_with("Atomic<")
        && name.ends_with('>')
        && sole_param_target(reader, st).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DwReader;
    use crate::raw_types::{
        NsId, RawArray, RawBase, RawEnum, RawGenericParameter, RawMember, RawPointer, RawStruct,
        RawUnion, RawVariant, VariantShape,
    };

    use gimli::UnitSectionOffset;

    use ::std::collections::BTreeMap;

    use crate::bundle::POINTER_SIZE;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset(offset))
    }

    /// A fixture reader with builder methods spelling layouts the way the
    /// detectors read them.
    #[derive(Default)]
    struct Fx {
        reader: DwReader<'static>,
    }

    impl Fx {
        fn ns(&mut self, path: &'static str) -> NsId {
            let mut ns = None;
            for seg in path.split("::") {
                let name = self.reader.strings.intern(seg);
                ns = Some(self.reader.namespaces.insert(ns, name));
            }
            ns.unwrap()
        }

        fn base(&mut self, id: TypeId, name: &'static str, encoding: Encoding, size: u64) {
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Base(RawBase {
                    name,
                    namespace: None,
                    encoding,
                    size,
                    alignment: None,
                }),
            );
        }

        fn members(
            &mut self,
            members: &[(&'static str, TypeId, u64)],
        ) -> Box<[RawMember<crate::StrId>]> {
            members
                .iter()
                .map(|&(name, type_id, offset)| RawMember {
                    name: Some(self.reader.strings.intern(name)),
                    offset,
                    type_id,
                    source_loc: None,
                })
                .collect()
        }

        fn params(
            &mut self,
            params: &[(&'static str, TypeId)],
        ) -> Box<[RawGenericParameter<crate::StrId>]> {
            params
                .iter()
                .map(|&(name, type_id)| RawGenericParameter {
                    name: Some(self.reader.strings.intern(name)),
                    type_id,
                })
                .collect()
        }

        fn strukt(
            &mut self,
            id: TypeId,
            namespace: Option<NsId>,
            name: &'static str,
            members: &[(&'static str, TypeId, u64)],
            params: &[(&'static str, TypeId)],
        ) {
            let members = self.members(members);
            let template_params = self.params(params);
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Struct(RawStruct {
                    name,
                    namespace,
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        }

        fn onion(
            &mut self,
            id: TypeId,
            namespace: Option<NsId>,
            name: &'static str,
            members: &[(&'static str, TypeId, u64)],
            params: &[(&'static str, TypeId)],
        ) {
            let members = self.members(members);
            let template_params = self.params(params);
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Union(RawUnion {
                    name,
                    namespace,
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        }

        fn pointer(&mut self, id: TypeId, target: TypeId) {
            self.reader.types.insert(
                id,
                RawType::Pointer(RawPointer {
                    name: None,
                    target_type_id: target,
                }),
            );
        }

        fn array(&mut self, id: TypeId, elem: TypeId, count: u64) {
            self.reader.types.insert(
                id,
                RawType::Array(RawArray {
                    elem_type_id: elem,
                    count,
                }),
            );
        }

        /// A `core::option::Option` whose `Some` payload is `payload`.
        fn option_of(&mut self, id: TypeId, namespace: NsId, payload: TypeId) {
            let some = RawVariant {
                member: RawMember {
                    name: Some(self.reader.strings.intern("Some")),
                    offset: 0,
                    type_id: payload,
                    source_loc: None,
                },
            };
            let name = Some(self.reader.strings.intern("Option<T>"));
            self.reader.types.insert(
                id,
                RawType::Enum(RawEnum {
                    name,
                    namespace: Some(namespace),
                    size: 8,
                    alignment: None,
                    shape: VariantShape::Many {
                        discr: None,
                        variants: Box::new([(Some(1), some)]),
                    },
                    template_params: Box::new([]),
                    source_loc: None,
                }),
            );
        }
    }

    fn detect(fx: &Fx, detector: super::super::Detector, id: TypeId) -> Option<DisplayNode> {
        detector(
            &mut Emitter::new(&fx.reader, BTreeMap::new(), None, None),
            id,
        )
    }

    /// Which leg of the BTreeMap layout to break, if any.
    #[derive(PartialEq, Clone, Copy)]
    enum Btree {
        Valid,
        ParamNotK,
        ParamNotA,
        LengthNarrow,
        ZeroCountKeys,
        CountMismatch,
        KeysWrongTarget,
        DataMoved,
    }

    fn btree(kind: Btree) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let map_ns = fx.ns("alloc::collections::btree::map");
        let node_ns = fx.ns("alloc::collections::btree::node");
        let option_ns = fx.ns("core::option");
        let mu_ns = fx.ns("core::mem::maybe_uninit");

        let key = type_id(1);
        let value = type_id(2);
        let global = type_id(3);
        let u64t = type_id(4);
        let u16t = type_id(5);
        let u32t = type_id(6);
        fx.base(key, "i64", Encoding::Signed, 8);
        fx.base(value, "u64", Encoding::Unsigned, 8);
        fx.strukt(global, None, "Global", &[], &[]);
        fx.base(u64t, "u64", Encoding::Unsigned, 8);
        fx.base(u16t, "u16", Encoding::Unsigned, 2);
        fx.base(u32t, "u32", Encoding::Unsigned, 4);

        let map = type_id(0x10);
        let opt = type_id(0x11);
        let node_ref = type_id(0x12);
        let non_null_leaf = type_id(0x13);
        let ptr_leaf = type_id(0x14);
        let leaf = type_id(0x15);
        let arr_k = type_id(0x16);
        let arr_v = type_id(0x17);
        let mu_k = type_id(0x18);
        let mu_v = type_id(0x19);
        let opt_parent = type_id(0x1a);
        let non_null_internal = type_id(0x1b);
        let ptr_internal = type_id(0x1c);
        let internal = type_id(0x1d);
        let arr_edge = type_id(0x1e);
        let mu_edge = type_id(0x1f);

        let length_ty = if kind == Btree::LengthNarrow {
            u32t
        } else {
            u64t
        };
        fx.strukt(
            map,
            Some(map_ns),
            "BTreeMap<i64, u64, alloc::alloc::Global>",
            &[("root", opt, 0), ("length", length_ty, 8)],
            &[
                (if kind == Btree::ParamNotK { "X" } else { "K" }, key),
                ("V", value),
                (if kind == Btree::ParamNotA { "B" } else { "A" }, global),
            ],
        );
        fx.option_of(opt, option_ns, node_ref);
        fx.strukt(
            node_ref,
            Some(node_ns),
            "NodeRef<marker::Owned, i64, u64, marker::LeafOrInternal>",
            &[("height", u64t, 0), ("node", non_null_leaf, 8)],
            &[
                ("BorrowType", global),
                ("K", key),
                ("V", value),
                ("Type", global),
            ],
        );
        fx.strukt(
            non_null_leaf,
            None,
            "NonNull<LeafNode<i64, u64>>",
            &[("pointer", ptr_leaf, 0)],
            &[],
        );
        fx.pointer(ptr_leaf, leaf);
        let keys_count = if kind == Btree::ZeroCountKeys { 0 } else { 11 };
        let vals_count = if kind == Btree::CountMismatch {
            keys_count + 1
        } else {
            keys_count
        };
        fx.strukt(
            leaf,
            Some(node_ns),
            "LeafNode<i64, u64>",
            &[
                ("len", u16t, 0),
                ("keys", arr_k, 8),
                ("vals", arr_v, 96),
                ("parent", opt_parent, 184),
            ],
            &[("K", key), ("V", value)],
        );
        fx.array(arr_k, mu_k, keys_count);
        fx.array(arr_v, mu_v, vals_count);
        let keys_target = if kind == Btree::KeysWrongTarget {
            value
        } else {
            key
        };
        fx.onion(
            mu_k,
            Some(mu_ns),
            "MaybeUninit<i64>",
            &[("value", keys_target, 0)],
            &[("T", keys_target)],
        );
        fx.onion(
            mu_v,
            Some(mu_ns),
            "MaybeUninit<u64>",
            &[("value", value, 0)],
            &[("T", value)],
        );
        fx.option_of(opt_parent, option_ns, non_null_internal);
        fx.strukt(
            non_null_internal,
            None,
            "NonNull<InternalNode<i64, u64>>",
            &[("pointer", ptr_internal, 0)],
            &[],
        );
        fx.pointer(ptr_internal, internal);
        let data_offset = if kind == Btree::DataMoved { 8 } else { 0 };
        fx.strukt(
            internal,
            Some(node_ns),
            "InternalNode<i64, u64>",
            &[("data", leaf, data_offset), ("edges", arr_edge, 200)],
            &[("K", key), ("V", value)],
        );
        fx.array(arr_edge, mu_edge, keys_count + 1);
        fx.onion(
            mu_edge,
            Some(mu_ns),
            "MaybeUninit<NonNull<LeafNode<i64, u64>>>",
            &[("value", non_null_leaf, 0)],
            &[("T", non_null_leaf)],
        );

        (fx, map)
    }

    #[test]
    fn test_btree_map_screens_each_leg_of_its_layout() {
        let (fx, map) = btree(Btree::Valid);
        assert!(detect(&fx, btree_map_node, map).is_some());

        for kind in [
            Btree::ParamNotK,
            Btree::ParamNotA,
            Btree::LengthNarrow,
            Btree::ZeroCountKeys,
            Btree::CountMismatch,
            Btree::KeysWrongTarget,
            Btree::DataMoved,
        ] {
            let (fx, map) = btree(kind);
            assert!(
                detect(&fx, btree_map_node, map).is_none(),
                "a broken leg must decline"
            );
        }
    }

    #[test]
    fn test_btree_node_screens_compare_names_and_key_value_types() {
        let (fx, _) = btree(Btree::Valid);
        let reader = &fx.reader;
        let key = type_id(1);
        let value = type_id(2);
        let node_ref = type_id(0x12);
        let leaf = type_id(0x15);
        let internal = type_id(0x1d);

        assert!(is_btree_node_ref(reader, node_ref, key, value));
        assert!(!is_btree_node_ref(reader, node_ref, value, key));
        assert!(!is_btree_node_ref(reader, leaf, key, value));
        // The node-ref shape under some other name is not a NodeRef.
        let mut fx = btree(Btree::Valid).0;
        let fake_ref = type_id(0x40);
        let node_ns = fx.ns("alloc::collections::btree::node");
        fx.strukt(
            fake_ref,
            Some(node_ns),
            "NodeRefish<marker::Owned, i64, u64, marker::LeafOrInternal>",
            &[],
            &[
                ("BorrowType", type_id(3)),
                ("K", key),
                ("V", value),
                ("Type", type_id(3)),
            ],
        );
        assert!(!is_btree_node_ref(&fx.reader, fake_ref, key, value));

        assert!(is_btree_node(reader, leaf, "LeafNode", key, value));
        assert!(is_btree_node(reader, internal, "InternalNode", key, value));
        assert!(!is_btree_node(reader, leaf, "InternalNode", key, value));
        assert!(!is_btree_node(reader, leaf, "LeafNode", value, key));
        assert!(!is_btree_node(reader, leaf, "LeafNode", key, key));
        assert!(!is_btree_node(reader, leaf, "LeafNode", value, value));
        assert!(!is_btree_node(reader, node_ref, "LeafNode", key, value));
    }

    fn vec_fixture(param_t: &'static str, retarget_alloc: bool) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let vec_ns = fx.ns("alloc::vec");
        let raw_vec_ns = fx.ns("alloc::raw_vec");
        let niche_ns = fx.ns("core::num::niche_types");

        let elem = type_id(1);
        let global = type_id(2);
        let other = type_id(3);
        let u8t = type_id(4);
        let u64t = type_id(5);
        let usize_t = type_id(6);
        fx.base(elem, "i64", Encoding::Signed, 8);
        fx.strukt(global, None, "Global", &[], &[]);
        fx.strukt(other, None, "Other", &[], &[]);
        fx.base(u8t, "u8", Encoding::Unsigned, 1);
        fx.base(u64t, "u64", Encoding::Unsigned, 8);
        fx.base(usize_t, "usize", Encoding::Unsigned, 8);

        let vec = type_id(0x10);
        let raw_vec = type_id(0x11);
        let inner = type_id(0x12);
        let byte_ptr = type_id(0x13);
        let cap = type_id(0x14);
        fx.strukt(
            vec,
            Some(vec_ns),
            "Vec<i64, alloc::alloc::Global>",
            &[("buf", raw_vec, 0), ("len", u64t, 8)],
            &[(param_t, elem), ("A", global)],
        );
        fx.strukt(
            raw_vec,
            Some(raw_vec_ns),
            "RawVec<i64, alloc::alloc::Global>",
            &[("inner", inner, 0)],
            &[
                ("T", elem),
                ("A", if retarget_alloc { other } else { global }),
            ],
        );
        fx.strukt(
            inner,
            Some(raw_vec_ns),
            "RawVecInner<alloc::alloc::Global>",
            &[("ptr", byte_ptr, 0), ("cap", cap, 8)],
            &[("A", global)],
        );
        fx.pointer(byte_ptr, u8t);
        fx.strukt(
            cap,
            Some(niche_ns),
            "UsizeNoHighBit",
            &[("__0", usize_t, 0)],
            &[],
        );
        (fx, vec)
    }

    #[test]
    fn test_vec_shape_validates_the_buffer_chain() {
        let (fx, vec) = vec_fixture("T", false);
        let mut emitter = Emitter::new(&fx.reader, BTreeMap::new(), None, None);
        assert!(vec_shape(&mut emitter, vec).is_some());

        // A first template param not named T is not a Vec.
        let (fx, vec) = vec_fixture("X", false);
        let mut emitter = Emitter::new(&fx.reader, BTreeMap::new(), None, None);
        assert!(vec_shape(&mut emitter, vec).is_none());

        // A RawVec bound over some other allocator is not this Vec's.
        let (fx, vec) = vec_fixture("T", true);
        let mut emitter = Emitter::new(&fx.reader, BTreeMap::new(), None, None);
        assert!(vec_shape(&mut emitter, vec).is_none());
    }

    fn dyn_fixture(elem_encoding: Encoding, elem_size: u64, double_vtable: bool) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let target = type_id(1);
        let data_ptr = type_id(2);
        let usize_t = type_id(3);
        let slots = type_id(4);
        let vtable_ptr = type_id(5);
        let wide = type_id(0x10);
        fx.strukt(target, None, "dyn app::Trait", &[], &[]);
        fx.pointer(data_ptr, target);
        fx.base(usize_t, "usize", elem_encoding, elem_size);
        fx.array(slots, usize_t, 3);
        fx.pointer(vtable_ptr, slots);
        let mut members = vec![("pointer", data_ptr, 0u64), ("vtable", vtable_ptr, 8)];
        if double_vtable {
            members.push(("vtable", vtable_ptr, 16));
        }
        fx.strukt(wide, None, "&dyn app::Trait", &members, &[]);
        (fx, wide)
    }

    #[test]
    fn test_dyn_pointer_screens_the_vtable_member() {
        // Three usize slots is the smallest vtable header.
        let (fx, wide) = dyn_fixture(Encoding::Unsigned, POINTER_SIZE, false);
        assert!(detect(&fx, dyn_pointer_node, wide).is_some());

        // A signed or narrow slot array is not a vtable, and two vtable
        // candidates leave the answer ambiguous.
        let (fx, wide) = dyn_fixture(Encoding::Signed, POINTER_SIZE, false);
        assert!(detect(&fx, dyn_pointer_node, wide).is_none());
        let (fx, wide) = dyn_fixture(Encoding::Unsigned, 4, false);
        assert!(detect(&fx, dyn_pointer_node, wide).is_none());
        let (fx, wide) = dyn_fixture(Encoding::Unsigned, POINTER_SIZE, true);
        assert!(detect(&fx, dyn_pointer_node, wide).is_none());
    }

    #[test]
    fn test_dyn_tail_search_stops_at_the_wrapper_depth_cap() {
        let mut fx = Fx::default();
        let tail = type_id(0x50);
        fx.strukt(tail, None, "dyn app::Trait", &[], &[]);
        let mut next = tail;
        for link in (0..9).rev() {
            let id = type_id(0x100 + link);
            fx.strukt(id, None, "Wrapper", &[("last", next, 16)], &[]);
            next = id;
        }
        assert_eq!(dyn_tail_offset(&fx.reader, next, &mut Vec::new()), None);
    }

    #[test]
    fn test_unsafe_cell_and_non_null_screen_namespace_and_name() {
        let mut fx = Fx::default();
        let cell_ns = fx.ns("core::cell");
        let ptr_ns = fx.ns("core::ptr::non_null");
        let word = type_id(1);
        fx.base(word, "u64", Encoding::Unsigned, 8);

        let cell = type_id(0x10);
        fx.strukt(
            cell,
            Some(cell_ns),
            "UnsafeCell<u64>",
            &[("value", word, 0)],
            &[("T", word)],
        );
        assert!(unsafe_cell_layout(&fx.reader, cell).is_some());
        let strayed = type_id(0x11);
        fx.strukt(
            strayed,
            Some(ptr_ns),
            "UnsafeCell<u64>",
            &[("value", word, 0)],
            &[("T", word)],
        );
        assert!(unsafe_cell_layout(&fx.reader, strayed).is_none());
        let unclosed = type_id(0x12);
        fx.strukt(
            unclosed,
            Some(cell_ns),
            "UnsafeCell<u64",
            &[("value", word, 0)],
            &[("T", word)],
        );
        assert!(unsafe_cell_layout(&fx.reader, unclosed).is_none());

        let target = type_id(2);
        let ptr = type_id(3);
        fx.strukt(target, None, "Value", &[], &[]);
        fx.pointer(ptr, target);
        let non_null = type_id(0x20);
        fx.strukt(
            non_null,
            Some(ptr_ns),
            "NonNull<Value>",
            &[("pointer", ptr, 0)],
            &[("T", target)],
        );
        assert!(non_null_layout(&fx.reader, non_null).is_some());
        let strayed = type_id(0x21);
        fx.strukt(
            strayed,
            Some(cell_ns),
            "NonNull<Value>",
            &[("pointer", ptr, 0)],
            &[("T", target)],
        );
        assert!(non_null_layout(&fx.reader, strayed).is_none());
        let unclosed = type_id(0x22);
        fx.strukt(
            unclosed,
            Some(ptr_ns),
            "NonNull<Value",
            &[("pointer", ptr, 0)],
            &[("T", target)],
        );
        assert!(non_null_layout(&fx.reader, unclosed).is_none());
    }

    #[test]
    fn test_usize_no_high_bit_is_transparent_over_its_word() {
        let mut fx = Fx::default();
        let niche_ns = fx.ns("core::num::niche_types");
        let word = type_id(1);
        fx.base(word, "usize", Encoding::Unsigned, POINTER_SIZE);
        let cap = type_id(0x10);
        fx.strukt(
            cap,
            Some(niche_ns),
            "UsizeNoHighBit",
            &[("__0", word, 0)],
            &[],
        );
        assert!(matches!(
            detect(&fx, usize_no_high_bit_node, cap),
            Some(DisplayNode::Alias { .. })
        ));
    }

    #[test]
    fn test_is_integer_admits_only_integer_encodings() {
        let mut fx = Fx::default();
        let unsigned = type_id(1);
        let signed = type_id(2);
        let float = type_id(3);
        let aggregate = type_id(4);
        fx.base(unsigned, "u64", Encoding::Unsigned, 8);
        fx.base(signed, "i64", Encoding::Signed, 8);
        fx.base(float, "f64", Encoding::Float, 8);
        fx.strukt(aggregate, None, "S", &[], &[]);

        assert!(is_integer(&fx.reader, unsigned));
        assert!(is_integer(&fx.reader, signed));
        assert!(!is_integer(&fx.reader, float));
        assert!(!is_integer(&fx.reader, aggregate));
    }

    fn generic_atomic(ns_path: &'static str, name: &'static str, params: usize) -> (Fx, TypeId) {
        let mut fx = Fx::default();
        let ns = fx.ns(ns_path);
        let word = type_id(1);
        fx.base(word, "u64", Encoding::Unsigned, 8);
        let atomic = type_id(0x10);
        let params: Vec<(&'static str, TypeId)> = (0..params).map(|_| ("T", word)).collect();
        fx.strukt(atomic, Some(ns), name, &[("v", word, 0)], &params);
        (fx, atomic)
    }

    #[test]
    fn test_generic_atomic_screens_namespace_name_and_param() {
        let (fx, atomic) = generic_atomic("core::sync::atomic", "Atomic<u64>", 1);
        assert!(is_generic_atomic(&fx.reader, atomic));
        // The generic spelling also formats: an alias to the stored word.
        assert!(matches!(
            detect(&fx, atomic_node, atomic),
            Some(DisplayNode::Alias { .. })
        ));

        let (fx, atomic) = generic_atomic("core::sync", "Atomic<u64>", 1);
        assert!(!is_generic_atomic(&fx.reader, atomic));
        let (fx, atomic) = generic_atomic("core::sync::atomic", "AtomicU64", 1);
        assert!(!is_generic_atomic(&fx.reader, atomic));
        let (fx, atomic) = generic_atomic("core::sync::atomic", "Atomic<u64", 1);
        assert!(!is_generic_atomic(&fx.reader, atomic));
        let (fx, atomic) = generic_atomic("core::sync::atomic", "Atomic<u64>", 2);
        assert!(!is_generic_atomic(&fx.reader, atomic));
    }
}

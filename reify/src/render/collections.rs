// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sequence and map renderers: contiguous slices, intrusive linked lists, and
//! associative collections with their storage-specific entry walks.

use crate::debug_type::{DisplayNode, FatHeader, MapEntries};
use crate::elements::{Elements, HeapGate, SeqError, Shortfall};
use crate::heap::{Gate, Liveness};
use crate::value::Value;

use hansei_bundle::{BundleType, BundleTypeId};

use proc::Target;

use foldhash::HashSet;

use std::cell::RefCell;
use std::fmt;
use std::fmt::Write as _;

use super::node::eval_node;
use super::par::{DisplayWith, MIN_PARALLEL_ITEMS, render_chunked};
use super::scalar::{byte_range, read_u64_at, read_unsigned_at};
use super::{
    FormatCache, RenderCtx, write_display_value, write_field_prefix, write_record_close,
    write_seq_close, write_seq_prefix,
};

/// Follow the `(data, len)` fat pointer `header` to a contiguous buffer and
/// render its first `len` `element`s as `[e, e, …]`, through the same
/// [`Elements`] read the parse path performs — one header validation, and one
/// refusal to believe a length further than the target corroborates it. A
/// shortfall renders the elements that are there and says how many are
/// missing; nothing served at all degrades whole. Unlike [`eval_list`] the
/// elements are contiguous, read in one target access.
pub(crate) fn eval_slice<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    header: &FatHeader,
    element: &BundleType<'a>,
    element_size: u32,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let stride = u64::from(element_size);
    let gate = HeapGate::for_header(ctx.heap, header);
    // A one-byte element makes this a string in all but type — a
    // `CString`'s buffer, a `Vec<u8>` — so it is spent from the string
    // budget, in bytes. Anything wider is a value with a line of its
    // own and comes out of the element budget.
    let cap = match stride {
        1 => ctx.max_str_len,
        _ => ctx.max_array_len,
    };
    let elements = match Elements::read_fat(header, *element, stride, bytes, ctx.proc, gate, cap) {
        Ok(elements) => elements,
        Err(SeqError::Invalid(why)) => return write!(f, "<invalid slice: {why}>"),
        Err(SeqError::Unreadable(_)) => return write!(f, "<unreadable slice buffer>"),
        Err(SeqError::Freed) => return write!(f, "<freed slice buffer>"),
        Err(SeqError::NoTarget) => return write!(f, "<target unavailable>"),
    };
    if elements.is_empty() {
        // Nothing served of a non-empty claim: the whole buffer is out of
        // reach, which is a degradation, not an empty sequence.
        return match (elements.truncated(), elements.shortfall()) {
            (Some(_), Shortfall::PastAllocation) => {
                write!(f, "<slice buffer overruns its allocation>")
            }
            (Some(_), _) => write!(f, "<unreadable slice buffer>"),
            (None, _) => write!(f, "[]"),
        };
    }

    // Vec elements pick their own integer rendering (never hex), and
    // stand in a `[…]` that prints no type to name theirs.
    let element_ctx = ctx.deeper().with_hex(false).unnamed();
    let len = elements.len();
    write!(f, "[")?;

    // A long slice formats its elements on worker threads.
    if ctx.parallel
        && len >= MIN_PARALLEL_ITEMS
        && let Some(visited) = ctx.visited
    {
        let seed = visited.borrow().clone();
        let worker = element_ctx.for_workers();
        let (elements_ref, depth) = (&elements, ctx.depth);
        render_chunked(f, len as usize, |range, out| {
            let task_visited = RefCell::new(seed.clone());
            let formats = FormatCache::default();
            let task_ctx = worker.ctx(&task_visited, &formats);
            let _ = write!(
                out,
                "{}",
                DisplayWith(|f: &mut fmt::Formatter<'_>| {
                    for index in range.clone() {
                        let child = elements_ref.get(index as u64);
                        write_seq_prefix(f, pretty, task_ctx.prefix, depth, index == 0)?;
                        write_display_value(f, &child, task_ctx, pretty)?;
                        if pretty {
                            write!(f, ",")?;
                        }
                    }
                    Ok(())
                })
            );
        })?;
    } else {
        for (index, child) in elements.iter().enumerate() {
            write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, index == 0)?;
            write_display_value(f, &child, element_ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
        }
    }
    if let Some(claimed) = elements.truncated() {
        write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, false)?;
        // A clipped claim is not a short read: those elements are outside
        // the allocation the buffer starts in, so they were never this
        // sequence's however readable the pages under them happen to be.
        match elements.shortfall() {
            Shortfall::PastAllocation => write!(f, "<{} more past its allocation>", claimed - len)?,
            Shortfall::PastCap => write!(f, "<{} more not shown>", claimed - len)?,
            Shortfall::Unreadable => write!(f, "<{} more unreadable>", claimed - len)?,
        }
    }
    write_seq_close(f, pretty, ctx.prefix, ctx.depth, true)?;
    write!(f, "]")
}

#[derive(Copy, Clone)]
struct BTreeNodeLayout<'a> {
    key: BundleType<'a>,
    value: BundleType<'a>,
    leaf: BundleType<'a>,
    leaf_len: BundleType<'a>,
    leaf_len_offset: u64,
    keys_offset: u64,
    key_slots: u64,
    values_offset: u64,
    internal: BundleType<'a>,
    edges_offset: u64,
    edge: BundleType<'a>,
    edge_pointer_offset: u64,
}

pub(crate) enum MapWalkError {
    Format,
    Invalid(&'static str),
    Marker(&'static str),
}

impl From<fmt::Error> for MapWalkError {
    fn from(_: fmt::Error) -> Self {
        Self::Format
    }
}

/// Render the presentation shared by associative collections. The entry source
/// owns storage traversal; this function owns recursive key/value display,
/// exact-length accounting, and inline/pretty punctuation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn eval_map<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    ty: &BundleType<'a>,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
    length_offset: u64,
    length_size: u32,
    key: BundleType<'a>,
    value: Option<BundleType<'a>>,
    entries: &MapEntries<'a>,
) -> fmt::Result {
    let Some(map_length) = read_unsigned_at(bytes, length_offset, u64::from(length_size)) else {
        return write!(f, "<truncated>");
    };
    f.write_str(ty.name())?;
    f.write_str(" {")?;
    if map_length == 0 {
        return write!(f, "}}");
    }

    // Keys and values stand in slots of the map, whose type names both.
    let entry_ctx = ctx.deeper().positional(*ty);

    // A big map formats its entries on worker threads: the storage walk
    // runs once collecting entry addresses, then chunks of entries
    // format concurrently and stitch back in walk order.
    if ctx.parallel
        && map_length >= MIN_PARALLEL_ITEMS
        && let Some(visited) = ctx.visited
    {
        return eval_map_parallel(
            f, bytes, ctx, entry_ctx, visited, pretty, map_length, key, value, entries,
        );
    }

    let mut emitted = 0u64;
    let walk = walk_map_entries(bytes, ctx, key, value, entries, &mut |key, value| {
        if emitted == map_length {
            return Err(MapWalkError::Invalid(
                "map contains more entries than length",
            ));
        }
        write_field_prefix(f, pretty, ctx.prefix, ctx.depth, emitted == 0)?;
        write_display_value(f, &key, entry_ctx, pretty)?;
        if let Some(value) = value {
            write!(f, ": ")?;
            write_display_value(f, &value, entry_ctx, pretty)?;
        }
        if pretty {
            write!(f, ",")?;
        }
        emitted += 1;
        Ok(())
    });

    write_map_tail(f, ctx.prefix, walk, emitted, map_length, pretty, ctx.depth)
}

/// The accounting a map render closes with, shared by the streaming and
/// parallel paths: the marker for a walk that ended early or found the
/// wrong number of entries, then the closing punctuation.
fn write_map_tail(
    f: &mut fmt::Formatter<'_>,
    prefix: &str,
    walk: std::result::Result<(), MapWalkError>,
    emitted: u64,
    map_length: u64,
    pretty: bool,
    depth: usize,
) -> fmt::Result {
    match walk {
        Ok(()) if emitted == map_length => {}
        Ok(()) => {
            write_field_prefix(f, pretty, prefix, depth, emitted == 0)?;
            write!(f, "<invalid: map contains fewer entries than length>")?;
        }
        Err(MapWalkError::Invalid(reason)) => {
            write_field_prefix(f, pretty, prefix, depth, emitted == 0)?;
            write!(f, "<invalid: {reason}>")?;
        }
        Err(MapWalkError::Marker(marker)) => {
            write_field_prefix(f, pretty, prefix, depth, emitted == 0)?;
            write!(f, "{marker}")?;
        }
        Err(MapWalkError::Format) => return Err(fmt::Error),
    }

    write_record_close(f, pretty, prefix, depth)?;
    write!(f, "}}")
}

/// [`eval_map`]'s body with the entries formatted on worker threads.
/// The walk runs first, collecting each entry's key and value address
/// under the same length accounting the streaming path applies; workers
/// then re-borrow the bytes at those addresses — free against a mapped
/// core — and format chunks of entries into buffers stitched back in
/// walk order.
#[allow(clippy::too_many_arguments)]
fn eval_map_parallel<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    entry_ctx: RenderCtx<'_, 'a, T>,
    visited: &RefCell<HashSet<(u64, BundleTypeId)>>,
    pretty: bool,
    map_length: u64,
    key: BundleType<'a>,
    value: Option<BundleType<'a>>,
    entries: &MapEntries<'a>,
) -> fmt::Result {
    let mut collected: Vec<(u64, Option<u64>)> = Vec::new();
    let walk = walk_map_entries(bytes, ctx, key, value, entries, &mut |key, value| {
        if collected.len() as u64 == map_length {
            return Err(MapWalkError::Invalid(
                "map contains more entries than length",
            ));
        }
        collected.push((key.addr, value.map(|value| value.addr)));
        Ok(())
    });

    let seed = visited.borrow().clone();
    let worker = entry_ctx.for_workers();
    let (entries_ref, depth) = (&collected, ctx.depth);
    render_chunked(f, collected.len(), |range, out| {
        let task_visited = RefCell::new(seed.clone());
        let formats = FormatCache::default();
        let task_ctx = worker.ctx(&task_visited, &formats);
        let _ = write!(
            out,
            "{}",
            DisplayWith(|f: &mut fmt::Formatter<'_>| {
                for index in range.clone() {
                    let (key_addr, value_addr) = entries_ref[index];
                    let value = value.zip(value_addr);
                    write_field_prefix(f, pretty, task_ctx.prefix, depth, index == 0)?;
                    write_map_entry(f, key, key_addr, value, task_ctx, pretty)?;
                }
                Ok(())
            })
        );
    })?;

    write_map_tail(
        f,
        ctx.prefix,
        walk,
        collected.len() as u64,
        map_length,
        pretty,
        depth,
    )
}

/// One map entry — `key: value`, or a set's `key`, and pretty's trailing
/// comma — from the addresses the collect pass recorded. The walk had
/// these very bytes in hand; a target that stops answering between the
/// walk and the format degrades like any other failed read.
fn write_map_entry<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    key: BundleType<'a>,
    key_addr: u64,
    value: Option<(BundleType<'a>, u64)>,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let read = |ty: BundleType<'a>, addr: u64| {
        ctx.read(addr, ty.size())
            .map(|bytes| Value { ty, addr, bytes })
    };
    let (key, value) = match (read(key, key_addr), value.map(|(ty, addr)| read(ty, addr))) {
        (Ok(key), None) => (key, None),
        (Ok(key), Some(Ok(value))) => (key, Some(value)),
        (Err(marker), _) | (_, Some(Err(marker))) => return f.write_str(marker),
    };
    write_display_value(f, &key, ctx, pretty)?;
    if let Some(value) = value {
        write!(f, ": ")?;
        write_display_value(f, &value, ctx, pretty)?;
    }
    if pretty {
        write!(f, ",")?;
    }
    Ok(())
}

/// Hand each entry of a map to `emit`, in the storage's own order: its key,
/// and its value unless the map is a set.
pub(crate) fn walk_map_entries<'a, T: Target>(
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    key: BundleType<'a>,
    value: Option<BundleType<'a>>,
    entries: &MapEntries<'a>,
    emit: &mut impl FnMut(Value<'a>, Option<Value<'a>>) -> std::result::Result<(), MapWalkError>,
) -> std::result::Result<(), MapWalkError> {
    let (
        MapEntries::BTree {
            root,
            root_offset,
            root_node,
            root_node_offset,
            height,
            height_offset,
            node_offset,
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
        },
        Some(value),
    ) = (entries, value)
    else {
        return walk_hash_entries(bytes, ctx, key, value, entries, emit);
    };

    let root_bytes = byte_range(bytes, *root_offset, root.size())
        .ok_or(MapWalkError::Marker("<truncated root>"))?;
    if !matches!(root.check_variant(root_bytes, "Some"), Some(Ok(Some(_)))) {
        return Err(MapWalkError::Marker("<invalid missing root>"));
    }

    let root_node_bytes = byte_range(bytes, *root_node_offset, root_node.size())
        .ok_or(MapWalkError::Marker("<truncated root node>"))?;
    let height = read_unsigned_at(root_node_bytes, *height_offset, height.size())
        .ok_or(MapWalkError::Marker("<truncated height>"))?;
    let root_address = read_u64_at(root_node_bytes, *node_offset)
        .ok_or(MapWalkError::Marker("<truncated node pointer>"))?;

    let layout = BTreeNodeLayout {
        key,
        value,
        leaf: *leaf,
        leaf_len: *leaf_len,
        leaf_len_offset: *leaf_len_offset,
        keys_offset: *keys_offset,
        key_slots: *key_slots,
        values_offset: *values_offset,
        internal: *internal,
        edges_offset: *edges_offset,
        edge: *edge,
        edge_pointer_offset: *edge_pointer_offset,
    };
    walk_btree_node(
        ctx,
        layout,
        root_address,
        height,
        &mut HashSet::default(),
        emit,
    )
}

fn walk_btree_node<'a, T: Target>(
    ctx: RenderCtx<'_, 'a, T>,
    layout: BTreeNodeLayout<'a>,
    address: u64,
    height: u64,
    visited: &mut HashSet<u64>,
    emit: &mut impl FnMut(Value<'a>, Option<Value<'a>>) -> std::result::Result<(), MapWalkError>,
) -> std::result::Result<(), MapWalkError> {
    if address == 0 {
        return Err(MapWalkError::Invalid("null node pointer"));
    }
    if height > 64 {
        return Err(MapWalkError::Invalid("implausible tree height"));
    }
    if !visited.insert(address) {
        return Err(MapWalkError::Invalid("node cycle"));
    }

    let result = (|| {
        let node_type = if height == 0 {
            layout.leaf
        } else {
            layout.internal
        };
        // A node the allocator has taken back is not a node: the walk
        // stops at it rather than reading whatever the last owner left
        // in the slot and emitting it as entries.
        let bytes = ctx
            .read(address, node_type.size())
            .map_err(|marker| match marker {
                "<freed>" => MapWalkError::Marker("<freed node>"),
                _ => MapWalkError::Invalid("unreadable node"),
            })?;
        let len = read_unsigned_at(bytes, layout.leaf_len_offset, layout.leaf_len.size())
            .ok_or(MapWalkError::Invalid("truncated node length"))?;
        if len > layout.key_slots {
            return Err(MapWalkError::Invalid("node length exceeds capacity"));
        }

        for index in 0..len {
            if height > 0 {
                let child = btree_edge_address(bytes, layout, index)?;
                walk_btree_node(ctx, layout, child, height - 1, visited, emit)?;
            }
            let key_start = layout
                .keys_offset
                .checked_add(
                    index
                        .checked_mul(layout.key.size())
                        .ok_or(MapWalkError::Invalid("key offset overflow"))?,
                )
                .ok_or(MapWalkError::Invalid("key offset overflow"))?;
            let value_start = layout
                .values_offset
                .checked_add(
                    index
                        .checked_mul(layout.value.size())
                        .ok_or(MapWalkError::Invalid("value offset overflow"))?,
                )
                .ok_or(MapWalkError::Invalid("value offset overflow"))?;
            let key_bytes = byte_range(bytes, key_start, layout.key.size())
                .ok_or(MapWalkError::Invalid("truncated key slot"))?;
            let value_bytes = byte_range(bytes, value_start, layout.value.size())
                .ok_or(MapWalkError::Invalid("truncated value slot"))?;
            let key_addr = address
                .checked_add(key_start)
                .ok_or(MapWalkError::Invalid("key address overflow"))?;
            let value_addr = address
                .checked_add(value_start)
                .ok_or(MapWalkError::Invalid("value address overflow"))?;
            let key = Value {
                ty: layout.key,
                addr: key_addr,
                bytes: key_bytes,
            };
            let value = Value {
                ty: layout.value,
                addr: value_addr,
                bytes: value_bytes,
            };
            emit(key, Some(value))?;
        }
        if height > 0 {
            let child = btree_edge_address(bytes, layout, len)?;
            walk_btree_node(ctx, layout, child, height - 1, visited, emit)?;
        }
        Ok(())
    })();
    visited.remove(&address);
    result
}

fn btree_edge_address<'a>(
    bytes: &[u8],
    layout: BTreeNodeLayout<'a>,
    index: u64,
) -> std::result::Result<u64, MapWalkError> {
    let offset = layout
        .edges_offset
        .checked_add(
            index
                .checked_mul(layout.edge.size())
                .ok_or(MapWalkError::Invalid("edge offset overflow"))?,
        )
        .and_then(|offset| offset.checked_add(layout.edge_pointer_offset))
        .ok_or(MapWalkError::Invalid("edge offset overflow"))?;
    read_u64_at(bytes, offset).ok_or(MapWalkError::Invalid("truncated edge slot"))
}

/// The most buckets a hash table is believed to have. Its control bytes are
/// read in one piece, one per bucket, so a mask out of dead memory would
/// otherwise ask for whatever its bits say.
const MAX_HASH_BUCKETS: u64 = 1 << 32;

/// Walk a hashbrown table's full buckets in bucket order. The control bytes
/// are read first and the buckets only where one of them is full, so an
/// empty table — whose control pointer names a static group with nothing
/// of the table's below it — reads nothing it does not have.
fn walk_hash_entries<'a, T: Target>(
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    key: BundleType<'a>,
    value: Option<BundleType<'a>>,
    entries: &MapEntries<'a>,
    emit: &mut impl FnMut(Value<'a>, Option<Value<'a>>) -> std::result::Result<(), MapWalkError>,
) -> std::result::Result<(), MapWalkError> {
    let MapEntries::Hash {
        bucket_mask_offset,
        ctrl_offset,
        bucket,
        key_offset,
        value_offset,
    } = entries
    else {
        return Err(MapWalkError::Invalid(
            "storage does not match the map's value",
        ));
    };
    let mask = read_u64_at(bytes, *bucket_mask_offset)
        .ok_or(MapWalkError::Marker("<truncated bucket mask>"))?;
    let ctrl = read_u64_at(bytes, *ctrl_offset)
        .ok_or(MapWalkError::Marker("<truncated control pointer>"))?;
    let buckets = mask
        .checked_add(1)
        .filter(|buckets| buckets.is_power_of_two())
        .ok_or(MapWalkError::Invalid(
            "bucket mask is not a power of two less one",
        ))?;
    if buckets > MAX_HASH_BUCKETS {
        return Err(MapWalkError::Invalid("implausible bucket count"));
    }
    if ctrl == 0 {
        return Err(MapWalkError::Invalid("null control pointer"));
    }
    let stride = bucket.size();
    let span = buckets
        .checked_mul(stride)
        .ok_or(MapWalkError::Invalid("table size overflow"))?;
    let base = ctrl
        .checked_sub(span)
        .ok_or(MapWalkError::Invalid("buckets start below address zero"))?;
    let unreadable = |what| {
        move |marker| match marker {
            "<freed>" => MapWalkError::Marker("<freed table>"),
            "<target unavailable>" => MapWalkError::Marker("<target unavailable>"),
            _ => MapWalkError::Invalid(what),
        }
    };
    let control = ctx
        .read(ctrl, buckets)
        .map_err(unreadable("unreadable control bytes"))?;
    if control.iter().all(|byte| byte & 0x80 != 0) {
        return Ok(());
    }

    // The buckets and the control bytes are one allocation, the buckets
    // at its start: a block that does not hold both is not this table's.
    // One the allocator took back the bucket read below refuses.
    if let Some(heap) = ctx.heap
        && let Liveness::Live { block } = heap.locate(base)
        && block.end < ctrl.saturating_add(buckets)
    {
        heap.note(Gate::Clipped);
        return Err(MapWalkError::Invalid("table runs past its allocation"));
    }
    let slots = ctx
        .read(base, span)
        .map_err(unreadable("unreadable buckets"))?;
    for (index, byte) in control.iter().enumerate() {
        if byte & 0x80 != 0 {
            continue;
        }
        // Bucket `i` ends `i` buckets below the control bytes.
        let start = (buckets - 1 - index as u64) * stride;
        let entry = |ty: BundleType<'a>, offset: u64, what| {
            let at = start + offset;
            byte_range(slots, at, ty.size())
                .map(|bytes| Value {
                    ty,
                    addr: base + at,
                    bytes,
                })
                .ok_or(MapWalkError::Invalid(what))
        };
        let key = entry(key, *key_offset, "truncated key slot")?;
        let value = match value.zip(*value_offset) {
            Some((value, offset)) => Some(entry(value, offset, "truncated value slot")?),
            None => None,
        };
        emit(key, value)?;
    }
    Ok(())
}

/// Walk the intrusive linked list at `head_offset` (0 = empty), rendering each
/// `node_ty` element via `node`. Each node is read from the target and the walk
/// follows the successor word at `next_offset`, guarded against cycles and
/// runaway length — the shared successor of the old `write_*_waiters` pair.
///
/// Elements render compactly (inline) regardless of `pretty`; `pretty` only
/// puts each on its own indented line. A queue entry is small, so this reads
/// far better than expanding every entry across several lines.
#[allow(clippy::too_many_arguments)]
pub(crate) fn eval_list<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    head_offset: u64,
    next_offset: u64,
    node: &DisplayNode<'a>,
    node_ty: &BundleType<'a>,
    node_size: u32,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let Some(head) = read_u64_at(bytes, head_offset) else {
        return write!(f, "<truncated>");
    };
    // An empty list is known from the head word alone; a populated one needs
    // the target to read each node.
    if head == 0 {
        return write!(f, "[]");
    }
    if ctx.proc.is_none() {
        return write!(f, "<target unavailable>");
    }
    write!(f, "[")?;

    let mut cur = head;
    let mut any = false;
    let mut seen = HashSet::default();
    let mut guard = 4096u32;
    while cur != 0 && guard > 0 {
        guard -= 1;
        if !seen.insert(cur) {
            break;
        }
        let node_bytes = match ctx.read(cur, u64::from(node_size)) {
            Ok(bytes) => bytes,
            Err(marker) => {
                write!(f, "{}{marker}", if any { ", " } else { "" })?;
                break;
            }
        };
        write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, !any)?;
        any = true;
        // Each element renders inline (`pretty = false`) even in pretty mode,
        // in a `[…]` that prints no type of its own.
        eval_node(
            f,
            node,
            node_ty,
            node_bytes,
            cur,
            ctx.deeper().unnamed(),
            false,
        )?;
        if pretty {
            write!(f, ",")?;
        }
        match read_u64_at(node_bytes, next_offset) {
            Some(next) => cur = next,
            None => break,
        }
    }
    write_seq_close(f, pretty, ctx.prefix, ctx.depth, any)?;
    write!(f, "]")
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;

    use hansei_bundle::BundleView;

    #[test]
    fn test_vec_displays_initialized_elements() {
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x2000u64, 3, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(VEC).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "[5, 8, 13]"
        );
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "[\n    5,\n    8,\n    13,\n]"
        );

        let invalid: Vec<u8> = [0x2000u64, 5, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(VEC).unwrap(), 0, &invalid);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "<invalid slice: the length exceeds the capacity>"
        );
    }

    #[test]
    fn test_slice_displays_initialized_elements() {
        // A `&[T]`/`Box<[T]>` renders through the same `Slice` node as `Vec`
        // but with no capacity word, so the length is used directly (the
        // capacity-less path — otherwise untested).
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        // A `(data_ptr, length)` fat pointer: address then element count, no
        // capacity word.
        let bytes: Vec<u8> = [0x2000u64, 3]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(SLICE).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "[5, 8, 13]"
        );
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "[\n    5,\n    8,\n    13,\n]"
        );
    }

    #[test]
    fn test_btree_map_displays_only_initialized_slots_in_order() {
        // A root holding key 2, with a smaller leaf left and a larger right.
        let mem = FakeMem::new()
            .at(0x1000, btree_internal(&[(2, 20)], &[0x2000, 0x3000]))
            .at(0x2000, btree_leaf(&[(1, 10)]))
            .at(0x3000, btree_leaf(&[(3, 30)]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&3u64.to_le_bytes());
        let value = Value::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);

        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "alloc::collections::btree::map::BTreeMap<u32, u32> { 1: 10, 2: 20, 3: 30 }"
        );
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert!(shown.contains("\n    1: 10,"), "{shown}");
        assert!(shown.contains("\n    2: 20,"), "{shown}");
        assert!(shown.contains("\n    3: 30,"), "{shown}");
        assert!(
            !shown.contains("2863311530"),
            "unused 0xaa slots leaked: {shown}"
        );
    }

    /// A slice long enough to cross the parallel threshold formats its
    /// elements on worker threads, chunked and stitched invisibly: the
    /// output is exactly what streaming produces, inline and pretty.
    /// (The three-element tests above stay under the threshold and
    /// cover the sequential path.)
    #[test]
    fn test_long_slice_renders_identically_in_parallel() {
        let values: Vec<u32> = (0..100).collect();
        let mem = FakeMem::new().at(0x2000, u32s(&values));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x2000u64, 100, 100]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(VEC).unwrap(), 0, &bytes);

        let inline = (0..100).map(|i| i.to_string()).collect::<Vec<_>>();
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            format!("[{}]", inline.join(", "))
        );
        let pretty: String = (0..100).map(|i| format!("\n    {i},")).collect();
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            format!("[{pretty}\n]")
        );
    }

    /// A map big enough to cross the parallel threshold renders its
    /// entries on worker threads: one walk collects the entry
    /// addresses, chunks format concurrently, and the stitched output
    /// is what streaming produces — a full height-three tree's 80
    /// entries in key order, none missing, none doubled.
    #[test]
    fn test_big_btree_map_renders_identically_in_parallel() {
        /// Build a full subtree bottom-up, assigning keys in traversal
        /// order so the expected text is just the keys in sequence;
        /// every value is its key plus 1000.
        fn build(
            nodes: &mut Vec<(u64, Vec<u8>)>,
            next_addr: &mut u64,
            next_key: &mut u32,
            height: u64,
        ) -> u64 {
            let addr = *next_addr;
            *next_addr += 0x100;
            if height == 0 {
                let k = *next_key;
                *next_key += 2;
                nodes.push((addr, btree_leaf(&[(k, k + 1000), (k + 1, k + 1001)])));
            } else {
                let e0 = build(nodes, next_addr, next_key, height - 1);
                let k0 = *next_key;
                *next_key += 1;
                let e1 = build(nodes, next_addr, next_key, height - 1);
                let k1 = *next_key;
                *next_key += 1;
                let e2 = build(nodes, next_addr, next_key, height - 1);
                nodes.push((
                    addr,
                    btree_internal(&[(k0, k0 + 1000), (k1, k1 + 1000)], &[e0, e1, e2]),
                ));
            }
            addr
        }

        let mut nodes = Vec::new();
        let (mut next_addr, mut next_key) = (0x10_0000u64, 0u32);
        let root = build(&mut nodes, &mut next_addr, &mut next_key, 3);
        assert_eq!(next_key, 80, "a full height-3 tree holds 80 entries");
        let mut mem = FakeMem::new();
        for (addr, bytes) in nodes {
            mem = mem.at(addr, bytes);
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&root.to_le_bytes());
        bytes[8..16].copy_from_slice(&3u64.to_le_bytes());
        bytes[16..].copy_from_slice(&80u64.to_le_bytes());
        let value = Value::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);

        let entries = (0..80)
            .map(|k| format!("{k}: {}", k + 1000))
            .collect::<Vec<_>>();
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            format!(
                "alloc::collections::btree::map::BTreeMap<u32, u32> {{ {} }}",
                entries.join(", ")
            )
        );
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        for k in 0..80u32 {
            assert!(
                shown.contains(&format!("\n    {k}: {},", k + 1000)),
                "entry {k} missing from:\n{shown}"
            );
        }
    }

    #[test]
    fn test_btree_map_reports_length_mismatch_and_node_cycle() {
        // One leaf holding a single entry, against a map claiming two.
        let one_leaf = FakeMem::new().at(0x1000, btree_leaf(&[(1, 10)]));
        // An internal node whose first edge points back at itself.
        let self_cycle = FakeMem::new().at(0x1000, btree_internal(&[], &[0x1000]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let ty = v.ty(BTREE_MAP).unwrap();
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[16..].copy_from_slice(&2u64.to_le_bytes());
        let value = Value::new(ty, 0x5000, &bytes);
        let shown = format!("{}", value.display_from_target(&one_leaf, 8));
        assert!(
            shown.contains("<invalid: map contains fewer entries than length>"),
            "{shown}"
        );

        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&1u64.to_le_bytes());
        let value = Value::new(ty, 0x5000, &bytes);
        let shown = format!("{}", value.display_from_target(&self_cycle, 8));
        assert!(shown.contains("<invalid: node cycle>"), "{shown}");
    }

    /// A tree node the allocator has taken back is not walked. The bytes
    /// in the slot decode as entries perfectly well — a freed node keeps
    /// whatever the last owner left — so nothing but the allocator can
    /// tell that they are not this map's, and the walk stops at the node
    /// rather than emitting them.
    /// A byte sequence is capped the way a string is: it is a string
    /// in all but type — a `CString`'s buffer, a `Vec<u8>` — and a
    /// fabricated length costs the same to print either way. Wider
    /// elements are left alone, so an ordinary `Vec<u32>` is never
    /// abbreviated by a byte budget.
    #[test]
    fn test_a_byte_sequence_is_capped_but_a_wider_one_is_not() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x2000, vec![7u8; 16])
            .at(0x3000, u32s(&[5, 8, 13, 21]));

        // A `&[u8]` of sixteen, shown three deep.
        let bytes_header = u64s(&[0x2000, 16]);
        let shown = format!(
            "{}",
            Value::new(v.ty(BYTE_SLICE).unwrap(), 0x1000, &bytes_header)
                .display_from_target(&mem, 8)
                .max_str_len(Some(3))
        );
        assert_eq!(shown, "[7, 7, 7, <13 more not shown>]");

        // The same cap over four-byte elements changes nothing: the
        // budget is bytes, and cutting a `Vec<u32>` at three of them
        // would abbreviate a value nobody asked to have abbreviated.
        let wide_header = u64s(&[0x3000, 4]);
        let wide = |cap_str, cap_arr| {
            format!(
                "{}",
                Value::new(v.ty(SLICE).unwrap(), 0x1000, &wide_header)
                    .display_from_target(&mem, 8)
                    .max_str_len(cap_str)
                    .max_array_len(cap_arr)
            )
        };
        assert_eq!(wide(Some(3), None), "[5, 8, 13, 21]");
        // It answers to its own budget, which is counted in elements
        // rather than bytes — a wide element is a value with a line of
        // its own, not a character.
        assert_eq!(wide(None, Some(2)), "[5, 8, <2 more not shown>]");
        assert_eq!(wide(None, Some(4)), "[5, 8, 13, 21]");
    }

    /// An inline array answers to the element budget too. Its count is
    /// the type's rather than the target's, so it cannot be fabricated
    /// — but a declared million-element array still costs a million
    /// lines, and the budget is about what a render costs.
    #[test]
    fn test_an_inline_array_answers_to_the_element_budget() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();
        // The fixture declares `[u32; 3]`.
        let bytes = u32s(&[1, 2, 3]);
        let arr = || Value::new(v.ty(ARR).unwrap(), 0x1000, &bytes);

        assert_eq!(
            format!(
                "{}",
                arr().display_from_target(&mem, 8).max_array_len(Some(2))
            ),
            "[0x00000001, 0x00000002, <1 more not shown>]"
        );
        assert_eq!(
            format!("{}", arr().display_from_target(&mem, 8).max_array_len(None)),
            "[0x00000001, 0x00000002, 0x00000003]"
        );
    }

    #[test]
    fn test_a_freed_btree_node_stops_the_walk() {
        let mem = FakeMem::new().at(0x1000, btree_leaf(&[(1, 10)]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let ty = v.ty(BTREE_MAP).unwrap();
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[16..].copy_from_slice(&1u64.to_le_bytes());
        let value = Value::new(ty, 0x5000, &bytes);

        // Live, and the entry is read as usual.
        let live = FakeHeap::new().live(0x1000, 0x400);
        let shown = format!("{}", value.display_from_target(&mem, 8).heap(&live));
        assert!(shown.contains("1: 10"), "{shown}");
        assert_eq!(live.counts(), (0, 0, 0));

        // Freed, and the same bytes are refused.
        let freed = FakeHeap::new().freed(0x1000, 0x400);
        let shown = format!("{}", value.display_from_target(&mem, 8).heap(&freed));
        assert!(shown.contains("<freed node>"), "{shown}");
        assert!(!shown.contains("1: 10"), "{shown}");
        assert_eq!(freed.counts(), (1, 0, 0));
    }

    /// The length-mismatch markers join the entry list with the same
    /// punctuation an entry gets: after a comma when entries were rendered,
    /// as the whole body when none were.
    #[test]
    fn test_btree_map_length_mismatch_markers_join_the_entry_list() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ty = v.ty(BTREE_MAP).unwrap();
        let show = |mem: &FakeMem, length: u64| {
            let bytes = u64s(&[0x1000, 0, length]);
            format!(
                "{}",
                Value::new(ty, 0x5000, &bytes).display_from_target(mem, 8)
            )
        };

        // One entry against a claim of two: the marker follows the entry.
        let one = FakeMem::new().at(0x1000, btree_leaf(&[(1, 10)]));
        assert_eq!(
            show(&one, 2),
            "alloc::collections::btree::map::BTreeMap<u32, u32> \
             { 1: 10, <invalid: map contains fewer entries than length> }"
        );
        // No entries against a claim of one: the marker is the whole body.
        let empty = FakeMem::new().at(0x1000, btree_leaf(&[]));
        assert_eq!(
            show(&empty, 1),
            "alloc::collections::btree::map::BTreeMap<u32, u32> \
             { <invalid: map contains fewer entries than length> }"
        );
        // Two entries against a claim of one: the walk is cut off after the
        // rendered entry and the marker follows it.
        let two = FakeMem::new().at(0x1000, btree_leaf(&[(1, 10), (2, 20)]));
        assert_eq!(
            show(&two, 1),
            "alloc::collections::btree::map::BTreeMap<u32, u32> \
             { 1: 10, <invalid: map contains more entries than length> }"
        );
    }

    /// A hash table's words as [`HASH_MAP`]/[`HASH_SET`] lay them out.
    fn table_words(ctrl: u64, buckets: u64, items: u64) -> Vec<u8> {
        u64s(&[ctrl, buckets - 1, 0, items])
    }

    fn pair(key: u32, value: u32) -> Vec<u8> {
        u32s(&[key, value])
    }

    /// Only a control byte with its top bit clear is a full bucket, and
    /// the buckets are read in control-byte order from below the control
    /// bytes: an EMPTY (`0xff`) and a DELETED (`0x80`) bucket are skipped
    /// whatever their slots hold, and a set prints its keys alone.
    #[test]
    fn test_hash_map_displays_full_buckets_in_bucket_order() {
        let table = hash_table(
            &[0x11, 0xff, 0x80, 0x7f],
            8,
            &[(0, pair(1, 10)), (2, pair(99, 99)), (3, pair(3, 30))],
        );
        let ctrl = 0x1000 + 4 * 8;
        let mem = FakeMem::new().at(0x1000, table);
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = table_words(ctrl, 4, 2);
        let value = Value::new(v.ty(HASH_MAP).unwrap(), 0x5000, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "hashbrown::map::HashMap<u32, u32> { 1: 10, 3: 30 }"
        );
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "hashbrown::map::HashMap<u32, u32> {\n    1: 10,\n    3: 30,\n}"
        );

        let set = hash_table(
            &[0xff, 0x05, 0x06, 0xff],
            4,
            &[(1, u32s(&[7])), (2, u32s(&[9]))],
        );
        let mem = FakeMem::new().at(0x1000, set);
        let bytes = table_words(0x1000 + 4 * 4, 4, 2);
        let value = Value::new(v.ty(HASH_SET).unwrap(), 0x5000, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "hashbrown::set::HashSet<u32> { 7, 9 }"
        );
    }

    /// An empty table is known from its item count alone: its control
    /// pointer names a static group with nothing of the table's around it,
    /// so nothing is read.
    #[test]
    fn test_an_empty_hash_map_reads_nothing() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = table_words(0x9999_0000, 1, 0);
        let value = Value::new(v.ty(HASH_MAP).unwrap(), 0x5000, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&FakeMem::new(), 8)),
            "hashbrown::map::HashMap<u32, u32> {}"
        );
    }

    /// The words a table is walked from are believed only as far as they
    /// describe a table: a mask that is not a power of two less one, a
    /// null control pointer, an item count the full buckets do not bear
    /// out, control bytes the target cannot serve, and a bucket count past
    /// any real table each end the walk with the reason.
    #[test]
    fn test_hash_map_refuses_words_that_describe_no_table() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ty = v.ty(HASH_MAP).unwrap();
        let table = hash_table(&[0x11, 0xff], 8, &[(0, pair(1, 10))]);
        let mem = FakeMem::new().at(0x1000, table);
        let ctrl = 0x1000 + 2 * 8;
        let show = |words: &[u64]| {
            let bytes = u64s(words);
            format!(
                "{}",
                Value::new(ty, 0x5000, &bytes).display_from_target(&mem, 8)
            )
        };
        let name = "hashbrown::map::HashMap<u32, u32>";
        assert_eq!(
            show(&[ctrl, 2, 0, 1]),
            format!("{name} {{ <invalid: bucket mask is not a power of two less one> }}")
        );
        assert_eq!(
            show(&[0, 1, 0, 1]),
            format!("{name} {{ <invalid: null control pointer> }}")
        );
        assert_eq!(
            show(&[ctrl, 1, 0, 2]),
            format!("{name} {{ 1: 10, <invalid: map contains fewer entries than length> }}")
        );
        assert_eq!(
            show(&[0x7000, 1, 0, 1]),
            format!("{name} {{ <invalid: unreadable control bytes> }}")
        );
        assert_eq!(
            show(&[ctrl, (1 << 40) - 1, 0, 1]),
            format!("{name} {{ <invalid: implausible bucket count> }}")
        );
        // The cap itself is a count a table may have: believed, and
        // then held to what the target can serve.
        assert_eq!(
            show(&[1 << 40, (1 << 32) - 1, 0, 1]),
            format!("{name} {{ <invalid: unreadable control bytes> }}")
        );
        // Control bytes marking nothing full are read and nothing more:
        // no bucket below them is asked for, whether or not the target
        // has one. Every one full, every one is read.
        let empty = FakeMem::new().at(0x2000, vec![0xff, 0xff]);
        let bytes = u64s(&[0x2000, 1, 0, 1]);
        assert_eq!(
            format!(
                "{}",
                Value::new(ty, 0x5000, &bytes).display_from_target(&empty, 8)
            ),
            format!("{name} {{ <invalid: map contains fewer entries than length> }}")
        );
        let full = FakeMem::new().at(
            0x1000,
            hash_table(&[0x01, 0x02], 8, &[(0, pair(1, 10)), (1, pair(2, 20))]),
        );
        let bytes = u64s(&[0x1000 + 2 * 8, 1, 0, 2]);
        assert_eq!(
            format!(
                "{}",
                Value::new(ty, 0x5000, &bytes).display_from_target(&full, 8)
            ),
            format!("{name} {{ 1: 10, 2: 20 }}")
        );
        // With no target to read at all, that is what the walk says:
        // nothing is wrong with the table.
        let bytes = u64s(&[ctrl, 1, 0, 1]);
        assert_eq!(
            format!("{}", Value::new(ty, 0x5000, &bytes).display()),
            format!("{name} {{ <target unavailable> }}")
        );
    }

    /// The buckets and their control bytes are one allocation: a table in
    /// a block the allocator took back is refused, and so is one whose
    /// control bytes run past the end of the block its buckets start in.
    #[test]
    fn test_a_hash_table_is_held_to_its_allocation() {
        let table = hash_table(&[0x11, 0xff], 8, &[(0, pair(1, 10))]);
        let mem = FakeMem::new().at(0x1000, table);
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = table_words(0x1000 + 2 * 8, 2, 1);
        let value = Value::new(v.ty(HASH_MAP).unwrap(), 0x5000, &bytes);
        let shown = |heap: &FakeHeap| format!("{}", value.display_from_target(&mem, 8).heap(heap));

        let live = FakeHeap::new().live(0x1000, 0x40);
        assert_eq!(shown(&live), "hashbrown::map::HashMap<u32, u32> { 1: 10 }");
        assert_eq!(live.counts(), (0, 0, 0));
        // A block ending at the last control byte holds the table.
        let exact = FakeHeap::new().live(0x1000, 2 * 8 + 2);
        assert_eq!(shown(&exact), "hashbrown::map::HashMap<u32, u32> { 1: 10 }");
        assert_eq!(exact.counts(), (0, 0, 0));

        let freed = FakeHeap::new().freed(0x1000, 0x40);
        assert!(shown(&freed).contains("<freed table>"), "{}", shown(&freed));
        assert_eq!(freed.counts(), (1, 0, 0));

        // Freed under the buckets alone, the control bytes past it: the
        // bytes read, and the buckets they mark are refused.
        let buckets_freed = FakeHeap::new().freed(0x1000, 2 * 8);
        assert!(
            shown(&buckets_freed).contains("<freed table>"),
            "{}",
            shown(&buckets_freed)
        );
        assert_eq!(buckets_freed.counts(), (1, 0, 0));

        let short = FakeHeap::new().live(0x1000, 0x11);
        assert!(
            shown(&short).contains("<invalid: table runs past its allocation>"),
            "{}",
            shown(&short)
        );
        assert_eq!(short.counts(), (0, 1, 0));
    }

    /// A chain of distinct nodes longer than the iteration cap stops at the
    /// cap: the cycle guard never fires on it, so the cap is the only thing
    /// bounding a corrupt (but acyclic) successor chain.
    #[test]
    fn test_node_list_caps_a_runaway_chain_at_the_iteration_guard() {
        const COUNT: u64 = 4100;
        let base = 0x10_0000u64;
        let mut region = Vec::with_capacity((COUNT * 16) as usize);
        for i in 0..COUNT {
            let next = if i + 1 == COUNT {
                0
            } else {
                base + (i + 1) * 16
            };
            region.extend_from_slice(&waiter_bytes(1, next));
        }
        let mem = FakeMem::new().at(base, region);

        let b = node_bundle();
        let v = BundleView::new(&b);
        let bytes = thing_bytes(0, 0, 0, 0, base);
        let value = Value::new(v.ty(N_THING).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 16));
        let rendered = shown.matches("Waiter {").count();
        assert_eq!(rendered, 4096, "{}", &shown[..shown.len().min(128)]);
    }

    /// A slice long enough that a parallel chunk holds more than one element
    /// still stitches in order — 100 elements make every chunk a single
    /// item on most hosts, leaving the chunk-start arithmetic unexercised.
    #[test]
    fn test_very_long_slice_chunks_stitch_in_order() {
        const N: u32 = 4000;
        let values: Vec<u32> = (0..N).collect();
        let mem = FakeMem::new().at(0x2000, u32s(&values));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x2000, N as u64, N as u64]);
        let value = Value::new(v.ty(VEC).unwrap(), 0, &bytes);
        let inline: Vec<String> = (0..N).map(|i| i.to_string()).collect();
        // The display budget is lifted: what this pins is that the
        // chunks stitch back in order, which takes more elements than
        // anyone would want printed by default.
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8).max_array_len(None)),
            format!("[{}]", inline.join(", "))
        );
    }

    #[test]
    fn test_node_list_empty_and_degradation() {
        // An empty queue (head word 0) needs no target reads.
        let no_reads = FakeMem::new().panic_on_unmapped();

        let b = node_bundle();
        let v = BundleView::new(&b);

        let empty = thing_bytes(0, 0, 0, 0, 0);
        let value = Value::new(v.ty(N_THING).unwrap(), 0, &empty);
        assert_eq!(
            format!("{}", value.display_from_target(&no_reads, 16)),
            "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, queue: [] }"
        );

        // A populated queue with no target reader degrades, not panics.
        let populated = thing_bytes(0, 0, 0, 0, 0x100);
        let value = Value::new(v.ty(N_THING).unwrap(), 0, &populated);
        let shown = format!("{}", value.display());
        assert!(shown.contains("queue: <target unavailable>"), "{shown}");
    }

    #[test]
    fn test_node_list_guards_cycles() {
        // A waiter whose successor points back at itself must not loop forever.
        let mem = FakeMem::new().at(0x100, waiter_bytes(1, 0x100));

        let b = node_bundle();
        let v = BundleView::new(&b);
        let bytes = thing_bytes(0, 0, 0, 0, 0x100);
        let value = Value::new(v.ty(N_THING).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 16)),
            "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, \
             queue: [Waiter { notification: kind=one, order=fifo }] }"
        );
    }

    /// The slice equivalents: a null buffer, an unreadable buffer, and a length
    /// whose byte extent overflows. Each degrades to its own marker instead of
    /// rendering a partial or invented list.
    #[test]
    fn test_slice_read_degradations_are_distinct() {
        let mem = FakeMem::new().unreadable();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let vec_ty = v.ty(VEC).unwrap();
        // Vec is (pointer, length, capacity).
        let fat = |parts: &[u64]| -> Vec<u8> {
            parts.iter().copied().flat_map(u64::to_le_bytes).collect()
        };
        let show = |parts: &[u64]| {
            format!(
                "{}",
                Value::new(vec_ty, 0, &fat(parts)).display_from_target(&mem, 8)
            )
        };

        assert_eq!(show(&[0, 0, 0]), "[]");
        assert_eq!(
            show(&[0, 3, 3]),
            "<invalid slice: the data pointer is null>"
        );
        assert_eq!(show(&[0x2000, 3, 3]), "<unreadable slice buffer>");
        assert_eq!(
            show(&[0x2000, 4, 3]),
            "<invalid slice: the length exceeds the capacity>"
        );
        assert_eq!(
            show(&[0x2000, u64::MAX, u64::MAX]),
            "<invalid slice: the buffer size overflows>"
        );
    }

    /// A length the target can only partly corroborate renders the elements
    /// that are there and says how many are missing, rather than degrading
    /// whole or quietly passing the prefix off as the full sequence.
    #[test]
    fn test_slice_render_reports_a_shortfall() {
        let mem = FakeMem::new().at(0x2000, u32s(&[7, 8, 9]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let fat = u64s(&[0x2000, 1000, 1000]);
        let value = Value::new(v.ty(VEC).unwrap(), 0, &fat);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "[7, 8, 9, <997 more unreadable>]"
        );
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "[\n    7,\n    8,\n    9,\n    <997 more unreadable>\n]"
        );
    }
}

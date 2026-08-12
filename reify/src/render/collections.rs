//! Sequence and map renderers: contiguous slices, intrusive linked lists, and
//! associative collections with their storage-specific entry walks.

use crate::debug_type::{DisplayNode, FatHeader, MapEntries};
use crate::elements::{Elements, SeqError};
use crate::value::Value;

use hansei_bundle::BundleType;

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
    let elements = match Elements::read_fat(header, *element, stride, bytes, ctx.proc) {
        Ok(elements) => elements,
        Err(SeqError::Invalid(why)) => return write!(f, "<invalid slice: {why}>"),
        Err(SeqError::Unreadable(_)) => return write!(f, "<unreadable slice buffer>"),
        Err(SeqError::NoTarget) => return write!(f, "<target unavailable>"),
    };
    if elements.is_empty() {
        // Nothing served of a non-empty claim: the whole buffer is out of
        // reach, which is a degradation, not an empty sequence.
        return match elements.truncated() {
            Some(_) => write!(f, "<unreadable slice buffer>"),
            None => write!(f, "[]"),
        };
    }

    // Vec elements pick their own integer rendering (never hex).
    let element_ctx = ctx.deeper().with_hex(false);
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
        write!(f, "<{} more unreadable>", claimed - len)?;
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

enum MapWalkError {
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
    value: BundleType<'a>,
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

    let entry_ctx = ctx.deeper();

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
    let walk = walk_map_entries(
        bytes,
        ctx.proc,
        key,
        value,
        entries,
        &mut |key_addr, key_bytes, value_addr, value_bytes| {
            if emitted == map_length {
                return Err(MapWalkError::Invalid(
                    "tree contains more entries than length",
                ));
            }
            write_field_prefix(f, pretty, ctx.prefix, ctx.depth, emitted == 0)?;
            let key = Value {
                ty: key,
                addr: key_addr,
                bytes: key_bytes,
            };
            let value = Value {
                ty: value,
                addr: value_addr,
                bytes: value_bytes,
            };
            write_display_value(f, &key, entry_ctx, pretty)?;
            write!(f, ": ")?;
            write_display_value(f, &value, entry_ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
            emitted += 1;
            Ok(())
        },
    );

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
            write!(f, "<invalid: tree contains fewer entries than length>")?;
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
    visited: &RefCell<HashSet<(u64, &'a str)>>,
    pretty: bool,
    map_length: u64,
    key: BundleType<'a>,
    value: BundleType<'a>,
    entries: &MapEntries<'a>,
) -> fmt::Result {
    let mut collected: Vec<(u64, u64)> = Vec::new();
    let walk = walk_map_entries(
        bytes,
        ctx.proc,
        key,
        value,
        entries,
        &mut |key_addr, _, value_addr, _| {
            if collected.len() as u64 == map_length {
                return Err(MapWalkError::Invalid(
                    "tree contains more entries than length",
                ));
            }
            collected.push((key_addr, value_addr));
            Ok(())
        },
    );

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
                    write_field_prefix(f, pretty, task_ctx.prefix, depth, index == 0)?;
                    write_map_entry(f, key, key_addr, value, value_addr, task_ctx, pretty)?;
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

/// One map entry — `key: value` and pretty's trailing comma — from the
/// addresses the collect pass recorded. The walk had these very bytes in
/// hand; a target that stops answering between the walk and the format
/// degrades like any other failed read.
fn write_map_entry<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    key: BundleType<'a>,
    key_addr: u64,
    value: BundleType<'a>,
    value_addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let Some(proc) = ctx.proc else {
        return write!(f, "<target unavailable>");
    };
    let (Ok(key_bytes), Ok(value_bytes)) = (
        proc.read_bytes(key_addr, key.size()),
        proc.read_bytes(value_addr, value.size()),
    ) else {
        return write!(f, "<unreadable>");
    };
    let key = Value {
        ty: key,
        addr: key_addr,
        bytes: key_bytes,
    };
    let value = Value {
        ty: value,
        addr: value_addr,
        bytes: value_bytes,
    };
    write_display_value(f, &key, ctx, pretty)?;
    write!(f, ": ")?;
    write_display_value(f, &value, ctx, pretty)?;
    if pretty {
        write!(f, ",")?;
    }
    Ok(())
}

fn walk_map_entries<'a, T: Target>(
    bytes: &[u8],
    proc: Option<&'a T>,
    key: BundleType<'a>,
    value: BundleType<'a>,
    entries: &MapEntries<'a>,
    emit: &mut impl FnMut(u64, &'a [u8], u64, &'a [u8]) -> std::result::Result<(), MapWalkError>,
) -> std::result::Result<(), MapWalkError> {
    let MapEntries::BTree {
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
    } = entries;

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
    let proc = proc.ok_or(MapWalkError::Marker("<target unavailable>"))?;

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
        proc,
        layout,
        root_address,
        height,
        &mut HashSet::default(),
        emit,
    )
}

fn walk_btree_node<'a, T: Target>(
    proc: &'a T,
    layout: BTreeNodeLayout<'a>,
    address: u64,
    height: u64,
    visited: &mut HashSet<u64>,
    emit: &mut impl FnMut(u64, &'a [u8], u64, &'a [u8]) -> std::result::Result<(), MapWalkError>,
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
        let bytes = proc
            .read_bytes(address, node_type.size())
            .map_err(|_| MapWalkError::Invalid("unreadable node"))?;
        let len = read_unsigned_at(bytes, layout.leaf_len_offset, layout.leaf_len.size())
            .ok_or(MapWalkError::Invalid("truncated node length"))?;
        if len > layout.key_slots {
            return Err(MapWalkError::Invalid("node length exceeds capacity"));
        }

        for index in 0..len {
            if height > 0 {
                let child = btree_edge_address(bytes, layout, index)?;
                walk_btree_node(proc, layout, child, height - 1, visited, emit)?;
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
            emit(key_addr, key_bytes, value_addr, value_bytes)?;
        }
        if height > 0 {
            let child = btree_edge_address(bytes, layout, len)?;
            walk_btree_node(proc, layout, child, height - 1, visited, emit)?;
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
    let Some(proc) = ctx.proc else {
        return write!(f, "<target unavailable>");
    };
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
        let Ok(node_bytes) = proc.read_bytes(cur, u64::from(node_size)) else {
            write!(f, "{}<unreadable>", if any { ", " } else { "" })?;
            break;
        };
        write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, !any)?;
        any = true;
        // Each element renders inline (`pretty = false`) even in pretty mode.
        eval_node(f, node, node_ty, node_bytes, cur, ctx.deeper(), false)?;
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
            shown.contains("<invalid: tree contains fewer entries than length>"),
            "{shown}"
        );

        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&1u64.to_le_bytes());
        let value = Value::new(ty, 0x5000, &bytes);
        let shown = format!("{}", value.display_from_target(&self_cycle, 8));
        assert!(shown.contains("<invalid: node cycle>"), "{shown}");
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

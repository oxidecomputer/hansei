//! Sequence and map renderers: contiguous slices, intrusive linked lists, and
//! associative collections with their storage-specific entry walks.

use crate::debug_type::{DebugType, DisplayNode, MapEntries};
use crate::value::TypeInfoRef;

use crate::target::ReadFromProc;

use std::collections::HashSet;
use std::fmt;

use super::node::eval_node;
use super::scalar::{byte_range, read_u64_at, read_unsigned_at};
use super::{DisplayRecurse, RenderCtx, write_indent, write_seq_close, write_seq_prefix};

/// Follow a `(data, len)` fat pointer to a contiguous buffer and render its
/// first `len` `element`s as `[e, e, …]`. `capacity`, when present, bounds
/// `len` (skipped for a zero-sized element, whose buffer is not read). Unlike
/// [`eval_list`] the elements are contiguous, read in one target access.
#[allow(clippy::too_many_arguments)]
pub(crate) fn eval_slice<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    pointer_offset: u64,
    length_offset: u64,
    length_size: u32,
    capacity: Option<(u64, u32)>,
    element: &T,
    element_size: u32,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let Some(len) = read_unsigned_at(bytes, length_offset, u64::from(length_size)) else {
        return write!(f, "<truncated slice length>");
    };
    let element_size = u64::from(element_size);
    if let Some((capacity_offset, capacity_size)) = capacity {
        let Some(capacity) = read_unsigned_at(bytes, capacity_offset, u64::from(capacity_size))
        else {
            return write!(f, "<truncated slice capacity>");
        };
        if element_size != 0 && len > capacity {
            return write!(f, "<invalid slice: length exceeds capacity>");
        }
    }
    if len == 0 {
        return write!(f, "[]");
    }
    let Some(pointer) = read_u64_at(bytes, pointer_offset) else {
        return write!(f, "<truncated slice pointer>");
    };

    let allocation = if element_size == 0 {
        Vec::new()
    } else {
        if pointer == 0 {
            return write!(f, "<invalid slice: null data pointer>");
        }
        let Some(byte_len) = len.checked_mul(element_size) else {
            return write!(f, "<invalid slice: buffer size overflow>");
        };
        let Some(proc) = ctx.proc else {
            return write!(f, "<target unavailable>");
        };
        let Ok(bytes) = proc.read_bytes(pointer, byte_len) else {
            return write!(f, "<unreadable slice buffer>");
        };
        bytes
    };

    // Vec elements pick their own integer rendering (never hex).
    let element_ctx = ctx.deeper().with_hex(false);
    write!(f, "[")?;
    for index in 0..len {
        write_seq_prefix(f, pretty, ctx.depth, index == 0)?;
        let Some(offset) = index.checked_mul(element_size) else {
            return write!(f, "<invalid element offset>");
        };
        let Some(bytes) = byte_range(&allocation, offset, element_size) else {
            return write!(f, "<truncated element>");
        };
        let Some(address) = pointer.checked_add(offset) else {
            return write!(f, "<invalid element address>");
        };
        let child = DisplayRecurse {
            info: TypeInfoRef {
                ty: *element,
                addr: address,
                bytes,
                _marker: std::marker::PhantomData,
            },
            ctx: element_ctx,
        };
        if pretty {
            write!(f, "{child:#},")?;
        } else {
            write!(f, "{child}")?;
        }
    }
    write_seq_close(f, pretty, ctx.depth, true)?;
    write!(f, "]")
}

#[derive(Copy, Clone)]
struct BTreeNodeLayout<T> {
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
pub(crate) fn eval_map<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    ty: &T,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
    length_offset: u64,
    length_size: u32,
    key: T,
    value: T,
    entries: &MapEntries<T>,
) -> fmt::Result {
    let Some(map_length) = read_unsigned_at(bytes, length_offset, u64::from(length_size)) else {
        return write!(f, "<truncated>");
    };
    write!(f, "{} {{", ty.name())?;
    if map_length == 0 {
        return write!(f, "}}");
    }

    let entry_ctx = ctx.deeper();
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
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            let key = DisplayRecurse {
                info: TypeInfoRef {
                    ty: key,
                    addr: key_addr,
                    bytes: key_bytes,
                    _marker: std::marker::PhantomData,
                },
                ctx: entry_ctx,
            };
            let value = DisplayRecurse {
                info: TypeInfoRef {
                    ty: value,
                    addr: value_addr,
                    bytes: value_bytes,
                    _marker: std::marker::PhantomData,
                },
                ctx: entry_ctx,
            };
            if pretty {
                write!(f, "{key:#}: {value:#},")?;
            } else {
                write!(f, "{key}: {value}")?;
            }
            emitted += 1;
            Ok(())
        },
    );

    match walk {
        Ok(()) if emitted == map_length => {}
        Ok(()) => {
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            write!(f, "<invalid: tree contains fewer entries than length>")?;
        }
        Err(MapWalkError::Invalid(reason)) => {
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            write!(f, "<invalid: {reason}>")?;
        }
        Err(MapWalkError::Marker(marker)) => {
            write_map_entry_prefix(f, pretty, ctx.depth, emitted)?;
            write!(f, "{marker}")?;
        }
        Err(MapWalkError::Format) => return Err(fmt::Error),
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, ctx.depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

fn write_map_entry_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    entry: u64,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 1)
    } else if entry == 0 {
        write!(f, " ")
    } else {
        write!(f, ", ")
    }
}

fn walk_map_entries<'a, T: DebugType<'a>>(
    bytes: &[u8],
    proc: Option<&dyn ReadFromProc>,
    key: T,
    value: T,
    entries: &MapEntries<T>,
    emit: &mut impl FnMut(u64, &[u8], u64, &[u8]) -> std::result::Result<(), MapWalkError>,
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

    let root_start =
        usize::try_from(*root_offset).map_err(|_| MapWalkError::Marker("<invalid root>"))?;
    let root_end = root_start
        .checked_add(root.size() as usize)
        .ok_or(MapWalkError::Marker("<invalid root>"))?;
    let root_bytes = bytes
        .get(root_start..root_end)
        .ok_or(MapWalkError::Marker("<truncated root>"))?;
    if !matches!(root.check_variant(root_bytes, "Some"), Some(Ok(Some(_)))) {
        return Err(MapWalkError::Marker("<invalid missing root>"));
    }

    let root_node_start = usize::try_from(*root_node_offset)
        .map_err(|_| MapWalkError::Marker("<invalid root node>"))?;
    let root_node_end = root_node_start
        .checked_add(root_node.size() as usize)
        .ok_or(MapWalkError::Marker("<invalid root node>"))?;
    let root_node_bytes = bytes
        .get(root_node_start..root_node_end)
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
        &mut HashSet::new(),
        emit,
    )
}

fn walk_btree_node<'a, T: DebugType<'a>>(
    proc: &dyn ReadFromProc,
    layout: BTreeNodeLayout<T>,
    address: u64,
    height: u64,
    visited: &mut HashSet<u64>,
    emit: &mut impl FnMut(u64, &[u8], u64, &[u8]) -> std::result::Result<(), MapWalkError>,
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
        let len = read_unsigned_at(&bytes, layout.leaf_len_offset, layout.leaf_len.size())
            .ok_or(MapWalkError::Invalid("truncated node length"))?;
        if len > layout.key_slots {
            return Err(MapWalkError::Invalid("node length exceeds capacity"));
        }

        for index in 0..len {
            if height > 0 {
                let child = btree_edge_address(&bytes, layout, index)?;
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
            let key_bytes = byte_range(&bytes, key_start, layout.key.size())
                .ok_or(MapWalkError::Invalid("truncated key slot"))?;
            let value_bytes = byte_range(&bytes, value_start, layout.value.size())
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
            let child = btree_edge_address(&bytes, layout, len)?;
            walk_btree_node(proc, layout, child, height - 1, visited, emit)?;
        }
        Ok(())
    })();
    visited.remove(&address);
    result
}

fn btree_edge_address<'a, T: DebugType<'a>>(
    bytes: &[u8],
    layout: BTreeNodeLayout<T>,
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
pub(crate) fn eval_list<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    head_offset: u64,
    next_offset: u64,
    node: &DisplayNode<T>,
    node_ty: &T,
    node_size: u32,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a>,
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
    let mut seen = HashSet::new();
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
        write_seq_prefix(f, pretty, ctx.depth, !any)?;
        any = true;
        // Each element renders inline (`pretty = false`) even in pretty mode.
        eval_node(f, node, node_ty, &node_bytes, cur, ctx.deeper(), false)?;
        if pretty {
            write!(f, ",")?;
        }
        match read_u64_at(&node_bytes, next_offset) {
            Some(next) => cur = next,
            None => break,
        }
    }
    write_seq_close(f, pretty, ctx.depth, any)?;
    write!(f, "]")
}

#[cfg(test)]
mod tests {
    use crate::TypeInfoRef;
    use crate::testhelper::*;

    use exegesis::bundle::BundleView;

    #[test]
    fn test_vec_displays_initialized_elements() {
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x2000u64, 3, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &bytes);
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
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &invalid);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "<invalid slice: length exceeds capacity>"
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
        let value = TypeInfoRef::new(v.ty(SLICE).unwrap(), 0, &bytes);
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
        let value = TypeInfoRef::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);

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
        let value = TypeInfoRef::new(ty, 0x5000, &bytes);
        let shown = format!("{}", value.display_from_target(&one_leaf, 8));
        assert!(
            shown.contains("<invalid: tree contains fewer entries than length>"),
            "{shown}"
        );

        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&1u64.to_le_bytes());
        let value = TypeInfoRef::new(ty, 0x5000, &bytes);
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
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &empty);
        assert_eq!(
            format!("{}", value.display_from_target(&no_reads, 16)),
            "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, queue: [] }"
        );

        // A populated queue with no target reader degrades, not panics.
        let populated = thing_bytes(0, 0, 0, 0, 0x100);
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &populated);
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
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &bytes);
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
                TypeInfoRef::new(vec_ty, 0, &fat(parts)).display_from_target(&mem, 8)
            )
        };

        assert_eq!(show(&[0, 0, 0]), "[]");
        assert_eq!(show(&[0, 3, 3]), "<invalid slice: null data pointer>");
        assert_eq!(show(&[0x2000, 3, 3]), "<unreadable slice buffer>");
        assert_eq!(
            show(&[0x2000, 4, 3]),
            "<invalid slice: length exceeds capacity>"
        );
        assert_eq!(
            show(&[0x2000, u64::MAX, u64::MAX]),
            "<invalid slice: buffer size overflow>"
        );
    }
}

//! The [`DisplayNode`] interpreter: one generic evaluator that renders a type
//! through the display program its bundle supplies, in place of a per-type
//! renderer. Owns the pretty-vs-inline layout, cycle guarding, and degradation
//! markers for every node kind.

use crate::debug_type::{Arm, DisplayNode, Field, Place, Stmt, ValueExpr};
use crate::value::Value;
use proc::Target;

use hansei_bundle::BundleType;

use std::fmt;

use super::collections::{eval_list, eval_map, eval_slice};
use super::dyn_ptr::eval_dyn_pointer;
use super::scalar::{
    apply, byte_range, eval_bytes, read_u64_at, read_unsigned_at, write_symbol, write_utf8_string,
};
use super::{
    RenderCtx, write_display_value, write_field_prefix, write_record_close, write_seq_close,
    write_seq_prefix,
};

/// Interpret a resolved [`DisplayNode`] tree — the single generic evaluator
/// that stands in for the per-type `write_*` renderers on node-based formats.
///
/// `ty` is the type the node is rendered against: its name titles a `Struct`
/// record and its members back `Field::Structural`. `bytes`/`addr` are that
/// value's buffer and target address; a node's offsets are relative to them.
/// `pretty` requests multi-line layout. All pretty-vs-inline, cycle-guard, and
/// degradation-string handling lives here, written once.
pub(crate) fn eval_node<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    node: &DisplayNode<'a>,
    ty: &BundleType<'a>,
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    match node {
        // Not a degradation: the bundle chose to keep this type's insides
        // out of the way, and `--ugly` is the way past that choice.
        DisplayNode::Elided => write!(f, "<elided>"),
        DisplayNode::Scalar {
            offset,
            word_size,
            decode,
        } => match read_unsigned_at(bytes, *offset, u64::from(*word_size)) {
            Some(word) => f.write_str(&apply(decode, word)),
            None => write!(f, "<truncated>"),
        },
        DisplayNode::Computed { value, decode } => match eval_expr(value, &[], bytes, addr, ctx) {
            Ok(word) => f.write_str(&apply(decode, word)),
            Err(marker) => write!(f, "{marker}"),
        },
        DisplayNode::Symbol { offset } => write_symbol(f, bytes, *offset, ctx.proc),
        DisplayNode::Struct { fields } => {
            eval_struct(f, fields, ty, None, bytes, addr, ctx, pretty)
        }
        DisplayNode::List {
            head_offset,
            next_offset,
            node,
            node_ty,
            node_size,
        } => eval_list(
            f,
            *head_offset,
            *next_offset,
            node,
            node_ty,
            *node_size,
            bytes,
            ctx,
            pretty,
        ),
        DisplayNode::Str { header } => write_utf8_string(f, bytes, header, ctx.proc),
        DisplayNode::Slice {
            header,
            element,
            element_size,
        } => eval_slice(f, header, element, *element_size, bytes, ctx, pretty),
        DisplayNode::Bytes {
            offset,
            size,
            notation,
        } => eval_bytes(f, bytes, *offset, u64::from(*size), *notation),
        DisplayNode::Alias {
            target,
            place,
            follow_pointers,
        } => {
            // Peeling a wrapper elides a representation detail, so it does not
            // consume the value-depth budget: `ctx` (and its `depth`) threads
            // through unchanged. An atomic snapshot (`follow_pointers` false)
            // shows a stored pointer's address rather than its pointee. Nulling
            // `proc` also stops a place from crossing a pointer, which a
            // non-following alias never does (its place is a local offset).
            let child_ctx = if *follow_pointers {
                ctx
            } else {
                RenderCtx {
                    proc: None,
                    visited: None,
                    ..ctx
                }
            };
            match read_place_bytes(place, bytes, addr, child_ctx, target.size()) {
                Ok((child_addr, child_bytes)) => {
                    let child = Value {
                        ty: *target,
                        addr: child_addr,
                        bytes: child_bytes,
                    };
                    write_display_value(f, &child, child_ctx, pretty)
                }
                Err(marker) => write!(f, "{marker}"),
            }
        }
        DisplayNode::SlotCount {
            bitmap_offset,
            bitmap_size,
            count,
        } => {
            let ready =
                read_unsigned_at(bytes, *bitmap_offset, u64::from(*bitmap_size)).unwrap_or(0);
            // Only the low `count` bits are per-slot readiness; the rest are
            // the released/closed flags.
            let mask = if *count >= 64 {
                u64::MAX
            } else {
                (1u64 << count) - 1
            };
            let written = (ready & mask).count_ones();
            write!(f, "[{written} slots]")
        }
        DisplayNode::Pointer {
            pointer_offset,
            via_offset,
            target,
            then,
        } => {
            // The record reads as its target but keeps the enclosing name, so a
            // degraded read still reports as e.g. `Receiver<T> { <null> }`.
            let name = ty.name();
            let Some(pointer) = read_u64_at(bytes, *pointer_offset) else {
                return write!(f, "{name} {{ <truncated> }}");
            };
            // Both accessors must be present to follow the pointer into the
            // process; without them the target cannot be read.
            let (Some(proc), Some(_visited)) = (ctx.proc, ctx.visited) else {
                return write!(f, "{name} {{ <target unavailable> }}");
            };
            if pointer == 0 {
                return write!(f, "{name} {{ <null> }}");
            }
            let addr = pointer.wrapping_add(*via_offset);
            let Ok(target_bytes) = proc.read_bytes(addr, target.size()) else {
                return write!(f, "{name} {{ <unreadable> }}");
            };
            // Render the target against its own bytes, titled with this type's
            // name. `then` is a `Struct` for the receiver, but any node works.
            match then.as_ref() {
                DisplayNode::Struct { fields } => eval_struct(
                    f,
                    fields,
                    target,
                    Some(name),
                    target_bytes,
                    addr,
                    ctx,
                    pretty,
                ),
                other => eval_node(f, other, target, target_bytes, addr, ctx, pretty),
            }
        }
        DisplayNode::DynPointer { .. } => {
            eval_dyn_pointer(f, *ty, Some(ty.name()), node, bytes, ctx, pretty)
        }
        DisplayNode::Map {
            length_offset,
            length_size,
            key,
            value,
            entries,
        } => eval_map(
            f,
            ty,
            bytes,
            ctx,
            pretty,
            *length_offset,
            *length_size,
            *key,
            *value,
            entries,
        ),
        DisplayNode::Variant {
            discriminant,
            arms,
            default,
        } => eval_variant(
            f,
            discriminant,
            arms,
            default.as_deref(),
            ty,
            bytes,
            addr,
            ctx,
            pretty,
        ),
        DisplayNode::CustomList {
            vars,
            condition,
            body,
            element,
        } => eval_custom_list(f, vars, condition, body, element, bytes, addr, ctx, pretty),
    }
}

/// The discriminant's raw bits, zero-extended — the representation a
/// [`Place`] guard's ranges are stated over.
fn u128_from_le(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .enumerate()
        .fold(0u128, |raw, (i, b)| raw | ((*b as u128) << (8 * i)))
}

/// Verify every guard `place` recorded for `segment`: read each discriminant
/// (from the local `bytes` for segment 0, else through `proc` at `base`) and
/// check it selects the variant the path descended into. A live read that
/// finds another variant degrades to `<inactive variant>` — the datum is not
/// there, not unreadable.
fn check_place_guards<'a, T: Target>(
    place: &Place,
    segment: usize,
    base: Option<u64>,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
) -> std::result::Result<(), &'static str> {
    for guard in place.guards.iter().filter(|g| g.segment == segment) {
        let raw = match base {
            None => u128_from_le(
                byte_range(bytes, guard.at, u64::from(guard.size)).ok_or("<truncated>")?,
            ),
            Some(base) => {
                let proc = ctx.proc.ok_or("<target unavailable>")?;
                let at = base.checked_add(guard.at).ok_or("<invalid address>")?;
                let word = proc
                    .read_bytes(at, u64::from(guard.size))
                    .map_err(|_| "<unreadable>")?;
                u128_from_le(word)
            }
        };
        if !guard.expect.selects(raw) {
            return Err("<inactive variant>");
        }
    }
    Ok(())
}

/// Read the `size`-byte machine word at `place`, following any pointer hops
/// through `proc` and verifying any variant guards along the way. Empty
/// `hops` is the common case: a borrowed local slice, no process read. On
/// failure the `Err` carries the exact degradation marker to print in the
/// value's place.
fn read_place_bytes<'a, T: Target>(
    place: &Place,
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    size: u64,
) -> std::result::Result<(u64, &'a [u8]), &'static str> {
    check_place_guards(place, 0, None, bytes, ctx)?;
    if place.hops.is_empty() {
        let slice = byte_range(bytes, place.root_offset, size).ok_or("<truncated>")?;
        return Ok((addr.wrapping_add(place.root_offset), slice));
    }
    let proc = ctx.proc.ok_or("<target unavailable>")?;
    let mut pointer = read_u64_at(bytes, place.root_offset).ok_or("<truncated>")?;
    let (last, intermediate) = place.hops.split_last().expect("hops is non-empty");
    let mut segment = 1;
    for hop in intermediate {
        if pointer == 0 {
            return Err("<null>");
        }
        check_place_guards(place, segment, Some(pointer), bytes, ctx)?;
        let addr = pointer.checked_add(*hop).ok_or("<invalid address>")?;
        let word = proc.read_bytes(addr, 8).map_err(|_| "<unreadable>")?;
        pointer = read_u64_at(word, 0).ok_or("<unreadable>")?;
        segment += 1;
    }
    if pointer == 0 {
        return Err("<null>");
    }
    check_place_guards(place, segment, Some(pointer), bytes, ctx)?;
    let target = pointer.checked_add(*last).ok_or("<invalid address>")?;
    let read = if size == 0 {
        &[][..]
    } else {
        proc.read_bytes(target, size).map_err(|_| "<unreadable>")?
    };
    Ok((target, read))
}

/// Evaluate a resolved [`ValueExpr`] against `bytes`, crossing pointer hops via
/// `ctx.proc`. `Err` carries a degradation marker for a failed read.
fn eval_expr<'a, T: Target>(
    expr: &ValueExpr,
    vars: &[u64],
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
) -> std::result::Result<u64, &'static str> {
    Ok(match expr {
        ValueExpr::Const(value) => *value,
        ValueExpr::Read(candidates) => {
            // One candidate per variant an active-variant step crossed (one
            // total for the selectors that crossed none): the live candidate
            // is the one whose guards select, so an inactive-variant miss
            // moves on to the next, and only every candidate missing — or a
            // real read failure on the live one — degrades the expression.
            let mut result = Err("<inactive variant>");
            for (place, size) in candidates {
                match read_place_bytes(place, bytes, addr, ctx, u64::from(*size)) {
                    Ok((_, word)) => {
                        result = read_unsigned_at(word, 0, u64::from(*size)).ok_or("<unreadable>");
                        break;
                    }
                    Err("<inactive variant>") => continue,
                    Err(marker) => {
                        result = Err(marker);
                        break;
                    }
                }
            }
            result?
        }
        ValueExpr::And(a, b) => {
            eval_expr(a, vars, bytes, addr, ctx)? & eval_expr(b, vars, bytes, addr, ctx)?
        }
        ValueExpr::Not(inner) => !eval_expr(inner, vars, bytes, addr, ctx)?,
        ValueExpr::Ne(a, b) => u64::from(
            eval_expr(a, vars, bytes, addr, ctx)? != eval_expr(b, vars, bytes, addr, ctx)?,
        ),
        ValueExpr::Var(id) => *vars.get(*id as usize).ok_or("<invalid var>")?,
        ValueExpr::Load {
            addr: addr_expr,
            size,
        } => {
            let target = eval_expr(addr_expr, vars, bytes, addr, ctx)?;
            let proc = ctx.proc.ok_or("<target unavailable>")?;
            let word = proc
                .read_bytes(target, u64::from(*size))
                .map_err(|_| "<unreadable>")?;
            read_unsigned_at(word, 0, u64::from(*size)).ok_or("<unreadable>")?
        }
        ValueExpr::Add(a, b) => eval_expr(a, vars, bytes, addr, ctx)?
            .wrapping_add(eval_expr(b, vars, bytes, addr, ctx)?),
        ValueExpr::Sub(a, b) => eval_expr(a, vars, bytes, addr, ctx)?
            .wrapping_sub(eval_expr(b, vars, bytes, addr, ctx)?),
        ValueExpr::Mul(a, b) => eval_expr(a, vars, bytes, addr, ctx)?
            .wrapping_mul(eval_expr(b, vars, bytes, addr, ctx)?),
        ValueExpr::Lt(a, b) => {
            u64::from(eval_expr(a, vars, bytes, addr, ctx)? < eval_expr(b, vars, bytes, addr, ctx)?)
        }
    })
}

/// Cap on [`DisplayNode::CustomList`] loop iterations. A body has no inner loop,
/// so this hard-bounds the emitted items (and any cyclic pointer walk) without a
/// per-node `visited` set: a malformed or cyclic program stops here instead of
/// spinning. A live tokio mpsc queue is a few blocks of ≤32 slots, far under it.
const MAX_CUSTOM_LIST_ITERS: u32 = 1000;

/// Result of running a [`Stmt`] sequence: whether to run the next loop iteration
/// or stop — a `Break` fired, or a read degraded to a marker already written.
enum Flow {
    Next,
    Stop,
}

/// Write a degradation marker as a pseudo-element in a sequence body: an inline
/// `, ` separator when elements precede it, then the marker. Matches the
/// `<unreadable>` handling in the list and mpsc-queue renderers.
fn write_seq_marker(f: &mut fmt::Formatter<'_>, marker: &str, any: bool) -> fmt::Result {
    write!(f, "{}{marker}", if any { ", " } else { "" })
}

/// Render a [`DisplayNode::CustomList`]: seed the loop variables from the value,
/// then interpret `body` each iteration while `condition` holds, emitting one
/// `element` per [`Stmt::Emit`]. Owns the iteration cap and reuses the shared
/// sequence punctuation; a failed read degrades to a marker like the other list
/// nodes. This is the general escape hatch a windowed/paged walk (the mpsc block
/// chain) uses in place of a bespoke leaf.
#[allow(clippy::too_many_arguments)]
fn eval_custom_list<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    vars_init: &[ValueExpr],
    condition: &ValueExpr,
    body: &[Stmt],
    element: &BundleType<'a>,
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    // Seeds read the value alone (no variables exist yet); a failed seed read
    // degrades the whole list before any bracket, like the other list nodes.
    let mut vars: Vec<u64> = Vec::with_capacity(vars_init.len());
    for init in vars_init {
        match eval_expr(init, &[], bytes, addr, ctx) {
            Ok(value) => vars.push(value),
            Err(marker) => return write!(f, "{marker}"),
        }
    }

    write!(f, "[")?;
    let mut any = false;
    for _ in 0..MAX_CUSTOM_LIST_ITERS {
        match eval_expr(condition, &vars, bytes, addr, ctx) {
            Ok(0) => break,
            Ok(_) => {}
            Err(marker) => {
                write_seq_marker(f, marker, any)?;
                break;
            }
        }
        match eval_stmts(
            f, body, &mut vars, element, bytes, addr, ctx, pretty, &mut any,
        )? {
            Flow::Next => {}
            Flow::Stop => break,
        }
    }
    write_seq_close(f, pretty, ctx.prefix, ctx.depth, any)?;
    write!(f, "]")
}

/// Run one [`Stmt`] sequence for a [`DisplayNode::CustomList`] iteration,
/// mutating `vars`, emitting elements, and returning whether the loop continues.
/// A read that degrades writes its marker inline and stops the loop.
#[allow(clippy::too_many_arguments)]
fn eval_stmts<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    stmts: &[Stmt],
    vars: &mut Vec<u64>,
    element: &BundleType<'a>,
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
    any: &mut bool,
) -> std::result::Result<Flow, fmt::Error> {
    // Evaluate an expression or degrade: a failed read writes its marker as
    // a pseudo-element and stops the loop, whichever statement asked.
    macro_rules! eval_or_stop {
        ($expr:expr) => {
            match eval_expr($expr, vars, bytes, addr, ctx) {
                Ok(value) => value,
                Err(marker) => {
                    write_seq_marker(f, marker, *any)?;
                    return Ok(Flow::Stop);
                }
            }
        };
    }

    for stmt in stmts {
        match stmt {
            Stmt::Set { var, value } => {
                let value = eval_or_stop!(value);
                if let Some(slot) = vars.get_mut(*var as usize) {
                    *slot = value;
                }
            }
            Stmt::If {
                cond,
                then,
                otherwise,
            } => {
                let branch = if eval_or_stop!(cond) != 0 {
                    then
                } else {
                    otherwise
                };
                if let Flow::Stop =
                    eval_stmts(f, branch, vars, element, bytes, addr, ctx, pretty, any)?
                {
                    return Ok(Flow::Stop);
                }
            }
            Stmt::Break { cond } => {
                if eval_or_stop!(cond) != 0 {
                    return Ok(Flow::Stop);
                }
            }
            Stmt::Emit { at } => {
                let target = eval_or_stop!(at);
                let Some(proc) = ctx.proc else {
                    write_seq_marker(f, "<target unavailable>", *any)?;
                    return Ok(Flow::Stop);
                };
                let Ok(element_bytes) = proc.read_bytes(target, element.size()) else {
                    write_seq_marker(f, "<unreadable>", *any)?;
                    return Ok(Flow::Stop);
                };
                write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, !*any)?;
                *any = true;
                let child = Value {
                    ty: *element,
                    addr: target,
                    bytes: element_bytes,
                };
                write_display_value(f, &child, ctx.deeper(), pretty)?;
                if pretty {
                    write!(f, ",")?;
                }
            }
        }
    }
    Ok(Flow::Next)
}

/// Render a [`DisplayNode::Variant`]: evaluate the discriminant, then render the
/// first arm whose value matches (else `default`, else `<unknown: N>` — the
/// same no-silent-state contract the scalar decoder follows). Only the selected
/// arm is evaluated, so an unseen watch receiver never reads its value.
#[allow(clippy::too_many_arguments)]
fn eval_variant<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    discriminant: &ValueExpr,
    arms: &[Arm<'a>],
    default: Option<&DisplayNode<'a>>,
    ty: &BundleType<'a>,
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let value = match eval_expr(discriminant, &[], bytes, addr, ctx) {
        Ok(value) => value,
        Err(marker) => return write!(f, "{marker}"),
    };
    if let Some(arm) = arms.iter().find(|arm| arm.value == value) {
        // `label`, `label(<payload>)`, or `<payload>` — covering a unit variant
        // (`None`), a tuple variant (`Some(x)`), and a bare label (`false`).
        if let Some(label) = &arm.label {
            write!(f, "{label}")?;
        }
        if let Some(payload) = &arm.payload {
            if arm.label.is_some() {
                write!(f, "(")?;
            }
            eval_node(f, payload, ty, bytes, addr, ctx.deeper(), pretty)?;
            if arm.label.is_some() {
                write!(f, ")")?;
            }
        }
        return Ok(());
    }
    match default {
        Some(node) => eval_node(f, node, ty, bytes, addr, ctx, pretty),
        None => write!(f, "<unknown: {value}>"),
    }
}

/// Render a [`DisplayNode::Struct`] record: `<ty> { field, … }`, each field
/// either a real member shown structurally or a label whose value is a nested
/// node.
#[allow(clippy::too_many_arguments)]
fn eval_struct<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    fields: &[Field<'a>],
    ty: &BundleType<'a>,
    name: Option<&str>,
    bytes: &'a [u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    // A `Pointer` re-roots the record at its target but titles it with the
    // enclosing type's name (a `Receiver` reads as its `Chan`); every other
    // caller titles it with the rendered type's own name.
    f.write_str(name.unwrap_or_else(|| ty.name()))?;
    f.write_str(" {")?;
    for (i, field) in fields.iter().enumerate() {
        write_field_prefix(f, pretty, ctx.prefix, ctx.depth, i == 0)?;
        match field {
            Field::Structural {
                name,
                ty: mem_ty,
                offset,
            } => {
                f.write_str(name)?;
                f.write_str(": ")?;
                match byte_range(bytes, *offset, mem_ty.size()) {
                    Some(mem_bytes) => {
                        let child = Value {
                            ty: *mem_ty,
                            addr: addr + offset,
                            bytes: mem_bytes,
                        };
                        write_display_value(f, &child, ctx.deeper(), pretty)?
                    }
                    None => write!(f, "<truncated>")?,
                }
            }
            Field::Computed { label, node } => {
                f.write_str(label)?;
                f.write_str(": ")?;
                eval_node(f, node, ty, bytes, addr, ctx.deeper(), pretty)?;
            }
        }
        if pretty {
            write!(f, ",")?;
        }
    }
    write_record_close(f, pretty, ctx.prefix, ctx.depth)?;
    write!(f, "}}")
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;

    use hansei_bundle::{
        Arm, BundleView, DisplayNode as BundleNode, MemberRef, ScalarDecode, Selector, Step,
        TypeDef, ValueExpr,
    };

    #[test]
    fn test_transparent_debug_format_elides_wrapper() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let value = Value::new(v.ty(WRAP).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display().depth(2)),
            "Point { x: 3, y: 4 }"
        );
    }

    #[test]
    fn test_atomic_debug_format_displays_stored_value() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 42u32.to_le_bytes();
        let value = Value::new(v.ty(ATOMIC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display().depth(1)), "42");
    }

    #[test]
    fn test_nested_transparent_formats_do_not_consume_depth() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let bytes = 42u32.to_le_bytes();
        let atomic = Value::new(v.ty(LOOM_ATOMIC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", atomic.display().depth(1)), "42");

        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let cell = Value::new(v.ty(LOOM_CELL).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", cell.display().depth(2)),
            "Point { x: 3, y: 4 }"
        );
    }

    #[test]
    fn test_atomic_pointer_does_not_dereference_stored_address() {
        // Any read at all means the stored address was dereferenced.
        let mem = FakeMem::new().panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let value = Value::new(v.ty(ATOMIC_PTR).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display_from_target(&mem, 8)), "0x1000");
    }

    #[test]
    fn test_following_alias_preserves_pointer_traversal() {
        let mem = FakeMem::new().at(0x1000, u32s(&[3, 4]));

        let mut b = test_bundle();
        b.types.debug_formats.insert(
            ATOMIC_PTR,
            BundleNode::Alias {
                at: sel(&[0]),
                follow_pointers: true,
            },
        );
        b.validate().expect("following alias must validate");
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let value = Value::new(v.ty(ATOMIC_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "0x1000 -> Point { x: 3, y: 4 }"
        );
    }

    #[test]
    fn test_notify_renders_compact_state_mutex_and_waiters() {
        // Two waiters live at 0x3000 and 0x3020: the first still parked (no
        // notification) with no waker registered yet, the second handed a
        // `notify_one` notification with a task waker armed — its data word
        // is the woken task's Header address.
        let mem = FakeMem::new()
            .at(0x3000, sync_waiter(0, 0x3020))
            .at(0x3020, sync_waiter_waking(1, 0, 0x77a0))
            .panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Flat Notify buffer: state @0, mutex state byte @8, head @16, tail @24.
        let notify = |state: u64, mutex: u8, head: u64| {
            let mut buf = vec![0u8; 32];
            buf[0..8].copy_from_slice(&state.to_le_bytes());
            buf[8] = mutex;
            buf[16..24].copy_from_slice(&head.to_le_bytes());
            buf
        };

        // Idle, unlocked, two parked waiters.
        let buf = notify(0, 0, 0x3000);
        let value = Value::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "tokio::sync::notify::Notify { state: state=idle, generation=0, \
             mutex: locked=false, parked=false, queue: [\
             tokio::sync::notify::Waiter { notification: kind=none, order=fifo, \
             waker: Option<Waker>::None }, \
             tokio::sync::notify::Waiter { notification: kind=one, order=fifo, \
             waker: Option<Waker>::Some(0x77a0) }] }"
        );

        // An address annotator reaches the armed waker's data word, and a
        // bare pointer word renders as the label itself: the waker row
        // names the task to be woken, with the address only as fallback.
        let annotate = |addr: u64| (addr == 0x77a0).then(|| "task 7".to_string());
        let shown = format!(
            "{}",
            value.display_from_target(&mem, 8).annotate_addrs(&annotate)
        );
        assert!(
            shown.contains("waker: Option<Waker>::Some(task 7)"),
            "{shown}"
        );

        // Notified with two notify_waiters calls, locked mutex, empty queue.
        // 0b1010 = notified (state 2) with generation 2 (10 >> 2).
        let buf = notify(0b1010, 0b01, 0);
        let value = Value::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "tokio::sync::notify::Notify { state: state=notified, generation=2, \
             mutex: locked=true, parked=false, queue: [] }"
        );

        // Without a target the queue cannot be walked, but state and mutex
        // (read from the value's own bytes) still render.
        let buf = notify(1, 0, 0x3000);
        let value = Value::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        let shown = format!("{}", value.display());
        assert!(shown.contains("state: state=waiting"), "{shown}");
        assert!(shown.contains("queue: <target unavailable>"), "{shown}");

        // Pretty mode puts each field and waiter on its own indented line.
        let buf = notify(0, 0, 0x3000);
        let value = Value::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "tokio::sync::notify::Notify {\n\
             \x20   state: state=idle, generation=0,\n\
             \x20   mutex: locked=false, parked=false,\n\
             \x20   queue: [\n\
             \x20       tokio::sync::notify::Waiter { notification: kind=none, order=fifo, \
             waker: Option<Waker>::None },\n\
             \x20       tokio::sync::notify::Waiter { notification: kind=one, order=fifo, \
             waker: Option<Waker>::Some(0x77a0) },\n\
             \x20   ],\n\
             }"
        );
    }

    #[test]
    fn test_semaphore_decodes_permits_field_in_place() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // 16-byte Semaphore: permits usize @0, waiters u32 @8.
        let bytes = |permits: u64, waiters: u32| {
            let mut buf = Vec::new();
            buf.extend_from_slice(&permits.to_le_bytes());
            buf.extend_from_slice(&waiters.to_le_bytes());
            buf.extend_from_slice(&[0u8; 4]);
            buf
        };
        let cases = [
            // permits are stored shifted left by one; bit 0 is the closed flag.
            (
                64u64,
                3u32,
                "tokio::sync::batch_semaphore::Semaphore { permits: closed=false, permits=32, \
                 waiters: 3 }",
            ),
            (
                0,
                0,
                "tokio::sync::batch_semaphore::Semaphore { permits: closed=false, permits=0, \
                 waiters: 0 }",
            ),
            // 65 = (32 << 1) | 1: 32 permits, closed.
            (
                65,
                9,
                "tokio::sync::batch_semaphore::Semaphore { permits: closed=true, permits=32, \
                 waiters: 9 }",
            ),
        ];
        for (permits, waiters, expected) in cases {
            let buf = bytes(permits, waiters);
            let value = Value::new(v.ty(SEMAPHORE).unwrap(), 0, &buf);
            assert_eq!(
                format!("{}", value.display()),
                expected,
                "permits={permits}"
            );
        }
    }

    #[test]
    fn test_mpsc_block_elides_values_to_written_count() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // 24-byte Block: [u32; 4] value slots @0, ready-bitmap usize @16.
        let block = |ready: u64| {
            let mut buf = vec![0u8; 16];
            buf.extend_from_slice(&ready.to_le_bytes());
            buf
        };
        // Three bits set within the 4-slot capacity: three written slots.
        let buf = block(0b1011);
        let value = Value::new(v.ty(BLOCK).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display()),
            "tokio::sync::mpsc::block::Block<u32> { values: [3 slots], header: BlockHeader { ready_slots: 11 } }"
        );

        // Bits outside the 4-slot capacity (released/closed flags) are ignored.
        let buf = block(0b1_0000);
        let value = Value::new(v.ty(BLOCK).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display()),
            "tokio::sync::mpsc::block::Block<u32> { values: [0 slots], header: BlockHeader { ready_slots: 16 } }"
        );
    }

    #[test]
    fn test_mpsc_chan_shows_only_queued_messages() {
        let mem = FakeMem::new().at(0x1000, mpsc_block(&[10, 20, 30, 40], 0, 0));

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Chan: tail usize @0, index usize @8, head ptr @16.
        let chan = |tail: u64, index: u64| {
            let mut c = Vec::new();
            c.extend_from_slice(&tail.to_le_bytes());
            c.extend_from_slice(&index.to_le_bytes());
            c.extend_from_slice(&0x1000u64.to_le_bytes());
            c
        };

        // index=1, tail=3: slots 1 and 2 are still queued.
        let bytes = chan(3, 1);
        let value = Value::new(v.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert!(shown.contains("queued: [20, 30]"), "{shown}");

        // Drained channel (index == tail): nothing queued, no stale slots shown.
        let bytes = chan(3, 3);
        let value = Value::new(v.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert!(shown.contains("queued: []"), "{shown}");
    }

    #[test]
    fn test_custom_list_walks_mpsc_block_chain() {
        // The shared `chan_queued_node` CustomList, installed as a top-level
        // format, walks the block chain from the value language: seed
        // cur/tail/block from the Chan, then loop reading each block's
        // start_index (a Load), emit the in-window slots, and follow `next`.
        let mem = FakeMem::new().at(0x1000, mpsc_block(&[10, 20, 30, 40], 0, 0));

        let mut b = test_bundle();
        b.types.debug_formats.insert(CHAN, chan_queued_node(U32));
        b.validate().expect("CustomList bundle must validate");
        let view = BundleView::new(&b);

        // Chan: tail usize @0, index usize @8, head ptr @16.
        let chan = |tail: u64, index: u64| {
            let mut buf = Vec::new();
            buf.extend_from_slice(&tail.to_le_bytes());
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&0x1000u64.to_le_bytes());
            buf
        };

        // index=1, tail=3: slots 1 and 2 are still queued — as MpscChan renders.
        let bytes = chan(3, 1);
        let value = Value::new(view.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert_eq!(shown, "[20, 30]", "{shown}");

        // Drained (index == tail): empty, and no block is read at all.
        let bytes = chan(3, 3);
        let value = Value::new(view.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert_eq!(shown, "[]", "{shown}");
    }

    #[test]
    fn test_mpsc_rx_renders_channel_with_capacity_and_free() {
        // The receiver's Arc raw pointer is 0x2000; the Chan sits 16 bytes in,
        // past the ArcInner strong/weak header, at 0x2010. Its head block is at
        // 0x1000.
        // RxChan at 0x2010: tail @0, index @8, head @16, then the semaphore's
        // permits @24 (-> free 3) and bound @32 (-> capacity 16).
        let mem = FakeMem::new()
            .at(0x1000, mpsc_block(&[10, 20, 30, 40], 0, 0))
            .at(0x2010, u64s(&[3, 1, 0x1000, 6, 16]))
            .panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Receiver holds the Arc raw pointer.
        let bytes = 0x2000u64.to_le_bytes();
        let value = Value::new(v.ty(RECEIVER).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert!(
            shown.starts_with("tokio::sync::mpsc::bounded::Receiver<u32> {"),
            "{shown}"
        );
        assert!(shown.contains("capacity: 16"), "{shown}");
        assert!(shown.contains("free: closed=false, permits=3"), "{shown}");
        assert!(shown.contains("queued: [20, 30]"), "{shown}");

        // A null channel pointer is reported rather than dereferenced.
        let bytes = 0u64.to_le_bytes();
        let value = Value::new(v.ty(RECEIVER).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert_eq!(
            shown,
            "tokio::sync::mpsc::bounded::Receiver<u32> { <null> }"
        );
    }

    #[test]
    fn test_bounded_semaphore_renders_compact_state_and_waiters() {
        // Two waiters live at 0x3000 and 0x3020, blocked on 2 and 1 permits.
        let mem = FakeMem::new()
            .at(0x3000, sync_waiter(2, 0x3020))
            .at(0x3020, sync_waiter(1, 0))
            .panic_on_unmapped();

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Flat bounded::Semaphore buffer: mutex state @0, head @8, tail @16,
        // closed @32, permits @40, bound @48.
        let sem = |mutex: u8, head: u64, closed: u8, permits: u64, bound: u64| {
            let mut buf = vec![0u8; 56];
            buf[0] = mutex;
            buf[8..16].copy_from_slice(&head.to_le_bytes());
            buf[32] = closed;
            buf[40..48].copy_from_slice(&permits.to_le_bytes());
            buf[48..56].copy_from_slice(&bound.to_le_bytes());
            buf
        };

        // Unlocked, open, 10 permits (stored << 1), capacity 16, two waiters.
        let buf = sem(0, 0x3000, 0, 20, 16);
        let value = Value::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "tokio::sync::mpsc::bounded::Semaphore { mutex: locked=false, parked=false, \
             closed: false, permits: closed=false, permits=10, bound: 16, queue: [\
             tokio::sync::batch_semaphore::Waiter { permits_needed: 2, \
             waker: Option<Waker>::None }, \
             tokio::sync::batch_semaphore::Waiter { permits_needed: 1, \
             waker: Option<Waker>::None }] }"
        );

        // Locked, closed, no permits, empty queue (null head).
        let buf = sem(0b01, 0, 1, 0, 16);
        let value = Value::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "tokio::sync::mpsc::bounded::Semaphore { mutex: locked=true, parked=false, \
             closed: true, permits: closed=false, permits=0, bound: 16, queue: [] }"
        );

        // Without a target the queue cannot be walked, but the inline fields
        // (read from the value's own bytes) still render.
        let buf = sem(0, 0x3000, 0, 20, 16);
        let value = Value::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        let shown = format!("{}", value.display());
        assert!(
            shown.contains("permits: closed=false, permits=10"),
            "{shown}"
        );
        assert!(shown.contains("queue: <target unavailable>"), "{shown}");

        // Pretty mode puts each field and waiter on its own indented line.
        let buf = sem(0, 0x3000, 0, 20, 16);
        let value = Value::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "tokio::sync::mpsc::bounded::Semaphore {\n\
             \x20   mutex: locked=false, parked=false,\n\
             \x20   closed: false,\n\
             \x20   permits: closed=false, permits=10,\n\
             \x20   bound: 16,\n\
             \x20   queue: [\n\
             \x20       tokio::sync::batch_semaphore::Waiter { permits_needed: 2, \
             waker: Option<Waker>::None },\n\
             \x20       tokio::sync::batch_semaphore::Waiter { permits_needed: 1, \
             waker: Option<Waker>::None },\n\
             \x20   ],\n\
             }"
        );
    }

    #[test]
    fn test_watch_receiver_renders_unseen_value_and_closed_independently() {
        // ArcInner::data is at 0x2010, holding Shared { state @0, value @8 }.
        let shared = |state: u64, value: u32| {
            FakeMem::new()
                .at(0x2010, state.to_le_bytes())
                .at(0x2018, value.to_le_bytes())
                .panic_on_unmapped()
        };

        let b = test_bundle();
        let v = BundleView::new(&b);
        let receiver = |observed: u64, pointer: u64| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&pointer.to_le_bytes());
            bytes.extend_from_slice(&observed.to_le_bytes());
            bytes
        };
        let cases = [
            (
                2,
                2,
                "tokio::sync::watch::Receiver<u32> { unseen: None, closed: false }",
            ),
            (
                0,
                2,
                "tokio::sync::watch::Receiver<u32> { unseen: Some(42), closed: false }",
            ),
            (
                2,
                3,
                "tokio::sync::watch::Receiver<u32> { unseen: None, closed: true }",
            ),
            (
                0,
                3,
                "tokio::sync::watch::Receiver<u32> { unseen: Some(42), closed: true }",
            ),
        ];
        for (observed, state, expected) in cases {
            let bytes = receiver(observed, 0x2000);
            let value = Value::new(v.ty(WATCH_RECEIVER).unwrap(), 0, &bytes);
            assert_eq!(
                format!("{}", value.display_from_target(&shared(state, 42), 8)),
                expected,
                "observed={observed}, state={state}"
            );
        }

        let bytes = receiver(0, 0x2000);
        let value = Value::new(v.ty(WATCH_RECEIVER).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{:#}", value.display_from_target(&shared(2, 42), 8)),
            "tokio::sync::watch::Receiver<u32> {\n\
             \x20   unseen: Some(42),\n\
             \x20   closed: false,\n\
             }"
        );

        // Degradation is now per field (the cross-Arc reads fail independently
        // in each Variant), rather than one whole-record marker.
        assert_eq!(
            format!("{}", value.display()),
            "tokio::sync::watch::Receiver<u32> \
             { unseen: <target unavailable>, closed: <target unavailable> }"
        );
        let bytes = receiver(0, 0);
        let value = Value::new(v.ty(WATCH_RECEIVER).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&shared(2, 42), 8)),
            "tokio::sync::watch::Receiver<u32> { unseen: <null>, closed: <null> }"
        );
    }

    #[test]
    fn test_node_struct_renders_every_field_and_list_kind() {
        // Two queued waiters at 0x100 → 0x200 → end.
        let mem = FakeMem::new()
            .at(0x100, waiter_bytes(1, 0x200)) // kind=one, order=fifo
            .at(0x200, waiter_bytes(6, 0)) // kind=all(2), order=lifo(1): 0b110
            .panic_on_unmapped();

        let b = node_bundle();
        let v = BundleView::new(&b);
        // state word: waiting (1) with generation 3 → (3 << 2) | 1 = 13.
        let bytes = thing_bytes(13, 1, 7, 9, 0x100);
        let value = Value::new(v.ty(N_THING).unwrap(), 0, &bytes);

        assert_eq!(
            format!("{}", value.display_from_target(&mem, 16)),
            "Thing { state: state=waiting, generation=3, flag: 1, point: Point { x: 7, y: 9 }, \
             queue: [Waiter { notification: kind=one, order=fifo }, \
             Waiter { notification: kind=all, order=lifo }] }"
        );

        let pretty = format!("{:#}", value.display_from_target(&mem, 16));
        assert!(
            pretty.contains("\n    state: state=waiting, generation=3,"),
            "{pretty}"
        );
        assert!(pretty.contains("\n    point: Point {"), "{pretty}");
        assert!(pretty.contains("\n    queue: ["), "{pretty}");
        assert!(
            pretty.contains("notification: kind=one, order=fifo"),
            "{pretty}"
        );
    }

    /// A `Variant` whose discriminant matches no arm and that declares no
    /// default reports the value rather than rendering nothing. This is the
    /// same "no silent state" rule the scalar decoder enforces, one level up:
    /// an enum gaining a variant upstream shows as an unknown, not a blank.
    #[test]
    fn test_variant_without_matching_arm_reports_the_value() {
        let b = node_bundle();
        let v = BundleView::new(&b);
        let choice = v.ty(N_CHOICE).unwrap();
        let show = |tag: u8| {
            format!(
                "{}",
                Value::new(choice, 0, std::slice::from_ref(&tag)).display()
            )
        };
        assert_eq!(show(0), "none");
        assert_eq!(show(1), "one");
        assert_eq!(show(2), "<unknown: 2>");
        assert_eq!(show(255), "<unknown: 255>");
    }

    /// An `Elided` format suppresses the whole value — its member never
    /// renders and the target is never read — while `--ugly` shows the
    /// structure like any other suppressed formatter.
    #[test]
    fn test_elided_hides_the_value_and_ugly_reveals_it() {
        let b = node_bundle();
        let v = BundleView::new(&b);
        let logger = v.ty(N_LOGGER).unwrap();
        // An unreadable target proves elision reads nothing: any read
        // would surface as a degradation string instead.
        let mem = FakeMem::new().unreadable();
        let bytes = 0xdead_beef_u64.to_le_bytes();
        let value = Value::new(logger, 0, &bytes);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "<elided>"
        );
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "<elided>"
        );
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8).ugly()),
            "Logger { drain: 3735928559 }"
        );
    }

    /// The render-time switches layer over the bundle's `Elided` formats:
    /// `no_elide` peels them off, a forced type elides whatever format it
    /// carries (or none) — under `no_elide` and under the ugly view too.
    #[test]
    fn test_elide_overrides_layer_over_the_bundle() {
        use crate::render::ElideOverride;

        let b = node_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().unreadable();
        let logger_bytes = 7_u64.to_le_bytes();
        let logger = Value::new(v.ty(N_LOGGER).unwrap(), 0, &logger_bytes);
        let point_bytes = u32s(&[1, 2]);
        let point = Value::new(v.ty(N_POINT).unwrap(), 0, &point_bytes);

        let no_elide = ElideOverride {
            no_elide: true,
            ..Default::default()
        };
        assert_eq!(
            format!(
                "{}",
                logger
                    .display_from_target(&mem, 8)
                    .elide_override(&no_elide)
            ),
            "Logger { drain: 7 }"
        );

        // A forced type elides with no format of its own, and the match
        // covers instantiations: the spec may omit generic arguments.
        let force_point = ElideOverride {
            no_elide: false,
            types: vec!["Point".to_owned()],
        };
        assert_eq!(
            format!(
                "{}",
                point
                    .display_from_target(&mem, 8)
                    .elide_override(&force_point)
            ),
            "<elided>"
        );

        // Forced elision wins over both no_elide and ugly.
        let force_logger = ElideOverride {
            no_elide: true,
            types: vec!["Logger".to_owned()],
        };
        assert_eq!(
            format!(
                "{}",
                logger
                    .display_from_target(&mem, 8)
                    .elide_override(&force_logger)
            ),
            "<elided>"
        );
        assert_eq!(
            format!(
                "{}",
                logger
                    .display_from_target(&mem, 8)
                    .elide_override(&force_logger)
                    .ugly()
            ),
            "<elided>"
        );
    }

    /// A `CustomList` lays out like the other sequence nodes in pretty mode:
    /// one element per indented line with a trailing comma.
    #[test]
    fn test_custom_list_lays_out_like_a_sequence() {
        let mut b = test_bundle();
        b.types.debug_formats.insert(CHAN, chan_queued_node(U32));
        b.validate().expect("CustomList bundle must validate");
        let view = BundleView::new(&b);
        let mem = FakeMem::new().at(0x1000, mpsc_block(&[10, 20, 30, 40], 0, 0));

        // Chan: tail usize @0, index usize @8, head ptr @16.
        let chan = u64s(&[3, 1, 0x1000]);
        let value = Value::new(view.ty(CHAN).unwrap(), 0, &chan);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "[\n    20,\n    30,\n]"
        );
    }

    /// A `Step::Variant` read yields the live variant's payload and degrades
    /// to `<inactive variant>` — never a misread — when another variant
    /// holds the storage.
    #[test]
    fn test_variant_step_reads_only_the_live_variant() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "msg"))),
            Step::Variant(strref(&b, "B")),
        ]);
        b.types.debug_formats.insert(
            MSG_WRAP,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        b.validate().expect("variant-stepped alias must validate");
        let v = BundleView::new(&b);

        // Tag 1: `B(u64)` is live, and the alias renders its payload word.
        let bytes = msg_wrap(1, 42);
        let value = Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "42");

        // Tag 0: `A` holds the storage, so the same 42 bytes mean nothing.
        let bytes = msg_wrap(0, 42);
        let value = Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "<inactive variant>");
    }

    /// A niche enum's default variant guards on *no other* variant's value
    /// matching — here `Opt`'s `Some(u64)`, live for any nonzero word.
    #[test]
    fn test_niche_variant_guard_checks_the_other_variants() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "opt"))),
            Step::Variant(strref(&b, "Some")),
        ]);
        b.types.debug_formats.insert(
            GUARD_OUTER,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        b.validate().expect("niche variant alias must validate");
        let v = BundleView::new(&b);
        let outer = |opt: u64| u64s(&[0, opt]);

        let bytes = outer(0xdead_beef);
        let value = Value::new(v.ty(GUARD_OUTER).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "3735928559");

        // The zero word selects `None`, so `Some`'s payload is not there.
        let bytes = outer(0);
        let value = Value::new(v.ty(GUARD_OUTER).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "<inactive variant>");
    }

    /// A guard whose enum lives behind a pointer reads the discriminant from
    /// the target process, degrading like any other cross-pointer read.
    #[test]
    fn test_variant_guard_checks_across_a_pointer() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "wrap"))),
            Step::Deref,
            Step::Member(MemberRef::Named(strref(&b, "msg"))),
            Step::Variant(strref(&b, "B")),
        ]);
        b.types.debug_formats.insert(
            GUARD_OUTER,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        b.validate()
            .expect("cross-pointer variant alias must validate");
        let v = BundleView::new(&b);
        let outer = |wrap: u64| u64s(&[wrap, 0]);
        let show = |mem: &FakeMem, bytes: &[u8]| {
            format!(
                "{}",
                Value::new(v.ty(GUARD_OUTER).unwrap(), 0, bytes).display_from_target(mem, 8)
            )
        };

        let mem = FakeMem::new()
            .at(0x1000, msg_wrap(1, 7))
            .panic_on_unmapped();
        assert_eq!(show(&mem, &outer(0x1000)), "7");

        // The pointee holds variant `C`: the guard reads the remote tag and
        // degrades instead of reading `B`'s payload.
        let mem = FakeMem::new()
            .at(0x1000, msg_wrap(2, 7))
            .panic_on_unmapped();
        assert_eq!(show(&mem, &outer(0x1000)), "<inactive variant>");

        // A null pointer degrades before any guard is consulted.
        let mem = FakeMem::new().panic_on_unmapped();
        assert_eq!(show(&mem, &outer(0)), "<null>");
    }

    /// A non-following alias nulls the target for everything under it: even
    /// a target whose own format reads through a pointer (a `&str`) shows
    /// its degradation, never the pointee.
    #[test]
    fn test_non_following_alias_never_reads_the_target() {
        let mem = FakeMem::new()
            .at(0x3000, b"hello".to_vec())
            .panic_on_unmapped();

        let mut b = test_bundle();
        // GuardOuter { wrap @0, opt @8 } reshaped so the aliased member is
        // a 16-byte `&str` — a format that reads the target when it has one.
        let TypeDef::Struct { size, members, .. } = &mut b.types.types[GUARD_OUTER.0 as usize]
        else {
            panic!("GuardOuter is not a struct");
        };
        *size = 24;
        members[1].ty = STR;
        b.types.debug_formats.insert(
            GUARD_OUTER,
            BundleNode::Alias {
                at: sel(&[1]),
                follow_pointers: false,
            },
        );
        b.validate().expect("non-following str alias must validate");

        let v = BundleView::new(&b);
        let bytes = u64s(&[0, 0x3000, 5]);
        let value = Value::new(v.ty(GUARD_OUTER).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "<target unavailable>"
        );
    }

    /// A degradation mid-walk writes its marker as a pseudo-element, joined
    /// to the elements already emitted with the same `, ` an element gets.
    #[test]
    fn test_custom_list_marker_joins_the_emitted_elements() {
        // Four queued messages exhaust the first block; the walk then moves
        // to the unreadable second block and degrades after them.
        let mem = FakeMem::new().at(0x4000, mpsc_block(&[20, 30, 40, 50], 0, 0x5000));

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Chan { tail: 5, index: 0, head: 0x4000 }.
        let bytes = u64s(&[5, 0, 0x4000]);
        let value = Value::new(v.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert!(
            shown.contains("queued: [20, 30, 40, 50, <unreadable>]"),
            "{shown}"
        );
    }

    /// Guards recorded past the first pointer hop are checked against the
    /// segment they were recorded for — a two-hop place whose enum sits at
    /// the far end, like a waiter's state behind two links.
    #[test]
    fn test_place_guards_past_the_first_pointer_hop_are_checked() {
        let mut b = test_bundle();
        // Give Node's head slot an enum payload: Node { value: Opt @0,
        // next: *Node @8 } — Opt is 8 bytes, so the layout still fits.
        let TypeDef::Struct { members, .. } = &mut b.types.types[NODE.0 as usize] else {
            panic!("Node is not a struct");
        };
        members[0].ty = OPT;
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "next"))),
            Step::Deref,
            Step::Member(MemberRef::Named(strref(&b, "next"))),
            Step::Deref,
            Step::Member(MemberRef::Named(strref(&b, "value"))),
            Step::Variant(strref(&b, "Some")),
        ]);
        b.types.debug_formats.insert(
            NODE,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        b.validate().expect("two-hop variant alias must validate");
        let v = BundleView::new(&b);
        let node = |value: u64, next: u64| u64s(&[value, next]);
        let show = |mem: &FakeMem, bytes: &[u8]| {
            format!(
                "{}",
                Value::new(v.ty(NODE).unwrap(), 0, bytes).display_from_target(mem, 8)
            )
        };

        // Two hops in, the live `Some` payload reads through.
        let mem = FakeMem::new()
            .at(0x2000, node(0, 0x3000))
            .at(0x3000, node(41, 0))
            .panic_on_unmapped();
        assert_eq!(show(&mem, &node(0, 0x2000)), "41");

        // The guard two segments in finds `None` live and degrades.
        let mem = FakeMem::new()
            .at(0x2000, node(0, 0x3000))
            .at(0x3000, node(0, 0))
            .panic_on_unmapped();
        assert_eq!(show(&mem, &node(0, 0x2000)), "<inactive variant>");

        // A null first link is reported as such, not chased through.
        let mem = FakeMem::new();
        assert_eq!(show(&mem, &node(0, 0)), "<null>");
    }

    /// A no-discriminant enum with a single variant has nothing to decode,
    /// so a variant step crosses it unguarded; the same shape with several
    /// variants is undecodable, and resolution declines to structural.
    #[test]
    fn test_univariant_enum_needs_no_guard_but_several_variants_decline() {
        let drop_discr = |b: &mut hansei_bundle::Bundle, univariant: bool| {
            let TypeDef::Enum { shape, .. } = &mut b.types.types[OPT.0 as usize] else {
                panic!("Opt is not an enum");
            };
            shape.discr = None;
            if univariant {
                shape.variants.remove(0);
            }
        };
        let alias = |b: &hansei_bundle::Bundle| BundleNode::Alias {
            at: Selector(vec![
                Step::Member(MemberRef::Named(strref(b, "opt"))),
                Step::Variant(strref(b, "Some")),
            ]),
            follow_pointers: true,
        };
        // GuardOuter { wrap: null, opt: 123 }.
        let bytes = u64s(&[0, 123]);

        let mut b = test_bundle();
        drop_discr(&mut b, true);
        let node = alias(&b);
        b.types.debug_formats.insert(GUARD_OUTER, node);
        b.validate().expect("univariant alias must validate");
        let v = BundleView::new(&b);
        let value = Value::new(v.ty(GUARD_OUTER).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "123");

        let mut b = test_bundle();
        drop_discr(&mut b, false);
        let node = alias(&b);
        b.types.debug_formats.insert(GUARD_OUTER, node);
        let v = BundleView::new(&b);
        let value = Value::new(v.ty(GUARD_OUTER).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display());
        assert!(shown.starts_with("GuardOuter"), "{shown}");
    }

    /// A `ValueExpr::Read` crossing a variant step carries the same guard, so
    /// a `Variant` node's discriminant degrades rather than computing from a
    /// dead variant's bytes.
    #[test]
    fn test_value_expr_read_crosses_a_variant_step() {
        let mut b = test_bundle();
        let seven = strref(&b, "one");
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "msg"))),
            Step::Variant(strref(&b, "B")),
        ]);
        b.types.debug_formats.insert(
            MSG_WRAP,
            BundleNode::Variant {
                discriminant: ValueExpr::Read(path),
                arms: vec![Arm {
                    value: 7,
                    label: Some(seven),
                    payload: None,
                }],
                default: None,
            },
        );
        b.validate().expect("variant-stepped read must validate");
        let v = BundleView::new(&b);

        let bytes = msg_wrap(1, 7);
        let value = Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "one");

        let bytes = msg_wrap(0, 7);
        let value = Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "<inactive variant>");
    }

    /// A `ValueExpr::Read` crossing an active-variant step resolves one
    /// guarded candidate per variant and reads through whichever is live —
    /// the same member name landing at a *different* offset per variant, the
    /// shape the scheduler-handle enum keeps its flavor handles in.
    #[test]
    fn test_value_expr_read_crosses_the_active_variant() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::ActiveVariant,
            Step::Member(MemberRef::Named(strref(&b, "x"))),
        ]);
        b.types.debug_formats.insert(
            FLAVOR,
            BundleNode::Computed {
                value: ValueExpr::Read(path),
                decode: ScalarDecode::Raw,
            },
        );
        b.validate().expect("an active-variant read must validate");
        let v = BundleView::new(&b);

        // Flavor: tag u8 @0, payloads @8 — A keeps x at +8, B at +16.
        let flavor = |tag: u8, a_x: u64, b_x: u64| {
            let mut out = vec![0u8; 24];
            out[0] = tag;
            out[8..16].copy_from_slice(&a_x.to_le_bytes());
            out[16..24].copy_from_slice(&b_x.to_le_bytes());
            out
        };
        let show =
            |bytes: &[u8]| format!("{}", Value::new(v.ty(FLAVOR).unwrap(), 0, bytes).display());

        assert_eq!(show(&flavor(0, 5, 9)), "5");
        assert_eq!(show(&flavor(1, 5, 9)), "9");
        // A tag no variant claims selects no candidate: the read degrades
        // rather than picking an offset.
        assert_eq!(show(&flavor(7, 5, 9)), "<inactive variant>");
    }

    /// An active-variant step outside a value-expression read has no way to
    /// try candidates: validation rejects it, and reify's resolution
    /// independently declines to structural display if such a bundle is
    /// ever loaded.
    #[test]
    fn test_active_variant_outside_a_read_is_rejected_and_declined() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::ActiveVariant,
            Step::Member(MemberRef::Named(strref(&b, "x"))),
        ]);
        b.types.debug_formats.insert(
            FLAVOR,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        let err = b
            .validate()
            .expect_err("an active-variant alias must not validate");
        assert!(
            format!("{err}").contains("which only a walk binding or a value-expression read may"),
            "{err}"
        );

        let v = BundleView::new(&b);
        let mut bytes = vec![0u8; 24];
        bytes[8..16].copy_from_slice(&5u64.to_le_bytes());
        let shown = format!("{}", Value::new(v.ty(FLAVOR).unwrap(), 0, &bytes).display());
        assert!(shown.starts_with("Flavor::A"), "{shown}");
    }

    /// A node that resolves its selector to a bare offset cannot carry the
    /// guard: validation rejects it, and reify's resolution independently
    /// declines to structural display if such a bundle is ever loaded.
    #[test]
    fn test_unguardable_variant_step_is_rejected_and_declined() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "msg"))),
            Step::Variant(strref(&b, "B")),
        ]);
        b.types.debug_formats.insert(
            MSG_WRAP,
            BundleNode::Scalar {
                at: path,
                decode: ScalarDecode::Raw,
            },
        );
        let err = b
            .validate()
            .expect_err("an unguardable step must not validate");
        assert!(
            format!("{err}").contains("crosses a variant its node cannot guard"),
            "{err}"
        );

        let v = BundleView::new(&b);
        let bytes = msg_wrap(1, 42);
        let shown = format!(
            "{}",
            Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes).display()
        );
        assert!(shown.starts_with("MsgWrap {"), "{shown}");
    }

    /// A `Computed` node renders the word its expression yields — here a
    /// difference of two counters no single selector could produce.
    #[test]
    fn test_computed_renders_an_expression_result() {
        let mut b = test_bundle();
        b.types.debug_formats.insert(
            CHAN,
            BundleNode::Struct {
                fields: vec![fsynth(
                    strref(&b, "queued"),
                    BundleNode::Computed {
                        value: vsub(vread(sel(&[0])), vread(sel(&[1]))),
                        decode: ScalarDecode::Raw,
                    },
                )],
            },
        );
        b.validate().expect("a computed field must validate");
        let v = BundleView::new(&b);

        // Chan: tail usize @0, index usize @8 — 5 written, 2 consumed.
        let bytes = u64s(&[5, 2, 0]);
        let value = Value::new(v.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display());
        assert!(shown.contains("queued: 3"), "{shown}");
    }

    /// A `Millis` decode spells a millisecond count as seconds, reading the
    /// word as signed so a raced difference degrades to a small negative
    /// duration rather than a wrapped astronomical one.
    #[test]
    fn test_millis_decode_spells_milliseconds_as_seconds() {
        let mut b = test_bundle();
        b.types.debug_formats.insert(
            CHAN,
            BundleNode::Computed {
                value: vsub(vread(sel(&[0])), vread(sel(&[1]))),
                decode: ScalarDecode::Millis,
            },
        );
        b.validate().expect("a millis decode must validate");
        let v = BundleView::new(&b);

        // Chan: tail usize @0, index usize @8.
        let show = |tail: u64, index: u64| {
            let bytes = u64s(&[tail, index, 0]);
            format!("{}", Value::new(v.ty(CHAN).unwrap(), 0, &bytes).display())
        };
        assert_eq!(show(12_721, 0), "12.721s");
        assert_eq!(show(500, 496), "0.004s");
        assert_eq!(show(496, 500), "-0.004s");
    }

    /// A `Computed` expression's reads carry the same degradation as any
    /// other: a guarded variant read that finds another variant live yields
    /// the marker, not arithmetic over dead bytes.
    #[test]
    fn test_computed_read_degrades_through_a_guard() {
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "msg"))),
            Step::Variant(strref(&b, "B")),
        ]);
        b.types.debug_formats.insert(
            MSG_WRAP,
            BundleNode::Computed {
                value: vsub(vread(path), vconst(2)),
                decode: ScalarDecode::Raw,
            },
        );
        b.validate().expect("a guarded computed read must validate");
        let v = BundleView::new(&b);

        let bytes = msg_wrap(1, 44);
        let value = Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "42");

        let bytes = msg_wrap(0, 44);
        let value = Value::new(v.ty(MSG_WRAP).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "<inactive variant>");
    }

    /// A `Computed` discriminant declares no loop variables, so a `Var` in
    /// its expression is a corrupt program.
    #[test]
    fn test_computed_declares_no_variables() {
        let mut b = test_bundle();
        b.types.debug_formats.insert(
            MSG_WRAP,
            BundleNode::Computed {
                value: vvar(0),
                decode: ScalarDecode::Raw,
            },
        );
        let err = b
            .validate()
            .expect_err("a Var in a Computed must not validate");
        assert!(format!("{err}").contains("out of range"), "{err}");
    }

    /// Validation walks a variant step like any other: a non-enum type or an
    /// unknown variant name is a corrupt program, not a render-time surprise.
    #[test]
    fn test_validate_rejects_bad_variant_steps() {
        // `Point` is not an enum.
        let mut b = test_bundle();
        let path = Selector(vec![Step::Variant(strref(&b, "B"))]);
        b.types.debug_formats.insert(
            POINT,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        let err = b
            .validate()
            .expect_err("a non-enum variant step must not validate");
        assert!(
            format!("{err}").contains("enters a variant of a non-enum type"),
            "{err}"
        );

        // `Msg` has no variant named `x`.
        let mut b = test_bundle();
        let path = Selector(vec![
            Step::Member(MemberRef::Named(strref(&b, "msg"))),
            Step::Variant(strref(&b, "x")),
        ]);
        b.types.debug_formats.insert(
            MSG_WRAP,
            BundleNode::Alias {
                at: path,
                follow_pointers: true,
            },
        );
        let err = b
            .validate()
            .expect_err("an unknown variant must not validate");
        assert!(format!("{err}").contains("no unique variant"), "{err}");
    }
}

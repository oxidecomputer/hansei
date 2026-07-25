//! The [`DisplayNode`] interpreter: one generic evaluator that renders a type
//! through the display program its bundle supplies, in place of a per-type
//! renderer. Owns the pretty-vs-inline layout, cycle guarding, and degradation
//! markers for every node kind.

use crate::debug_type::DebugType;
use crate::debug_type::{Arm, DisplayNode, Field, Place, Stmt, ValueExpr};
use crate::value::TypeInfoRef;

use std::borrow::Cow;
use std::fmt;

use super::collections::{eval_list, eval_map, eval_slice};
use super::dyn_ptr::eval_dyn_pointer;
use super::scalar::{
    apply, byte_range, eval_ip_addr, read_u64_at, read_unsigned_at, write_symbol, write_utf8_string,
};
use super::{DisplayRecurse, RenderCtx, write_indent, write_seq_close, write_seq_prefix};

/// Interpret a resolved [`DisplayNode`] tree — the single generic evaluator
/// that stands in for the per-type `write_*` renderers on node-based formats.
///
/// `ty` is the type the node is rendered against: its name titles a `Struct`
/// record and its members back `Field::Structural`. `bytes`/`addr` are that
/// value's buffer and target address; a node's offsets are relative to them.
/// `pretty` requests multi-line layout. All pretty-vs-inline, cycle-guard, and
/// degradation-string handling lives here, written once.
pub(crate) fn eval_node<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    node: &DisplayNode<T>,
    ty: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    match node {
        DisplayNode::Scalar {
            offset,
            word_size,
            decode,
        } => match read_unsigned_at(bytes, *offset, u64::from(*word_size)) {
            Some(word) => write!(f, "{}", apply(decode, word)),
            None => write!(f, "<truncated>"),
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
        DisplayNode::Str {
            pointer_offset,
            length_offset,
            length_size,
            capacity,
        } => write_utf8_string(
            f,
            bytes,
            *pointer_offset,
            *length_offset,
            u64::from(*length_size),
            capacity.map(|(offset, size)| (offset, u64::from(size))),
            ctx.proc,
        ),
        DisplayNode::Slice {
            pointer_offset,
            length_offset,
            length_size,
            capacity,
            element,
            element_size,
        } => eval_slice(
            f,
            *pointer_offset,
            *length_offset,
            *length_size,
            *capacity,
            element,
            *element_size,
            bytes,
            ctx,
            pretty,
        ),
        DisplayNode::IpAddr {
            octets_offset,
            octets_size,
        } => eval_ip_addr(f, bytes, *octets_offset, u64::from(*octets_size)),
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
                    let child = DisplayRecurse {
                        info: TypeInfoRef {
                            ty: *target,
                            addr: child_addr,
                            bytes: child_bytes.as_ref(),
                            _marker: std::marker::PhantomData,
                        },
                        ctx: child_ctx,
                    };
                    if pretty {
                        write!(f, "{child:#}")
                    } else {
                        write!(f, "{child}")
                    }
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
                    &target_bytes,
                    addr,
                    ctx,
                    pretty,
                ),
                other => eval_node(f, other, target, &target_bytes, addr, ctx, pretty),
            }
        }
        DisplayNode::DynPointer { .. } => {
            eval_dyn_pointer(f, *ty, Some(ty.name()), node, bytes, ctx)
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

/// Read the `size`-byte machine word at `place`, following any pointer hops
/// through `proc`. Empty `hops` is the common case: a borrowed local slice, no
/// process read. On failure the `Err` carries the exact degradation marker to
/// print in the value's place.
fn read_place_bytes<'b>(
    place: &Place,
    bytes: &'b [u8],
    addr: u64,
    ctx: RenderCtx<'_, '_>,
    size: u64,
) -> std::result::Result<(u64, Cow<'b, [u8]>), &'static str> {
    if place.hops.is_empty() {
        let slice = byte_range(bytes, place.root_offset, size).ok_or("<truncated>")?;
        return Ok((addr.wrapping_add(place.root_offset), Cow::Borrowed(slice)));
    }
    let proc = ctx.proc.ok_or("<target unavailable>")?;
    let mut pointer = read_u64_at(bytes, place.root_offset).ok_or("<truncated>")?;
    let (last, intermediate) = place.hops.split_last().expect("hops is non-empty");
    for hop in intermediate {
        if pointer == 0 {
            return Err("<null>");
        }
        let addr = pointer.checked_add(*hop).ok_or("<invalid address>")?;
        let word = proc.read_bytes(addr, 8).map_err(|_| "<unreadable>")?;
        pointer = read_u64_at(&word, 0).ok_or("<unreadable>")?;
    }
    if pointer == 0 {
        return Err("<null>");
    }
    let target = pointer.checked_add(*last).ok_or("<invalid address>")?;
    let read = if size == 0 {
        Vec::new()
    } else {
        proc.read_bytes(target, size).map_err(|_| "<unreadable>")?
    };
    Ok((target, Cow::Owned(read)))
}

/// Evaluate a resolved [`ValueExpr`] against `bytes`, crossing pointer hops via
/// `ctx.proc`. `Err` carries a degradation marker for a failed read.
fn eval_expr(
    expr: &ValueExpr,
    vars: &[u64],
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, '_>,
) -> std::result::Result<u64, &'static str> {
    Ok(match expr {
        ValueExpr::Const(value) => *value,
        ValueExpr::Read(place, size) => {
            let (_, word) = read_place_bytes(place, bytes, addr, ctx, u64::from(*size))?;
            read_unsigned_at(word.as_ref(), 0, u64::from(*size)).ok_or("<unreadable>")?
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
            read_unsigned_at(&word, 0, u64::from(*size)).ok_or("<unreadable>")?
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
fn eval_custom_list<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    vars_init: &[ValueExpr],
    condition: &ValueExpr,
    body: &[Stmt],
    element: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
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
    write_seq_close(f, pretty, ctx.depth, any)?;
    write!(f, "]")
}

/// Run one [`Stmt`] sequence for a [`DisplayNode::CustomList`] iteration,
/// mutating `vars`, emitting elements, and returning whether the loop continues.
/// A read that degrades writes its marker inline and stops the loop.
#[allow(clippy::too_many_arguments)]
fn eval_stmts<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    stmts: &[Stmt],
    vars: &mut Vec<u64>,
    element: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
    any: &mut bool,
) -> std::result::Result<Flow, fmt::Error> {
    for stmt in stmts {
        match stmt {
            Stmt::Set { var, value } => {
                let value = match eval_expr(value, vars, bytes, addr, ctx) {
                    Ok(value) => value,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                if let Some(slot) = vars.get_mut(*var as usize) {
                    *slot = value;
                }
            }
            Stmt::If {
                cond,
                then,
                otherwise,
            } => {
                let cond = match eval_expr(cond, vars, bytes, addr, ctx) {
                    Ok(cond) => cond,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                let branch = if cond != 0 { then } else { otherwise };
                if let Flow::Stop =
                    eval_stmts(f, branch, vars, element, bytes, addr, ctx, pretty, any)?
                {
                    return Ok(Flow::Stop);
                }
            }
            Stmt::Break { cond } => {
                let cond = match eval_expr(cond, vars, bytes, addr, ctx) {
                    Ok(cond) => cond,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                if cond != 0 {
                    return Ok(Flow::Stop);
                }
            }
            Stmt::Emit { at } => {
                let target = match eval_expr(at, vars, bytes, addr, ctx) {
                    Ok(target) => target,
                    Err(marker) => {
                        write_seq_marker(f, marker, *any)?;
                        return Ok(Flow::Stop);
                    }
                };
                let Some(proc) = ctx.proc else {
                    write_seq_marker(f, "<target unavailable>", *any)?;
                    return Ok(Flow::Stop);
                };
                let Ok(element_bytes) = proc.read_bytes(target, element.size()) else {
                    write_seq_marker(f, "<unreadable>", *any)?;
                    return Ok(Flow::Stop);
                };
                write_seq_prefix(f, pretty, ctx.depth, !*any)?;
                *any = true;
                let child = DisplayRecurse {
                    info: TypeInfoRef {
                        ty: *element,
                        addr: target,
                        bytes: &element_bytes,
                        _marker: std::marker::PhantomData,
                    },
                    ctx: ctx.deeper(),
                };
                if pretty {
                    write!(f, "{child:#},")?;
                } else {
                    write!(f, "{child}")?;
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
fn eval_variant<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    discriminant: &ValueExpr,
    arms: &[Arm<T>],
    default: Option<&DisplayNode<T>>,
    ty: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
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
fn eval_struct<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    fields: &[Field<T>],
    ty: &T,
    name: Option<&str>,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    // A `Pointer` re-roots the record at its target but titles it with the
    // enclosing type's name (a `Receiver` reads as its `Chan`); every other
    // caller titles it with the rendered type's own name.
    write!(f, "{} {{", name.unwrap_or_else(|| ty.name()))?;
    for (i, field) in fields.iter().enumerate() {
        // Field prefix: pretty starts a fresh indented line; inline opens with
        // a space after `{` and separates subsequent fields with `, `.
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.depth + 1)?;
        } else if i > 0 {
            write!(f, ", ")?;
        } else {
            write!(f, " ")?;
        }
        match field {
            Field::Structural {
                name,
                ty: mem_ty,
                offset,
            } => {
                write!(f, "{name}: ")?;
                match byte_range(bytes, *offset, mem_ty.size()) {
                    Some(mem_bytes) => {
                        let child = DisplayRecurse {
                            info: TypeInfoRef {
                                ty: *mem_ty,
                                addr: addr + offset,
                                bytes: mem_bytes,
                                _marker: std::marker::PhantomData,
                            },
                            ctx: ctx.deeper(),
                        };
                        if pretty {
                            write!(f, "{child:#}")?
                        } else {
                            write!(f, "{child}")?
                        }
                    }
                    None => write!(f, "<truncated>")?,
                }
            }
            Field::Computed { label, node } => {
                write!(f, "{label}: ")?;
                eval_node(f, node, ty, bytes, addr, ctx.deeper(), pretty)?;
            }
        }
        if pretty {
            write!(f, ",")?;
        }
    }
    if pretty {
        writeln!(f)?;
        write_indent(f, ctx.depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

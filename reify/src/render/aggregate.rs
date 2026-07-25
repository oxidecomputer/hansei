//! Structural rendering of Rust aggregates: struct and enum-variant bodies,
//! including the `__N` tuple-field elision that makes a tuple struct render as
//! `Name(v0, v1)` rather than `Name { __0: v0, __1: v1 }`.

use crate::Error;
use crate::debug_type::{DebugMember, DebugType, DisplayNode};
use crate::value::TypeInfoRef;

use std::fmt;

use super::dyn_ptr::eval_dyn_pointer;
use super::{DisplayRecurse, RenderCtx, write_hex_bytes, write_indent};

/// True when `members` are a Rust tuple aggregate — a tuple struct or a tuple
/// enum variant — whose fields rustc names `__0, __1, …` in declaration order.
/// Such a value renders positionally (`Name(v0, v1)`), eliding the synthetic
/// labels, to match `rustc`/gdb/lldb `Debug` output. A regular struct names a
/// field something other than `__i`, so one non-matching member rules it out.
/// Detection runs on the *full* member list so a `(ZST, T)` tuple is still
/// recognized even though the ZST is not displayed.
fn is_tuple<'a, M: DebugMember<'a>>(members: &[M]) -> bool {
    !members.is_empty()
        && members.iter().enumerate().all(|(i, m)| {
            m.name()
                .strip_prefix("__")
                .and_then(|rest| rest.parse::<usize>().ok())
                == Some(i)
        })
}

/// Render one member's value (or `<truncated>`) at its offset, recursing with
/// the deeper context. Shared by the tuple and named aggregate bodies.
fn write_member_value<'a, M: DebugMember<'a>>(
    f: &mut fmt::Formatter<'_>,
    member: &M,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let mem_ty = member.ty();
    let start = member.offset() as usize;
    let end = start + mem_ty.size() as usize;
    match bytes.get(start..end) {
        Some(mem_bytes) => {
            let child = DisplayRecurse {
                info: TypeInfoRef {
                    ty: mem_ty,
                    addr: addr + member.offset(),
                    bytes: mem_bytes,
                    _marker: std::marker::PhantomData,
                },
                ctx: ctx.deeper(),
            };
            if pretty {
                write!(f, "{:#}", child)
            } else {
                write!(f, "{}", child)
            }
        }
        None => write!(f, "<truncated>"),
    }
}

/// Render the body of a struct or enum-variant payload after its name/variant
/// has been written: a tuple aggregate as `(v0, v1)` (labels elided), a named
/// aggregate as ` { field: v, … }`, and an empty/all-ZST aggregate as nothing
/// (a unit). Zero-sized members are never displayed.
fn write_aggregate_body<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    ty: &T,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    let all: Vec<_> = ty.members().collect();
    let tuple = is_tuple(&all);
    let shown: Vec<_> = all.into_iter().filter(|m| m.ty().size() > 0).collect();

    if shown.is_empty() {
        return Ok(());
    }

    if tuple {
        write!(f, "(")?;
        for (i, member) in shown.iter().enumerate() {
            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.depth + 1)?;
            } else if i > 0 {
                write!(f, ", ")?;
            }
            write_member_value(f, member, bytes, addr, ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
        }
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.depth)?;
        }
        write!(f, ")")
    } else {
        write!(f, " {{")?;
        for (i, member) in shown.iter().enumerate() {
            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.depth + 1)?;
            } else if i > 0 {
                write!(f, ",")?;
            }
            write!(f, " {}: ", member.name())?;
            write_member_value(f, member, bytes, addr, ctx, pretty)?;
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
}

pub(crate) fn write_struct_fields<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    pretty: bool,
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    if !name.is_empty() {
        write!(f, "{}", name)?;
    }
    write_aggregate_body(f, &info.ty, info.bytes, info.addr, ctx, pretty)
}

pub(crate) fn write_rust_enum<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    name: &str,
    pretty: bool,
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    let Ok((variant_name, var_ty, offset)) = info
        .ty
        .active_variant(info.bytes)
        .unwrap_or_else(|| Err(Error::not_an_enum(name.to_string())))
    else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };

    let start = offset as usize;
    let end = start + var_ty.size() as usize;
    let Some(variant_bytes) = info.bytes.get(start..end) else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };
    let variant_addr = info.addr + offset;
    let variant_info = TypeInfoRef {
        ty: var_ty,
        addr: variant_addr,
        bytes: variant_bytes,
        _marker: std::marker::PhantomData,
    }
    .peel();

    if !name.is_empty() {
        write!(f, "{}::", name)?;
    }
    write!(f, "{}", variant_name)?;

    // Zero-sized variant (unit variant)
    if var_ty.size() == 0 {
        return Ok(());
    }

    if !ctx.ugly
        && let Some(node @ DisplayNode::DynPointer { .. }) = variant_info.ty.debug_format()
    {
        return eval_dyn_pointer(f, variant_info.ty, None, &node, variant_info.bytes, ctx);
    }

    // A payload carrying a semantic display format (a `&str`/`String`, a
    // `Vec`, an IP address, ...) should render as that value, not as its
    // raw representation fields. `Cow<str>::Borrowed("x")` reads far better
    // than `Borrowed { data_ptr: .., length: .. }`. Delegating to the value
    // formatter keeps this general across every known format (trait objects
    // are handled above, with their own layout). `--ugly` mode forgoes this
    // and renders the payload's raw fields.
    if !ctx.ugly && variant_info.ty.debug_format().is_some() {
        // Peeling into the payload's own formatter is a representation detail,
        // so it stays at the same depth.
        let child = DisplayRecurse {
            info: variant_info,
            ctx,
        };
        write!(f, "(")?;
        if pretty {
            write!(f, "{child:#}")?;
        } else {
            write!(f, "{child}")?;
        }
        return write!(f, ")");
    }

    // A tuple variant (`Some(x)`, `Ok(x)`) renders positionally; a struct
    // variant (`Variant { field: x }`) keeps its labels. Both share the
    // aggregate body renderer, so the `__N` elision is applied in one place.
    write_aggregate_body(
        f,
        &variant_info.ty,
        variant_info.bytes,
        variant_info.addr,
        ctx,
        pretty,
    )
}

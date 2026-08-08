//! Structural rendering of Rust aggregates: struct and enum-variant bodies,
//! including the `__N` tuple-field elision that makes a tuple struct render as
//! `Name(v0, v1)` rather than `Name { __0: v0, __1: v1 }`.

use crate::debug_type::{DisplayNode, TypeKind};
use crate::value::TypeInfoRef;

use exegesis::bundle::{BundleMember, BundleType};

use std::fmt;

use super::dyn_ptr::eval_dyn_pointer;
use super::{RenderCtx, write_display_value, write_hex_bytes, write_indent};

/// True when `members` are a Rust tuple aggregate — a tuple struct or a tuple
/// enum variant — whose fields rustc names `__0, __1, …` in declaration order.
/// Such a value renders positionally (`Name(v0, v1)`), eliding the synthetic
/// labels, to match `rustc`/gdb/lldb `Debug` output. A regular struct names a
/// field something other than `__i`, so one non-matching member rules it out.
/// Detection runs on the *full* member list so a `(ZST, T)` tuple is still
/// recognized even though the ZST is not displayed.
fn is_tuple<'a>(members: impl Iterator<Item = BundleMember<'a>>) -> bool {
    let mut any = false;
    for (i, m) in members.enumerate() {
        if tuple_field_index(m.name()) != Some(i) {
            return false;
        }
        any = true;
    }
    any
}

/// The position a synthetic tuple-field name encodes, if it is one:
/// rustc names a tuple struct's and a tuple variant's fields `__0`,
/// `__1`, … A field named anything else came from the source.
fn tuple_field_index(name: &str) -> Option<usize> {
    name.strip_prefix("__")
        .and_then(|rest| rest.parse::<usize>().ok())
}

/// True when `ty` is a struct whose one sized member carries a
/// source-level name. This is the shape peeling dissolves — a struct
/// variant declared with a single field — and the name goes with it
/// unless the body is written from the payload as declared.
fn has_named_single_field<'a>(ty: &BundleType<'a>) -> bool {
    if ty.kind() != TypeKind::Struct {
        return false;
    }
    let mut sized = ty.members().filter(|m| m.ty().size() > 0);
    match (sized.next(), sized.next()) {
        (Some(member), None) => tuple_field_index(member.name()).is_none(),
        _ => false,
    }
}

/// Render one member's value (or `<truncated>`) at its offset, recursing with
/// the deeper context. Shared by the tuple and named aggregate bodies.
fn write_member_value<'a>(
    f: &mut fmt::Formatter<'_>,
    member: &BundleMember<'a>,
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
            let child = TypeInfoRef {
                ty: mem_ty,
                addr: addr + member.offset(),
                bytes: mem_bytes,
            };
            write_display_value(f, &child, ctx.deeper(), pretty)
        }
        None => write!(f, "<truncated>"),
    }
}

/// Render the body of a struct or enum-variant payload after its name/variant
/// has been written: a tuple aggregate as `(v0, v1)` (labels elided), a named
/// aggregate as ` { field: v, … }`, and an empty/all-ZST aggregate as nothing
/// (a unit). Zero-sized members are never displayed.
fn write_aggregate_body<'a>(
    f: &mut fmt::Formatter<'_>,
    ty: &BundleType<'a>,
    bytes: &[u8],
    addr: u64,
    ctx: RenderCtx<'_, 'a>,
    pretty: bool,
) -> fmt::Result {
    // Two cheap passes over the member slice rather than a collected
    // Vec: this runs once per structurally-rendered value, and a deep
    // trace renders millions of them.
    let tuple = is_tuple(ty.members());
    let mut shown = ty.members().filter(|m| m.ty().size() > 0).peekable();

    if shown.peek().is_none() {
        return Ok(());
    }

    if tuple {
        write!(f, "(")?;
        for (i, member) in shown.enumerate() {
            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.prefix, ctx.depth + 1)?;
            } else if i > 0 {
                write!(f, ", ")?;
            }
            write_member_value(f, &member, bytes, addr, ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
        }
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.prefix, ctx.depth)?;
        }
        write!(f, ")")
    } else {
        write!(f, " {{")?;
        for (i, member) in shown.enumerate() {
            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.prefix, ctx.depth + 1)?;
            } else {
                // Inline, the space separates the field from the opening brace
                // or from the preceding comma. Pretty has already indented, so
                // adding it there would put the field one column past the
                // closing brace's own indent.
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, " ")?;
            }
            f.write_str(member.name())?;
            f.write_str(": ")?;
            write_member_value(f, &member, bytes, addr, ctx, pretty)?;
            if pretty {
                write!(f, ",")?;
            }
        }
        if pretty {
            writeln!(f)?;
            write_indent(f, ctx.prefix, ctx.depth)?;
        } else {
            write!(f, " ")?;
        }
        write!(f, "}}")
    }
}

pub(crate) fn write_struct_fields<'a>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a>,
    name: &str,
    pretty: bool,
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    if !name.is_empty() {
        f.write_str(name)?;
    }
    write_aggregate_body(f, &info.ty, info.bytes, info.addr, ctx, pretty)
}

pub(crate) fn write_rust_enum<'a>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a>,
    name: &str,
    pretty: bool,
    ctx: RenderCtx<'_, 'a>,
) -> fmt::Result {
    let Some(Ok(active)) = info.ty.active_variant(info.bytes) else {
        if !name.is_empty() {
            write!(f, "{} ", name)?;
        }
        return write_hex_bytes(f, info.bytes);
    };
    let (variant_name, var_ty, offset) = (active.name, active.ty, active.offset);
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
    }
    .peel();

    if !name.is_empty() {
        f.write_str(name)?;
        f.write_str("::")?;
    }
    f.write_str(variant_name)?;

    // Zero-sized variant (unit variant)
    if var_ty.size() == 0 {
        return Ok(());
    }

    // A struct variant declared with one field — tokio's
    // `Entered { allow_block_in_place }` — is a single-member struct, so
    // peeling dissolves it into that field's type and the label goes with
    // it. Write its body from the payload as declared, where the name is
    // still there; the members' own formats still apply, since the body
    // renderer recurses per member. A payload carrying a format of its
    // own is left to the delegation below, which is what a `String`-like
    // wrapper needs, and a tuple variant's synthetic `__0` stays elided.
    if (ctx.ugly || ctx.debug_format(&var_ty).is_none()) && has_named_single_field(&var_ty) {
        return write_aggregate_body(f, &var_ty, variant_bytes, variant_addr, ctx, pretty);
    }

    if !ctx.ugly
        && let Some(node) = ctx.debug_format(&variant_info.ty)
        && matches!(*node, DisplayNode::DynPointer { .. })
    {
        return eval_dyn_pointer(
            f,
            variant_info.ty,
            None,
            &node,
            variant_info.bytes,
            ctx,
            pretty,
        );
    }

    // A payload carrying a semantic display format (a `&str`/`String`, a
    // `Vec`, an IP address, ...) should render as that value, not as its
    // raw representation fields. `Cow<str>::Borrowed("x")` reads far better
    // than `Borrowed { data_ptr: .., length: .. }`. Delegating to the value
    // formatter keeps this general across every known format (trait objects
    // are handled above, with their own layout). `--ugly` mode forgoes this
    // and renders the payload's raw fields.
    if !ctx.ugly && ctx.debug_format(&variant_info.ty).is_some() {
        // Peeling into the payload's own formatter is a representation detail,
        // so it stays at the same depth.
        write!(f, "(")?;
        write_display_value(f, &variant_info, ctx, pretty)?;
        return write!(f, ")");
    }

    // A payload that peels to a value rather than an aggregate — the `u8`
    // behind `Option<u8>::Some`, the pointer behind a newtype variant —
    // has no members for the body renderer to walk, so it is written
    // positionally here instead. Without this the payload is dropped
    // silently and the variant reads as a unit, which is the one thing a
    // value renderer must never do. It costs a level of depth, as the
    // same value would inside a tuple variant of two.
    //
    // The test is the payload's kind, not whether it has members: a
    // niche-encoded unit variant (`Option<Waker>::None`) is a struct
    // that declares none while covering the whole enum, and it must
    // stay a unit rather than gain a body.
    if !matches!(
        variant_info.ty.kind(),
        TypeKind::Struct | TypeKind::Union | TypeKind::Other
    ) {
        write!(f, "(")?;
        write_display_value(f, &variant_info, ctx.deeper(), pretty)?;
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

#[cfg(test)]
mod tests {
    use crate::TypeInfoRef;
    use crate::testhelper::*;

    use exegesis::bundle::{Bundle, BundleView, DisplayNode as BundleNode, TypeDef};

    #[test]
    fn test_ugly_suppresses_enum_payload_formatter() {
        // Reshape `Opt::Some`'s payload to a `&str`, whose own `Str` format is
        // normally delegated to when it appears as an enum payload. `--ugly`
        // suppresses that delegation and shows the payload's raw fields.
        let mut b = test_bundle();
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 16;
        shape.variants[1].payload.ty = STR;
        b.validate().expect("modified enum bundle must validate");

        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display().ugly()),
            "Opt::Some { data_ptr: 0x3000, length: 8 }"
        );
    }

    #[test]
    fn test_tuple_struct_elides_synthetic_field_names() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();

        // A tuple struct's `__0`/`__1` fields render positionally, eliding the
        // synthetic labels, to match Rust `Debug` (`Pair(1, 2)`).
        let pair = TypeInfoRef::new(v.ty(PAIR).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", pair.display_with_depth(2)), "Pair(1, 2)");
        assert_eq!(
            format!("{:#}", pair.display_with_depth(2)),
            "Pair(\n    1,\n    2,\n)"
        );

        // A regular struct still shows its field names (regression guard).
        let point = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", point.display_with_depth(2)),
            "Point { x: 1, y: 2 }"
        );
    }

    #[test]
    fn test_str_payload_in_enum_renders_as_value() {
        let mem = FakeMem::new().at(0x3000, b"hi\nthere".to_vec());

        // Point Opt::Some's payload at a `&str`; its `Str` display format
        // must win over dumping the fat pointer's raw fields, matching how a
        // `Cow<str>::Borrowed` key should read.
        let mut b = test_bundle();
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 16;
        shape.variants[1].payload.ty = STR;
        b.validate().expect("modified enum bundle must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "Opt::Some(\"hi\\nthere\")"
        );
        // The payload is a value, not a record, so pretty mode has nothing to
        // lay out and renders the same -- the parenthesised form is the
        // variant's, not the payload's.
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            "Opt::Some(\"hi\\nthere\")"
        );
    }

    #[test]
    fn test_wrapped_str_payload_in_enum_is_not_peeled() {
        let mem = FakeMem::new().at(0x3000, b"hi\nthere".to_vec());

        // A `String`/`Utf8PathBuf` is a single-member wrapper carrying its own
        // `Str` format around an inner `Vec<u8>` (which has a `Slice` format).
        // Reshape `Wrap` into that: a one-member wrapper over `Vec` with a `Str`
        // format of its own. As `Opt::Some`'s payload it must render as the
        // string, not peel past its `Str` to the inner `Vec`'s byte slice.
        let mut b = test_bundle();
        let TypeDef::Struct { size, members, .. } = &mut b.types.types[WRAP.0 as usize] else {
            panic!("Wrap is not a struct");
        };
        *size = 24;
        members[0].ty = VEC;
        b.types.debug_formats.insert(
            WRAP,
            BundleNode::Str {
                pointer: sel(&[0, 0]),
                length: sel(&[0, 1]),
                capacity: Some(sel(&[0, 2])),
            },
        );
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 24;
        shape.variants[1].payload.ty = WRAP;
        b.validate().expect("modified enum bundle must validate");

        let v = BundleView::new(&b);
        // Vec-shaped payload bytes: data pointer, length, capacity.
        let bytes: Vec<u8> = [0x3000u64, 8, 16]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "Opt::Some(\"hi\\nthere\")"
        );
    }

    /// Enum variant bodies in pretty mode. The variant name is written inline
    /// and the payload is laid out by the same aggregate body a struct uses, so
    /// a named payload nests and a unit variant adds nothing.
    #[test]
    fn test_enum_variant_bodies_lay_out_like_structs() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let msg = v.ty(MSG).unwrap();
        let variant = |discr: u8, payload: &[u8]| {
            let mut bytes = vec![0u8; 16];
            bytes[0] = discr;
            bytes[8..8 + payload.len()].copy_from_slice(payload);
            bytes
        };

        // A(Point): the payload's own fields, prefixed with the variant.
        let a = variant(0, &u32s(&[1, 2]));
        let a = TypeInfoRef::new(msg, 0, &a);
        assert_eq!(format!("{}", a.display()), "Msg::A { x: 1, y: 2 }");
        assert_eq!(
            format!("{:#}", a.display()),
            "Msg::A {\n    x: 1,\n    y: 2,\n}"
        );

        // C(unit): a zero-sized payload writes no body at all.
        let c = variant(2, &[]);
        let c = TypeInfoRef::new(msg, 0, &c);
        assert_eq!(format!("{}", c.display()), "Msg::C");
        assert_eq!(format!("{:#}", c.display()), "Msg::C");

        // B(u64): the payload type is a bare scalar, with no members for
        // the aggregate body to walk, so it is written positionally --
        // like the one-field tuple variant it stands for. Pretty mode has
        // no structure to lay out, so both spellings agree.
        let b_bytes = variant(1, &7u64.to_le_bytes());
        let b_val = TypeInfoRef::new(msg, 0, &b_bytes);
        assert_eq!(format!("{}", b_val.display()), "Msg::B(7)");
        assert_eq!(format!("{:#}", b_val.display()), "Msg::B(7)");
    }

    /// The shape extracted DWARF actually produces: a variant's payload
    /// is a struct with one field, which peeling dissolves into that
    /// field's own type before the body is written. Both what the field
    /// holds and what it is called have to survive that — a
    /// `Option<u8>::Some(3)` reading as a bare `Some` drops the payload
    /// silently, and a named field reading as `Entered(true)` drops the
    /// only thing that says what the `true` means.
    #[test]
    fn test_single_field_payload_survives_peeling() {
        // `AtomicStorage<u32>` is a one-field struct over a scalar,
        // carrying no display format of its own, so nothing but peeling
        // stands between the variant and the value.
        let named = single_field_payload(false);
        let v = BundleView::new(&named);
        let bytes = 7u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "Opt::Some { value: 7 }");
        assert_eq!(
            format!("{:#}", value.display()),
            "Opt::Some {\n    value: 7,\n}"
        );

        // The same payload with the field named as rustc names a tuple
        // variant's: the label is synthetic, so it is elided and the
        // value reads positionally.
        let tuple = single_field_payload(true);
        let v = BundleView::new(&tuple);
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display()), "Opt::Some(7)");
    }

    /// A copy of the fixture bundle whose `Opt::Some` payload is
    /// `AtomicStorage<u32>` — a one-field struct over a scalar, with no
    /// display format of its own — keeping the field's declared name or
    /// giving it the `__0` rustc gives a tuple variant's.
    fn single_field_payload(synthetic: bool) -> Bundle {
        let mut b = test_bundle();
        if synthetic {
            // `LoomUnsafeCell` is the fixture's one tuple-named member,
            // and so its source of an interned `__0`.
            let TypeDef::Struct { members, .. } = &b.types.types[LOOM_CELL.0 as usize] else {
                panic!("LoomUnsafeCell is not a struct");
            };
            let name = members[0].name;
            assert_eq!(b.strings.get(name), Some("__0"), "not a tuple field name");
            let TypeDef::Struct { members, .. } = &mut b.types.types[ATOMIC_STORAGE.0 as usize]
            else {
                panic!("AtomicStorage is not a struct");
            };
            members[0].name = name;
        }
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 8;
        shape.variants[1].payload.ty = ATOMIC_STORAGE;
        b.validate().expect("modified enum bundle must validate");
        b
    }

    /// An enum whose discriminant matches no variant cannot be decoded into a
    /// payload, so it falls back to its name over the raw bytes rather than
    /// picking a variant or rendering nothing. Pretty mode has no structure to
    /// lay out, so both spellings agree.
    #[test]
    fn test_undecodable_enum_falls_back_to_name_and_bytes() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = vec![0u8; 16];
        bytes[0] = 99;
        let value = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);
        let expected = "Msg [0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]";
        assert_eq!(format!("{}", value.display()), expected);
        assert_eq!(format!("{:#}", value.display()), expected);
    }
}

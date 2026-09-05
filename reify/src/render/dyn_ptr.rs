// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trait-object rendering: display a `dyn Trait` data pointer and its vtable,
//! recovering the concrete type from a vtable function symbol where possible.

use crate::debug_type::DisplayNode;
use crate::value::Value;
use proc::Target;

use hansei_bundle::BundleType;

use std::fmt;

use super::scalar::read_u64_at;
use super::{
    RenderCtx, write_display_value, write_hex_fixed, write_hex_u64, write_indent,
    write_record_close,
};

#[derive(Debug)]
struct VtableFunction {
    slot: u32,
    display: String,
    concrete: Option<String>,
}

pub(crate) fn eval_dyn_pointer<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    ty: BundleType<'a>,
    name: Option<&str>,
    node: &DisplayNode<'a>,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let DisplayNode::DynPointer {
        pointer_offset,
        vtable,
        vtable_offset,
        drop_in_place: drop_in_place_slot,
        size: size_slot,
        align: align_slot,
        tail_prefixes,
    } = node
    else {
        unreachable!()
    };

    let Some(pointer_address) = read_u64_at(bytes, *pointer_offset) else {
        return write!(f, "<truncated>");
    };
    let Some(vtable_address) = read_u64_at(bytes, *vtable_offset) else {
        return write!(f, "<truncated>");
    };
    let words = read_vtable_words(*vtable, vtable_address, ctx.proc);

    let mut functions = Vec::new();
    if let (Some(proc), Some(words)) = (ctx.proc, words.as_deref()) {
        for (slot, &address) in words.iter().enumerate() {
            let slot = slot as u32;
            if slot == *size_slot || slot == *align_slot || address == 0 {
                continue;
            }
            let Some(display) = resolve_function_symbol(Some(proc), address) else {
                continue;
            };
            let concrete = hansei_bundle::symbols::concrete_type_from_vtable_symbol(&display)
                .map(str::to_owned);
            functions.push(VtableFunction {
                slot,
                display,
                concrete,
            });
        }
    }

    let inferred = infer_concrete_type(ty, words.as_deref(), *size_slot, &functions);
    let (concrete, concrete_ty) = match inferred {
        Some((name, resolved)) => (Some(name), resolved),
        None => (None, None),
    };
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        write!(f, "{name}")?;
    }
    write!(f, " {{")?;

    write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth)?;
    f.write_str("pointer: ")?;
    write_hex_u64(f, pointer_address)?;
    // The vtable resolves the erased *tail* type; when the pointer targets an
    // unsized wrapper (e.g. `ArcInner<dyn Trait>`) the value lives past a
    // sized header whose extent depends on the concrete type's alignment,
    // which is the vtable's to say.
    let align_word = words
        .as_deref()
        .and_then(|words| words.get(*align_slot as usize).copied());
    let pointee_address =
        tail_offset(tail_prefixes, align_word).map(|offset| pointer_address.wrapping_add(offset));
    // A zero-sized concrete type (e.g. slog's `()` list terminator) has no
    // pointee worth following — the `concrete type:` line below already names
    // it. Showing `-> ()` would only add noise.
    if let (Some(concrete_ty), Some(_), Some(visited)) = (
        concrete_ty.filter(|ty| ty.size() > 0),
        ctx.proc,
        ctx.visited,
    ) {
        let key = pointee_address.map(|address| (address, concrete_ty.name()));
        match key {
            // A header is in the way and the word that says how far it
            // reaches is not an alignment: nothing places the value.
            None => match align_word {
                Some(align) => write!(f, " -> <vtable align {align} is not a power of two>")?,
                None => f.write_str(" -> <vtable align unavailable>")?,
            },
            Some(key) if !visited.borrow_mut().insert(key) => write!(f, " -> <cycle>")?,
            Some(key) => {
                let pointee_address = key.0;
                match ctx.read(pointee_address, concrete_ty.size()) {
                    Ok(pointee_bytes) => {
                        let pointee = Value {
                            ty: concrete_ty,
                            addr: pointee_address,
                            bytes: pointee_bytes,
                        };
                        write!(f, " -> ")?;
                        write_display_value(
                            f,
                            &pointee,
                            RenderCtx {
                                suppress_addr: true,
                                ..ctx.deeper()
                            },
                            pretty,
                        )?;
                    }
                    Err(marker) => write!(f, " -> {marker}")?,
                }
                visited.borrow_mut().remove(&key);
            }
        }
    }
    write!(f, ",")?;
    write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth)?;
    write!(
        f,
        "concrete type: {},",
        concrete.as_deref().unwrap_or("<unknown>")
    )?;
    write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth)?;
    write!(f, "vtable: ")?;

    match words.as_deref() {
        Some(words) if ctx.depth + 1 < ctx.max_depth => {
            write!(f, "{{")?;
            write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth + 1)?;
            let drop_address = words
                .get(*drop_in_place_slot as usize)
                .copied()
                .unwrap_or(0);
            f.write_str("drop_in_place: ")?;
            write_hex_u64(f, drop_address)?;
            if let Some(function) = functions
                .iter()
                .find(|function| function.slot == *drop_in_place_slot)
            {
                write!(f, " -> {}", function.display)?;
            }
            write!(f, ",")?;

            write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth + 1)?;
            match words.get(*size_slot as usize) {
                Some(size) => write!(f, "size: {size},")?,
                None => write!(f, "size: <unavailable>,")?,
            }
            write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth + 1)?;
            match words.get(*align_slot as usize) {
                Some(align) => write!(f, "align: {align},")?,
                None => write!(f, "align: <unavailable>,")?,
            }

            for (slot, &address) in words.iter().enumerate() {
                let slot = slot as u32;
                if slot == *drop_in_place_slot || slot == *size_slot || slot == *align_slot {
                    continue;
                }
                write_dyn_field_prefix(f, pretty, ctx.prefix, ctx.depth + 1)?;
                if let Some(function) = functions.iter().find(|function| function.slot == slot) {
                    write!(f, "method[{slot}]: ")?;
                    write_hex_u64(f, address)?;
                    write!(f, " -> {},", function.display)?;
                } else {
                    write!(f, "entry[{slot}]: ")?;
                    write_hex_fixed(f, address, 8)?;
                    f.write_str(",")?;
                }
            }

            write_record_close(f, pretty, ctx.prefix, ctx.depth + 1)?;
            write!(f, "}},")?;
        }
        Some(_) => {
            write_hex_u64(f, vtable_address)?;
            f.write_str(" -> { .. },")?;
        }
        None if vtable_address == 0 => f.write_str("0x0,")?,
        None => {
            write_hex_u64(f, vtable_address)?;
            f.write_str(" -> <unreadable>,")?;
        }
    }

    write_record_close(f, pretty, ctx.prefix, ctx.depth)?;
    write!(f, "}}")
}

/// How far past the data pointer the erased value starts: zero for a bare
/// `dyn`, and otherwise the wrappers' sized prefixes laid end to end with
/// each rounded up to the concrete value's alignment — std places every
/// unsized tail that way (`Arc::data_offset` rounds `ArcInner<()>`'s size
/// to `align_of_val`), so `[16]` under an align of 64 is 64, not 16, and
/// `[16, 5]` under 32 is 64, not 32. `None` when a header is in the way
/// and the vtable's align word is missing or not a power of two: no layout
/// was ever computed from such a value, so no offset follows from it.
fn tail_offset(prefixes: &[u64], align: Option<u64>) -> Option<u64> {
    if prefixes.is_empty() {
        return Some(0);
    }
    let align = align.filter(|align| align.is_power_of_two())?;
    prefixes.iter().try_fold(0u64, |offset, prefix| {
        offset.checked_add(*prefix)?.checked_next_multiple_of(align)
    })
}

pub(crate) fn resolve_function_symbol<T: Target>(proc: Option<&T>, address: u64) -> Option<String> {
    if address == 0 {
        return None;
    }
    let symbol = crate::target::function_symbol(proc?, address)?;
    let stripped = hansei_bundle::strip_llvm_suffix(&symbol);
    Some(
        rustc_demangle::try_demangle(stripped)
            .map(|symbol| format!("{symbol:#}"))
            .unwrap_or_else(|_| stripped.to_owned()),
    )
}

/// Punctuation before one field of the dyn-pointer record (or its nested
/// vtable record, one level deeper): a fresh line indented past `depth` in
/// pretty mode, a space inline — every field writes its own trailing comma.
fn write_dyn_field_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    prefix: &str,
    depth: usize,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, prefix, depth + 1)
    } else {
        write!(f, " ")
    }
}

fn read_vtable_words<'a, T: Target>(
    vtable: BundleType<'a>,
    address: u64,
    proc: Option<&T>,
) -> Option<Vec<u64>> {
    if address == 0 {
        return None;
    }
    let (element, count) = vtable.pointer_target()?.array_info()?;
    if element.size() != 8 {
        return None;
    }
    let byte_len = count.checked_mul(8)?;
    let bytes = proc?.read_bytes(address, byte_len).ok()?;
    if bytes.len() != byte_len as usize {
        return None;
    }
    Some(
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect(),
    )
}

/// The concrete type the vtable's function symbols agree on, corroborated
/// against the size word the vtable carries, together with the type that
/// name resolves to where it resolves to exactly one.
///
/// The caller needs both, and a name lookup is not cheap — it compares
/// against every named type in the bundle that shares its hash — so the
/// resolved type answers the size question too: a name that resolves has
/// one id, hence one size. Only a name borne by several ids, which
/// [`type_by_name`](BundleType::type_by_name) declines, still needs asking
/// whether those ids at least agree on a size.
fn infer_concrete_type<'a>(
    ty: BundleType<'a>,
    words: Option<&[u64]>,
    size_slot: u32,
    functions: &[VtableFunction],
) -> Option<(String, Option<BundleType<'a>>)> {
    let mut concrete = functions
        .iter()
        .filter_map(|function| function.concrete.as_deref());
    let candidate = concrete.next()?.to_owned();
    if concrete.any(|other| other != candidate) {
        return None;
    }
    let resolved = ty.type_by_name(&candidate);
    let expected = match resolved {
        Some(resolved) => Some(resolved.size()),
        None => ty.size_by_name(&candidate),
    };
    if let (Some(expected), Some(actual)) = (expected, words?.get(size_slot as usize).copied())
        && expected != actual
    {
        return None;
    }
    Some((candidate, resolved))
}

#[cfg(test)]
mod tests {
    use super::tail_offset;
    use crate::Value;
    use crate::testhelper::*;

    use hansei_bundle::{BundleView, TypeDef};

    #[test]
    fn test_dyn_pointer_formats_unknown_concrete_type() {
        let mem = FakeMem::new().at(0x3000, u64s(&[0x2c557a0, 152, 8]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert_eq!(
            shown,
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1234,\n",
                "    concrete type: <unknown>,\n",
                "    vtable: {\n",
                "        drop_in_place: 0x2c557a0,\n",
                "        size: 152,\n",
                "        align: 8,\n",
                "    },\n",
                "}"
            )
        );
    }

    #[test]
    fn test_dyn_pointer_infers_concrete_type_from_method_with_null_drop() {
        let mem = FakeMem::new()
            .at(0x1234, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0, 8, 8, 0x4000]))
            .symbol(0x4000, "<Point as app::Trait>::run");

        let mut b = test_bundle();
        let TypeDef::Array { count, .. } = &mut b.types.types[VTABLE_ARRAY.0 as usize] else {
            panic!("vtable is not an array");
        };
        *count = 4;
        b.validate().expect("expanded vtable must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert!(
            shown.contains("pointer: 0x1234 -> Point {\n        x: 1,\n        y: 2,\n    },"),
            "{shown}"
        );
        assert!(shown.contains("concrete type: Point,"), "{shown}");
        assert!(shown.contains("drop_in_place: 0x0,"), "{shown}");
        assert!(
            shown.contains("method[3]: 0x4000 -> <Point as app::Trait>::run,"),
            "{shown}"
        );
    }

    /// An `Arc<dyn Trait>`'s data pointer targets `ArcInner`, whose two
    /// refcount words DWARF places the value after, at 16 — but std puts
    /// it at that prefix rounded up to the concrete type's alignment, so
    /// a 64-aligned `Point` sits at +64 and the bytes at +16 are padding.
    #[test]
    fn test_wrapped_dyn_pointee_starts_at_the_alignment_multiple() {
        let mem = FakeMem::new()
            .at(0x1010, u32s(&[9, 9]))
            .at(0x1040, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0x4000, 8, 64]))
            .symbol(0x4000, "<Point as app::Trait>::drop");

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1000, 0x3000]);
        let value = Value::new(v.ty(ARC_DYN_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert!(
            shown.contains("pointer: 0x1000 -> Point {\n        x: 1,\n        y: 2,\n    },"),
            "{shown}"
        );
        assert!(shown.contains("align: 64,"), "{shown}");
    }

    /// Under an alignment the header already satisfies, the prefix is the
    /// offset: a word-aligned value starts right after the refcounts.
    #[test]
    fn test_wrapped_dyn_pointee_under_a_small_alignment_follows_the_header() {
        let mem = FakeMem::new()
            .at(0x1010, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0x4000, 8, 8]))
            .symbol(0x4000, "<Point as app::Trait>::drop");

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1000, 0x3000]);
        let value = Value::new(v.ty(ARC_DYN_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert!(
            shown.contains("pointer: 0x1000 -> Point {\n        x: 1,\n        y: 2,\n    },"),
            "{shown}"
        );
    }

    /// Two wrappers round twice: Arc's 16 goes to 32 under a 32-aligned
    /// value, and the Mutex's 5 on top of that goes to 64. Rounding the
    /// summed prefixes once (21 → 32) would read the Mutex's own header
    /// as the value; under an alignment of 8 the same fold lands at 24.
    #[test]
    fn test_nested_wrappers_round_at_every_level() {
        let show = |align: u64, mem: FakeMem| {
            let mem = mem
                .at(0x3000, u64s(&[0x4000, 8, align]))
                .symbol(0x4000, "<Point as app::Trait>::drop");
            let b = test_bundle();
            let v = BundleView::new(&b);
            let bytes = u64s(&[0x1000, 0x3000]);
            let value = Value::new(v.ty(ARC_MUTEX_DYN_PTR).unwrap(), 0, &bytes);
            format!("{}", value.display_from_target(&mem, 8))
        };

        let wide = show(
            32,
            FakeMem::new()
                .at(0x1020, u32s(&[9, 9]))
                .at(0x1040, u32s(&[1, 2])),
        );
        assert!(
            wide.contains("pointer: 0x1000 -> Point { x: 1, y: 2 },"),
            "{wide}"
        );

        let narrow = show(8, FakeMem::new().at(0x1018, u32s(&[3, 4])));
        assert!(
            narrow.contains("pointer: 0x1000 -> Point { x: 3, y: 4 },"),
            "{narrow}"
        );
    }

    /// A vtable whose align word is not a power of two places nothing
    /// behind a header: the pointee is not read from a guessed offset,
    /// and the record says why. A bare dyn pointee has no header to
    /// place, so the same word costs it nothing.
    #[test]
    fn test_wrapped_dyn_pointee_declines_a_vtable_align_that_is_no_alignment() {
        let mem = FakeMem::new()
            .at(0x1000, u32s(&[1, 2]))
            .at(0x1010, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0x4000, 8, 3]))
            .symbol(0x4000, "<Point as app::Trait>::drop");

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1000, 0x3000]);

        let wrapped = Value::new(v.ty(ARC_DYN_PTR).unwrap(), 0, &bytes);
        let shown = format!("{}", wrapped.display_from_target(&mem, 8));
        assert!(
            shown.contains("pointer: 0x1000 -> <vtable align 3 is not a power of two>,"),
            "{shown}"
        );
        assert!(shown.contains("concrete type: Point,"), "{shown}");

        let bare = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{}", bare.display_from_target(&mem, 8));
        assert!(
            shown.contains("pointer: 0x1000 -> Point { x: 1, y: 2 },"),
            "{shown}"
        );
    }

    /// A pointee that holds the same wide pointer is followed once: the
    /// second visit to that address as that type is the cycle marker, not
    /// a descent the depth budget has to cut.
    #[test]
    fn test_wrapped_dyn_pointee_that_points_back_at_itself_is_a_cycle() {
        let mem = FakeMem::new()
            .at(0x1040, u64s(&[0x1000, 0x3000]))
            .at(0x3000, u64s(&[0x4000, 16, 64]))
            .symbol(0x4000, "<SelfRef as app::Trait>::drop");

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1000, 0x3000]);
        let value = Value::new(v.ty(ARC_DYN_PTR).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&mem, 8));
        assert!(
            shown.contains(
                "pointer: 0x1000 -> SelfRef { back: ArcDynPtr { pointer: 0x1000 -> <cycle>,"
            ),
            "{shown}"
        );
        assert_eq!(shown.matches("SelfRef {").count(), 1, "{shown}");
    }

    /// The fold behind the reads above, at the values the fixtures cannot
    /// spell: no prefixes need no alignment, a missing or zero align word
    /// places nothing, and an offset that overflows is no offset.
    #[test]
    fn test_tail_offset_rounds_each_prefix_to_the_alignment() {
        assert_eq!(tail_offset(&[], None), Some(0));
        assert_eq!(tail_offset(&[], Some(3)), Some(0));
        assert_eq!(tail_offset(&[16], Some(1)), Some(16));
        assert_eq!(tail_offset(&[16], Some(8)), Some(16));
        assert_eq!(tail_offset(&[16], Some(16)), Some(16));
        assert_eq!(tail_offset(&[16], Some(32)), Some(32));
        assert_eq!(tail_offset(&[16], Some(64)), Some(64));
        assert_eq!(tail_offset(&[16, 5], Some(1)), Some(21));
        assert_eq!(tail_offset(&[16, 5], Some(8)), Some(24));
        assert_eq!(tail_offset(&[16, 5], Some(32)), Some(64));
        assert_eq!(tail_offset(&[16], None), None);
        assert_eq!(tail_offset(&[16], Some(0)), None);
        assert_eq!(tail_offset(&[16], Some(3)), None);
        assert_eq!(tail_offset(&[u64::MAX], Some(8)), None);
        assert_eq!(tail_offset(&[u64::MAX - 6], Some(8)), None);
    }

    /// A null vtable word and a nonzero one nothing can read are different
    /// findings, and each keeps its own spelling.
    #[test]
    fn test_dyn_pointer_distinguishes_null_and_unreadable_vtables() {
        let mem = FakeMem::new();

        let b = test_bundle();
        let v = BundleView::new(&b);
        let show = |vtable: u64| {
            let bytes = u64s(&[0x1234, vtable]);
            let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
            format!("{:#}", value.display_from_target(&mem, 8))
        };

        assert_eq!(
            show(0),
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1234,\n",
                "    concrete type: <unknown>,\n",
                "    vtable: 0x0,\n",
                "}"
            )
        );
        assert_eq!(
            show(0x3000),
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1234,\n",
                "    concrete type: <unknown>,\n",
                "    vtable: 0x3000 -> <unreadable>,\n",
                "}"
            )
        );
    }

    /// The size and align words are data, not code: a function symbol that
    /// happens to sit at the address they spell must not enter the method
    /// list or sway concrete-type inference.
    #[test]
    fn test_vtable_size_and_align_slots_never_resolve_as_methods() {
        let mem = FakeMem::new()
            .at(0x1000, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0, 8, 8, 0x4000]))
            .symbol(8, "<Other as app::Trait>::leak")
            .symbol(0x4000, "<Point as app::Trait>::run");

        let mut b = test_bundle();
        let TypeDef::Array { count, .. } = &mut b.types.types[VTABLE_ARRAY.0 as usize] else {
            panic!("vtable is not an array");
        };
        *count = 4;
        b.validate().expect("expanded vtable must validate");
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1000, 0x3000]);
        let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        // A disagreeing "concrete type" leaked from the size/align words
        // would turn the inferred `Point` into `<unknown>` and drop the
        // pointee; the full expected text also pins the method line's
        // one-deeper indentation.
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8)),
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1000 -> Point {\n",
                "        x: 1,\n",
                "        y: 2,\n",
                "    },\n",
                "    concrete type: Point,\n",
                "    vtable: {\n",
                "        drop_in_place: 0x0,\n",
                "        size: 8,\n",
                "        align: 8,\n",
                "        method[3]: 0x4000 -> <Point as app::Trait>::run,\n",
                "    },\n",
                "}"
            )
        );
    }

    /// A pointee elided at the depth budget keeps its typed placeholder
    /// but not the `@` address suffix: the pointer render just printed
    /// that address ahead of its `->`, and saying it twice on one line
    /// says nothing new.
    #[test]
    fn test_elided_pointee_does_not_repeat_the_pointer_address() {
        let mem = FakeMem::new()
            .at(0x1000, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0x4000, 8, 8]))
            .symbol(0x4000, "<Point as app::Trait>::drop");

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1000, 0x3000]);
        let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 1)),
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1000 -> Point { .. },\n",
                "    concrete type: Point,\n",
                "    vtable: 0x3000 -> { .. },\n",
                "}"
            )
        );
    }

    /// One depth step below the budget the vtable is elided to its address,
    /// not expanded — the boundary is `depth + 1`, the level its record
    /// would render at.
    #[test]
    fn test_dyn_pointer_collapses_the_vtable_at_the_depth_budget() {
        let mem = FakeMem::new().at(0x3000, u64s(&[0x2c557a0, 152, 8]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u64s(&[0x1234, 0x3000]);
        let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 1)),
            concat!(
                "FatPtr {\n",
                "    pointer: 0x1234,\n",
                "    concrete type: <unknown>,\n",
                "    vtable: 0x3000 -> { .. },\n",
                "}"
            )
        );
    }

    #[test]
    fn test_dyn_pointer_format_is_preserved_in_enum_payload() {
        let mem = FakeMem::new().at(0x3000, u64s(&[0, 8, 8]));

        let mut b = test_bundle();
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 16;
        shape.variants[1].payload.ty = FAT_PTR;
        b.validate().expect("modified enum bundle must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = Value::new(v.ty(OPT).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert!(shown.starts_with("Opt::Some {"), "{shown}");
        assert!(!shown.contains("FatPtr"), "{shown}");
        assert!(shown.contains("concrete type: <unknown>,"), "{shown}");
    }
}

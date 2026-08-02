//! Trait-object rendering: display a `dyn Trait` data pointer and its vtable,
//! recovering the concrete type from a vtable function symbol where possible.

use crate::debug_type::{DebugType, DisplayNode};
use crate::target::ReadFromProc;
use crate::value::TypeInfoRef;

use std::fmt;

use super::scalar::read_u64_at;
use super::{DisplayRecurse, RenderCtx, write_indent};

#[derive(Debug)]
struct VtableFunction {
    slot: u32,
    display: String,
    concrete: Option<String>,
}

pub(crate) fn eval_dyn_pointer<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    ty: T,
    name: Option<&str>,
    node: &DisplayNode<T>,
    bytes: &[u8],
    ctx: RenderCtx<'_, 'a, T>,
) -> fmt::Result {
    let DisplayNode::DynPointer {
        pointer_offset,
        vtable,
        vtable_offset,
        drop_in_place: drop_in_place_slot,
        size: size_slot,
        align: align_slot,
        tail_offset,
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
            let concrete =
                exegesis::symbols::concrete_type_from_vtable_symbol(&display).map(str::to_owned);
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
    let pretty = f.alternate();
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        write!(f, "{name}")?;
    }
    write!(f, " {{")?;

    write_dyn_field_prefix(f, pretty, ctx.depth)?;
    write!(f, "pointer: 0x{pointer_address:x}")?;
    // The vtable resolves the erased *tail* type; when the pointer targets an
    // unsized wrapper (e.g. `ArcInner<dyn Trait>`) the value lives past a
    // sized header, so read the pointee at the tail offset, not the raw
    // pointer.
    let pointee_address = pointer_address.wrapping_add(*tail_offset);
    // A zero-sized concrete type (e.g. slog's `()` list terminator) has no
    // pointee worth following — the `concrete type:` line below already names
    // it. Showing `-> ()` would only add noise.
    if let (Some(concrete_ty), Some(proc), Some(visited)) = (
        concrete_ty.filter(|ty| ty.size() > 0),
        ctx.proc,
        ctx.visited,
    ) {
        let key = (pointee_address, concrete_ty.name());
        if !visited.borrow_mut().insert(key) {
            write!(f, " -> <cycle>")?;
        } else {
            match proc.read_bytes(pointee_address, concrete_ty.size()) {
                Ok(pointee_bytes) => {
                    let pointee = DisplayRecurse {
                        info: TypeInfoRef {
                            ty: concrete_ty,
                            addr: pointee_address,
                            bytes: &pointee_bytes,
                            _marker: std::marker::PhantomData,
                        },
                        ctx: ctx.deeper(),
                    };
                    if pretty {
                        write!(f, " -> {pointee:#}")?;
                    } else {
                        write!(f, " -> {pointee}")?;
                    }
                }
                Err(_) => write!(f, " -> <unreadable>")?,
            }
            visited.borrow_mut().remove(&key);
        }
    }
    write!(f, ",")?;
    write_dyn_field_prefix(f, pretty, ctx.depth)?;
    write!(
        f,
        "concrete type: {},",
        concrete.as_deref().unwrap_or("<unknown>")
    )?;
    write_dyn_field_prefix(f, pretty, ctx.depth)?;
    write!(f, "vtable: ")?;

    match words.as_deref() {
        Some(words) if ctx.depth + 1 < ctx.max_depth => {
            write!(f, "{{")?;
            write_vtable_field_prefix(f, pretty, ctx.depth)?;
            let drop_address = words
                .get(*drop_in_place_slot as usize)
                .copied()
                .unwrap_or(0);
            write!(f, "drop_in_place: 0x{drop_address:x}")?;
            if let Some(function) = functions
                .iter()
                .find(|function| function.slot == *drop_in_place_slot)
            {
                write!(f, " -> {}", function.display)?;
            }
            write!(f, ",")?;

            write_vtable_field_prefix(f, pretty, ctx.depth)?;
            match words.get(*size_slot as usize) {
                Some(size) => write!(f, "size: {size},")?,
                None => write!(f, "size: <unavailable>,")?,
            }
            write_vtable_field_prefix(f, pretty, ctx.depth)?;
            match words.get(*align_slot as usize) {
                Some(align) => write!(f, "align: {align},")?,
                None => write!(f, "align: <unavailable>,")?,
            }

            for (slot, &address) in words.iter().enumerate() {
                let slot = slot as u32;
                if slot == *drop_in_place_slot || slot == *size_slot || slot == *align_slot {
                    continue;
                }
                write_vtable_field_prefix(f, pretty, ctx.depth)?;
                if let Some(function) = functions.iter().find(|function| function.slot == slot) {
                    write!(f, "method[{slot}]: 0x{address:x} -> {},", function.display)?;
                } else {
                    write!(f, "entry[{slot}]: 0x{address:016x},")?;
                }
            }

            if pretty {
                writeln!(f)?;
                write_indent(f, ctx.depth + 1)?;
            } else {
                write!(f, " ")?;
            }
            write!(f, "}},")?;
        }
        Some(_) => write!(f, "0x{vtable_address:x} -> ...,")?,
        None if vtable_address == 0 => write!(f, "0x0,")?,
        None => write!(f, "0x{vtable_address:x} -> <unreadable>,")?,
    }

    if pretty {
        writeln!(f)?;
        write_indent(f, ctx.depth)?;
    } else {
        write!(f, " ")?;
    }
    write!(f, "}}")
}

pub(crate) fn resolve_function_symbol(
    proc: Option<&dyn ReadFromProc>,
    address: u64,
) -> Option<String> {
    if address == 0 {
        return None;
    }
    let symbol = proc?.function_symbol(address)?;
    let stripped = exegesis::bundle::strip_llvm_suffix(&symbol);
    Some(
        rustc_demangle::try_demangle(stripped)
            .map(|symbol| format!("{symbol:#}"))
            .unwrap_or_else(|_| stripped.to_owned()),
    )
}

fn write_dyn_field_prefix(f: &mut fmt::Formatter<'_>, pretty: bool, depth: usize) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 1)
    } else {
        write!(f, " ")
    }
}

fn write_vtable_field_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 2)
    } else {
        write!(f, " ")
    }
}

fn read_vtable_words<'a, T: DebugType<'a>>(
    vtable: T,
    address: u64,
    proc: Option<&dyn ReadFromProc>,
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
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
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
/// [`type_by_name`](DebugType::type_by_name) declines, still needs asking
/// whether those ids at least agree on a size.
fn infer_concrete_type<'a, T: DebugType<'a>>(
    ty: T,
    words: Option<&[u64]>,
    size_slot: u32,
    functions: &[VtableFunction],
) -> Option<(String, Option<T>)> {
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
    use crate::TypeInfoRef;
    use crate::testhelper::*;

    use exegesis::bundle::{BundleView, TypeDef};

    #[test]
    fn test_dyn_pointer_formats_unknown_concrete_type() {
        let mem = FakeMem::new().at(0x3000, u64s(&[0x2c557a0, 152, 8]));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
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
        let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
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
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&mem, 8));
        assert!(shown.starts_with("Opt::Some {"), "{shown}");
        assert!(!shown.contains("FatPtr"), "{shown}");
        assert!(shown.contains("concrete type: <unknown>,"), "{shown}");
    }
}

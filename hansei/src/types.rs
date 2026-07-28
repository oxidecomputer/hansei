//! Type lookup against the bundle.
//!
//! Every value hansei prints was decoded with a layout the bundle
//! recorded, so when a rendering looks wrong the next question is what
//! that layout actually says. These two commands answer it: find a type
//! by part of its name, then print its definition — the same members,
//! offsets and variants the walk navigates by.

use anyhow::{Result, bail};
use exegesis::bundle::{BundleType, BundleView, DiscrValue, TypeDef, VariantDef, variant_name};

use std::io;

/// Print the definition of every type named exactly `name`.
///
/// One name can have several definitions: identical instantiations
/// emitted by different compilation units are recorded per id, and a
/// name that resolves to more than one layout is worth seeing in full.
pub fn describe(view: &BundleView<'_>, name: &str, out: &mut dyn io::Write) -> Result<()> {
    let matches: Vec<BundleType<'_>> = view
        .named_types()
        .filter(|(n, _)| *n == name)
        .map(|(_, ty)| ty)
        .collect();
    if matches.is_empty() {
        bail!("the bundle records no type named {name}; try `find-types {name}`");
    }
    for (i, ty) in matches.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
            writeln!(out, "(definition {} of {})", i + 1, matches.len())?;
        }
        definition(*ty, out)?;
    }
    Ok(())
}

/// List the names containing `needle`, one per line.
pub fn find(view: &BundleView<'_>, needle: &str, out: &mut dyn io::Write) -> Result<()> {
    // The index is sorted by name, so repeated definitions of one name
    // arrive together and collapse into a single line.
    let mut count = 0usize;
    let mut previous: Option<(&str, usize)> = None;
    for (name, _) in view.named_types().filter(|(n, _)| n.contains(needle)) {
        match &mut previous {
            Some((seen, definitions)) if *seen == name => *definitions += 1,
            _ => {
                if let Some((seen, definitions)) = previous {
                    write_name(out, seen, definitions)?;
                }
                previous = Some((name, 1));
                count += 1;
            }
        }
    }
    if let Some((seen, definitions)) = previous {
        write_name(out, seen, definitions)?;
    }
    match count {
        1 => writeln!(out, "\n1 type")?,
        n => writeln!(out, "\n{n} types")?,
    }
    Ok(())
}

fn write_name(out: &mut dyn io::Write, name: &str, definitions: usize) -> Result<()> {
    match definitions {
        1 => writeln!(out, "{name}")?,
        n => writeln!(out, "{name}  ({n} definitions)")?,
    }
    Ok(())
}

fn bytes(size: u64) -> String {
    match size {
        1 => "1 byte".to_string(),
        n => format!("{n} bytes"),
    }
}

/// One type's recorded layout.
fn definition(ty: BundleType<'_>, out: &mut dyn io::Write) -> Result<()> {
    match ty.def() {
        TypeDef::Base { encoding, .. } => {
            writeln!(
                out,
                "base {} — {}, {encoding:?}",
                ty.name(),
                bytes(ty.size())
            )?;
        }
        TypeDef::Pointer { .. } => {
            writeln!(out, "pointer {}", label(ty))?;
        }
        TypeDef::Array { .. } => {
            writeln!(out, "array {} — {}", label(ty), bytes(ty.size()))?;
        }
        TypeDef::Struct { .. } | TypeDef::Union { .. } => {
            let kind = if matches!(ty.def(), TypeDef::Union { .. }) {
                "union"
            } else {
                "struct"
            };
            writeln!(out, "{kind} {} — {}", ty.name(), bytes(ty.size()))?;
            // In layout order rather than declaration order: this is a
            // view of memory, and rustc reorders fields freely.
            let mut members: Vec<_> = ty.members().collect();
            members.sort_by_key(|m| m.offset());
            let width = members
                .iter()
                .map(|m| m.name().len())
                .max()
                .unwrap_or_default();
            for m in members {
                writeln!(
                    out,
                    "  +{:<6} {:<width$}  {}",
                    m.offset(),
                    m.name(),
                    label(m.ty())
                )?;
            }
        }
        TypeDef::Enum { .. } => {
            writeln!(out, "enum {} — {}", ty.name(), bytes(ty.size()))?;
            enum_variants(ty, out)?;
        }
        TypeDef::CEnum { enumerators, .. } => {
            writeln!(out, "c-enum {} — {}", ty.name(), bytes(ty.size()))?;
            for (name, value) in enumerators {
                writeln!(out, "  {} = {value}", ty.resolve_str(*name))?;
            }
        }
        TypeDef::Opaque { size, .. } => {
            let size = match size {
                Some(size) => bytes(*size),
                None => "size unknown".to_string(),
            };
            writeln!(out, "opaque {} — {size}", ty.name())?;
            writeln!(out, "  (the extractor could not model this type)")?;
        }
    }

    // What the value renderer does with this type, when it does anything
    // beyond walking the members above.
    if let Some(format) = ty.debug_format() {
        writeln!(out, "  formatter: {format:?}")?;
    }
    Ok(())
}

/// An enum's discriminant and the variants it selects, with the source
/// line rustc recorded for each — which for a coroutine's `SuspendN`
/// states is the await point itself.
fn enum_variants(ty: BundleType<'_>, out: &mut dyn io::Write) -> Result<()> {
    let Some(shape) = ty.variant_shape() else {
        return Ok(());
    };
    match &shape.discr {
        Some(discr) => writeln!(
            out,
            "  discriminant +{}  {}",
            discr.offset,
            label(ty.related_type(discr.ty))
        )?,
        None => writeln!(out, "  no discriminant (single variant)")?,
    }
    let name_of =
        |v: &VariantDef| variant_name(ty.resolve_str(v.name), ty.related_type(v.payload.ty));
    let width = shape
        .variants
        .iter()
        .map(|v| name_of(v).len())
        .max()
        .unwrap_or_default();
    for v in &shape.variants {
        let selector = match &v.discr_values {
            Some(values) => values
                .0
                .iter()
                .map(|value| match value {
                    DiscrValue::Value(x) => x.to_string(),
                    DiscrValue::Range(lo, hi) => format!("{lo}..={hi}"),
                })
                .collect::<Vec<_>>()
                .join(", "),
            // The niche encoding's fallback: everything the other
            // variants did not claim.
            None => "otherwise".to_string(),
        };
        let decl = v
            .decl
            .map(|loc| format!("  — {}:{}", ty.resolve_str(loc.file), loc.line))
            .unwrap_or_default();
        writeln!(
            out,
            "  {:<width$} = {selector:<10} +{:<6} {}{decl}",
            name_of(v),
            v.payload.offset,
            label(ty.related_type(v.payload.ty)),
        )?;
    }
    Ok(())
}

/// How a type reads in a member list. Pointers and arrays are anonymous
/// in the bundle, so they are spelled out from what they point at or
/// hold rather than printed as a placeholder.
fn label(ty: BundleType<'_>) -> String {
    fn go(ty: BundleType<'_>, depth: usize) -> String {
        if depth == 0 {
            return "...".to_string();
        }
        match ty.def() {
            TypeDef::Pointer { name: Some(_), .. } => ty.name().to_string(),
            TypeDef::Pointer { name: None, .. } => match ty.pointer_target() {
                Some(target) => format!("*{}", go(target, depth - 1)),
                None => ty.name().to_string(),
            },
            TypeDef::Array { .. } => match ty.array_info() {
                Some((elem, count)) => format!("[{}; {count}]", go(elem, depth - 1)),
                None => ty.name().to_string(),
            },
            _ => ty.name().to_string(),
        }
    }
    go(ty, 8)
}

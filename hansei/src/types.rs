//! Type lookup against the bundle.
//!
//! Every value hansei prints was decoded with a layout the bundle
//! recorded, so when a rendering looks wrong the next question is what
//! that layout actually says. These two commands answer it: find a type
//! by part of its name, then print its definition — the same members,
//! offsets and variants the walk navigates by, and on request the
//! layout of everything that definition in turn names, nested under the
//! line that names it.

use anyhow::{Result, bail};
use exegesis::bundle::{
    BundleType, BundleTypeId, BundleView, DiscrValue, TypeDef, VariantDef, variant_name,
};

use std::io;

/// What stands in for a type that is already open further up the same
/// path: a list's node reaches itself, and its layout is the one being
/// read at the time.
const DESCRIBED_ABOVE: &str = "(described above)";

/// What marks a line the nesting has more to say below but `--depth`
/// stops it at. It goes on the line itself rather than on one of its
/// own: at the depth every second line would carry a note otherwise.
const MORE_BELOW: &str = " …";

/// Whether a rendering follows what a layout names, how far, and what
/// it has open above the line it is writing.
struct Nesting {
    follow: bool,
    /// How many types may be open below the root at once.
    depth: usize,
    /// The ids open on the path down from the root — so also how deep
    /// that path is. A type reaches itself only across a pointer — a
    /// list node holding a `*Node` — and without this the nesting
    /// would go on until the stack ran out.
    open: Vec<BundleTypeId>,
}

impl Nesting {
    /// Whether following what a line names is what would come next,
    /// but this rendering has followed as deep as it may.
    fn stops_at(&self, ty: BundleType<'_>) -> bool {
        self.follow
            && self.open.len() > self.depth
            && reach(ty).is_some_and(|(target, _)| has_body(target))
    }
}

/// Print the definition of every type named exactly `name`, following
/// what each definition names `depth` types deep when `recursive`.
///
/// One name can have several definitions: identical instantiations
/// emitted by different compilation units are recorded per id, and a
/// name that resolves to more than one layout is worth seeing in full.
pub fn describe(
    view: &BundleView<'_>,
    name: &str,
    recursive: bool,
    depth: usize,
    out: &mut dyn io::Write,
) -> Result<()> {
    let matches: Vec<BundleType<'_>> = view
        .named_types()
        .filter(|(n, _)| *n == name)
        .map(|(_, ty)| ty)
        .collect();
    if matches.is_empty() {
        bail!("the bundle records no type named {name}; try `find-types {name}`");
    }
    let mut nesting = Nesting {
        follow: recursive,
        depth,
        open: Vec::new(),
    };
    for (i, ty) in matches.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
            writeln!(out, "(definition {} of {})", i + 1, matches.len())?;
        }
        definition(*ty, 0, &mut nesting, out)?;
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

/// One type's recorded layout: what it is, then what it holds.
fn definition(
    ty: BundleType<'_>,
    indent: usize,
    nesting: &mut Nesting,
    out: &mut dyn io::Write,
) -> Result<()> {
    writeln!(out, "{:indent$}{}", "", heading(ty))?;
    open(ty, indent + 2, nesting, out)
}

/// The line a definition opens with: the kind, the name, and the extent.
fn heading(ty: BundleType<'_>) -> String {
    match ty.def() {
        TypeDef::Base { encoding, .. } => {
            format!("base {} — {}, {encoding:?}", ty.name(), bytes(ty.size()))
        }
        TypeDef::Pointer { .. } => format!("pointer {}", label(ty)),
        TypeDef::Array { .. } => format!("array {} — {}", label(ty), bytes(ty.size())),
        TypeDef::Struct { .. } => format!("struct {} — {}", ty.name(), bytes(ty.size())),
        TypeDef::Union { .. } => format!("union {} — {}", ty.name(), bytes(ty.size())),
        TypeDef::Enum { .. } => format!("enum {} — {}", ty.name(), bytes(ty.size())),
        TypeDef::CEnum { .. } => format!("c-enum {} — {}", ty.name(), bytes(ty.size())),
        TypeDef::Opaque { size, .. } => {
            let size = match size {
                Some(size) => bytes(*size),
                None => "size unknown".to_string(),
            };
            format!("opaque {} — {size}", ty.name())
        }
    }
}

/// Describe what `ty` holds, unless it is already open above — which is
/// where a type that reaches itself stops.
fn open(
    ty: BundleType<'_>,
    indent: usize,
    nesting: &mut Nesting,
    out: &mut dyn io::Write,
) -> Result<()> {
    if nesting.open.contains(&ty.id()) {
        writeln!(out, "{:indent$}{DESCRIBED_ABOVE}", "")?;
        return Ok(());
    }
    nesting.open.push(ty.id());
    let described = body(ty, indent, nesting, out);
    nesting.open.pop();
    described
}

/// What a type holds, at `indent`: its members, its variants, or the
/// note that it holds nothing this tool can say anything about.
fn body(
    ty: BundleType<'_>,
    indent: usize,
    nesting: &mut Nesting,
    out: &mut dyn io::Write,
) -> Result<()> {
    match ty.def() {
        TypeDef::Base { .. } => {}
        // Anonymous, and already spelled out by `label` wherever they
        // are named, so there is nothing to say but what they address.
        TypeDef::Pointer { .. } | TypeDef::Array { .. } => follow(ty, indent, nesting, out)?,
        TypeDef::Struct { .. } | TypeDef::Union { .. } => members(ty, indent, nesting, out)?,
        TypeDef::Enum { .. } => enum_variants(ty, indent, nesting, out)?,
        TypeDef::CEnum { enumerators, .. } => {
            for (name, value) in enumerators {
                writeln!(out, "{:indent$}{} = {value}", "", ty.resolve_str(*name))?;
            }
        }
        TypeDef::Opaque { .. } => {
            writeln!(
                out,
                "{:indent$}(the extractor could not model this type)",
                ""
            )?;
        }
    }
    Ok(())
}

/// A struct's or union's members, each followed by what its type holds.
fn members(
    ty: BundleType<'_>,
    indent: usize,
    nesting: &mut Nesting,
    out: &mut dyn io::Write,
) -> Result<()> {
    // In layout order rather than declaration order: this is a view of
    // memory, and rustc reorders fields freely.
    let mut members: Vec<_> = ty.members().collect();
    members.sort_by_key(|m| m.offset());
    let width = members
        .iter()
        .map(|m| m.name().len())
        .max()
        .unwrap_or_default();
    for m in members {
        let more = if nesting.stops_at(m.ty()) {
            MORE_BELOW
        } else {
            ""
        };
        writeln!(
            out,
            "{:indent$}+{:<6} {:<width$}  {}{more}",
            "",
            m.offset(),
            m.name(),
            label(m.ty())
        )?;
        follow(m.ty(), indent + 2, nesting, out)?;
    }
    Ok(())
}

/// An enum's discriminant and the variants it selects, with the source
/// line rustc recorded for each — which for a coroutine's `SuspendN`
/// states is the await point itself — and what each variant holds.
fn enum_variants(
    ty: BundleType<'_>,
    indent: usize,
    nesting: &mut Nesting,
    out: &mut dyn io::Write,
) -> Result<()> {
    let Some(shape) = ty.variant_shape() else {
        return Ok(());
    };
    match &shape.discr {
        Some(discr) => writeln!(
            out,
            "{:indent$}discriminant +{}  {}",
            "",
            discr.offset,
            label(ty.related_type(discr.ty))
        )?,
        None => writeln!(out, "{:indent$}no discriminant (single variant)", "")?,
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
        let payload = ty.related_type(v.payload.ty);
        let more = if nesting.stops_at(payload) {
            MORE_BELOW
        } else {
            ""
        };
        writeln!(
            out,
            "{:indent$}{:<width$} = {selector:<10} +{:<6} {}{more}{decl}",
            "",
            name_of(v),
            v.payload.offset,
            label(payload),
        )?;
        follow(payload, indent + 2, nesting, out)?;
    }
    Ok(())
}

/// Nest the layout of what a line just named beneath that line.
fn follow(
    ty: BundleType<'_>,
    indent: usize,
    nesting: &mut Nesting,
    out: &mut dyn io::Write,
) -> Result<()> {
    // The line above carries the mark that says what is not written
    // here, so there is nothing left to write.
    if !nesting.follow || nesting.open.len() > nesting.depth {
        return Ok(());
    }
    let Some((target, crossed)) = reach(ty) else {
        return Ok(());
    };
    if !crossed {
        // The line above named it and its bytes are part of the ones
        // being described, so its members carry straight on below, at
        // offsets that go on counting from that line's.
        return open(target, indent, nesting, out);
    }
    // A pointer, or an array element, addresses a frame of its own: the
    // offsets below start again from nothing there, so what they belong
    // to is named on a line of its own rather than read as more of the
    // line above.
    let described = nesting.open.contains(&target.id());
    let note = if described {
        format!("  {DESCRIBED_ABOVE}")
    } else {
        String::new()
    };
    writeln!(out, "{:indent$}→ {}{note}", "", heading(target))?;
    if described {
        return Ok(());
    }
    open(target, indent + 2, nesting, out)
}

/// The type whose layout belongs under a line that named `ty`, and
/// whether reaching it left the bytes that line accounts for.
///
/// A base type is left to the line that named it — `count  u32` says
/// everything a definition of `u32` would — and a pointer and an array
/// are anonymous, so what goes below them is what they address: the
/// pointee, or one array element.
fn reach(ty: BundleType<'_>) -> Option<(BundleType<'_>, bool)> {
    let mut ty = ty;
    // Bounded like `label`'s walk and for the same reason: a chain of
    // pointers to pointers is finite, but nothing here says how long.
    for hop in 0..8 {
        if has_layout(ty) {
            return Some((ty, hop > 0));
        }
        ty = match ty.def() {
            TypeDef::Pointer { .. } => ty.pointer_target()?,
            TypeDef::Array { .. } => ty.array_info()?.0,
            _ => return None,
        };
    }
    None
}

/// Whether [`body`] writes anything for this type. A `PhantomData` has
/// no members, so the line that named it is its whole layout and there
/// is nothing below to say has been left out.
fn has_body(ty: BundleType<'_>) -> bool {
    match ty.def() {
        TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => !members.is_empty(),
        TypeDef::CEnum { enumerators, .. } => !enumerators.is_empty(),
        TypeDef::Enum { .. } | TypeDef::Opaque { .. } => true,
        TypeDef::Base { .. } | TypeDef::Pointer { .. } | TypeDef::Array { .. } => false,
    }
}

/// Whether describing this type says anything the line that named it
/// did not already.
fn has_layout(ty: BundleType<'_>) -> bool {
    matches!(
        ty.def(),
        TypeDef::Struct { .. }
            | TypeDef::Union { .. }
            | TypeDef::Enum { .. }
            | TypeDef::CEnum { .. }
            // Not a layout, but the one thing worth saying about a
            // member whose type the extractor could not model.
            | TypeDef::Opaque { .. }
    )
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

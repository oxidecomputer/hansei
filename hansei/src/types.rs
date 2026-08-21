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
use hansei_bundle::{
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

#[cfg(test)]
mod tests {
    use super::*;

    use hansei_bundle::Encoding;
    use hansei_bundle::{
        Bundle, DiscrDef, DiscrValues, FORMAT_VERSION, InfraTypes, MemberDef, Meta, StrRef,
        StringInterner, TypeTable, VariantShape,
    };

    /// A bundle exercising every shape the describer renders: a
    /// self-reaching list node, empty and opaque types, a c-enum, a
    /// tagged enum with ranged and fallback selectors, nested arrays
    /// and double pointers, and one name with two definitions.
    fn bundle() -> Bundle {
        let mut strings = StringInterner::new();
        let mut names = std::collections::BTreeMap::new();
        for name in [
            "u64",
            "Node",
            "value",
            "next",
            "Ghost",
            "Wrapper",
            "node",
            "ghost",
            "mystery",
            "color",
            "arr",
            "indirect",
            "Mystery",
            "Color",
            "Red",
            "Green",
            "OptEnum",
            "Unit",
            "None",
            "Some",
            "Many",
            "dup::Type",
            "Pack",
            "nodes",
            "opts",
        ] {
            names.insert(name, strings.intern(name));
        }
        let n = |name: &str| names[name];
        let member = |name: &str, ty: u32, offset: u64| MemberDef {
            name: n(name),
            ty: BundleTypeId(ty),
            offset,
        };
        let variant = |name: &str, values: Option<DiscrValues>, ty: u32| VariantDef {
            name: n(name),
            discr_values: values,
            payload: member(name, ty, 0),
            decl: None,
            await_site: None,
        };
        use hansei_bundle::DiscrValue::{Range, Value};

        let types = vec![
            // 0: u64
            TypeDef::Base {
                name: n("u64"),
                size: 8,
                encoding: Encoding::Unsigned,
            },
            // 1: Node { value: u64, next: *Node } — reaches itself
            TypeDef::Struct {
                name: n("Node"),
                size: 16,
                members: vec![member("value", 0, 0), member("next", 2, 8)],
            },
            // 2: *Node
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(1),
            },
            // 3: Ghost {} — a PhantomData: named, but nothing below
            TypeDef::Struct {
                name: n("Ghost"),
                size: 0,
                members: vec![],
            },
            // 4: Mystery — what the extractor could not model
            TypeDef::Opaque {
                name: n("Mystery"),
                size: None,
            },
            // 5: Color — a c-enum
            TypeDef::CEnum {
                name: n("Color"),
                size: 1,
                repr: BundleTypeId(0),
                enumerators: vec![(n("Red"), 0), (n("Green"), 1)],
            },
            // 6: [u64; 3]
            TypeDef::Array {
                elem: BundleTypeId(0),
                count: 3,
            },
            // 7: **Node
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(2),
            },
            // 8: Unit {}
            TypeDef::Struct {
                name: n("Unit"),
                size: 0,
                members: vec![],
            },
            // 9: OptEnum — explicit, ranged, and fallback selectors
            TypeDef::Enum {
                name: n("OptEnum"),
                size: 16,
                shape: VariantShape {
                    discr: Some(DiscrDef {
                        offset: 8,
                        ty: BundleTypeId(0),
                    }),
                    variants: vec![
                        variant("None", Some(DiscrValues(vec![Value(0)])), 8),
                        variant("Some", Some(DiscrValues(vec![Range(1, 3)])), 0),
                        // A payload with a body of its own, so a
                        // recursive description has something to nest
                        // under a variant row.
                        variant("Many", None, 5),
                    ],
                },
            },
            // 10: Wrapper — one member of every spelling
            TypeDef::Struct {
                name: n("Wrapper"),
                size: 64,
                members: vec![
                    member("node", 1, 0),
                    member("ghost", 3, 16),
                    member("mystery", 4, 16),
                    member("color", 5, 17),
                    member("arr", 6, 24),
                    member("indirect", 7, 48),
                ],
            },
            // 11 and 12: one name, two definitions
            TypeDef::Struct {
                name: n("dup::Type"),
                size: 8,
                members: vec![member("value", 0, 0)],
            },
            TypeDef::Struct {
                name: n("dup::Type"),
                size: 16,
                members: vec![member("value", 0, 8)],
            },
            // 13: [Node; 2] — an array whose element has a layout
            TypeDef::Array {
                elem: BundleTypeId(1),
                count: 2,
            },
            // 14: Pack { nodes: [Node; 2], opts: OptEnum }
            TypeDef::Struct {
                name: n("Pack"),
                size: 48,
                members: vec![member("nodes", 13, 0), member("opts", 9, 32)],
            },
        ];

        let strings = strings.finish();
        let mut name_index: Vec<(StrRef, BundleTypeId)> = types
            .iter()
            .enumerate()
            .filter_map(|(i, def)| {
                let name = match def {
                    TypeDef::Base { name, .. }
                    | TypeDef::Struct { name, .. }
                    | TypeDef::Enum { name, .. }
                    | TypeDef::CEnum { name, .. }
                    | TypeDef::Opaque { name, .. } => *name,
                    TypeDef::Pointer { .. } | TypeDef::Array { .. } => return None,
                    TypeDef::Union { name, .. } => *name,
                };
                Some((name, BundleTypeId(i as u32)))
            })
            .collect();
        name_index.sort_by_key(|(r, _)| strings.get(*r).unwrap().to_string());

        let ty = BundleTypeId(0);
        Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings,
            types: TypeTable {
                types,
                name_index,
                ..Default::default()
            },
            tasks: Default::default(),
            dyn_futures: Default::default(),
            statics: Default::default(),
            walks: Default::default(),
            infra: InfraTypes {
                header: ty,
                vtable: ty,
                trailer: ty,
                context: ty,
                scheduler_handle: ty,
                mt_handle: ty,
                ct_handle: ty,
                location: ty,
                raw_waker_vtable: ty,
            },
            provenance: Default::default(),
        }
    }

    fn described(name: &str, recursive: bool, depth: usize) -> String {
        let bundle = bundle();
        let view = BundleView::new(&bundle);
        let mut out = Vec::new();
        describe(&view, name, recursive, depth, &mut out).expect("describe succeeds");
        String::from_utf8(out).unwrap()
    }

    fn found(needle: &str) -> String {
        let bundle = bundle();
        let view = BundleView::new(&bundle);
        let mut out = Vec::new();
        find(&view, needle, &mut out).expect("find succeeds");
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn test_find_lists_matches_and_counts() {
        let out = found("Node");
        assert!(out.contains("Node\n"), "{out}");
        assert!(out.ends_with("1 type\n"), "{out}");

        // Repeated definitions of one name collapse into one line.
        let out = found("dup");
        assert!(out.contains("dup::Type  (2 definitions)"), "{out}");
        assert!(out.ends_with("1 type\n"), "{out}");

        let out = found("no_such_needle");
        assert!(out.ends_with("0 types\n"), "{out}");

        // An empty needle matches every named type.
        let out = found("");
        assert!(out.contains("Wrapper"), "{out}");
        assert!(out.contains("OptEnum"), "{out}");
    }

    #[test]
    fn test_describe_unknown_name_suggests_find() {
        let bundle = bundle();
        let view = BundleView::new(&bundle);
        let err = describe(&view, "no::such::Type", false, 0, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("find-types"), "{err}");
    }

    #[test]
    fn test_describe_prints_every_definition_of_a_name() {
        let out = described("dup::Type", false, 0);
        assert!(out.contains("(definition 2 of 2)"), "{out}");
        assert_eq!(out.matches("struct dup::Type").count(), 2, "{out}");
    }

    /// A list node reaches itself across its `next` pointer; the second
    /// visit says so instead of recursing until the stack runs out.
    #[test]
    fn test_a_recursive_description_stops_at_a_cycle() {
        let out = described("Node", true, 8);
        // The pointee gets a heading of its own — offsets restart there.
        assert!(out.contains("→ struct Node"), "{out}");
        assert!(out.contains(DESCRIBED_ABOVE), "{out}");
    }

    /// `--depth` stops the nesting and marks the line that has more
    /// below it; a full-depth rendering carries no mark.
    #[test]
    fn test_depth_truncation_marks_the_line() {
        let shallow = described("Wrapper", true, 0);
        assert!(shallow.contains(MORE_BELOW), "{shallow}");
        // Marked on the line naming the nested struct, not followed.
        assert!(!shallow.contains("+8     next"), "{shallow}");

        let deep = described("Wrapper", true, 8);
        assert!(!deep.contains(MORE_BELOW), "{deep}");
        assert!(deep.contains("next"), "{deep}");
    }

    /// A type with nothing below the line that names it — an empty
    /// struct, a base, an array of bases — is never marked as
    /// truncated, while a pointer chain that reaches a layout is: what
    /// `reach` finds decides, not the member's own kind.
    #[test]
    fn test_bodyless_members_carry_no_truncation_mark() {
        let out = described("Wrapper", true, 0);
        for line in out.lines() {
            for bodyless in ["ghost", "value", "arr"] {
                if line.contains(bodyless) {
                    assert!(!line.contains(MORE_BELOW), "{line:?}");
                }
            }
            // A c-enum with enumerators has a body the way a struct
            // with members does, so the cut is marked.
            if line.contains("color") || line.contains("indirect") {
                assert!(line.contains(MORE_BELOW), "{line:?}");
            }
        }
    }

    #[test]
    fn test_cenum_and_opaque_bodies() {
        let out = described("Color", false, 0);
        assert!(out.contains("c-enum Color — 1 byte"), "{out}");
        assert!(out.contains("Red = 0"), "{out}");
        assert!(out.contains("Green = 1"), "{out}");

        let out = described("Mystery", false, 0);
        assert!(out.contains("opaque Mystery — size unknown"), "{out}");
        assert!(out.contains("could not model"), "{out}");
    }

    /// The enum rendering spells each variant's selector the way the
    /// discriminant encodes it: a value, a range, or the niche
    /// fallback's "otherwise".
    #[test]
    fn test_enum_variants_render_their_selectors() {
        let out = described("OptEnum", false, 0);
        assert!(out.contains("discriminant +8"), "{out}");
        assert!(out.contains("= 0 "), "{out}");
        assert!(out.contains("1..=3"), "{out}");
        assert!(out.contains("otherwise"), "{out}");
    }

    /// A member whose type is a struct carries straight on below its
    /// own line; only a crossing — a pointer, an array — earns an arrow
    /// heading. Wrapper holds exactly three: `indirect`'s fresh Node,
    /// that Node's own cyclic `next`, and inline `node`'s cyclic
    /// `next`.
    #[test]
    fn test_only_a_crossing_earns_an_arrow_heading() {
        let out = described("Wrapper", true, 8);
        assert_eq!(out.matches("→ struct Node").count(), 3, "{out}");
    }

    /// A crossed body opens two columns in from the arrow line that
    /// named it: `indirect`'s Node members sit at six spaces, two past
    /// their arrow's four.
    #[test]
    fn test_a_crossed_body_indents_by_two() {
        let out = described("Wrapper", true, 8);
        assert!(
            out.lines()
                .any(|l| l.starts_with("      +0") && l.contains("value")),
            "{out}"
        );
    }

    /// At the depth boundary the root's own members still print
    /// unmarked: the mark belongs to rows that sit below a crossing,
    /// one level too deep to follow.
    #[test]
    fn test_the_depth_boundary_leaves_the_roots_members_unmarked() {
        let out = described("Wrapper", true, 1);
        let node = out
            .lines()
            .find(|l| l.contains("node"))
            .expect("the node member row prints");
        assert!(!node.contains(MORE_BELOW), "{node:?}");
    }

    /// An array member's element is reached like a pointee: the element
    /// type's layout opens beneath an arrow heading of its own.
    #[test]
    fn test_an_array_member_reaches_its_element() {
        let out = described("Pack", true, 8);
        assert!(out.contains("[Node; 2]"), "{out}");
        assert!(out.contains("→ struct Node"), "{out}");
        assert!(out.contains("value"), "{out}");
    }

    /// A variant's payload opens two columns in from its row: the
    /// `Many` payload's enumerators sit at six spaces, two past their
    /// variant rows' four.
    #[test]
    fn test_a_variant_payload_indents_by_two() {
        let out = described("Pack", true, 8);
        assert!(out.contains("\n      Red = 0\n"), "{out}");
    }

    /// Pointers and arrays are anonymous in the bundle; member lines
    /// spell them from what they address.
    #[test]
    fn test_labels_spell_pointers_and_arrays() {
        let out = described("Wrapper", false, 0);
        assert!(out.contains("[u64; 3]"), "{out}");
        assert!(out.contains("**Node"), "{out}");

        let out = described("Node", false, 0);
        assert!(out.contains("*Node"), "{out}");
    }
}

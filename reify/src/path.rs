//! Member/element paths into a value: the resolver behind `print`'s
//! path grammar.
//!
//! A path is a sequence of [`Step`]s applied to a root [`Value`]:
//! `.member` navigates structure the way Rust's `.` does — through a
//! reference, a `Box`, an `Arc`/`Rc` header, a `Pin`, a `NonNull`, a
//! niched `Option<NonNull>`, and into an enum's active variant —
//! `[N]` and ranges select elements through the same formatter walks
//! the renderer uses, and `*` dereferences explicitly, the only way
//! through a raw pointer the auto-deref would not follow on its own.
//! A range fans out: every following step applies to each selected
//! element, and the result is a list labeled `[i]` per element.

use crate::debug_type::{DisplayNode, TypeKind};
use crate::render::collections::{MapWalkError, walk_map_entries};
use crate::render::scalar::read_unsigned_at;
use crate::render::{FormatCache, RenderCtx};
use crate::value::Value;
use crate::{Error, Result};

use proc::Target;

/// One step of a parsed path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// `.name`: a struct, tuple (`.0`), or enum-variant member.
    Member(String),
    /// `[N]`: the `N`th element, or for a map the `N`th entry in the
    /// formatter's iteration order.
    Index(u64),
    /// `[a..b]`, `[a..=b]`, `[..b]`, `[a..]`: a run of elements.
    Range {
        start: u64,
        /// `None` runs to the sequence's end.
        end: Option<u64>,
        inclusive: bool,
    },
    /// `*`: an explicit dereference.
    Deref,
}

/// Parse a path — the concatenation of everything after the root —
/// into steps. The grammar is postfix and total: every character
/// belongs to the step opened by the `.`, `[` or `*` before it.
pub fn parse(path: &str) -> Result<Vec<Step>> {
    let err = |why: String| Error::path_syntax(path.to_string(), why);
    let mut steps = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('*') {
            steps.push(Step::Deref);
            rest = r;
        } else if let Some(r) = rest.strip_prefix('.') {
            let end = r.find(['.', '[', '*']).unwrap_or(r.len());
            if end == 0 {
                return Err(err("`.` needs a member name after it".into()));
            }
            steps.push(Step::Member(r[..end].to_string()));
            rest = &r[end..];
        } else if let Some(r) = rest.strip_prefix('[') {
            let Some(end) = r.find(']') else {
                return Err(err("`[` without a closing `]`".into()));
            };
            steps.push(parse_selector(&r[..end]).map_err(err)?);
            rest = &r[end + 1..];
        } else {
            let c = rest.chars().next().expect("rest is not empty");
            return Err(err(format!(
                "a step starts with `.`, `[` or `*`, not `{c}`"
            )));
        }
    }
    Ok(steps)
}

/// Parse the inside of one `[…]`: an index, or a Rust range over
/// element positions.
fn parse_selector(inside: &str) -> std::result::Result<Step, String> {
    let number = |s: &str| -> std::result::Result<u64, String> {
        s.parse()
            .map_err(|_| format!("`{s}` is not an element number in `[{inside}]`"))
    };
    let Some((a, b)) = inside.split_once("..") else {
        return Ok(Step::Index(number(inside)?));
    };
    let (inclusive, b) = match b.strip_prefix('=') {
        Some(b) => (true, b),
        None => (false, b),
    };
    let start = if a.is_empty() { 0 } else { number(a)? };
    let end = match (b.is_empty(), inclusive) {
        (true, true) => return Err(format!("`..=` needs an end in `[{inside}]`")),
        (true, false) => None,
        (false, _) => Some(number(b)?),
    };
    if let Some(end) = end
        && start > end
    {
        return Err(format!("`[{inside}]` starts past its own end"));
    }
    Ok(Step::Range {
        start,
        end,
        inclusive,
    })
}

/// One resolved value: a plain value, or a map entry — a key/value
/// pair with no type of its own, which `.0`/`.1` take apart.
#[derive(Debug)]
pub enum Node<'a> {
    Value(Value<'a>),
    Entry { key: Value<'a>, value: Value<'a> },
}

/// One result of resolving a path: where a range fanned out, `label`
/// carries the `[i]` positions that led here; otherwise it is empty
/// and the result is the single value the path named.
#[derive(Debug)]
pub struct Resolved<'a> {
    pub label: String,
    pub node: Node<'a>,
}

/// Apply `steps` to `root`, reading through `proc` wherever a step
/// crosses a pointer or a buffer. One value in, one out — unless a
/// range fans out, after which every later step applies to each
/// element and the list is the answer.
pub fn resolve<'a, T: Target>(
    proc: &'a T,
    root: Value<'a>,
    steps: &[Step],
) -> Result<Vec<Resolved<'a>>> {
    let mut nodes = vec![Resolved {
        label: String::new(),
        node: Node::Value(root),
    }];
    for step in steps {
        let mut next = Vec::new();
        for r in nodes {
            match step {
                Step::Member(name) => next.push(Resolved {
                    label: r.label,
                    node: member_step(proc, r.node, name)?,
                }),
                Step::Deref => {
                    let Node::Value(v) = r.node else {
                        return Err(Error::entry_step("*"));
                    };
                    next.push(Resolved {
                        label: r.label,
                        node: Node::Value(deref_step(proc, v)?),
                    });
                }
                Step::Index(n) => {
                    let Node::Value(v) = r.node else {
                        return Err(Error::entry_step("[…]"));
                    };
                    next.push(Resolved {
                        label: r.label,
                        node: element_at(proc, &v, *n)?,
                    });
                }
                Step::Range {
                    start,
                    end,
                    inclusive,
                } => {
                    let Node::Value(v) = r.node else {
                        return Err(Error::entry_step("[…]"));
                    };
                    for (i, node) in elements_in(proc, &v, *start, *end, *inclusive)? {
                        next.push(Resolved {
                            label: format!("{}[{i}]", r.label),
                            node,
                        });
                    }
                }
            }
        }
        nodes = next;
    }
    Ok(nodes)
}

/// `.name`, with Rust's auto-deref: while the member is not here,
/// follow what the value is — into an enum's active variant, through
/// a pointer, past an `ArcInner`/`RcBox` header, down one transparent
/// wrapper — and ask again. Bounded so a cyclic pointer chain refuses
/// instead of spinning.
fn member_step<'a, T: Target>(proc: &'a T, node: Node<'a>, name: &str) -> Result<Node<'a>> {
    let v = match node {
        Node::Entry { key, value } => {
            return match name {
                "0" | "__0" => Ok(Node::Value(key)),
                "1" | "__1" => Ok(Node::Value(value)),
                _ => Err(Error::entry_step(&format!(".{name}"))),
            };
        }
        Node::Value(v) => v,
    };
    let mut v = v;
    for _ in 0..32 {
        if let Some(m) = try_member_spellings(&v, name)? {
            return Ok(Node::Value(m));
        }
        match v.ty.kind() {
            TypeKind::Enum => {
                // The name may be a variant's own: the active one
                // answers its payload, an inactive one is refused with
                // the name of the variant that is live instead.
                match v.try_select_variant(name) {
                    Ok(Some(payload)) => return Ok(Node::Value(payload)),
                    Ok(None) => {
                        let active = v.active_variant_raw()?.0;
                        return Err(Error::inactive_variant_member(
                            name.to_string(),
                            active.to_string(),
                        ));
                    }
                    // Not a variant name: descend into the active
                    // variant's payload and look there.
                    Err(_) => {
                        let (_, payload) = v.active_variant()?;
                        v = payload;
                    }
                }
            }
            TypeKind::Pointer => v = v.deref_ptr(proc)?,
            _ => {
                if let Some(data) = heap_header_data(&v)? {
                    v = data;
                } else if let Some(inner) = single_sized_member(&v) {
                    // One wrapper level at a time — a full peel would
                    // skip past the middle layers' own member names.
                    v = inner;
                } else {
                    return Err(no_member_listing(&v, name));
                }
            }
        }
    }
    Err(Error::path_syntax(
        format!(".{name}"),
        "the value never settled after 32 dereferences".to_string(),
    ))
}

/// The names a `.name` step could take next from `node` — what a
/// prompt offers after a trailing `.`. They are the members
/// [`member_step`] would find: the value's own, and, wherever its
/// auto-deref would look further, the ones it would find there — an
/// enum's active variant and its payload's members, a pointer's
/// target's, the data behind a heap header, a transparent wrapper's
/// inner — in that order, each name once. Compiler slots (`__…`) are
/// left out, except a tuple's fields, offered as the `.0` the grammar
/// reads. A value that cannot be followed (an unreadable pointer, an
/// undecodable variant) ends the listing with what was found so far —
/// an enum whose discriminant cannot be read with every variant, any
/// of which could be the live one.
pub fn member_names<T: Target>(proc: &T, node: &Node<'_>) -> Vec<String> {
    let mut v = match node {
        Node::Entry { .. } => return vec!["0".to_string(), "1".to_string()],
        Node::Value(v) => *v,
    };
    let mut names: Vec<String> = Vec::new();
    let offer = |names: &mut Vec<String>, name: String| {
        if !names.contains(&name) {
            names.push(name);
        }
    };
    for _ in 0..32 {
        let tuple = v.ty.name().starts_with('(');
        for m in v.ty.members() {
            match m.name().strip_prefix("__") {
                None => offer(&mut names, m.name().to_string()),
                Some(index) if tuple && index.chars().all(|c| c.is_ascii_digit()) => {
                    offer(&mut names, index.to_string())
                }
                Some(_) => {}
            }
        }
        match v.ty.kind() {
            TypeKind::Enum => match v.active_variant() {
                // Only the live variant: `.name` refuses the others,
                // so offering them would offer what cannot resolve.
                Ok((active, payload)) => {
                    offer(&mut names, active.to_string());
                    v = payload;
                }
                // With no discriminant to read, any of them could be
                // the one.
                Err(_) => {
                    for variant in v.ty.variants() {
                        offer(&mut names, variant.name.to_string());
                    }
                    break;
                }
            },
            TypeKind::Pointer => match v.deref_ptr(proc) {
                Ok(target) => v = target,
                Err(_) => break,
            },
            _ => {
                if let Ok(Some(data)) = heap_header_data(&v) {
                    v = data;
                } else if let Some(inner) = single_sized_member(&v) {
                    v = inner;
                } else {
                    break;
                }
            }
        }
    }
    names
}

/// `.name` against the members the type declares, with the tuple
/// spelling: `.0` reads the `__0` DWARF gives a tuple field.
fn try_member_spellings<'a>(v: &Value<'a>, name: &str) -> Result<Option<Value<'a>>> {
    if let Some(m) = v.try_member(name)? {
        return Ok(Some(m));
    }
    if name.chars().all(|c| c.is_ascii_digit()) {
        return v.try_member(&format!("__{name}"));
    }
    Ok(None)
}

/// The `data`/`value` behind a heap header the auto-deref landed on: a
/// sized `Arc<T>` dereferences to `ArcInner<T> { strong, weak, data }`,
/// and the member the user named lives past the counts.
fn heap_header_data<'a>(v: &Value<'a>) -> Result<Option<Value<'a>>> {
    let name = v.ty.name();
    let inner = if name.starts_with("alloc::sync::ArcInner<") {
        "data"
    } else if name.starts_with("alloc::rc::RcBox<") || name.starts_with("alloc::rc::RcInner<") {
        "value"
    } else {
        return Ok(None);
    };
    v.member(inner).map(Some)
}

/// The single sized member a transparent wrapper descends to — one
/// level, unlike [`Value::peel`], so every layer's own member names
/// get their turn first.
fn single_sized_member<'a>(v: &Value<'a>) -> Option<Value<'a>> {
    if v.ty.kind() != TypeKind::Struct {
        return None;
    }
    let mut sized = v.ty.members().filter(|m| m.ty().size() > 0);
    let (m, None) = (sized.next()?, sized.next()) else {
        return None;
    };
    let start = m.offset() as usize;
    let bytes = v.bytes.get(start..start + m.ty().size() as usize)?;
    Some(Value::new(m.ty(), v.addr + m.offset(), bytes))
}

/// The no-member refusal, naming the members that do exist.
fn no_member_listing(v: &Value<'_>, name: &str) -> Error {
    let members: Vec<&str> = v.ty.members().map(|m| m.name()).collect();
    if members.is_empty() {
        return Error::no_member(v.ty.name().to_string(), name.to_string());
    }
    Error::no_member_of(
        v.ty.name().to_string(),
        name.to_string(),
        members.join(", "),
    )
}

/// `*`: peel, cross an enum wrapper (`Option<NonNull<T>>` is a
/// pointer-sized enum, not a pointer), and dereference — or refuse
/// naming what the value actually is.
fn deref_step<'a, T: Target>(proc: &'a T, v: Value<'a>) -> Result<Value<'a>> {
    let mut v = v.peel();
    for _ in 0..8 {
        match v.ty.kind() {
            TypeKind::Pointer => return v.deref_ptr(proc),
            TypeKind::Enum => v = v.active_variant()?.1,
            _ => break,
        }
    }
    Err(Error::unexpected_type(
        v.ty.kind(),
        TypeKind::Pointer,
        v.ty.name().to_string(),
    ))
}

/// A value's elements, however its container spells them: the map
/// entries a `Map` display program walks, or the sequence
/// [`Value::elements`] reads (a `Vec`, a slice, an inline array).
enum Seq<'a> {
    Elems(crate::Elements<'a>),
    Entries(Vec<(Value<'a>, Value<'a>)>),
}

impl<'a> Seq<'a> {
    fn len(&self) -> u64 {
        match self {
            Seq::Elems(e) => e.len(),
            Seq::Entries(v) => v.len() as u64,
        }
    }

    fn get(&self, i: u64) -> Node<'a> {
        match self {
            Seq::Elems(e) => Node::Value(e.get(i)),
            Seq::Entries(v) => {
                let (key, value) = v[i as usize];
                Node::Entry { key, value }
            }
        }
    }
}

fn seq_of<'a, T: Target>(proc: &'a T, v: &Value<'a>) -> Result<Seq<'a>> {
    let v = v.peel();
    if let Some(DisplayNode::Map {
        length_offset,
        length_size,
        key,
        value,
        entries,
    }) = DisplayNode::resolve(v.ty)
    {
        let claimed = read_unsigned_at(v.bytes, length_offset, u64::from(length_size))
            .ok_or_else(|| Error::invalid_sequence(v.ty.name(), "truncated length"))?;
        let mut collected: Vec<(Value<'a>, Value<'a>)> = Vec::new();
        let formats = FormatCache::default();
        let ctx = RenderCtx::for_walk(proc, &formats);
        let walk = walk_map_entries(
            v.bytes,
            ctx,
            key,
            value,
            &entries,
            &mut |key_addr, key_bytes, value_addr, value_bytes| {
                if collected.len() as u64 == claimed {
                    return Err(MapWalkError::Invalid(
                        "tree contains more entries than length",
                    ));
                }
                collected.push((
                    Value::new(key, key_addr, key_bytes),
                    Value::new(value, value_addr, value_bytes),
                ));
                Ok(())
            },
        );
        if let Err(MapWalkError::Invalid(why) | MapWalkError::Marker(why)) = walk {
            // A cut-off walk still resolves the entries it reached;
            // only an index past them reports why the rest is missing.
            return Ok(Seq::Entries(if collected.is_empty() {
                return Err(Error::invalid_sequence(v.ty.name(), why));
            } else {
                collected
            }));
        }
        return Ok(Seq::Entries(collected));
    }
    v.elements(proc).map(Seq::Elems)
}

/// `[N]`.
fn element_at<'a, T: Target>(proc: &'a T, v: &Value<'a>, n: u64) -> Result<Node<'a>> {
    let seq = seq_of(proc, v)?;
    let len = seq.len();
    if n >= len {
        if let Seq::Elems(e) = &seq
            && let Some(claimed) = e.truncated()
            && n < claimed
        {
            return Err(Error::short_sequence(v.ty.name(), claimed, len));
        }
        return Err(Error::index_past_end(v.ty.name(), n, len));
    }
    Ok(seq.get(n))
}

/// A range of elements, with the positions they came from. Mirrors
/// Rust slicing: an empty range at the boundary is fine, a bound past
/// the length refuses with the length.
fn elements_in<'a, T: Target>(
    proc: &'a T,
    v: &Value<'a>,
    start: u64,
    end: Option<u64>,
    inclusive: bool,
) -> Result<Vec<(u64, Node<'a>)>> {
    let seq = seq_of(proc, v)?;
    let len = seq.len();
    let bound = match (end, inclusive) {
        (None, _) => len,
        (Some(e), false) => e,
        (Some(e), true) => e
            .checked_add(1)
            .ok_or_else(|| Error::index_past_end(v.ty.name(), e, len))?,
    };
    if bound > len || start > len {
        return Err(Error::range_past_end(v.ty.name(), start.max(bound), len));
    }
    Ok((start..bound).map(|i| (i, seq.get(i))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelper::*;

    use hansei_bundle::BundleView;

    /// The single value a path without a range resolves to.
    fn one<'a>(mut r: Vec<Resolved<'a>>) -> Value<'a> {
        assert_eq!(r.len(), 1, "one value expected");
        let r = r.pop().unwrap();
        assert_eq!(r.label, "", "no fan-out label without a range");
        match r.node {
            Node::Value(v) => v,
            Node::Entry { .. } => panic!("a value, not an entry"),
        }
    }

    fn shown(r: Vec<Resolved<'_>>) -> String {
        format!("{}", one(r).display())
    }

    /// Every step form parses; every malformed spelling refuses naming
    /// the path and what went wrong.
    #[test]
    fn test_parse_covers_every_step_and_refusal() {
        assert_eq!(
            parse(".self.config[3][1..4][..2][3..][1..=2][..=5][..]*").expect("parses"),
            vec![
                Step::Member("self".into()),
                Step::Member("config".into()),
                Step::Index(3),
                Step::Range {
                    start: 1,
                    end: Some(4),
                    inclusive: false
                },
                Step::Range {
                    start: 0,
                    end: Some(2),
                    inclusive: false
                },
                Step::Range {
                    start: 3,
                    end: None,
                    inclusive: false
                },
                Step::Range {
                    start: 1,
                    end: Some(2),
                    inclusive: true
                },
                Step::Range {
                    start: 0,
                    end: Some(5),
                    inclusive: true
                },
                Step::Range {
                    start: 0,
                    end: None,
                    inclusive: false
                },
                Step::Deref,
            ]
        );
        assert_eq!(parse("").expect("empty path is no steps"), vec![]);
        for (path, why) in [
            ("x", "starts with"),
            (".a[", "closing"),
            ("[a]", "not an element number"),
            ("[3..=]", "needs an end"),
            ("[4..3]", "starts past its own end"),
            (".", "member name"),
            (".a..b", "member name"),
        ] {
            let err = parse(path).expect_err(path).to_string();
            assert!(err.contains(why), "{path}: {err}");
            assert!(err.contains("cannot parse path"), "{path}: {err}");
        }
    }

    /// `.member` finds a wrapper's own member, descends transparent
    /// wrappers one level at a time, and reads tuples as `.0`/`.1`.
    #[test]
    fn test_member_navigates_wrappers_and_tuples() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();
        let bytes = u32s(&[3, 4]);
        let wrap = Value::new(v.ty(WRAP).unwrap(), 0x100, &bytes);
        // The wrapper's own member, then through it.
        assert_eq!(
            shown(resolve(&mem, wrap, &parse(".inner.x").unwrap()).unwrap()),
            "3"
        );
        // The wrapper is transparent to its inner's members too.
        assert_eq!(
            shown(resolve(&mem, wrap, &parse(".y").unwrap()).unwrap()),
            "4"
        );

        let pair = Value::new(v.ty(PAIR).unwrap(), 0x100, &bytes);
        assert_eq!(
            shown(resolve(&mem, pair, &parse(".0").unwrap()).unwrap()),
            "3"
        );
        assert_eq!(
            shown(resolve(&mem, pair, &parse(".__1").unwrap()).unwrap()),
            "4"
        );
    }

    /// `.member` crosses a pointer on its own — Rust's `.` — while `*`
    /// spells the same hop explicitly and refuses a non-pointer.
    #[test]
    fn test_member_auto_derefs_and_deref_is_checked() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000]))
            .at(0x2000, u32s(&[7, 9]));
        let ptr = Value::read(&mem, v.ty(PTR).unwrap(), 0x1000).unwrap();
        assert_eq!(
            shown(resolve(&mem, ptr, &parse(".y").unwrap()).unwrap()),
            "9"
        );
        assert_eq!(
            shown(resolve(&mem, ptr, &parse("*.x").unwrap()).unwrap()),
            "7"
        );
        assert_eq!(
            shown(resolve(&mem, ptr, &parse("*").unwrap()).unwrap()),
            "Point { x: 7, y: 9 }"
        );

        let point = Value::read(&mem, v.ty(POINT).unwrap(), 0x2000).unwrap();
        let err = resolve(&mem, point, &parse("*").unwrap()).expect_err("not a pointer");
        assert!(err.to_string().contains("pointer"), "{err}");
    }

    /// On an enum, `.member` reads through the active variant; naming
    /// an inactive variant refuses with the active one's name.
    #[test]
    fn test_member_reads_the_active_variant_only() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();

        // Msg::A(Point { 7, 9 }): tag 0 at offset 0, payload at 8.
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&9u32.to_le_bytes());
        let msg = Value::new(v.ty(MSG).unwrap(), 0x100, &bytes);
        // The active variant's payload members resolve unnamed…
        assert_eq!(
            shown(resolve(&mem, msg, &parse(".x").unwrap()).unwrap()),
            "7"
        );
        // …and the variant name answers the payload itself.
        assert_eq!(
            shown(resolve(&mem, msg, &parse(".A").unwrap()).unwrap()),
            "Point { x: 7, y: 9 }"
        );
        let err = resolve(&mem, msg, &parse(".B").unwrap()).expect_err("B is not active");
        assert!(err.to_string().contains("active variant"), "{err}");
        assert!(err.to_string().contains('A'), "{err}");

        // The niche enum spells the same way.
        let some = u64s(&[42]);
        let opt = Value::new(v.ty(OPT).unwrap(), 0x100, &some);
        assert_eq!(
            shown(resolve(&mem, opt, &parse(".Some").unwrap()).unwrap()),
            "42"
        );
        let err = resolve(&mem, opt, &parse(".None").unwrap()).expect_err("Some is active");
        assert!(err.to_string().contains("Some"), "{err}");
    }

    /// A member reached behind an `ArcInner` header: the deref lands on
    /// the header, and the hop to `data` is taken for the reader.
    #[test]
    fn test_member_descends_an_arc_inner_header() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // ArcInner { strong: 1, weak: 1, data: Shared { state: 5, value: 9 } }
        let mut inner = u64s(&[1, 1, 5]);
        inner.extend_from_slice(&u32s(&[9]));
        inner.extend_from_slice(&[0u8; 4]);
        let mem = FakeMem::new().at(0x4000, inner);
        let ptr_bytes = u64s(&[0x4000]);
        let ptr = Value::new(v.ty(WATCH_ARC_INNER_PTR).unwrap(), 0x100, &ptr_bytes);
        assert_eq!(
            shown(resolve(&mem, ptr, &parse(".value").unwrap()).unwrap()),
            "9"
        );
        // The header's own members still answer when named.
        assert_eq!(
            shown(resolve(&mem, ptr, &parse(".strong").unwrap()).unwrap()),
            "1"
        );
    }

    /// The names offered after a `.` are the ones `.name` would then
    /// accept: a struct's own; a wrapper's own and then its inner's; an
    /// enum's active variant and its payload's; a pointer's target's;
    /// a heap header's own and the data's behind it. Compiler slots
    /// are left out, a tuple's fields offered as digits, a map entry's
    /// halves as `0` and `1`.
    #[test]
    fn test_member_names_follow_the_auto_deref() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let names = |mem: &FakeMem, value: Value<'_>| -> Vec<String> {
            member_names(mem, &Node::Value(value))
        };

        let mem = FakeMem::new();
        let bytes = u32s(&[3, 4]);
        let point = Value::new(v.ty(POINT).unwrap(), 0x100, &bytes);
        assert_eq!(names(&mem, point), ["x", "y"]);
        let wrap = Value::new(v.ty(WRAP).unwrap(), 0x100, &bytes);
        assert_eq!(names(&mem, wrap), ["inner", "x", "y"]);
        // `Pair(u32, u32)` is a tuple struct with a name, so its `__0`
        // is a compiler spelling and stays out; a bare tuple's is `.0`.
        let pair = Value::new(v.ty(PAIR).unwrap(), 0x100, &bytes);
        assert!(names(&mem, pair).is_empty(), "{:?}", names(&mem, pair));
        let tuple = Value::new(v.ty(TUPLE2).unwrap(), 0x100, &bytes);
        assert_eq!(names(&mem, tuple), ["0", "1"]);

        // Msg::A(Point { 7, 9 }): the live variant, then its payload's
        // — B and C are not offered, since `.B` would refuse.
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&9u32.to_le_bytes());
        let msg = Value::new(v.ty(MSG).unwrap(), 0x100, &bytes);
        assert_eq!(names(&mem, msg), ["A", "x", "y"]);

        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000]))
            .at(0x2000, u32s(&[7, 9]));
        let ptr = Value::read(&mem, v.ty(PTR).unwrap(), 0x1000).unwrap();
        assert_eq!(names(&mem, ptr), ["x", "y"]);
        // An unreadable target ends the listing with nothing.
        let dangling = u64s(&[0x9000]);
        let ptr = Value::new(v.ty(PTR).unwrap(), 0x100, &dangling);
        assert!(names(&mem, ptr).is_empty());

        // ArcInner { strong, weak, data: Shared { state, value } }.
        let mut inner = u64s(&[1, 1, 5]);
        inner.extend_from_slice(&u32s(&[9]));
        inner.extend_from_slice(&[0u8; 4]);
        let mem = FakeMem::new().at(0x4000, inner);
        let ptr_bytes = u64s(&[0x4000]);
        let arc = Value::new(v.ty(WATCH_ARC_INNER_PTR).unwrap(), 0x100, &ptr_bytes);
        assert_eq!(
            names(&mem, arc),
            ["strong", "weak", "data", "state", "value"]
        );

        let entry = Node::Entry {
            key: point,
            value: point,
        };
        assert_eq!(member_names(&mem, &entry), ["0", "1"]);
    }

    /// `[N]` and every range form over a `Vec`, mirroring Rust
    /// slicing: an empty range at the boundary is fine, a bound past
    /// the length refuses with the length.
    #[test]
    fn test_index_and_ranges_over_a_vec() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x3000, u32s(&[10, 20, 30]));
        let mut bytes = u64s(&[0x3000, 3, 4]);
        bytes.truncate(24);
        let vec = Value::new(v.ty(VEC).unwrap(), 0x100, &bytes);
        let run = |path: &str| resolve(&mem, vec, &parse(path).unwrap());

        assert_eq!(shown(run("[1]").unwrap()), "20");
        let fanned: Vec<(String, String)> = run("[0..2]")
            .unwrap()
            .into_iter()
            .map(|r| {
                let Node::Value(v) = r.node else {
                    panic!("value")
                };
                (r.label, format!("{}", v.display()))
            })
            .collect();
        assert_eq!(
            fanned,
            [
                ("[0]".to_string(), "10".to_string()),
                ("[1]".to_string(), "20".to_string())
            ]
        );
        assert_eq!(run("[..]").unwrap().len(), 3);
        assert_eq!(run("[1..=2]").unwrap().len(), 2);
        // Inclusive end at the last element.
        assert_eq!(run("[..=2]").unwrap().len(), 3);
        // Empty ranges stand, at the boundary included.
        assert_eq!(run("[3..3]").unwrap().len(), 0);
        assert_eq!(run("[3..]").unwrap().len(), 0);

        for (path, want) in [
            ("[0..5]", "3 elements"),
            ("[5]", "index 5"),
            ("[..=3]", "3 elements"),
        ] {
            let err = run(path).expect_err(path).to_string();
            assert!(err.contains(want), "{path}: {err}");
        }
    }

    /// `[N]` on a map is the Nth entry in walk order, taken apart by
    /// `.0`/`.1`; anything else on an entry refuses; a range over
    /// entries fans out with a step applied to each.
    #[test]
    fn test_map_entries_index_navigate_and_fan_out() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // Keys 1, 2, 3 → values 10, 20, 30, as the renderer's own test
        // lays the tree out.
        let mem = FakeMem::new()
            .at(0x1000, btree_internal(&[(2, 20)], &[0x2000, 0x3000]))
            .at(0x2000, btree_leaf(&[(1, 10)]))
            .at(0x3000, btree_leaf(&[(3, 30)]));
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&3u64.to_le_bytes());
        let map = Value::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);
        let run = |path: &str| resolve(&mem, map, &parse(path).unwrap());

        assert_eq!(shown(run("[1].0").unwrap()), "2");
        assert_eq!(shown(run("[1].1").unwrap()), "20");
        match run("[0]").unwrap().pop().unwrap().node {
            Node::Entry { key, value } => {
                assert_eq!(format!("{}", key.display()), "1");
                assert_eq!(format!("{}", value.display()), "10");
            }
            Node::Value(_) => panic!("a map index yields the entry pair"),
        }

        // The fan-out: a step after a range applies to each entry.
        let keys: Vec<String> = run("[0..2].0")
            .unwrap()
            .into_iter()
            .map(|r| {
                let Node::Value(v) = r.node else {
                    panic!("value")
                };
                format!("{}{}", r.label, v.display())
            })
            .collect();
        assert_eq!(keys, ["[0]1", "[1]2"]);

        for (path, want) in [
            ("[1].2", ".0"),
            ("[1][0]", "map entry"),
            ("[1]*", "map entry"),
            ("[9]", "3 elements"),
        ] {
            let err = run(path).expect_err(path).to_string();
            assert!(err.contains(want), "{path}: {err}");
        }
    }

    /// Inline arrays and borrowed slices answer the same element steps.
    #[test]
    fn test_arrays_and_slices_index() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let arr_bytes = u32s(&[1, 2, 3]);
        let mem = FakeMem::new().at(0x5000, u32s(&[7, 8, 9]));
        let arr = Value::new(v.ty(ARR).unwrap(), 0x100, &arr_bytes);
        assert_eq!(
            shown(resolve(&mem, arr, &parse("[2]").unwrap()).unwrap()),
            "3"
        );

        let slice_bytes = u64s(&[0x5000, 3]);
        let slice = Value::new(v.ty(SLICE).unwrap(), 0x100, &slice_bytes);
        assert_eq!(
            shown(resolve(&mem, slice, &parse("[1]").unwrap()).unwrap()),
            "8"
        );
    }

    /// The heap-header hop knows Rc's spelling, and the wrapper
    /// descent lands at the member's real offset past a zero-sized
    /// leading field.
    #[test]
    fn test_rc_headers_and_padded_wrappers_descend() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // RcBox { strong: 1, weak: 1, value: Point { 27, 42 } }.
        let mut inner = u64s(&[1, 1]);
        inner.extend_from_slice(&u32s(&[27, 42]));
        let mem = FakeMem::new().at(0x6000, inner);
        let ptr_bytes = u64s(&[0x6000]);
        let rc = Value::new(v.ty(RC_BOX_PTR).unwrap(), 0x100, &ptr_bytes);
        assert_eq!(
            shown(resolve(&mem, rc, &parse(".x").unwrap()).unwrap()),
            "27"
        );

        // PadWrap { pad: (), point: Point { 7, 9 } @4 }: the descent
        // adds the member's offset, so `.y` sits at base + 4 + 4.
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&u32s(&[7, 9]));
        let wrap = Value::new(v.ty(PAD_WRAP).unwrap(), 0x200, &bytes);
        let y = one(resolve(&mem, wrap, &parse(".y").unwrap()).unwrap());
        assert_eq!(format!("{}", y.display()), "9");
        assert_eq!(y.addr, 0x200 + 4 + 4);
    }

    /// `*` crosses a niche pointer enum — `Option<NonNull<T>>`'s
    /// shape — to the pointee its live variant holds.
    #[test]
    fn test_deref_crosses_a_niche_pointer_enum() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[7, 9]));
        let bytes = u64s(&[0x2000]);
        let opt = Value::new(v.ty(OPT_PTR).unwrap(), 0x100, &bytes);
        assert_eq!(
            shown(resolve(&mem, opt, &parse("*").unwrap()).unwrap()),
            "Point { x: 7, y: 9 }"
        );
    }

    /// A truncated sequence tells an index inside the claim apart
    /// from one past it: the first is a short read, the second is the
    /// reader's own overreach.
    #[test]
    fn test_truncated_sequences_report_the_claim() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // The Vec claims five elements; the target serves three.
        let mem = FakeMem::new().at(0x3000, u32s(&[10, 20, 30]));
        let bytes = u64s(&[0x3000, 5, 5]);
        let vec = Value::new(v.ty(VEC).unwrap(), 0x100, &bytes);
        let run = |path: &str| resolve(&mem, vec, &parse(path).unwrap());

        assert_eq!(shown(run("[2]").unwrap()), "30");
        let err = run("[3]").expect_err("inside the claim").to_string();
        assert!(err.contains("claims 5") && err.contains("3"), "{err}");
        let err = run("[5]").expect_err("past the claim").to_string();
        assert!(err.contains("past the end"), "{err}");
    }

    /// A missing member names the members that do exist; a type with
    /// no element view refuses indexing.
    #[test]
    fn test_refusals_name_what_is_there() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new();
        let bytes = u32s(&[1, 2]);
        let point = Value::new(v.ty(POINT).unwrap(), 0x100, &bytes);
        let err = resolve(&mem, point, &parse(".z").unwrap()).expect_err("no z");
        assert!(err.to_string().contains("x, y"), "{err}");

        // A String is a display leaf, not a sequence of values.
        let string_bytes = u64s(&[0x5000, 2, 2]);
        let string = Value::new(v.ty(STRING).unwrap(), 0x100, &string_bytes);
        assert!(resolve(&mem, string, &parse("[0]").unwrap()).is_err());
    }
}

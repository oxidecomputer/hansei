//! Rendering a typed value to text.
//!
//! [`write_display_value`] is the dispatcher: it applies the guard rails
//! (zero-sized, depth budget, short buffer), hands a type carrying its own
//! [`DisplayNode`](crate::debug_type::DisplayNode) format to [`node`], and
//! otherwise renders structurally through
//! [`classify`](crate::debug_type::DebugType::classify). [`RenderCtx`] carries
//! depth, the optional target reader, the pointer cycle guard, and the `ugly`
//! override down every recursion.

pub(crate) mod aggregate;
pub(crate) mod collections;
pub(crate) mod dyn_ptr;
pub(crate) mod node;
pub(crate) mod scalar;

use crate::debug_type::{DebugType, DisplayNode, TypeClass};
use crate::target::ReadFromProc;
use crate::value::{TypeInfo, TypeInfoRef};

use aggregate::{write_rust_enum, write_struct_fields};
use node::eval_node;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

/// Display programs a render pass has already resolved, keyed by
/// [`DebugType::format_cache_key`]. A `None` entry records a type whose
/// resolution declined (or that carries no format), which is asked for as
/// often as one whose resolution succeeded.
pub(crate) type FormatCache<T> = RefCell<HashMap<u64, Option<Rc<DisplayNode<T>>>>>;

impl<'a, T: DebugType<'a>> fmt::Display for TypeInfoRef<'_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(f, self, RenderCtx::plain(0, 16), f.alternate())
    }
}

impl<'a, T: DebugType<'a>> fmt::Display for TypeInfo<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_ref(), f)
    }
}

pub struct DisplayValue<'r, 'buf, 'a: 'buf, T: DebugType<'a>> {
    info: &'r TypeInfoRef<'buf, 'a, T>,
    depth: usize,
    max_depth: usize,
    ugly: bool,
}

impl<'r, 'buf, 'a: 'buf, T: DebugType<'a>> DisplayValue<'r, 'buf, 'a, T> {
    /// Suppress custom formatters and render the base structural view.
    pub fn ugly(mut self) -> Self {
        self.ugly = true;
        self
    }
}

impl<'a, T: DebugType<'a>> fmt::Display for DisplayValue<'_, '_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_display_value(
            f,
            self.info,
            RenderCtx::plain(self.depth, self.max_depth).with_ugly(self.ugly),
            f.alternate(),
        )
    }
}

pub struct DisplayTargetValue<'r, 'buf, 'a: 'buf, T: DebugType<'a>, P: ReadFromProc> {
    info: &'r TypeInfoRef<'buf, 'a, T>,
    proc: &'r P,
    max_depth: usize,
    ugly: bool,
    elide: Option<&'r ElideOverride>,
    visited: RefCell<HashSet<(u64, &'a str)>>,
    formats: FormatCache<T>,
}

impl<'r, 'buf, 'a: 'buf, T: DebugType<'a>, P: ReadFromProc> DisplayTargetValue<'r, 'buf, 'a, T, P> {
    /// Suppress custom formatters and render the base structural view.
    pub fn ugly(mut self) -> Self {
        self.ugly = true;
        self
    }

    /// Adjust which types render as `<elided>`; see [`ElideOverride`].
    pub fn elide_override(mut self, elide: &'r ElideOverride) -> Self {
        self.elide = Some(elide);
        self
    }
}

impl<'a, T: DebugType<'a>, P: ReadFromProc> fmt::Display for DisplayTargetValue<'_, '_, 'a, T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ctx = RenderCtx {
            depth: 0,
            max_depth: self.max_depth,
            proc: Some(self.proc),
            visited: Some(&self.visited),
            hex_integers: false,
            ugly: self.ugly,
            elide: self.elide,
            formats: Some(&self.formats),
        };
        write_display_value(f, self.info, ctx, f.alternate())
    }
}

impl<'buf, 'a: 'buf, T: DebugType<'a>> TypeInfoRef<'buf, 'a, T> {
    pub fn display(&self) -> DisplayValue<'_, 'buf, 'a, T> {
        DisplayValue {
            info: self,
            depth: 0,
            max_depth: 8,
            ugly: false,
        }
    }

    pub fn display_with_depth(&self, max_depth: usize) -> DisplayValue<'_, 'buf, 'a, T> {
        DisplayValue {
            info: self,
            depth: 0,
            max_depth,
            ugly: false,
        }
    }

    /// Format this value while recursively reading typed pointees from a
    /// target. Pointer traversal consumes one level of the depth budget.
    pub fn display_from_target<'r, P: ReadFromProc>(
        &'r self,
        proc: &'r P,
        max_depth: usize,
    ) -> DisplayTargetValue<'r, 'buf, 'a, T, P> {
        DisplayTargetValue {
            info: self,
            proc,
            max_depth,
            ugly: false,
            elide: None,
            visited: RefCell::new(HashSet::new()),
            formats: FormatCache::default(),
        }
    }
}

/// The context threaded through the recursive `write_*` renderers: recursion
/// depth bookkeeping, the optional target reader and cycle-guard used to
/// follow pointers into the process, whether integers render in hex, and
/// whether custom debug formatters are suppressed in favour of the base
/// structural view. Bundling these keeps the renderer signatures small (they
/// otherwise take the same trailing arguments everywhere).
#[derive(Copy, Clone)]
pub(crate) struct RenderCtx<'buf, 'a, T: DebugType<'a>> {
    depth: usize,
    max_depth: usize,
    proc: Option<&'buf dyn ReadFromProc>,
    visited: Option<&'buf RefCell<HashSet<(u64, &'a str)>>>,
    /// Where this pass memoizes resolved display programs; `None` renders
    /// resolve on every ask (the plain, targetless displays).
    formats: Option<&'buf FormatCache<T>>,
    hex_integers: bool,
    /// Suppress every type's own [`debug_format`](DebugType::debug_format) and
    /// render purely through [`classify`](DebugType::classify) — the "ugly",
    /// structural view. Propagates to nested values, so a whole subtree
    /// renders without custom formatters once set.
    ugly: bool,
    /// Render-time adjustment of what renders as `<elided>`; `None` leaves
    /// the bundle's choices alone.
    elide: Option<&'buf ElideOverride>,
}

/// A render-time adjustment of which types render as `<elided>`, layered
/// over the bundle's own choices.
///
/// `no_elide` ignores the `Elided` display formats the bundle carries, so
/// the types under them render structurally; `types` names types that
/// render `<elided>` regardless of what format they carry — including
/// under `no_elide`, so "nothing but these" is `no_elide` plus a list,
/// and including under the ugly view, where an explicit elision is the
/// more specific of the user's two asks.
#[derive(Clone, Debug, Default)]
pub struct ElideOverride {
    /// Ignore the `Elided` display formats carried by the bundle.
    pub no_elide: bool,
    /// Patterns for type names to force to `<elided>`. A pattern with a
    /// `*` is a glob, each `*` matching any run of characters; one
    /// without is a fully-qualified name, which also covers every
    /// instantiation when it carries no generic arguments, the way a
    /// detector keyed on the base name does. Both sides are compared in
    /// the normalized spelling (no whitespace, default allocators
    /// elided), so a pattern need not match the debug info's formatting.
    pub types: Vec<String>,
}

impl ElideOverride {
    /// Whether the value type named `name` is forced to `<elided>`.
    fn forces(&self, name: &str) -> bool {
        if self.types.is_empty() {
            return false;
        }
        let name = exegesis::symbols::normalized_rust_type_name(name);
        let base = name.split_once('<').map_or(&*name, |(base, _)| base);
        self.types.iter().any(|spec| {
            let spec = exegesis::symbols::normalized_rust_type_name(spec);
            if spec.contains('*') {
                glob_match(&spec, &name)
            } else {
                spec == name || spec == base
            }
        })
    }
}

/// Whether `name` matches `pattern`, where each `*` matches any run of
/// characters and everything else matches itself. Anchored at both ends:
/// `steno::*` does not match a name that merely contains `steno::`.
///
/// The classic two-pointer walk with one backtrack point per `*`. Bytes
/// are enough: a `*` consumes UTF-8 continuation bytes like any others,
/// and the literal stretches only match where the same bytes occur.
fn glob_match(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0, 0);
    let mut backtrack = None;
    while ni < name.len() {
        if pattern.get(pi) == Some(&b'*') {
            // Match nothing for now; remember where to widen from.
            backtrack = Some((pi, ni));
            pi += 1;
        } else if pattern.get(pi) == Some(&name[ni]) {
            pi += 1;
            ni += 1;
        } else if let Some((star, matched)) = backtrack {
            // Widen the last `*` by one character and retry after it.
            backtrack = Some((star, matched + 1));
            pi = star + 1;
            ni = matched + 1;
        } else {
            return false;
        }
    }
    pattern[pi..].iter().all(|&ch| ch == b'*')
}

impl<'buf, 'a, T: DebugType<'a>> RenderCtx<'buf, 'a, T> {
    /// A context with no target to read from (structural rendering only).
    fn plain(depth: usize, max_depth: usize) -> Self {
        Self {
            depth,
            max_depth,
            proc: None,
            visited: None,
            formats: None,
            hex_integers: false,
            ugly: false,
            elide: None,
        }
    }

    /// The type's resolved display program. Resolving reduces the bundle's
    /// name-addressed selectors to byte offsets and allocates the resolved
    /// tree, so a pass carrying a cache pays that once per type rather than
    /// once per value — a map of ten thousand `String`s asks ten thousand
    /// times and resolves once.
    fn debug_format(&self, ty: &T) -> Option<Rc<DisplayNode<T>>> {
        let Some(cache) = self.formats else {
            return ty.debug_format().map(Rc::new);
        };
        let key = ty.format_cache_key();
        if let Some(hit) = cache.borrow().get(&key) {
            return hit.clone();
        }
        let resolved = ty.debug_format().map(Rc::new);
        cache.borrow_mut().insert(key, resolved.clone());
        resolved
    }

    /// The context for a value nested one level deeper.
    fn deeper(self) -> Self {
        Self {
            depth: self.depth + 1,
            ..self
        }
    }

    /// The same context with the hex-integer flag overridden — array and `Vec`
    /// elements choose their own rendering independent of the parent.
    fn with_hex(self, hex_integers: bool) -> Self {
        Self {
            hex_integers,
            ..self
        }
    }

    /// The same context with custom formatters suppressed (or not).
    fn with_ugly(self, ugly: bool) -> Self {
        Self { ugly, ..self }
    }
}

/// Render one value. This is also how a renderer recurses into a child:
/// called directly, with `pretty` passed along rather than re-encoded as
/// a `{:#}` format spec — re-entering `core::fmt::write` per child value
/// costs an `Arguments` and several frames at every level of a tree this
/// renders millions of nodes of.
pub(crate) fn write_display_value<'a, T: DebugType<'a>>(
    f: &mut fmt::Formatter<'_>,
    info: &TypeInfoRef<'_, 'a, T>,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let ty = info.ty;
    let bytes = info.bytes;

    if bytes.is_empty() && ty.size() == 0 {
        return write!(f, "{}", ty.name());
    }

    if ctx.depth >= ctx.max_depth {
        return write!(f, "...");
    }

    if (bytes.len() as u64) < ty.size() {
        return write!(f, "<truncated>");
    }

    // A forced elision outranks everything, `--ugly` included: both flags
    // are the user speaking, and the elision is the more specific ask.
    if let Some(elide) = ctx.elide
        && elide.forces(ty.name())
    {
        return write!(f, "<elided>");
    }

    // `--ugly` mode skips every custom formatter and renders the type through
    // its structural classification below; `--no-elide` skips only the
    // bundle's `Elided` formats, leaving the types under them structural.
    if !ctx.ugly
        && let Some(node) = ctx.debug_format(&ty)
        && !(matches!(*node, DisplayNode::Elided) && ctx.elide.is_some_and(|e| e.no_elide))
    {
        // A top-level `Scalar` formatter (e.g. a parking_lot `RawMutex`)
        // has no enclosing field label to give it context, so it is prefixed
        // with the type name — `<name>: <decoded>`. Other nodes name (or
        // elide) themselves as they render.
        if let DisplayNode::Scalar { .. } = *node {
            write!(f, "{}: ", ty.name())?;
        }
        return eval_node(f, &node, &ty, info.bytes, info.addr, ctx, pretty);
    }

    match ty.classify() {
        TypeClass::Integer {
            size,
            is_signed,
            is_bool,
            is_char,
        } => {
            if is_bool {
                return write!(f, "{}", bytes[0] != 0);
            }

            if is_char {
                let ch = bytes[0];
                return if ch.is_ascii_graphic() || ch == b' ' {
                    write!(f, "'{}'", ch as char)
                } else {
                    write!(f, "'\\x{:02x}'", ch)
                };
            }

            if ctx.hex_integers {
                return match size {
                    1 => write!(f, "0x{:02x}", bytes[0]),
                    2 => write!(
                        f,
                        "0x{:04x}",
                        u16::from_le_bytes(bytes[..2].try_into().unwrap())
                    ),
                    4 => write!(
                        f,
                        "0x{:08x}",
                        u32::from_le_bytes(bytes[..4].try_into().unwrap())
                    ),
                    8 => write!(
                        f,
                        "0x{:016x}",
                        u64::from_le_bytes(bytes[..8].try_into().unwrap())
                    ),
                    _ => write_hex_bytes(f, bytes),
                };
            }

            if is_signed {
                match size {
                    1 => write!(f, "{}", bytes[0] as i8),
                    2 => write!(f, "{}", i16::from_le_bytes(bytes[..2].try_into().unwrap())),
                    4 => write!(f, "{}", i32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    8 => write!(f, "{}", i64::from_le_bytes(bytes[..8].try_into().unwrap())),
                    _ => write_hex_bytes(f, bytes),
                }
            } else {
                match size {
                    1 => write!(f, "{}", bytes[0]),
                    2 => write!(f, "{}", u16::from_le_bytes(bytes[..2].try_into().unwrap())),
                    4 => write!(f, "{}", u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                    8 => write!(f, "{}", u64::from_le_bytes(bytes[..8].try_into().unwrap())),
                    _ => write_hex_bytes(f, bytes),
                }
            }
        }

        TypeClass::Float { size } => match size {
            4 => write!(f, "{}", f32::from_le_bytes(bytes[..4].try_into().unwrap())),
            8 => write!(f, "{}", f64::from_le_bytes(bytes[..8].try_into().unwrap())),
            _ => write_hex_bytes(f, bytes),
        },

        TypeClass::Pointer { target } => {
            if bytes.len() < 8 {
                return write!(f, "<truncated>");
            }
            let addr = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if addr == 0 {
                return write!(f, "null");
            }
            // A pointer to a zero-sized type (e.g. `RawWaker`'s `*const ()`
            // data pointer) has no meaningful pointee to follow — reading it
            // would only ever print the type's name (`-> ()`). Show just the
            // address.
            if target.size() == 0 {
                return write!(f, "0x{addr:x}");
            }
            let (Some(proc), Some(visited)) = (ctx.proc, ctx.visited) else {
                return write!(f, "0x{addr:x}");
            };
            let key = (addr, target.name());
            if !visited.borrow_mut().insert(key) {
                return write!(f, "0x{addr:x} -> <cycle>");
            }
            let result = match proc.read_bytes(addr, target.size()) {
                Ok(pointee_bytes) => {
                    let pointee = TypeInfoRef {
                        ty: target,
                        addr,
                        bytes: &pointee_bytes,
                        _marker: std::marker::PhantomData,
                    };
                    write!(f, "0x{addr:x} -> ")
                        .and_then(|()| write_display_value(f, &pointee, ctx.deeper(), pretty))
                }
                Err(_) => write!(f, "0x{addr:x} -> <unreadable>"),
            };
            visited.borrow_mut().remove(&key);
            result
        }

        TypeClass::Struct => {
            let name = ty.name();
            write_struct_fields(f, info, name, pretty, ctx)
        }

        TypeClass::Union => {
            let name = ty.name();
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            write!(f, "{{ ")?;
            write_hex_bytes(f, bytes)?;
            write!(f, " }}")
        }

        TypeClass::RustEnum => {
            let name = ty.name();
            write_rust_enum(f, info, name, pretty, ctx)
        }

        TypeClass::CEnum => {
            // For C-style enums, try to find the active variant name.
            if let Some(Ok((name, _, _))) = ty.active_variant(bytes) {
                write!(f, "{}", name)
            } else {
                write_hex_bytes(f, bytes)
            }
        }

        TypeClass::Array { element, count } => {
            let elem_size = element.size() as usize;
            let count = count as usize;
            let hex_elements = matches!(
                element.classify(),
                TypeClass::Integer {
                    is_bool: false,
                    is_char: false,
                    ..
                }
            );

            write!(f, "[")?;
            for i in 0..count {
                let start = i * elem_size;
                let end = start + elem_size;
                if let Some(elem_bytes) = bytes.get(start..end) {
                    if pretty {
                        writeln!(f)?;
                        write_indent(f, ctx.depth + 1)?;
                    } else if i > 0 {
                        write!(f, ", ")?;
                    }

                    let child = TypeInfoRef {
                        ty: element,
                        addr: info.addr + start as u64,
                        bytes: elem_bytes,
                        _marker: std::marker::PhantomData,
                    };
                    write_display_value(f, &child, ctx.deeper().with_hex(hex_elements), pretty)?;
                    if pretty {
                        write!(f, ",")?;
                    }
                } else {
                    // Unreachable for a backend whose array size agrees with
                    // its element size times count, which the guard at the top
                    // of this function has already checked the buffer against.
                    // Kept because the slice is fallible and a backend that
                    // disagreed must degrade rather than read past the end.
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "<truncated>")?;
                    break;
                }
            }
            if pretty && count > 0 {
                writeln!(f)?;
                write_indent(f, ctx.depth)?;
            }
            write!(f, "]")
        }

        TypeClass::Opaque => {
            let name = ty.name();
            if !name.is_empty() {
                write!(f, "{} ", name)?;
            }
            write_hex_bytes(f, bytes)
        }
    }
}

pub(crate) fn write_indent(f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    for _ in 0..depth {
        write!(f, "    ")?;
    }
    Ok(())
}

/// Prefix punctuation before one element of a `[e, e, …]` sequence. In pretty
/// mode: a newline and one deeper indent so each element sits on its own line.
/// Inline: a `, ` separator before every element but the first (`first` is
/// whether no element has been written yet). Shared by the slice, list, and
/// mpsc-queue renderers so the bracket/indent/comma dance lives in one place.
pub(crate) fn write_seq_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    first: bool,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, depth + 1)
    } else if first {
        Ok(())
    } else {
        write!(f, ", ")
    }
}

/// Whitespace closing a `[e, e, …]` sequence body, written before the caller's
/// `]`. In pretty mode, once `any` element has been emitted, a newline and an
/// indent back to `depth` so the bracket lines up with the opener; inline (or
/// when empty), nothing.
pub(crate) fn write_seq_close(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    depth: usize,
    any: bool,
) -> fmt::Result {
    if pretty && any {
        writeln!(f)?;
        write_indent(f, depth)?;
    }
    Ok(())
}

pub(crate) fn write_hex_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    write!(f, "[")?;
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            write!(f, ", ")?;
        }
        write!(f, "0x{:02x}", b)?;
    }
    write!(f, "]")
}

// ---------------------------------------------------------------------------
// ParseCtx & ParseWithDbgInfo
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::TypeInfoRef;
    use crate::testhelper::*;

    use exegesis::bundle::BundleView;

    #[test]
    fn test_ugly_suppresses_custom_formatters() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        // A `Scalar` format (`RawMutex`) renders its decoded bits normally, but
        // `--ugly` shows the underlying struct field.
        let mutex = TypeInfoRef::new(v.ty(RAW_MUTEX).unwrap(), 0, &[1u8]);
        assert_eq!(
            format!("{}", mutex.display()),
            "parking_lot::raw_mutex::RawMutex: locked=true, parked=false"
        );
        assert_eq!(
            format!("{}", mutex.display().ugly()),
            "parking_lot::raw_mutex::RawMutex { state: 1 }"
        );

        // A `Str` format renders as a quoted string normally; `--ugly` shows the
        // pointer/length representation instead. (No target: the pointer prints
        // as a bare address rather than being followed.)
        let str_bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let s = TypeInfoRef::new(v.ty(STR).unwrap(), 0, &str_bytes);
        assert_eq!(
            format!("{}", s.display().ugly()),
            "&str { data_ptr: 0x3000, length: 8 }"
        );
    }

    #[test]
    fn test_integer_arrays_display_as_zero_padded_hex() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let bytes: Vec<u8> = [1u32, 0xabcdef, u32::MAX]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let array = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", array.display()),
            "[0x00000001, 0x00abcdef, 0xffffffff]"
        );

        let bytes: Vec<u8> = [1u64, 0xabcdef, u64::MAX]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let array = TypeInfoRef::new(v.ty(VTABLE_ARRAY).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", array.display()),
            "[0x0000000000000001, 0x0000000000abcdef, 0xffffffffffffffff]"
        );
        assert_eq!(
            format!("{:#}", array.display()),
            "[\n    0x0000000000000001,\n    0x0000000000abcdef,\n    0xffffffffffffffff,\n]"
        );
    }

    #[test]
    fn test_target_display_recurses_through_pointers() {
        let mem = FakeMem::new()
            .at(0x1000, node_bytes(1, 0x2000))
            .at(0x2000, node_bytes(2, 0));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let root = TypeInfoRef::new(v.ty(NODE_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", root.display_from_target(&mem, 8));
        assert!(shown.contains("value: 1"), "{shown}");
        assert!(shown.contains("value: 2"), "{shown}");

        let shallow = format!("{:#}", root.display_from_target(&mem, 1));
        assert_eq!(shallow, "0x1000 -> ...");
    }

    /// Every `TypeClass` arm that no other test reaches: the float, signed and
    /// character encodings, the hex fallback for a width the integer branch has
    /// no case for, and the union and opaque dumps.
    #[test]
    fn test_base_type_encodings_render_by_class() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let show = |id, bytes: &[u8]| {
            format!(
                "{}",
                TypeInfoRef::new(v.ty(id).unwrap(), 0, bytes).display()
            )
        };

        assert_eq!(show(F32, &1.5f32.to_le_bytes()), "1.5");
        assert_eq!(show(F64, &(-0.25f64).to_le_bytes()), "-0.25");

        assert_eq!(show(I8, &(-1i8).to_le_bytes()), "-1");
        assert_eq!(show(I16, &(-300i16).to_le_bytes()), "-300");
        assert_eq!(show(I32, &(-70000i32).to_le_bytes()), "-70000");
        assert_eq!(show(I64, &i64::MIN.to_le_bytes()), "-9223372036854775808");

        assert_eq!(show(U16, &4242u16.to_le_bytes()), "4242");

        // A width the signed/unsigned match has no case for dumps its bytes.
        assert_eq!(show(U24, &[0x01, 0x02, 0x03]), "[0x01, 0x02, 0x03]");

        // A union is dumped whole -- its members overlap, so there is no one
        // reading to show.
        assert_eq!(
            show(VAL_UNION, &7u64.to_le_bytes()),
            "Val { [0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] }"
        );

        // An opaque the extractor could not model keeps its name over the dump.
        assert_eq!(
            show(UNMODELLED, &[0xde, 0xad, 0xbe, 0xef]),
            "Unmodelled [0xde, 0xad, 0xbe, 0xef]"
        );
    }

    /// A `char` renders quoted, escaping anything not printable ASCII. reify
    /// reads only the low byte of the 4-byte scalar, so a non-ASCII code point
    /// shows that byte escaped rather than the character it belongs to.
    #[test]
    fn test_char_renders_quoted_and_escapes_non_printable() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let show = |c: u32| {
            format!(
                "{}",
                TypeInfoRef::new(v.ty(CHAR).unwrap(), 0, &c.to_le_bytes()).display()
            )
        };
        assert_eq!(show(u32::from('A')), "'A'");
        assert_eq!(show(u32::from(' ')), "' '");
        assert_eq!(show(0x07), "'\\x07'");
        assert_eq!(show(u32::from('é')), "'\\xe9'");
    }

    /// A C enumeration dumps its bytes rather than naming the enumerator. The
    /// `CEnum` arm asks `active_variant`, which is only implemented for a Rust
    /// enum's `VariantShape` and returns `None` for every `TypeDef::CEnum`, so
    /// the name lookup can never succeed through the current `DebugType`
    /// interface.
    #[test]
    fn test_c_enum_falls_back_to_hex_bytes() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let color = v.ty(COLOR).unwrap();
        assert!(color.active_variant(&1u32.to_le_bytes()).is_none());
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(color, 0, &1u32.to_le_bytes()).display()
            ),
            "[0x01, 0x00, 0x00, 0x00]"
        );
    }

    /// A buffer shorter than the type is reported rather than read past. The
    /// guard is at the top of the renderer, so it catches a short array before
    /// the per-element slicing does -- a bundle array's size is defined as
    /// element size times count, so the element branch's own `<truncated>` is
    /// unreachable through this backend.
    #[test]
    fn test_short_buffer_renders_truncated() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        // Point is 8 bytes; 4 is not enough to render it at all.
        let short = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &[0u8; 4]);
        assert_eq!(format!("{}", short.display()), "<truncated>");

        // `[u32; 3]` is 12 bytes; two elements' worth does not render partially.
        let arr = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &[1u8, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(format!("{}", arr.display()), "<truncated>");
    }

    /// The depth budget stops recursion with `...` rather than rendering an
    /// unbounded tree, and one more level of budget renders one more level.
    #[test]
    fn test_depth_budget_truncates_with_ellipsis() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let point = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &bytes);

        // Depth 0 has no budget for the value itself.
        assert_eq!(format!("{}", point.display_with_depth(0)), "...");
        // Depth 1 renders the struct but not its fields.
        assert_eq!(
            format!("{}", point.display_with_depth(1)),
            "Point { x: ..., y: ... }"
        );
        // Depth 2 reaches the leaves.
        assert_eq!(
            format!("{}", point.display_with_depth(2)),
            "Point { x: 1, y: 2 }"
        );
    }

    /// Following a pointer into the target degrades to a marker when the read
    /// fails, and is guarded against a cycle -- while a value reached twice by
    /// separate paths still renders twice, because the guard entry is removed
    /// once a pointee is done.
    #[test]
    fn test_pointer_traversal_degrades_and_guards_cycles() {
        let unreadable = FakeMem::new().unreadable();
        // 0x100 points at itself.
        let self_cycle = FakeMem::new().at(0x100, node_bytes(1, 0x100));
        // Two pointers reach 0x300, which ends the chain.
        let diamond = FakeMem::new()
            .at(0x100, node_bytes(1, 0x300))
            .at(0x300, node_bytes(9, 0));

        let b = test_bundle();
        let v = BundleView::new(&b);
        let ptr = v.ty(NODE_PTR).unwrap();
        let head = 0x100u64.to_le_bytes();
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(ptr, 0, &head).display_from_target(&unreadable, 16)
            ),
            "0x100 -> <unreadable>"
        );
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(ptr, 0, &head).display_from_target(&self_cycle, 16)
            ),
            "0x100 -> Node { value: 1, next: 0x100 -> <cycle> }"
        );

        // The same address twice in sequence is not a cycle: both pointers to
        // 0x300 render it, because the guard entry is dropped on the way out.
        let two = v.ty(NODE).unwrap();
        let pair = {
            let mut bytes = node_bytes(1, 0x100);
            bytes[8..].copy_from_slice(&0x300u64.to_le_bytes());
            bytes
        };
        let shown = format!(
            "{}",
            TypeInfoRef::new(two, 0, &pair).display_from_target(&diamond, 16)
        );
        assert_eq!(
            shown,
            "Node { value: 1, next: 0x300 -> Node { value: 9, next: null } }"
        );
    }

    /// The bare `Display` impls are a separate entry point from `display()`,
    /// with their own depth budget -- 16 rather than 8 -- so a value nested
    /// past eight levels renders through one and truncates through the other.
    /// Both spellings, borrowed and owned, reach the same renderer.
    #[test]
    fn test_bare_display_impls_use_their_own_depth() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let point = TypeInfoRef::new(v.ty(POINT).unwrap(), 0x1000, &bytes);

        // `{}` on the value itself, rather than on a Display* wrapper.
        assert_eq!(format!("{point}"), "Point { x: 1, y: 2 }");
        assert_eq!(
            format!("{point}"),
            format!("{}", point.display_with_depth(16))
        );
        assert_eq!(format!("{point:#}"), "Point {\n    x: 1,\n    y: 2,\n}");

        // The owned form renders identically, through the same impl.
        let owned = crate::TypeInfo::from(point.clone());
        assert_eq!(format!("{owned}"), format!("{point}"));
        assert_eq!(format!("{owned:#}"), format!("{point:#}"));
    }

    /// `ugly()` on a target-reading display suppresses custom formatters the
    /// same way it does without a target, and keeps following pointers.
    #[test]
    fn test_ugly_applies_to_a_target_reading_display() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13]));
        let bytes: Vec<u8> = [0x2000u64, 3, 3]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &bytes);

        // The Vec's own format renders its elements.
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8)),
            "[5, 8, 13]"
        );
        // `ugly` renders the representation instead, still reading the target
        // for the data pointer it now shows structurally.
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8).ugly()),
            "alloc::vec::Vec<u32> { ptr: 0x2000 -> 5, len: 3, capacity: 3 }"
        );
    }

    /// Nesting in pretty mode. Every line sits on a four-space grid, and each
    /// record's closing brace is one level left of the fields it closes --
    /// which is what a named struct's field prefix used to break, indenting
    /// fields to `4 * depth + 1` while the closer stayed at `4 * depth`.
    #[test]
    fn test_pretty_nesting_indents_on_a_four_space_grid() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        // A pointer followed in pretty mode: the pointee's fields indent from
        // its own depth and its closer lands one level left of them.
        let mem = FakeMem::new().at(0x2000, u32s(&[3, 4]));
        let bytes = 0x2000u64.to_le_bytes();
        let ptr = TypeInfoRef::new(v.ty(PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{:#}", ptr.display_from_target(&mem, 8)),
            "0x2000 -> Point {\n        x: 3,\n        y: 4,\n    }"
        );

        // Three levels of record nesting, from the structural view of a type
        // whose own formatter would otherwise flatten it.
        let notify = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &[0u8; 32]);
        let shown = format!("{:#}", notify.display().ugly());
        for line in shown.lines() {
            let indent = line.len() - line.trim_start().len();
            assert_eq!(indent % 4, 0, "off the grid: {line:?}\nin {shown}");
        }

        let indent_of = |needle: &str| {
            shown
                .lines()
                .find(|l| l.trim_start().starts_with(needle))
                .map(|l| l.len() - l.trim_start().len())
                .unwrap_or_else(|| panic!("no line for {needle}: {shown}"))
        };
        assert_eq!(indent_of("state: 0,"), 4);
        assert_eq!(indent_of("raw:"), 8);
        assert_eq!(indent_of("head: null,"), 12);
        // The innermost record's fields are at twelve, so it closes at eight.
        assert!(
            shown.contains("\n            head: null,\n            tail: null,\n        },"),
            "{shown}"
        );
    }

    /// Suppressing custom formatters leaves the structural view, which lays out
    /// with the same rules and still follows a pointer it is handed.
    #[test]
    fn test_ugly_renders_the_structural_view_in_pretty() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13]));
        let fat = u64s(&[0x2000, 3, 3]);
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &fat);
        assert_eq!(
            format!("{:#}", value.display_from_target(&mem, 8).ugly()),
            "alloc::vec::Vec<u32> {\n    ptr: 0x2000 -> 5,\n    len: 3,\n    capacity: 3,\n}"
        );
    }

    /// A bool renders by its truth rather than its byte, so any non-zero
    /// pattern reads as `true`. A zero-sized type has no bytes to render and
    /// is shown by name.
    #[test]
    fn test_bool_and_zero_sized_types_render_structurally() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bool_ty = v.ty(BOOL).unwrap();
        let show = |byte: u8| {
            format!(
                "{}",
                TypeInfoRef::new(bool_ty, 0, std::slice::from_ref(&byte)).display()
            )
        };
        assert_eq!(show(0), "false");
        assert_eq!(show(1), "true");
        // Not a comparison against 1: a byte that is neither is still true.
        assert_eq!(show(7), "true");

        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(v.ty(UNIT).unwrap(), 0, &[]).display()
            ),
            "Unit"
        );
    }

    /// A pointer with nothing to read through shows its address and stops.
    /// Null is named, and a word too short to hold an address is reported.
    #[test]
    fn test_pointer_without_a_target_shows_its_address() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ptr = v.ty(PTR).unwrap();
        let show = |bytes: &[u8]| format!("{}", TypeInfoRef::new(ptr, 0, bytes).display());

        assert_eq!(show(&0x2000u64.to_le_bytes()), "0x2000");
        assert_eq!(show(&0u64.to_le_bytes()), "null");
        assert_eq!(show(&[0u8; 4]), "<truncated>");
    }

    /// Integer array elements render zero-padded to their own width, so the
    /// column lines up whatever the element type is. Every width the renderer
    /// has a case for, from one byte to eight.
    #[test]
    fn test_integer_arrays_pad_hex_to_the_element_width() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let show = |id, bytes: &[u8]| {
            format!(
                "{}",
                TypeInfoRef::new(v.ty(id).unwrap(), 0, bytes).display()
            )
        };
        assert_eq!(
            show(IPV4_OCTETS, &[1, 2, 3, 0xff]),
            "[0x01, 0x02, 0x03, 0xff]"
        );
        assert_eq!(show(U16_ARR, &[0x01, 0x00, 0xff, 0xff]), "[0x0001, 0xffff]");
        assert_eq!(
            show(ARR, &u32s(&[1, 0xabcdef, u32::MAX])),
            "[0x00000001, 0x00abcdef, 0xffffffff]"
        );
    }

    #[test]
    fn test_glob_matches_anchored_wildcards() {
        use super::glob_match;

        assert!(glob_match("alloc::vec::Vec<*>", "alloc::vec::Vec<u8>"));
        assert!(glob_match("*::Logger<*>", "slog::Logger<a::B<c::D>>"));
        assert!(glob_match("steno::*", "steno::saga_log::SagaLog"));
        assert!(glob_match("*", "anything at all"));
        assert!(glob_match("a*b*c", "a__b__b__c"));
        assert!(glob_match("exact", "exact"));

        // Anchored: a bare segment is not a substring match.
        assert!(!glob_match("steno::*", "nexus::steno::Wrapper"));
        assert!(!glob_match("*::Logger", "slog::Logger<a::B>"));
        assert!(!glob_match("a*b", "a__b__c"));
        assert!(!glob_match("exact", "exactly"));
    }

    #[test]
    fn test_forces_normalizes_both_sides() {
        use super::ElideOverride;

        let elide = |spec: &str| ElideOverride {
            no_elide: false,
            types: vec![spec.to_owned()],
        };
        // Both sides are compared normalized: whitespace gone, default
        // allocator elided.
        assert!(elide("alloc::vec::Vec<u8>").forces("alloc::vec::Vec<u8, alloc::alloc::Global>"));
        assert!(elide("alloc::vec::Vec<*>").forces("alloc::vec::Vec<u8, alloc::alloc::Global>"));
        // A bare name covers instantiations; a glob must spell them.
        assert!(elide("slog::Logger").forces("slog::Logger<a::B>"));
        assert!(!elide("slog::Log*er").forces("slog::Logger<a::B>"));
        assert!(elide("slog::Log*er<*>").forces("slog::Logger<a::B>"));
    }
}

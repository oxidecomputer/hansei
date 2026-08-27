//! Rendering a typed value to text.
//!
//! [`write_display_value`] is the dispatcher: it applies the guard rails
//! (zero-sized, depth budget, short buffer), hands a type carrying its own
//! [`DisplayNode`](crate::debug_type::DisplayNode) format to [`node`], and
//! otherwise renders structurally through
//! [`classify`](hansei_bundle::BundleType::classify). [`RenderCtx`] carries
//! depth, the optional target reader, the pointer cycle guard, and the `ugly`
//! override down every recursion.

pub(crate) mod aggregate;
pub(crate) mod collections;
pub(crate) mod dyn_ptr;
pub(crate) mod node;
pub(crate) mod par;
pub(crate) mod scalar;

use crate::debug_type::{DisplayNode, TypeClass};
use crate::heap::{Gate, Heap, Liveness};
use crate::value::Value;
use proc::Target;

use hansei_bundle::{BundleType, BundleTypeId};

use aggregate::{write_rust_enum, write_struct_fields};
use node::eval_node;
use par::WorkerCtx;
use scalar::{read_u64_at, read_unsigned_at};

use foldhash::{HashMap, HashSet};

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

/// Display programs a render pass has already resolved, keyed by bundle type
/// id. A `None` entry records a type whose resolution declined (or that
/// carries no format), which is asked for as often as one whose resolution
/// succeeded.
pub(crate) type FormatCache<'a> = RefCell<HashMap<BundleTypeId, Option<Rc<DisplayNode<'a>>>>>;

/// The depth budget a display renders with when the caller does not pick
/// one — what [`Value::display`] starts from.
#[cfg(test)]
const DEFAULT_DEPTH: usize = 8;

/// How much of a string a render shows before saying how much is left.
///
/// A length is read out of the target like any other word, so a corrupt
/// one claims whatever its bits say — and the target serves every
/// mapped page under the claim, which the escaped rendering then
/// multiplies by four. That is how a single fabricated `String` came to
/// ask for 1.4 GB of output. This is the ceiling on how much any one
/// string can cost to print, whether it is corrupt or merely enormous;
/// [`DisplayValue::max_str_len`] moves it.
pub const DEFAULT_MAX_STR_LEN: u64 = 128 * 1024;

/// How many elements of a sequence a render shows before saying how
/// many are left.
///
/// The sibling of [`DEFAULT_MAX_STR_LEN`] for everything wider than a
/// byte, and counted in elements rather than bytes because that is what
/// costs a line apiece. The two are separate budgets because they bound
/// different things, and they are wildly different sizes for the same
/// reason: a byte buffer is text, printed dozens to a line and read as
/// a whole, while a wide element is a value with a line of its own and
/// an indent in front of it. A hundred and twenty-eight of those is
/// already more than anyone reads; past it a listing is scrolled, not
/// examined. [`DisplayValue::max_array_len`] moves it.
pub const DEFAULT_MAX_ARRAY_LEN: u64 = 128;

/// A caller-supplied label for addresses the renderer prints. A followed
/// pointer keeps its address and gains the label — `0x… (label) -> …` —
/// while a pointer shown only as its bare word (a zero-sized pointee, an
/// alias snapshot) renders as the label itself, since the label *is* what
/// that word means; the address remains the fallback when the annotator
/// returns `None`. `Sync` because the parallel fan-out shares it across
/// worker threads; the lifetime lets it borrow the caller's lookup state.
pub type AddrAnnotator<'r> = dyn Fn(u64) -> Option<String> + Sync + 'r;

/// A value formatted for display: what [`Value::display`] and
/// [`Value::display_from_target`] build, with or without a target to read
/// pointees through, and what the render-time options chain onto.
pub struct DisplayValue<'r, 'a, T> {
    info: &'r Value<'a>,
    /// Where pointees are read from; `None` renders only the bytes in hand,
    /// showing a pointer as its bare address.
    proc: Option<&'a T>,
    max_depth: usize,
    ugly: bool,
    elide: Option<&'r ElideOverride>,
    annotate: Option<&'r AddrAnnotator<'r>>,
    heap: Option<&'r dyn Heap>,
    max_str_len: Option<u64>,
    max_array_len: Option<u64>,
    prefix: &'r str,
    visited: RefCell<HashSet<(u64, &'a str)>>,
    formats: FormatCache<'a>,
}

impl<'r, 'a, T> DisplayValue<'r, 'a, T> {
    /// Override the depth budget (default 8). Each level of nesting — a
    /// member, an element, a followed pointer — spends one.
    pub fn depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

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

    /// Label pointer addresses; see [`AddrAnnotator`] for how a label
    /// lands on followed versus bare pointers. What hansei uses to mark
    /// a pointer into a task's allocation with that task's id.
    pub fn annotate_addrs(mut self, annotate: &'r AddrAnnotator<'r>) -> Self {
        self.annotate = Some(annotate);
        self
    }

    /// Corroborate every read this render makes against the target's own
    /// allocator: a pointer into freed memory is left unexpanded, and a
    /// sequence is believed no further than the allocation holding its
    /// buffer. Without one the render believes the bytes, which is what
    /// a target whose allocator keeps no readable metadata gets.
    pub fn heap(mut self, heap: &'r dyn Heap) -> Self {
        self.heap = Some(heap);
        self
    }

    /// How much of a string to show, in bytes; `None` shows all of it.
    /// Defaults to [`DEFAULT_MAX_STR_LEN`] — see there for why a
    /// ceiling exists at all. What is left is reported rather than
    /// dropped, the way every other shortfall is.
    pub fn max_str_len(mut self, max: Option<u64>) -> Self {
        self.max_str_len = max;
        self
    }

    /// How many elements of a sequence to show; `None` shows all of
    /// them. Defaults to [`DEFAULT_MAX_ARRAY_LEN`]. Byte sequences are
    /// bounded by [`max_str_len`](DisplayValue::max_str_len) instead,
    /// since they are strings in all but type.
    pub fn max_array_len(mut self, max: Option<u64>) -> Self {
        self.max_array_len = max;
        self
    }

    /// Open every pretty-mode line after the first with `prefix`, ahead
    /// of the renderer's own indentation — so a caller embedding the
    /// value under a heading gets final-form lines instead of scanning
    /// and re-copying the text to lay its margin in. The first line is
    /// the caller's to place; the value never ends with a newline.
    pub fn line_prefix(mut self, prefix: &'r str) -> Self {
        self.prefix = prefix;
        self
    }
}

impl<'a, T: Target> fmt::Display for DisplayValue<'_, 'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ctx = RenderCtx {
            depth: 0,
            max_depth: self.max_depth,
            proc: self.proc,
            visited: Some(&self.visited),
            hex_integers: false,
            ugly: self.ugly,
            elide: self.elide,
            annotate: self.annotate,
            heap: self.heap,
            max_str_len: self.max_str_len,
            max_array_len: self.max_array_len,
            prefix: self.prefix,
            formats: &self.formats,
            // A collection only fans out when its entries read through a
            // target; the bytes in hand render inline.
            parallel: self.proc.is_some(),
        };
        write_display_value(f, self.info, ctx, f.alternate())
    }
}

impl<'a> Value<'a> {
    /// Format this value from the bytes in hand, reading nothing: a pointer
    /// shows its bare address. This is the view the renderer itself switches
    /// to for a non-following [`DisplayNode::Alias`] (an atomic's snapshot);
    /// tests drive it directly, but a caller always attaches a target —
    /// [`Value::display_from_target`] is the production entry.
    #[cfg(test)]
    pub(crate) fn display(&self) -> DisplayValue<'_, 'a, crate::testhelper::FakeMem> {
        DisplayValue {
            info: self,
            proc: None,
            max_depth: DEFAULT_DEPTH,
            ugly: false,
            elide: None,
            annotate: None,
            heap: None,
            max_str_len: Some(DEFAULT_MAX_STR_LEN),
            max_array_len: Some(DEFAULT_MAX_ARRAY_LEN),
            prefix: "",
            visited: RefCell::new(HashSet::default()),
            formats: FormatCache::default(),
        }
    }

    /// Format this value while recursively reading typed pointees from a
    /// target. Pointer traversal consumes one level of the depth budget.
    pub fn display_from_target<'r, T: Target>(
        &'r self,
        proc: &'a T,
        max_depth: usize,
    ) -> DisplayValue<'r, 'a, T> {
        DisplayValue {
            info: self,
            proc: Some(proc),
            max_depth,
            ugly: false,
            elide: None,
            annotate: None,
            heap: None,
            max_str_len: Some(DEFAULT_MAX_STR_LEN),
            max_array_len: Some(DEFAULT_MAX_ARRAY_LEN),
            prefix: "",
            visited: RefCell::new(HashSet::default()),
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
///
/// `'buf` is the pass's own state — the cycle guard, the format cache, the
/// caller's overrides — while `'a` is the value lifetime: the reader sits
/// there rather than at `'buf` because a pointer followed mid-render becomes
/// a [`Value`] of the same value lifetime as the one being rendered, and
/// its bytes are the read's.
pub(crate) struct RenderCtx<'buf, 'a, T> {
    depth: usize,
    max_depth: usize,
    proc: Option<&'a T>,
    visited: Option<&'buf RefCell<HashSet<(u64, &'a str)>>>,
    /// Where this pass memoizes resolved display programs.
    formats: &'buf FormatCache<'a>,
    /// Whether a collection may fan its entries out across worker
    /// threads. True at the root of a target-backed render; the
    /// collection that spends it hands its workers `false`, so fan-out
    /// happens once, at the outermost eligible sequence.
    parallel: bool,
    hex_integers: bool,
    /// Suppress every type's own [`DisplayNode::resolve`] and
    /// render purely through [`classify`](BundleType::classify) — the "ugly",
    /// structural view. Propagates to nested values, so a whole subtree
    /// renders without custom formatters once set.
    ugly: bool,
    /// Render-time adjustment of what renders as `<elided>`; `None` leaves
    /// the bundle's choices alone.
    elide: Option<&'buf ElideOverride>,
    /// Labels for pointer addresses; see
    /// [`DisplayValue::annotate_addrs`].
    annotate: Option<&'buf AddrAnnotator<'buf>>,
    /// The target's own allocator, where it keeps metadata this session
    /// could read; see [`DisplayValue::heap`]. `None` believes the bytes.
    pub(crate) heap: Option<&'buf dyn Heap>,
    /// How much of a string to show; see [`DisplayValue::max_str_len`].
    pub(crate) max_str_len: Option<u64>,
    /// How many elements of a sequence to show; see
    /// [`DisplayValue::max_array_len`].
    pub(crate) max_array_len: Option<u64>,
    /// Text opening every pretty-mode line after the first, written by
    /// [`write_indent`] ahead of the depth indentation; see
    /// [`DisplayValue::line_prefix`]. Empty for a bare display.
    prefix: &'buf str,
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
    /// elided), and a pattern matches the folded display spelling as
    /// well as the raw one — so any name the output prints can be
    /// pasted back, kind word and all.
    pub types: Vec<String>,
    /// The bundle's impl-path substitutions, so the folded spelling a
    /// pattern is matched against is the one the output prints. The
    /// caller that builds the override holds the bundle; the renderer
    /// down here does not.
    pub impls: hansei_bundle::names::ImplFold,
}

impl ElideOverride {
    /// Whether the value type named `name` is forced to `<elided>`.
    fn forces(&self, name: &str) -> bool {
        if self.types.is_empty() {
            return false;
        }
        // The raw spelling and the folded one output displays are one
        // type to the user, so a pattern matches against either — and a
        // displayed name pasted whole carries the kind word the display
        // joined, so a spec sheds one before comparing.
        let raw = hansei_bundle::symbols::normalized_rust_type_name(name);
        let folded = hansei_bundle::names::fold_type_name(name, &self.impls);
        let folded = hansei_bundle::symbols::normalized_rust_type_name(&folded);
        let spellings: &[&str] = if folded == raw {
            &[&raw]
        } else {
            &[&raw, &folded]
        };
        self.types.iter().any(|spec| {
            let spec = hansei_bundle::names::strip_kind_prefix(spec);
            let spec = hansei_bundle::symbols::normalized_rust_type_name(spec);
            spellings.iter().any(|name| {
                if spec.contains('*') {
                    glob_match(&spec, name)
                } else {
                    let base = name.split_once('<').map_or(*name, |(base, _)| base);
                    spec == *name || spec == base
                }
            })
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

// Derived `Copy`/`Clone` would demand `T: Copy` even though only `&T` is
// held, so both are spelled out.
impl<T> Copy for RenderCtx<'_, '_, T> {}
impl<T> Clone for RenderCtx<'_, '_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'buf, 'a, T> RenderCtx<'buf, 'a, T> {
    /// The `Send + Sync` slice of this context, from which a worker
    /// thread rebuilds a context of its own around task-local caches.
    pub(crate) fn for_workers(&self) -> WorkerCtx<'buf, 'a, T> {
        WorkerCtx {
            depth: self.depth,
            max_depth: self.max_depth,
            proc: self.proc,
            hex_integers: self.hex_integers,
            ugly: self.ugly,
            elide: self.elide,
            annotate: self.annotate,
            heap: self.heap,
            max_str_len: self.max_str_len,
            max_array_len: self.max_array_len,
            prefix: self.prefix,
        }
    }

    /// Whether the allocator says `addr` names memory it has taken back.
    ///
    /// The verdict is the allocator's alone: `false` covers both "the
    /// block is still handed out" and "there is no allocator to ask",
    /// because a render with nothing to corroborate against must read
    /// exactly what it always read.
    pub(crate) fn freed(&self, addr: u64) -> bool {
        let Some(heap) = self.heap else {
            return false;
        };
        let freed = matches!(heap.locate(addr), Liveness::Freed);
        if freed {
            heap.note(Gate::Freed);
        }
        freed
    }

    /// The type's resolved display program. Resolving reduces the bundle's
    /// name-addressed selectors to byte offsets and allocates the resolved
    /// tree, so a pass carrying a cache pays that once per type rather than
    /// once per value — a map of ten thousand `String`s asks ten thousand
    /// times and resolves once.
    fn debug_format(&self, ty: &BundleType<'a>) -> Option<Rc<DisplayNode<'a>>> {
        let key = ty.id();
        if let Some(hit) = self.formats.borrow().get(&key) {
            return hit.clone();
        }
        let resolved = DisplayNode::resolve(*ty).map(Rc::new);
        self.formats.borrow_mut().insert(key, resolved.clone());
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
}

impl<'a, T: Target> RenderCtx<'_, 'a, T> {
    /// Read `size` bytes at `addr`, refusing outright the memory the
    /// allocator says has been freed. Every read the renderer makes
    /// through a pointer goes through here, so a stale pointer is
    /// declined once, in one place, whichever formatter followed it.
    ///
    /// `Err` carries the degradation marker to print in the value's
    /// place, the way the reads it replaces already did.
    pub(crate) fn read(&self, addr: u64, size: u64) -> Result<&'a [u8], &'static str> {
        let proc = self.proc.ok_or("<target unavailable>")?;
        if self.freed(addr) {
            return Err("<freed>");
        }
        proc.read_bytes(addr, size).map_err(|_| "<unreadable>")
    }
}

/// Render one value. This is also how a renderer recurses into a child:
/// called directly, with `pretty` passed along rather than re-encoded as
/// a `{:#}` format spec — re-entering `core::fmt::write` per child value
/// costs an `Arguments` and several frames at every level of a tree this
/// renders millions of nodes of.
pub(crate) fn write_display_value<'a, T: Target>(
    f: &mut fmt::Formatter<'_>,
    info: &Value<'a>,
    ctx: RenderCtx<'_, 'a, T>,
    pretty: bool,
) -> fmt::Result {
    let ty = info.ty;
    let bytes = info.bytes;

    if bytes.is_empty() && ty.size() == 0 {
        return f.write_str(ty.name());
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
            f.write_str(ty.name())?;
            f.write_str(": ")?;
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
                return f.write_str(if bytes[0] != 0 { "true" } else { "false" });
            }

            if is_char {
                let ch = bytes[0];
                return if ch.is_ascii_graphic() || ch == b' ' {
                    write!(f, "'{}'", ch as char)
                } else {
                    f.write_str("'\\x")?;
                    f.write_str(hex_pair(ch))?;
                    f.write_str("'")
                };
            }

            // A width with no whole-word reading (`read_unsigned_at` knows
            // 1, 2, 4 and 8) dumps its bytes.
            let Some(word) = read_unsigned_at(bytes, 0, size) else {
                return write_hex_bytes(f, bytes);
            };
            if ctx.hex_integers {
                write_hex_fixed(f, word, size as usize)
            } else if is_signed {
                // Sign-extend the word from its own width to i64.
                let shift = 64 - 8 * size as u32;
                write!(f, "{}", ((word as i64) << shift) >> shift)
            } else {
                write!(f, "{}", word)
            }
        }

        TypeClass::Float { size } => match size {
            4 => write!(f, "{}", f32::from_le_bytes(bytes[..4].try_into().unwrap())),
            8 => write!(f, "{}", f64::from_le_bytes(bytes[..8].try_into().unwrap())),
            _ => write_hex_bytes(f, bytes),
        },

        TypeClass::Pointer { target } => {
            let Some(addr) = read_u64_at(bytes, 0) else {
                return write!(f, "<truncated>");
            };
            if addr == 0 {
                return write!(f, "null");
            }
            // A pointer to a zero-sized type (e.g. `RawWaker`'s `*const ()`
            // data pointer) has no meaningful pointee to follow — reading it
            // would only ever print the type's name (`-> ()`). Show just the
            // address, or the annotator's name for it.
            if target.size() == 0 {
                return write_addr_or_label(f, addr, ctx.annotate);
            }
            let (Some(_), Some(visited)) = (ctx.proc, ctx.visited) else {
                return write_addr_or_label(f, addr, ctx.annotate);
            };
            let key = (addr, target.name());
            if !visited.borrow_mut().insert(key) {
                write_annotated_addr(f, addr, ctx.annotate)?;
                return f.write_str(" -> <cycle>");
            }
            let result = match ctx.read(addr, target.size()) {
                Ok(pointee_bytes) => {
                    let pointee = Value {
                        ty: target,
                        addr,
                        bytes: pointee_bytes,
                    };
                    write_annotated_addr(f, addr, ctx.annotate)
                        .and_then(|()| f.write_str(" -> "))
                        .and_then(|()| write_display_value(f, &pointee, ctx.deeper(), pretty))
                }
                Err(marker) => write_annotated_addr(f, addr, ctx.annotate)
                    .and_then(|()| f.write_str(" -> "))
                    .and_then(|()| f.write_str(marker)),
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
            if let Some(Ok(active)) = ty.active_variant(bytes) {
                write!(f, "{}", active.name)
            } else {
                write_hex_bytes(f, bytes)
            }
        }

        TypeClass::Array { element, count } => {
            let elem_size = element.size() as usize;
            // An inline array's count is the type's, not the target's,
            // so it cannot be fabricated the way a fat pointer's length
            // can — but a declared `[u64; 1_000_000]` still costs a
            // million lines to print, and the budget is about what a
            // render costs rather than about whether to believe it.
            // Byte arrays spend the string budget, as byte slices do.
            let declared = count;
            let cap = match elem_size {
                1 => ctx.max_str_len,
                _ => ctx.max_array_len,
            };
            let count = cap.map_or(declared, |cap| declared.min(cap)) as usize;
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
                write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, i == 0)?;
                let Some(elem_bytes) = bytes.get(start..end) else {
                    // Unreachable for a backend whose array size agrees with
                    // its element size times count, which the guard at the top
                    // of this function has already checked the buffer against.
                    // Kept because the slice is fallible and a backend that
                    // disagreed must degrade rather than read past the end.
                    write!(f, "<truncated>")?;
                    break;
                };
                let child = Value {
                    ty: element,
                    addr: info.addr + start as u64,
                    bytes: elem_bytes,
                };
                write_display_value(f, &child, ctx.deeper().with_hex(hex_elements), pretty)?;
                if pretty {
                    write!(f, ",")?;
                }
            }
            if (count as u64) < declared {
                write_seq_prefix(f, pretty, ctx.prefix, ctx.depth, false)?;
                write!(f, "<{} more not shown>", declared - count as u64)?;
            }
            write_seq_close(f, pretty, ctx.prefix, ctx.depth, count > 0)?;
            write!(f, "]")
        }

        TypeClass::Opaque => write_named_bytes(f, ty.name(), bytes),
    }
}

/// Open a pretty-mode line: the caller's line prefix, then four spaces
/// per depth level. Every newline the renderer writes is followed by
/// this, which is what lets a caller get final-form lines out of
/// [`DisplayValue::line_prefix`] instead of re-indenting them.
/// The spaces come off a static run in slices as large as it allows,
/// not a write per level.
pub(crate) fn write_indent(f: &mut fmt::Formatter<'_>, prefix: &str, depth: usize) -> fmt::Result {
    const SPACES: &str = match str::from_utf8(&[b' '; 256]) {
        Ok(spaces) => spaces,
        Err(_) => unreachable!(),
    };
    f.write_str(prefix)?;
    let mut pending = depth * 4;
    while pending > 0 {
        let run = pending.min(SPACES.len());
        f.write_str(&SPACES[..run])?;
        pending -= run;
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
    prefix: &str,
    depth: usize,
    first: bool,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, prefix, depth + 1)
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
    prefix: &str,
    depth: usize,
    any: bool,
) -> fmt::Result {
    if pretty && any {
        writeln!(f)?;
        write_indent(f, prefix, depth)?;
    }
    Ok(())
}

/// Prefix punctuation before one field of a `Name { field, … }` record body.
/// In pretty mode: a newline and one deeper indent. Inline: the space after
/// the opening brace for the first field (`first`), a `, ` separator for the
/// rest. Shared by the struct, aggregate, and map renderers.
pub(crate) fn write_field_prefix(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    prefix: &str,
    depth: usize,
    first: bool,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, prefix, depth + 1)
    } else if first {
        f.write_str(" ")
    } else {
        f.write_str(", ")
    }
}

/// Whitespace closing a `Name { … }` record body, written before the caller's
/// `}`. In pretty mode, a newline and an indent back to `depth` so the brace
/// lines up with the opener; inline, the space separating it from the last
/// field.
pub(crate) fn write_record_close(
    f: &mut fmt::Formatter<'_>,
    pretty: bool,
    prefix: &str,
    depth: usize,
) -> fmt::Result {
    if pretty {
        writeln!(f)?;
        write_indent(f, prefix, depth)
    } else {
        f.write_str(" ")
    }
}

/// `Name [0x…]` — the type's name (when it has one) over a raw byte dump,
/// the fallback for an opaque and for an enum that cannot be decoded.
pub(crate) fn write_named_bytes(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    bytes: &[u8],
) -> fmt::Result {
    if !name.is_empty() {
        write!(f, "{} ", name)?;
    }
    write_hex_bytes(f, bytes)
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// All 256 byte values as two lowercase hex digits, concatenated:
/// `"000102…feff"`. [`hex_pair`] slices it, so a byte's digits come off
/// a static string instead of through the `fmt` integer machinery —
/// hex is written per byte in enough loops for `LowerHex`'s share of
/// render CPU to show in profiles.
const HEX_PAIRS: &str = {
    const BYTES: [u8; 512] = {
        let mut table = [0u8; 512];
        let mut i = 0;
        while i < 256 {
            table[i * 2] = HEX_DIGITS[i >> 4];
            table[i * 2 + 1] = HEX_DIGITS[i & 0xf];
            i += 1;
        }
        table
    };
    match str::from_utf8(&BYTES) {
        Ok(pairs) => pairs,
        Err(_) => unreachable!(),
    }
};

/// The two lowercase hex digits of `byte`.
pub(crate) fn hex_pair(byte: u8) -> &'static str {
    &HEX_PAIRS[byte as usize * 2..byte as usize * 2 + 2]
}

/// A followed pointer's address, with the caller's label after it when an
/// annotator claims it: `0x… (label)`. The address stays first because the
/// pointee it introduces is about to be rendered against it.
pub(crate) fn write_annotated_addr(
    f: &mut fmt::Formatter<'_>,
    addr: u64,
    annotate: Option<&AddrAnnotator<'_>>,
) -> fmt::Result {
    write_hex_u64(f, addr)?;
    if let Some(label) = annotate.and_then(|annotate| annotate(addr)) {
        f.write_str(" (")?;
        f.write_str(&label)?;
        f.write_str(")")?;
    }
    Ok(())
}

/// A pointer rendered as only its bare word — a zero-sized pointee, an
/// alias snapshot. Here the label *is* the value's meaning (a task waker's
/// data word means "that task"), so it replaces the hex; the address is
/// the fallback when the annotator has no name for it.
pub(crate) fn write_addr_or_label(
    f: &mut fmt::Formatter<'_>,
    addr: u64,
    annotate: Option<&AddrAnnotator<'_>>,
) -> fmt::Result {
    match annotate.and_then(|annotate| annotate(addr)) {
        Some(label) => f.write_str(&label),
        None => write_hex_u64(f, addr),
    }
}

/// `0x` and `value` in minimal-width lowercase hex — `0x{value:x}`
/// without the `Arguments` interpreter and `pad_integral` behind
/// `write!`, which every followed pointer would otherwise pay.
pub(crate) fn write_hex_u64(f: &mut fmt::Formatter<'_>, value: u64) -> fmt::Result {
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    let mut v = value;
    loop {
        i -= 1;
        buf[i] = HEX_DIGITS[(v & 0xf) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    f.write_str("0x")?;
    f.write_str(str::from_utf8(&buf[i..]).unwrap_or("<bad hex>"))
}

/// `0x` and the low `width` bytes of `value` in zero-padded lowercase
/// hex, most significant first — the `0x{value:04x}`-style spellings
/// the fixed-width integer renderings use.
pub(crate) fn write_hex_fixed(f: &mut fmt::Formatter<'_>, value: u64, width: usize) -> fmt::Result {
    f.write_str("0x")?;
    for i in (0..width).rev() {
        f.write_str(hex_pair((value >> (i * 8)) as u8))?;
    }
    Ok(())
}

pub(crate) fn write_hex_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("[")?;
    for (i, b) in bytes.iter().enumerate() {
        f.write_str(if i == 0 { "0x" } else { ", 0x" })?;
        f.write_str(hex_pair(*b))?;
    }
    f.write_str("]")
}

// ---------------------------------------------------------------------------
// ParseCtx & ParseWithDbgInfo
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;

    use hansei_bundle::BundleView;

    #[test]
    fn test_ugly_suppresses_custom_formatters() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        // A `Scalar` format (`RawMutex`) renders its decoded bits normally, but
        // `--ugly` shows the underlying struct field.
        let mutex = Value::new(v.ty(RAW_MUTEX).unwrap(), 0, &[1u8]);
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
        let s = Value::new(v.ty(STR).unwrap(), 0, &str_bytes);
        assert_eq!(
            format!("{}", s.display().ugly()),
            "&str { data_ptr: 0x3000, length: 8 }"
        );
    }

    /// An array with no elements closes on the opening line even in pretty
    /// mode — the break-and-indent close belongs only to a populated one.
    #[test]
    fn test_an_empty_array_closes_without_a_line_break() {
        let mut b = test_bundle();
        let hansei_bundle::TypeDef::Array { count, .. } = &mut b.types.types[ARR.0 as usize] else {
            panic!("ARR is not an array");
        };
        *count = 0;
        b.validate().expect("empty array must validate");

        let v = BundleView::new(&b);
        // The type is zero-sized but the buffer is not, so the rendering
        // reaches the array body rather than the unit shortcut.
        let bytes = [0u8; 4];
        let value = Value::new(v.ty(ARR).unwrap(), 0, &bytes);
        assert_eq!(format!("{:#}", value.display().depth(4)), "[]");
    }

    #[test]
    fn test_integer_arrays_display_as_zero_padded_hex() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let bytes: Vec<u8> = [1u32, 0xabcdef, u32::MAX]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let array = Value::new(v.ty(ARR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", array.display()),
            "[0x00000001, 0x00abcdef, 0xffffffff]"
        );

        let bytes: Vec<u8> = [1u64, 0xabcdef, u64::MAX]
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let array = Value::new(v.ty(VTABLE_ARRAY).unwrap(), 0, &bytes);
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
        let root = Value::new(v.ty(NODE_PTR).unwrap(), 0, &bytes);
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
        let show =
            |id, bytes: &[u8]| format!("{}", Value::new(v.ty(id).unwrap(), 0, bytes).display());

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
                Value::new(v.ty(CHAR).unwrap(), 0, &c.to_le_bytes()).display()
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
    /// the name lookup can never succeed through the current `BundleType`
    /// interface.
    #[test]
    fn test_c_enum_falls_back_to_hex_bytes() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let color = v.ty(COLOR).unwrap();
        assert!(color.active_variant(&1u32.to_le_bytes()).is_none());
        assert_eq!(
            format!("{}", Value::new(color, 0, &1u32.to_le_bytes()).display()),
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
        let short = Value::new(v.ty(POINT).unwrap(), 0, &[0u8; 4]);
        assert_eq!(format!("{}", short.display()), "<truncated>");

        // `[u32; 3]` is 12 bytes; two elements' worth does not render partially.
        let arr = Value::new(v.ty(ARR).unwrap(), 0, &[1u8, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(format!("{}", arr.display()), "<truncated>");
    }

    /// The depth budget stops recursion with `...` rather than rendering an
    /// unbounded tree, and one more level of budget renders one more level.
    #[test]
    fn test_depth_budget_truncates_with_ellipsis() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let point = Value::new(v.ty(POINT).unwrap(), 0, &bytes);

        // Depth 0 has no budget for the value itself.
        assert_eq!(format!("{}", point.display().depth(0)), "...");
        // Depth 1 renders the struct but not its fields.
        assert_eq!(
            format!("{}", point.display().depth(1)),
            "Point { x: ..., y: ... }"
        );
        // Depth 2 reaches the leaves.
        assert_eq!(
            format!("{}", point.display().depth(2)),
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
                Value::new(ptr, 0, &head).display_from_target(&unreadable, 16)
            ),
            "0x100 -> <unreadable>"
        );
        assert_eq!(
            format!(
                "{}",
                Value::new(ptr, 0, &head).display_from_target(&self_cycle, 16)
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
            Value::new(two, 0, &pair).display_from_target(&diamond, 16)
        );
        assert_eq!(
            shown,
            "Node { value: 1, next: 0x300 -> Node { value: 9, next: null } }"
        );
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
        let value = Value::new(v.ty(VEC).unwrap(), 0, &bytes);

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
        let ptr = Value::new(v.ty(PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{:#}", ptr.display_from_target(&mem, 8)),
            "0x2000 -> Point {\n        x: 3,\n        y: 4,\n    }"
        );

        // Three levels of record nesting, from the structural view of a type
        // whose own formatter would otherwise flatten it.
        let notify = Value::new(v.ty(NOTIFY).unwrap(), 0, &[0u8; 32]);
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
        let value = Value::new(v.ty(VEC).unwrap(), 0, &fat);
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
                Value::new(bool_ty, 0, std::slice::from_ref(&byte)).display()
            )
        };
        assert_eq!(show(0), "false");
        assert_eq!(show(1), "true");
        // Not a comparison against 1: a byte that is neither is still true.
        assert_eq!(show(7), "true");

        assert_eq!(
            format!("{}", Value::new(v.ty(UNIT).unwrap(), 0, &[]).display()),
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
        let show = |bytes: &[u8]| format!("{}", Value::new(ptr, 0, bytes).display());

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
        let show =
            |id, bytes: &[u8]| format!("{}", Value::new(v.ty(id).unwrap(), 0, bytes).display());
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

    /// `line_prefix` opens every pretty line after the first with the
    /// caller's text, ahead of the renderer's own four-space grid — the
    /// contract that lets hansei stream value lines through unmodified.
    /// The first line stays bare (the caller places it), no line ends in
    /// a trailing newline, and the prefix crosses the parallel fan-out:
    /// a long slice renders the same lines chunked as streamed.
    #[test]
    fn test_line_prefix_opens_every_line_but_the_first() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let mem = FakeMem::new().at(0x2000, u32s(&[3, 4]));
        let bytes = 0x2000u64.to_le_bytes();
        let ptr = Value::new(v.ty(PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{:#}", ptr.display_from_target(&mem, 8).line_prefix(">> ")),
            "0x2000 -> Point {\n>>         x: 3,\n>>         y: 4,\n>>     }"
        );

        let values: Vec<u32> = (0..100).collect();
        let mem = FakeMem::new().at(0x3000, u32s(&values));
        let fat = u64s(&[0x3000, 100, 100]);
        let vec = Value::new(v.ty(VEC).unwrap(), 0, &fat);
        let shown = format!("{:#}", vec.display_from_target(&mem, 8).line_prefix(">> "));
        let mut lines = shown.lines();
        assert_eq!(lines.next(), Some("["));
        for (i, line) in lines.enumerate() {
            assert!(line.starts_with(">> "), "line {i} unprefixed: {line:?}");
        }
        assert!(shown.ends_with(">> ]"), "{shown}");
    }

    /// An address annotator labels the pointers it claims — followed,
    /// unreadable, or bare — and leaves null and unclaimed ones alone.
    #[test]
    fn test_annotator_labels_the_addresses_it_claims() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let annotate = |addr: u64| (addr == 0x2000).then(|| "task 7".to_string());

        // Followed: the label sits between the address and the pointee.
        let mem = FakeMem::new().at(0x2000, u32s(&[3, 4]));
        let bytes = 0x2000u64.to_le_bytes();
        let ptr = Value::new(v.ty(PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!(
                "{}",
                ptr.display_from_target(&mem, 8).annotate_addrs(&annotate)
            ),
            "0x2000 (task 7) -> Point { x: 3, y: 4 }"
        );

        // Unreadable: the label still identifies where the pointer aims.
        let unreadable = FakeMem::new().unreadable();
        assert_eq!(
            format!(
                "{}",
                ptr.display_from_target(&unreadable, 8)
                    .annotate_addrs(&annotate)
            ),
            "0x2000 (task 7) -> <unreadable>"
        );

        // An address the annotator does not claim renders bare, and null
        // is never offered to it.
        let elsewhere = FakeMem::new().at(0x3000, u32s(&[1, 2]));
        let bytes = 0x3000u64.to_le_bytes();
        let other = Value::new(v.ty(PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!(
                "{}",
                other
                    .display_from_target(&elsewhere, 8)
                    .annotate_addrs(&annotate)
            ),
            "0x3000 -> Point { x: 1, y: 2 }"
        );
        let null = 0u64.to_le_bytes();
        let null_ptr = Value::new(v.ty(PTR).unwrap(), 0, &null);
        assert_eq!(
            format!(
                "{}",
                null_ptr
                    .display_from_target(&elsewhere, 8)
                    .annotate_addrs(&|_| Some("never".to_string()))
            ),
            "null"
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
        // A mismatch on the first character after a leading `*` widens the
        // star from a zero-length match.
        assert!(glob_match("*z", "az"));

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
            ..Default::default()
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

    /// The folded spellings the listings print are accepted back: the
    /// short std path, the env-folded coroutine name, and either with
    /// the kind word the display joined still attached.
    #[test]
    fn test_forces_accepts_the_displayed_spelling() {
        use super::ElideOverride;

        let elide = |spec: &str| ElideOverride {
            no_elide: false,
            types: vec![spec.to_owned()],
            ..Default::default()
        };
        assert!(elide("Vec<u8>").forces("alloc::vec::Vec<u8, alloc::alloc::Global>"));
        assert!(elide("Vec").forces("alloc::vec::Vec<u8, alloc::alloc::Global>"));
        assert!(elide("app::work").forces("app::work::{async_fn_env#0}"));
        assert!(elide("async fn app::work").forces("app::work::{async_fn_env#0}"));
        assert!(elide("future tokio::time::Sleep").forces("tokio::time::Sleep"));
        // The raw spelling still names the type it always did.
        assert!(elide("app::work::{async_fn_env#0}").forces("app::work::{async_fn_env#0}"));
        // Folding is a fold, not a licence: another crate's Vec is not
        // std's.
        assert!(!elide("Vec<u8>").forces("myalloc::vec::Vec<u8>"));
    }

    /// With the bundle's impl substitutions on the override, a spec in
    /// the folded spelling matches the raw impl-path name the bundle
    /// records — and without them, it does not pretend to.
    #[test]
    fn test_forces_accepts_the_impl_folded_spelling() {
        use super::ElideOverride;

        let elide = |spec: &str, impls| ElideOverride {
            no_elide: false,
            types: vec![spec.to_owned()],
            impls,
        };
        let impls = || {
            hansei_bundle::names::ImplFold::from_pairs([(
                "tokio::sync::mutex::{impl#10}",
                "tokio::sync::mutex::Mutex",
            )])
        };
        let raw = "tokio::sync::mutex::{impl#10}::lock::{async_fn_env#0}<()>";
        assert!(elide("tokio::sync::mutex::Mutex::lock<()>", impls()).forces(raw));
        assert!(elide("async fn tokio::sync::mutex::Mutex::lock<()>", impls()).forces(raw));
        assert!(elide(raw, impls()).forces(raw));
        assert!(!elide("tokio::sync::mutex::Mutex::lock<()>", Default::default()).forces(raw));
    }

    /// A pointer into memory the allocator has taken back is not
    /// followed: the address still prints, and what would have been the
    /// value behind it is the mark instead — the way an unreadable
    /// target is already marked. Without the allocator to ask, the same
    /// bytes render as the value they claim to be, which is the whole
    /// reason the gate exists.
    #[test]
    fn test_a_pointer_into_freed_memory_is_not_expanded() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x300, node_bytes(9, 0));
        let ptr = v.ty(NODE_PTR).unwrap();
        let head = 0x300u64.to_le_bytes();
        let shown = |heap: &FakeHeap| {
            format!(
                "{}",
                Value::new(ptr, 0, &head)
                    .display_from_target(&mem, 16)
                    .heap(heap)
            )
        };

        let freed = FakeHeap::new().freed(0x300, 32);
        assert_eq!(shown(&freed), "0x300 -> <freed>");
        assert_eq!(freed.counts(), (1, 0, 0));

        // The same read against a live block, and against an address the
        // allocator accounts for at all, is the ordinary one.
        let live = FakeHeap::new().live(0x300, 32);
        assert_eq!(shown(&live), "0x300 -> Node { value: 9, next: null }");
        assert_eq!(live.counts(), (0, 0, 0));

        assert_eq!(
            format!(
                "{}",
                Value::new(ptr, 0, &head).display_from_target(&mem, 16)
            ),
            "0x300 -> Node { value: 9, next: null }"
        );
    }

    /// A sequence is believed no further than the allocation its buffer
    /// starts in: the elements that fit render, and the length the value
    /// claimed is reported rather than served. The pages past the
    /// allocation are readable — they belong to somebody — which is
    /// exactly what nothing but the allocator could have caught.
    #[test]
    fn test_a_sequence_is_cut_to_its_allocation() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13, 21, 34]));
        // A `Vec<u32>` claiming five elements out of a 12-byte block.
        let header = u64s(&[0x2000, 5, 5]);
        let vec = Value::new(v.ty(VEC).unwrap(), 0x1000, &header);
        let heap = FakeHeap::new().live(0x2000, 12);
        assert_eq!(
            format!("{}", vec.display_from_target(&mem, 8).heap(&heap)),
            "[5, 8, 13, <2 more past its allocation>]"
        );
        assert_eq!(heap.counts(), (0, 1, 0));

        // The same claim with the allocation big enough is served whole.
        let roomy = FakeHeap::new().live(0x2000, 20);
        assert_eq!(
            format!("{}", vec.display_from_target(&mem, 8).heap(&roomy)),
            "[5, 8, 13, 21, 34]"
        );
        assert_eq!(roomy.counts(), (0, 0, 0));

        // The same bound on a string, which is the shape the fiction
        // actually took: a length out of dead bytes claiming gigabytes
        // of somebody else's address space.
        let text = FakeMem::new().at(0x4000, b"hello, world".to_vec());
        let header = u64s(&[0x4000, 12, 12]);
        let value = Value::new(v.ty(STRING).unwrap(), 0x1000, &header);
        let heap = FakeHeap::new().live(0x4000, 5);
        assert_eq!(
            format!("{}", value.display_from_target(&text, 8).heap(&heap)),
            "\"hello\" <7 more bytes past its allocation>"
        );
        assert_eq!(heap.counts(), (0, 1, 0));
    }

    /// A sequence whose buffer has been freed renders no elements at
    /// all: a length and a pointer out of dead bytes describe nothing,
    /// and a partial read of them would be fiction with a count on it.
    #[test]
    fn test_a_freed_sequence_buffer_serves_nothing() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x2000, u32s(&[5, 8, 13]))
            .at(0x3000, b"hello".to_vec());
        let heap = FakeHeap::new().freed(0x2000, 12).freed(0x3000, 8);

        let vec_header = u64s(&[0x2000, 3, 3]);
        let vec = Value::new(v.ty(VEC).unwrap(), 0x1000, &vec_header);
        assert_eq!(
            format!("{}", vec.display_from_target(&mem, 8).heap(&heap)),
            "<freed slice buffer>"
        );

        let text_header = u64s(&[0x3000, 5, 8]);
        let text = Value::new(v.ty(STRING).unwrap(), 0x1000, &text_header);
        assert_eq!(
            format!("{}", text.display_from_target(&mem, 8).heap(&heap)),
            "<freed string data>"
        );
        assert_eq!(heap.counts(), (2, 0, 0));
    }

    /// A string is shown only as far as the cap, and says how much it
    /// is not showing.
    ///
    /// This is the bound that keeps a corrupt length from costing
    /// gigabytes to print: the cap is on the *read*, so the target is
    /// never asked for the pages the header claims, and the escaped
    /// rendering of them is never built. Nothing is wrong with the
    /// bytes past it, so the shortfall does not say there is.
    #[test]
    fn test_a_string_is_shown_only_to_the_cap() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, b"hello, world".to_vec());
        let header = u64s(&[0x2000, 12, 12]);
        let value = Value::new(v.ty(STRING).unwrap(), 0x1000, &header);
        let shown = |cap| format!("{}", value.display_from_target(&mem, 8).max_str_len(cap));

        assert_eq!(shown(Some(5)), "\"hello\" <7 more bytes not shown>");
        // At and above the length the cap is invisible: a string that
        // fits says nothing about a bound it never reached.
        assert_eq!(shown(Some(12)), "\"hello, world\"");
        assert_eq!(shown(Some(u64::MAX)), "\"hello, world\"");
        assert_eq!(shown(None), "\"hello, world\"");
        // A cap of zero asks for nothing and says so, rather than
        // reading as an empty string or a failed read.
        assert_eq!(shown(Some(0)), "\"\" <12 bytes not shown>");
    }

    /// The cap is the renderer's own choice, so it must not be confused
    /// with the target refusing bytes or the allocator disowning them —
    /// each shortfall says which it was.
    #[test]
    fn test_the_three_shortfalls_are_spelled_apart() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let header = u64s(&[0x2000, 12, 12]);
        let value = Value::new(v.ty(STRING).unwrap(), 0x1000, &header);

        // Only five bytes are there to serve, and the cap is not
        // reached: the target is what came up short.
        let short = FakeMem::new().at(0x2000, b"hello".to_vec());
        assert_eq!(
            format!("{}", value.display_from_target(&short, 8)),
            "\"hello\" <7 more bytes unreadable>"
        );

        // All twelve are readable, but the allocation holding them
        // ends after five.
        let mem = FakeMem::new().at(0x2000, b"hello, world".to_vec());
        let heap = FakeHeap::new().live(0x2000, 5);
        assert_eq!(
            format!("{}", value.display_from_target(&mem, 8).heap(&heap)),
            "\"hello\" <7 more bytes past its allocation>"
        );

        // And the cap, which is none of the above.
        assert_eq!(
            format!(
                "{}",
                value.display_from_target(&mem, 8).max_str_len(Some(5))
            ),
            "\"hello\" <7 more bytes not shown>"
        );
    }

    /// A buffer that owns its whole allocation is expected to start at
    /// one. A mismatch is counted and nothing else: it is evidence about
    /// a pointer, and the value still renders. A borrowed slice, which
    /// legitimately points into the middle of somebody else's
    /// allocation, is not held to it at all.
    #[test]
    fn test_an_owning_buffer_off_its_base_is_counted_only() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x2000, u32s(&[5, 8, 13]));
        // The block starts below the buffer, as it would with a malloc
        // header — but the pointer is further in still, so it owns
        // nothing.
        let heap = FakeHeap::new().live_at(0x1f00, 0x200, 0x1f10);

        let vec_header = u64s(&[0x2000, 3, 3]);
        let vec = Value::new(v.ty(VEC).unwrap(), 0x1000, &vec_header);
        assert_eq!(
            format!("{}", vec.display_from_target(&mem, 8).heap(&heap)),
            "[5, 8, 13]"
        );
        assert_eq!(heap.counts(), (0, 0, 1));

        // A `&[T]` carries no capacity, so it is not an owning pointer
        // and the same address is no evidence of anything.
        let borrowed = FakeHeap::new().live_at(0x1f00, 0x200, 0x1f10);
        let slice_header = u64s(&[0x2000, 3]);
        let slice = Value::new(v.ty(SLICE).unwrap(), 0x1000, &slice_header);
        assert_eq!(
            format!("{}", slice.display_from_target(&mem, 8).heap(&borrowed)),
            "[5, 8, 13]"
        );
        assert_eq!(borrowed.counts(), (0, 0, 0));

        // And a freed block is weighed for nothing but being freed:
        // the free scrubbed the header that recorded which pointer was
        // handed out, so every address in it reads as an interior one
        // and a mismatch would be an artifact of the free rather than
        // evidence about the pointer.
        let gone = FakeHeap::new().freed(0x1f00, 0x200);
        assert_eq!(
            format!("{}", vec.display_from_target(&mem, 8).heap(&gone)),
            "<freed slice buffer>"
        );
        assert_eq!(gone.counts(), (1, 0, 0));
    }
}

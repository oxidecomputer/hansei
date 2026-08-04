//! What a [`DisplayNode`] requires of the types its selectors land on.
//!
//! Every node kind has an addressing contract — a `Str`'s length is a `usize`,
//! a `Symbol` reads a pointer, a `Bytes` notation reads an array — and that
//! contract has to hold in two type universes. exegesis navigates DWARF while
//! it builds a node; validation re-checks the finished node against the
//! bundle's own [`TypeTable`](super::TypeTable) on every save and load, since a
//! bundle read back is untrusted input. Stating each requirement once here, and
//! leaving each side only the predicate for its own representation, is what
//! keeps the two from drifting apart.
//!
//! The table is the *floor*. A detector may screen more tightly than the shape
//! it declares — `&str` insists on a byte pointer where the `Str` node accepts
//! any pointer, so camino's typed one also validates — but it may not accept
//! less.

use crate::bundle::schema::{DisplayNode, MapEntries, Selector};

/// What a resolved [`Selector`] is expected to land on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Shape {
    /// A machine word: any sized type of 1..=8 bytes, which is what a scalar
    /// decode and a value expression can read.
    Word,
    /// An unsigned base type of exactly `size` bytes: an atomic word, a
    /// length, a capacity, a permit count.
    Uint(u64),
    /// Any type occupying exactly one pointer word: a niche-optimized
    /// `Option<NonNull<_>>` list head/next.
    PointerSized,
    /// Any pointer type.
    Pointer,
    /// Any array type.
    Array,
    /// No constraint on the landed type.
    Any,
}

impl std::fmt::Display for Shape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shape::Word => write!(f, "a machine word"),
            Shape::Uint(size) => write!(f, "a {size}-byte unsigned integer"),
            Shape::PointerSized => write!(f, "a pointer-sized value"),
            Shape::Pointer => write!(f, "a pointer"),
            Shape::Array => write!(f, "an array"),
            Shape::Any => write!(f, "a resolvable type"),
        }
    }
}

/// One datum a [`DisplayNode`] addresses within the value it is rendered
/// against, with the shape the datum's type must have.
pub struct Addressed<'a> {
    /// How this datum reads in a diagnostic ("a `Str`'s length").
    pub what: &'static str,
    /// The path to it, rooted at the type the node is rendered against.
    pub sel: &'a Selector,
    /// The floor its landing type must meet.
    pub shape: Shape,
    /// Whether an empty selector — the value itself — is a legal address. Only
    /// [`DisplayNode::Symbol`] allows it: a bare function pointer *is* the code
    /// pointer. Every other node must navigate at least one step away from the
    /// value it renders.
    pub root_allowed: bool,
    /// Whether the path may cross a [`Step::Variant`](super::Step::Variant).
    /// Only a datum whose read travels as a guarded place — an `Alias`, or a
    /// value-expression read — can check the enum's discriminant at render
    /// time; every other node resolves its selector to a bare offset, which
    /// would read a variant's storage without knowing it is live. Both
    /// checking sides enforce this, so such a program declines instead of
    /// silently falling back to structural display.
    pub variants_allowed: bool,
}

impl<'a> Addressed<'a> {
    fn new(what: &'static str, sel: &'a Selector, shape: Shape) -> Self {
        Addressed {
            what,
            sel,
            shape,
            root_allowed: false,
            variants_allowed: false,
        }
    }

    fn at_root(mut self) -> Self {
        self.root_allowed = true;
        self
    }

    fn guarded(mut self) -> Self {
        self.variants_allowed = true;
        self
    }
}

impl DisplayNode {
    /// Every datum this node addresses *within the value it renders*, so a
    /// caller holding that value's type can check them all in one pass.
    ///
    /// Selectors rooted somewhere else are deliberately absent: a `List`'s
    /// `next` is rooted at the list's node type, a `Pointer`'s `via` at its
    /// pointee, a `Map`'s entry walk at whichever storage type each step
    /// reached. Those roots are only known once the node is partly resolved, so
    /// their checks belong to the caller that resolves them. Nothing here
    /// recurses into a child node either — a child is rendered against a type
    /// its parent determines.
    pub fn addressed(&self) -> Vec<Addressed<'_>> {
        let word = crate::bundle::POINTER_SIZE;
        match self {
            DisplayNode::Scalar { at, .. } => {
                vec![Addressed::new("a scalar word", at, Shape::Word)]
            }
            DisplayNode::Symbol { at } => {
                vec![Addressed::new("a symbol pointer", at, Shape::Pointer).at_root()]
            }
            DisplayNode::List { head, .. } => {
                vec![Addressed::new("a list head", head, Shape::PointerSized)]
            }
            DisplayNode::Str {
                pointer,
                length,
                capacity,
            } => buffer(
                ["a string pointer", "a string length", "a string capacity"],
                pointer,
                length,
                capacity.as_ref(),
                word,
            ),
            DisplayNode::Slice {
                pointer,
                length,
                capacity,
                ..
            } => buffer(
                ["a slice pointer", "a slice length", "a slice capacity"],
                pointer,
                length,
                capacity.as_ref(),
                word,
            ),
            DisplayNode::Bytes { at, .. } => {
                vec![Addressed::new("an inline byte array", at, Shape::Array)]
            }
            DisplayNode::Alias { at, .. } => {
                // An aliased value may have any type — a peeled atomic is a
                // plain integer, a pointer, or a small struct — so the only
                // requirement is that the path resolves. An alias reads
                // through a guarded place, so it may cross a variant step.
                vec![Addressed::new("an aliased value", at, Shape::Any).guarded()]
            }
            DisplayNode::SlotCount { bitmap, slots } => vec![
                Addressed::new("a readiness bitmap", bitmap, Shape::Uint(word)),
                Addressed::new("a slot array", slots, Shape::Array),
            ],
            DisplayNode::Pointer { at, .. } => {
                vec![Addressed::new("a pointer hop", at, Shape::Pointer)]
            }
            DisplayNode::DynPointer {
                pointer, vtable, ..
            } => vec![
                Addressed::new("a dyn data pointer", pointer, Shape::Pointer),
                Addressed::new("a dyn vtable pointer", vtable, Shape::Pointer),
            ],
            DisplayNode::Map {
                length, entries, ..
            } => {
                let MapEntries::BTree { root, .. } = entries.as_ref();
                vec![
                    Addressed::new("a map length", length, Shape::Uint(word)),
                    Addressed::new("a B-tree root", root, Shape::Any),
                ]
            }
            // A `Struct`'s fields address members by index, not by selector; a
            // `Variant` and a `CustomList` address through value expressions,
            // whose reads are checked as they are walked. `Elided` renders
            // nothing, so there is nothing for it to address.
            DisplayNode::Struct { .. }
            | DisplayNode::Variant { .. }
            | DisplayNode::CustomList { .. }
            | DisplayNode::Elided => Vec::new(),
        }
    }
}

/// The `(pointer, length, capacity?)` triple both buffer-shaped nodes carry.
/// The data pointer's pointee is deliberately unconstrained: a `Vec`'s and a
/// `String`'s are byte-erased (`*u8`) while a `&[T]`'s and a
/// `&camino::Utf8Path`'s are typed, and the render reads `length` elements
/// through the pointer either way.
fn buffer<'a>(
    what: [&'static str; 3],
    pointer: &'a Selector,
    length: &'a Selector,
    capacity: Option<&'a Selector>,
    word: u64,
) -> Vec<Addressed<'a>> {
    let mut addressed = vec![
        Addressed::new(what[0], pointer, Shape::Pointer),
        Addressed::new(what[1], length, Shape::Uint(word)),
    ];
    if let Some(capacity) = capacity {
        addressed.push(Addressed::new(what[2], capacity, Shape::Uint(word)));
    }
    addressed
}

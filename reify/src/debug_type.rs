use crate::Result;

pub use exegesis::bundle::Notation;

use std::fmt;
use std::num::NonZeroU8;

/// Reify's own TypeKind — the union of kinds reify cares about.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Integer,
    Float,
    Pointer,
    Array,
    Struct,
    Union,
    Enum,
    /// Typedef, const, volatile, restrict, forward, unknown, etc.
    Other,
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Pointer => "pointer",
            Self::Array => "array",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Other => "other",
        };
        f.write_str(desc)
    }
}

/// Core trait: a type from debug information.
///
/// `exegesis::bundle::BundleType<'a>` implements this, letting `TypeInfo`
/// and `TypeInfoRef` render values described by a bundle.
pub trait DebugType<'a>: Copy + Clone + Sized + fmt::Debug {
    type Member: DebugMember<'a, Type = Self>;
    type MemberIter: ExactSizeIterator<Item = Self::Member>;

    // --- Core metadata ---

    fn size(&self) -> u64;

    fn name(&self) -> &'a str;

    fn kind(&self) -> TypeKind;

    // --- Structural access (struct/union members) ---

    /// Look up a member by name. Returns `None` if this type has no members
    /// or if no member with the given name exists.
    fn member(&self, name: &str) -> Option<Self::Member>;

    /// Iterate over members. Returns an empty iterator for non-struct/union
    /// types.
    fn members(&self) -> Self::MemberIter;

    // --- Pointer: get the target type ---

    /// If this is a pointer type, return the type it points to.
    fn pointer_target(&self) -> Option<Self>;

    // --- Array: get element type and count ---

    /// If this is an array type, return `(element_type, count)`.
    fn array_info(&self) -> Option<(Self, u64)>;

    // --- Enum variant operations ---
    //
    // These abstract the bundle's VariantShape encoding of Rust enums
    // behind a common interface.

    /// If this type represents a Rust enum, determine the active variant
    /// from `bytes`. Returns `(variant_name, variant_payload_type,
    /// payload_byte_offset)`.
    ///
    /// Returns `None` if this is not an enum-like type.
    /// Returns `Some(Err(..))` if it is an enum but the discriminant is
    /// invalid.
    fn active_variant(&self, bytes: &[u8]) -> Option<Result<(&'a str, Self, u64)>>;

    /// If this type represents a Rust enum, check whether the named variant
    /// is active. Returns `(payload_type, payload_byte_offset)` if active,
    /// `Ok(None)` if a different variant is active.
    ///
    /// Returns `None` (outer) if this is not an enum-like type.
    fn check_variant(&self, bytes: &[u8], name: &str) -> Option<Result<Option<(Self, u64)>>>;

    // --- Display support ---

    /// Classify this type for display formatting.
    fn classify(&self) -> TypeClass<Self>;

    /// Custom display instructions supplied by the debug-info backend.
    fn debug_format(&self) -> Option<DisplayNode<Self>> {
        None
    }

    /// A key identifying this type within its backend, under which a render
    /// pass caches its [`debug_format`](Self::debug_format) resolution — so
    /// two types may share a key only when their resolved programs are
    /// interchangeable. Bundle types use their table id.
    fn format_cache_key(&self) -> u64;

    /// Whether this type's own [`debug_format`](Self::debug_format) renders it
    /// as a self-contained value that [`peel`](crate::TypeInfoRef::peel) must
    /// not unwrap into its representation (a `Str`, a `Slice`, a `Map`, …). A
    /// transparent `Alias` format (an atomic, a newtype wrapper) is *not* a
    /// leaf — it renders as an inner member — so peeling continues through it.
    /// The default resolves the full node; backends that can answer more
    /// cheaply should override it.
    fn is_display_leaf(&self) -> bool {
        !matches!(self.debug_format(), None | Some(DisplayNode::Alias { .. }))
    }

    /// Look up the unique byte size of a fully-qualified type name in the
    /// same debug-info backend. Used only to corroborate a concrete type
    /// recovered from a vtable function symbol.
    fn size_by_name(&self, _name: &str) -> Option<u64> {
        None
    }

    /// Look up an unambiguous concrete type by its fully-qualified name in
    /// the same debug-info backend.
    fn type_by_name(&self, _name: &str) -> Option<Self> {
        None
    }
}

/// Resolved form of a bundle [`exegesis::bundle::ScalarDecode`]: the bit layout
/// of one machine word, with labels resolved from the bundle's string table to
/// owned strings. reify's `apply` interprets it, enforcing the two "no silent
/// state" rules documented on the bundle type.
#[derive(Clone, Debug)]
pub enum ScalarDecode {
    /// Render the whole word as an unsigned integer.
    Raw,
    /// Decompose the word into named sub-fields, low bit first.
    Bits(Vec<BitField>),
}

/// One named sub-field of a word decoded by [`ScalarDecode::Bits`].
#[derive(Clone, Debug)]
pub struct BitField {
    /// Label printed for this field (`name=…`).
    pub name: String,
    /// Low bit of this field within the word.
    pub shift: u8,
    /// Field width in bits; `None` means "all bits at and above `shift`".
    pub width: Option<NonZeroU8>,
    /// How the extracted sub-value is rendered.
    pub render: FieldRender,
}

/// How a [`BitField`]'s extracted sub-value is rendered.
#[derive(Clone, Debug)]
pub enum FieldRender {
    /// Exhaustive value → label table; a value absent renders `<unknown: N>`.
    Enum(Vec<(u64, String)>),
    /// Render the sub-value as an unsigned integer (`name=N`).
    Uint,
}

/// Resolved form of a bundle [`exegesis::bundle::DisplayNode`]: the same tree
/// shape, but every [`exegesis::bundle::Selector`] is reduced to a byte offset
/// (relative to the value the node is rendered against) and every related type
/// id is resolved to a concrete `T`. reify's `eval_node` walks it with one
/// generic interpreter.
#[derive(Clone, Debug)]
pub enum DisplayNode<T> {
    /// Decode the `word_size`-byte word at `offset` via `decode`.
    Scalar {
        offset: u64,
        word_size: u32,
        decode: ScalarDecode,
    },
    /// Render the pointer word at `offset` as a code symbol, without ever
    /// following it as a data pointer.
    Symbol { offset: u64 },
    /// Render a record of the listed [`Field`]s in order.
    Struct { fields: Vec<Field<T>> },
    /// Walk an intrusive linked list: read the head word at `head_offset`
    /// (0 = empty), then for each node read `node_size` bytes of `node_ty` from
    /// the target, render it with `node`, and follow the successor word at
    /// `next_offset`.
    List {
        head_offset: u64,
        next_offset: u64,
        node: Box<DisplayNode<T>>,
        node_ty: T,
        node_size: u32,
    },
    /// Follow a `(data, len)` string slice and render its bytes as a quoted,
    /// escaped UTF-8 string. `pointer_offset` locates the data pointer,
    /// `length_offset`/`length_size` the byte length; `capacity`, when present,
    /// locates an owned buffer's capacity word (validated against the length).
    Str {
        pointer_offset: u64,
        length_offset: u64,
        length_size: u32,
        capacity: Option<(u64, u32)>,
    },
    /// Follow a `(data, len)` fat pointer to a contiguous buffer and render its
    /// first `length` `element`s as `[e, e, …]`. `pointer_offset` locates the
    /// data pointer and `length_offset`/`length_size` the element count;
    /// `capacity`, when present, locates an owned buffer's capacity (validated
    /// against the length). `element_size` is the stride between successive
    /// elements.
    Slice {
        pointer_offset: u64,
        length_offset: u64,
        length_size: u32,
        capacity: Option<(u64, u32)>,
        element: T,
        element_size: u32,
    },
    /// Render the inline `size`-byte array at `offset` in `notation`: an IPv4
    /// (4 bytes) or IPv6 (16 bytes) address, or a hyphenated UUID (16 bytes).
    Bytes {
        offset: u64,
        size: u32,
        notation: Notation,
    },
    /// Render the `target` value at `place` as though it were the whole value,
    /// peeling a transparent wrapper. `place` is usually a plain local offset
    /// (a wrapper member), but may cross a pointer — that is how a
    /// `watch::Receiver`'s `Some(T)` payload renders the `T` living behind its
    /// `Arc`. `follow_pointers` mirrors the bundle node: when false a pointer
    /// alias (an atomic's stored address) is shown without being dereferenced.
    Alias {
        target: T,
        place: Place,
        follow_pointers: bool,
    },
    /// Render a readiness bitmap as `[<n> slots]`. `bitmap_offset`/`bitmap_size`
    /// locate the readiness word; `count` is the slot capacity, used to mask
    /// off the unrelated high flag bits before counting the set bits.
    SlotCount {
        bitmap_offset: u64,
        bitmap_size: u32,
        count: u32,
    },
    /// Follow the pointer at `pointer_offset`, add `via_offset` to reach the
    /// `target`, read it from the process, and render it with `then`. The
    /// degradation markers are titled with the enclosing type's name (a
    /// `Receiver` reads as the `Chan` it drains).
    Pointer {
        pointer_offset: u64,
        via_offset: u64,
        target: T,
        then: Box<DisplayNode<T>>,
    },
    /// Display a Rust trait-object data pointer and vtable. `tail_offset` is
    /// added to the data-pointer address before reading the concrete pointee,
    /// skipping the sized header of an unsized wrapper such as `ArcInner`.
    DynPointer {
        pointer_offset: u64,
        vtable: T,
        vtable_offset: u64,
        drop_in_place: u32,
        size: u32,
        align: u32,
        tail_offset: u64,
    },
    /// Render an associative collection, using `entries` to produce exactly
    /// `length` key/value pairs and the shared map presentation for output.
    Map {
        length_offset: u64,
        length_size: u32,
        key: T,
        value: T,
        entries: Box<MapEntries<T>>,
    },
    /// Select one of `arms` (else `default`) by matching the value the
    /// `discriminant` expression computes. See the bundle
    /// [`exegesis::bundle::DisplayNode::Variant`] for the model.
    Variant {
        discriminant: ValueExpr,
        arms: Vec<Arm<T>>,
        default: Option<Box<DisplayNode<T>>>,
    },
    /// Interpret a small imperative program to generate a `[e, e, …]` sequence:
    /// the resolved form of the bundle
    /// [`exegesis::bundle::DisplayNode::CustomList`]. `vars` seed loop
    /// variables, `body` runs each iteration while `condition` holds, and each
    /// [`Stmt::Emit`] renders `element` against the bytes read at a computed
    /// address. The evaluator caps iterations, so a cyclic walk terminates.
    CustomList {
        vars: Vec<ValueExpr>,
        condition: ValueExpr,
        body: Vec<Stmt>,
        element: T,
    },
    /// Render the value as the single token `<elided>`, reading nothing.
    Elided,
}

/// One resolved [`DisplayNode::CustomList`] body statement, mirroring the bundle
/// [`exegesis::bundle::Stmt`]. Carries no type parameter: a statement only moves
/// words and addresses, and the sole element type lives on the list itself.
#[derive(Clone, Debug)]
pub enum Stmt {
    /// Assign loop variable `var`: `vars[var] = value`.
    Set { var: u32, value: ValueExpr },
    /// Run `then` when `cond` is nonzero, otherwise `otherwise`.
    If {
        cond: ValueExpr,
        then: Vec<Stmt>,
        otherwise: Vec<Stmt>,
    },
    /// Emit one element: render the list's element at the address `at` computes.
    Emit { at: ValueExpr },
    /// Stop the loop when `cond` is nonzero.
    Break { cond: ValueExpr },
}

/// A resolved location that may cross pointer hops, read at render time. An
/// empty `hops` is a plain local offset (the common case); each hop follows the
/// pointer word located so far and advances into the pointee. This is the
/// resolved form of a [`Selector`] that contains a [`Step::Deref`].
#[derive(Clone, Debug)]
pub struct Place {
    /// Offset from the enclosing value's base to the first pointer word (when
    /// there are hops) or directly to the datum (when there are none).
    pub(crate) root_offset: u64,
    /// Successive pointer hops; the last entry's offset reaches the final
    /// datum, earlier entries reach the next pointer word.
    pub(crate) hops: Vec<u64>,
}

/// One resolved [`DisplayNode::Variant`] arm.
#[derive(Clone, Debug)]
pub struct Arm<T> {
    pub(crate) value: u64,
    pub(crate) label: Option<String>,
    pub(crate) payload: Option<Box<DisplayNode<T>>>,
}

/// Resolved [`exegesis::bundle::ValueExpr`]: a `Read` carries its resolved
/// [`Place`] and word width; the rest mirror the bundle form. Not generic over
/// the type parameter — an expression only ever yields a machine word.
#[derive(Clone, Debug)]
pub enum ValueExpr {
    Read(Place, u32),
    Const(u64),
    And(Box<ValueExpr>, Box<ValueExpr>),
    Not(Box<ValueExpr>),
    Ne(Box<ValueExpr>, Box<ValueExpr>),
    /// Read a [`DisplayNode::CustomList`] loop variable by index.
    Var(u32),
    /// Read a `size`-byte word from the process at a computed address.
    Load {
        addr: Box<ValueExpr>,
        size: u32,
    },
    Add(Box<ValueExpr>, Box<ValueExpr>),
    Sub(Box<ValueExpr>, Box<ValueExpr>),
    Mul(Box<ValueExpr>, Box<ValueExpr>),
    Lt(Box<ValueExpr>, Box<ValueExpr>),
}

/// Resolved storage-specific entry traversal for [`DisplayNode::Map`].
#[derive(Clone, Debug)]
pub enum MapEntries<T> {
    /// Resolved B-tree node layout and root location.
    BTree {
        root: T,
        root_offset: u64,
        root_node: T,
        root_node_offset: u64,
        height: T,
        height_offset: u64,
        node_offset: u64,
        leaf: T,
        leaf_len: T,
        leaf_len_offset: u64,
        keys_offset: u64,
        key_slots: u64,
        values_offset: u64,
        internal: T,
        edges_offset: u64,
        edge: T,
        edge_pointer_offset: u64,
    },
}

/// One resolved field of a [`DisplayNode::Struct`]. A bundle `Synth` field and
/// a member whose value a node computes both resolve to `Computed` — they
/// differ only in where the label comes from; a plain member resolves to
/// `Structural`.
#[derive(Clone, Debug)]
pub enum Field<T> {
    /// A real member rendered with reify's ordinary structural display.
    Structural { name: String, ty: T, offset: u64 },
    /// A label whose value is produced by a nested node.
    Computed { label: String, node: DisplayNode<T> },
}

/// A member (field) of a struct, union, or enum variant payload.
pub trait DebugMember<'a>: Copy + Clone + Sized {
    type Type: DebugType<'a>;

    fn name(&self) -> &'a str;
    fn ty(&self) -> Self::Type;
    /// The byte offset of this member within its parent type.
    fn offset(&self) -> u64;
}

/// Classification of a debug type for display formatting.
///
/// Reify's display code matches on this instead of backend-specific type
/// enums.
pub enum TypeClass<T> {
    /// An integer type with encoding info for display.
    Integer {
        size: u64,
        is_signed: bool,
        is_bool: bool,
        is_char: bool,
    },
    /// A floating point type.
    Float { size: u64 },
    /// A pointer. `target` is the pointee type.
    Pointer { target: T },
    /// A fixed-size array.
    Array { element: T, count: u64 },
    /// A plain struct — display its fields.
    Struct,
    /// A plain union — hex dump.
    Union,
    /// A Rust discriminated enum — use active_variant() for display.
    RustEnum,
    /// A C-style enum (named integer constants).
    CEnum,
    /// Opaque / unknown — hex dump.
    Opaque,
}

// ---------------------------------------------------------------------------
// Bundle implementation
// ---------------------------------------------------------------------------

use exegesis::Encoding;
use exegesis::bundle::{BundleMember, BundleMemberIter, BundleType, TypeDef, VariantError};

impl<'a> DebugType<'a> for BundleType<'a> {
    type Member = BundleMember<'a>;
    type MemberIter = BundleMemberIter<'a>;

    fn size(&self) -> u64 {
        BundleType::size(self)
    }

    fn name(&self) -> &'a str {
        BundleType::name(self)
    }

    fn kind(&self) -> TypeKind {
        match self.def() {
            TypeDef::Base { encoding, .. } => match encoding {
                Encoding::Float => TypeKind::Float,
                _ => TypeKind::Integer,
            },
            TypeDef::Pointer { .. } => TypeKind::Pointer,
            TypeDef::Array { .. } => TypeKind::Array,
            TypeDef::Struct { .. } => TypeKind::Struct,
            TypeDef::Union { .. } => TypeKind::Union,
            TypeDef::Enum { .. } | TypeDef::CEnum { .. } => TypeKind::Enum,
            TypeDef::Opaque { .. } => TypeKind::Other,
        }
    }

    fn member(&self, name: &str) -> Option<Self::Member> {
        BundleType::member(self, name)
    }

    fn members(&self) -> Self::MemberIter {
        BundleType::members(self)
    }

    fn pointer_target(&self) -> Option<Self> {
        BundleType::pointer_target(self)
    }

    fn array_info(&self) -> Option<(Self, u64)> {
        BundleType::array_info(self)
    }

    fn active_variant(&self, bytes: &[u8]) -> Option<Result<(&'a str, Self, u64)>> {
        let decoded = BundleType::active_variant(self, bytes)?;
        Some(
            decoded
                .map(|v| (v.name, v.ty, v.offset))
                .map_err(|e| bundle_variant_error(self, e)),
        )
    }

    fn check_variant(&self, bytes: &[u8], name: &str) -> Option<Result<Option<(Self, u64)>>> {
        let checked = BundleType::check_variant(self, bytes, name)?;
        Some(checked.map_err(|e| match e {
            VariantError::NoSuchVariant => {
                crate::Error::no_enumerator(self.name().to_string(), name.to_string())
            }
            other => bundle_variant_error(self, other),
        }))
    }

    fn classify(&self) -> TypeClass<Self> {
        match self.def() {
            TypeDef::Base { size, encoding, .. } => match encoding {
                Encoding::Float => TypeClass::Float { size: *size },
                _ => TypeClass::Integer {
                    size: *size,
                    is_signed: matches!(encoding, Encoding::Signed | Encoding::SignedChar),
                    is_bool: matches!(encoding, Encoding::Boolean),
                    is_char: matches!(
                        encoding,
                        Encoding::SignedChar | Encoding::UnsignedChar | Encoding::UtfChar
                    ),
                },
            },
            TypeDef::Pointer { .. } => TypeClass::Pointer {
                target: self.pointer_target().expect("pointer has a target"),
            },
            TypeDef::Array { .. } => {
                let (element, count) = self.array_info().expect("array has element info");
                TypeClass::Array { element, count }
            }
            TypeDef::Struct { .. } => TypeClass::Struct,
            TypeDef::Union { .. } => TypeClass::Union,
            TypeDef::Enum { .. } => TypeClass::RustEnum,
            TypeDef::CEnum { .. } => TypeClass::CEnum,
            TypeDef::Opaque { .. } => TypeClass::Opaque,
        }
    }

    fn format_cache_key(&self) -> u64 {
        u64::from(self.id().0)
    }

    fn debug_format(&self) -> Option<DisplayNode<Self>> {
        use exegesis::bundle::{MemberRef, Selector, Step};

        /// The member a [`MemberRef`] addresses in `ty`, resolved the way the
        /// bundle resolves it: by position, or by the one member bearing the
        /// name. A name that no member or several members answer to resolves
        /// to nothing, so the display program declines rather than landing on
        /// an arbitrary member.
        fn member_at<'a>(ty: BundleType<'a>, at: &MemberRef) -> Option<BundleMember<'a>> {
            let members: Vec<_> = ty.members().collect();
            let index = at.resolve(members.len(), |index, name| {
                members[index].name() == ty.resolve_str(name)
            })?;
            members.get(index).copied()
        }

        /// Resolve a selector against `root` to `(landed type, Place)`. The one
        /// traversal primitive: `Member` steps accumulate offsets, a `Deref`
        /// step segments the [`Place`] (stashing the offset so far and
        /// restarting inside the pointee). Its flat sibling `resolve_selector`
        /// is the adapter used by every node that reads within one allocation.
        fn resolve_place<'a>(
            root: BundleType<'a>,
            sel: &Selector,
        ) -> Option<(BundleType<'a>, Place)> {
            let mut ty = root;
            let mut offset = 0u64;
            let mut place = Place {
                root_offset: 0,
                hops: Vec::new(),
            };
            let mut before_first_deref = true;
            for step in sel.steps() {
                match step {
                    Step::Member(at) => {
                        let member = member_at(ty, at)?;
                        offset = offset.checked_add(member.offset())?;
                        ty = member.ty();
                    }
                    Step::Deref => {
                        if before_first_deref {
                            place.root_offset = offset;
                            before_first_deref = false;
                        } else {
                            place.hops.push(offset);
                        }
                        ty = ty.pointer_target()?;
                        offset = 0;
                    }
                }
            }
            if before_first_deref {
                place.root_offset = offset;
            } else {
                place.hops.push(offset);
            }
            Some((ty, place))
        }

        /// Resolve a selector that stays within the value's own bytes to
        /// `(landed type, byte offset)`. Returns `None` if the selector
        /// unexpectedly crosses a pointer — a fail-safe fallback to structural
        /// display rather than a misread. Every node but `Variant`/`Alias`
        /// reads locally and uses this.
        fn resolve_selector<'a>(
            root: BundleType<'a>,
            sel: &Selector,
        ) -> Option<(BundleType<'a>, u64)> {
            let (ty, place) = resolve_place(root, sel)?;
            place.hops.is_empty().then_some((ty, place.root_offset))
        }

        /// Resolve a bundle [`exegesis::bundle::ValueExpr`] into reify's form,
        /// resolving each `Read` selector to a [`Place`] plus its word width.
        fn resolve_value_expr<'a>(
            scope: BundleType<'a>,
            expr: &exegesis::bundle::ValueExpr,
        ) -> Option<ValueExpr> {
            use exegesis::bundle::ValueExpr as BundleExpr;
            Some(match expr {
                BundleExpr::Read(sel) => {
                    let (ty, place) = resolve_place(scope, sel)?;
                    ValueExpr::Read(place, ty.size() as u32)
                }
                BundleExpr::Const(value) => ValueExpr::Const(*value),
                BundleExpr::And(a, b) => ValueExpr::And(
                    Box::new(resolve_value_expr(scope, a)?),
                    Box::new(resolve_value_expr(scope, b)?),
                ),
                BundleExpr::Not(inner) => {
                    ValueExpr::Not(Box::new(resolve_value_expr(scope, inner)?))
                }
                BundleExpr::Ne(a, b) => ValueExpr::Ne(
                    Box::new(resolve_value_expr(scope, a)?),
                    Box::new(resolve_value_expr(scope, b)?),
                ),
                BundleExpr::Var(id) => ValueExpr::Var(*id),
                BundleExpr::Load { addr, size } => ValueExpr::Load {
                    addr: Box::new(resolve_value_expr(scope, addr)?),
                    size: *size,
                },
                BundleExpr::Add(a, b) => ValueExpr::Add(
                    Box::new(resolve_value_expr(scope, a)?),
                    Box::new(resolve_value_expr(scope, b)?),
                ),
                BundleExpr::Sub(a, b) => ValueExpr::Sub(
                    Box::new(resolve_value_expr(scope, a)?),
                    Box::new(resolve_value_expr(scope, b)?),
                ),
                BundleExpr::Mul(a, b) => ValueExpr::Mul(
                    Box::new(resolve_value_expr(scope, a)?),
                    Box::new(resolve_value_expr(scope, b)?),
                ),
                BundleExpr::Lt(a, b) => ValueExpr::Lt(
                    Box::new(resolve_value_expr(scope, a)?),
                    Box::new(resolve_value_expr(scope, b)?),
                ),
            })
        }

        /// Resolve a bundle [`exegesis::bundle::Stmt`] into reify's form,
        /// resolving every embedded [`ValueExpr`] against `scope`.
        fn resolve_stmt(scope: BundleType<'_>, stmt: &exegesis::bundle::Stmt) -> Option<Stmt> {
            use exegesis::bundle::Stmt as BundleStmt;
            Some(match stmt {
                BundleStmt::Set { var, value } => Stmt::Set {
                    var: *var,
                    value: resolve_value_expr(scope, value)?,
                },
                BundleStmt::If {
                    cond,
                    then,
                    otherwise,
                } => Stmt::If {
                    cond: resolve_value_expr(scope, cond)?,
                    then: then
                        .iter()
                        .map(|stmt| resolve_stmt(scope, stmt))
                        .collect::<Option<Vec<_>>>()?,
                    otherwise: otherwise
                        .iter()
                        .map(|stmt| resolve_stmt(scope, stmt))
                        .collect::<Option<Vec<_>>>()?,
                },
                BundleStmt::Emit { at } => Stmt::Emit {
                    at: resolve_value_expr(scope, at)?,
                },
                BundleStmt::Break { cond } => Stmt::Break {
                    cond: resolve_value_expr(scope, cond)?,
                },
            })
        }

        /// Resolve a bundle [`exegesis::bundle::ScalarDecode`] into reify's
        /// owned form, resolving each label [`StrRef`] against `root`'s bundle.
        fn resolve_decode(
            root: BundleType<'_>,
            decode: &exegesis::bundle::ScalarDecode,
        ) -> ScalarDecode {
            use exegesis::bundle::{FieldRender as BundleRender, ScalarDecode as BundleDecode};
            match decode {
                BundleDecode::Raw => ScalarDecode::Raw,
                BundleDecode::Bits(fields) => ScalarDecode::Bits(
                    fields
                        .iter()
                        .map(|field| BitField {
                            name: root.resolve_str(field.name).to_string(),
                            shift: field.shift,
                            width: field.width,
                            render: match &field.render {
                                BundleRender::Enum(table) => FieldRender::Enum(
                                    table
                                        .iter()
                                        .map(|(v, l)| (*v, root.resolve_str(*l).to_string()))
                                        .collect(),
                                ),
                                BundleRender::Uint => FieldRender::Uint,
                            },
                        })
                        .collect(),
                ),
            }
        }

        /// Recursively resolve a bundle [`exegesis::bundle::DisplayNode`] into
        /// reify's offset-carrying form, rooted at `scope` (the type the node
        /// is rendered against). Mirrors the recursion in io.rs `check_node`.
        fn resolve_node<'a>(
            scope: BundleType<'a>,
            node: &exegesis::bundle::DisplayNode,
        ) -> Option<DisplayNode<BundleType<'a>>> {
            use exegesis::bundle::DisplayNode as BundleNode;
            match node {
                BundleNode::Scalar { at, decode } => {
                    let (landed, offset) = resolve_selector(scope, at)?;
                    Some(DisplayNode::Scalar {
                        offset,
                        word_size: landed.size() as u32,
                        decode: resolve_decode(scope, decode),
                    })
                }
                BundleNode::Symbol { at } => {
                    let (_, offset) = resolve_selector(scope, at)?;
                    Some(DisplayNode::Symbol { offset })
                }
                BundleNode::Struct { fields } => Some(DisplayNode::Struct {
                    fields: fields
                        .iter()
                        .map(|field| resolve_field(scope, field))
                        .collect::<Option<Vec<_>>>()?,
                }),
                BundleNode::List {
                    head,
                    next,
                    node,
                    node_ty,
                } => {
                    let (_, head_offset) = resolve_selector(scope, head)?;
                    let node_ty = scope.related_type(*node_ty);
                    let (_, next_offset) = resolve_selector(node_ty, next)?;
                    Some(DisplayNode::List {
                        head_offset,
                        next_offset,
                        node: Box::new(resolve_node(node_ty, node)?),
                        node_ty,
                        node_size: node_ty.size() as u32,
                    })
                }
                BundleNode::Str {
                    pointer,
                    length,
                    capacity,
                } => {
                    let (pointer_ty, pointer_offset) = resolve_selector(scope, pointer)?;
                    pointer_ty.pointer_target()?;
                    let (length_ty, length_offset) = resolve_selector(scope, length)?;
                    let capacity = match capacity {
                        Some(capacity) => {
                            let (capacity_ty, capacity_offset) = resolve_selector(scope, capacity)?;
                            Some((capacity_offset, capacity_ty.size() as u32))
                        }
                        None => None,
                    };
                    Some(DisplayNode::Str {
                        pointer_offset,
                        length_offset,
                        length_size: length_ty.size() as u32,
                        capacity,
                    })
                }
                BundleNode::Slice {
                    pointer,
                    length,
                    capacity,
                    element,
                } => {
                    let (pointer_ty, pointer_offset) = resolve_selector(scope, pointer)?;
                    pointer_ty.pointer_target()?;
                    let (length_ty, length_offset) = resolve_selector(scope, length)?;
                    let capacity = match capacity {
                        Some(capacity) => {
                            let (capacity_ty, capacity_offset) = resolve_selector(scope, capacity)?;
                            Some((capacity_offset, capacity_ty.size() as u32))
                        }
                        None => None,
                    };
                    let element = scope.related_type(*element);
                    Some(DisplayNode::Slice {
                        pointer_offset,
                        length_offset,
                        length_size: length_ty.size() as u32,
                        capacity,
                        element,
                        element_size: element.size() as u32,
                    })
                }
                BundleNode::Bytes { at, notation } => {
                    let (array_ty, offset) = resolve_selector(scope, at)?;
                    // `array_info` bounds the read to a real array; io.rs has
                    // already checked its element is an unsigned byte and its
                    // length is one the notation spells.
                    let (_, count) = array_ty.array_info()?;
                    Some(DisplayNode::Bytes {
                        offset,
                        size: count as u32,
                        notation: *notation,
                    })
                }
                BundleNode::Alias {
                    at,
                    follow_pointers,
                } => {
                    let (target, place) = resolve_place(scope, at)?;
                    Some(DisplayNode::Alias {
                        target,
                        place,
                        follow_pointers: *follow_pointers,
                    })
                }
                BundleNode::SlotCount { bitmap, slots } => {
                    let (bitmap_ty, bitmap_offset) = resolve_selector(scope, bitmap)?;
                    let (array_ty, _) = resolve_selector(scope, slots)?;
                    let (_, count) = array_ty.array_info()?;
                    Some(DisplayNode::SlotCount {
                        bitmap_offset,
                        bitmap_size: bitmap_ty.size() as u32,
                        count: count as u32,
                    })
                }
                BundleNode::Pointer { at, via, then } => {
                    let (ptr_ty, pointer_offset) = resolve_selector(scope, at)?;
                    let pointee_ty = ptr_ty.pointer_target()?;
                    let (target, via_offset) = resolve_selector(pointee_ty, via)?;
                    Some(DisplayNode::Pointer {
                        pointer_offset,
                        via_offset,
                        target,
                        then: Box::new(resolve_node(target, then)?),
                    })
                }
                BundleNode::DynPointer {
                    pointer,
                    vtable,
                    drop_in_place,
                    size,
                    align,
                    tail_offset,
                } => {
                    let (_, pointer_offset) = resolve_selector(scope, pointer)?;
                    let (vtable, vtable_offset) = resolve_selector(scope, vtable)?;
                    Some(DisplayNode::DynPointer {
                        pointer_offset,
                        vtable,
                        vtable_offset,
                        drop_in_place: *drop_in_place,
                        size: *size,
                        align: *align,
                        tail_offset: *tail_offset,
                    })
                }
                BundleNode::Map {
                    length,
                    key,
                    value,
                    entries,
                } => {
                    let (length_ty, length_offset) = resolve_selector(scope, length)?;
                    let key = scope.related_type(*key);
                    let value = scope.related_type(*value);
                    Some(DisplayNode::Map {
                        length_offset,
                        length_size: length_ty.size() as u32,
                        key,
                        value,
                        entries: Box::new(resolve_map_entries(scope, key, value, entries)?),
                    })
                }
                BundleNode::Variant {
                    discriminant,
                    arms,
                    default,
                } => {
                    let arms = arms
                        .iter()
                        .map(|arm| {
                            Some(Arm {
                                value: arm.value,
                                label: arm.label.map(|label| scope.resolve_str(label).to_string()),
                                payload: match &arm.payload {
                                    Some(payload) => Some(Box::new(resolve_node(scope, payload)?)),
                                    None => None,
                                },
                            })
                        })
                        .collect::<Option<Vec<_>>>()?;
                    let default = match default {
                        Some(default) => Some(Box::new(resolve_node(scope, default)?)),
                        None => None,
                    };
                    Some(DisplayNode::Variant {
                        discriminant: resolve_value_expr(scope, discriminant)?,
                        arms,
                        default,
                    })
                }
                BundleNode::CustomList {
                    vars,
                    condition,
                    body,
                    element,
                } => {
                    let vars = vars
                        .iter()
                        .map(|expr| resolve_value_expr(scope, expr))
                        .collect::<Option<Vec<_>>>()?;
                    let body = body
                        .iter()
                        .map(|stmt| resolve_stmt(scope, stmt))
                        .collect::<Option<Vec<_>>>()?;
                    Some(DisplayNode::CustomList {
                        vars,
                        condition: resolve_value_expr(scope, condition)?,
                        body,
                        element: scope.related_type(*element),
                    })
                }
                BundleNode::Elided => Some(DisplayNode::Elided),
            }
        }

        fn resolve_map_entries<'a>(
            scope: BundleType<'a>,
            key: BundleType<'a>,
            value: BundleType<'a>,
            entries: &exegesis::bundle::MapEntries,
        ) -> Option<MapEntries<BundleType<'a>>> {
            let exegesis::bundle::MapEntries::BTree {
                root,
                root_node,
                height,
                node,
                leaf,
                leaf_len,
                leaf_keys,
                leaf_values,
                internal,
                internal_data: _,
                internal_edges,
                edge: edge_path,
            } = entries;

            let (root, root_offset) = resolve_selector(scope, root)?;
            let (some, some_offset) = root.variant("Some")?;
            let (root_node, root_node_offset) = resolve_selector(some, root_node)?;
            let (height, height_offset) = resolve_selector(root_node, height)?;
            let (node, node_offset) = resolve_selector(root_node, node)?;
            node.pointer_target()?;

            let leaf = scope.related_type(*leaf);
            let (leaf_len, leaf_len_offset) = resolve_selector(leaf, leaf_len)?;
            let (keys, keys_offset) = resolve_selector(leaf, leaf_keys)?;
            let (key_slot, key_slots) = keys.array_info()?;
            if key_slot.size() != key.size() {
                return None;
            }
            let (values, values_offset) = resolve_selector(leaf, leaf_values)?;
            let (value_slot, value_slots) = values.array_info()?;
            if value_slot.size() != value.size() || value_slots != key_slots {
                return None;
            }

            let internal = scope.related_type(*internal);
            let (edges, edges_offset) = resolve_selector(internal, internal_edges)?;
            let (edge, edge_slots) = edges.array_info()?;
            if edge_slots != key_slots + 1 {
                return None;
            }
            let (edge_pointer, edge_pointer_offset) = resolve_selector(edge, edge_path)?;
            edge_pointer.pointer_target()?;

            Some(MapEntries::BTree {
                root,
                root_offset,
                root_node,
                root_node_offset: root_offset
                    .checked_add(some_offset)?
                    .checked_add(root_node_offset)?,
                height,
                height_offset,
                node_offset,
                leaf,
                leaf_len,
                leaf_len_offset,
                keys_offset,
                key_slots,
                values_offset,
                internal,
                edges_offset,
                edge,
                edge_pointer_offset,
            })
        }

        /// Resolve one bundle [`exegesis::bundle::Field`]. A member whose value
        /// a node computes and a synthesized field both become `Computed`;
        /// they differ only in where the label comes from.
        fn resolve_field<'a>(
            scope: BundleType<'a>,
            field: &exegesis::bundle::Field,
        ) -> Option<Field<BundleType<'a>>> {
            use exegesis::bundle::Field as BundleField;
            match field {
                BundleField::Member { at, node } => {
                    let member = member_at(scope, at)?;
                    Some(match node {
                        None => Field::Structural {
                            name: member.name().to_string(),
                            ty: member.ty(),
                            offset: member.offset(),
                        },
                        Some(node) => Field::Computed {
                            label: member.name().to_string(),
                            node: resolve_node(scope, node)?,
                        },
                    })
                }
                BundleField::Synth { label, node } => Some(Field::Computed {
                    label: scope.resolve_str(*label).to_string(),
                    node: resolve_node(scope, node)?,
                }),
            }
        }

        resolve_node(*self, BundleType::debug_format(self)?)
    }

    fn is_display_leaf(&self) -> bool {
        // A raw map lookup — no `resolve_node`, so `peel` can call it per step.
        use exegesis::bundle::DisplayNode as BundleNode;
        matches!(
            BundleType::debug_format(self),
            Some(node) if !matches!(node, BundleNode::Alias { .. })
        )
    }

    fn size_by_name(&self, name: &str) -> Option<u64> {
        BundleType::size_by_name(self, name)
    }

    fn type_by_name(&self, name: &str) -> Option<Self> {
        BundleType::type_by_name(self, name)
    }
}

impl<'a> DebugMember<'a> for BundleMember<'a> {
    type Type = BundleType<'a>;

    fn name(&self) -> &'a str {
        BundleMember::name(self)
    }

    fn ty(&self) -> BundleType<'a> {
        BundleMember::ty(self)
    }

    fn offset(&self) -> u64 {
        BundleMember::offset(self)
    }
}

/// Map a bundle variant-decode failure onto reify's error type.
fn bundle_variant_error(ty: &BundleType<'_>, e: VariantError) -> crate::Error {
    match e {
        VariantError::ShortBuffer { needed, len } => {
            crate::Error::unexpected_len(len as u32, needed as u32)
        }
        VariantError::NoVariantMatch { raw } => {
            crate::Error::invalid_discriminant_value(ty.name().to_string(), raw as i64)
        }
        other => crate::Error::parse_type(format!("{}: {other}", ty.name())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhelper::*;
    use crate::{TypeInfoRef, TypeKind};

    use exegesis::bundle::BundleView;

    #[test]
    fn test_kind_mapping() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let kind = |id| v.ty(id).unwrap().kind();
        assert_eq!(kind(U32), TypeKind::Integer);
        assert_eq!(kind(BOOL), TypeKind::Integer);
        assert_eq!(kind(POINT), TypeKind::Struct);
        assert_eq!(kind(MSG), TypeKind::Enum);
        assert_eq!(kind(PTR), TypeKind::Pointer);
        assert_eq!(kind(ARR), TypeKind::Array);
    }

    #[test]
    fn test_member_access_and_display() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [1u32, 2u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let r = TypeInfoRef::new(v.ty(POINT).unwrap(), 0x1000, &bytes);

        let y = r.member("y").expect("member y");
        assert_eq!(y.addr, 0x1004);
        assert_eq!(format!("{}", y.display()), "2");
        assert!(r.try_member("z").expect("no error").is_none());

        let shown = format!("{}", r.display());
        assert!(
            shown.contains("x: 1") && shown.contains("y: 2"),
            "got {shown:?}"
        );
    }

    #[test]
    fn test_active_variant_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let msg = v.ty(MSG).unwrap();

        let mut bytes = [0u8; 16];
        bytes[0] = 1;
        bytes[8..].copy_from_slice(&42u64.to_le_bytes());
        let r = TypeInfoRef::new(msg, 0, &bytes);
        assert!(r.is_enum());

        let (name, payload) = r.active_variant().expect("decode failed");
        assert_eq!(name, "B");
        assert_eq!(format!("{}", payload.display()), "42");

        // Struct payload: bytes window starts at the payload offset.
        bytes[0] = 0;
        bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&8u32.to_le_bytes());
        let r = TypeInfoRef::new(msg, 0, &bytes);
        let (name, payload) = r.active_variant().expect("decode failed");
        assert_eq!(name, "A");
        assert_eq!(format!("{}", payload.member("x").unwrap().display()), "7");

        // Struct types are not enums.
        let p = TypeInfoRef::new(v.ty(POINT).unwrap(), 0, &bytes[8..16]);
        assert!(!p.is_enum());
        assert!(p.active_variant().is_err());
    }

    #[test]
    fn test_select_variant_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 16];
        bytes[0] = 1;
        let r = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);

        assert!(r.try_select_variant("B").expect("no error").is_some());
        assert!(r.try_select_variant("A").expect("no error").is_none());
        // Unknown variant names are an error, not "inactive".
        assert!(r.try_select_variant("Nope").is_err());
    }

    #[test]
    fn test_niche_variant_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let opt = v.ty(OPT).unwrap();

        let bytes = 0u64.to_le_bytes();
        let (name, _) = TypeInfoRef::new(opt, 0, &bytes).active_variant().unwrap();
        assert_eq!(name, "None");

        let bytes = 0xdead_beefu64.to_le_bytes();
        let r = TypeInfoRef::new(opt, 0, &bytes);
        let (name, payload) = r.active_variant().unwrap();
        assert_eq!(name, "Some");
        assert_eq!(format!("{}", payload.display()), "3735928559");
    }

    #[test]
    fn test_invalid_discriminant_is_error() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 16];
        bytes[0] = 9;
        let r = TypeInfoRef::new(v.ty(MSG).unwrap(), 0, &bytes);
        let err = r.active_variant().expect_err("tag 9 must not decode");
        let msg = format!("{err}");
        assert!(
            msg.contains("discriminant") || msg.contains("Msg"),
            "got {msg:?}"
        );
    }

    #[test]
    fn test_peel_single_member_wrapper() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let peeled = TypeInfoRef::new(v.ty(WRAP).unwrap(), 0, &bytes).peel();
        assert_eq!(DebugType::name(&peeled.ty), "Point");
        assert_eq!(format!("{}", peeled.member("y").unwrap().display()), "4");
    }

    #[test]
    fn test_array_elements_through_typeinfo() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [10u32, 20, 30]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        let r = TypeInfoRef::new(v.ty(ARR).unwrap(), 0, &bytes);
        let shown: Vec<String> = r
            .array_elements()
            .expect("array elements")
            .map(|e| format!("{}", e.display()))
            .collect();
        assert_eq!(shown, ["10", "20", "30"]);
    }
}

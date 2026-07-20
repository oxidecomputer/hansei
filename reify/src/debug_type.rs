use crate::Result;

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

    // --- Wrapper type unwrapping ---

    /// Unwrap transparent wrapper types (typedef, const, volatile, restrict)
    /// to the underlying type. Returns `self` if not a wrapper.
    fn peel_wrappers(&self) -> Self;

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
    fn debug_format(&self) -> Option<DebugFormat<Self>> {
        None
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

/// Backend-independent, fully resolved custom display instructions.
#[derive(Clone, Debug)]
pub enum DebugFormat<T> {
    /// Display `target` at `offset` as though it were the containing value.
    Transparent { target: T, offset: u64 },
    /// Apply semantics for a known family of types.
    Known(KnownFormat<T>),
    /// Interpret a composable display program (Formatter IR). The resolved
    /// counterpart of [`exegesis::bundle::DebugFormat::Node`], with every
    /// selector reduced to a byte offset and every related type resolved to
    /// a concrete `T`.
    Node(DisplayNode<T>),
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
}

/// One resolved field of a [`DisplayNode::Struct`]. The bundle's `Named` and
/// `Override` fields both resolve to `Computed` (they differ only in where the
/// label comes from); `Member` resolves to `Structural`.
#[derive(Clone, Debug)]
pub enum Field<T> {
    /// A real member rendered with reify's ordinary structural display.
    Structural { name: String, ty: T, offset: u64 },
    /// A label whose value is produced by a nested node.
    Computed { label: String, node: DisplayNode<T> },
}

/// Closed set of semantic formatters understood by reify.
#[derive(Clone, Debug)]
pub enum KnownFormat<T> {
    /// Display an atomic's stored value without following pointer values.
    Atomic { value: T, offset: u64 },
    /// Display a function pointer as an address and symbol without following
    /// the address as data.
    FunctionPointer,
    /// Display a Rust trait-object data pointer and vtable.
    ///
    /// `tail_offset` is added to the data-pointer address before reading the
    /// concrete pointee: it is the offset of the `dyn Trait` tail within the
    /// struct the pointer targets, so an `Arc`'s sized header (its strong and
    /// weak counts) is skipped. Zero for a bare `dyn Trait` pointee.
    DynPointer {
        pointer_offset: u64,
        vtable: T,
        vtable_offset: u64,
        drop_in_place: u32,
        size: u32,
        align: u32,
        tail_offset: u64,
    },
    /// Display the fields of `core::task::RawWakerVTable` as function
    /// addresses and symbols.
    RawWakerVTable {
        clone_offset: u64,
        wake_offset: u64,
        wake_by_ref_offset: u64,
        drop_offset: u64,
    },
    /// Display a parking_lot `RawMutex`'s decoded lock state. `state_offset`
    /// locates the single state byte within the mutex; `state_decode` is its
    /// bit layout.
    RawMutex {
        state_offset: u64,
        state_decode: ScalarDecode,
    },
    /// Display a `tokio::sync::notify::Notify` compactly: its notification
    /// state, waiter-mutex lock state, and the queue of parked waiters. The
    /// `*_offset` fields locate each within the value; `state_offset` is the
    /// notification state word (low two bits idle/waiting/notified) and
    /// `head_offset` the queue's head `Option<NonNull<Waiter>>` word. `waiter`
    /// is the `Waiter` node type (`waiter_size` bytes); `waiter_notification_offset`
    /// and `waiter_next_offset` locate each node's notification word and
    /// successor pointer, which reify follows to list the queued waiters.
    Notify {
        state_offset: u64,
        state_decode: ScalarDecode,
        mutex_offset: u64,
        mutex_decode: ScalarDecode,
        head_offset: u64,
        waiter: T,
        waiter_size: u32,
        waiter_notification_offset: u64,
        waiter_notification_decode: ScalarDecode,
        waiter_next_offset: u64,
    },
    /// Display a `tokio::sync::batch_semaphore::Semaphore`, decoding its
    /// `permits` field to the available count and closed flag. `permits_member`
    /// is that field's index and `permits_offset` locates the atomic `usize`.
    Semaphore {
        permits_member: u32,
        permits_offset: u64,
        permits_decode: ScalarDecode,
    },
    /// Display a `tokio::sync::watch::state::AtomicState` decoded to its
    /// version and closed flag. `state_offset` locates the atomic `usize`;
    /// `state_decode` is its bit layout.
    WatchState {
        state_offset: u64,
        state_decode: ScalarDecode,
    },
    /// Display a `tokio::sync::mpsc::chan::Chan<T, S>`'s live queued messages
    /// (indices `[index, tail)`) by walking its block chain from the head
    /// block, rendering each queued slot as `element`. `*_offset` fields
    /// within the channel locate the read/write positions and head pointer;
    /// the block-relative offsets locate each block's start index, successor
    /// pointer, and inline slot array (`stride` bytes each, `count` per block).
    MpscChan {
        tail_offset: u64,
        index_offset: u64,
        head_offset: u64,
        block_size: u32,
        start_index_offset: u64,
        next_offset: u64,
        values_offset: u64,
        element: T,
        stride: u32,
        count: u32,
    },
    /// Display a `tokio::sync::mpsc::block::Block<T>` with its `values` member
    /// elided to a written-slot count. `ready_offset`/`ready_size` locate the
    /// readiness bitmap and `count` is the block capacity (to mask off the
    /// released/closed flag bits); `values_member` is the field shown as the
    /// count. Contents are not dereferenced — see the schema note.
    MpscBlock {
        ready_offset: u64,
        ready_size: u32,
        values_member: u32,
        count: u32,
    },
    /// Display a `tokio::sync::mpsc::bounded::Receiver<T>` as its underlying
    /// channel. `chan_pointer_offset` locates the receiver's `Arc` raw pointer;
    /// `chan_offset` is added to the pointee address to skip the Arc's
    /// strong/weak header and reach the `Chan`, which is rendered as `chan`
    /// (carrying its own [`KnownFormat::MpscChan`]). `bound_offset` and
    /// `permits_offset` locate the bounded capacity and available permit word
    /// within that `Chan`, shown as `capacity` and `free`.
    MpscRx {
        chan: T,
        chan_pointer_offset: u64,
        chan_offset: u64,
        bound_offset: u64,
        permits_offset: u64,
        permits_decode: ScalarDecode,
    },
    /// Display an IPv4 or IPv6 address in standard notation.
    IpAddress { octets: T, offset: u64 },
    /// Display the initialized elements of a Vec.
    Vec {
        pointer_offset: u64,
        length: T,
        length_offset: u64,
        capacity: T,
        capacity_offset: u64,
        element: T,
    },
    /// Display a borrowed string as quoted, escaped UTF-8.
    Str {
        pointer_offset: u64,
        length: T,
        length_offset: u64,
    },
    /// Display an owned string as quoted, escaped UTF-8.
    String {
        pointer_offset: u64,
        length: T,
        length_offset: u64,
        capacity: T,
        capacity_offset: u64,
    },
    /// Display a BTreeMap by walking its initialized nodes in key order.
    BTreeMap {
        root: T,
        root_offset: u64,
        root_node: T,
        root_node_offset: u64,
        length: T,
        length_offset: u64,
        height: T,
        height_offset: u64,
        node_offset: u64,
        key: T,
        value: T,
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
    /// A transparent wrapper (typedef, const, volatile, restrict) — recurse
    /// into the inner type.
    Wrapper(T),
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

    fn peel_wrappers(&self) -> Self {
        // Wrapper kinds (typedef/const/volatile) are resolved away at
        // extraction time and never appear in bundles.
        *self
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

    fn debug_format(&self) -> Option<DebugFormat<Self>> {
        use exegesis::bundle::{
            DebugFormat as BundleFormat, KnownFormat as BundleKnownFormat, Selector, Step,
        };

        /// Resolve a selector against `root` to `(landed type, byte offset)`.
        ///
        /// `Member` steps accumulate member offsets. A `Deref` step needs a
        /// runtime pointer read the flat resolved form can't represent, so it
        /// bails to structural display; the node resolver (a later phase)
        /// handles cross-pointer selectors. No detector emits a `Deref` today.
        fn resolve_selector<'a>(
            root: BundleType<'a>,
            sel: &Selector,
        ) -> Option<(BundleType<'a>, u64)> {
            let mut ty = root;
            let mut offset = 0u64;
            for step in sel.steps() {
                match step {
                    Step::Member(index) => {
                        let member = ty.members().nth(*index as usize)?;
                        offset = offset.checked_add(member.offset())?;
                        ty = member.ty();
                    }
                    Step::Deref => return None,
                }
            }
            Some((ty, offset))
        }

        /// Resolve a single member index against `ty`. Used for the structural
        /// member-index fields the bespoke formatters still carry as `u32`.
        fn member_at(ty: BundleType<'_>, index: u32) -> Option<(BundleType<'_>, u64)> {
            let member = ty.members().nth(index as usize)?;
            Some((member.ty(), member.offset()))
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
            }
        }

        /// Resolve one bundle [`exegesis::bundle::Field`]. `Named`/`Override`
        /// collapse to `Computed` (they differ only in the label source).
        fn resolve_field<'a>(
            scope: BundleType<'a>,
            field: &exegesis::bundle::Field,
        ) -> Option<Field<BundleType<'a>>> {
            use exegesis::bundle::Field as BundleField;
            match field {
                BundleField::Member(index) => {
                    let member = scope.members().nth(*index as usize)?;
                    Some(Field::Structural {
                        name: member.name().to_string(),
                        ty: member.ty(),
                        offset: member.offset(),
                    })
                }
                BundleField::Named { label, node } => Some(Field::Computed {
                    label: scope.resolve_str(*label).to_string(),
                    node: resolve_node(scope, node)?,
                }),
                BundleField::Override { index, node } => {
                    let member = scope.members().nth(*index as usize)?;
                    Some(Field::Computed {
                        label: member.name().to_string(),
                        node: resolve_node(scope, node)?,
                    })
                }
            }
        }

        match BundleType::debug_format(self)? {
            BundleFormat::Transparent { member } => {
                let (target, offset) = resolve_selector(*self, member)?;
                Some(DebugFormat::Transparent { target, offset })
            }
            BundleFormat::Node(node) => Some(DebugFormat::Node(resolve_node(*self, node)?)),
            BundleFormat::Known(BundleKnownFormat::Atomic { value }) => {
                let (value, offset) = resolve_selector(*self, value)?;
                Some(DebugFormat::Known(KnownFormat::Atomic { value, offset }))
            }
            BundleFormat::Known(BundleKnownFormat::FunctionPointer) => {
                Some(DebugFormat::Known(KnownFormat::FunctionPointer))
            }
            BundleFormat::Known(BundleKnownFormat::DynPointer {
                pointer,
                vtable,
                drop_in_place,
                size,
                align,
                tail_offset,
            }) => {
                let (_, pointer_offset) = member_at(*self, *pointer)?;
                let (vtable, vtable_offset) = member_at(*self, *vtable)?;
                Some(DebugFormat::Known(KnownFormat::DynPointer {
                    pointer_offset,
                    vtable,
                    vtable_offset,
                    drop_in_place: *drop_in_place,
                    size: *size,
                    align: *align,
                    tail_offset: *tail_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::RawWakerVTable {
                clone,
                wake,
                wake_by_ref,
                drop,
            }) => {
                let (_, clone_offset) = member_at(*self, *clone)?;
                let (_, wake_offset) = member_at(*self, *wake)?;
                let (_, wake_by_ref_offset) = member_at(*self, *wake_by_ref)?;
                let (_, drop_offset) = member_at(*self, *drop)?;
                Some(DebugFormat::Known(KnownFormat::RawWakerVTable {
                    clone_offset,
                    wake_offset,
                    wake_by_ref_offset,
                    drop_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::RawMutex {
                state,
                state_decode,
            }) => {
                let (_, state_offset) = resolve_selector(*self, state)?;
                Some(DebugFormat::Known(KnownFormat::RawMutex {
                    state_offset,
                    state_decode: resolve_decode(*self, state_decode),
                }))
            }
            BundleFormat::Known(BundleKnownFormat::Notify {
                state,
                state_decode,
                mutex,
                mutex_decode,
                head,
                waiter,
                waiter_notification,
                waiter_notification_decode,
                waiter_next,
            }) => {
                let (_, state_offset) = resolve_selector(*self, state)?;
                let (_, mutex_offset) = resolve_selector(*self, mutex)?;
                let (_, head_offset) = resolve_selector(*self, head)?;
                let waiter_ty = self.related_type(*waiter);
                let (_, waiter_notification_offset) =
                    resolve_selector(waiter_ty, waiter_notification)?;
                let (_, waiter_next_offset) = resolve_selector(waiter_ty, waiter_next)?;
                Some(DebugFormat::Known(KnownFormat::Notify {
                    state_offset,
                    state_decode: resolve_decode(*self, state_decode),
                    mutex_offset,
                    mutex_decode: resolve_decode(*self, mutex_decode),
                    head_offset,
                    waiter: waiter_ty,
                    waiter_size: waiter_ty.size() as u32,
                    waiter_notification_offset,
                    waiter_notification_decode: resolve_decode(*self, waiter_notification_decode),
                    waiter_next_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::Semaphore {
                permits,
                permits_decode,
            }) => {
                let (_, permits_offset) = resolve_selector(*self, permits)?;
                let permits_member = permits.first_member()?;
                Some(DebugFormat::Known(KnownFormat::Semaphore {
                    permits_member,
                    permits_offset,
                    permits_decode: resolve_decode(*self, permits_decode),
                }))
            }
            BundleFormat::Known(BundleKnownFormat::WatchState {
                state,
                state_decode,
            }) => {
                let (_, state_offset) = resolve_selector(*self, state)?;
                Some(DebugFormat::Known(KnownFormat::WatchState {
                    state_offset,
                    state_decode: resolve_decode(*self, state_decode),
                }))
            }
            BundleFormat::Known(BundleKnownFormat::MpscChan {
                tail,
                index,
                head,
                start_index,
                next,
                values,
                element,
            }) => {
                let (_, tail_offset) = resolve_selector(*self, tail)?;
                let (_, index_offset) = resolve_selector(*self, index)?;
                let (head_ty, head_offset) = resolve_selector(*self, head)?;
                let block_ty = head_ty.pointer_target()?;
                let (_, start_index_offset) = resolve_selector(block_ty, start_index)?;
                let (_, next_offset) = resolve_selector(block_ty, next)?;
                let (array_ty, values_offset) = resolve_selector(block_ty, values)?;
                let (elem_ty, count) = array_ty.array_info()?;
                Some(DebugFormat::Known(KnownFormat::MpscChan {
                    tail_offset,
                    index_offset,
                    head_offset,
                    block_size: block_ty.size() as u32,
                    start_index_offset,
                    next_offset,
                    values_offset,
                    element: self.related_type(*element),
                    stride: elem_ty.size() as u32,
                    count: count as u32,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::MpscBlock {
                ready_slots,
                values,
            }) => {
                let (ready_ty, ready_offset) = resolve_selector(*self, ready_slots)?;
                let (array_ty, _) = resolve_selector(*self, values)?;
                let (_, count) = array_ty.array_info()?;
                let values_member = values.first_member()?;
                Some(DebugFormat::Known(KnownFormat::MpscBlock {
                    ready_offset,
                    ready_size: ready_ty.size() as u32,
                    values_member,
                    count: count as u32,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::MpscRx {
                chan_pointer,
                chan,
                bound,
                permits,
                permits_decode,
            }) => {
                let (ptr_ty, chan_pointer_offset) = resolve_selector(*self, chan_pointer)?;
                let arcinner_ty = ptr_ty.pointer_target()?;
                let (chan_ty, chan_offset) = resolve_selector(arcinner_ty, chan)?;
                let (_, bound_offset) = resolve_selector(chan_ty, bound)?;
                let (_, permits_offset) = resolve_selector(chan_ty, permits)?;
                Some(DebugFormat::Known(KnownFormat::MpscRx {
                    chan: chan_ty,
                    chan_pointer_offset,
                    chan_offset,
                    bound_offset,
                    permits_offset,
                    permits_decode: resolve_decode(*self, permits_decode),
                }))
            }
            BundleFormat::Known(BundleKnownFormat::IpAddress { octets }) => {
                let (octets, offset) = resolve_selector(*self, octets)?;
                let (octet, count) = octets.array_info()?;
                if !matches!(count, 4 | 16)
                    || !matches!(
                        octet.classify(),
                        TypeClass::Integer {
                            size: 1,
                            is_signed: false,
                            is_bool: false,
                            is_char: false,
                        }
                    )
                {
                    return None;
                }
                Some(DebugFormat::Known(KnownFormat::IpAddress {
                    octets,
                    offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::Vec {
                pointer,
                length,
                capacity,
                element,
            }) => {
                let (pointer, pointer_offset) = resolve_selector(*self, pointer)?;
                pointer.pointer_target()?;
                let (length, length_offset) = resolve_selector(*self, length)?;
                let (capacity, capacity_offset) = resolve_selector(*self, capacity)?;
                Some(DebugFormat::Known(KnownFormat::Vec {
                    pointer_offset,
                    length,
                    length_offset,
                    capacity,
                    capacity_offset,
                    element: self.related_type(*element),
                }))
            }
            BundleFormat::Known(BundleKnownFormat::Str { pointer, length }) => {
                let (pointer, pointer_offset) = resolve_selector(*self, pointer)?;
                pointer.pointer_target()?;
                let (length, length_offset) = resolve_selector(*self, length)?;
                Some(DebugFormat::Known(KnownFormat::Str {
                    pointer_offset,
                    length,
                    length_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::String {
                pointer,
                length,
                capacity,
            }) => {
                let (pointer, pointer_offset) = resolve_selector(*self, pointer)?;
                pointer.pointer_target()?;
                let (length, length_offset) = resolve_selector(*self, length)?;
                let (capacity, capacity_offset) = resolve_selector(*self, capacity)?;
                Some(DebugFormat::Known(KnownFormat::String {
                    pointer_offset,
                    length,
                    length_offset,
                    capacity,
                    capacity_offset,
                }))
            }
            BundleFormat::Known(BundleKnownFormat::BTreeMap {
                root,
                length,
                root_node,
                height,
                node,
                key,
                value,
                leaf,
                leaf_len,
                leaf_keys,
                leaf_values,
                internal,
                internal_data: _,
                internal_edges,
                edge: edge_path,
            }) => {
                let (root, root_offset) = member_at(*self, *root)?;
                let (some, some_offset) = root.variant("Some")?;
                let (root_node, root_node_offset) = resolve_selector(some, root_node)?;
                let (length, length_offset) = member_at(*self, *length)?;
                let (height, height_offset) = member_at(root_node, *height)?;
                let (node, node_offset) = resolve_selector(root_node, node)?;
                node.pointer_target()?;

                let key = self.related_type(*key);
                let value = self.related_type(*value);
                let leaf = self.related_type(*leaf);
                let (leaf_len, leaf_len_offset) = member_at(leaf, *leaf_len)?;
                let (keys, keys_offset) = member_at(leaf, *leaf_keys)?;
                let (key_slot, key_slots) = keys.array_info()?;
                if key_slot.size() != key.size() {
                    return None;
                }
                let (values, values_offset) = member_at(leaf, *leaf_values)?;
                let (value_slot, value_slots) = values.array_info()?;
                if value_slot.size() != value.size() || value_slots != key_slots {
                    return None;
                }

                let internal = self.related_type(*internal);
                let (edges, edges_offset) = member_at(internal, *internal_edges)?;
                let (edge, edge_slots) = edges.array_info()?;
                if edge_slots != key_slots + 1 {
                    return None;
                }
                let (edge_pointer, edge_pointer_offset) = resolve_selector(edge, edge_path)?;
                edge_pointer.pointer_target()?;

                Some(DebugFormat::Known(KnownFormat::BTreeMap {
                    root,
                    root_offset,
                    root_node,
                    root_node_offset: root_offset
                        .checked_add(some_offset)?
                        .checked_add(root_node_offset)?,
                    length,
                    length_offset,
                    height,
                    height_offset,
                    node_offset,
                    key,
                    value,
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
                }))
            }
        }
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

// ---------------------------------------------------------------------------
// Bundle backend conformance tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bundle_tests {
    use super::{DebugType, TypeKind};
    use crate::{ReadFromProc, TypeInfoRef};

    use exegesis::Encoding;
    use exegesis::bundle::{
        BitField as BundleBitField, Bundle, BundleTypeId, BundleView,
        DebugFormat as BundleDebugFormat, DiscrDef, DiscrValue, DiscrValues,
        DisplayNode as BundleNode, DynFutureTable, FORMAT_VERSION, Field as BundleField,
        FieldRender as BundleFieldRender, InfraTypes, KnownFormat as BundleKnownFormat, MemberDef,
        Meta, ProvenanceTable, ScalarDecode as BundleScalarDecode, Selector, StaticsTable, StrRef,
        StringInterner, TaskTable, TypeDef, TypeTable, VariantDef, VariantShape,
    };
    use std::num::NonZeroU8;

    /// Build a member-only [`Selector`] from member indices — the shape every
    /// selector in these synthetic bundles has (Phase A emits no `Deref`).
    fn sel(members: &[u32]) -> Selector {
        Selector::from(members.to_vec())
    }

    /// Build an enumerated bundle [`BundleBitField`] from pre-interned labels.
    fn ebf(name: StrRef, shift: u8, width: u8, table: Vec<(u64, StrRef)>) -> BundleBitField {
        BundleBitField {
            name,
            shift,
            width: NonZeroU8::new(width),
            render: BundleFieldRender::Enum(table),
        }
    }

    /// Build an unsigned-integer tail bundle [`BundleBitField`] (`width: None`).
    fn ubf(name: StrRef, shift: u8) -> BundleBitField {
        BundleBitField {
            name,
            shift,
            width: None,
            render: BundleFieldRender::Uint,
        }
    }

    const U32: BundleTypeId = BundleTypeId(0);
    const U64: BundleTypeId = BundleTypeId(1);
    const BOOL: BundleTypeId = BundleTypeId(2);
    const U8: BundleTypeId = BundleTypeId(3);
    const UNIT: BundleTypeId = BundleTypeId(4);
    const POINT: BundleTypeId = BundleTypeId(5);
    const MSG: BundleTypeId = BundleTypeId(6);
    const OPT: BundleTypeId = BundleTypeId(7);
    const WRAP: BundleTypeId = BundleTypeId(8);
    const PTR: BundleTypeId = BundleTypeId(9);
    const ARR: BundleTypeId = BundleTypeId(10);
    const NODE: BundleTypeId = BundleTypeId(11);
    const NODE_PTR: BundleTypeId = BundleTypeId(12);
    const VTABLE_ARRAY: BundleTypeId = BundleTypeId(13);
    const VTABLE_PTR: BundleTypeId = BundleTypeId(14);
    const FAT_PTR: BundleTypeId = BundleTypeId(15);
    const ATOMIC: BundleTypeId = BundleTypeId(16);
    const ATOMIC_STORAGE: BundleTypeId = BundleTypeId(17);
    const ATOMIC_PTR: BundleTypeId = BundleTypeId(18);
    const LOOM_ATOMIC: BundleTypeId = BundleTypeId(19);
    const LOOM_CELL: BundleTypeId = BundleTypeId(20);
    const DYN_TRAIT: BundleTypeId = BundleTypeId(21);
    const DYN_TRAIT_PTR: BundleTypeId = BundleTypeId(22);
    const RAW_WAKER_VTABLE: BundleTypeId = BundleTypeId(23);
    const FUNCTION_TARGET: BundleTypeId = BundleTypeId(24);
    const FUNCTION_PTR: BundleTypeId = BundleTypeId(25);
    const BTREE_MAP: BundleTypeId = BundleTypeId(26);
    const BTREE_ROOT: BundleTypeId = BundleTypeId(27);
    const BTREE_NODE_REF: BundleTypeId = BundleTypeId(28);
    const BTREE_LEAF_PTR: BundleTypeId = BundleTypeId(29);
    const BTREE_LEAF: BundleTypeId = BundleTypeId(30);
    const MAYBE_U32: BundleTypeId = BundleTypeId(31);
    const BTREE_SLOTS: BundleTypeId = BundleTypeId(32);
    const BTREE_INTERNAL: BundleTypeId = BundleTypeId(33);
    const BTREE_EDGES: BundleTypeId = BundleTypeId(34);
    const IPV4_OCTETS: BundleTypeId = BundleTypeId(35);
    const IPV4: BundleTypeId = BundleTypeId(36);
    const IPV6_OCTETS: BundleTypeId = BundleTypeId(37);
    const IPV6: BundleTypeId = BundleTypeId(38);
    const U8_PTR: BundleTypeId = BundleTypeId(39);
    const VEC: BundleTypeId = BundleTypeId(40);
    const STR: BundleTypeId = BundleTypeId(41);
    const STRING: BundleTypeId = BundleTypeId(42);
    const RAW_MUTEX: BundleTypeId = BundleTypeId(43);
    const NOTIFY: BundleTypeId = BundleTypeId(44);
    const SEMAPHORE: BundleTypeId = BundleTypeId(45);
    const BLOCK: BundleTypeId = BundleTypeId(46);
    const BLOCK_VALUES: BundleTypeId = BundleTypeId(47);
    const BLOCK_HEADER: BundleTypeId = BundleTypeId(48);
    const WATCH_STATE: BundleTypeId = BundleTypeId(49);
    const CHAN: BundleTypeId = BundleTypeId(50);
    const CHAN_BLOCK: BundleTypeId = BundleTypeId(51);
    const CHAN_BLOCK_HEADER: BundleTypeId = BundleTypeId(52);
    const CHAN_BLOCK_PTR: BundleTypeId = BundleTypeId(53);
    const RX_CHAN: BundleTypeId = BundleTypeId(54);
    const RX_SEMAPHORE: BundleTypeId = BundleTypeId(55);
    const ARC_INNER: BundleTypeId = BundleTypeId(56);
    const ARC_INNER_PTR: BundleTypeId = BundleTypeId(57);
    const RECEIVER: BundleTypeId = BundleTypeId(58);
    const BOUNDED_SEM: BundleTypeId = BundleTypeId(59);
    const BSEM_INNER: BundleTypeId = BundleTypeId(60);
    const BSEM_MUTEX: BundleTypeId = BundleTypeId(61);
    const BSEM_WAITLIST: BundleTypeId = BundleTypeId(62);
    const BSEM_LIST: BundleTypeId = BundleTypeId(63);
    const WAITER: BundleTypeId = BundleTypeId(64);
    const WAITER_PTR: BundleTypeId = BundleTypeId(65);
    const NOTIFY_MUTEX: BundleTypeId = BundleTypeId(66);
    const NOTIFY_LIST: BundleTypeId = BundleTypeId(67);
    const NOTIFY_WAITER: BundleTypeId = BundleTypeId(68);
    const NOTIFY_WAITER_PTR: BundleTypeId = BundleTypeId(69);

    /// A hand-built mini-bundle exercising every TypeDef kind reify touches:
    ///
    /// - `Point { x: u32 @0, y: u32 @4 }`
    /// - `Msg` — tagged enum, u8 discr @0: `A(Point)@8 | B(u64)@8 | C(unit)@8`
    /// - `Opt` — niche enum, u64 discr @0: `None(unit)=0 | Some(u64) default`
    /// - `Wrap { inner: Point @0 }` — single-member wrapper for peel()
    /// - `*Point`, `[u32; 3]`
    fn test_bundle() -> Bundle {
        let mut strings = StringInterner::new();
        let mut s = |name: &str| strings.intern(name);

        let (u32n, u64n, booln, u8n, unitn) = (s("u32"), s("u64"), s("bool"), s("u8"), s("Unit"));
        let (pointn, xn, yn) = (s("Point"), s("x"), s("y"));
        let (msgn, an, bn, cn) = (s("Msg"), s("A"), s("B"), s("C"));
        let (optn, nonen, somen) = (s("Opt"), s("None"), s("Some"));
        let (wrapn, innern) = (s("Wrap"), s("inner"));
        let (noden, valuen, nextn) = (s("Node"), s("value"), s("next"));
        let (fatn, pointern, vtablen) = (s("FatPtr"), s("pointer"), s("vtable"));
        let dyn_traitn = s("dyn app::Trait");
        let raw_waker_vtablen = s("core::task::wake::RawWakerVTable");
        let unresolvedn = s("<unresolved>");
        let (clonen, waken, wake_by_refn, dropn) =
            (s("clone"), s("wake"), s("wake_by_ref"), s("drop"));
        let (atomicn, storagen, vn) = (s("Atomic<u32>"), s("AtomicStorage<u32>"), s("v"));
        let atomic_ptrn = s("Atomic<*mut Point>");
        let (loom_atomicn, loom_celln, tuple0n) =
            (s("AtomicU32"), s("LoomUnsafeCell<Point>"), s("__0"));
        let btree_mapn = s("alloc::collections::btree::map::BTreeMap<u32, u32>");
        let btree_rootn = s("Option<NodeRef>");
        let btree_node_refn = s("NodeRef");
        let btree_leafn = s("LeafNode");
        let maybe_u32n = s("MaybeUninit<u32>");
        let btree_internaln = s("InternalNode");
        let (rootn, lengthn, heightn, noden2, lenn, keysn, valsn, datan, edgesn) = (
            s("root"),
            s("length"),
            s("height"),
            s("node"),
            s("len"),
            s("keys"),
            s("vals"),
            s("data"),
            s("edges"),
        );
        let (uninitn, some2n, none2n) = (s("uninit"), s("Some"), s("None"));
        let (ipv4n, ipv6n, octetsn) = (
            s("core::net::ip_addr::Ipv4Addr"),
            s("core::net::ip_addr::Ipv6Addr"),
            s("octets"),
        );
        let (vecn, ptrn, vec_lenn, capacityn) =
            (s("alloc::vec::Vec<u32>"), s("ptr"), s("len"), s("capacity"));
        let (strn, stringn, data_ptrn, length2n) = (
            s("&str"),
            s("alloc::string::String"),
            s("data_ptr"),
            s("length"),
        );
        let (raw_mutexn, staten) = (s("parking_lot::raw_mutex::RawMutex"), s("state"));
        let (notifyn, waitersn) = (s("tokio::sync::notify::Notify"), s("waiters"));
        let (semaphoren, permitsn) = (s("tokio::sync::batch_semaphore::Semaphore"), s("permits"));
        let (blockn, block_headern, ready_slotsn, headerfieldn) = (
            s("tokio::sync::mpsc::block::Block<u32>"),
            s("BlockHeader"),
            s("ready_slots"),
            s("header"),
        );
        let valuesfieldn = s("values");
        let watch_staten = s("tokio::sync::watch::state::AtomicState");
        let (chann, chan_blockn, chan_block_headern) = (
            s("tokio::sync::mpsc::chan::Chan<u32>"),
            s("ChanBlock"),
            s("ChanBlockHeader"),
        );
        let (tailn, headn, indexn, start_indexn) =
            (s("tail"), s("head"), s("index"), s("start_index"));
        let (receivern, rx_semn, arc_innern) = (
            s("tokio::sync::mpsc::bounded::Receiver<u32>"),
            s("tokio::sync::mpsc::bounded::Semaphore"),
            s("alloc::sync::ArcInner<tokio::sync::mpsc::chan::Chan<u32>>"),
        );
        let (strongn, weakn, boundn, chanfieldn, semfieldn) = (
            s("strong"),
            s("weak"),
            s("bound"),
            s("chan"),
            s("semaphore"),
        );

        // Labels for the sync-primitive `ScalarDecode` tables. Interned here so
        // the decode-building closures below can assemble tables from `Copy`
        // `StrRef`s without re-borrowing the interner.
        let (lockedl, unlockedl, parkedl, unparkedl) =
            (s("locked"), s("unlocked"), s("parked"), s("unparked"));
        let (statel, idlel, waitingl, notifiedl, generationl) = (
            s("state"),
            s("idle"),
            s("waiting"),
            s("notified"),
            s("generation"),
        );
        let (closedl, openl, permitsl, versionl) =
            (s("closed"), s("open"), s("permits"), s("version"));
        let (kindl, nonel, onel, alll, orderl, fifol, lifol) = (
            s("kind"),
            s("none"),
            s("one"),
            s("all"),
            s("order"),
            s("fifo"),
            s("lifo"),
        );
        let mutex_decode = || {
            BundleScalarDecode::Bits(vec![
                ebf(lockedl, 0, 1, vec![(0, unlockedl), (1, lockedl)]),
                ebf(parkedl, 1, 1, vec![(0, unparkedl), (1, parkedl)]),
            ])
        };
        let semaphore_permits_decode = || {
            BundleScalarDecode::Bits(vec![
                ebf(closedl, 0, 1, vec![(0, openl), (1, closedl)]),
                ubf(permitsl, 1),
            ])
        };
        let (bsem_mutexn, bsem_waitlistn, bsem_listn, waitern) = (
            s(
                "lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, tokio::sync::batch_semaphore::Waitlist>",
            ),
            s("tokio::sync::batch_semaphore::Waitlist"),
            s(
                "tokio::util::linked_list::LinkedList<tokio::sync::batch_semaphore::Waiter, tokio::sync::batch_semaphore::Waiter>",
            ),
            s("tokio::sync::batch_semaphore::Waiter"),
        );
        let (rawn, closedn, queuen) = (s("raw"), s("closed"), s("queue"));
        let (notify_mutexn, notify_listn, notify_waitern, notificationn) = (
            s(
                "lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, tokio::util::linked_list::LinkedList<tokio::sync::notify::Waiter, tokio::sync::notify::Waiter>>",
            ),
            s(
                "tokio::util::linked_list::LinkedList<tokio::sync::notify::Waiter, tokio::sync::notify::Waiter>",
            ),
            s("tokio::sync::notify::Waiter"),
            s("notification"),
        );

        let m = |name, ty, offset| MemberDef { name, ty, offset };
        let tag = |v: u128| Some(DiscrValues(vec![DiscrValue::Value(v)]));

        let types = vec![
            TypeDef::Base {
                name: u32n,
                size: 4,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Base {
                name: u64n,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Base {
                name: booln,
                size: 1,
                encoding: Encoding::Boolean,
            },
            TypeDef::Base {
                name: u8n,
                size: 1,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Struct {
                name: unitn,
                size: 0,
                members: vec![],
            },
            TypeDef::Struct {
                name: pointn,
                size: 8,
                members: vec![m(xn, U32, 0), m(yn, U32, 4)],
            },
            TypeDef::Enum {
                name: msgn,
                size: 16,
                shape: VariantShape {
                    discr: Some(DiscrDef { offset: 0, ty: U8 }),
                    variants: vec![
                        VariantDef {
                            name: an,
                            discr_values: tag(0),
                            payload: m(an, POINT, 8),
                            decl: None,
                        },
                        VariantDef {
                            name: bn,
                            discr_values: tag(1),
                            payload: m(bn, U64, 8),
                            decl: None,
                        },
                        VariantDef {
                            name: cn,
                            discr_values: tag(2),
                            payload: m(cn, UNIT, 8),
                            decl: None,
                        },
                    ],
                },
            },
            TypeDef::Enum {
                name: optn,
                size: 8,
                shape: VariantShape {
                    discr: Some(DiscrDef { offset: 0, ty: U64 }),
                    variants: vec![
                        VariantDef {
                            name: nonen,
                            discr_values: tag(0),
                            payload: m(nonen, UNIT, 0),
                            decl: None,
                        },
                        VariantDef {
                            name: somen,
                            discr_values: None,
                            payload: m(somen, U64, 0),
                            decl: None,
                        },
                    ],
                },
            },
            TypeDef::Struct {
                name: wrapn,
                size: 8,
                members: vec![m(innern, POINT, 0)],
            },
            TypeDef::Pointer {
                name: None,
                target: POINT,
            },
            TypeDef::Array {
                elem: U32,
                count: 3,
            },
            TypeDef::Struct {
                name: noden,
                size: 16,
                members: vec![m(valuen, U32, 0), m(nextn, NODE_PTR, 8)],
            },
            TypeDef::Pointer {
                name: None,
                target: NODE,
            },
            TypeDef::Array {
                elem: U64,
                count: 3,
            },
            TypeDef::Pointer {
                name: None,
                target: VTABLE_ARRAY,
            },
            TypeDef::Struct {
                name: fatn,
                size: 16,
                members: vec![m(pointern, DYN_TRAIT_PTR, 0), m(vtablen, VTABLE_PTR, 8)],
            },
            TypeDef::Struct {
                name: atomicn,
                size: 4,
                members: vec![m(vn, ATOMIC_STORAGE, 0)],
            },
            TypeDef::Struct {
                name: storagen,
                size: 4,
                members: vec![m(valuen, U32, 0)],
            },
            TypeDef::Struct {
                name: atomic_ptrn,
                size: 8,
                members: vec![m(vn, PTR, 0)],
            },
            TypeDef::Struct {
                name: loom_atomicn,
                size: 4,
                members: vec![m(innern, ATOMIC, 0)],
            },
            TypeDef::Struct {
                name: loom_celln,
                size: 8,
                members: vec![m(tuple0n, WRAP, 0)],
            },
            TypeDef::Struct {
                name: dyn_traitn,
                size: 0,
                members: vec![],
            },
            TypeDef::Pointer {
                name: None,
                target: DYN_TRAIT,
            },
            TypeDef::Struct {
                name: raw_waker_vtablen,
                size: 32,
                members: vec![
                    m(clonen, PTR, 0),
                    m(waken, PTR, 8),
                    m(wake_by_refn, PTR, 16),
                    m(dropn, PTR, 24),
                ],
            },
            TypeDef::Opaque {
                name: unresolvedn,
                size: None,
            },
            TypeDef::Pointer {
                name: None,
                target: FUNCTION_TARGET,
            },
            TypeDef::Struct {
                name: btree_mapn,
                size: 24,
                members: vec![m(rootn, BTREE_ROOT, 0), m(lengthn, U64, 16)],
            },
            TypeDef::Enum {
                name: btree_rootn,
                size: 16,
                shape: VariantShape {
                    discr: Some(DiscrDef { offset: 0, ty: U64 }),
                    variants: vec![
                        VariantDef {
                            name: none2n,
                            discr_values: tag(0),
                            payload: m(none2n, UNIT, 0),
                            decl: None,
                        },
                        VariantDef {
                            name: some2n,
                            discr_values: None,
                            payload: m(some2n, BTREE_NODE_REF, 0),
                            decl: None,
                        },
                    ],
                },
            },
            TypeDef::Struct {
                name: btree_node_refn,
                size: 16,
                members: vec![m(noden2, BTREE_LEAF_PTR, 0), m(heightn, U64, 8)],
            },
            TypeDef::Pointer {
                name: None,
                target: BTREE_LEAF,
            },
            TypeDef::Struct {
                name: btree_leafn,
                size: 20,
                members: vec![
                    m(lenn, U8, 0),
                    m(keysn, BTREE_SLOTS, 4),
                    m(valsn, BTREE_SLOTS, 12),
                ],
            },
            TypeDef::Union {
                name: maybe_u32n,
                size: 4,
                members: vec![m(uninitn, UNIT, 0), m(valuen, U32, 0)],
            },
            TypeDef::Array {
                elem: MAYBE_U32,
                count: 2,
            },
            TypeDef::Struct {
                name: btree_internaln,
                size: 48,
                members: vec![m(datan, BTREE_LEAF, 0), m(edgesn, BTREE_EDGES, 24)],
            },
            TypeDef::Array {
                elem: BTREE_LEAF_PTR,
                count: 3,
            },
            TypeDef::Array { elem: U8, count: 4 },
            TypeDef::Struct {
                name: ipv4n,
                size: 4,
                members: vec![m(octetsn, IPV4_OCTETS, 0)],
            },
            TypeDef::Array {
                elem: U8,
                count: 16,
            },
            TypeDef::Struct {
                name: ipv6n,
                size: 16,
                members: vec![m(octetsn, IPV6_OCTETS, 0)],
            },
            TypeDef::Pointer {
                name: None,
                target: U8,
            },
            TypeDef::Struct {
                name: vecn,
                size: 24,
                members: vec![
                    m(ptrn, U8_PTR, 0),
                    m(vec_lenn, U64, 8),
                    m(capacityn, U64, 16),
                ],
            },
            TypeDef::Struct {
                name: strn,
                size: 16,
                members: vec![m(data_ptrn, U8_PTR, 0), m(length2n, U64, 8)],
            },
            TypeDef::Struct {
                name: stringn,
                size: 24,
                members: vec![
                    m(ptrn, U8_PTR, 0),
                    m(vec_lenn, U64, 8),
                    m(capacityn, U64, 16),
                ],
            },
            TypeDef::Struct {
                name: raw_mutexn,
                size: 1,
                members: vec![m(staten, U8, 0)],
            },
            // Notify { state: usize @0, waiters: Mutex<LinkedList<Waiter>> @8 }
            // (the loom/UnsafeCell wrappers the detector navigates are collapsed
            // here — reify only needs the resolved offsets).
            TypeDef::Struct {
                name: notifyn,
                size: 32,
                members: vec![m(staten, U64, 0), m(waitersn, NOTIFY_MUTEX, 8)],
            },
            TypeDef::Struct {
                name: semaphoren,
                size: 16,
                members: vec![m(permitsn, U64, 0), m(waitersn, U32, 8)],
            },
            TypeDef::Struct {
                name: blockn,
                size: 24,
                members: vec![
                    m(valuesfieldn, BLOCK_VALUES, 0),
                    m(headerfieldn, BLOCK_HEADER, 16),
                ],
            },
            TypeDef::Array {
                elem: U32,
                count: 4,
            },
            TypeDef::Struct {
                name: block_headern,
                size: 8,
                members: vec![m(ready_slotsn, U64, 0)],
            },
            TypeDef::Struct {
                name: watch_staten,
                size: 8,
                members: vec![m(tuple0n, U64, 0)],
            },
            // Chan { tail: usize @0, index: usize @8, head: *ChanBlock @16 }
            TypeDef::Struct {
                name: chann,
                size: 24,
                members: vec![
                    m(tailn, U64, 0),
                    m(indexn, U64, 8),
                    m(headn, CHAN_BLOCK_PTR, 16),
                ],
            },
            // ChanBlock { values: [u32; 4] @0, header: ChanBlockHeader @16 }
            TypeDef::Struct {
                name: chan_blockn,
                size: 32,
                members: vec![
                    m(valuesfieldn, BLOCK_VALUES, 0),
                    m(headerfieldn, CHAN_BLOCK_HEADER, 16),
                ],
            },
            // ChanBlockHeader { start_index: usize @0, next: *ChanBlock @8 }
            TypeDef::Struct {
                name: chan_block_headern,
                size: 16,
                members: vec![m(start_indexn, U64, 0), m(nextn, CHAN_BLOCK_PTR, 8)],
            },
            TypeDef::Pointer {
                name: None,
                target: CHAN_BLOCK,
            },
            // RxChan: tail @0, index @8, head @16, semaphore @24 (like Chan
            // but with the bounded semaphore appended).
            TypeDef::Struct {
                name: chann,
                size: 40,
                members: vec![
                    m(tailn, U64, 0),
                    m(indexn, U64, 8),
                    m(headn, CHAN_BLOCK_PTR, 16),
                    m(semfieldn, RX_SEMAPHORE, 24),
                ],
            },
            // bounded::Semaphore { permits: usize @0, bound: usize @8 }.
            TypeDef::Struct {
                name: rx_semn,
                size: 16,
                members: vec![m(permitsn, U64, 0), m(boundn, U64, 8)],
            },
            // ArcInner { strong: usize @0, weak: usize @8, data: RxChan @16 }.
            TypeDef::Struct {
                name: arc_innern,
                size: 56,
                members: vec![m(strongn, U64, 0), m(weakn, U64, 8), m(datan, RX_CHAN, 16)],
            },
            TypeDef::Pointer {
                name: None,
                target: ARC_INNER,
            },
            // Receiver { chan: *ArcInner @0 } (Rx/Arc/NonNull collapsed to the
            // single raw pointer the format actually navigates to).
            TypeDef::Struct {
                name: receivern,
                size: 8,
                members: vec![m(chanfieldn, ARC_INNER_PTR, 0)],
            },
            // bounded::Semaphore { semaphore: batch Semaphore @0, bound @48 }.
            TypeDef::Struct {
                name: rx_semn,
                size: 56,
                members: vec![m(semfieldn, BSEM_INNER, 0), m(boundn, U64, 48)],
            },
            // batch_semaphore::Semaphore { waiters: Mutex @0, permits @40 }.
            TypeDef::Struct {
                name: semaphoren,
                size: 48,
                members: vec![m(waitersn, BSEM_MUTEX, 0), m(permitsn, U64, 40)],
            },
            // Mutex { raw: RawMutex @0, data: Waitlist @8 } (the loom/UnsafeCell
            // wrappers the detector navigates are collapsed here — reify only
            // needs the resolved offsets).
            TypeDef::Struct {
                name: bsem_mutexn,
                size: 40,
                members: vec![m(rawn, RAW_MUTEX, 0), m(datan, BSEM_WAITLIST, 8)],
            },
            // Waitlist { queue: LinkedList @0, closed: bool @24 }.
            TypeDef::Struct {
                name: bsem_waitlistn,
                size: 32,
                members: vec![m(queuen, BSEM_LIST, 0), m(closedn, BOOL, 24)],
            },
            // LinkedList { head: *Waiter @0, tail: *Waiter @8 }.
            TypeDef::Struct {
                name: bsem_listn,
                size: 16,
                members: vec![m(headn, WAITER_PTR, 0), m(tailn, WAITER_PTR, 8)],
            },
            // Waiter { state: usize @0 (permits needed), next: *Waiter @8 }.
            TypeDef::Struct {
                name: waitern,
                size: 32,
                members: vec![m(staten, U64, 0), m(nextn, WAITER_PTR, 8)],
            },
            TypeDef::Pointer {
                name: None,
                target: WAITER,
            },
            // Notify's waiter mutex: Mutex { raw: RawMutex @0, data: LinkedList
            // @8 } (loom/UnsafeCell wrappers collapsed; unlike the batch
            // semaphore there is no Waitlist — the mutex guards the list directly).
            TypeDef::Struct {
                name: notify_mutexn,
                size: 24,
                members: vec![m(rawn, RAW_MUTEX, 0), m(datan, NOTIFY_LIST, 8)],
            },
            // LinkedList { head: *Waiter @0, tail: *Waiter @8 }.
            TypeDef::Struct {
                name: notify_listn,
                size: 16,
                members: vec![
                    m(headn, NOTIFY_WAITER_PTR, 0),
                    m(tailn, NOTIFY_WAITER_PTR, 8),
                ],
            },
            // Waiter { notification: usize @0, next: *Waiter @8 }.
            TypeDef::Struct {
                name: notify_waitern,
                size: 32,
                members: vec![m(notificationn, U64, 0), m(nextn, NOTIFY_WAITER_PTR, 8)],
            },
            TypeDef::Pointer {
                name: None,
                target: NOTIFY_WAITER,
            },
        ];

        // Field labels for the node-based `BoundedSemaphore` formatter (deduped
        // by the interner, so re-interning existing strings is harmless).
        let (mutexfl, closedfl, permitsfl, boundfl, queuefl, permits_neededfl) = (
            s("mutex"),
            s("closed"),
            s("permits"),
            s("bound"),
            s("queue"),
            s("permits_needed"),
        );
        let (emptyl, falsel, truel) = (s(""), s("false"), s("true"));
        let bool_decode =
            || BundleScalarDecode::Bits(vec![ebf(emptyl, 0, 0, vec![(0, falsel), (1, truel)])]);

        let b = Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings: strings.finish(),
            types: TypeTable {
                types,
                debug_formats: std::collections::BTreeMap::from([
                    (WRAP, BundleDebugFormat::Transparent { member: sel(&[0]) }),
                    (
                        ATOMIC,
                        BundleDebugFormat::Known(BundleKnownFormat::Atomic {
                            value: sel(&[0, 0]),
                        }),
                    ),
                    (
                        ATOMIC_PTR,
                        BundleDebugFormat::Known(BundleKnownFormat::Atomic { value: sel(&[0]) }),
                    ),
                    (
                        LOOM_ATOMIC,
                        BundleDebugFormat::Transparent { member: sel(&[0]) },
                    ),
                    (
                        LOOM_CELL,
                        BundleDebugFormat::Transparent { member: sel(&[0]) },
                    ),
                    (
                        FAT_PTR,
                        BundleDebugFormat::Known(BundleKnownFormat::DynPointer {
                            pointer: 0,
                            vtable: 1,
                            drop_in_place: 0,
                            size: 1,
                            align: 2,
                            tail_offset: 0,
                        }),
                    ),
                    (
                        RAW_WAKER_VTABLE,
                        BundleDebugFormat::Known(BundleKnownFormat::RawWakerVTable {
                            clone: 0,
                            wake: 1,
                            wake_by_ref: 2,
                            drop: 3,
                        }),
                    ),
                    (
                        FUNCTION_PTR,
                        BundleDebugFormat::Known(BundleKnownFormat::FunctionPointer),
                    ),
                    (
                        BTREE_MAP,
                        BundleDebugFormat::Known(BundleKnownFormat::BTreeMap {
                            root: 0,
                            length: 1,
                            root_node: sel(&[]),
                            height: 1,
                            node: sel(&[0]),
                            key: U32,
                            value: U32,
                            leaf: BTREE_LEAF,
                            leaf_len: 0,
                            leaf_keys: 1,
                            leaf_values: 2,
                            internal: BTREE_INTERNAL,
                            internal_data: 0,
                            internal_edges: 1,
                            edge: sel(&[]),
                        }),
                    ),
                    (
                        IPV4,
                        BundleDebugFormat::Known(BundleKnownFormat::IpAddress {
                            octets: sel(&[0]),
                        }),
                    ),
                    (
                        IPV6,
                        BundleDebugFormat::Known(BundleKnownFormat::IpAddress {
                            octets: sel(&[0]),
                        }),
                    ),
                    (
                        VEC,
                        BundleDebugFormat::Known(BundleKnownFormat::Vec {
                            pointer: sel(&[0]),
                            length: sel(&[1]),
                            capacity: sel(&[2]),
                            element: U32,
                        }),
                    ),
                    (
                        STR,
                        BundleDebugFormat::Known(BundleKnownFormat::Str {
                            pointer: sel(&[0]),
                            length: sel(&[1]),
                        }),
                    ),
                    (
                        STRING,
                        BundleDebugFormat::Known(BundleKnownFormat::String {
                            pointer: sel(&[0]),
                            length: sel(&[1]),
                            capacity: sel(&[2]),
                        }),
                    ),
                    (
                        RAW_MUTEX,
                        BundleDebugFormat::Known(BundleKnownFormat::RawMutex {
                            state: sel(&[0]),
                            state_decode: mutex_decode(),
                        }),
                    ),
                    (
                        NOTIFY,
                        BundleDebugFormat::Known(BundleKnownFormat::Notify {
                            state: sel(&[0]),
                            state_decode: BundleScalarDecode::Bits(vec![
                                ebf(
                                    statel,
                                    0,
                                    2,
                                    vec![(0, idlel), (1, waitingl), (2, notifiedl)],
                                ),
                                ubf(generationl, 2),
                            ]),
                            mutex: sel(&[1, 0, 0]),
                            mutex_decode: mutex_decode(),
                            head: sel(&[1, 1, 0]),
                            waiter: NOTIFY_WAITER,
                            waiter_notification: sel(&[0]),
                            waiter_notification_decode: BundleScalarDecode::Bits(vec![
                                ebf(kindl, 0, 2, vec![(0, nonel), (1, onel), (2, alll)]),
                                ebf(orderl, 2, 1, vec![(0, fifol), (1, lifol)]),
                            ]),
                            waiter_next: sel(&[1]),
                        }),
                    ),
                    (
                        SEMAPHORE,
                        BundleDebugFormat::Known(BundleKnownFormat::Semaphore {
                            permits: sel(&[0]),
                            permits_decode: semaphore_permits_decode(),
                        }),
                    ),
                    (
                        BLOCK,
                        BundleDebugFormat::Known(BundleKnownFormat::MpscBlock {
                            ready_slots: sel(&[1, 0]),
                            values: sel(&[0]),
                        }),
                    ),
                    (
                        WATCH_STATE,
                        BundleDebugFormat::Known(BundleKnownFormat::WatchState {
                            state: sel(&[0]),
                            state_decode: BundleScalarDecode::Bits(vec![
                                ebf(closedl, 0, 1, vec![(0, openl), (1, closedl)]),
                                ubf(versionl, 1),
                            ]),
                        }),
                    ),
                    (
                        CHAN,
                        BundleDebugFormat::Known(BundleKnownFormat::MpscChan {
                            tail: sel(&[0]),
                            index: sel(&[1]),
                            head: sel(&[2]),
                            start_index: sel(&[1, 0]),
                            next: sel(&[1, 1]),
                            values: sel(&[0]),
                            element: U32,
                        }),
                    ),
                    (
                        RX_CHAN,
                        BundleDebugFormat::Known(BundleKnownFormat::MpscChan {
                            tail: sel(&[0]),
                            index: sel(&[1]),
                            head: sel(&[2]),
                            start_index: sel(&[1, 0]),
                            next: sel(&[1, 1]),
                            values: sel(&[0]),
                            element: U32,
                        }),
                    ),
                    (
                        RECEIVER,
                        BundleDebugFormat::Known(BundleKnownFormat::MpscRx {
                            // Receiver → raw pointer @ member 0; ArcInner → `data`
                            // @ member 2; capacity/permits within the RxChan's
                            // semaphore (member 3): bound @1, permits @0.
                            chan_pointer: sel(&[0]),
                            chan: sel(&[2]),
                            bound: sel(&[3, 1]),
                            permits: sel(&[3, 0]),
                            permits_decode: semaphore_permits_decode(),
                        }),
                    ),
                    (
                        BOUNDED_SEM,
                        BundleDebugFormat::Node(BundleNode::Struct {
                            fields: vec![
                                BundleField::Named {
                                    label: mutexfl,
                                    node: BundleNode::Scalar {
                                        at: sel(&[0, 0, 0, 0]),
                                        decode: mutex_decode(),
                                    },
                                },
                                BundleField::Named {
                                    label: closedfl,
                                    node: BundleNode::Scalar {
                                        at: sel(&[0, 0, 1, 1]),
                                        decode: bool_decode(),
                                    },
                                },
                                BundleField::Named {
                                    label: permitsfl,
                                    node: BundleNode::Scalar {
                                        at: sel(&[0, 1]),
                                        decode: semaphore_permits_decode(),
                                    },
                                },
                                BundleField::Named {
                                    label: boundfl,
                                    node: BundleNode::Scalar {
                                        at: sel(&[1]),
                                        decode: BundleScalarDecode::Raw,
                                    },
                                },
                                BundleField::Named {
                                    label: queuefl,
                                    node: BundleNode::List {
                                        head: sel(&[0, 0, 1, 0, 0]),
                                        next: sel(&[1]),
                                        node: Box::new(BundleNode::Struct {
                                            fields: vec![BundleField::Named {
                                                label: permits_neededfl,
                                                node: BundleNode::Scalar {
                                                    at: sel(&[0]),
                                                    decode: BundleScalarDecode::Raw,
                                                },
                                            }],
                                        }),
                                        node_ty: WAITER,
                                    },
                                },
                            ],
                        }),
                    ),
                ]),
                name_index: vec![(pointn, POINT)],
            },
            tasks: TaskTable::default(),
            dyn_futures: DynFutureTable::default(),
            statics: StaticsTable::default(),
            infra: InfraTypes {
                header: U32,
                vtable: U32,
                trailer: U32,
                context: U32,
                scheduler_handle: U32,
                mt_handle: U32,
                location: U32,
                raw_waker_vtable: RAW_WAKER_VTABLE,
            },
            provenance: ProvenanceTable::default(),
        };
        b.validate().expect("test bundle must validate");
        b
    }

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
    fn test_ip_addresses_use_standard_notation() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let ipv4 = [192, 0, 2, 1];
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(v.ty(IPV4).unwrap(), 0, &ipv4).display()
            ),
            "192.0.2.1"
        );

        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            format!(
                "{}",
                TypeInfoRef::new(v.ty(IPV6).unwrap(), 0, &ipv6).display()
            ),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_vec_displays_initialized_elements() {
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x2000);
                assert_eq!(len, 12);
                Ok([5u32, 8, 13]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x2000u64, 3, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "[5, 8, 13]"
        );
        assert_eq!(
            format!("{:#}", value.display_from_target(&Reader, 8)),
            "[\n    5,\n    8,\n    13,\n]"
        );

        let invalid: Vec<u8> = [0x2000u64, 5, 4]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(VEC).unwrap(), 0, &invalid);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "<invalid Vec: length exceeds capacity>"
        );
    }

    #[test]
    fn test_str_and_string_display_quoted_utf8() {
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                let bytes: &[u8] = match addr {
                    0x3000 => b"hi\nthere",
                    0x4000 => b"owned\ttext",
                    _ => panic!("unexpected address 0x{addr:x}"),
                };
                assert_eq!(len, bytes.len() as u64);
                Ok(bytes.to_vec())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let str_bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(STR).unwrap(), 0, &str_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "\"hi\\nthere\""
        );

        let string_bytes: Vec<u8> = [0x4000u64, 10, 16]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(STRING).unwrap(), 0, &string_bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "\"owned\\ttext\""
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
    fn test_transparent_debug_format_elides_wrapper() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let value = TypeInfoRef::new(v.ty(WRAP).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_with_depth(2)),
            "Point { x: 3, y: 4 }"
        );
    }

    #[test]
    fn test_atomic_debug_format_displays_stored_value() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 42u32.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(ATOMIC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", value.display_with_depth(1)), "42");
    }

    #[test]
    fn test_nested_transparent_formats_do_not_consume_depth() {
        let b = test_bundle();
        let v = BundleView::new(&b);

        let bytes = 42u32.to_le_bytes();
        let atomic = TypeInfoRef::new(v.ty(LOOM_ATOMIC).unwrap(), 0, &bytes);
        assert_eq!(format!("{}", atomic.display_with_depth(1)), "42");

        let bytes: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let cell = TypeInfoRef::new(v.ty(LOOM_CELL).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", cell.display_with_depth(2)),
            "Point { x: 3, y: 4 }"
        );
    }

    #[test]
    fn test_atomic_pointer_does_not_dereference_stored_address() {
        struct NoReads;

        impl ReadFromProc for NoReads {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("atomic pointer formatter unexpectedly read {addr:#x}")
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(ATOMIC_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&NoReads, 8)),
            "0x1000"
        );
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
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                let (value, next) = match addr {
                    0x1000 => (1u32, 0x2000u64),
                    0x2000 => (2u32, 0u64),
                    _ => return Err(crate::Error::invalid_addr(addr)),
                };
                let mut bytes = vec![0; 16];
                bytes[..4].copy_from_slice(&value.to_le_bytes());
                bytes[8..].copy_from_slice(&next.to_le_bytes());
                Ok(bytes)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x1000u64.to_le_bytes();
        let root = TypeInfoRef::new(v.ty(NODE_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", root.display_from_target(&Reader, 8));
        assert!(shown.contains("value: 1"), "{shown}");
        assert!(shown.contains("value: 2"), "{shown}");

        let shallow = format!("{:#}", root.display_from_target(&Reader, 1));
        assert_eq!(shallow, "0x1000 -> ...");
    }

    #[test]
    fn test_dyn_pointer_formats_unknown_concrete_type() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x3000);
                Ok([0x2c557a0u64, 152, 8]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1234u64, 0x3000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(FAT_PTR).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
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
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                match addr {
                    0x1234 => Ok([1u32, 2].into_iter().flat_map(u32::to_le_bytes).collect()),
                    0x3000 => Ok([0u64, 8, 8, 0x4000]
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect()),
                    _ => Err(crate::Error::invalid_addr(addr)),
                }
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                (addr == 0x4000).then(|| "<Point as app::Trait>::run".to_owned())
            }
        }

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
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(
            shown.contains("pointer: 0x1234 -> Point {\n         x: 1,\n         y: 2,\n    },"),
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
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x3000);
                Ok([0u64, 8, 8]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect())
            }
        }

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
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(shown.starts_with("Opt::Some {"), "{shown}");
        assert!(!shown.contains("FatPtr"), "{shown}");
        assert!(shown.contains("concrete type: <unknown>,"), "{shown}");
    }

    #[test]
    fn test_str_payload_in_enum_renders_as_value() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x3000);
                assert_eq!(len, 8);
                Ok(b"hi\nthere".to_vec())
            }
        }

        // Point Opt::Some's payload at a `&str`; its `Str` display format
        // must win over dumping the fat pointer's raw fields, matching how a
        // `Cow<str>::Borrowed` key should read.
        let mut b = test_bundle();
        let TypeDef::Enum { size, shape, .. } = &mut b.types.types[OPT.0 as usize] else {
            panic!("Opt is not an enum");
        };
        *size = 16;
        shape.variants[1].payload.ty = STR;
        b.validate().expect("modified enum bundle must validate");
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x3000u64, 8]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(OPT).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "Opt::Some(\"hi\\nthere\")"
        );
    }

    #[test]
    fn test_raw_mutex_decodes_lock_state() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let cases = [
            (
                0u8,
                "parking_lot::raw_mutex::RawMutex: locked=unlocked, parked=unparked",
            ),
            (
                1,
                "parking_lot::raw_mutex::RawMutex: locked=locked, parked=unparked",
            ),
            (
                2,
                "parking_lot::raw_mutex::RawMutex: locked=unlocked, parked=parked",
            ),
            (
                3,
                "parking_lot::raw_mutex::RawMutex: locked=locked, parked=parked",
            ),
        ];
        for (state, expected) in cases {
            let value = TypeInfoRef::new(v.ty(RAW_MUTEX).unwrap(), 0, std::slice::from_ref(&state));
            assert_eq!(format!("{}", value.display()), expected, "state={state}");
        }
    }

    #[test]
    fn test_notify_renders_compact_state_mutex_and_waiters() {
        // Two waiters live at 0x3000 and 0x3020: the first still parked (no
        // notification), the second handed a `notify_one` notification.
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                // Waiter { notification: usize @0, next: *Waiter @8 }.
                let (notification, next) = match addr {
                    0x3000 => (0u64, 0x3020u64),
                    0x3020 => (1u64, 0u64),
                    other => panic!("unexpected read at {other:#x}"),
                };
                let mut b = Vec::new();
                b.extend_from_slice(&notification.to_le_bytes());
                b.extend_from_slice(&next.to_le_bytes());
                b.resize(32, 0);
                b.truncate(len as usize);
                Ok(b)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Flat Notify buffer: state @0, mutex state byte @8, head @16, tail @24.
        let notify = |state: u64, mutex: u8, head: u64| {
            let mut buf = vec![0u8; 32];
            buf[0..8].copy_from_slice(&state.to_le_bytes());
            buf[8] = mutex;
            buf[16..24].copy_from_slice(&head.to_le_bytes());
            buf
        };

        // Idle, unlocked, two parked waiters.
        let buf = notify(0, 0, 0x3000);
        let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "tokio::sync::notify::Notify { state: state=idle, generation=0, \
             mutex: locked=unlocked, parked=unparked, queue: [\
             tokio::sync::notify::Waiter { notification: kind=none, order=fifo }, \
             tokio::sync::notify::Waiter { notification: kind=one, order=fifo }] }"
        );

        // Notified with two notify_waiters calls, locked mutex, empty queue.
        // 0b1010 = notified (state 2) with generation 2 (10 >> 2).
        let buf = notify(0b1010, 0b01, 0);
        let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "tokio::sync::notify::Notify { state: state=notified, generation=2, \
             mutex: locked=locked, parked=unparked, queue: [] }"
        );

        // Without a target the queue cannot be walked, but state and mutex
        // (read from the value's own bytes) still render.
        let buf = notify(1, 0, 0x3000);
        let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        let shown = format!("{}", value.display());
        assert!(shown.contains("state: state=waiting"), "{shown}");
        assert!(shown.contains("queue: <target unavailable>"), "{shown}");

        // Pretty mode puts each field and waiter on its own indented line.
        let buf = notify(0, 0, 0x3000);
        let value = TypeInfoRef::new(v.ty(NOTIFY).unwrap(), 0, &buf);
        assert_eq!(
            format!("{:#}", value.display_from_target(&Reader, 8)),
            "tokio::sync::notify::Notify {\n\
             \x20   state: state=idle, generation=0,\n\
             \x20   mutex: locked=unlocked, parked=unparked,\n\
             \x20   queue: [\n\
             \x20       tokio::sync::notify::Waiter { notification: kind=none, order=fifo },\n\
             \x20       tokio::sync::notify::Waiter { notification: kind=one, order=fifo },\n\
             \x20   ],\n\
             }"
        );
    }

    #[test]
    fn test_semaphore_decodes_permits_field_in_place() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // 16-byte Semaphore: permits usize @0, waiters u32 @8.
        let bytes = |permits: u64, waiters: u32| {
            let mut buf = Vec::new();
            buf.extend_from_slice(&permits.to_le_bytes());
            buf.extend_from_slice(&waiters.to_le_bytes());
            buf.extend_from_slice(&[0u8; 4]);
            buf
        };
        let cases = [
            // permits are stored shifted left by one; bit 0 is the closed flag.
            (
                64u64,
                3u32,
                "tokio::sync::batch_semaphore::Semaphore { permits: closed=open, permits=32, \
                 waiters: 3 }",
            ),
            (
                0,
                0,
                "tokio::sync::batch_semaphore::Semaphore { permits: closed=open, permits=0, \
                 waiters: 0 }",
            ),
            // 65 = (32 << 1) | 1: 32 permits, closed.
            (
                65,
                9,
                "tokio::sync::batch_semaphore::Semaphore { permits: closed=closed, permits=32, \
                 waiters: 9 }",
            ),
        ];
        for (permits, waiters, expected) in cases {
            let buf = bytes(permits, waiters);
            let value = TypeInfoRef::new(v.ty(SEMAPHORE).unwrap(), 0, &buf);
            assert_eq!(
                format!("{}", value.display()),
                expected,
                "permits={permits}"
            );
        }
    }

    #[test]
    fn test_mpsc_block_elides_values_to_written_count() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        // 24-byte Block: [u32; 4] value slots @0, ready-bitmap usize @16.
        let block = |ready: u64| {
            let mut buf = vec![0u8; 16];
            buf.extend_from_slice(&ready.to_le_bytes());
            buf
        };
        // Three bits set within the 4-slot capacity: three written slots.
        let buf = block(0b1011);
        let value = TypeInfoRef::new(v.ty(BLOCK).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display()),
            "tokio::sync::mpsc::block::Block<u32> { values: [3 slots], header: BlockHeader { ready_slots: 11 } }"
        );

        // Bits outside the 4-slot capacity (released/closed flags) are ignored.
        let buf = block(0b1_0000);
        let value = TypeInfoRef::new(v.ty(BLOCK).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display()),
            "tokio::sync::mpsc::block::Block<u32> { values: [0 slots], header: BlockHeader { ready_slots: 16 } }"
        );
    }

    #[test]
    fn test_mpsc_chan_shows_only_queued_messages() {
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x1000);
                // ChanBlock: [u32; 4] values @0, start_index usize @16, next ptr @24.
                let mut b = Vec::new();
                for v in [10u32, 20, 30, 40] {
                    b.extend_from_slice(&v.to_le_bytes());
                }
                b.extend_from_slice(&0u64.to_le_bytes()); // start_index
                b.extend_from_slice(&0u64.to_le_bytes()); // next (null)
                b.truncate(len as usize);
                Ok(b)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Chan: tail usize @0, index usize @8, head ptr @16.
        let chan = |tail: u64, index: u64| {
            let mut c = Vec::new();
            c.extend_from_slice(&tail.to_le_bytes());
            c.extend_from_slice(&index.to_le_bytes());
            c.extend_from_slice(&0x1000u64.to_le_bytes());
            c
        };

        // index=1, tail=3: slots 1 and 2 are still queued.
        let bytes = chan(3, 1);
        let value = TypeInfoRef::new(v.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&Reader, 8));
        assert!(shown.contains("queued: [20, 30]"), "{shown}");

        // Drained channel (index == tail): nothing queued, no stale slots shown.
        let bytes = chan(3, 3);
        let value = TypeInfoRef::new(v.ty(CHAN).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&Reader, 8));
        assert!(shown.contains("queued: []"), "{shown}");
    }

    #[test]
    fn test_mpsc_rx_renders_channel_with_capacity_and_free() {
        // The receiver's Arc raw pointer is 0x2000; the Chan sits 16 bytes in,
        // past the ArcInner strong/weak header, at 0x2010. Its head block is at
        // 0x1000.
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                let mut b = Vec::new();
                match addr {
                    0x2010 => {
                        // RxChan: tail @0, index @8, head @16, semaphore @24
                        // (permits @24, bound @32).
                        b.extend_from_slice(&3u64.to_le_bytes()); // tail
                        b.extend_from_slice(&1u64.to_le_bytes()); // index
                        b.extend_from_slice(&0x1000u64.to_le_bytes()); // head
                        b.extend_from_slice(&6u64.to_le_bytes()); // permits -> free 3
                        b.extend_from_slice(&16u64.to_le_bytes()); // bound -> capacity 16
                    }
                    0x1000 => {
                        // ChanBlock: [u32; 4] values, start_index, next (null).
                        for v in [10u32, 20, 30, 40] {
                            b.extend_from_slice(&v.to_le_bytes());
                        }
                        b.extend_from_slice(&0u64.to_le_bytes()); // start_index
                        b.extend_from_slice(&0u64.to_le_bytes()); // next
                    }
                    other => panic!("unexpected read at {other:#x}"),
                }
                b.truncate(len as usize);
                Ok(b)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Receiver holds the Arc raw pointer.
        let bytes = 0x2000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(RECEIVER).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&Reader, 8));
        assert!(
            shown.starts_with("tokio::sync::mpsc::bounded::Receiver<u32> {"),
            "{shown}"
        );
        assert!(shown.contains("capacity: 16"), "{shown}");
        assert!(shown.contains("free: closed=open, permits=3"), "{shown}");
        assert!(shown.contains("queued: [20, 30]"), "{shown}");

        // A null channel pointer is reported rather than dereferenced.
        let bytes = 0u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(RECEIVER).unwrap(), 0, &bytes);
        let shown = format!("{}", value.display_from_target(&Reader, 8));
        assert_eq!(
            shown,
            "tokio::sync::mpsc::bounded::Receiver<u32> { <null> }"
        );
    }

    #[test]
    fn test_bounded_semaphore_renders_compact_state_and_waiters() {
        // Two waiters live at 0x3000 and 0x3020, blocked on 2 and 1 permits.
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                // Waiter { state: usize @0, next: *Waiter @8 }.
                let (state, next) = match addr {
                    0x3000 => (2u64, 0x3020u64),
                    0x3020 => (1u64, 0u64),
                    other => panic!("unexpected read at {other:#x}"),
                };
                let mut b = Vec::new();
                b.extend_from_slice(&state.to_le_bytes());
                b.extend_from_slice(&next.to_le_bytes());
                b.resize(32, 0);
                b.truncate(len as usize);
                Ok(b)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        // Flat bounded::Semaphore buffer: mutex state @0, head @8, tail @16,
        // closed @32, permits @40, bound @48.
        let sem = |mutex: u8, head: u64, closed: u8, permits: u64, bound: u64| {
            let mut buf = vec![0u8; 56];
            buf[0] = mutex;
            buf[8..16].copy_from_slice(&head.to_le_bytes());
            buf[32] = closed;
            buf[40..48].copy_from_slice(&permits.to_le_bytes());
            buf[48..56].copy_from_slice(&bound.to_le_bytes());
            buf
        };

        // Unlocked, open, 10 permits (stored << 1), capacity 16, two waiters.
        let buf = sem(0, 0x3000, 0, 20, 16);
        let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "tokio::sync::mpsc::bounded::Semaphore { mutex: locked=unlocked, parked=unparked, \
             closed: false, permits: closed=open, permits=10, bound: 16, queue: [\
             tokio::sync::batch_semaphore::Waiter { permits_needed: 2 }, \
             tokio::sync::batch_semaphore::Waiter { permits_needed: 1 }] }"
        );

        // Locked, closed, no permits, empty queue (null head).
        let buf = sem(0b01, 0, 1, 0, 16);
        let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "tokio::sync::mpsc::bounded::Semaphore { mutex: locked=locked, parked=unparked, \
             closed: true, permits: closed=open, permits=0, bound: 16, queue: [] }"
        );

        // Without a target the queue cannot be walked, but the inline fields
        // (read from the value's own bytes) still render.
        let buf = sem(0, 0x3000, 0, 20, 16);
        let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        let shown = format!("{}", value.display());
        assert!(
            shown.contains("permits: closed=open, permits=10"),
            "{shown}"
        );
        assert!(shown.contains("queue: <target unavailable>"), "{shown}");

        // Pretty mode puts each field and waiter on its own indented line.
        let buf = sem(0, 0x3000, 0, 20, 16);
        let value = TypeInfoRef::new(v.ty(BOUNDED_SEM).unwrap(), 0, &buf);
        assert_eq!(
            format!("{:#}", value.display_from_target(&Reader, 8)),
            "tokio::sync::mpsc::bounded::Semaphore {\n\
             \x20   mutex: locked=unlocked, parked=unparked,\n\
             \x20   closed: false,\n\
             \x20   permits: closed=open, permits=10,\n\
             \x20   bound: 16,\n\
             \x20   queue: [\n\
             \x20       tokio::sync::batch_semaphore::Waiter { permits_needed: 2 },\n\
             \x20       tokio::sync::batch_semaphore::Waiter { permits_needed: 1 },\n\
             \x20   ],\n\
             }"
        );
    }

    #[test]
    fn test_watch_state_decodes_version_and_closed() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let cases = [
            // Bit 0 is the closed flag; the version is the remaining bits, so
            // it reads as the update count (tokio steps the state by 2), e.g.
            // raw 4 → version 2.
            (
                0u64,
                "tokio::sync::watch::state::AtomicState: closed=open, version=0",
            ),
            (
                4,
                "tokio::sync::watch::state::AtomicState: closed=open, version=2",
            ),
            (
                1,
                "tokio::sync::watch::state::AtomicState: closed=closed, version=0",
            ),
            (
                5,
                "tokio::sync::watch::state::AtomicState: closed=closed, version=2",
            ),
        ];
        for (state, expected) in cases {
            let bytes = state.to_le_bytes();
            let value = TypeInfoRef::new(v.ty(WATCH_STATE).unwrap(), 0, &bytes);
            assert_eq!(format!("{}", value.display()), expected, "state={state}");
        }
    }

    #[test]
    fn test_raw_waker_vtable_resolves_function_symbols() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("function pointer at {addr:#x} must not be dereferenced")
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                match addr {
                    0x1000 => Some("tokio::runtime::task::waker::clone_waker".to_owned()),
                    0x2000 => Some("tokio::runtime::task::waker::wake_by_val".to_owned()),
                    0x3000 => Some("tokio::runtime::task::waker::wake_by_ref".to_owned()),
                    0x4000 => Some("tokio::runtime::task::waker::drop_waker".to_owned()),
                    _ => None,
                }
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes: Vec<u8> = [0x1000u64, 0x2000, 0x3000, 0x4000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let value = TypeInfoRef::new(v.ty(RAW_WAKER_VTABLE).unwrap(), 0, &bytes);
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert_eq!(
            shown,
            concat!(
                "core::task::wake::RawWakerVTable {\n",
                "    clone: 0x1000 -> tokio::runtime::task::waker::clone_waker,\n",
                "    wake: 0x2000 -> tokio::runtime::task::waker::wake_by_val,\n",
                "    wake_by_ref: 0x3000 -> tokio::runtime::task::waker::wake_by_ref,\n",
                "    drop: 0x4000 -> tokio::runtime::task::waker::drop_waker,\n",
                "}"
            )
        );
    }

    #[test]
    fn test_function_pointer_resolves_symbol_without_dereference() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("function pointer at {addr:#x} must not be dereferenced")
            }

            fn function_symbol(&self, addr: u64) -> Option<String> {
                (addr == 0x5000).then(|| "app::callback".to_owned())
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = 0x5000u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "0x5000 -> app::callback"
        );
        assert_eq!(format!("{}", value.display()), "0x5000");

        let null = 0u64.to_le_bytes();
        let value = TypeInfoRef::new(v.ty(FUNCTION_PTR).unwrap(), 0, &null);
        assert_eq!(format!("{}", value.display_from_target(&Reader, 8)), "null");
    }

    #[test]
    fn test_btree_map_displays_only_initialized_slots_in_order() {
        struct Reader;

        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                let mut bytes = vec![0xaa; len as usize];
                match addr {
                    0x1000 => {
                        bytes[0] = 1;
                        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
                        bytes[12..16].copy_from_slice(&20u32.to_le_bytes());
                        bytes[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
                        bytes[32..40].copy_from_slice(&0x3000u64.to_le_bytes());
                    }
                    0x2000 => {
                        bytes[0] = 1;
                        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
                        bytes[12..16].copy_from_slice(&10u32.to_le_bytes());
                    }
                    0x3000 => {
                        bytes[0] = 1;
                        bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
                        bytes[12..16].copy_from_slice(&30u32.to_le_bytes());
                    }
                    _ => return Err(crate::Error::invalid_addr(addr)),
                }
                Ok(bytes)
            }
        }

        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = [0u8; 24];
        bytes[..8].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..].copy_from_slice(&3u64.to_le_bytes());
        let value = TypeInfoRef::new(v.ty(BTREE_MAP).unwrap(), 0x5000, &bytes);

        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 8)),
            "alloc::collections::btree::map::BTreeMap<u32, u32> { 1: 10, 2: 20, 3: 30 }"
        );
        let shown = format!("{:#}", value.display_from_target(&Reader, 8));
        assert!(shown.contains("\n    1: 10,"), "{shown}");
        assert!(shown.contains("\n    2: 20,"), "{shown}");
        assert!(shown.contains("\n    3: 30,"), "{shown}");
        assert!(
            !shown.contains("2863311530"),
            "unused 0xaa slots leaked: {shown}"
        );
    }

    // -----------------------------------------------------------------------
    // Formatter IR (`DisplayNode`) scaffolding
    // -----------------------------------------------------------------------

    // Type ids for [`node_bundle`], dense from zero into its own type table.
    const N_U32: BundleTypeId = BundleTypeId(0);
    const N_U64: BundleTypeId = BundleTypeId(1);
    const N_U8: BundleTypeId = BundleTypeId(2);
    const N_POINT: BundleTypeId = BundleTypeId(3);
    const N_WAITER: BundleTypeId = BundleTypeId(4);
    const N_WAITER_PTR: BundleTypeId = BundleTypeId(5);
    const N_THING: BundleTypeId = BundleTypeId(6);

    /// A self-contained bundle whose sole formatter is a [`BundleNode`] tree,
    /// exercising every scaffolded node kind and field kind at once:
    ///
    /// ```text
    /// Thing {
    ///   state: <Scalar Bits>          // Named field
    ///   flag:  <Scalar Raw>           // Override field (reuses member 1's name)
    ///   point: Point { x, y }         // Member field (structural recursion)
    ///   queue: [Waiter { notification: <Scalar Bits> }, …]   // List of Struct
    /// }
    /// ```
    ///
    /// Built separately from [`test_bundle`] so its layout can't perturb the
    /// other tests' shared fixtures.
    fn node_bundle() -> Bundle {
        use BundleField::{Member, Named, Override};

        let mut strings = StringInterner::new();
        let mut s = |name: &str| strings.intern(name);

        let (u32n, u64n, u8n) = (s("u32"), s("u64"), s("u8"));
        let (pointn, xn, yn) = (s("Point"), s("x"), s("y"));
        let (thingn, staten, flagn, pointfn, headn) =
            (s("Thing"), s("state"), s("flag"), s("point"), s("head"));
        let (waitern, notifn, nextn) = (s("Waiter"), s("notification"), s("next"));
        let (statel, idlel, waitingl, notifiedl, genl) = (
            s("state"),
            s("idle"),
            s("waiting"),
            s("notified"),
            s("generation"),
        );
        let (kindl, nonel, onel, alll, orderl, fifol, lifol) = (
            s("kind"),
            s("none"),
            s("one"),
            s("all"),
            s("order"),
            s("fifo"),
            s("lifo"),
        );
        let queuel = s("queue");

        let m = |name, ty, offset| MemberDef { name, ty, offset };

        let types = vec![
            TypeDef::Base {
                name: u32n,
                size: 4,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Base {
                name: u64n,
                size: 8,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Base {
                name: u8n,
                size: 1,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Struct {
                name: pointn,
                size: 8,
                members: vec![m(xn, N_U32, 0), m(yn, N_U32, 4)],
            },
            TypeDef::Struct {
                name: waitern,
                size: 16,
                members: vec![m(notifn, N_U64, 0), m(nextn, N_WAITER_PTR, 8)],
            },
            TypeDef::Pointer {
                name: None,
                target: N_WAITER,
            },
            TypeDef::Struct {
                name: thingn,
                size: 28,
                members: vec![
                    m(staten, N_U64, 0),
                    m(flagn, N_U8, 8),
                    m(pointfn, N_POINT, 12),
                    m(headn, N_WAITER_PTR, 20),
                ],
            },
        ];

        let state_decode = BundleScalarDecode::Bits(vec![
            ebf(
                statel,
                0,
                2,
                vec![(0, idlel), (1, waitingl), (2, notifiedl)],
            ),
            ubf(genl, 2),
        ]);
        let notif_decode = BundleScalarDecode::Bits(vec![
            ebf(kindl, 0, 2, vec![(0, nonel), (1, onel), (2, alll)]),
            ebf(orderl, 2, 1, vec![(0, fifol), (1, lifol)]),
        ]);

        let waiter_node = BundleNode::Struct {
            fields: vec![Named {
                label: notifn,
                node: BundleNode::Scalar {
                    at: sel(&[0]),
                    decode: notif_decode,
                },
            }],
        };
        let thing_node = BundleNode::Struct {
            fields: vec![
                Named {
                    label: staten,
                    node: BundleNode::Scalar {
                        at: sel(&[0]),
                        decode: state_decode,
                    },
                },
                Override {
                    index: 1,
                    node: BundleNode::Scalar {
                        at: sel(&[1]),
                        decode: BundleScalarDecode::Raw,
                    },
                },
                Member(2),
                Named {
                    label: queuel,
                    node: BundleNode::List {
                        head: sel(&[3]),
                        next: sel(&[1]),
                        node: Box::new(waiter_node),
                        node_ty: N_WAITER,
                    },
                },
            ],
        };

        let b = Bundle {
            meta: Meta {
                format_version: FORMAT_VERSION,
                ..Default::default()
            },
            strings: strings.finish(),
            types: TypeTable {
                types,
                debug_formats: std::collections::BTreeMap::from([(
                    N_THING,
                    BundleDebugFormat::Node(thing_node),
                )]),
                name_index: vec![],
            },
            tasks: TaskTable::default(),
            dyn_futures: DynFutureTable::default(),
            statics: StaticsTable::default(),
            infra: InfraTypes {
                header: N_U32,
                vtable: N_U32,
                trailer: N_U32,
                context: N_U32,
                scheduler_handle: N_U32,
                mt_handle: N_U32,
                location: N_U32,
                raw_waker_vtable: N_U32,
            },
            provenance: ProvenanceTable::default(),
        };
        b.validate().expect("node bundle must validate");
        b
    }

    /// Lay out a `Thing` value's 28 bytes. `head` is the queue head word.
    fn thing_bytes(state: u64, flag: u8, x: u32, y: u32, head: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 28];
        bytes[0..8].copy_from_slice(&state.to_le_bytes());
        bytes[8] = flag;
        bytes[12..16].copy_from_slice(&x.to_le_bytes());
        bytes[16..20].copy_from_slice(&y.to_le_bytes());
        bytes[20..28].copy_from_slice(&head.to_le_bytes());
        bytes
    }

    /// Lay out a `Waiter` node's 16 bytes: notification word + successor.
    fn waiter_bytes(notification: u64, next: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[0..8].copy_from_slice(&notification.to_le_bytes());
        bytes[8..16].copy_from_slice(&next.to_le_bytes());
        bytes
    }

    #[test]
    fn test_node_struct_renders_every_field_and_list_kind() {
        // Two queued waiters at 0x100 → 0x200 → end.
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(len, 16);
                Ok(match addr {
                    0x100 => waiter_bytes(1, 0x200), // kind=one, order=fifo
                    0x200 => waiter_bytes(6, 0),     // kind=all(2), order=lifo(1): 0b110
                    _ => panic!("unexpected waiter address 0x{addr:x}"),
                })
            }
        }

        let b = node_bundle();
        let v = BundleView::new(&b);
        // state word: waiting (1) with generation 3 → (3 << 2) | 1 = 13.
        let bytes = thing_bytes(13, 1, 7, 9, 0x100);
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &bytes);

        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 16)),
            "Thing { state: state=waiting, generation=3, flag: 1, point: Point { x: 7, y: 9 }, \
             queue: [Waiter { notification: kind=one, order=fifo }, \
             Waiter { notification: kind=all, order=lifo }] }"
        );

        let pretty = format!("{:#}", value.display_from_target(&Reader, 16));
        assert!(
            pretty.contains("\n    state: state=waiting, generation=3,"),
            "{pretty}"
        );
        assert!(pretty.contains("\n    point: Point {"), "{pretty}");
        assert!(pretty.contains("\n    queue: ["), "{pretty}");
        assert!(
            pretty.contains("notification: kind=one, order=fifo"),
            "{pretty}"
        );
    }

    #[test]
    fn test_node_list_empty_and_degradation() {
        // An empty queue (head word 0) needs no target reads.
        struct NoReads;
        impl ReadFromProc for NoReads {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                panic!("no reads expected, got 0x{addr:x}")
            }
        }

        let b = node_bundle();
        let v = BundleView::new(&b);

        let empty = thing_bytes(0, 0, 0, 0, 0);
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &empty);
        assert_eq!(
            format!("{}", value.display_from_target(&NoReads, 16)),
            "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, queue: [] }"
        );

        // A populated queue with no target reader degrades, not panics.
        let populated = thing_bytes(0, 0, 0, 0, 0x100);
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &populated);
        let shown = format!("{}", value.display());
        assert!(shown.contains("queue: <target unavailable>"), "{shown}");
    }

    #[test]
    fn test_node_list_guards_cycles() {
        // A waiter whose successor points back at itself must not loop forever.
        struct Reader;
        impl ReadFromProc for Reader {
            fn read_bytes(&self, addr: u64, _len: u64) -> crate::Result<Vec<u8>> {
                assert_eq!(addr, 0x100);
                Ok(waiter_bytes(1, 0x100)) // self-cycle
            }
        }

        let b = node_bundle();
        let v = BundleView::new(&b);
        let bytes = thing_bytes(0, 0, 0, 0, 0x100);
        let value = TypeInfoRef::new(v.ty(N_THING).unwrap(), 0, &bytes);
        assert_eq!(
            format!("{}", value.display_from_target(&Reader, 16)),
            "Thing { state: state=idle, generation=0, flag: 0, point: Point { x: 0, y: 0 }, \
             queue: [Waiter { notification: kind=one, order=fifo }] }"
        );
    }

    #[test]
    fn test_node_validation_rejects_out_of_range_member() {
        // A `Member` field naming a member index the type does not have must be
        // caught by `check_node` at validation time.
        let mut b = node_bundle();
        b.types.debug_formats.insert(
            N_POINT,
            BundleDebugFormat::Node(BundleNode::Struct {
                fields: vec![BundleField::Member(9)],
            }),
        );
        let err = b
            .validate()
            .expect_err("out-of-range Member must be rejected");
        assert!(format!("{err}").contains("out of range"), "{err}");
    }
}

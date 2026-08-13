//! Detectors for the tokio types whose layout has held across every
//! supported tokio version: the sync primitives, the mpsc block chain,
//! and the loom shims. A tokio release is what moves anything here; a
//! layout a release has restructured lives in a per-family module
//! (`tokio_v1_47`) instead.

use super::ReachStep::{ActiveVariant, Deref, FindParam, Named, PeelTo, Resolved, Variant};
use super::crates::{is_raw_mutex, mutex_byte_path};
use super::std::{is_generic_atomic, unsafe_cell_layout};
use super::{
    Reach, Through, WORD, Want, find_unique, is_unsigned_integer, reach, sole_param_target,
    step_into, struct_of, transparent, unique_member, zero_offset_member,
};
use crate::bundle::{
    Arm, BundleTypeId, DisplayNode, Field, ScalarDecode, Selector, Shape, Stmt, StringInterner,
    ValueExpr,
};
use crate::extract::{Emitter, fq_name, ns_path, raw_type_size};
use crate::raw_types::RawType;
use crate::{DwReader, TypeId};

/// Render a `tokio::sync::notify::Notify` as a curated record: the notification
/// state word, the waiter mutex byte, and the intrusive waiter queue as a list
/// whose nodes each show whether that waiter has been handed a notification.
pub(super) fn notify_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The notification state word, an atomic `usize` behind tokio's loom shim.
    let state = emitter.walk(id, &reach![Named("state"), PeelTo(WORD)])?.0;

    // The waiter list lives behind the `waiters` mutex. tokio wraps it in a loom
    // shim over parking_lot's `lock_api::Mutex`; navigate the shim (`__1`) to the
    // real mutex, whose `raw` is the parking_lot RawMutex and whose `data` (an
    // `UnsafeCell`, member `value`) holds the `LinkedList` directly (there is no
    // `Waitlist` wrapper as in the batch semaphore). Reach the RawMutex's single
    // state byte through its atomic wrapper by walking to the zero-offset `u8`,
    // which works whether the compiler emitted the atomic as the generic
    // `Atomic<u8>` or the concrete `AtomicU8`.
    let raw = reach![Named("waiters"), Named("__1"), Named("raw")];
    if !is_raw_mutex(reader, emitter.landed(id, &raw)?) {
        return None;
    }
    let mutex = emitter.walk(id, &mutex_byte_path(raw))?.0;

    let (head, _) = emitter.walk(
        id,
        &reach![
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("head")
        ],
    )?;

    // The queue is a `LinkedList<Waiter, Waiter>`; its node type is the `Waiter`.
    let (_, queue_ty) = emitter.walk(
        id,
        &reach![
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value")
        ],
    )?;
    let list = struct_of(reader, queue_ty)?;
    let param = list.template_params.last()?;
    let waiter = reader.canonicalize(param.type_id);
    if fq_name(reader, waiter).as_deref() != Some("tokio::sync::notify::Waiter") {
        return None;
    }

    // Rooted at the `Waiter`: its atomic `notification` word (whether it has been
    // handed a notification) and its successor pointer (`pointers.inner.value.next`).
    let waiter_notification = emitter
        .walk(waiter, &reach![Named("notification"), PeelTo(WORD)])?
        .0;
    let (waiter_next, _) = emitter.walk(
        waiter,
        &reach![
            Named("pointers"),
            Named("inner"),
            Named("value"),
            Named("next")
        ],
    )?;

    let state_decode = emitter.notify_state_decode();
    let mutex_decode = emitter.mutex_byte_decode();
    let notification_decode = emitter.notification_decode();
    let queue = emitter.waiter_queue_field(
        head,
        waiter,
        waiter_next,
        "notification",
        waiter_notification,
        notification_decode,
    );
    let state = emitter.named_scalar("state", state, state_decode);
    let mutex = emitter.named_scalar("mutex", mutex, mutex_decode);
    Some(DisplayNode::Struct {
        fields: vec![state, mutex, queue],
    })
}

/// Render a `tokio::sync::batch_semaphore::Semaphore` structurally, but decode
/// its atomic permit word in place (available count plus closed flag); every
/// other member shows as itself.
/// Whether `id` is the batch semaphore. A caller that reached one by walking
/// has had no dispatch key screen it, so the name is checked where it is
/// reached rather than in the detector the key already selected.
pub(super) fn is_batch_semaphore(reader: &DwReader<'_>, id: TypeId) -> bool {
    fq_name(reader, id).as_deref() == Some("tokio::sync::batch_semaphore::Semaphore")
}

/// The batch semaphore's atomic permit word, reached under `prefix`.
pub(super) fn permits_path(mut prefix: Reach<'_>) -> Reach<'_> {
    prefix.push(Named("permits"));
    prefix.push(PeelTo(WORD));
    prefix
}

pub(super) fn batch_semaphore_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // Render the semaphore as itself, with the permit word decoded in place.
    let decode = emitter.semaphore_permits_decode();
    let permits = DisplayNode::Scalar {
        at: emitter.walk(id, &reach![Named("permits"), PeelTo(WORD)])?.0,
        decode,
    };
    Some(DisplayNode::Struct {
        fields: emitter.visible_fields(id, vec![("permits", permits)])?,
    })
}

/// A `tokio::sync::watch::state::AtomicState` is a single decoded atomic state
/// word: the closed flag in bit 0 and the version counter above it.
pub(super) fn watch_state_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let decode = emitter.watch_state_decode();
    Some(DisplayNode::Scalar {
        at: emitter.walk(id, &reach![Named("__0"), PeelTo(WORD)])?.0,
        decode,
    })
}

pub(super) fn mpsc_block_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // Render the block as itself, but replace the `values` array with a
    // written-slot count derived from the readiness bitmap in
    // `header.ready_slots` — an atomic `usize` behind the usual loom/cell
    // shims. A block cannot tell a still-queued message from a consumed one,
    // so the values themselves are not shown.
    let values = DisplayNode::SlotCount {
        bitmap: emitter
            .walk(
                id,
                &reach![Named("header"), Named("ready_slots"), PeelTo(WORD)],
            )?
            .0,
        slots: emitter.walk(id, &reach![Named("values"), Named("__0")])?.0,
    };
    Some(DisplayNode::Struct {
        fields: emitter.visible_fields(id, vec![("values", values)])?,
    })
}

/// Render the `Arc`-backed payload of a watch channel as the four things worth
/// knowing about it: the published value, the packed version-and-closed state,
/// and the live receiver and sender counts.
///
/// The value is guarded by a `RwLock` whose bookkeeping differs by platform and
/// lock implementation, so the `T` is searched for rather than navigated to.
/// The other three members render through their own formatters — `AtomicState`
/// decodes itself, and each reference count is an atomic that aliases its word
/// — so the pattern only has to name them.
///
/// The two `Notify` members are deliberately absent: `notify_rx` alone is eight
/// of them, and a watch channel's waiters are reported by the tasks parked on
/// it rather than by the channel they are parked on.
pub(super) fn watch_shared_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Struct {
        fields: watch_shared_fields(emitter, id)?,
    })
}

/// The record a watch channel's shared state renders as. Shared by
/// [`watch_shared_node`], which is rooted at the allocation, and
/// [`watch_sender_node`], which reaches the same allocation across an `Arc` —
/// so the two cannot drift into showing different things.
pub(super) fn watch_shared_fields(emitter: &mut Emitter<'_>, root: TypeId) -> Option<Vec<Field>> {
    let value = DisplayNode::Alias {
        at: emitter.walk(root, &reach![Named("value"), FindParam])?.0,
        follow_pointers: true,
    };
    let mut fields = vec![Field::computed(emitter.member_named(root, "value")?, value)];
    for name in ["state", "ref_count_rx", "ref_count_tx"] {
        fields.push(Field::member(emitter.member_named(root, name)?));
    }
    Some(fields)
}

/// Render a `tokio::sync::watch::Sender<T>` as the shared state it publishes
/// to. A sender is one member — an `Arc` of that state — so showing the `Arc`,
/// its `ArcInner` and the strong/weak header before anything useful costs three
/// levels of nesting for no information. Hop the pointer instead and render the
/// state itself.
pub(super) fn watch_sender_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    // A sized `Arc<T>` points at `ArcInner<T> { strong, weak, data: T }`, so the
    // hop is the `NonNull`'s raw pointer and the step past the header is `data`.
    let (at, ptr) = emitter.walk(id, &reach![Named("shared"), Named("ptr"), Named("pointer")])?;
    let pointee = emitter.pointee(ptr)?;
    let (via, target) = emitter.walk(pointee, &reach![Named("data")])?;
    Some(DisplayNode::Pointer {
        at,
        via,
        then: Box::new(DisplayNode::Struct {
            fields: watch_shared_fields(emitter, target)?,
        }),
    })
}

/// Render a `tokio::sync::watch::Receiver<T>` as its one-slot inbox — an unseen
/// value and an independent closed flag — computed by comparing the receiver's
/// observed version with the `Arc`-backed published version. This composes from
/// `Variant` + `ValueExpr` rather than a bespoke node: the state and value words
/// are reached by selectors that cross the `Arc` via a `Deref` step.
pub(super) fn watch_receiver_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    let receiver = struct_of(reader, id)?;
    let [element_param] = receiver.template_params.as_ref() else {
        return None;
    };
    if element_param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let element = reader.canonicalize(element_param.type_id);

    // Receiver::version is a transparent `Version(usize)` wrapper.
    let observed = emitter.walk(id, &reach![Named("version"), PeelTo(WORD)])?.0;

    // Receiver::shared is an Arc. Its NonNull raw pointer targets ArcInner,
    // whose `data` member is the actual Shared<T> allocation payload.
    let (shared, ptr_ty) =
        emitter.walk(id, &reach![Named("shared"), Named("ptr"), Named("pointer")])?;
    let RawType::Pointer(ptr) = reader.canonical_type(ptr_ty)? else {
        return None;
    };
    let arc_inner = reader.canonicalize(ptr.target_type_id);
    let (shared_data, shared_ty) = emitter.walk(arc_inner, &reach![Named("data")])?;
    if fq_name(reader, shared_ty)?.split('<').next()? != "tokio::sync::watch::Shared" {
        return None;
    }
    let shared_def = struct_of(reader, shared_ty)?;
    let [shared_element] = shared_def.template_params.as_ref() else {
        return None;
    };
    if reader.canonicalize(shared_element.type_id) != element {
        return None;
    }

    // The packed state is an atomic usize behind Tokio's loom wrappers.
    let state = emitter
        .walk(shared_ty, &reach![Named("state"), PeelTo(WORD)])?
        .0;

    // The value is behind the platform-selected RwLock implementation. Search
    // its concrete aggregate storage for the one T rather than baking in the
    // std/parking_lot wrapper chain.
    let (_, value_member) = unique_member(reader, &shared_def.members, "value")?;
    let is_element = |candidate| candidate == element;
    let (value_tail, _) = find_unique(
        reader,
        value_member.type_id,
        Want::Type(&is_element),
        Through::AnyOffset,
    )?;
    let mut value_path = reach![Named("value")];
    value_path.push(Resolved(value_tail));
    let value = emitter.walk(shared_ty, &value_path)?.0;

    // Reserve the element type so the `Some(T)` alias resolves even if nothing
    // else pulls it into the type graph.
    emitter.reserve(element);

    // A selector from the receiver across its `Arc`: the `shared` pointer, a
    // `Deref` to the `ArcInner`, then `shared_data` (past the strong/weak
    // header) and the tail within the `Shared<T>`.
    let cross_arc = |tail: Selector| shared.clone().deref().then(shared_data.clone()).then(tail);
    let state_sel = cross_arc(state);
    let value_sel = cross_arc(value);
    let closed_mask = 1u64;

    use ValueExpr::{Const, Read};
    // unseen = observed != (state & !closed_mask), the published version; render
    // the newest value as `Some(T)` when it differs.
    let unseen = DisplayNode::Variant {
        discriminant: Read(observed).ne(Read(state_sel.clone()) & !Const(closed_mask)),
        arms: vec![
            emitter.label_arm(0, "None"),
            Arm {
                value: 1,
                label: Some(emitter.intern("Some")),
                payload: Some(Box::new(DisplayNode::Alias {
                    at: value_sel,
                    follow_pointers: true,
                })),
            },
        ],
        default: None,
    };
    // closed is the low state bit, independent of the version.
    let closed = DisplayNode::Variant {
        discriminant: Read(state_sel) & Const(closed_mask),
        arms: vec![emitter.label_arm(0, "false"), emitter.label_arm(1, "true")],
        default: None,
    };
    Some(DisplayNode::Struct {
        fields: vec![
            Field::Synth {
                label: emitter.intern("unseen"),
                node: unseen,
            },
            Field::Synth {
                label: emitter.intern("closed"),
                node: closed,
            },
        ],
    })
}

/// Render a bounded mpsc handle — a `Sender` or the `Receiver` — as the channel
/// it is a handle on, reached across its `Arc`: a [`DisplayNode::Pointer`] hop
/// to the `Chan`, whose own record is prefixed with the decoded `capacity` (the
/// bounded semaphore's `bound`) and `free` (the batch semaphore's permit word).
///
/// One detector serves both because they navigate identically: a `Receiver`'s
/// `chan` is a `chan::Rx` and a `Sender`'s a `chan::Tx`, and each holds the
/// shared allocation at `inner`. They also want the same answers — how much
/// room is left, whether the far end is gone, what is in flight — so neither
/// gets a record of its own.
///
/// A sender cannot pick itself out of what it sees: `queued` is every sender's
/// messages, and a sender blocked in `send` is one of the semaphore's waiters
/// with nothing marking which.
pub(super) fn mpsc_handle_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    // Handle → Rx/Tx → Arc → the `NonNull` raw pointer at `ptr.pointer`, which
    // targets the `ArcInner<Chan>` allocation.
    let (chan_pointer, ptr_ty) = emitter.walk(
        id,
        &reach![
            Named("chan"),
            Named("inner"),
            Named("ptr"),
            Named("pointer")
        ],
    )?;
    let arcinner = emitter.pointee(ptr_ty)?;

    // Skip the Arc's strong/weak header to the `data` field: the `Chan`.
    let (chan, chan_ty) = emitter.walk(arcinner, &reach![Named("data")])?;
    if !fq_name(reader, chan_ty)
        .as_deref()
        .is_some_and(|name| name.starts_with("tokio::sync::mpsc::chan::Chan<"))
    {
        return None;
    }

    // Capacity is the bounded semaphore's `bound`, a plain `usize`.
    let (bound, bound_ty) = emitter.walk(chan_ty, &reach![Named("semaphore"), Named("bound")])?;
    if !is_unsigned_integer(reader, bound_ty, crate::bundle::POINTER_SIZE) {
        return None;
    }

    // Available buffer slots live in the batch semaphore's atomic `permits`
    // word. Reach the inner `batch_semaphore::Semaphore`, then walk to its
    // permit `usize`, and root the path at the `Chan`.
    let inner = reach![Named("semaphore"), Named("semaphore")];
    if !is_batch_semaphore(reader, emitter.landed(chan_ty, &inner)?) {
        return None;
    }
    let permits = emitter.walk(chan_ty, &permits_path(inner.clone()))?.0;

    // The channel behind the pointer renders exactly as a standalone `Chan`
    // would; reuse its navigation so the queued walk and member list are shared.
    let chan_shape = mpsc_chan_shape(emitter, chan_ty)?;

    let permits_decode = emitter.semaphore_permits_decode();
    let capacity = emitter.named_scalar("capacity", bound, ScalarDecode::Raw);
    let free = emitter.named_scalar("free", permits, permits_decode);
    let mut fields = vec![capacity, free];
    fields.extend(emitter.chan_struct_fields(chan_ty, chan_shape)?);
    Some(DisplayNode::Pointer {
        at: chan_pointer,
        via: chan,
        then: Box::new(DisplayNode::Struct { fields }),
    })
}

/// Render a `tokio::sync::mpsc::bounded::Semaphore` as a curated record: the
/// mutex byte, closed flag, permit word, and capacity, plus the intrusive waiter
/// queue as a list whose nodes each show the permits that waiter is blocked on.
pub(super) fn bounded_semaphore_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    // The dispatch table screens by name; this validates only the structure.
    // The capacity is the bounded semaphore's own `bound`, a plain `usize`.
    let (bound, bound_ty) = emitter.walk(id, &reach![Named("bound")])?;
    if !is_unsigned_integer(reader, bound_ty, crate::bundle::POINTER_SIZE) {
        return None;
    }

    // The available permits are the inner batch semaphore's atomic word.
    let inner = reach![Named("semaphore")];
    if !is_batch_semaphore(reader, emitter.landed(id, &inner)?) {
        return None;
    }
    let permits = emitter.walk(id, &permits_path(inner))?.0;

    // The waiter list lives behind the batch semaphore's `waiters` mutex. tokio
    // wraps it in a loom shim over parking_lot's `lock_api::Mutex`; navigate the
    // shim (`__1`) to the real mutex, whose `raw` is the parking_lot RawMutex and
    // whose `data` (an `UnsafeCell`, member `value`) holds the `Waitlist`. Reach
    // the RawMutex's single state byte through its atomic wrapper by walking to
    // the zero-offset `u8`, which works whether the compiler emitted the atomic
    // as the generic `Atomic<u8>` or the concrete `AtomicU8`.
    let raw = reach![
        Named("semaphore"),
        Named("waiters"),
        Named("__1"),
        Named("raw")
    ];
    if !is_raw_mutex(reader, emitter.landed(id, &raw)?) {
        return None;
    }
    let mutex = emitter.walk(id, &mutex_byte_path(raw))?.0;

    let (closed, closed_ty) = emitter.walk(
        id,
        &reach![
            Named("semaphore"),
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("closed")
        ],
    )?;
    if !matches!(reader.canonical_type(closed_ty), Some(RawType::Base(base)) if base.size == 1) {
        return None;
    }

    let (head, _) = emitter.walk(
        id,
        &reach![
            Named("semaphore"),
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("queue"),
            Named("head")
        ],
    )?;

    // The queue is a `LinkedList<Waiter, Waiter>`; its node type is the `Waiter`.
    let (_, queue_ty) = emitter.walk(
        id,
        &reach![
            Named("semaphore"),
            Named("waiters"),
            Named("__1"),
            Named("data"),
            Named("value"),
            Named("queue")
        ],
    )?;
    let list = struct_of(reader, queue_ty)?;
    let param = list.template_params.last()?;
    let waiter = reader.canonicalize(param.type_id);
    if fq_name(reader, waiter).as_deref() != Some("tokio::sync::batch_semaphore::Waiter") {
        return None;
    }

    // Rooted at the `Waiter`: its atomic `state` word (permits still needed) and
    // its successor pointer (`pointers.inner.value.next`).
    let waiter_state = emitter
        .walk(waiter, &reach![Named("state"), PeelTo(WORD)])?
        .0;
    let (waiter_next, _) = emitter.walk(
        waiter,
        &reach![
            Named("pointers"),
            Named("inner"),
            Named("value"),
            Named("next")
        ],
    )?;

    let mutex_decode = emitter.mutex_byte_decode();
    let bool_decode = emitter.bool_decode();
    let permits_decode = emitter.semaphore_permits_decode();
    let queue = emitter.waiter_queue_field(
        head,
        waiter,
        waiter_next,
        "permits_needed",
        waiter_state,
        ScalarDecode::Raw,
    );
    let mutex = emitter.named_scalar("mutex", mutex, mutex_decode);
    let closed = emitter.named_scalar("closed", closed, bool_decode);
    let permits = emitter.named_scalar("permits", permits, permits_decode);
    let bound = emitter.named_scalar("bound", bound, ScalarDecode::Raw);
    Some(DisplayNode::Struct {
        fields: vec![mutex, closed, permits, bound, queue],
    })
}

/// Sum the byte offsets `selector` walks within `ty`, returning the datum's
/// total offset and the type it lands on. A [`DisplayNode::CustomList`] bakes
/// block-relative offsets as `Const`s (the block base is a runtime word), so a
/// selector produced by [`field_path`] becomes a plain number here. Only member
/// steps have an offset to sum: a [`Step::Deref`] leaves the value being
/// rendered, so a selector containing one has no offset within `ty` and is
/// rejected.
pub(super) fn path_offset(
    reader: &DwReader<'_>,
    strings: &StringInterner,
    ty: TypeId,
    selector: &Selector,
) -> Option<(u64, TypeId)> {
    let mut cur = reader.canonicalize(ty);
    let mut offset = 0u64;
    for step in selector.steps() {
        let (landed, member) = step_into(reader, strings, cur, step)?;
        // Only a member step has an offset to sum.
        let (members, index) = member?;
        offset = offset.checked_add(members[index].offset)?;
        cur = landed;
    }
    Some((offset, cur))
}

/// Where a `tokio::sync::mpsc::chan::Chan` keeps the state its `queued` walk
/// needs, plus the members it shows structurally. Shared by the standalone
/// `Chan` formatter ([`mpsc_chan_node`]) and the `Receiver` ([`mpsc_rx_node`]),
/// which renders the same record behind a pointer hop.
pub(super) struct ChanShape {
    /// Value-anchored selectors seeding the walk's loop variables.
    tail: Selector,
    index: Selector,
    head: Selector,
    /// Byte offsets of a block's fields, baked into the CustomList program as
    /// constants since the block base is a runtime pointer.
    start_index_offset: u64,
    next_offset: u64,
    values_offset: u64,
    /// Slot stride and per-block slot count of the inline values array.
    stride: u64,
    count: u64,
    element: TypeId,
}

/// A channel is a struct whose first field is the synthetic `queued` block-chain
/// walk; the rest are its real members.
pub(super) fn mpsc_chan_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let shape = mpsc_chan_shape(emitter, id)?;
    Some(DisplayNode::Struct {
        fields: emitter.chan_struct_fields(id, shape)?,
    })
}

pub(super) fn mpsc_chan_shape(emitter: &mut Emitter<'_>, id: TypeId) -> Option<ChanShape> {
    let reader = emitter.reader;
    // Both callers screen by name; this validates only the structure.
    // Sender write position and receiver read position, plus the receiver's
    // head block pointer. The rx fields sit behind CachePadded/UnsafeCell
    // wrappers; navigate them by name.
    // `tail_position` is a (shared) atomic usize; `index` is a plain usize on
    // the single-consumer receiver. Walk to the stored word either way.
    let tail = emitter
        .walk(
            id,
            &reach![
                Named("tx"),
                Named("value"),
                Named("tail_position"),
                PeelTo(WORD)
            ],
        )?
        .0;
    let index = emitter
        .walk(
            id,
            &reach![
                Named("rx_fields"),
                Named("__0"),
                Named("value"),
                Named("list"),
                Named("index"),
                PeelTo(WORD)
            ],
        )?
        .0;
    let (head, head_ty) = emitter.walk(
        id,
        &reach![
            Named("rx_fields"),
            Named("__0"),
            Named("value"),
            Named("list"),
            Named("head"),
            Named("pointer")
        ],
    )?;
    let RawType::Pointer(head_ptr) = reader.canonical_type(head_ty)? else {
        return None;
    };
    let block = reader.canonicalize(head_ptr.target_type_id);

    // Paths rooted at the block type.
    let (start_index, _) = emitter.walk(block, &reach![Named("header"), Named("start_index")])?;
    // `next` is an `AtomicPtr`; walk the atomic wrappers to the raw pointer.
    let next = emitter
        .walk(
            block,
            &reach![Named("header"), Named("next"), PeelTo(Shape::Pointer)],
        )?
        .0;
    let (values, values_ty) = emitter.walk(block, &reach![Named("values"), Named("__0")])?;
    let RawType::Array(values_arr) = reader.canonical_type(values_ty)? else {
        return None;
    };

    // The block base is a runtime pointer, so its fields are reached by Load at
    // constant offsets rather than selectors; resolve those offsets and the
    // slot array's stride/count here.
    let start_index_offset = path_offset(reader, &emitter.interner, block, &start_index)?.0;
    let next_offset = path_offset(reader, &emitter.interner, block, &next)?.0;
    let values_offset = path_offset(reader, &emitter.interner, block, &values)?.0;
    let stride = raw_type_size(reader, values_arr.elem_type_id)?;
    let count = values_arr.count;

    // `element` is the block's message type `T`.
    let bst = struct_of(reader, block)?;
    let [param] = bst.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") {
        return None;
    }
    let element = reader.canonicalize(param.type_id);

    // The channel renders as a struct: the synthetic `queued` field followed
    // by its real members. Structural display skips zero-sized members, so
    // enumerate over the full list and keep the surviving indices.
    Some(ChanShape {
        tail,
        index,
        head,
        start_index_offset,
        next_offset,
        values_offset,
        stride,
        count,
        element,
    })
}

/// Build the synthetic `queued` field's node: a [`DisplayNode::CustomList`] that
/// walks the mpsc block chain and emits the live `[index, tail)` messages,
/// reproducing the retired bespoke `MpscChan` leaf from the general value
/// language. Loop variables are `0 = cur` (the read index, advanced per
/// message), `1 = tail`, and `2 = block` (the current block pointer). A block's
/// fields are read with `Load` at constant offsets because the block base is a
/// runtime word, not a member of the rendered value.
#[allow(clippy::too_many_arguments)]
pub(super) fn mpsc_queued_node(
    tail: Selector,
    index: Selector,
    head: Selector,
    start_index_offset: u64,
    next_offset: u64,
    values_offset: u64,
    stride: u64,
    count: u64,
    element: BundleTypeId,
) -> DisplayNode {
    use ValueExpr::{Const, Read, Var};
    let word = crate::bundle::POINTER_SIZE as u32;
    // `block->start_index`, recomputed at each use (there is no `start` var).
    let start = || (Var(2) + Const(start_index_offset)).load(word);
    DisplayNode::CustomList {
        vars: vec![
            Read(index), // 0: cur = read index
            Read(tail),  // 1: tail
            Read(head),  // 2: block = head pointer
        ],
        condition: Var(0).lt(Var(1)) & Var(2).ne(Const(0)),
        body: vec![
            // A block starting past cur is malformed; stop before the offset
            // subtraction below would underflow.
            Stmt::Break {
                cond: Var(0).lt(start()),
            },
            Stmt::If {
                // cur - start < slots: the message lives in this block.
                cond: (Var(0) - start()).lt(Const(count)),
                then: vec![
                    // Emit values[cur - start] at values_offset + i*stride.
                    Stmt::Emit {
                        at: Var(2) + (Const(values_offset) + (Var(0) - start()) * Const(stride)),
                    },
                    Stmt::Set {
                        var: 0,
                        value: Var(0) + Const(1),
                    },
                ],
                // Past this block: follow the successor pointer.
                otherwise: vec![Stmt::Set {
                    var: 2,
                    value: (Var(2) + Const(next_offset)).load(word),
                }],
            },
        ],
        element,
    }
}

/// tokio pads a field out to a cache line by wrapping it in a struct whose one
/// member is the value; show the value, so the padding does not read as a level
/// of structure that is not there.
pub(super) fn cache_padded_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    Some(DisplayNode::Alias {
        at: emitter.walk(id, &reach![Named("value")])?.0,
        follow_pointers: true,
    })
}

/// tokio's loom shim wraps a `core::cell::UnsafeCell<T>` in a newtype over the
/// same `T`; display it as the cell, which is itself transparent.
pub(super) fn loom_unsafe_cell_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    let target = sole_param_target(reader, st)?;
    let cell = zero_offset_member(reader, &st.members, Some("__0"), |ty| {
        unsafe_cell_layout(reader, ty).is_some_and(|(_, inner)| inner == target)
    })?;
    transparent(emitter, &st.members, cell)
}

pub(super) fn loom_atomic_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // The prefix key reaches every `atomic_<width>` module; require the single
    // segment and the `Atomic*` type name it cannot express.
    let namespace = st.namespace.map(|ns| ns_path(reader, ns))?;
    let atomic_module = namespace.strip_prefix("tokio::loom::std::atomic_")?;
    if atomic_module.is_empty() || atomic_module.contains("::") {
        return None;
    }
    let name = st.name.map(|name| reader.strings.get(name))?;
    if !name.starts_with("Atomic") {
        return None;
    }
    // The shim holds the real atomic in an `UnsafeCell`, so accept a member
    // only when a `core::sync::atomic::Atomic<_>` is what the cell contains.
    let inner = zero_offset_member(reader, &st.members, Some("inner"), |ty| {
        unsafe_cell_layout(reader, ty).is_some_and(|(_, atomic)| is_generic_atomic(reader, atomic))
    })?;
    transparent(emitter, &st.members, inner)
}

/// tokio's `loom::std::parking_lot` shims are newtypes that pair a
/// `PhantomData` marker with the real parking_lot lock (`Mutex`, `RwLock`,
/// `Condvar`, and their guards). Display them as the inner lock so the
/// loom scaffolding does not obscure it.
pub(super) fn loom_parking_lot_node(emitter: &mut Emitter<'_>, id: TypeId) -> Option<DisplayNode> {
    let reader = emitter.reader;
    let st = struct_of(reader, id)?;
    // The prefix key spans the whole shim module — which is the point, since
    // every type in it is a wrapper — but it also admits a submodule the key
    // cannot exclude, so require the module itself.
    if st.namespace.map(|ns| ns_path(reader, ns))? != "tokio::loom::std::parking_lot" {
        return None;
    }
    // Any member name will do, since the shims spell the lock differently; what
    // identifies it is being the one member at offset zero that is not a marker.
    let lock = zero_offset_member(reader, &st.members, None, |ty| {
        !fq_name(reader, reader.canonicalize(ty))
            .is_some_and(|name| name.starts_with("core::marker::PhantomData"))
    })?;
    transparent(emitter, &st.members, lock)
}

/// The driver wheel's clock — `elapsed`, ms since the runtime's
/// `TimeSource` epoch, advanced each time the wheel is processed — reached
/// from a timer entry's own scheduler handle under `prefix`: driver →
/// whichever flavor variant is live → its `Arc` → the runtime's
/// `driver::Handle` → the time handle → the `Traditional` driver's
/// mutex-guarded `InnerState`. Both flavor handles spell every member below
/// the variant identically (`driver` on each is the same `driver::Handle`),
/// which is what lets the scheduler enum be crossed with an active-variant
/// step — one recorded path serving either flavor, the read selecting the
/// live candidate by its guard. `time` is an `Option<time::Handle>` (`None`
/// only for a runtime built without a time driver) and the mutex spelling
/// varies by feature set, so the guarded steps and the parameter search do
/// the navigating. The remaining enums on the path are crossed with guarded
/// variant steps, so an alternative timer degrades the field to
/// `<inactive variant>` rather than misreading; the mutex is not taken, the
/// usual torn-read caveat for a live target.
///
/// The one navigation here that is not version-invariant is `time::Inner`:
/// tokio 1.49 made it an enum over the driver flavor
/// (`Traditional` | `Alternative`) when the alternative timer arrived,
/// where before it is the traditional driver's struct itself. Which
/// spelling holds is version-determined, so the calling family declares it
/// (`flavored_inner`) rather than this walk probing both — everything else
/// has held across every supported tokio version, which is why this lives
/// here rather than in a timer family module.
pub(super) fn wheel_elapsed(
    emitter: &mut Emitter<'_>,
    root: TypeId,
    prefix: &Reach<'_>,
    flavored_inner: bool,
) -> Option<Selector> {
    let mut path = prefix.clone();
    path.extend(reach![
        Named("driver"),
        ActiveVariant,
        Named("__0"),
        Named("ptr"),
        Named("pointer"),
        Deref,
        Named("data"),
        Named("driver"),
        Named("time"),
        Variant("Some"),
        Named("__0"),
        Named("inner"),
    ]);
    if flavored_inner {
        path.push(Variant("Traditional"));
    }
    path.extend(reach![
        Named("state"),
        FindParam,
        Named("wheel"),
        Named("elapsed"),
    ]);
    emitter.walk(root, &path).map(|(sel, _)| sel)
}

impl Emitter<'_> {
    /// tokio `Notify` state word: low two bits the notification state, the rest
    /// the `notify_waiters()` generation counter.
    fn notify_state_decode(&mut self) -> ScalarDecode {
        let state = self.enum_field(
            "state",
            0,
            2,
            &[(0, "idle"), (1, "waiting"), (2, "notified")],
        );
        let generation = self.uint_tail_field("generation", 2);
        ScalarDecode::Bits(vec![state, generation])
    }

    /// tokio per-waiter `AtomicNotification` word: kind in bits 0–1, FIFO/LIFO
    /// order in bit 2 (so `notify_one` LIFO reads as the packed value 5).
    fn notification_decode(&mut self) -> ScalarDecode {
        let kind = self.enum_field("kind", 0, 2, &[(0, "none"), (1, "one"), (2, "all")]);
        let order = self.enum_field("order", 2, 1, &[(0, "fifo"), (1, "lifo")]);
        ScalarDecode::Bits(vec![kind, order])
    }

    /// tokio batch-semaphore permit word: bit 0 closed, the rest the available
    /// permit count.
    fn semaphore_permits_decode(&mut self) -> ScalarDecode {
        let closed = self.bool_field("closed", 0);
        let permits = self.uint_tail_field("permits", 1);
        ScalarDecode::Bits(vec![closed, permits])
    }

    /// tokio watch `AtomicState`: bit 0 closed, the rest the version counter.
    fn watch_state_decode(&mut self) -> ScalarDecode {
        let closed = self.bool_field("closed", 0);
        let version = self.uint_tail_field("version", 1);
        ScalarDecode::Bits(vec![closed, version])
    }

    /// Build the `queue` field shared by the waiter-mutex formatters (`Notify`
    /// and the bounded-channel `Semaphore`): an intrusive [`DisplayNode::List`]
    /// over the parked `waiter`s, each shown as a one-field record naming what
    /// it is blocked on. `head` reaches the list head (rooted at the formatted
    /// type); `waiter_next` reaches a node's successor and `payload` its
    /// blocked-on word — decoded by `payload_decode` under `payload_label` —
    /// both rooted at `waiter`.
    fn waiter_queue_field(
        &mut self,
        head: Selector,
        waiter: TypeId,
        waiter_next: Selector,
        payload_label: &str,
        payload: Selector,
        payload_decode: ScalarDecode,
    ) -> Field {
        let node_ty = self.reserve(waiter);
        let payload_label = self.interner.intern(payload_label);
        let queue = self.interner.intern("queue");
        let mut fields = vec![Field::Synth {
            label: payload_label,
            node: DisplayNode::Scalar {
                at: payload,
                decode: payload_decode,
            },
        }];
        // The waker the parked task registered — for a tokio task waker its
        // data word is that task's Header, so the queue names who will be
        // woken. The member renders structurally: `Option<Waker>`'s own
        // variant decode supplies the Some/None, and the `Waker` formatter
        // reduces the payload to that data word.
        if let Some(at) = self.member_named(waiter, "waker") {
            fields.push(Field::member(at));
        }
        Field::Synth {
            label: queue,
            node: DisplayNode::List {
                head,
                next: waiter_next,
                node: Box::new(DisplayNode::Struct { fields }),
                node_ty,
            },
        }
    }

    /// Build the fields of a `tokio::sync::mpsc::chan::Chan` record: the
    /// synthetic `queued` field (a [`DisplayNode::CustomList`] walk over the
    /// block chain) followed by the channel's real members shown structurally.
    /// Shared by the
    /// standalone `Chan` formatter and the `Receiver`, which prepends its
    /// decoded `capacity`/`free` fields to the same list.
    fn chan_struct_fields(&mut self, chan: TypeId, shape: ChanShape) -> Option<Vec<Field>> {
        let ChanShape {
            tail,
            index,
            head,
            start_index_offset,
            next_offset,
            values_offset,
            stride,
            count,
            element,
        } = shape;
        let element = self.reserve(element);
        let queued = Field::Synth {
            label: self.intern("queued"),
            node: mpsc_queued_node(
                tail,
                index,
                head,
                start_index_offset,
                next_offset,
                values_offset,
                stride,
                count,
                element,
            ),
        };
        let mut fields = vec![queued];
        fields.extend(self.visible_fields(chan, Vec::new())?);
        Some(fields)
    }
}

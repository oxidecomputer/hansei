// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Raw-shape screens for the std pointer adapters and tracing's
//! `Instrumented`: what a reviewed delegation rule's layout has to look
//! like in the DWARF, decided where the reader's original definitions
//! and template parameters are still at hand.
//!
//! A screen establishes shape facts only — that this pointer is a `&mut
//! F` by every definition's own name, that this `Pin<Ptr>` holds its
//! `Ptr` in the one member std declares, which member of a wide pointer
//! is which. Whether a rule binds is the binder's call, over the final
//! type table and the defining units' compiler verdicts; a screen's
//! answer authorizes no poll and reads no storage.

pub(crate) use super::crates::H1Role;
use super::std::dyn_pointer_layout;
use super::{struct_of, unique_member};
use crate::bundle::names::{generic_args, is_future_trait_object};
use crate::extract::{fq_name, ns_path};
use crate::raw_types::{RawPointer, RawType, RawVariant, VariantShape};
use crate::{DwReader, StrId, TypeId};

use std::collections::BTreeSet;

/// What a thin or wide pointer adapter points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Pointee {
    /// A sized `F`, reached by dereferencing the thin pointer.
    Sized(TypeId),
    /// A `dyn Future` behind a wide pointer.
    Dyn(WidePointer),
}

/// A `{ pointer, vtable }` wide pointer to a trait object: the struct
/// carrying the two members, their names and types, and the zero-sized
/// `dyn` type the data pointer targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WidePointer {
    pub(crate) wide: TypeId,
    pub(crate) pointer: String,
    pub(crate) vtable: String,
    pub(crate) data_ptr: TypeId,
    pub(crate) vtable_ptr: TypeId,
    pub(crate) trait_ty: TypeId,
    /// Whether the object is a bare `dyn Future`, whose vtable the
    /// reviewed ABI describes slot for slot. Any other trait may still
    /// carry `Future` as a supertrait — an adapter over it is a future
    /// exactly when the trait requires one — but the poll's slot is
    /// that trait's own business, so the binding claims none.
    pub(crate) future_trait: bool,
}

/// One of the four reviewed std adapters, with what it points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StdAdapter {
    MutRef(Pointee),
    Box(Pointee),
    /// `Pin<&mut F>`: the member holding the reference, the reference
    /// type, and what it points at.
    PinMutRef {
        member: String,
        reference: TypeId,
        pointee: Pointee,
    },
    /// `Pin<Box<F>>`: the member holding the box, the box type, and what
    /// it points at.
    PinBox {
        member: String,
        boxed: TypeId,
        pointee: Pointee,
    },
}

/// The `T` of `tracing::instrument::Instrumented<T>` and the member
/// holding it, by the struct's own declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstrumentedLayout {
    pub(crate) inner: String,
    pub(crate) future: TypeId,
}

/// A wrapper whose whole poll is one forward: the member it forwards
/// through and the type that member holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardLayout {
    pub(crate) member: String,
    pub(crate) inner: TypeId,
}

/// futures-util's `stream::Next<'_, St>`: the member holding the
/// `&mut St` its poll goes through, and the stream `St` that reference
/// targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NextLayout {
    pub(crate) stream: String,
    pub(crate) target: TypeId,
}

/// tokio-util's `ReusableBoxFuture<'_, T>`: the member holding its
/// pinned box, the `Pin`'s one member and the `Box` that member holds,
/// and the wide pointer to the trait object the box is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReusableBoxLayout {
    pub(crate) boxed: String,
    pub(crate) pin: (String, TypeId),
    pub(crate) wide: WidePointer,
}

/// futures-util's `map::Map<Fut, F>`, the two-state enum behind the
/// `map` combinator: which variant is which, the member holding the
/// mapped future while it runs, and that future's declared type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MapLayout {
    pub(crate) incomplete: String,
    pub(crate) future_member: String,
    pub(crate) complete: String,
    pub(crate) future: TypeId,
}

/// Why a thin pointer was not taken as the shape a screen asked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PointerDecline {
    /// No recorded definition, a nameless one, or one whose name is
    /// not the shape: the type is something else, and the screen goes
    /// on to its next shape.
    NotTheShape,
    /// Every definition is the shape, but they name `targets` distinct
    /// canonical targets: one pointer type stands over several
    /// pointees, a collapse the identity partition did not split. No
    /// other shape will claim it, and a reader deserves to hear why.
    Disagree { targets: usize },
}

/// The canonical target every original definition of the thin pointer
/// `id` agrees on, provided each definition's own name — before any
/// declaration inherited one — satisfies `expect` for that target. A
/// definition with no name, a name that does not, or a pointer with no
/// recorded definition at all is not the shape; definitions naming
/// different targets decline with their count.
fn agreed_pointer(
    reader: &DwReader<'_>,
    id: TypeId,
    expect: impl Fn(&str, TypeId) -> bool,
) -> Result<TypeId, PointerDecline> {
    // Definitions agree on the canonical target, not the DIE: each unit
    // emits its own copy of the pointee.
    let definitions = reader.type_definitions(id).map(|die| {
        reader.pointer_definition(die).map(|pointer| RawPointer {
            name: pointer.name,
            target_type_id: reader.canonicalize(pointer.target_type_id),
        })
    });
    agreed_target(definitions, |name, target| {
        expect(reader.strings.get(name), target)
    })
}

/// The target every definition agrees on, each definition named and
/// satisfying `expect`; a missing definition, a nameless one, or one
/// `expect` refuses is not the shape, and definitions naming different
/// targets decline with how many.
fn agreed_target(
    definitions: impl Iterator<Item = Option<RawPointer<StrId>>>,
    expect: impl Fn(StrId, TypeId) -> bool,
) -> Result<TypeId, PointerDecline> {
    let mut targets = BTreeSet::new();
    for pointer in definitions {
        let pointer = pointer.ok_or(PointerDecline::NotTheShape)?;
        let target = pointer.target_type_id;
        if !expect(pointer.name.ok_or(PointerDecline::NotTheShape)?, target) {
            return Err(PointerDecline::NotTheShape);
        }
        targets.insert(target);
    }
    match targets.len() {
        0 => Err(PointerDecline::NotTheShape),
        1 => Ok(targets.into_iter().next().expect("one target")),
        targets => Err(PointerDecline::Disagree { targets }),
    }
}

/// `&mut F` as a thin pointer: every definition named `&mut <F>` for the
/// exact `F` it targets. A raw pointer, a shared reference, or a pointer
/// whose name was inherited from a declaration is not one.
fn mut_ref_thin(reader: &DwReader<'_>, id: TypeId) -> Result<TypeId, PointerDecline> {
    agreed_pointer(reader, id, |name, target| {
        name.strip_prefix("&mut ")
            .is_some_and(|rest| fq_name(reader, target).as_deref() == Some(rest))
    })
}

/// A sized `Box<F, Global>` as rustc's debuginfo spells it: a thin
/// pointer named `alloc::boxed::Box<F, alloc::alloc::Global>` for the
/// exact `F` it targets, by every definition.
fn box_thin(reader: &DwReader<'_>, id: TypeId) -> Result<TypeId, PointerDecline> {
    agreed_pointer(reader, id, |name, target| {
        let Some(("alloc::boxed::Box", args)) = generic_args(name) else {
            return false;
        };
        matches!(args.as_slice(), [f, "alloc::alloc::Global"]
            if fq_name(reader, target).as_deref() == Some(f))
    })
}

/// A wide pointer to a trait object: rustc's `{ pointer, vtable }`
/// struct whose data pointer targets the trait object itself (no
/// unsized aggregate around it) and whose vtable declares at least the
/// four words a one-method vtable has. The struct's own name has to
/// satisfy `expect` for the pointee's name.
///
/// The trait need not be `Future`. What makes such a pointer a
/// delegation route is the adapter over it being positively a future,
/// which its own poll evidence decides elsewhere: `Box<T>: Future`
/// holds only where `T: Future` does, so the concrete value behind the
/// pointer implements `Future` whatever the object's principal trait
/// is. Only the vtable's *layout* is the principal trait's business,
/// which [`WidePointer::future_trait`] carries to the binder.
fn wide(
    reader: &DwReader<'_>,
    id: TypeId,
    expect: impl Fn(&str, &str) -> bool,
) -> Option<WidePointer> {
    let st = struct_of(reader, id)?;
    let layout = dyn_pointer_layout(reader, id)?;
    if !layout.tail_prefixes.is_empty() || layout.vtable_words < 4 {
        return None;
    }
    let pointee = fq_name(reader, layout.pointee)?;
    if !expect(&fq_name(reader, id)?, &pointee) {
        return None;
    }
    // The layout found each member by name and shape; the members are
    // then addressed by name, which has to be unique for that.
    let (_, pointer) = unique_member(reader, &st.members, "pointer")?;
    let (_, vtable) = unique_member(reader, &st.members, "vtable")?;
    Some(WidePointer {
        wide: reader.canonicalize(id),
        pointer: "pointer".to_owned(),
        vtable: "vtable".to_owned(),
        data_ptr: reader.canonicalize(pointer.type_id),
        vtable_ptr: reader.canonicalize(vtable.type_id),
        trait_ty: layout.pointee,
        future_trait: is_future_trait_object(&pointee),
    })
}

/// `&mut F` thin or wide. A thin pointer whose definitions disagree on
/// `F` is declined with that reason: it is a reference to several
/// pointees, which no wide screen will claim either.
fn mut_ref(reader: &DwReader<'_>, id: TypeId) -> Result<Pointee, PointerDecline> {
    match mut_ref_thin(reader, id) {
        Ok(target) => return Ok(Pointee::Sized(target)),
        Err(PointerDecline::NotTheShape) => {}
        Err(decline) => return Err(decline),
    }
    wide(reader, id, |name, pointee| {
        name.strip_prefix("&mut ") == Some(pointee)
    })
    .map(Pointee::Dyn)
    .ok_or(PointerDecline::NotTheShape)
}

/// `Box<F>` thin or wide, declined the way [`mut_ref`] is.
fn boxed(reader: &DwReader<'_>, id: TypeId) -> Result<Pointee, PointerDecline> {
    match box_thin(reader, id) {
        Ok(target) => return Ok(Pointee::Sized(target)),
        Err(PointerDecline::NotTheShape) => {}
        Err(decline) => return Err(decline),
    }
    wide(reader, id, |name, pointee| {
        matches!(generic_args(name), Some(("alloc::boxed::Box", args))
            if args.as_slice() == [pointee, "alloc::alloc::Global"])
    })
    .map(Pointee::Dyn)
    .ok_or(PointerDecline::NotTheShape)
}

/// `core::pin::Pin<Ptr>` as std declares it: one template parameter
/// `Ptr`, one member `pointer` at offset zero that *is* that parameter.
/// Returns the member's name and the canonical `Ptr`.
fn pin(reader: &DwReader<'_>, id: TypeId) -> Option<(String, TypeId)> {
    let st = struct_of(reader, id)?;
    if st.namespace.map(|ns| ns_path(reader, ns)).as_deref() != Some("core::pin")
        || !st
            .name
            .is_some_and(|name| reader.strings.get(name).starts_with("Pin<"))
    {
        return None;
    }
    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("Ptr") {
        return None;
    }
    let [member] = st.members.as_ref() else {
        return None;
    };
    let ptr = reader.canonicalize(param.type_id);
    let name = reader.strings.get(member.name?);
    (name == "pointer" && member.offset == 0 && reader.canonicalize(member.type_id) == ptr)
        .then(|| (name.to_owned(), ptr))
}

/// Screen `id` as one of the reviewed std adapters. `Pin<P>` over any
/// other `P` — a user pointer with its own `DerefMut`, an `Arc`, a
/// `Rc` — is not one, however many pointer-sized members it has.
pub(crate) fn std_adapter(reader: &DwReader<'_>, id: TypeId) -> Option<StdAdapter> {
    std_adapter_screen(reader, id).ok()
}

/// [`std_adapter`] with the reason a pointer of the shape was declined:
/// a `Box` or `&mut` whose definitions name several targets is not an
/// adapter, and nothing else either, so the reason is the record's.
pub(crate) fn std_adapter_screen(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Result<StdAdapter, PointerDecline> {
    if let Some((member, ptr)) = pin(reader, id) {
        match boxed(reader, ptr) {
            Ok(pointee) => {
                return Ok(StdAdapter::PinBox {
                    member,
                    boxed: ptr,
                    pointee,
                });
            }
            Err(PointerDecline::NotTheShape) => {}
            Err(decline) => return Err(decline),
        }
        return mut_ref(reader, ptr).map(|pointee| StdAdapter::PinMutRef {
            member,
            reference: ptr,
            pointee,
        });
    }
    match boxed(reader, id) {
        Ok(pointee) => return Ok(StdAdapter::Box(pointee)),
        Err(PointerDecline::NotTheShape) => {}
        Err(decline) => return Err(decline),
    }
    mut_ref(reader, id).map(StdAdapter::MutRef)
}

/// Screen `id` as `tracing::instrument::Instrumented<T>`: one template
/// parameter `T`, exactly the two members `inner` and `span`. Which
/// wrappers `inner` holds `T` in is std's business and the binder's,
/// over the final table.
pub(crate) fn instrumented(reader: &DwReader<'_>, id: TypeId) -> Option<InstrumentedLayout> {
    let st = struct_of(reader, id)?;
    if st.namespace.map(|ns| ns_path(reader, ns)).as_deref() != Some("tracing::instrument")
        || !st
            .name
            .is_some_and(|name| reader.strings.get(name).starts_with("Instrumented<"))
    {
        return None;
    }
    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("T") || st.members.len() != 2 {
        return None;
    }
    unique_member(reader, &st.members, "inner")?;
    unique_member(reader, &st.members, "span")?;
    Some(InstrumentedLayout {
        inner: "inner".to_owned(),
        future: reader.canonicalize(param.type_id),
    })
}

/// A struct declared in `module` whose own name starts with `prefix`.
/// The module is the type's definition path, not a use site's: the same
/// name under another module is another crate's type.
fn declared_in<'r>(
    reader: &'r DwReader<'_>,
    id: TypeId,
    module: &str,
    prefix: &str,
) -> Option<&'r crate::raw_types::RawStruct<crate::StrId>> {
    let st = struct_of(reader, id)?;
    (st.namespace.map(|ns| ns_path(reader, ns)).as_deref() == Some(module)
        && st
            .name
            .is_some_and(|name| reader.strings.get(name).starts_with(prefix)))
    .then_some(st)
}

/// The one member of a one-member struct, named `member`, and the type
/// it holds. A second member of any kind — including a zero-sized one —
/// is a layout the reviewed forward was not read against.
fn sole_member(
    reader: &DwReader<'_>,
    st: &crate::raw_types::RawStruct<crate::StrId>,
    member: &str,
) -> Option<ForwardLayout> {
    let [only] = st.members.as_ref() else {
        return None;
    };
    let (_, found) = unique_member(reader, &st.members, member)?;
    (only.offset == 0).then(|| ForwardLayout {
        member: member.to_owned(),
        inner: reader.canonicalize(found.type_id),
    })
}

/// The generic arguments an instantiation's own name carries, as the
/// compiler wrote them.
fn name_args(reader: &DwReader<'_>, id: TypeId) -> Option<Vec<String>> {
    let name = fq_name(reader, id)?;
    let (_, args) = generic_args(&name)?;
    Some(args.iter().map(|a| (*a).to_owned()).collect())
}

/// Screen `id` as futures-util's `map::Map<Fut, F>`: the enum the `map`
/// combinator's poll actually runs, with the two variants
/// `Incomplete { future, f }` and `Complete`, `future` being the `Fut`
/// the instantiation names and `f` the `F`.
///
/// rustc attaches no template parameters to an enum's DIE, so the
/// instantiation's own arguments are read from its name — which is the
/// compiler's other record of the same thing — and each is held to the
/// type the member actually has.
pub(crate) fn futures_util_map(reader: &DwReader<'_>, id: TypeId) -> Option<MapLayout> {
    let RawType::Enum(en) = reader.canonical_type(id)? else {
        return None;
    };
    if en.namespace.map(|ns| ns_path(reader, ns)).as_deref()
        != Some("futures_util::future::future::map")
    {
        return None;
    }
    let name = fq_name(reader, id)?;
    let Some(("futures_util::future::future::map::Map", args)) = generic_args(&name) else {
        return None;
    };
    let [declared_future, declared_fn] = args.as_slice() else {
        return None;
    };
    let VariantShape::Many { variants, .. } = &en.shape else {
        return None;
    };
    let [(_, first), (_, second)] = variants.as_ref() else {
        return None;
    };
    let named = |variant: &RawVariant<crate::StrId>, expected: &str| {
        variant
            .member
            .name
            .map(|name| reader.strings.get(name))
            .filter(|name| *name == expected)
            .map(|_| variant.member.type_id)
    };
    // Declaration order, not the discriminant's: the payloads say which
    // is which, and both are checked.
    let incomplete = named(first, "Incomplete")?;
    let complete = named(second, "Complete")?;
    let payload = struct_of(reader, incomplete)?;
    if payload.members.len() != 2 || !struct_of(reader, complete)?.members.is_empty() {
        return None;
    }
    let (_, future) = unique_member(reader, &payload.members, "future")?;
    let (_, mapped) = unique_member(reader, &payload.members, "f")?;
    (fq_name(reader, future.type_id).as_deref() == Some(*declared_future)
        && fq_name(reader, mapped.type_id).as_deref() == Some(*declared_fn))
    .then(|| MapLayout {
        incomplete: "Incomplete".to_owned(),
        future_member: "future".to_owned(),
        complete: "Complete".to_owned(),
        future: reader.canonicalize(future.type_id),
    })
}

/// Screen `id` as the public `Map<Fut, F>` the `delegate_all!` macro
/// builds around `map::Map`: one member `inner`, holding exactly the
/// enum above at the same instantiation.
pub(crate) fn futures_util_map_wrapper(reader: &DwReader<'_>, id: TypeId) -> Option<ForwardLayout> {
    let st = declared_in(reader, id, "futures_util::future::future", "Map<")?;
    let forward = sole_member(reader, st, "inner")?;
    futures_util_map(reader, forward.inner)?;
    (name_args(reader, id)? == name_args(reader, forward.inner)?).then_some(forward)
}

/// Screen `id` as futures-util's `MapErr<Fut, F>`, another
/// `delegate_all!` newtype: one member `inner`, holding the public
/// `Map` the macro's constructor puts there.
pub(crate) fn futures_util_map_err(reader: &DwReader<'_>, id: TypeId) -> Option<ForwardLayout> {
    let st = declared_in(reader, id, "futures_util::future::try_future", "MapErr<")?;
    let forward = sole_member(reader, st, "inner")?;
    fq_name(reader, forward.inner)?
        .starts_with("futures_util::future::future::Map<")
        .then_some(forward)
}

/// Screen `id` as futures-util's `IntoFuture<Fut>`: one member
/// `future`, which is the `Fut` it was instantiated with.
pub(crate) fn futures_util_into_future(reader: &DwReader<'_>, id: TypeId) -> Option<ForwardLayout> {
    let st = declared_in(
        reader,
        id,
        "futures_util::future::try_future::into_future",
        "IntoFuture<",
    )?;
    let forward = sole_member(reader, st, "future")?;
    let [fut] = st.template_params.as_ref() else {
        return None;
    };
    (fut.name.map(|name| reader.strings.get(name)) == Some("Fut")
        && forward.inner == reader.canonicalize(fut.type_id))
    .then_some(forward)
}

/// Screen `id` as hyper-util's `TokioSleep`: one member `inner`,
/// holding tokio's own `Sleep`. The newtype exists to give that sleep
/// an `Unpin` trait object, and holds nothing else.
pub(crate) fn hyper_util_tokio_sleep(reader: &DwReader<'_>, id: TypeId) -> Option<ForwardLayout> {
    let st = declared_in(reader, id, "hyper_util::rt::tokio", "TokioSleep")?;
    let forward = sole_member(reader, st, "inner")?;
    (fq_name(reader, forward.inner).as_deref() == Some("tokio::time::sleep::Sleep"))
        .then_some(forward)
}

/// Screen `id` as tokio's `task::coop::Coop<F>`: one member `fut`,
/// holding the `F` the instantiation declares. The wrapper spends a
/// unit of the task's cooperative budget, then polls that member and
/// nothing else.
pub(crate) fn tokio_coop(reader: &DwReader<'_>, id: TypeId) -> Option<ForwardLayout> {
    let st = declared_in(reader, id, "tokio::task::coop", "Coop<")?;
    let forward = sole_member(reader, st, "fut")?;
    let [f] = st.template_params.as_ref() else {
        return None;
    };
    (f.name.map(|name| reader.strings.get(name)) == Some("F")
        && forward.inner == reader.canonicalize(f.type_id))
    .then_some(forward)
}

/// Screen `id` as core's `future::pending::Pending<T>`: a zero-sized
/// struct whose one member `_data` is the `PhantomData` that carries
/// its `T`. Anything else at that name — a member with a size, a
/// second member — is a layout the reviewed poll was not read against.
pub(crate) fn core_pending(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(st) = declared_in(reader, id, "core::future::pending", "Pending<") else {
        return false;
    };
    let Some(forward) = sole_member(reader, st, "_data") else {
        return false;
    };
    st.size == 0
        && fq_name(reader, forward.inner)
            .is_some_and(|name| name.starts_with("core::marker::PhantomData<"))
}

/// Screen `id` as futures-util's `future::pending::Pending<T>`, the
/// future `futures::future::pending()` returns: the same shape as
/// core's — a zero-sized struct whose one member `_data` is the
/// `PhantomData` carrying its `T` — declared in the crate's own module.
pub(crate) fn futures_util_pending(reader: &DwReader<'_>, id: TypeId) -> bool {
    let Some(st) = declared_in(reader, id, "futures_util::future::pending", "Pending<") else {
        return false;
    };
    let Some(forward) = sole_member(reader, st, "_data") else {
        return false;
    };
    st.size == 0
        && fq_name(reader, forward.inner)
            .is_some_and(|name| name.starts_with("core::marker::PhantomData<"))
}

/// Screen `id` as futures-util's `stream::Next<'_, St>`: one member
/// `stream`, a `&mut St` whose target is the `St` the instantiation
/// declares. The future's poll is that stream's `poll_next` and nothing
/// else; what the stream polls in turn is its own type's business.
pub(crate) fn futures_util_next(reader: &DwReader<'_>, id: TypeId) -> Option<NextLayout> {
    let st = declared_in(reader, id, "futures_util::stream::stream::next", "Next<")?;
    let forward = sole_member(reader, st, "stream")?;
    let [param] = st.template_params.as_ref() else {
        return None;
    };
    let target = mut_ref_thin(reader, forward.inner).ok()?;
    (param.name.map(|name| reader.strings.get(name)) == Some("St")
        && target == reader.canonicalize(param.type_id))
    .then_some(NextLayout {
        stream: forward.member,
        target,
    })
}

/// Screen `id` as tokio-stream's `WatchStream<T>`: one member `inner`,
/// holding tokio-util's `ReusableBoxFuture` by that type's own
/// declaration. The stream's `poll_next` polls that box and nothing
/// else, then refills it.
pub(crate) fn tokio_stream_watch_stream(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<ForwardLayout> {
    let st = declared_in(reader, id, "tokio_stream::wrappers::watch", "WatchStream<")?;
    let forward = sole_member(reader, st, "inner")?;
    declared_in(
        reader,
        forward.inner,
        "tokio_util::sync::reusable_box",
        "ReusableBoxFuture<",
    )?;
    Some(forward)
}

/// Screen `id` as tokio-util's `ReusableBoxFuture<'_, T>`: one member
/// `boxed`, a `Pin<Box<dyn …>>` as the std adapter screen reads one,
/// over a trait object. Every poll of the type goes through that box;
/// a box over a sized future is not the type as reviewed.
pub(crate) fn tokio_util_reusable_box(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<ReusableBoxLayout> {
    let st = declared_in(
        reader,
        id,
        "tokio_util::sync::reusable_box",
        "ReusableBoxFuture<",
    )?;
    let forward = sole_member(reader, st, "boxed")?;
    match std_adapter(reader, forward.inner)? {
        StdAdapter::PinBox {
            member,
            boxed,
            pointee: Pointee::Dyn(wide),
        } => Some(ReusableBoxLayout {
            boxed: forward.member,
            pin: (member, boxed),
            wide,
        }),
        _ => None,
    }
}

/// A `PollFn` over the closure tokio's `select!` awaits, as the raw
/// screen saw it: the member holding the closure, the closure
/// environment, its two by-reference captures and what each points at
/// — the mask word and the tuple of branch futures, member by member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectLayout {
    /// The `PollFn`'s one member and the closure environment it holds.
    pub(crate) closure: String,
    pub(crate) env: TypeId,
    /// The capture pointing at the mask, and the unsigned word behind
    /// it (its size is the mask's width).
    pub(crate) mask: String,
    pub(crate) mask_word: TypeId,
    /// The capture pointing at the tuple, and the tuple.
    pub(crate) futures: String,
    pub(crate) tuple: TypeId,
    /// The tuple's members in order — branch `i` is `__i` — with the
    /// future type each holds.
    pub(crate) branches: Vec<(String, TypeId)>,
}

/// Screen `id` as the `PollFn` a `select!` expansion awaits: std's
/// `core::future::poll_fn::PollFn<F>` holding an `F` in its one member
/// `f`, where `F` is a closure environment with exactly two members,
/// `_ref__disabled: &mut <unsigned word>` and `_ref__futures: &mut
/// (F0, …)`, the word 1, 2, 4 or 8 bytes wide and the tuple an
/// aggregate of members `__0` through `__n-1` in order with at least
/// one and no more than the word has bits. Any other `PollFn` — the
/// mpsc receiver's, a user's — declines; whose `select.rs` the closure
/// was written in is the binder's question, over its declaration site.
pub(crate) fn tokio_select(reader: &DwReader<'_>, id: TypeId) -> Option<SelectLayout> {
    let st = declared_in(reader, id, "core::future::poll_fn", "PollFn<")?;
    let closure = sole_member(reader, st, "f")?;
    let env = struct_of(reader, closure.inner)?;
    if !env
        .name
        .is_some_and(|name| reader.strings.get(name).starts_with("{closure_env#"))
        || env.members.len() != 2
    {
        return None;
    }
    let (_, disabled) = unique_member(reader, &env.members, "_ref__disabled")?;
    let (_, futures) = unique_member(reader, &env.members, "_ref__futures")?;
    let mask_word = mut_ref_thin(reader, disabled.type_id).ok()?;
    let width = match reader.canonical_type(mask_word)? {
        RawType::Base(base) if base.encoding == crate::Encoding::Unsigned => base.size,
        _ => return None,
    };
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let tuple = mut_ref_thin(reader, futures.type_id).ok()?;
    let tuple_st = struct_of(reader, tuple)?;
    if !tuple_st
        .name
        .is_some_and(|name| reader.strings.get(name).starts_with('('))
        || tuple_st.members.is_empty()
        || tuple_st.members.len() as u64 > width * 8
    {
        return None;
    }
    let mut branches = Vec::with_capacity(tuple_st.members.len());
    for (i, member) in tuple_st.members.iter().enumerate() {
        let name = reader.strings.get(member.name?);
        if name != format!("__{i}") {
            return None;
        }
        branches.push((name.to_owned(), reader.canonicalize(member.type_id)));
    }
    Some(SelectLayout {
        closure: closure.member,
        env: closure.inner,
        mask: "_ref__disabled".to_owned(),
        mask_word,
        futures: "_ref__futures".to_owned(),
        tuple,
        branches,
    })
}

/// A `PollFn` over the closure tokio's `Interval::tick` awaits, as the
/// raw screen saw it: the member holding the closure, the closure
/// environment, its one capture and the `Interval` it points at, and
/// the interval's member holding the pinned box its `Sleep` lives in,
/// with that box's own type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IntervalTickLayout {
    /// The `PollFn`'s one member and the closure environment it holds.
    pub(crate) closure: String,
    pub(crate) env: TypeId,
    /// The capture pointing at the interval, and the interval.
    pub(crate) interval_ref: String,
    pub(crate) interval: TypeId,
    /// The interval's member holding its `Pin<Box<Sleep>>`, and that
    /// pinned box.
    pub(crate) delay: String,
    pub(crate) boxed: TypeId,
}

/// Screen `id` as the `PollFn` tokio's `Interval::tick` awaits: std's
/// `core::future::poll_fn::PollFn<F>` holding an `F` in its one member
/// `f`, where `F` is a closure environment declared under
/// `tokio::time::interval::{impl#N}::tick::{async_fn#0}` with exactly
/// one member, `_ref__self: &mut Interval`, the `Interval` being the
/// struct of that name declared in `tokio::time::interval`, with a
/// member `delay` holding a `Pin<Box<Sleep>>` over tokio's own `Sleep`.
/// The closure's body is `self.poll_tick(cx)`, whose pending path
/// polls that box and nothing else. Any other `PollFn` — the mpsc
/// receiver's, a `select!`'s, a user's — declines; whose `interval.rs`
/// the closure was written in is the binder's question, over its
/// declaration site.
pub(crate) fn tokio_interval_tick(reader: &DwReader<'_>, id: TypeId) -> Option<IntervalTickLayout> {
    let st = declared_in(reader, id, "core::future::poll_fn", "PollFn<")?;
    let closure = sole_member(reader, st, "f")?;
    let env = struct_of(reader, closure.inner)?;
    let under_tick = env
        .namespace
        .map(|ns| ns_path(reader, ns))
        .is_some_and(|path| {
            path.strip_prefix("tokio::time::interval::{impl#")
                .and_then(|rest| rest.strip_suffix("}::tick::{async_fn#0}"))
                .is_some_and(|index| !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()))
        });
    if !under_tick
        || !env
            .name
            .is_some_and(|name| reader.strings.get(name).starts_with("{closure_env#"))
        || env.members.len() != 1
    {
        return None;
    }
    let (_, capture) = unique_member(reader, &env.members, "_ref__self")?;
    let interval = mut_ref_thin(reader, capture.type_id).ok()?;
    let interval_st = declared_in(reader, interval, "tokio::time::interval", "Interval")?;
    if reader.strings.get(interval_st.name?) != "Interval" {
        return None;
    }
    let (_, delay) = unique_member(reader, &interval_st.members, "delay")?;
    let Some(StdAdapter::PinBox {
        pointee: Pointee::Sized(sleep),
        ..
    }) = std_adapter(reader, delay.type_id)
    else {
        return None;
    };
    (fq_name(reader, sleep).as_deref() == Some("tokio::time::sleep::Sleep")).then(|| {
        IntervalTickLayout {
            closure: closure.member,
            env: closure.inner,
            interval_ref: "_ref__self".to_owned(),
            interval,
            delay: "delay".to_owned(),
            boxed: reader.canonicalize(delay.type_id),
        }
    })
}

/// The payload type of the variant named `variant` of the enum `id`,
/// canonicalized; `None` for anything that is not an enum with a
/// variant of that name.
fn variant_payload(reader: &DwReader<'_>, id: TypeId, variant: &str) -> Option<TypeId> {
    let RawType::Enum(en) = reader.canonical_type(id)? else {
        return None;
    };
    let named = |v: &RawVariant<crate::StrId>| {
        v.member
            .name
            .is_some_and(|name| reader.strings.get(name) == variant)
    };
    let payload = match &en.shape {
        VariantShape::One(v) if named(v) => v.member.type_id,
        VariantShape::Many { variants, .. } => {
            let mut found = variants.iter().filter(|(_, v)| named(v));
            let (_, v) = found.next()?;
            if found.next().is_some() {
                return None;
            }
            v.member.type_id
        }
        _ => return None,
    };
    Some(reader.canonicalize(payload))
}

/// Whether `id` is an enum declared in `module` under exactly `name`.
fn enum_declared_in(reader: &DwReader<'_>, id: TypeId, module: &str, name: &str) -> bool {
    let Some(RawType::Enum(en)) = reader.canonical_type(id) else {
        return false;
    };
    en.namespace.map(|ns| ns_path(reader, ns)).as_deref() == Some(module)
        && en.name.map(|n| reader.strings.get(n)) == Some(name)
}

/// Whether `id` is an enum declared in `module` whose name starts with
/// `prefix` — a generic enum, whose name carries its arguments.
fn enum_declared_in_prefix(reader: &DwReader<'_>, id: TypeId, module: &str, prefix: &str) -> bool {
    let Some(RawType::Enum(en)) = reader.canonical_type(id) else {
        return false;
    };
    en.namespace.map(|ns| ns_path(reader, ns)).as_deref() == Some(module)
        && en
            .name
            .is_some_and(|n| reader.strings.get(n).starts_with(prefix))
}

/// The unique member `member` of the struct `id`, canonicalized.
fn member_of(reader: &DwReader<'_>, id: TypeId, member: &str) -> Option<TypeId> {
    let st = struct_of(reader, id)?;
    let (_, found) = unique_member(reader, &st.members, member)?;
    Some(reader.canonicalize(found.type_id))
}

/// hyper's `proto::h1::dispatch::Dispatcher<D, Bs, I, T>` as the raw
/// screen saw it: the role its `T` names, and the type at the end of
/// every route the connection binding records — each reached by the
/// member and variant names the reviewed layout declares, so the
/// binder can hold the same names to the final table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpDispatcherLayout {
    pub(crate) role: H1Role,
    /// `conn.state.keep_alive`, the `KA` enum.
    pub(crate) keep_alive: TypeId,
    /// `conn.state.reading`, the `Reading` enum.
    pub(crate) reading: TypeId,
    /// `conn.state.writing`, the `Writing` enum.
    pub(crate) writing: TypeId,
    /// `conn.state.method`, the `Option<Method>`.
    pub(crate) method: TypeId,
    /// The method's enum inside it: `Some.__0.__0`.
    pub(crate) method_inner: TypeId,
    /// The decoder's `kind` inside `Reading::Continue` and
    /// `Reading::Body`, and the encoder's inside `Writing::Body`.
    pub(crate) read_continue_kind: TypeId,
    pub(crate) read_body_kind: TypeId,
    pub(crate) write_body_kind: TypeId,
    /// `is_closing`, a `bool`.
    pub(crate) is_closing: TypeId,
    /// The client dispatch's words, for a `T` of `role::Client`.
    pub(crate) client: Option<HttpClientLayout>,
    /// The server dispatch's words, for a `T` of `role::Server`.
    pub(crate) server: Option<HttpServerLayout>,
}

/// The client dispatch as the raw screen saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpClientLayout {
    /// `dispatch.callback`, the `Option<Callback<..>>`.
    pub(crate) callback: TypeId,
    /// The oneshot `Sender` in `callback`'s `Some.__0.Retry.__0.Some.__0`.
    pub(crate) retry: TypeId,
    /// The same through `NoRetry`.
    pub(crate) no_retry: TypeId,
    /// `dispatch.rx.inner`, the `UnboundedReceiver<Envelope<..>>`.
    pub(crate) rx: TypeId,
    /// `dispatch.rx.taker.inner.ptr.pointer`, the `*const
    /// ArcInner<want::Inner>` the receiver shares with its sender.
    pub(crate) want: TypeId,
}

/// The server dispatch as the raw screen saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpServerLayout {
    /// `dispatch.in_flight`'s one member — the `Pin`'s pointer — and
    /// the `Box` it holds.
    pub(crate) in_flight_member: String,
    pub(crate) in_flight_box: TypeId,
    /// The `Option` behind that box, `Some` while a handler runs.
    pub(crate) in_flight: TypeId,
    /// `conn.state.h1_header_read_timeout_running`, a `bool`.
    pub(crate) header_read_timeout_running: TypeId,
    /// The two words of the `Duration` in
    /// `conn.state.h1_header_read_timeout`'s `Some`: `secs`, a `u64`,
    /// and `nanos.__0`, the `u32` inside std's `Nanoseconds`.
    pub(crate) header_read_timeout_secs: TypeId,
    pub(crate) header_read_timeout_nanos: TypeId,
    /// The header-read timer itself: the boxed `dyn Sleep` in
    /// `conn.state.h1_header_read_timeout_fut`'s `Some`, as the `Pin`'s
    /// member holding the `Box`, the `Box`'s data pointer member, and
    /// that pointer's type.
    pub(crate) header_read_timer_pin: String,
    pub(crate) header_read_timer_pointer: String,
    pub(crate) header_read_timer: TypeId,
    /// The service the dispatch drives, and what it keeps where a
    /// reviewed convention says it does.
    pub(crate) service: TypeId,
    pub(crate) dropshot: Option<DropshotHandlerLayout>,
}

/// dropshot's `ServerRequestHandler<C>` as the screen saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DropshotHandlerLayout {
    /// `remote_addr`, std's `SocketAddr`: the accepted socket's peer.
    pub(crate) remote_addr: TypeId,
    /// The declared `C`: the application's context the server was
    /// built with.
    pub(crate) context: TypeId,
}

/// The member names the connection binding's routes are made of, as
/// the reviewed hyper layout declares them. One list, shared by the
/// screen that finds the shape in the DWARF and the binder that holds
/// it to the final table.
pub(crate) mod hyper_h1 {
    pub(crate) const CONN: &str = "conn";
    pub(crate) const STATE: &str = "state";
    pub(crate) const KEEP_ALIVE: &str = "keep_alive";
    pub(crate) const READING: &str = "reading";
    pub(crate) const WRITING: &str = "writing";
    pub(crate) const METHOD: &str = "method";
    pub(crate) const IS_CLOSING: &str = "is_closing";
    pub(crate) const DISPATCH: &str = "dispatch";
    pub(crate) const CALLBACK: &str = "callback";
    pub(crate) const RETRY: &str = "Retry";
    pub(crate) const NO_RETRY: &str = "NoRetry";
    pub(crate) const RX: &str = "rx";
    /// The receiver's `want::Taker`, down to the `*const` its `Arc`
    /// keeps: `taker.inner.ptr.pointer`.
    pub(crate) const TAKER: &str = "taker";
    pub(crate) const TAKER_PTR: [&str; 4] = [TAKER, INNER, PTR, POINTER];
    pub(crate) const PTR: &str = "ptr";
    pub(crate) const POINTER: &str = "pointer";
    pub(crate) const INNER: &str = "inner";
    pub(crate) const SOME: &str = "Some";
    pub(crate) const PAYLOAD: &str = "__0";
    pub(crate) const CONTINUE: &str = "Continue";
    pub(crate) const BODY: &str = "Body";
    pub(crate) const KIND: &str = "kind";
    pub(crate) const IN_FLIGHT: &str = "in_flight";
    pub(crate) const HEADER_READ_TIMEOUT_RUNNING: &str = "h1_header_read_timeout_running";
    /// The timeout the header-read timer is armed for, and std's
    /// `Duration` down to its two words.
    pub(crate) const HEADER_READ_TIMEOUT: &str = "h1_header_read_timeout";
    pub(crate) const SECS: &str = "secs";
    pub(crate) const NANOS: &str = "nanos";
    /// The header-read timer, a pinned box of hyper's `dyn Sleep`.
    pub(crate) const HEADER_READ_TIMEOUT_FUT: &str = "h1_header_read_timeout_fut";
    pub(crate) const IO: &str = "io";
    pub(crate) const SERVICE: &str = "service";
    /// dropshot's request handler: the member its server stores the
    /// accepted socket's peer address in.
    pub(crate) const REMOTE_ADDR: &str = "remote_addr";
    /// hyper-util's version-choosing wrapper: its state member and
    /// the state's three variants.
    pub(crate) const READ_VERSION: &str = "ReadVersion";
    pub(crate) const H1: &str = "H1";
    pub(crate) const H2: &str = "H2";
}

/// Screen `id` as hyper's HTTP/1 `Dispatcher`: declared in
/// `hyper::proto::h1::dispatch` with a `T` of `role::Client` or
/// `role::Server`, holding `conn` (a `proto::h1::conn::Conn` whose
/// `state` is the `State` with the four words), `dispatch` and
/// `is_closing`. For the client, `dispatch` is the `dispatch::Client`
/// whose `callback` is an `Option` of the `Callback` enum, each of
/// whose two variants carries an `Option` of a oneshot `Sender`, and
/// whose `rx` holds the unbounded receiver in `inner`. For the server,
/// `dispatch` is the `dispatch::Server` whose `in_flight` is a `Pin` of
/// a `Box` of the `Option` holding the running handler, and the state
/// carries the header-read timer's flag beside its words.
pub(crate) fn hyper_h1_dispatcher(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HttpDispatcherLayout> {
    use hyper_h1::*;
    let st = declared_in(reader, id, "hyper::proto::h1::dispatch", "Dispatcher<")?;
    let role = super::crates::h1_role(reader, st)?;
    let conn = member_of(reader, id, CONN)?;
    declared_in(reader, conn, "hyper::proto::h1::conn", "Conn<")?;
    let state = member_of(reader, conn, STATE)?;
    declared_in(reader, state, "hyper::proto::h1::conn", "State")?;
    let word = |name: &str, expected: &str| {
        let ty = member_of(reader, state, name)?;
        (fq_name(reader, ty).as_deref() == Some(expected)).then_some(ty)
    };
    let keep_alive = word(KEEP_ALIVE, "hyper::proto::h1::conn::KA")?;
    let reading = word(READING, "hyper::proto::h1::conn::Reading")?;
    let writing = word(WRITING, "hyper::proto::h1::conn::Writing")?;
    let method = word(METHOD, "core::option::Option<http::method::Method>")?;
    // The method's own enum, through the option and the `Method`
    // newtype; the body framing, through the variant carrying the
    // decoder or encoder to its `kind`.
    let method_inner = member_of(
        reader,
        member_of(reader, variant_payload(reader, method, SOME)?, PAYLOAD)?,
        PAYLOAD,
    )?;
    if fq_name(reader, method_inner).as_deref() != Some("http::method::Inner") {
        return None;
    }
    let framing = |word: TypeId, variant: &str, module: &str, codec_name: &str| {
        let module = format!("hyper::proto::h1::{module}");
        let codec = member_of(reader, variant_payload(reader, word, variant)?, PAYLOAD)?;
        declared_in(reader, codec, &module, codec_name)?;
        let kind = member_of(reader, codec, KIND)?;
        enum_declared_in(reader, kind, &module, "Kind").then_some(kind)
    };
    let read_continue_kind = framing(reading, CONTINUE, "decode", "Decoder")?;
    let read_body_kind = framing(reading, BODY, "decode", "Decoder")?;
    let write_body_kind = framing(writing, BODY, "encode", "Encoder")?;
    let is_closing = member_of(reader, id, IS_CLOSING)?;
    if fq_name(reader, is_closing).as_deref() != Some("bool") {
        return None;
    }
    let dispatch = member_of(reader, id, DISPATCH)?;
    let mut server = None;
    let client = match role {
        H1Role::Server => {
            declared_in(reader, dispatch, "hyper::proto::h1::dispatch", "Server<")?;
            // The handler behind its pinned box: the `Pin`'s one member
            // is the `Box`, and the box's pointee is the `Option`.
            let in_flight = member_of(reader, dispatch, IN_FLIGHT)?;
            let (in_flight_member, in_flight_box) = pin(reader, in_flight)?;
            let option = box_thin(reader, in_flight_box).ok()?;
            if !fq_name(reader, option)?.starts_with("core::option::Option<") {
                return None;
            }
            variant_payload(reader, option, SOME)?;
            let flag = member_of(reader, state, HEADER_READ_TIMEOUT_RUNNING)?;
            if fq_name(reader, flag).as_deref() != Some("bool") {
                return None;
            }
            let (secs, nanos) = duration_words(
                reader,
                member_of(
                    reader,
                    variant_payload(reader, member_of(reader, state, HEADER_READ_TIMEOUT)?, SOME)?,
                    PAYLOAD,
                )?,
            )?;
            // The timer: the `Option`'s `Some` pins a `Box` of hyper's
            // `dyn Sleep`, whose data pointer is the timer's address.
            // rustc names the object with its `Future` supertrait's
            // output bound.
            let timer = variant_payload(
                reader,
                member_of(reader, state, HEADER_READ_TIMEOUT_FUT)?,
                SOME,
            )?;
            let (timer_pin, timer_box) = pin(reader, member_of(reader, timer, PAYLOAD)?)?;
            let Ok(Pointee::Dyn(timer_box)) = boxed(reader, timer_box) else {
                return None;
            };
            if fq_name(reader, timer_box.trait_ty).as_deref()
                != Some("dyn hyper::rt::timer::Sleep<Output=()>")
            {
                return None;
            }
            let service = member_of(reader, dispatch, SERVICE)?;
            server = Some(HttpServerLayout {
                in_flight_member,
                in_flight_box,
                in_flight: option,
                header_read_timeout_running: flag,
                header_read_timeout_secs: secs,
                header_read_timeout_nanos: nanos,
                header_read_timer_pin: timer_pin,
                header_read_timer_pointer: timer_box.pointer,
                header_read_timer: timer_box.data_ptr,
                service,
                dropshot: dropshot_request_handler(reader, service),
            });
            None
        }
        H1Role::Client => {
            declared_in(reader, dispatch, "hyper::proto::h1::dispatch", "Client<")?;
            let callback = member_of(reader, dispatch, CALLBACK)?;
            if !fq_name(reader, callback)?
                .starts_with("core::option::Option<hyper::client::dispatch::Callback<")
            {
                return None;
            }
            let some = variant_payload(reader, callback, SOME)?;
            let enum_ = member_of(reader, some, PAYLOAD)?;
            let sender = |variant: &str| {
                let payload = variant_payload(reader, enum_, variant)?;
                let option = member_of(reader, payload, PAYLOAD)?;
                let some = variant_payload(reader, option, SOME)?;
                let sender = member_of(reader, some, PAYLOAD)?;
                fq_name(reader, sender)?
                    .starts_with("tokio::sync::oneshot::Sender<")
                    .then_some(sender)
            };
            let retry = sender(RETRY)?;
            let no_retry = sender(NO_RETRY)?;
            let receiver = member_of(reader, dispatch, RX)?;
            declared_in(reader, receiver, "hyper::client::dispatch", "Receiver<")?;
            let rx = member_of(reader, receiver, INNER)?;
            if !fq_name(reader, rx)?.starts_with("tokio::sync::mpsc::unbounded::UnboundedReceiver<")
            {
                return None;
            }
            let want = want_pointer(reader, member_of(reader, receiver, TAKER)?, "Taker")?;
            Some(HttpClientLayout {
                callback,
                retry,
                no_retry,
                rx,
                want,
            })
        }
    };
    Some(HttpDispatcherLayout {
        role,
        keep_alive,
        reading,
        writing,
        method,
        method_inner,
        read_continue_kind,
        read_body_kind,
        write_body_kind,
        is_closing,
        client,
        server,
    })
}

/// std's `Duration { secs: u64, nanos: Nanoseconds }`, whose
/// `Nanoseconds` is the niche-carrying newtype over a `u32`: the two
/// words' types, `secs` and `nanos.__0`.
fn duration_words(reader: &DwReader<'_>, duration: TypeId) -> Option<(TypeId, TypeId)> {
    use hyper_h1::{NANOS, PAYLOAD, SECS};
    declared_in(reader, duration, "core::time", "Duration")?;
    let secs = member_of(reader, duration, SECS)?;
    let nanos = member_of(reader, duration, NANOS)?;
    declared_in(reader, nanos, "core::num::niche_types", "Nanoseconds")?;
    let nanos = member_of(reader, nanos, PAYLOAD)?;
    (fq_name(reader, secs).as_deref() == Some("u64")
        && fq_name(reader, nanos).as_deref() == Some("u32"))
    .then_some((secs, nanos))
}

/// Screen `service` as dropshot's `ServerRequestHandler<C>`, declared in
/// `dropshot::server` with its one template parameter `C` — the
/// application's context — and a `remote_addr` member holding the
/// accepted socket's peer as `core::net::SocketAddr`; `None` for any
/// other service, which the review says nothing about.
pub(crate) fn dropshot_request_handler(
    reader: &DwReader<'_>,
    service: TypeId,
) -> Option<DropshotHandlerLayout> {
    let st = declared_in(reader, service, "dropshot::server", "ServerRequestHandler<")?;
    let [param] = st.template_params.as_ref() else {
        return None;
    };
    if param.name.map(|name| reader.strings.get(name)) != Some("C") {
        return None;
    }
    let remote_addr = member_of(reader, service, hyper_h1::REMOTE_ADDR)?;
    (fq_name(reader, remote_addr).as_deref() == Some("core::net::socket_addr::SocketAddr")).then(
        || DropshotHandlerLayout {
            remote_addr,
            context: reader.canonicalize(param.type_id),
        },
    )
}

/// The member names a request binding's routes are made of, as the
/// reviewed reqwest, http and dropshot layouts declare them, and std's
/// `String` down to its byte pointer. One list, shared by the screens
/// that find the shapes in the DWARF and the binder that holds them
/// to the final table.
pub(crate) mod request {
    pub(crate) const METHOD: &str = "method";
    pub(crate) const PAYLOAD: &str = "__0";
    /// reqwest's `PendingRequest`: the `Url`, whose `serialization` is
    /// the whole URL as a `String`.
    pub(crate) const URL: &str = "url";
    pub(crate) const SERIALIZATION: &str = "serialization";
    /// http's `Request`: its `Parts`, whose `uri`'s `path_and_query` is
    /// a `ByteStr` over a `Bytes`.
    pub(crate) const HEAD: &str = "head";
    pub(crate) const URI: &str = "uri";
    pub(crate) const PATH_AND_QUERY: &str = "path_and_query";
    pub(crate) const DATA: &str = "data";
    pub(crate) const BYTES: &str = "bytes";
    /// `Bytes`' view, and std's `String` from its `Vec<u8>` through the
    /// raw buffer to the byte pointer: `vec.buf.inner.ptr.pointer.pointer`
    /// and `vec.len`.
    pub(crate) const PTR: &str = "ptr";
    pub(crate) const LEN: &str = "len";
    pub(crate) const VEC: &str = "vec";
    pub(crate) const BUF: &str = "buf";
    pub(crate) const INNER: &str = "inner";
    pub(crate) const POINTER: &str = "pointer";
    /// dropshot's `RequestContext`: its `RequestInfo`.
    pub(crate) const REQUEST: &str = "request";
    pub(crate) const STRING_PTR: [&str; 6] = [VEC, BUF, INNER, PTR, POINTER, POINTER];
    pub(crate) const STRING_LEN: [&str; 2] = [VEC, LEN];
    pub(crate) const PATH_PTR: [&str; 5] = [URI, PATH_AND_QUERY, DATA, BYTES, PTR];
    pub(crate) const PATH_LEN: [&str; 5] = [URI, PATH_AND_QUERY, DATA, BYTES, LEN];
}

/// Which crate's type a request binding was screened as.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HttpRequestKind {
    ReqwestPendingRequest,
    HttpRequest,
    DropshotRequestContext,
}

/// A type keeping a request's words as the raw screen saw it: the
/// method's enum and the two words the target's text is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpRequestLayout {
    pub(crate) kind: HttpRequestKind,
    /// `http::method::Inner`, reached through the `Method` newtype.
    pub(crate) method_inner: TypeId,
    /// The `*const u8` the target's bytes start at, and their count.
    pub(crate) target_ptr: TypeId,
    pub(crate) target_len: TypeId,
}

/// Whether `id` is a pointer to a byte.
fn is_byte_pointer(reader: &DwReader<'_>, id: TypeId) -> bool {
    matches!(
        reader.canonical_type(id),
        Some(RawType::Pointer(RawPointer { target_type_id, .. }))
            if super::is_unsigned_integer(reader, *target_type_id, 1)
    )
}

/// http's `Method` newtype around its `Inner` enum: the enum's type.
fn method_inner(reader: &DwReader<'_>, method: TypeId) -> Option<TypeId> {
    declared_in(reader, method, "http::method", "Method")?;
    let inner = member_of(reader, method, request::PAYLOAD)?;
    enum_declared_in(reader, inner, "http::method", "Inner").then_some(inner)
}

/// bytes' `Bytes`: its `ptr` and `len`, the view whatever vtable owns
/// the storage.
fn bytes_text(reader: &DwReader<'_>, bytes: TypeId) -> Option<(TypeId, TypeId)> {
    declared_in(reader, bytes, "bytes::bytes", "Bytes")?;
    let ptr = member_of(reader, bytes, request::PTR)?;
    let len = member_of(reader, bytes, request::LEN)?;
    (is_byte_pointer(reader, ptr) && super::is_unsigned_integer(reader, len, 8))
        .then_some((ptr, len))
}

/// http's `Uri`, down to the bytes of its `path_and_query`.
fn path_and_query_text(reader: &DwReader<'_>, uri: TypeId) -> Option<(TypeId, TypeId)> {
    declared_in(reader, uri, "http::uri", "Uri")?;
    let path_and_query = member_of(reader, uri, request::PATH_AND_QUERY)?;
    declared_in(reader, path_and_query, "http::uri::path", "PathAndQuery")?;
    let data = member_of(reader, path_and_query, request::DATA)?;
    declared_in(reader, data, "http::byte_str", "ByteStr")?;
    bytes_text(reader, member_of(reader, data, request::BYTES)?)
}

/// std's `String`, down to its byte pointer and length.
fn string_text(reader: &DwReader<'_>, string: TypeId) -> Option<(TypeId, TypeId)> {
    declared_in(reader, string, "alloc::string", "String")?;
    let mut ptr = string;
    for member in request::STRING_PTR {
        ptr = member_of(reader, ptr, member)?;
    }
    let mut len = string;
    for member in request::STRING_LEN {
        len = member_of(reader, len, member)?;
    }
    (is_byte_pointer(reader, ptr) && super::is_unsigned_integer(reader, len, 8))
        .then_some((ptr, len))
}

/// Screen `id` as reqwest's `PendingRequest`, declared in
/// `reqwest::async_impl::client` with `method` http's `Method` and `url`
/// the `url` crate's `Url`, whose `serialization` is the whole URL as
/// a `String`.
pub(crate) fn reqwest_pending_request(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HttpRequestLayout> {
    declared_in(reader, id, "reqwest::async_impl::client", "PendingRequest")?;
    let method_inner = method_inner(reader, member_of(reader, id, request::METHOD)?)?;
    let url = member_of(reader, id, request::URL)?;
    declared_in(reader, url, "url", "Url")?;
    let (target_ptr, target_len) =
        string_text(reader, member_of(reader, url, request::SERIALIZATION)?)?;
    Some(HttpRequestLayout {
        kind: HttpRequestKind::ReqwestPendingRequest,
        method_inner,
        target_ptr,
        target_len,
    })
}

/// Screen `id` as http's `Request<B>`, declared in `http::request` with
/// its `head` the `Parts` holding `method` and `uri`.
pub(crate) fn http_request(reader: &DwReader<'_>, id: TypeId) -> Option<HttpRequestLayout> {
    declared_in(reader, id, "http::request", "Request<")?;
    let head = member_of(reader, id, request::HEAD)?;
    declared_in(reader, head, "http::request", "Parts")?;
    let method_inner = method_inner(reader, member_of(reader, head, request::METHOD)?)?;
    let (target_ptr, target_len) =
        path_and_query_text(reader, member_of(reader, head, request::URI)?)?;
    Some(HttpRequestLayout {
        kind: HttpRequestKind::HttpRequest,
        method_inner,
        target_ptr,
        target_len,
    })
}

/// Screen `id` as dropshot's `RequestContext<C>`, declared in
/// `dropshot::handler` with its `request` the `RequestInfo` holding
/// `method` and `uri`.
pub(crate) fn dropshot_request_context(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HttpRequestLayout> {
    declared_in(reader, id, "dropshot::handler", "RequestContext<")?;
    let info = member_of(reader, id, request::REQUEST)?;
    declared_in(reader, info, "dropshot::handler", "RequestInfo")?;
    let method_inner = method_inner(reader, member_of(reader, info, request::METHOD)?)?;
    let (target_ptr, target_len) =
        path_and_query_text(reader, member_of(reader, info, request::URI)?)?;
    Some(HttpRequestLayout {
        kind: HttpRequestKind::DropshotRequestContext,
        method_inner,
        target_ptr,
        target_len,
    })
}

/// hyper's `UpgradeableConnection` of either side as the raw screen
/// saw it: the member holding the `Option` of the `Connection`, the
/// option, the connection, the member of it holding the dispatcher —
/// `inner` on the client, `conn` on the server — and the dispatcher,
/// which is what the poll reaches through
/// `inner.as_mut().unwrap().<member>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpUpgradeableLayout {
    pub(crate) inner: String,
    pub(crate) option: TypeId,
    pub(crate) connection: TypeId,
    pub(crate) dispatcher_member: String,
    pub(crate) dispatcher: TypeId,
}

/// Screen `id` as hyper's `Connection` declared in `module` — the
/// client's `client::conn::http1` or the server's `server::conn::http1`
/// — with one member, `member`, holding the `Dispatcher` its poll
/// forwards to.
fn hyper_h1_connection(
    reader: &DwReader<'_>,
    id: TypeId,
    module: &str,
    member: &str,
) -> Option<ForwardLayout> {
    let st = declared_in(reader, id, module, "Connection<")?;
    let forward = sole_member(reader, st, member)?;
    declared_in(
        reader,
        forward.inner,
        "hyper::proto::h1::dispatch",
        "Dispatcher<",
    )?;
    Some(forward)
}

/// Screen `id` as hyper's `UpgradeableConnection` declared in `module`:
/// one member `inner` holding an `Option` of the `Connection` declared
/// in `connection_module`, whose `member` is the dispatcher the poll
/// reaches.
fn hyper_h1_upgradeable(
    reader: &DwReader<'_>,
    id: TypeId,
    module: &str,
    connection_module: &str,
    member: &str,
) -> Option<HttpUpgradeableLayout> {
    let st = declared_in(reader, id, module, "UpgradeableConnection<")?;
    let forward = sole_member(reader, st, hyper_h1::INNER)?;
    if !fq_name(reader, forward.inner)?.starts_with(&format!(
        "core::option::Option<{connection_module}::Connection<"
    )) {
        return None;
    }
    let some = variant_payload(reader, forward.inner, hyper_h1::SOME)?;
    let connection = member_of(reader, some, hyper_h1::PAYLOAD)?;
    let dispatcher = hyper_h1_connection(reader, connection, connection_module, member)?;
    Some(HttpUpgradeableLayout {
        inner: forward.member,
        option: forward.inner,
        connection,
        dispatcher_member: dispatcher.member,
        dispatcher: dispatcher.inner,
    })
}

/// Screen `id` as one of tokio-rustls's handshake newtypes — `Connect`,
/// `Accept`, `FallibleConnect`, `FallibleAccept`, in the crate root or
/// beside its side's stream — whose one member `__0` holds the
/// `MidHandshake` its poll forwards to.
pub(crate) fn tokio_rustls_handshake(reader: &DwReader<'_>, id: TypeId) -> Option<ForwardLayout> {
    let st = [
        "tokio_rustls",
        "tokio_rustls::client",
        "tokio_rustls::server",
    ]
    .into_iter()
    .flat_map(|module| {
        ["Connect<", "Accept<", "FallibleConnect<", "FallibleAccept<"]
            .map(|prefix| declared_in(reader, id, module, prefix))
    })
    .flatten()
    .next()?;
    let forward = sole_member(reader, st, "__0")?;
    // The handshake is an enum, which `declared_in` does not screen.
    fq_name(reader, forward.inner)?
        .starts_with("tokio_rustls::common::handshake::MidHandshake<")
        .then_some(forward)
}

/// Screen `id` as hyper's `Connection<T, B>` of `client::conn::http1`:
/// one member `inner` holding the `Dispatcher` its poll forwards to.
pub(crate) fn hyper_h1_client_connection(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<ForwardLayout> {
    hyper_h1_connection(reader, id, "hyper::client::conn::http1", hyper_h1::INNER)
}

/// Screen `id` as hyper's `UpgradeableConnection<T, B>` of
/// `client::conn::http1::upgrades`: one member `inner` holding an
/// `Option` of the `Connection` above, whose own `inner` is the
/// dispatcher the poll reaches.
pub(crate) fn hyper_h1_client_upgradeable(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HttpUpgradeableLayout> {
    hyper_h1_upgradeable(
        reader,
        id,
        "hyper::client::conn::http1::upgrades",
        "hyper::client::conn::http1",
        hyper_h1::INNER,
    )
}

/// Screen `id` as hyper's `Connection<I, S>` of `server::conn::http1`:
/// one member `conn` holding the `Dispatcher` its poll forwards to.
pub(crate) fn hyper_h1_server_connection(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<ForwardLayout> {
    hyper_h1_connection(reader, id, "hyper::server::conn::http1", hyper_h1::CONN)
}

/// Screen `id` as hyper's `UpgradeableConnection<I, S>` of
/// `server::conn::http1` — declared beside its `Connection`, not in an
/// `upgrades` module of its own as the client's is: one member `inner`
/// holding an `Option` of that `Connection`, whose `conn` is the
/// dispatcher the poll reaches.
pub(crate) fn hyper_h1_server_upgradeable(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HttpUpgradeableLayout> {
    hyper_h1_upgradeable(
        reader,
        id,
        "hyper::server::conn::http1",
        "hyper::server::conn::http1",
        hyper_h1::CONN,
    )
}

/// hyper-util's `server::conn::auto::UpgradeableConnection<I, S, E>` as
/// the raw screen saw it: the member holding its state enum, the enum,
/// and under the enum's `H1` the member holding hyper's HTTP/1
/// upgradeable connection and that connection's type — what the poll
/// forwards to once the version is chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpAutoLayout {
    pub(crate) state: String,
    pub(crate) state_ty: TypeId,
    pub(crate) h1_conn: String,
    pub(crate) h1: TypeId,
}

/// Screen `id` as hyper-util's version-choosing `UpgradeableConnection`:
/// one member `state` holding the `UpgradeableConnState` enum declared
/// beside it, whose `ReadVersion` carries the `read_version` future of
/// the same module, whose `H1` carries hyper's server-side upgradeable
/// connection in `conn`, and whose `H2` carries hyper's HTTP/2 server
/// connection in `conn`.
pub(crate) fn hyper_util_auto_upgradeable(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HttpAutoLayout> {
    use hyper_h1::*;
    const MODULE: &str = "hyper_util::server::conn::auto";
    let st = declared_in(reader, id, MODULE, "UpgradeableConnection<")?;
    let forward = sole_member(reader, st, STATE)?;
    if !enum_declared_in_prefix(reader, forward.inner, MODULE, "UpgradeableConnState<") {
        return None;
    }
    let read_version = member_of(
        reader,
        variant_payload(reader, forward.inner, READ_VERSION)?,
        "read_version",
    )?;
    declared_in(reader, read_version, MODULE, "ReadVersion<")?;
    let h1 = member_of(reader, variant_payload(reader, forward.inner, H1)?, CONN)?;
    hyper_h1_server_upgradeable(reader, h1)?;
    let h2 = member_of(reader, variant_payload(reader, forward.inner, H2)?, CONN)?;
    declared_in(reader, h2, "hyper::server::conn::http2", "Connection<")?;
    Some(HttpAutoLayout {
        state: forward.member,
        state_ty: forward.inner,
        h1_conn: CONN.to_owned(),
        h1,
    })
}

/// The member names a hash table's routes are made of, as hashbrown's
/// `HashMap` and `HashSet` and std's wrappers around them declare them.
/// One list, shared by the screen, the display program built on it and
/// the binder that holds the same names to the final table.
pub(crate) mod hash_table {
    /// std's `HashMap` and `HashSet`: the hashbrown value each wraps.
    pub(crate) const BASE: &str = "base";
    /// hashbrown's `HashSet`: the `HashMap<T, ()>` it is.
    pub(crate) const MAP: &str = "map";
    /// hashbrown's `HashMap`: its `RawTable`, and the `RawTableInner`
    /// that one keeps the words in, both under this name.
    pub(crate) const TABLE: &str = "table";
    pub(crate) const BUCKET_MASK: &str = "bucket_mask";
    pub(crate) const ITEMS: &str = "items";
    /// The `NonNull<u8>` control pointer, and the raw pointer in it.
    pub(crate) const CTRL: &str = "ctrl";
    pub(crate) const POINTER: &str = "pointer";
    /// A bucket's key and value: the two slots of its `(K, V)`.
    pub(crate) const KEY: &str = "__0";
    pub(crate) const VALUE: &str = "__1";
}

/// Which type a hash table was screened as.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum HashTableKind {
    HashbrownMap,
    HashbrownSet,
    StdMap,
    StdSet,
}

impl HashTableKind {
    /// The members from the screened type to hashbrown's `HashMap`.
    pub(crate) fn outer(self) -> &'static [&'static str] {
        use hash_table::{BASE, MAP};
        match self {
            HashTableKind::HashbrownMap => &[],
            HashTableKind::HashbrownSet => &[MAP],
            HashTableKind::StdMap => &[BASE],
            HashTableKind::StdSet => &[BASE, MAP],
        }
    }

    /// Whether the table's values are a set's units, never read.
    pub(crate) fn is_set(self) -> bool {
        matches!(self, HashTableKind::HashbrownSet | HashTableKind::StdSet)
    }
}

/// A hash table as the raw screen saw it: the hashbrown `HashMap` the
/// screened type is or wraps, the bucket type its `RawTable` stores and
/// that bucket's key and value, and the types of the words the walk
/// reads — each reached by the member names [`hash_table`] lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HashTableLayout {
    pub(crate) kind: HashTableKind,
    /// hashbrown's `HashMap<K, V, S, A>`: whose release the layout is.
    pub(crate) map: TypeId,
    /// The `(K, V)` the table stores, `(T, ())` for a set.
    pub(crate) bucket: TypeId,
    pub(crate) key: TypeId,
    pub(crate) value: TypeId,
    /// `table.table.bucket_mask` and `.items`, both `usize`.
    pub(crate) bucket_mask: TypeId,
    pub(crate) items: TypeId,
    /// `table.table.ctrl.pointer`, the `*const u8` under the `NonNull`.
    pub(crate) ctrl: TypeId,
}

/// Screen `id` as a hash table: hashbrown's `HashMap<K, V>` or its
/// `HashSet<T>` (a `HashMap<T, ()>` in `map`), or std's wrapper of
/// either (in `base`). The table is the `RawTable<(K, V)>` in `table`,
/// whose own `table` is the `RawTableInner` holding `bucket_mask`,
/// `ctrl` and `items`, and whose `T` is the bucket: a `(K, V)` whose
/// slots are the map's own `K` and `V`.
pub(crate) fn hash_table(reader: &DwReader<'_>, id: TypeId) -> Option<HashTableLayout> {
    use hash_table::{BUCKET_MASK, CTRL, ITEMS, KEY, POINTER, TABLE, VALUE};
    let kind = if declared_in(reader, id, "hashbrown::map", "HashMap<").is_some() {
        HashTableKind::HashbrownMap
    } else if declared_in(reader, id, "hashbrown::set", "HashSet<").is_some() {
        HashTableKind::HashbrownSet
    } else if declared_in(reader, id, "std::collections::hash::map", "HashMap<").is_some() {
        HashTableKind::StdMap
    } else if declared_in(reader, id, "std::collections::hash::set", "HashSet<").is_some() {
        HashTableKind::StdSet
    } else {
        return None;
    };
    let mut map = reader.canonicalize(id);
    for (depth, member) in kind.outer().iter().enumerate() {
        map = member_of(reader, map, member)?;
        let expected = match (kind, depth) {
            (HashTableKind::StdSet, 0) => ("hashbrown::set", "HashSet<"),
            _ => ("hashbrown::map", "HashMap<"),
        };
        declared_in(reader, map, expected.0, expected.1)?;
    }

    let st = declared_in(reader, map, "hashbrown::map", "HashMap<")?;
    let param = |name: &str| {
        st.template_params
            .iter()
            .find(|param| param.name.map(|n| reader.strings.get(n)) == Some(name))
            .map(|param| reader.canonicalize(param.type_id))
    };
    let (key, value) = (param("K")?, param("V")?);
    let raw = member_of(reader, map, TABLE)?;
    let raw_table = declared_in(reader, raw, "hashbrown::raw", "RawTable<")?;
    let bucket = raw_table
        .template_params
        .iter()
        .find(|param| param.name.map(|n| reader.strings.get(n)) == Some("T"))
        .map(|param| reader.canonicalize(param.type_id))?;
    if member_of(reader, bucket, KEY)? != key || member_of(reader, bucket, VALUE)? != value {
        return None;
    }
    if kind.is_set() && fq_name(reader, value).as_deref() != Some("()") {
        return None;
    }

    let inner = member_of(reader, raw, TABLE)?;
    declared_in(reader, inner, "hashbrown::raw", "RawTableInner")?;
    let bucket_mask = member_of(reader, inner, BUCKET_MASK)?;
    let items = member_of(reader, inner, ITEMS)?;
    let non_null = member_of(reader, inner, CTRL)?;
    declared_in(reader, non_null, "core::ptr::non_null", "NonNull<")?;
    let ctrl = member_of(reader, non_null, POINTER)?;
    (super::is_unsigned_integer(reader, bucket_mask, 8)
        && super::is_unsigned_integer(reader, items, 8)
        && is_byte_pointer(reader, ctrl))
    .then_some(HashTableLayout {
        kind,
        map,
        bucket,
        key,
        value,
        bucket_mask,
        items,
        ctrl,
    })
}

/// want's `Giver` or `Taker`, named `name`, down to the `*const` to the
/// `ArcInner<want::Inner>` the two ends of one channel share:
/// `inner.ptr.pointer`, want's `Arc<Inner>` through std's `NonNull`.
fn want_pointer(reader: &DwReader<'_>, handle: TypeId, name: &str) -> Option<TypeId> {
    use hyper_h1::{INNER, POINTER, PTR};
    let st = declared_in(reader, handle, "want", name)?;
    if st.name.map(|n| reader.strings.get(n)) != Some(name) {
        return None;
    }
    let arc = member_of(reader, handle, INNER)?;
    declared_in(reader, arc, "alloc::sync", "Arc<")?;
    let non_null = member_of(reader, arc, PTR)?;
    declared_in(reader, non_null, "core::ptr::non_null", "NonNull<")?;
    let pointer = member_of(reader, non_null, POINTER)?;
    let Some(RawType::Pointer(RawPointer { target_type_id, .. })) = reader.canonical_type(pointer)
    else {
        return None;
    };
    (fq_name(reader, *target_type_id).as_deref() == Some("alloc::sync::ArcInner<want::Inner>"))
        .then_some(pointer)
}

/// The member names hyper-util's legacy client pool is read by, from
/// its reaper and its checkout down to what names each connection.
pub(crate) mod hyper_pool {
    pub(crate) const POOL: &str = "pool";
    pub(crate) const PAYLOAD: &str = "__0";
    pub(crate) const SOME: &str = "Some";
    pub(crate) const PTR: &str = "ptr";
    pub(crate) const POINTER: &str = "pointer";
    pub(crate) const STRONG: &str = "strong";
    pub(crate) const DATA: &str = "data";
    pub(crate) const VALUE: &str = "value";
    pub(crate) const IDLE: &str = "idle";
    pub(crate) const KEY: &str = "key";
    pub(crate) const LEN: &str = "len";
    pub(crate) const TX: &str = "tx";
    pub(crate) const HTTP1: &str = "Http1";
    /// The pool key `(Scheme, Authority)`'s authority, and its text:
    /// `__1.data.bytes`, http's `ByteStr` over a `Bytes`.
    pub(crate) const AUTHORITY: &str = "__1";
    pub(crate) const BYTES: &str = "bytes";
    /// A `Vec`'s buffer pointer, `buf.inner.ptr.pointer.pointer`.
    pub(crate) const VEC_PTR: [&str; 5] = ["buf", "inner", PTR, POINTER, POINTER];
    /// A pooled HTTP/1 sender's `want::Giver`, from `tx`'s `Http1`
    /// payload: `__0.dispatch.giver.inner.ptr.pointer`.
    pub(crate) const GIVER_PTR: [&str; 6] = [PAYLOAD, "dispatch", "giver", "inner", PTR, POINTER];
}

/// Where hyper-util's legacy pool is declared.
const POOL_MODULE: &str = "hyper_util::client::legacy::pool";

/// The pool's idle reaper, `IdleTask<T, K>`, as the raw screen saw it:
/// the types at the end of each route its binding records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolReaperLayout {
    /// The pool's `ArcInner` strong count.
    pub(crate) strong: TypeId,
    /// The idle map, `HashMap<K, Vec<Idle<T>>>`, and its bucket.
    pub(crate) idle: TypeId,
    pub(crate) bucket: TypeId,
    /// The key authority's text, from the bucket.
    pub(crate) key_ptr: TypeId,
    pub(crate) key_len: TypeId,
    /// The idle list's buffer pointer and length, from the bucket.
    pub(crate) entries_ptr: TypeId,
    pub(crate) entries_len: TypeId,
    /// `Idle<T>`, and its sender's `want` pointer.
    pub(crate) entry: TypeId,
    pub(crate) want: TypeId,
}

/// A connection checked out of the pool, `Pooled<T, K>`, as the raw
/// screen saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PoolCheckoutLayout {
    pub(crate) key_ptr: TypeId,
    pub(crate) key_len: TypeId,
    pub(crate) want: TypeId,
}

/// The pool key `(Scheme, Authority)`'s authority text: the pointer and
/// length of the `Bytes` under http's `ByteStr`.
fn authority_text(reader: &DwReader<'_>, key: TypeId) -> Option<(TypeId, TypeId)> {
    use hyper_pool::{AUTHORITY, BYTES, DATA};
    let authority = member_of(reader, key, AUTHORITY)?;
    declared_in(reader, authority, "http::uri::authority", "Authority")?;
    let data = member_of(reader, authority, DATA)?;
    declared_in(reader, data, "http::byte_str", "ByteStr")?;
    bytes_text(reader, member_of(reader, data, BYTES)?)
}

/// hyper-util's `PoolClient<B>`, down to its HTTP/1 sender's `want`
/// pointer: `tx`, the `PoolTx` enum, whose `Http1` holds hyper's
/// `SendRequest`, whose `dispatch` is the `dispatch::Sender` keeping
/// the `Giver`.
fn pool_client_want(reader: &DwReader<'_>, client: TypeId) -> Option<TypeId> {
    use hyper_pool::{HTTP1, PAYLOAD, TX};
    declared_in(
        reader,
        client,
        "hyper_util::client::legacy::client",
        "PoolClient<",
    )?;
    let tx = member_of(reader, client, TX)?;
    if !enum_declared_in_prefix(reader, tx, "hyper_util::client::legacy::client", "PoolTx<") {
        return None;
    }
    let send = member_of(reader, variant_payload(reader, tx, HTTP1)?, PAYLOAD)?;
    declared_in(reader, send, "hyper::client::conn::http1", "SendRequest<")?;
    let sender = member_of(reader, send, "dispatch")?;
    declared_in(reader, sender, "hyper::client::dispatch", "Sender<")?;
    want_pointer(reader, member_of(reader, sender, "giver")?, "Giver")
}

/// A two-way choice of future as the raw screen saw it: each variant's
/// name, and the future its one member `__0` holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EitherLayout {
    pub(crate) left: (String, TypeId),
    pub(crate) right: (String, TypeId),
}

/// Screen `id` as futures-util's `future::Either<A, B>`: the enum
/// `Left(A) | Right(B)`, each variant's payload one member `__0` holding
/// the future its template parameter names.
pub(crate) fn futures_util_either(reader: &DwReader<'_>, id: TypeId) -> Option<EitherLayout> {
    if !enum_declared_in_prefix(reader, id, "futures_util::future::either", "Either<") {
        return None;
    }
    let Some(RawType::Enum(en)) = reader.canonical_type(id) else {
        return None;
    };
    let VariantShape::Many { variants, .. } = &en.shape else {
        return None;
    };
    if variants.len() != 2 {
        return None;
    }
    // rustc records an enum's template parameters on each variant's
    // struct, not on the enum; each side's future is the one its
    // parameter names, wherever the variant records it.
    let side = |variant: &str, param_name: &str| {
        let payload = variant_payload(reader, id, variant)?;
        let future = member_of(reader, payload, "__0")?;
        let param = struct_of(reader, payload)?
            .template_params
            .iter()
            .find(|param| param.name.map(|n| reader.strings.get(n)) == Some(param_name))
            .map(|param| reader.canonicalize(param.type_id));
        param
            .is_none_or(|param| param == future)
            .then(|| (variant.to_owned(), future))
    };
    Some(EitherLayout {
        left: side("Left", "A")?,
        right: side("Right", "B")?,
    })
}

/// tower's retry `ResponseFuture` as the raw screen saw it: the member
/// holding its state, the state enum, the member of `Called` holding the
/// service's future and of `Waiting` holding the policy's, and the name
/// of the state in which neither is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TowerRetryLayout {
    pub(crate) state: String,
    pub(crate) state_ty: TypeId,
    pub(crate) called: (String, String, TypeId),
    pub(crate) waiting: (String, String, TypeId),
    pub(crate) retrying: String,
}

/// Screen `id` as tower's `retry::future::ResponseFuture<P, S,
/// Request>`: `{ request, retry, state }`, whose `state` is the
/// module's `State<F, P>` enum `Called { future } | Waiting { waiting }
/// | Retrying`.
pub(crate) fn tower_retry_response_future(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<TowerRetryLayout> {
    declared_in(reader, id, "tower::retry::future", "ResponseFuture<")?;
    let state_ty = member_of(reader, id, "state")?;
    if !enum_declared_in_prefix(reader, state_ty, "tower::retry::future", "State<") {
        return None;
    }
    let Some(RawType::Enum(en)) = reader.canonical_type(state_ty) else {
        return None;
    };
    let VariantShape::Many { variants, .. } = &en.shape else {
        return None;
    };
    if variants.len() != 3 {
        return None;
    }
    let holding = |variant: &str, member: &str| {
        let future = member_of(reader, variant_payload(reader, state_ty, variant)?, member)?;
        Some((variant.to_owned(), member.to_owned(), future))
    };
    variant_payload(reader, state_ty, "Retrying")?;
    Some(TowerRetryLayout {
        state: "state".to_owned(),
        state_ty,
        called: holding("Called", "future")?,
        waiting: holding("Waiting", "waiting")?,
        retrying: "Retrying".to_owned(),
    })
}

/// Screen `id` as reqwest's cookie layer's `ResponseFuture<S, B>`,
/// declared in `reqwest::cookie::service`: `{ future, cookie_store, url
/// }`, whose poll forwards to `future` and only reads the other two once
/// the response is in.
pub(crate) fn reqwest_cookie_response_future(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<ForwardLayout> {
    declared_in(reader, id, "reqwest::cookie::service", "ResponseFuture<")?;
    Some(ForwardLayout {
        member: "future".to_owned(),
        inner: member_of(reader, id, "future")?,
    })
}

/// hyper-util's legacy client `ResponseFuture` as the raw screen saw
/// it: the member holding hyper-util's own `SyncWrapper`, the wrapper's
/// one member, and the pinned box of `dyn Future` it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HyperUtilResponseLayout {
    pub(crate) inner: String,
    pub(crate) wrapped: String,
    pub(crate) boxed: TypeId,
}

/// Screen `id` as hyper-util's legacy client `ResponseFuture`: `{ inner:
/// SyncWrapper<Pin<Box<dyn Future<..> + Send>>> }`, whose poll is the
/// boxed future's through the wrapper's `get_mut`.
pub(crate) fn hyper_util_response_future(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<HyperUtilResponseLayout> {
    let st = declared_in(
        reader,
        id,
        "hyper_util::client::legacy::client",
        "ResponseFuture",
    )?;
    if st.name.map(|n| reader.strings.get(n)) != Some("ResponseFuture") {
        return None;
    }
    let wrapper = member_of(reader, id, "inner")?;
    declared_in(reader, wrapper, "hyper_util::common::sync", "SyncWrapper<")?;
    let boxed = member_of(reader, wrapper, "__0")?;
    fq_name(reader, boxed)?
        .starts_with("core::pin::Pin<alloc::boxed::Box<(dyn core::future::future::Future<")
        .then(|| HyperUtilResponseLayout {
            inner: "inner".to_owned(),
            wrapped: "__0".to_owned(),
            boxed,
        })
}

/// Screen `id` as hyper-util's pool reaper, `IdleTask<T, K>`, declared
/// in the pool's module: its `pool` is a `WeakOpt` over an `Option` of
/// std's `Weak` to the `Mutex<PoolInner<T, K>>`, whose `idle` is std's
/// `HashMap<K, Vec<Idle<T>>>` keyed by `(Scheme, Authority)`, and whose
/// `Idle`'s `value` is the `PoolClient`.
pub(crate) fn hyper_util_pool_reaper(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<PoolReaperLayout> {
    use hyper_pool::*;
    declared_in(reader, id, POOL_MODULE, "IdleTask<")?;
    let weak_opt = member_of(reader, id, POOL)?;
    declared_in(reader, weak_opt, POOL_MODULE, "WeakOpt<")?;
    let option = member_of(reader, weak_opt, PAYLOAD)?;
    let weak = member_of(reader, variant_payload(reader, option, SOME)?, PAYLOAD)?;
    declared_in(reader, weak, "alloc::sync", "Weak<")?;
    let non_null = member_of(reader, weak, PTR)?;
    declared_in(reader, non_null, "core::ptr::non_null", "NonNull<")?;
    let pointer = member_of(reader, non_null, POINTER)?;
    let Some(RawType::Pointer(RawPointer { target_type_id, .. })) = reader.canonical_type(pointer)
    else {
        return None;
    };
    let arc_inner = reader.canonicalize(*target_type_id);
    declared_in(reader, arc_inner, "alloc::sync", "ArcInner<")?;
    let strong = member_of(reader, arc_inner, STRONG)?;
    if !fq_name(reader, strong)?.starts_with("core::sync::atomic::Atomic") {
        return None;
    }
    // std's `Mutex` has moved module between releases; what the route is
    // reviewed against is the pool, so any `std::sync` mutex over an
    // `UnsafeCell` of the pool's inner state is it.
    let mutex = member_of(reader, arc_inner, DATA)?;
    let st = struct_of(reader, mutex)?;
    if !(st
        .namespace
        .is_some_and(|ns| ns_path(reader, ns).starts_with("std::sync"))
        && st
            .name
            .is_some_and(|name| reader.strings.get(name).starts_with("Mutex<")))
    {
        return None;
    }
    let cell = member_of(reader, mutex, DATA)?;
    declared_in(reader, cell, "core::cell", "UnsafeCell<")?;
    let inner = member_of(reader, cell, VALUE)?;
    declared_in(reader, inner, POOL_MODULE, "PoolInner<")?;
    let idle = member_of(reader, inner, IDLE)?;
    let table = hash_table(reader, idle)?;
    if table.kind != HashTableKind::StdMap {
        return None;
    }
    let (key_ptr, key_len) = authority_text(reader, table.key)?;
    let list = declared_in(reader, table.value, "alloc::vec", "Vec<")?;
    let entry = list
        .template_params
        .iter()
        .find(|param| param.name.map(|n| reader.strings.get(n)) == Some("T"))
        .map(|param| reader.canonicalize(param.type_id))?;
    declared_in(reader, entry, POOL_MODULE, "Idle<")?;
    let mut entries_ptr = table.value;
    for member in VEC_PTR {
        entries_ptr = member_of(reader, entries_ptr, member)?;
    }
    let entries_len = member_of(reader, table.value, LEN)?;
    if !(is_byte_pointer(reader, entries_ptr) && super::is_unsigned_integer(reader, entries_len, 8))
    {
        return None;
    }
    let want = pool_client_want(reader, member_of(reader, entry, VALUE)?)?;
    Some(PoolReaperLayout {
        strong,
        idle,
        bucket: table.bucket,
        key_ptr,
        key_len,
        entries_ptr,
        entries_len,
        entry,
        want,
    })
}

/// Screen `id` as a connection checked out of hyper-util's pool,
/// `Pooled<T, K>`: its `value` an `Option` of the `PoolClient`, its
/// `key` the `(Scheme, Authority)`.
pub(crate) fn hyper_util_pool_checkout(
    reader: &DwReader<'_>,
    id: TypeId,
) -> Option<PoolCheckoutLayout> {
    use hyper_pool::*;
    declared_in(reader, id, POOL_MODULE, "Pooled<")?;
    let value = member_of(reader, id, VALUE)?;
    let client = member_of(reader, variant_payload(reader, value, SOME)?, PAYLOAD)?;
    let want = pool_client_want(reader, client)?;
    let (key_ptr, key_len) = authority_text(reader, member_of(reader, id, KEY)?)?;
    Some(PoolCheckoutLayout {
        key_ptr,
        key_len,
        want,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_types::{
        NsId, RawArray, RawBase, RawGenericParameter, RawMember, RawPointer, RawStruct, RawType,
    };
    use crate::{Encoding, TypeId};

    use gimli::UnitSectionOffset;

    fn type_id(offset: usize) -> TypeId {
        TypeId(UnitSectionOffset(offset))
    }

    #[derive(Default)]
    struct Fx {
        reader: DwReader<'static>,
    }

    impl Fx {
        fn ns(&mut self, path: &'static str) -> NsId {
            let mut ns = None;
            for seg in path.split("::") {
                let name = self.reader.strings.intern(seg);
                ns = Some(self.reader.namespaces.insert(ns, name));
            }
            ns.unwrap()
        }

        fn strukt(
            &mut self,
            id: TypeId,
            namespace: Option<NsId>,
            name: &'static str,
            members: &[(&'static str, TypeId, u64)],
            params: &[(&'static str, TypeId)],
        ) {
            let members = members
                .iter()
                .map(|&(name, type_id, offset)| RawMember {
                    name: Some(self.reader.strings.intern(name)),
                    offset,
                    type_id,
                    source_loc: None,
                })
                .collect();
            let template_params = params
                .iter()
                .map(|&(name, type_id)| RawGenericParameter {
                    name: Some(self.reader.strings.intern(name)),
                    type_id,
                })
                .collect();
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Struct(RawStruct {
                    name,
                    namespace,
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        }

        fn pointer(&mut self, id: TypeId, name: Option<&'static str>, target: TypeId) {
            let name = name.map(|name| self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Pointer(RawPointer {
                    name,
                    target_type_id: target,
                }),
            );
        }

        /// A two-variant Rust enum: each `(name, payload)` becomes a
        /// variant whose member names the payload struct.
        fn enumm(
            &mut self,
            id: TypeId,
            namespace: Option<NsId>,
            name: &'static str,
            variants: &[(&'static str, TypeId)],
        ) {
            let variants = variants
                .iter()
                .map(|&(name, payload)| {
                    (
                        None,
                        RawVariant {
                            member: RawMember {
                                name: Some(self.reader.strings.intern(name)),
                                offset: 0,
                                type_id: payload,
                                source_loc: None,
                            },
                        },
                    )
                })
                .collect::<Vec<_>>();
            let name = Some(self.reader.strings.intern(name));
            self.reader.types.insert(
                id,
                RawType::Enum(crate::raw_types::RawEnum {
                    name,
                    namespace,
                    size: 16,
                    alignment: None,
                    shape: VariantShape::Many {
                        discr: None,
                        variants: variants.into_boxed_slice(),
                    },
                    template_params: Box::default(),
                    source_loc: None,
                }),
            );
        }

        fn base(&mut self, id: TypeId, name: &'static str, encoding: Encoding, size: u64) {
            self.reader.types.insert(
                id,
                RawType::Base(RawBase {
                    name: Some(self.reader.strings.intern(name)),
                    namespace: None,
                    encoding,
                    size,
                    alignment: None,
                }),
            );
        }

        fn vtable(&mut self, id: TypeId, words: u64) {
            let usize_t = type_id(0x900);
            let slots = type_id(0x901);
            self.base(usize_t, "usize", Encoding::Unsigned, 8);
            self.reader.types.insert(
                slots,
                RawType::Array(RawArray {
                    elem_type_id: usize_t,
                    count: words,
                }),
            );
            self.pointer(id, None, slots);
        }
    }

    const FUT: TypeId = TypeId(UnitSectionOffset(0x10));
    const DYN: TypeId = TypeId(UnitSectionOffset(0x11));
    const DATA: TypeId = TypeId(UnitSectionOffset(0x12));
    const VTABLE: TypeId = TypeId(UnitSectionOffset(0x13));
    const BOX: TypeId = TypeId(UnitSectionOffset(0x20));
    const REF: TypeId = TypeId(UnitSectionOffset(0x21));
    const BOX_DYN: TypeId = TypeId(UnitSectionOffset(0x22));
    const REF_DYN: TypeId = TypeId(UnitSectionOffset(0x23));
    const PIN: TypeId = TypeId(UnitSectionOffset(0x30));

    /// `app::Fut`, its `dyn Future` spelling, and thin/wide pointers of
    /// both adapter kinds over each.
    fn fixture() -> Fx {
        let mut fx = Fx::default();
        let app = fx.ns("app");
        fx.strukt(FUT, Some(app), "Fut", &[], &[]);
        fx.strukt(
            DYN,
            None,
            "(dyn core::future::future::Future<Output=()> + core::marker::Send)",
            &[],
            &[],
        );
        fx.pointer(DATA, None, DYN);
        fx.vtable(VTABLE, 4);
        fx.pointer(
            BOX,
            Some("alloc::boxed::Box<app::Fut, alloc::alloc::Global>"),
            FUT,
        );
        fx.pointer(REF, Some("&mut app::Fut"), FUT);
        fx.strukt(
            BOX_DYN,
            None,
            "alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global>",
            &[("pointer", DATA, 0), ("vtable", VTABLE, 8)],
            &[],
        );
        fx.strukt(
            REF_DYN,
            None,
            "&mut (dyn core::future::future::Future<Output=()> + core::marker::Send)",
            &[("pointer", DATA, 0), ("vtable", VTABLE, 8)],
            &[],
        );
        fx
    }

    fn pin_over(fx: &mut Fx, ptr: TypeId) {
        let pin = fx.ns("core::pin");
        fx.strukt(
            PIN,
            Some(pin),
            "Pin<P>",
            &[("pointer", ptr, 0)],
            &[("Ptr", ptr)],
        );
    }

    fn wide_over(wide: TypeId) -> Pointee {
        Pointee::Dyn(WidePointer {
            wide,
            pointer: "pointer".into(),
            vtable: "vtable".into(),
            data_ptr: DATA,
            vtable_ptr: VTABLE,
            trait_ty: DYN,
            future_trait: true,
        })
    }

    /// The stream routes: `Next` holds a `&mut St` to the `St` it
    /// declares and nothing else; `WatchStream` holds tokio-util's box
    /// by that type's own declaration; `ReusableBoxFuture` holds a
    /// pinned box over a trait object. Each declines a by-value stream,
    /// another module's type in the member, or a sized box.
    #[test]
    fn test_the_stream_wrappers_hold_what_their_reviews_say() {
        const ST: TypeId = TypeId(UnitSectionOffset(0x80));
        const REF_ST: TypeId = TypeId(UnitSectionOffset(0x81));
        const NEXT: TypeId = TypeId(UnitSectionOffset(0x82));
        const WATCH: TypeId = TypeId(UnitSectionOffset(0x83));
        const REUSABLE: TypeId = TypeId(UnitSectionOffset(0x84));
        const OTHER: TypeId = TypeId(UnitSectionOffset(0x85));
        let build = |fx: &mut Fx, stream_member: TypeId, boxed_member: TypeId, inner: TypeId| {
            let app = fx.ns("app");
            let next_mod = fx.ns("futures_util::stream::stream::next");
            let watch_mod = fx.ns("tokio_stream::wrappers::watch");
            let reusable_mod = fx.ns("tokio_util::sync::reusable_box");
            fx.strukt(ST, Some(app), "St", &[], &[]);
            fx.pointer(REF_ST, Some("&mut app::St"), ST);
            fx.strukt(
                NEXT,
                Some(next_mod),
                "Next<app::St>",
                &[("stream", stream_member, 0)],
                &[("St", ST)],
            );
            fx.strukt(
                REUSABLE,
                Some(reusable_mod),
                "ReusableBoxFuture<()>",
                &[("boxed", boxed_member, 0)],
                &[("T", FUT)],
            );
            fx.strukt(
                WATCH,
                Some(watch_mod),
                "WatchStream<u32>",
                &[("inner", inner, 0)],
                &[("T", FUT)],
            );
            fx.strukt(OTHER, Some(app), "ReusableBoxFuture<()>", &[], &[]);
        };
        let mut fx = fixture();
        pin_over(&mut fx, BOX_DYN);
        build(&mut fx, REF_ST, PIN, REUSABLE);
        assert_eq!(
            futures_util_next(&fx.reader, NEXT),
            Some(NextLayout {
                stream: "stream".into(),
                target: ST,
            })
        );
        assert_eq!(
            tokio_stream_watch_stream(&fx.reader, WATCH),
            Some(ForwardLayout {
                member: "inner".into(),
                inner: REUSABLE,
            })
        );
        assert_eq!(
            tokio_util_reusable_box(&fx.reader, REUSABLE),
            Some(ReusableBoxLayout {
                boxed: "boxed".into(),
                pin: ("pointer".into(), BOX_DYN),
                wide: match wide_over(BOX_DYN) {
                    Pointee::Dyn(wide) => wide,
                    Pointee::Sized(_) => unreachable!(),
                },
            })
        );
        // Each screen reads only its own type: the others' ids are
        // not it.
        assert_eq!(futures_util_next(&fx.reader, WATCH), None);
        assert_eq!(tokio_stream_watch_stream(&fx.reader, REUSABLE), None);
        assert_eq!(tokio_util_reusable_box(&fx.reader, WATCH), None);
        // A `Next` holding its stream by value, a `WatchStream` whose
        // `inner` is another crate's `ReusableBoxFuture`, a box over a
        // sized future.
        let mut fx = fixture();
        pin_over(&mut fx, BOX_DYN);
        build(&mut fx, ST, PIN, OTHER);
        assert_eq!(futures_util_next(&fx.reader, NEXT), None);
        assert_eq!(tokio_stream_watch_stream(&fx.reader, WATCH), None);
        let mut fx = fixture();
        pin_over(&mut fx, BOX);
        build(&mut fx, REF_ST, PIN, REUSABLE);
        assert_eq!(tokio_util_reusable_box(&fx.reader, REUSABLE), None);
        // A `WatchStream` over such a box still screens: what its box
        // holds is the box's own screen to refuse.
        assert!(tokio_stream_watch_stream(&fx.reader, WATCH).is_some());
        let mut fx = fixture();
        pin_over(&mut fx, BOX_DYN);
        build(&mut fx, REF_ST, BOX_DYN, REUSABLE);
        assert_eq!(tokio_util_reusable_box(&fx.reader, REUSABLE), None);
        // The reference must target the `St` the instantiation
        // declares, and the parameter must be that `St`: one without
        // the other is another layout.
        const REF_FUT: TypeId = TypeId(UnitSectionOffset(0x86));
        for (member, param) in [(REF_FUT, ("St", ST)), (REF_ST, ("F", ST))] {
            let mut fx = fixture();
            let app = fx.ns("app");
            let next_mod = fx.ns("futures_util::stream::stream::next");
            fx.strukt(ST, Some(app), "St", &[], &[]);
            fx.pointer(REF_ST, Some("&mut app::St"), ST);
            fx.pointer(REF_FUT, Some("&mut app::Fut"), FUT);
            fx.strukt(
                NEXT,
                Some(next_mod),
                "Next<app::St>",
                &[("stream", member, 0)],
                &[param],
            );
            assert_eq!(futures_util_next(&fx.reader, NEXT), None, "{param:?}");
        }
    }

    #[test]
    fn test_thin_adapters_are_named_for_their_exact_target() {
        let fx = fixture();
        assert_eq!(
            std_adapter(&fx.reader, BOX),
            Some(StdAdapter::Box(Pointee::Sized(FUT)))
        );
        assert_eq!(
            std_adapter(&fx.reader, REF),
            Some(StdAdapter::MutRef(Pointee::Sized(FUT)))
        );
        // A raw pointer, a shared reference, a box over another type or
        // a non-default allocator, and a nameless pointer are not adapters.
        for name in [
            Some("*mut app::Fut"),
            Some("&app::Fut"),
            Some("&mut app::Other"),
            Some("alloc::boxed::Box<app::Other, alloc::alloc::Global>"),
            Some("alloc::boxed::Box<app::Fut, app::Arena>"),
            Some("alloc::boxed::Box<app::Fut>"),
            None,
        ] {
            let mut fx = fixture();
            fx.pointer(REF, name, FUT);
            assert_eq!(std_adapter(&fx.reader, REF), None, "{name:?}");
        }
    }

    /// Every definition of a pointer has to say the same thing: two
    /// definitions naming different targets are no adapter, and neither
    /// is a definition with no name or one the screen refuses.
    #[test]
    fn test_pointer_definitions_must_agree_on_the_target() {
        let mut fx = Fx::default();
        let name = fx.reader.strings.intern("&mut app::Fut");
        let def = |target: TypeId| {
            Some(RawPointer {
                name: Some(name),
                target_type_id: target,
            })
        };
        let accept = |_: StrId, _: TypeId| true;
        let disagree = Err(PointerDecline::Disagree { targets: 2 });
        assert_eq!(
            agreed_target([def(FUT), def(FUT)].into_iter(), accept),
            Ok(FUT)
        );
        assert_eq!(
            agreed_target([def(FUT), def(DYN)].into_iter(), accept),
            disagree
        );
        assert_eq!(
            agreed_target([def(DYN), def(FUT)].into_iter(), accept),
            disagree
        );
        assert_eq!(
            agreed_target([def(FUT), def(DYN), def(FUT), def(BOX)].into_iter(), accept),
            Err(PointerDecline::Disagree { targets: 3 })
        );
        let not_the_shape = Err(PointerDecline::NotTheShape);
        assert_eq!(
            agreed_target([def(FUT), None].into_iter(), accept),
            not_the_shape
        );
        assert_eq!(
            agreed_target(
                [Some(RawPointer {
                    name: None,
                    target_type_id: FUT,
                })]
                .into_iter(),
                accept
            ),
            not_the_shape
        );
        assert_eq!(
            agreed_target([def(FUT)].into_iter(), |_, target| target != FUT),
            not_the_shape
        );
        assert_eq!(agreed_target(std::iter::empty(), accept), not_the_shape);
    }

    #[test]
    fn test_wide_adapters_need_a_bare_trait_object_and_a_method_slot() {
        let fx = fixture();
        assert_eq!(
            std_adapter(&fx.reader, BOX_DYN),
            Some(StdAdapter::Box(wide_over(BOX_DYN)))
        );
        assert_eq!(
            std_adapter(&fx.reader, REF_DYN),
            Some(StdAdapter::MutRef(wide_over(REF_DYN)))
        );
        // Three vtable words leave no method slot at all.
        let mut fx = fixture();
        fx.vtable(VTABLE, 3);
        assert_eq!(std_adapter(&fx.reader, BOX_DYN), None);
        // A box named for a pointee it does not target.
        let mut fx = fixture();
        fx.strukt(
            DYN,
            None,
            "(dyn core::ops::function::FnOnce<()> -> Box<dyn core::future::future::Future<Output=()>>)",
            &[],
            &[],
        );
        assert_eq!(std_adapter(&fx.reader, BOX_DYN), None);
        // A wide pointer named for a different pointee than it targets.
        let mut fx = fixture();
        fx.strukt(
            REF_DYN,
            None,
            "&mut (dyn core::future::future::Future<Output=u8>)",
            &[("pointer", DATA, 0), ("vtable", VTABLE, 8)],
            &[],
        );
        assert_eq!(std_adapter(&fx.reader, REF_DYN), None);
    }

    #[test]
    fn test_pin_routes_through_its_declared_pointer_only() {
        for (ptr, expected) in [
            (
                BOX,
                StdAdapter::PinBox {
                    member: "pointer".into(),
                    boxed: BOX,
                    pointee: Pointee::Sized(FUT),
                },
            ),
            (
                REF,
                StdAdapter::PinMutRef {
                    member: "pointer".into(),
                    reference: REF,
                    pointee: Pointee::Sized(FUT),
                },
            ),
        ] {
            let mut fx = fixture();
            pin_over(&mut fx, ptr);
            assert_eq!(std_adapter(&fx.reader, PIN), Some(expected));
        }
        let mut fx = fixture();
        pin_over(&mut fx, BOX_DYN);
        assert!(matches!(
            std_adapter(&fx.reader, PIN),
            Some(StdAdapter::PinBox {
                pointee: Pointee::Dyn(_),
                ..
            })
        ));
        // A `Pin` over a user pointer type with one pointer-sized member
        // is not a supported route, and neither is a `Pin` whose member
        // is not its parameter, whose parameter is not `Ptr`, or that
        // lives outside `core::pin`.
        let mut fx = fixture();
        let app = fx.ns("app");
        fx.strukt(
            type_id(0x40),
            Some(app),
            "MyPtr<F>",
            &[("p", REF, 0)],
            &[("F", FUT)],
        );
        pin_over(&mut fx, type_id(0x40));
        assert_eq!(std_adapter(&fx.reader, PIN), None);
        let mut fx = fixture();
        let pin = fx.ns("core::pin");
        fx.strukt(
            PIN,
            Some(pin),
            "Pin<P>",
            &[("pointer", REF, 0)],
            &[("Ptr", BOX)],
        );
        assert_eq!(std_adapter(&fx.reader, PIN), None);
        let mut fx = fixture();
        let pin = fx.ns("core::pin");
        fx.strukt(
            PIN,
            Some(pin),
            "Pin<P>",
            &[("pointer", REF, 0)],
            &[("P", REF)],
        );
        assert_eq!(std_adapter(&fx.reader, PIN), None);
        let mut fx = fixture();
        let app = fx.ns("app");
        fx.strukt(
            PIN,
            Some(app),
            "Pin<P>",
            &[("pointer", REF, 0)],
            &[("Ptr", REF)],
        );
        assert_eq!(std_adapter(&fx.reader, PIN), None);
    }

    #[test]
    fn test_instrumented_is_its_two_declared_members() {
        let mut fx = fixture();
        let tracing = fx.ns("tracing::instrument");
        let md = type_id(0x50);
        let span = type_id(0x51);
        fx.strukt(
            md,
            None,
            "ManuallyDrop<app::Fut>",
            &[("value", FUT, 0)],
            &[],
        );
        fx.strukt(span, None, "Span", &[], &[]);
        let inst = type_id(0x52);
        fx.strukt(
            inst,
            Some(tracing),
            "Instrumented<app::Fut>",
            &[("span", span, 0), ("inner", md, 40)],
            &[("T", FUT)],
        );
        assert_eq!(
            instrumented(&fx.reader, inst),
            Some(InstrumentedLayout {
                inner: "inner".into(),
                future: FUT,
            })
        );
        // A same-named struct elsewhere, or one with another member set,
        // is not the reviewed one.
        let app = fx.ns("app");
        fx.strukt(
            inst,
            Some(app),
            "Instrumented<app::Fut>",
            &[("span", span, 0), ("inner", md, 40)],
            &[("T", FUT)],
        );
        assert_eq!(instrumented(&fx.reader, inst), None);
        fx.strukt(
            inst,
            Some(tracing),
            "Instrumented<app::Fut>",
            &[("span", span, 0), ("inner", md, 40), ("extra", FUT, 72)],
            &[("T", FUT)],
        );
        assert_eq!(instrumented(&fx.reader, inst), None);
    }
    /// futures-util's `map` combinator: the enum the poll runs, and the
    /// `delegate_all!` newtype over it. Both are screened by their own
    /// definition module and layout, and the enum's declared arguments
    /// have to be the types its members actually hold — rustc attaches
    /// no template parameters to an enum, so the name is where they are.
    fn map_fixture() -> (Fx, TypeId, TypeId) {
        const INCOMPLETE: TypeId = TypeId(UnitSectionOffset(0x60));
        const COMPLETE: TypeId = TypeId(UnitSectionOffset(0x61));
        const ENUM: TypeId = TypeId(UnitSectionOffset(0x62));
        const WRAPPER: TypeId = TypeId(UnitSectionOffset(0x63));
        let mut fx = fixture();
        let app = fx.ns("app");
        fx.strukt(type_id(0x64), Some(app), "Fn", &[], &[]);
        let map_mod = fx.ns("futures_util::future::future::map");
        let future_mod = fx.ns("futures_util::future::future");
        fx.strukt(
            INCOMPLETE,
            Some(map_mod),
            "Map<app::Fut, app::Fn>::Incomplete",
            &[("future", FUT, 8), ("f", type_id(0x64), 8)],
            &[],
        );
        fx.strukt(
            COMPLETE,
            Some(map_mod),
            "Map<app::Fut, app::Fn>::Complete",
            &[],
            &[],
        );
        fx.enumm(
            ENUM,
            Some(map_mod),
            "Map<app::Fut, app::Fn>",
            &[("Incomplete", INCOMPLETE), ("Complete", COMPLETE)],
        );
        fx.strukt(
            WRAPPER,
            Some(future_mod),
            "Map<app::Fut, app::Fn>",
            &[("inner", ENUM, 0)],
            &[],
        );
        (fx, ENUM, WRAPPER)
    }

    #[test]
    fn test_the_map_combinator_is_screened_by_its_states_and_its_newtype() {
        let (fx, map, wrapper) = map_fixture();
        assert_eq!(
            futures_util_map(&fx.reader, map),
            Some(MapLayout {
                incomplete: "Incomplete".into(),
                future_member: "future".into(),
                complete: "Complete".into(),
                future: FUT,
            })
        );
        assert_eq!(
            futures_util_map_wrapper(&fx.reader, wrapper),
            Some(ForwardLayout {
                member: "inner".into(),
                inner: map,
            })
        );
        // The states are the review: another module, a variant renamed,
        // a payload holding a type the name does not declare, a
        // completed state with storage, or a third state is not it.
        let map_mod = {
            let mut fx = fx;
            fx.ns("futures_util::future::future::map")
        };
        for departure in ["Renamed", "Complete"] {
            let (mut fx, ..) = map_fixture();
            fx.enumm(
                map,
                Some(map_mod),
                "Map<app::Fut, app::Fn>",
                &[(departure, type_id(0x60)), ("Complete", type_id(0x61))],
            );
            assert_eq!(futures_util_map(&fx.reader, map), None, "{departure}");
        }
        let (mut fx, ..) = map_fixture();
        fx.strukt(
            type_id(0x60),
            Some(map_mod),
            "Map<app::Fut, app::Fn>::Incomplete",
            &[("future", DYN, 8), ("f", type_id(0x64), 8)],
            &[],
        );
        assert_eq!(futures_util_map(&fx.reader, map), None);
        let (mut fx, ..) = map_fixture();
        fx.strukt(
            type_id(0x61),
            Some(map_mod),
            "Map<app::Fut, app::Fn>::Complete",
            &[("held", FUT, 0)],
            &[],
        );
        assert_eq!(futures_util_map(&fx.reader, map), None);
        // The newtype is only the newtype while it holds that enum in
        // its one member, at the same instantiation.
        let (mut fx, ..) = map_fixture();
        fx.strukt(
            wrapper,
            Some(map_mod),
            "Map<app::Fut, app::Fn>",
            &[("inner", map, 0)],
            &[],
        );
        assert_eq!(futures_util_map_wrapper(&fx.reader, wrapper), None);
        let (mut fx, ..) = map_fixture();
        let future_mod = fx.ns("futures_util::future::future");
        fx.strukt(
            wrapper,
            Some(future_mod),
            "Map<app::Other, app::Fn>",
            &[("inner", map, 0)],
            &[],
        );
        assert_eq!(futures_util_map_wrapper(&fx.reader, wrapper), None);
        let (mut fx, ..) = map_fixture();
        fx.strukt(
            wrapper,
            Some(future_mod),
            "Map<app::Fut, app::Fn>",
            &[("inner", map, 0), ("extra", FUT, 8)],
            &[],
        );
        assert_eq!(futures_util_map_wrapper(&fx.reader, wrapper), None);
    }

    /// The remaining one-member forwards: `MapErr` over a public `Map`,
    /// `IntoFuture` over the `Fut` it declares, and hyper-util's sleep
    /// newtype over tokio's own `Sleep`. Each holds exactly that, in
    /// exactly the member its implementation forwards through.
    #[test]
    fn test_the_forwarding_wrappers_hold_what_their_reviews_say() {
        const MAP_ERR: TypeId = TypeId(UnitSectionOffset(0x70));
        const INTO: TypeId = TypeId(UnitSectionOffset(0x71));
        const SLEEP: TypeId = TypeId(UnitSectionOffset(0x72));
        const TOKIO_SLEEP: TypeId = TypeId(UnitSectionOffset(0x73));
        const COOP: TypeId = TypeId(UnitSectionOffset(0x74));
        let (mut fx, _, wrapper) = map_fixture();
        let try_future = fx.ns("futures_util::future::try_future");
        let into_mod = fx.ns("futures_util::future::try_future::into_future");
        let rt = fx.ns("hyper_util::rt::tokio");
        let sleep_mod = fx.ns("tokio::time::sleep");
        let coop_mod = fx.ns("tokio::task::coop");
        fx.strukt(
            MAP_ERR,
            Some(try_future),
            "MapErr<app::Fut, app::Fn>",
            &[("inner", wrapper, 0)],
            &[],
        );
        fx.strukt(
            INTO,
            Some(into_mod),
            "IntoFuture<app::Fut>",
            &[("future", FUT, 0)],
            &[("Fut", FUT)],
        );
        fx.strukt(SLEEP, Some(sleep_mod), "Sleep", &[], &[]);
        fx.strukt(
            TOKIO_SLEEP,
            Some(rt),
            "TokioSleep",
            &[("inner", SLEEP, 0)],
            &[],
        );
        let forward = |member: &str, inner| {
            Some(ForwardLayout {
                member: member.to_owned(),
                inner,
            })
        };
        assert_eq!(
            futures_util_map_err(&fx.reader, MAP_ERR),
            forward("inner", wrapper)
        );
        assert_eq!(
            futures_util_into_future(&fx.reader, INTO),
            forward("future", FUT)
        );
        assert_eq!(
            hyper_util_tokio_sleep(&fx.reader, TOKIO_SLEEP),
            forward("inner", SLEEP)
        );
        fx.strukt(
            COOP,
            Some(coop_mod),
            "Coop<app::Fut>",
            &[("fut", FUT, 0)],
            &[("F", FUT)],
        );
        assert_eq!(tokio_coop(&fx.reader, COOP), forward("fut", FUT));
        // What each holds is the check: a `MapErr` over anything but the
        // public `Map`, an `IntoFuture` over something other than the
        // `Fut` it declares, a sleep newtype over anything but tokio's
        // own, and a `Coop` whose member is not the `F` it declares are
        // layouts no review covers.
        fx.strukt(
            COOP,
            Some(coop_mod),
            "Coop<app::Fut>",
            &[("fut", SLEEP, 0)],
            &[("F", FUT)],
        );
        assert_eq!(tokio_coop(&fx.reader, COOP), None);
        fx.strukt(
            COOP,
            Some(coop_mod),
            "Coop<app::Fut>",
            &[("fut", FUT, 0), ("budget", SLEEP, 8)],
            &[("F", FUT)],
        );
        assert_eq!(tokio_coop(&fx.reader, COOP), None);
        fx.strukt(
            MAP_ERR,
            Some(try_future),
            "MapErr<app::Fut, app::Fn>",
            &[("inner", FUT, 0)],
            &[],
        );
        assert_eq!(futures_util_map_err(&fx.reader, MAP_ERR), None);
        fx.strukt(
            INTO,
            Some(into_mod),
            "IntoFuture<app::Fut>",
            &[("future", SLEEP, 0)],
            &[("Fut", FUT)],
        );
        assert_eq!(futures_util_into_future(&fx.reader, INTO), None);
        fx.strukt(
            TOKIO_SLEEP,
            Some(rt),
            "TokioSleep",
            &[("inner", FUT, 0)],
            &[],
        );
        assert_eq!(hyper_util_tokio_sleep(&fx.reader, TOKIO_SLEEP), None);
        // And where it lives: the same names under another module are
        // another crate's types.
        let app = fx.ns("app");
        fx.strukt(
            TOKIO_SLEEP,
            Some(app),
            "TokioSleep",
            &[("inner", SLEEP, 0)],
            &[],
        );
        assert_eq!(hyper_util_tokio_sleep(&fx.reader, TOKIO_SLEEP), None);
        fx.strukt(
            COOP,
            Some(app),
            "Coop<app::Fut>",
            &[("fut", FUT, 0)],
            &[("F", FUT)],
        );
        assert_eq!(tokio_coop(&fx.reader, COOP), None);
    }

    /// core's `Pending<T>` is exactly its reviewed layout: declared in
    /// `core::future::pending`, zero-sized, one member `_data` that is
    /// a `PhantomData`. A size, a second member, another member type
    /// or another module is a layout the reviewed poll was not read
    /// against, whatever the name says.
    #[test]
    fn test_pending_is_a_zero_sized_phantom_data_in_its_own_module() {
        const PENDING: TypeId = TypeId(UnitSectionOffset(0x80));
        const PHANTOM: TypeId = TypeId(UnitSectionOffset(0x81));
        let mut fx = fixture();
        let pending_mod = fx.ns("core::future::pending");
        let marker = fx.ns("core::marker");
        let app = fx.ns("app");
        let resize = |fx: &mut Fx, id: TypeId, size: u64| {
            let Some(RawType::Struct(st)) = fx.reader.types.get_mut(&id) else {
                panic!("a struct");
            };
            st.size = size;
        };
        fx.strukt(PHANTOM, Some(marker), "PhantomData<fn()>", &[], &[]);
        resize(&mut fx, PHANTOM, 0);
        let pending = |fx: &mut Fx, ns, members: &[(&'static str, TypeId, u64)], size| {
            fx.strukt(PENDING, Some(ns), "Pending<()>", members, &[]);
            resize(fx, PENDING, size);
        };
        pending(&mut fx, pending_mod, &[("_data", PHANTOM, 0)], 0);
        assert!(core_pending(&fx.reader, PENDING));
        // A size: something in it the review did not see.
        pending(&mut fx, pending_mod, &[("_data", PHANTOM, 0)], 8);
        assert!(!core_pending(&fx.reader, PENDING));
        // A second member, zero-sized or not.
        pending(
            &mut fx,
            pending_mod,
            &[("_data", PHANTOM, 0), ("extra", PHANTOM, 0)],
            0,
        );
        assert!(!core_pending(&fx.reader, PENDING));
        // The one member is not a `PhantomData`.
        pending(&mut fx, pending_mod, &[("_data", FUT, 0)], 0);
        assert!(!core_pending(&fx.reader, PENDING));
        // Another member name.
        pending(&mut fx, pending_mod, &[("data", PHANTOM, 0)], 0);
        assert!(!core_pending(&fx.reader, PENDING));
        // The right shape declared somewhere else.
        pending(&mut fx, app, &[("_data", PHANTOM, 0)], 0);
        assert!(!core_pending(&fx.reader, PENDING));
    }

    /// A wide pointer to a trait object of some other trait is still an
    /// adapter's pointee — its concrete value implements `Future` or the
    /// adapter would not be one — but it claims no reviewed poll slot.
    #[test]
    fn test_a_wide_pointer_records_whether_its_object_is_a_future() {
        let mut fx = fixture();
        assert_eq!(
            std_adapter(&fx.reader, BOX_DYN),
            Some(StdAdapter::Box(wide_over(BOX_DYN)))
        );
        fx.strukt(DYN, None, "dyn app::Parked<Output=u32>", &[], &[]);
        fx.strukt(
            BOX_DYN,
            None,
            "alloc::boxed::Box<dyn app::Parked<Output=u32>, alloc::alloc::Global>",
            &[("pointer", DATA, 0), ("vtable", VTABLE, 8)],
            &[],
        );
        let Some(StdAdapter::Box(Pointee::Dyn(wide))) = std_adapter(&fx.reader, BOX_DYN) else {
            panic!("a box over a trait object is still an owned adapter");
        };
        assert!(!wide.future_trait);
        assert_eq!(wide.trait_ty, DYN);
    }
    /// A `select!`'s `PollFn`: std's `PollFn<F>` with `F` a closure
    /// environment whose two captures point at an unsigned word and a
    /// tuple of `__i` members. Each departure — another `PollFn`, a
    /// third capture, a signed or nine-byte word, a tuple with a gap in
    /// its member names, more members than the word has bits, a
    /// capture that is not a `&mut` — is not the reviewed layout.
    #[test]
    fn test_the_select_poll_fn_is_screened_by_its_closures_captures() {
        const POLL_FN: TypeId = TypeId(UnitSectionOffset(0x80));
        const ENV: TypeId = TypeId(UnitSectionOffset(0x81));
        const U8: TypeId = TypeId(UnitSectionOffset(0x82));
        const MASK_REF: TypeId = TypeId(UnitSectionOffset(0x83));
        const TUPLE: TypeId = TypeId(UnitSectionOffset(0x84));
        const TUPLE_REF: TypeId = TypeId(UnitSectionOffset(0x85));
        const I8: TypeId = TypeId(UnitSectionOffset(0x86));
        const U128: TypeId = TypeId(UnitSectionOffset(0x87));
        fn select_fixture() -> Fx {
            let mut fx = fixture();
            let poll_fn = fx.ns("core::future::poll_fn");
            let user = fx.ns("app::run::{async_fn#0}");
            fx.base(U8, "u8", Encoding::Unsigned, 1);
            fx.pointer(MASK_REF, Some("&mut u8"), U8);
            fx.strukt(
                TUPLE,
                None,
                "(app::Fut, &mut app::Fut)",
                &[("__0", FUT, 0), ("__1", REF, 8)],
                &[],
            );
            fx.pointer(TUPLE_REF, Some("&mut (app::Fut, &mut app::Fut)"), TUPLE);
            fx.strukt(
                ENV,
                Some(user),
                "{closure_env#1}",
                &[
                    ("_ref__disabled", MASK_REF, 0),
                    ("_ref__futures", TUPLE_REF, 8),
                ],
                &[],
            );
            fx.strukt(
                POLL_FN,
                Some(poll_fn),
                "PollFn<app::run::{async_fn#0}::{closure_env#1}>",
                &[("f", ENV, 0)],
                &[("F", ENV)],
            );
            fx
        }
        let fx = select_fixture();
        assert_eq!(
            tokio_select(&fx.reader, POLL_FN),
            Some(SelectLayout {
                closure: "f".into(),
                env: ENV,
                mask: "_ref__disabled".into(),
                mask_word: U8,
                futures: "_ref__futures".into(),
                tuple: TUPLE,
                branches: vec![("__0".into(), FUT), ("__1".into(), REF)],
            })
        );
        // Another module's `PollFn`, or the closure held in another
        // member, is not std's over a closure.
        let mut fx = select_fixture();
        let app = fx.ns("app");
        fx.strukt(
            POLL_FN,
            Some(app),
            "PollFn<app::run::{async_fn#0}::{closure_env#1}>",
            &[("f", ENV, 0)],
            &[("F", ENV)],
        );
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        let mut fx = select_fixture();
        let poll_fn = fx.ns("core::future::poll_fn");
        fx.strukt(
            POLL_FN,
            Some(poll_fn),
            "PollFn<app::run::{async_fn#0}::{closure_env#1}>",
            &[("closure", ENV, 0)],
            &[("F", ENV)],
        );
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        // The closure has to be one, with exactly the two captures.
        let mut fx = select_fixture();
        let user = fx.ns("app::run::{async_fn#0}");
        fx.strukt(
            ENV,
            Some(user),
            "Recv<u32>",
            &[
                ("_ref__disabled", MASK_REF, 0),
                ("_ref__futures", TUPLE_REF, 8),
            ],
            &[],
        );
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        for members in [
            &[("_ref__disabled", MASK_REF, 0)][..],
            &[
                ("_ref__disabled", MASK_REF, 0),
                ("_ref__futures", TUPLE_REF, 8),
                ("_ref__start", MASK_REF, 16),
            ][..],
            &[
                ("_ref__disabled", MASK_REF, 0),
                ("_ref__futs", TUPLE_REF, 8),
            ][..],
            // The captures are references: a mask held by value, a
            // tuple pointed at through a `Box`.
            &[("_ref__disabled", U8, 0), ("_ref__futures", TUPLE_REF, 8)][..],
            &[("_ref__disabled", MASK_REF, 0), ("_ref__futures", BOX, 8)][..],
        ] {
            let mut fx = select_fixture();
            let user = fx.ns("app::run::{async_fn#0}");
            fx.strukt(ENV, Some(user), "{closure_env#1}", members, &[]);
            assert_eq!(tokio_select(&fx.reader, POLL_FN), None, "{members:?}");
        }
        // The mask is an unsigned word of a width tokio-macros emits.
        let mut fx = select_fixture();
        fx.base(I8, "i8", Encoding::Signed, 1);
        fx.pointer(MASK_REF, Some("&mut i8"), I8);
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        let mut fx = select_fixture();
        fx.base(U128, "u128", Encoding::Unsigned, 16);
        fx.pointer(MASK_REF, Some("&mut u128"), U128);
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        // The tuple's members are `__0` onward without a gap, at least
        // one, and no more than the mask has bits.
        for members in [
            &[][..],
            &[("__0", FUT, 0), ("__2", REF, 8)][..],
            &[("__1", FUT, 0), ("__0", REF, 8)][..],
            &[("head", FUT, 0), ("tail", REF, 8)][..],
        ] {
            let mut fx = select_fixture();
            fx.strukt(TUPLE, None, "(app::Fut, &mut app::Fut)", members, &[]);
            assert_eq!(tokio_select(&fx.reader, POLL_FN), None, "{members:?}");
        }
        let mut fx = select_fixture();
        let nine: Vec<(&'static str, TypeId, u64)> = [
            "__0", "__1", "__2", "__3", "__4", "__5", "__6", "__7", "__8",
        ]
        .iter()
        .enumerate()
        .map(|(i, name)| (*name, FUT, i as u64 * 8))
        .collect();
        fx.strukt(TUPLE, None, "(app::Fut, &mut app::Fut)", &nine, &[]);
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        // Exactly eight fill the `u8` mask and are admitted.
        let mut fx = select_fixture();
        fx.strukt(TUPLE, None, "(app::Fut, &mut app::Fut)", &nine[..8], &[]);
        assert_eq!(
            tokio_select(&fx.reader, POLL_FN).map(|l| (l.mask_word, l.branches.len())),
            Some((U8, 8))
        );
        // Nine branches fit a `u16` mask.
        let mut fx = select_fixture();
        fx.base(U128, "u16", Encoding::Unsigned, 2);
        fx.pointer(MASK_REF, Some("&mut u16"), U128);
        fx.strukt(TUPLE, None, "(app::Fut, &mut app::Fut)", &nine, &[]);
        assert_eq!(
            tokio_select(&fx.reader, POLL_FN).map(|l| (l.mask_word, l.branches.len())),
            Some((U128, 9))
        );
        // A tuple that is not one: a struct with `__i` members but a
        // name of its own.
        let mut fx = select_fixture();
        fx.strukt(
            TUPLE,
            None,
            "app::Pair",
            &[("__0", FUT, 0), ("__1", REF, 8)],
            &[],
        );
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
    }

    /// The tick's `PollFn` is screened by where its closure was
    /// declared and by what the one capture reaches: a `&mut Interval`
    /// whose `delay` is a `Pin<Box<Sleep>>` over tokio's own `Sleep`.
    /// Every departure — another module's `PollFn`, a closure declared
    /// elsewhere, a second capture, a capture that is not a reference
    /// to tokio's `Interval`, a `delay` that is not that pinned box —
    /// declines.
    #[test]
    fn test_the_interval_tick_poll_fn_is_screened_by_its_capture_and_the_box() {
        const POLL_FN: TypeId = TypeId(UnitSectionOffset(0x90));
        const ENV: TypeId = TypeId(UnitSectionOffset(0x91));
        const INTERVAL_REF: TypeId = TypeId(UnitSectionOffset(0x92));
        const INTERVAL: TypeId = TypeId(UnitSectionOffset(0x93));
        const PIN: TypeId = TypeId(UnitSectionOffset(0x94));
        const SLEEP_BOX: TypeId = TypeId(UnitSectionOffset(0x95));
        const SLEEP: TypeId = TypeId(UnitSectionOffset(0x96));
        const DURATION: TypeId = TypeId(UnitSectionOffset(0x97));
        const OTHER_PIN: TypeId = TypeId(UnitSectionOffset(0x98));
        fn tick_fixture() -> Fx {
            let mut fx = fixture();
            let poll_fn = fx.ns("core::future::poll_fn");
            let tick = fx.ns("tokio::time::interval::{impl#2}::tick::{async_fn#0}");
            let interval_mod = fx.ns("tokio::time::interval");
            let sleep_mod = fx.ns("tokio::time::sleep");
            let pin_mod = fx.ns("core::pin");
            let time = fx.ns("core::time");
            fx.strukt(SLEEP, Some(sleep_mod), "Sleep", &[], &[]);
            fx.strukt(DURATION, Some(time), "Duration", &[], &[]);
            fx.pointer(
                SLEEP_BOX,
                Some("alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>"),
                SLEEP,
            );
            fx.strukt(
                PIN,
                Some(pin_mod),
                "Pin<alloc::boxed::Box<tokio::time::sleep::Sleep, alloc::alloc::Global>>",
                &[("pointer", SLEEP_BOX, 0)],
                &[("Ptr", SLEEP_BOX)],
            );
            fx.strukt(
                INTERVAL,
                Some(interval_mod),
                "Interval",
                &[("period", DURATION, 0), ("delay", PIN, 16)],
                &[],
            );
            fx.pointer(
                INTERVAL_REF,
                Some("&mut tokio::time::interval::Interval"),
                INTERVAL,
            );
            fx.strukt(
                ENV,
                Some(tick),
                "{closure_env#0}",
                &[("_ref__self", INTERVAL_REF, 0)],
                &[],
            );
            fx.strukt(
                POLL_FN,
                Some(poll_fn),
                "PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>",
                &[("f", ENV, 0)],
                &[("F", ENV)],
            );
            fx
        }
        let fx = tick_fixture();
        assert_eq!(
            tokio_interval_tick(&fx.reader, POLL_FN),
            Some(IntervalTickLayout {
                closure: "f".into(),
                env: ENV,
                interval_ref: "_ref__self".into(),
                interval: INTERVAL,
                delay: "delay".into(),
                boxed: PIN,
            })
        );
        // The select screen and this one are the two readings of a
        // `PollFn`, and neither takes the other's.
        assert_eq!(tokio_select(&fx.reader, POLL_FN), None);
        // Another module's `PollFn`, or the closure held in another
        // member.
        let mut fx = tick_fixture();
        let app = fx.ns("app");
        fx.strukt(
            POLL_FN,
            Some(app),
            "PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>",
            &[("f", ENV, 0)],
            &[("F", ENV)],
        );
        assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None);
        let mut fx = tick_fixture();
        let poll_fn = fx.ns("core::future::poll_fn");
        fx.strukt(
            POLL_FN,
            Some(poll_fn),
            "PollFn<tokio::time::interval::{impl#2}::tick::{async_fn#0}::{closure_env#0}>",
            &[("closure", ENV, 0)],
            &[("F", ENV)],
        );
        assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None);
        // The closure is `tick`'s own: not another method's, not a
        // user's, not a module below tokio's, and one with the one
        // capture — a second capture, a capture by another name, or one
        // held by value is another closure.
        for path in [
            "tokio::time::interval::{impl#2}::poll_tick::{async_fn#0}",
            "tokio::time::interval::{impl#2}::tick",
            "tokio::time::interval::{impl#}::tick::{async_fn#0}",
            "tokio::time::interval::{impl#x}::tick::{async_fn#0}",
            "tokio::time::interval::{impl#2}::tick::{async_fn#1}",
            "tokio::time::interval::tick::{async_fn#0}",
            "tokio_stream::wrappers::interval::{impl#2}::tick::{async_fn#0}",
            "app::run::{async_fn#0}",
        ] {
            let mut fx = tick_fixture();
            let elsewhere = fx.ns(path);
            fx.strukt(
                ENV,
                Some(elsewhere),
                "{closure_env#0}",
                &[("_ref__self", INTERVAL_REF, 0)],
                &[],
            );
            assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None, "{path}");
        }
        for members in [
            &[
                ("_ref__self", INTERVAL_REF, 0),
                ("_ref__cx", INTERVAL_REF, 8),
            ][..],
            &[("_ref__interval", INTERVAL_REF, 0)][..],
            &[("_ref__self", INTERVAL, 0)][..],
            &[][..],
        ] {
            let mut fx = tick_fixture();
            let tick = fx.ns("tokio::time::interval::{impl#2}::tick::{async_fn#0}");
            fx.strukt(ENV, Some(tick), "{closure_env#0}", members, &[]);
            assert_eq!(
                tokio_interval_tick(&fx.reader, POLL_FN),
                None,
                "{members:?}"
            );
        }
        let mut fx = tick_fixture();
        let tick = fx.ns("tokio::time::interval::{impl#2}::tick::{async_fn#0}");
        fx.strukt(
            ENV,
            Some(tick),
            "Tick",
            &[("_ref__self", INTERVAL_REF, 0)],
            &[],
        );
        assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None);
        // The capture reaches tokio's `Interval` and no other struct of
        // that name, or of a longer one.
        for (module, name, reference) in [
            (
                "tokio_stream::wrappers::interval",
                "Interval",
                "&mut tokio_stream::wrappers::interval::Interval",
            ),
            ("app", "Interval", "&mut app::Interval"),
            (
                "tokio::time::interval",
                "IntervalStream",
                "&mut tokio::time::interval::IntervalStream",
            ),
        ] {
            let mut fx = tick_fixture();
            let module = fx.ns(module);
            fx.strukt(
                INTERVAL,
                Some(module),
                name,
                &[("period", DURATION, 0), ("delay", PIN, 16)],
                &[],
            );
            fx.pointer(INTERVAL_REF, Some(reference), INTERVAL);
            assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None, "{name}");
        }
        // `delay` is the pinned box over tokio's `Sleep`: not a bare
        // box, not a pin over another box, not a member by another
        // name, not missing.
        let mut fx = tick_fixture();
        let interval_mod = fx.ns("tokio::time::interval");
        fx.strukt(
            INTERVAL,
            Some(interval_mod),
            "Interval",
            &[("period", DURATION, 0), ("delay", SLEEP_BOX, 16)],
            &[],
        );
        assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None);
        let mut fx = tick_fixture();
        let pin_mod = fx.ns("core::pin");
        fx.strukt(
            OTHER_PIN,
            Some(pin_mod),
            "Pin<alloc::boxed::Box<app::Fut, alloc::alloc::Global>>",
            &[("pointer", BOX, 0)],
            &[("Ptr", BOX)],
        );
        fx.strukt(
            INTERVAL,
            Some(interval_mod),
            "Interval",
            &[("period", DURATION, 0), ("delay", OTHER_PIN, 16)],
            &[],
        );
        assert_eq!(tokio_interval_tick(&fx.reader, POLL_FN), None);
        for members in [
            &[("period", DURATION, 0), ("sleep", PIN, 16)][..],
            &[("period", DURATION, 0)][..],
        ] {
            let mut fx = tick_fixture();
            let interval_mod = fx.ns("tokio::time::interval");
            fx.strukt(INTERVAL, Some(interval_mod), "Interval", members, &[]);
            assert_eq!(
                tokio_interval_tick(&fx.reader, POLL_FN),
                None,
                "{members:?}"
            );
        }
    }

    /// The enum helpers the dispatcher screen navigates with: a variant
    /// is found by its own name and no other, on a one-variant enum as
    /// on a many-variant one, and an enum is declared where it is
    /// declared under the name it has — both halves of that test.
    #[test]
    fn test_variant_payload_and_enum_declared_in_match_by_name() {
        const ONE: TypeId = TypeId(UnitSectionOffset(0xa0));
        const MANY: TypeId = TypeId(UnitSectionOffset(0xa1));
        const A: TypeId = TypeId(UnitSectionOffset(0xa2));
        const B: TypeId = TypeId(UnitSectionOffset(0xa3));
        const NOT_ENUM: TypeId = TypeId(UnitSectionOffset(0xa4));
        let mut fx = Fx::default();
        let decode = fx.ns("hyper::proto::h1::decode");
        let encode = fx.ns("hyper::proto::h1::encode");
        fx.strukt(A, None, "A", &[], &[]);
        fx.strukt(B, None, "B", &[], &[]);
        fx.strukt(NOT_ENUM, Some(decode), "Kind", &[], &[]);
        fx.enumm(MANY, Some(decode), "Kind", &[("Length", A), ("Chunked", B)]);
        // A one-variant enum has no discriminant and one member.
        let only = RawVariant {
            member: RawMember {
                name: Some(fx.reader.strings.intern("Only")),
                offset: 0,
                type_id: A,
                source_loc: None,
            },
        };
        let name = Some(fx.reader.strings.intern("Kind"));
        fx.reader.types.insert(
            ONE,
            RawType::Enum(crate::raw_types::RawEnum {
                name,
                namespace: Some(encode),
                size: 8,
                alignment: None,
                shape: VariantShape::One(only),
                template_params: Box::default(),
                source_loc: None,
            }),
        );
        let reader = &fx.reader;
        assert_eq!(variant_payload(reader, MANY, "Length"), Some(A));
        assert_eq!(variant_payload(reader, MANY, "Chunked"), Some(B));
        assert_eq!(variant_payload(reader, MANY, "Eof"), None);
        assert_eq!(variant_payload(reader, ONE, "Only"), Some(A));
        assert_eq!(variant_payload(reader, ONE, "Other"), None);
        assert_eq!(variant_payload(reader, NOT_ENUM, "Only"), None);
        assert!(enum_declared_in(
            reader,
            MANY,
            "hyper::proto::h1::decode",
            "Kind"
        ));
        assert!(!enum_declared_in(
            reader,
            MANY,
            "hyper::proto::h1::encode",
            "Kind"
        ));
        assert!(!enum_declared_in(
            reader,
            MANY,
            "hyper::proto::h1::decode",
            "Decoder"
        ));
        assert!(enum_declared_in(
            reader,
            ONE,
            "hyper::proto::h1::encode",
            "Kind"
        ));
        assert!(!enum_declared_in(
            reader,
            NOT_ENUM,
            "hyper::proto::h1::decode",
            "Kind"
        ));
    }

    /// hyper's `Connection` of either side holds its dispatcher in the
    /// one member its poll forwards through — `inner` on the client,
    /// `conn` on the server — declared in its own module and no other,
    /// and holding the dispatcher and nothing else. The version-choosing
    /// wrapper's state is an enum declared in hyper-util's auto module
    /// under its generic name: the same name elsewhere, or a struct of
    /// that name, is not it.
    /// dropshot's request handler is the service that keeps a peer
    /// address and names the server's context: declared in its server
    /// module, with `remote_addr` a `SocketAddr` and its one template
    /// parameter `C`. Another crate's handler of the same shape, the
    /// member under another type, or a parameter by another name, is
    /// neither.
    #[test]
    fn test_dropshot_request_handler_keeps_the_peer_and_the_context() {
        const HANDLER: TypeId = TypeId(UnitSectionOffset(0xa0));
        const ADDR: TypeId = TypeId(UnitSectionOffset(0xa1));
        const OTHER: TypeId = TypeId(UnitSectionOffset(0xa2));
        const PAYLOAD: TypeId = TypeId(UnitSectionOffset(0xa3));
        const CONTEXT: TypeId = TypeId(UnitSectionOffset(0xa4));
        let mut fx = Fx::default();
        let server = fx.ns("dropshot::server");
        let net = fx.ns("core::net::socket_addr");
        let app = fx.ns("app");
        fx.strukt(PAYLOAD, Some(net), "SocketAddrV4", &[], &[]);
        fx.enumm(
            ADDR,
            Some(net),
            "SocketAddr",
            &[("V4", PAYLOAD), ("V6", PAYLOAD)],
        );
        fx.strukt(OTHER, Some(app), "Other", &[], &[]);
        fx.strukt(CONTEXT, Some(app), "Context", &[], &[]);
        let members = [("server", OTHER, 0), ("remote_addr", ADDR, 8)];
        fx.strukt(
            HANDLER,
            Some(server),
            "ServerRequestHandler<app::Context>",
            &members,
            &[("C", CONTEXT)],
        );
        assert_eq!(
            dropshot_request_handler(&fx.reader, HANDLER),
            Some(DropshotHandlerLayout {
                remote_addr: ADDR,
                context: CONTEXT,
            })
        );
        // The same shape in another crate says nothing.
        fx.strukt(
            HANDLER,
            Some(app),
            "ServerRequestHandler<app::Context>",
            &members,
            &[("C", CONTEXT)],
        );
        assert_eq!(dropshot_request_handler(&fx.reader, HANDLER), None);
        // The member has to hold the address type.
        fx.strukt(
            HANDLER,
            Some(server),
            "ServerRequestHandler<app::Context>",
            &[("server", OTHER, 0), ("remote_addr", OTHER, 8)],
            &[("C", CONTEXT)],
        );
        assert_eq!(dropshot_request_handler(&fx.reader, HANDLER), None);
        // The context is the parameter the review read, and the only one.
        for params in [&[][..], &[("T", CONTEXT)], &[("C", CONTEXT), ("S", OTHER)]] {
            fx.strukt(
                HANDLER,
                Some(server),
                "ServerRequestHandler<app::Context>",
                &members,
                params,
            );
            assert_eq!(
                dropshot_request_handler(&fx.reader, HANDLER),
                None,
                "{params:?}"
            );
        }
    }

    /// std's `Duration` gives up its two words only as std declares
    /// them: `secs` a `u64`, and `nanos` the `Nanoseconds` newtype over
    /// a `u32`. Either word of another width, or a `Duration` declared
    /// elsewhere, is no duration.
    #[test]
    fn test_duration_words_are_std_widths() {
        const DURATION: TypeId = TypeId(UnitSectionOffset(0xb0));
        const NANOS: TypeId = TypeId(UnitSectionOffset(0xb1));
        const U64: TypeId = TypeId(UnitSectionOffset(0xb2));
        const U32: TypeId = TypeId(UnitSectionOffset(0xb3));
        let mut fx = Fx::default();
        let time = fx.ns("core::time");
        let niche = fx.ns("core::num::niche_types");
        let app = fx.ns("app");
        fx.base(U64, "u64", Encoding::Unsigned, 8);
        fx.base(U32, "u32", Encoding::Unsigned, 4);
        let mut build = |ns, secs, nanos| {
            fx.strukt(NANOS, Some(niche), "Nanoseconds", &[("__0", nanos, 0)], &[]);
            fx.strukt(
                DURATION,
                Some(ns),
                "Duration",
                &[("secs", secs, 0), ("nanos", NANOS, 8)],
                &[],
            );
            duration_words(&fx.reader, DURATION)
        };
        assert_eq!(build(time, U64, U32), Some((U64, U32)));
        assert_eq!(build(time, U32, U32), None);
        assert_eq!(build(time, U64, U64), None);
        assert_eq!(build(app, U64, U32), None);
    }

    /// The three request layouts: each screen wants its own crate's
    /// type, the method's `Inner` through the `Method` newtype, and the
    /// target's text down to a byte pointer and a word — reqwest's URL
    /// through std's `String`, the two servers' path through http's
    /// `Uri` to its `Bytes`. Another crate's type of the same shape, a
    /// `Method` that is no newtype over `Inner`, or a text whose pointer
    /// is not to bytes is no layout.
    #[test]
    fn test_request_layouts_reach_the_method_and_the_target_text() {
        let t = |n: u32| TypeId(UnitSectionOffset(0xb00 + n as usize));
        let (u8_t, word, byte_ptr, unit) = (t(0), t(1), t(2), t(3));
        let (inner, method, other_method, non_null, unique, raw_vec_inner, raw_vec, vec) =
            (t(4), t(5), t(6), t(7), t(8), t(9), t(10), t(11));
        let (string, url, pending, bytes, byte_str, pq, uri, parts, request, info, rqctx) = (
            t(12),
            t(13),
            t(14),
            t(15),
            t(16),
            t(17),
            t(18),
            t(19),
            t(20),
            t(21),
            t(22),
        );
        let mut fx = Fx::default();
        fx.base(u8_t, "u8", Encoding::Unsigned, 1);
        fx.base(word, "usize", Encoding::Unsigned, 8);
        fx.pointer(byte_ptr, Some("*const u8"), u8_t);
        let core_ns = fx.ns("core");
        fx.strukt(unit, Some(core_ns), "()", &[], &[]);
        let method_mod = fx.ns("http::method");
        fx.enumm(
            inner,
            Some(method_mod),
            "Inner",
            &[("Get", unit), ("Post", unit)],
        );
        fx.strukt(
            method,
            Some(method_mod),
            "Method",
            &[("__0", inner, 0)],
            &[],
        );
        fx.strukt(
            other_method,
            Some(method_mod),
            "Method",
            &[("__0", word, 0)],
            &[],
        );
        let ptr_mod = fx.ns("core::ptr::non_null");
        fx.strukt(
            non_null,
            Some(ptr_mod),
            "NonNull<u8>",
            &[("pointer", byte_ptr, 0)],
            &[],
        );
        let unique_mod = fx.ns("core::ptr::unique");
        fx.strukt(
            unique,
            Some(unique_mod),
            "Unique<u8>",
            &[("pointer", non_null, 0)],
            &[],
        );
        let raw_vec_mod = fx.ns("alloc::raw_vec");
        fx.strukt(
            raw_vec_inner,
            Some(raw_vec_mod),
            "RawVecInner",
            &[("ptr", unique, 0), ("cap", word, 8)],
            &[],
        );
        fx.strukt(
            raw_vec,
            Some(raw_vec_mod),
            "RawVec<u8>",
            &[("inner", raw_vec_inner, 0)],
            &[],
        );
        let vec_mod = fx.ns("alloc::vec");
        fx.strukt(
            vec,
            Some(vec_mod),
            "Vec<u8>",
            &[("buf", raw_vec, 0), ("len", word, 16)],
            &[],
        );
        let string_mod = fx.ns("alloc::string");
        fx.strukt(string, Some(string_mod), "String", &[("vec", vec, 0)], &[]);
        let url_mod = fx.ns("url");
        fx.strukt(
            url,
            Some(url_mod),
            "Url",
            &[("serialization", string, 0)],
            &[],
        );
        let client = fx.ns("reqwest::async_impl::client");
        fx.strukt(
            pending,
            Some(client),
            "PendingRequest",
            &[("method", method, 0), ("url", url, 8)],
            &[],
        );
        let bytes_mod = fx.ns("bytes::bytes");
        fx.strukt(
            bytes,
            Some(bytes_mod),
            "Bytes",
            &[("ptr", byte_ptr, 8), ("len", word, 16)],
            &[],
        );
        let byte_str_mod = fx.ns("http::byte_str");
        fx.strukt(
            byte_str,
            Some(byte_str_mod),
            "ByteStr",
            &[("bytes", bytes, 0)],
            &[],
        );
        let path_mod = fx.ns("http::uri::path");
        fx.strukt(
            pq,
            Some(path_mod),
            "PathAndQuery",
            &[("data", byte_str, 0), ("query", word, 32)],
            &[],
        );
        let uri_mod = fx.ns("http::uri");
        fx.strukt(uri, Some(uri_mod), "Uri", &[("path_and_query", pq, 0)], &[]);
        let request_mod = fx.ns("http::request");
        fx.strukt(
            parts,
            Some(request_mod),
            "Parts",
            &[("method", method, 0), ("uri", uri, 8)],
            &[],
        );
        fx.strukt(
            request,
            Some(request_mod),
            "Request<B>",
            &[("head", parts, 0), ("body", unit, 48)],
            &[],
        );
        let handler = fx.ns("dropshot::handler");
        fx.strukt(
            info,
            Some(handler),
            "RequestInfo",
            &[("method", method, 0), ("uri", uri, 8)],
            &[],
        );
        fx.strukt(
            rqctx,
            Some(handler),
            "RequestContext<C>",
            &[("request", info, 8)],
            &[],
        );
        let layout = |kind| HttpRequestLayout {
            kind,
            method_inner: inner,
            target_ptr: byte_ptr,
            target_len: word,
        };
        assert_eq!(
            reqwest_pending_request(&fx.reader, pending),
            Some(layout(HttpRequestKind::ReqwestPendingRequest))
        );
        assert_eq!(
            http_request(&fx.reader, request),
            Some(layout(HttpRequestKind::HttpRequest))
        );
        assert_eq!(
            dropshot_request_context(&fx.reader, rqctx),
            Some(layout(HttpRequestKind::DropshotRequestContext))
        );
        // Each screen wants its own type: the others are no layout to it.
        assert_eq!(reqwest_pending_request(&fx.reader, request), None);
        assert_eq!(http_request(&fx.reader, rqctx), None);
        assert_eq!(dropshot_request_context(&fx.reader, pending), None);
        // The text's pointer has to be to bytes and its length a word,
        // in `Bytes` and in `String` alike.
        let bytes_as = |fx: &mut Fx, ptr, len| {
            fx.strukt(
                bytes,
                Some(bytes_mod),
                "Bytes",
                &[("ptr", ptr, 8), ("len", len, 16)],
                &[],
            )
        };
        bytes_as(&mut fx, word, word);
        assert_eq!(http_request(&fx.reader, request), None);
        bytes_as(&mut fx, byte_ptr, u8_t);
        assert_eq!(http_request(&fx.reader, request), None);
        bytes_as(&mut fx, byte_ptr, word);
        assert!(http_request(&fx.reader, request).is_some());
        let vec_as = |fx: &mut Fx, len| {
            fx.strukt(
                vec,
                Some(vec_mod),
                "Vec<u8>",
                &[("buf", raw_vec, 0), ("len", len, 16)],
                &[],
            )
        };
        vec_as(&mut fx, u8_t);
        assert_eq!(reqwest_pending_request(&fx.reader, pending), None);
        vec_as(&mut fx, word);
        assert!(reqwest_pending_request(&fx.reader, pending).is_some());
        // The same shape in another crate says nothing.
        let app = fx.ns("app");
        fx.strukt(
            request,
            Some(app),
            "Request<B>",
            &[("head", parts, 0), ("body", unit, 48)],
            &[],
        );
        assert_eq!(http_request(&fx.reader, request), None);
        // A `Method` that is no newtype over `Inner` names no method.
        fx.strukt(
            info,
            Some(handler),
            "RequestInfo",
            &[("method", other_method, 0), ("uri", uri, 8)],
            &[],
        );
        assert_eq!(dropshot_request_context(&fx.reader, rqctx), None);
        // A `url` that is no `Url` names no target.
        fx.strukt(
            pending,
            Some(client),
            "PendingRequest",
            &[("method", method, 0), ("url", string, 8)],
            &[],
        );
        assert_eq!(reqwest_pending_request(&fx.reader, pending), None);
    }

    #[test]
    fn test_hyper_connections_hold_their_dispatcher_and_the_auto_state_is_its_enum() {
        const DISPATCHER: TypeId = TypeId(UnitSectionOffset(0x90));
        const CLIENT: TypeId = TypeId(UnitSectionOffset(0x91));
        const SERVER: TypeId = TypeId(UnitSectionOffset(0x92));
        const OTHER: TypeId = TypeId(UnitSectionOffset(0x93));
        const STATE: TypeId = TypeId(UnitSectionOffset(0x94));
        const PAYLOAD: TypeId = TypeId(UnitSectionOffset(0x95));
        let mut fx = Fx::default();
        let dispatch = fx.ns("hyper::proto::h1::dispatch");
        let client_mod = fx.ns("hyper::client::conn::http1");
        let server_mod = fx.ns("hyper::server::conn::http1");
        let app = fx.ns("app");
        fx.strukt(
            DISPATCHER,
            Some(dispatch),
            "Dispatcher<D, Bs, I, T>",
            &[],
            &[],
        );
        fx.strukt(OTHER, Some(app), "Other", &[], &[]);
        fx.strukt(
            CLIENT,
            Some(client_mod),
            "Connection<T, B>",
            &[("inner", DISPATCHER, 0)],
            &[],
        );
        fx.strukt(
            SERVER,
            Some(server_mod),
            "Connection<I, S>",
            &[("conn", DISPATCHER, 0)],
            &[],
        );
        let forward = |member: &str| {
            Some(ForwardLayout {
                member: member.to_owned(),
                inner: DISPATCHER,
            })
        };
        assert_eq!(
            hyper_h1_client_connection(&fx.reader, CLIENT),
            forward("inner")
        );
        assert_eq!(
            hyper_h1_server_connection(&fx.reader, SERVER),
            forward("conn")
        );
        // Each side's screen is its own module's.
        assert_eq!(hyper_h1_client_connection(&fx.reader, SERVER), None);
        assert_eq!(hyper_h1_server_connection(&fx.reader, CLIENT), None);
        // The member holds the dispatcher and nothing else.
        fx.strukt(
            CLIENT,
            Some(client_mod),
            "Connection<T, B>",
            &[("inner", OTHER, 0)],
            &[],
        );
        assert_eq!(hyper_h1_client_connection(&fx.reader, CLIENT), None);
        fx.strukt(
            SERVER,
            Some(server_mod),
            "Connection<I, S>",
            &[("conn", DISPATCHER, 0), ("extra", OTHER, 8)],
            &[],
        );
        assert_eq!(hyper_h1_server_connection(&fx.reader, SERVER), None);
        // The wrapper's state: the enum by prefix, in its module.
        let auto = fx.ns("hyper_util::server::conn::auto");
        fx.strukt(PAYLOAD, Some(auto), "ReadVersion<I>", &[], &[]);
        fx.enumm(
            STATE,
            Some(auto),
            "UpgradeableConnState<I, S, E>",
            &[("ReadVersion", PAYLOAD), ("H1", PAYLOAD)],
        );
        let auto_path = "hyper_util::server::conn::auto";
        assert!(enum_declared_in_prefix(
            &fx.reader,
            STATE,
            auto_path,
            "UpgradeableConnState<"
        ));
        assert!(!enum_declared_in_prefix(
            &fx.reader,
            STATE,
            auto_path,
            "ConnState<"
        ));
        assert!(!enum_declared_in_prefix(
            &fx.reader,
            STATE,
            "app",
            "UpgradeableConnState<"
        ));
        fx.enumm(
            STATE,
            Some(app),
            "UpgradeableConnState<I, S, E>",
            &[("ReadVersion", PAYLOAD), ("H1", PAYLOAD)],
        );
        assert!(!enum_declared_in_prefix(
            &fx.reader,
            STATE,
            auto_path,
            "UpgradeableConnState<"
        ));
        fx.strukt(STATE, Some(auto), "UpgradeableConnState<I, S, E>", &[], &[]);
        assert!(!enum_declared_in_prefix(
            &fx.reader,
            STATE,
            auto_path,
            "UpgradeableConnState<"
        ));
    }

    /// A hashbrown map is screened as its table: the bucket its
    /// `RawTable` stores has to be the map's own `(K, V)` in both
    /// slots, and the table's three words have to be two unsigned words
    /// and a byte pointer. Any one of them departing is no table.
    #[test]
    fn test_a_hash_table_screen_holds_every_part_of_the_layout() {
        use hash_table::{BUCKET_MASK, CTRL, ITEMS, KEY, POINTER, TABLE, VALUE};
        let t = |n: u32| TypeId(UnitSectionOffset(0xc00 + n as usize));
        let (word, u32_t, u8_t, byte_ptr, word_ptr, non_null) =
            (t(0), t(1), t(2), t(3), t(4), t(5));
        let (inner, raw, bucket, map) = (t(6), t(7), t(8), t(9));
        // What the map's parts are made of, each part from `parts`.
        let build = |parts: [TypeId; 5]| {
            let [bucket_key, bucket_mask, items, ctrl, value] = parts;
            let mut fx = Fx::default();
            fx.base(word, "usize", Encoding::Unsigned, 8);
            fx.base(u32_t, "u32", Encoding::Unsigned, 4);
            fx.base(u8_t, "u8", Encoding::Unsigned, 1);
            fx.pointer(byte_ptr, Some("*const u8"), u8_t);
            fx.pointer(word_ptr, Some("*const usize"), word);
            let ptr_ns = fx.ns("core::ptr::non_null");
            fx.strukt(
                non_null,
                Some(ptr_ns),
                "NonNull<u8>",
                &[(POINTER, ctrl, 0)],
                &[],
            );
            let raw_ns = fx.ns("hashbrown::raw");
            fx.strukt(
                inner,
                Some(raw_ns),
                "RawTableInner",
                &[
                    (BUCKET_MASK, bucket_mask, 0),
                    (CTRL, non_null, 8),
                    ("growth_left", word, 16),
                    (ITEMS, items, 24),
                ],
                &[],
            );
            fx.strukt(
                raw,
                Some(raw_ns),
                "RawTable<(usize, u32), alloc::alloc::Global>",
                &[(TABLE, inner, 0)],
                &[("T", bucket)],
            );
            fx.strukt(
                bucket,
                None,
                "(usize, u32)",
                &[(KEY, bucket_key, 0), (VALUE, value, 8)],
                &[],
            );
            let map_ns = fx.ns("hashbrown::map");
            fx.strukt(
                map,
                Some(map_ns),
                "HashMap<usize, u32>",
                &[(TABLE, raw, 0)],
                &[("K", word), ("V", u32_t)],
            );
            fx
        };
        let sound = [word, word, word, byte_ptr, u32_t];
        let fx = build(sound);
        assert_eq!(
            hash_table(&fx.reader, map),
            Some(HashTableLayout {
                kind: HashTableKind::HashbrownMap,
                map,
                bucket,
                key: word,
                value: u32_t,
                bucket_mask: word,
                items: word,
                ctrl: byte_ptr,
            })
        );
        // One part at a time: a bucket whose key or value is another
        // type than the map's, a mask or a count narrower than a word,
        // a control pointer to words rather than bytes.
        for (at, other, what) in [
            (0, u32_t, "a bucket key"),
            (4, word, "a bucket value"),
            (1, u32_t, "a bucket mask"),
            (2, u32_t, "an item count"),
            (3, word_ptr, "a control pointer"),
        ] {
            let mut parts = sound;
            parts[at] = other;
            assert_eq!(
                hash_table(&build(parts).reader, map),
                None,
                "{what} of the wrong type still screens"
            );
        }
    }
}

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

use super::std::dyn_pointer_layout;
use super::{struct_of, unique_member};
use crate::bundle::names::{generic_args, is_future_trait_object};
use crate::extract::{fq_name, ns_path};
use crate::raw_types::{RawPointer, RawType, RawVariant, VariantShape};
use crate::{DwReader, StrId, TypeId};

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

/// The canonical target every original definition of the thin pointer
/// `id` agrees on, provided each definition's own name — before any
/// declaration inherited one — satisfies `expect` for that target. A
/// definition with no name, a name that does not, or two definitions
/// disagreeing on the target decline; so does a pointer with no
/// recorded definition at all.
fn agreed_pointer(
    reader: &DwReader<'_>,
    id: TypeId,
    expect: impl Fn(&str, TypeId) -> bool,
) -> Option<TypeId> {
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
/// satisfying `expect`; a missing definition, a nameless one, one
/// `expect` refuses, or two naming different targets decline.
fn agreed_target(
    definitions: impl Iterator<Item = Option<RawPointer<StrId>>>,
    expect: impl Fn(StrId, TypeId) -> bool,
) -> Option<TypeId> {
    let mut agreed = None;
    for pointer in definitions {
        let pointer = pointer?;
        let target = pointer.target_type_id;
        if !expect(pointer.name?, target) {
            return None;
        }
        match agreed {
            Some(previous) if previous != target => return None,
            _ => agreed = Some(target),
        }
    }
    agreed
}

/// `&mut F` as a thin pointer: every definition named `&mut <F>` for the
/// exact `F` it targets. A raw pointer, a shared reference, or a pointer
/// whose name was inherited from a declaration is not one.
fn mut_ref_thin(reader: &DwReader<'_>, id: TypeId) -> Option<TypeId> {
    agreed_pointer(reader, id, |name, target| {
        name.strip_prefix("&mut ")
            .is_some_and(|rest| fq_name(reader, target).as_deref() == Some(rest))
    })
}

/// A sized `Box<F, Global>` as rustc's debuginfo spells it: a thin
/// pointer named `alloc::boxed::Box<F, alloc::alloc::Global>` for the
/// exact `F` it targets, by every definition.
fn box_thin(reader: &DwReader<'_>, id: TypeId) -> Option<TypeId> {
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

fn mut_ref(reader: &DwReader<'_>, id: TypeId) -> Option<Pointee> {
    if let Some(target) = mut_ref_thin(reader, id) {
        return Some(Pointee::Sized(target));
    }
    wide(reader, id, |name, pointee| {
        name.strip_prefix("&mut ") == Some(pointee)
    })
    .map(Pointee::Dyn)
}

fn boxed(reader: &DwReader<'_>, id: TypeId) -> Option<Pointee> {
    if let Some(target) = box_thin(reader, id) {
        return Some(Pointee::Sized(target));
    }
    wide(reader, id, |name, pointee| {
        matches!(generic_args(name), Some(("alloc::boxed::Box", args))
            if args.as_slice() == [pointee, "alloc::alloc::Global"])
    })
    .map(Pointee::Dyn)
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
    if let Some((member, ptr)) = pin(reader, id) {
        if let Some(pointee) = boxed(reader, ptr) {
            return Some(StdAdapter::PinBox {
                member,
                boxed: ptr,
                pointee,
            });
        }
        if let Some(pointee) = mut_ref(reader, ptr) {
            return Some(StdAdapter::PinMutRef {
                member,
                reference: ptr,
                pointee,
            });
        }
        return None;
    }
    if let Some(pointee) = boxed(reader, id) {
        return Some(StdAdapter::Box(pointee));
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
    let mask_word = mut_ref_thin(reader, disabled.type_id)?;
    let width = match reader.canonical_type(mask_word)? {
        RawType::Base(base) if base.encoding == crate::Encoding::Unsigned => base.size,
        _ => return None,
    };
    if !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let tuple = mut_ref_thin(reader, futures.type_id)?;
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
        assert_eq!(
            agreed_target([def(FUT), def(FUT)].into_iter(), accept),
            Some(FUT)
        );
        assert_eq!(
            agreed_target([def(FUT), def(DYN)].into_iter(), accept),
            None
        );
        assert_eq!(
            agreed_target([def(DYN), def(FUT)].into_iter(), accept),
            None
        );
        assert_eq!(agreed_target([def(FUT), None].into_iter(), accept), None);
        assert_eq!(
            agreed_target(
                [Some(RawPointer {
                    name: None,
                    target_type_id: FUT,
                })]
                .into_iter(),
                accept
            ),
            None
        );
        assert_eq!(
            agreed_target([def(FUT)].into_iter(), |_, target| target != FUT),
            None
        );
        assert_eq!(agreed_target(std::iter::empty(), accept), None);
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
        let (mut fx, _, wrapper) = map_fixture();
        let try_future = fx.ns("futures_util::future::try_future");
        let into_mod = fx.ns("futures_util::future::try_future::into_future");
        let rt = fx.ns("hyper_util::rt::tokio");
        let sleep_mod = fx.ns("tokio::time::sleep");
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
        // What each holds is the check: a `MapErr` over anything but the
        // public `Map`, an `IntoFuture` over something other than the
        // `Fut` it declares, and a sleep newtype over anything but
        // tokio's own are layouts no review covers.
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
}

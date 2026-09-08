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
use crate::raw_types::RawPointer;
use crate::{DwReader, StrId, TypeId};

/// What a thin or wide pointer adapter points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Pointee {
    /// A sized `F`, reached by dereferencing the thin pointer.
    Sized(TypeId),
    /// A `dyn Future` behind a wide pointer.
    Dyn(WidePointer),
}

/// A `{ pointer, vtable }` wide pointer to a bare future trait object:
/// the struct carrying the two members, their names and types, and the
/// zero-sized `dyn` type the data pointer targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WidePointer {
    pub(crate) wide: TypeId,
    pub(crate) pointer: String,
    pub(crate) vtable: String,
    pub(crate) data_ptr: TypeId,
    pub(crate) vtable_ptr: TypeId,
    pub(crate) trait_ty: TypeId,
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

/// A wide pointer to a bare `dyn Future`: rustc's `{ pointer, vtable }`
/// struct whose data pointer targets the trait object itself (no
/// unsized aggregate around it) and whose vtable declares at least the
/// four words a `Future` vtable has. The struct's own name has to
/// satisfy `expect` for the pointee's name.
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
    if !is_future_trait_object(&pointee) || !expect(&fq_name(reader, id)?, &pointee) {
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

        fn vtable(&mut self, id: TypeId, words: u64) {
            let usize_t = type_id(0x900);
            let slots = type_id(0x901);
            self.reader.types.insert(
                usize_t,
                RawType::Base(RawBase {
                    name: Some(self.reader.strings.intern("usize")),
                    namespace: None,
                    encoding: Encoding::Unsigned,
                    size: 8,
                    alignment: None,
                }),
            );
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
    fn test_wide_adapters_need_a_bare_future_trait_object_and_a_poll_slot() {
        let fx = fixture();
        assert_eq!(
            std_adapter(&fx.reader, BOX_DYN),
            Some(StdAdapter::Box(wide_over(BOX_DYN)))
        );
        assert_eq!(
            std_adapter(&fx.reader, REF_DYN),
            Some(StdAdapter::MutRef(wide_over(REF_DYN)))
        );
        // Three vtable words leave no poll slot.
        let mut fx = fixture();
        fx.vtable(VTABLE, 3);
        assert_eq!(std_adapter(&fx.reader, BOX_DYN), None);
        // Some other trait object, however future-flavored its generics.
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
}

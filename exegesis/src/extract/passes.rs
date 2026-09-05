// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Closing passes over the emitted type table: demote types whose layout
//! does not hold together, and strip coroutine states of members that are
//! another state's storage.

use crate::bundle::names::coroutine_kind;
use crate::bundle::{BundleTypeId, MemberDef, StrRef, TypeDef, TypeTable};

use tracing::warn;

use std::collections::HashSet;

/// Drop from each of a coroutine's states the members that are not that
/// state's own.
///
/// Only the active state's storage means anything: which one that is comes
/// from the discriminant, and the others hold whatever the coroutine last
/// left there. rustc's own debuginfo does not hold to that. It lists a
/// coroutine's captures as members of *every* variant, at the offsets they
/// occupy in `Unresumed`, however long ago the state being described stopped
/// using them — `Returned` and `Panicked` carry them too, and there the
/// captures provably cannot exist: a coroutine drops them in place on its
/// way out.
///
/// Which suspended states a capture is dead in depends on what kind of
/// coroutine it is, and the type's name says which.
///
/// An `async fn`'s captures are its arguments, and the desugaring moves
/// each into a body local at entry, so the capture slot is dead from the
/// first suspend on. An argument still live at a suspend point is a saved
/// local with a slot of its own, and rustc relocates it there (and,
/// separately, lists it twice); one that is dead is left pointing at the
/// slot it had in `Unresumed`. So a member matching an `Unresumed` member
/// exactly — name, type and offset — is `Unresumed`'s storage rather than
/// this state's, and describing it means reading bytes whose meaning ended
/// whenever the coroutine moved past them. In the `simple-await` fixture
/// that is a `oneshot::Sender` consumed by `send()` a line before the
/// await, whose channel has since been freed: what is left at the offset
/// is a dangling pointer into reused heap.
///
/// An `async move { … }` block has no such step: its captures *are* the
/// body's storage for the whole life of the coroutine, at the one offset
/// in every state, and a suspended state that dropped them would hide the
/// lock a task is waiting on or the sender it has not yet fired. So a
/// block's captures stay in its `Suspend` states and go only from the
/// terminal ones. A capture the body moved out of before suspending is
/// still listed, holding a byte-perfect copy of what was moved; the
/// debuginfo carries no liveness for captures, and nothing in the bundle
/// can tell that copy from a live value. Async closures and hand-written
/// coroutines are treated as blocks: whether their arguments get the
/// `async fn` move has not been checked against a fixture, and listing a
/// stale argument is the lesser failure next to hiding a live capture.
///
/// This recognizes a rustc artifact by its shape, so what it found is
/// reported under `--stats`. The member counts alone are a weak signal — they
/// fall to zero both when rustc stops emitting the artifact and when it
/// renames the states out from under the match — so the coroutines *seen* are
/// counted beside the ones matched to an `Unresumed`. Many seen against none
/// matched says the naming moved; both falling together says the debuginfo
/// did.
///
/// Neither catches the failure that would cost something: an argument left at
/// its `Unresumed` offset while still live would be dropped, and no count
/// would move. Nothing in the bundle separates that case from a dead one —
/// the liveness is in the source — so what guards it is the acceptance suite
/// asserting a fixture's locals in full against a freshly extracted bundle.
pub(super) fn drop_members_of_other_states(
    types: &mut TypeTable,
    names: &[Option<String>],
) -> StatePass {
    let mut found = StatePass::default();

    // Every coroutine's `Unresumed` payload, against the other states of the
    // same coroutine. Collected first because the members are read from one
    // entry of the table and written to another.
    let mut work: Vec<(BundleTypeId, Vec<BundleTypeId>, bool)> = Vec::new();
    for (i, def) in types.types.iter().enumerate() {
        let TypeDef::Enum { shape, .. } = def else {
            continue;
        };
        let payloads = || shape.variants.iter().map(|v| v.payload.ty);
        // Coroutine-shaped, by rustc's own names for the states — whether or
        // not the one this pass needs is among them.
        let coroutine = payloads()
            .filter_map(|id| state_name(names, id))
            .any(|n| n == "Returned" || n == "Panicked" || n.starts_with("Suspend"));
        if !coroutine {
            continue;
        }
        found.coroutines_seen += 1;
        let Some(unresumed) = payloads().find(|id| state_name(names, *id) == Some("Unresumed"))
        else {
            continue;
        };
        found.coroutines_matched += 1;
        let args_moved_at_entry = names
            .get(i)
            .and_then(|n| n.as_deref())
            .and_then(coroutine_kind)
            == Some("async fn");
        work.push((
            unresumed,
            payloads().filter(|id| *id != unresumed).collect(),
            args_moved_at_entry,
        ));
    }

    for (unresumed, states, args_moved_at_entry) in work {
        let held_by_unresumed: HashSet<(StrRef, BundleTypeId, u64)> =
            members_of(types, unresumed).iter().map(key).collect();
        for state in states {
            let terminal = matches!(
                state_name(names, state),
                Some("Returned") | Some("Panicked")
            );
            let strip = args_moved_at_entry || terminal;
            let members = match &mut types.types[state.0 as usize] {
                TypeDef::Struct { members, .. } | TypeDef::Union { members, .. } => members,
                _ => continue,
            };
            let mut kept: HashSet<(StrRef, BundleTypeId, u64)> = HashSet::new();
            members.retain(|m| {
                if held_by_unresumed.contains(&key(m)) {
                    if strip {
                        found.members_dropped += 1;
                        return false;
                    }
                    found.captures_kept += 1;
                }
                // The same member listed twice over, which is how rustc
                // spells an argument that *is* live here: once as the
                // argument, once as the saved local, both at the one slot.
                if !kept.insert(key(m)) {
                    found.members_deduplicated += 1;
                    return false;
                }
                true
            });
        }
    }
    found
}

/// What [`drop_members_of_other_states`] found, reported under `--stats`.
#[derive(Default, PartialEq, Eq, Debug)]
pub(super) struct StatePass {
    pub(super) coroutines_seen: usize,
    pub(super) coroutines_matched: usize,
    pub(super) members_dropped: usize,
    pub(super) members_deduplicated: usize,
    /// Members matching `Unresumed`'s that a suspended state of a block
    /// kept, because there they are the block's captures.
    pub(super) captures_kept: usize,
}

fn key(m: &MemberDef) -> (StrRef, BundleTypeId, u64) {
    (m.name, m.ty, m.offset)
}

fn members_of(types: &TypeTable, id: BundleTypeId) -> &[MemberDef] {
    match types.get(id) {
        Some(TypeDef::Struct { members, .. }) | Some(TypeDef::Union { members, .. }) => members,
        _ => &[],
    }
}

/// The last path segment of a coroutine state's payload type, which is the
/// state's own name: `Unresumed`, `Returned`, `Suspend0`, and so on.
fn state_name(names: &[Option<String>], id: BundleTypeId) -> Option<&str> {
    let name = names.get(id.0 as usize)?.as_deref()?;
    Some(name.rsplit("::").next().unwrap_or(name))
}

/// Demote any type whose own layout does not hold together to an `Opaque` of
/// the same size, returning how many were replaced.
///
/// A member reaching past the end of its parent means the offsets and sizes
/// DWARF gave us disagree, and anything navigating into such a type reads
/// outside the value. Replacing it keeps its id and byte size -- so every type
/// that embeds or points to it still lays out correctly -- while removing the
/// members that cannot be trusted. The renderer then shows it as a name over
/// its bytes rather than inventing fields, which is the same treatment a type
/// the extractor could not model at all receives.
///
/// A declared size of zero means "unknown", not "empty": an unsized type such
/// as `CStr` or a declaration-only DIE records no byte size. There is nothing
/// to bound those against, so they are left alone.
pub(super) fn demote_types_with_members_out_of_bounds(
    types: &mut TypeTable,
    names: &[Option<String>],
) -> usize {
    let overflows = |size: u64, m: &MemberDef| {
        types
            .size_of(m.ty)
            .is_some_and(|member_size| m.offset.saturating_add(member_size) > size)
    };

    // Collected first: demoting as we go would turn a type into an `Opaque` of
    // unknown member size and change the verdict for whatever embeds it.
    let mut demote = Vec::new();
    for (i, def) in types.types.iter().enumerate() {
        let (name, size, bad) = match def {
            TypeDef::Struct {
                name,
                size,
                members,
            }
            | TypeDef::Union {
                name,
                size,
                members,
            } => (*name, *size, members.iter().find(|m| overflows(*size, m))),
            TypeDef::Enum { name, size, shape } => (
                *name,
                *size,
                shape
                    .variants
                    .iter()
                    .map(|v| &v.payload)
                    .find(|m| overflows(*size, m)),
            ),
            _ => continue,
        };
        if size == 0 {
            continue;
        }
        let Some(bad) = bad else { continue };
        warn!(
            "type {i} `{}` has size {size} but member at offset {} is {} bytes; \
             emitting it as opaque",
            names
                .get(i)
                .and_then(|n| n.as_deref())
                .unwrap_or("<unnamed>"),
            bad.offset,
            types.size_of(bad.ty).unwrap_or(0),
        );
        demote.push((i, name, size));
    }

    for (i, name, size) in &demote {
        types.types[*i] = TypeDef::Opaque {
            name: *name,
            size: Some(*size),
        };
    }
    demote.len()
}

#[cfg(test)]
mod tests {
    use super::{StatePass, demote_types_with_members_out_of_bounds, drop_members_of_other_states};

    /// A member reaching past its parent means DWARF gave us offsets and sizes
    /// that disagree, so the type is emitted as an opaque of the same size
    /// rather than as fields nothing can safely read. Sound types, and types
    /// whose size is unknown rather than zero, are left as they are.
    #[test]
    fn test_demote_types_with_members_out_of_bounds() {
        use crate::bundle::{
            BundleTypeId, DiscrDef, MemberDef, StringInterner, TypeDef, TypeTable, VariantDef,
            VariantShape,
        };
        use std::collections::BTreeMap;

        let mut strings = StringInterner::new();
        let mut s = |n: &str| strings.intern(n);
        let (u32n, soundn, oobn, unsizedn, enumn, varn) = (
            s("u32"),
            s("Sound"),
            s("Oob"),
            s("Unsized"),
            s("Enum"),
            s("V"),
        );
        let u32t = BundleTypeId(0);
        let m = |name, ty, offset| MemberDef { name, ty, offset };

        let mut types = TypeTable {
            types: vec![
                // 0: u32
                TypeDef::Base {
                    name: u32n,
                    size: 4,
                    encoding: crate::Encoding::Unsigned,
                },
                // 1: Sound { a: u32 @0, b: u32 @4 } -- fits exactly.
                TypeDef::Struct {
                    name: soundn,
                    size: 8,
                    members: vec![m(u32n, u32t, 0), m(u32n, u32t, 4)],
                },
                // 2: Oob { a: u32 @0, b: u32 @6 } -- b runs two bytes over.
                TypeDef::Struct {
                    name: oobn,
                    size: 8,
                    members: vec![m(u32n, u32t, 0), m(u32n, u32t, 6)],
                },
                // 3: Unsized { inner: u32 @0 } with no recorded size -- a DST
                // or a declaration-only DIE, which there is nothing to bound.
                TypeDef::Struct {
                    name: unsizedn,
                    size: 0,
                    members: vec![m(u32n, u32t, 0)],
                },
                // 4: an enum whose variant payload runs past its size.
                TypeDef::Enum {
                    name: enumn,
                    size: 4,
                    shape: VariantShape {
                        discr: Some(DiscrDef {
                            offset: 0,
                            ty: u32t,
                        }),
                        variants: vec![VariantDef {
                            name: varn,
                            discr_values: None,
                            payload: m(varn, u32t, 2),
                            decl: None,
                            await_site: None,
                        }],
                    },
                },
            ],
            debug_formats: BTreeMap::new(),
            name_index: vec![],
            ..Default::default()
        };
        let names = vec![
            Some("u32".to_owned()),
            Some("Sound".to_owned()),
            Some("Oob".to_owned()),
            Some("Unsized".to_owned()),
            Some("Enum".to_owned()),
        ];

        assert_eq!(
            demote_types_with_members_out_of_bounds(&mut types, &names),
            2
        );

        // The sound struct and the sizeless one keep their members.
        assert!(matches!(types.types[1], TypeDef::Struct { .. }));
        assert!(matches!(types.types[3], TypeDef::Struct { .. }));

        // The two bad ones become opaques that keep their name and byte size,
        // so anything embedding or pointing at them still lays out correctly.
        assert!(matches!(
            types.types[2],
            TypeDef::Opaque {
                name,
                size: Some(8)
            } if name == oobn
        ));
        assert!(matches!(
            types.types[4],
            TypeDef::Opaque {
                name,
                size: Some(4)
            } if name == enumn
        ));

        // Running again finds nothing left to demote.
        assert_eq!(
            demote_types_with_members_out_of_bounds(&mut types, &names),
            0
        );
    }

    /// The coroutine screen keys on rustc's own state names: any one of
    /// `Returned`, `Panicked`, or a `Suspend` state marks the enum, and
    /// no other name does.
    #[test]
    fn test_coroutines_are_recognized_by_any_state_name() {
        use crate::bundle::{
            BundleTypeId, MemberDef, StringInterner, TypeDef, TypeTable, VariantDef, VariantShape,
        };

        for (state, seen) in [
            ("Returned", 1),
            ("Panicked", 1),
            ("Suspend7", 1),
            ("Working", 0),
        ] {
            let mut strings = StringInterner::new();
            let name = strings.intern(state);
            let envn = strings.intern("E");
            let mut types = TypeTable {
                types: vec![
                    TypeDef::Struct {
                        name,
                        size: 8,
                        members: vec![],
                    },
                    TypeDef::Enum {
                        name: envn,
                        size: 8,
                        shape: VariantShape {
                            discr: None,
                            variants: vec![VariantDef {
                                name,
                                discr_values: None,
                                payload: MemberDef {
                                    name,
                                    ty: BundleTypeId(0),
                                    offset: 0,
                                },
                                decl: None,
                                await_site: None,
                            }],
                        },
                    },
                ],
                ..Default::default()
            };
            let names = vec![Some(format!("E::{state}")), Some("E".to_owned())];
            let found = drop_members_of_other_states(&mut types, &names);
            assert_eq!(found.coroutines_seen, seen, "{state}");
        }
    }

    /// rustc lists an `async fn`'s arguments in every one of a coroutine's
    /// states. Where the argument is still live the listing is relocated to
    /// its saved-local slot (and doubled); where it is dead it is left at the
    /// slot it had in `Unresumed`, which is another state's storage and reads
    /// as whatever the coroutine last left there.
    #[test]
    fn test_async_fn_states_drop_arguments_left_at_their_unresumed_slot() {
        use crate::bundle::{
            BundleTypeId, MemberDef, StringInterner, TypeDef, TypeTable, VariantDef, VariantShape,
        };
        use std::collections::BTreeMap;

        let mut strings = StringInterner::new();
        let mut s = |n: &str| strings.intern(n);
        let (argn, localn, envn) = (s("ready"), s("count"), s("env"));
        let u32t = BundleTypeId(0);
        let m = |name, offset| MemberDef {
            name,
            ty: u32t,
            offset,
        };
        let state = |name, members| TypeDef::Struct {
            name,
            size: 32,
            members,
        };
        let variant = |ty| VariantDef {
            name: envn,
            discr_values: None,
            payload: MemberDef {
                name: envn,
                ty,
                offset: 0,
            },
            decl: None,
            await_site: None,
        };

        let mut types = TypeTable {
            types: vec![
                TypeDef::Base {
                    name: s("u32"),
                    size: 4,
                    encoding: crate::Encoding::Unsigned,
                },
                // 1: Unresumed holds the argument at its own slot.
                state(argn, vec![m(argn, 0)]),
                // 2: Suspend0, where the argument is still live: relocated
                // off slot 0, and listed twice over.
                state(argn, vec![m(argn, 16), m(argn, 16), m(localn, 8)]),
                // 3: Suspend1, where it is dead: left pointing at slot 0.
                state(argn, vec![m(argn, 0), m(localn, 8)]),
                // 4: Returned, a terminal state that cannot hold it at all.
                state(argn, vec![m(argn, 0)]),
                TypeDef::Enum {
                    name: envn,
                    size: 32,
                    shape: VariantShape {
                        discr: None,
                        variants: (1..=4).map(|i| variant(BundleTypeId(i))).collect(),
                    },
                },
            ],
            debug_formats: BTreeMap::new(),
            name_index: vec![],
            ..Default::default()
        };
        // An `async fn`'s env, spelled the way rustc does, generics and
        // all: the gate reads the kind off the name's last path segment.
        let env = "app::work::{async_fn_env#0}<alloc::string::String>";
        let names: Vec<Option<String>> = ["u32", "Unresumed", "Suspend0", "Suspend1", "Returned"]
            .iter()
            .map(|state| Some(format!("{env}::{state}")))
            .chain([Some(env.to_owned())])
            .collect();

        assert_eq!(
            drop_members_of_other_states(&mut types, &names),
            StatePass {
                coroutines_seen: 1,
                coroutines_matched: 1,
                members_dropped: 2,
                members_deduplicated: 1,
                captures_kept: 0,
            }
        );

        let members = |i: usize| match &types.types[i] {
            TypeDef::Struct { members, .. } => members.clone(),
            other => panic!("{other:?} is not a struct"),
        };
        // Unresumed is the state that owns them, and keeps them.
        assert_eq!(members(1), vec![m(argn, 0)]);
        // Suspend0's copy is live, so only the repeat goes.
        assert_eq!(members(2), vec![m(argn, 16), m(localn, 8)]);
        // Suspend1 and Returned keep only what is theirs.
        assert_eq!(members(3), vec![m(localn, 8)]);
        assert_eq!(members(4), vec![]);

        // Running again still recognizes the coroutine, and finds nothing
        // left to drop in it.
        assert_eq!(
            drop_members_of_other_states(&mut types, &names),
            StatePass {
                coroutines_seen: 1,
                coroutines_matched: 1,
                ..Default::default()
            }
        );

        // A coroutine rustc has renamed the states of is still counted as
        // one, and reported as unmatched rather than passed over in silence.
        let renamed: Vec<Option<String>> = names
            .iter()
            .map(|n| n.as_deref().map(|n| n.replace("Unresumed", "Start")))
            .collect();
        let found = drop_members_of_other_states(&mut types, &renamed);
        assert_eq!(found.coroutines_seen, 1);
        assert_eq!(found.coroutines_matched, 0);
    }

    /// An `async move` block's captures are its storage in every state, at
    /// the one offset. rustc lists them the same way it lists an `async
    /// fn`'s dead arguments — once, at the `Unresumed` slot — so the kind
    /// in the env's name is what keeps a suspended state's captures and
    /// strips only the terminal states, where the block has dropped them.
    #[test]
    fn test_async_block_states_keep_captures_until_the_block_returns() {
        use crate::bundle::{
            BundleTypeId, MemberDef, StringInterner, TypeDef, TypeTable, VariantDef, VariantShape,
        };
        use std::collections::BTreeMap;

        let mut strings = StringInterner::new();
        let mut s = |n: &str| strings.intern(n);
        let (lockn, txn, guardn, awaiteen, envn) =
            (s("lock"), s("tx"), s("_guard"), s("__awaitee"), s("env"));
        let u32t = BundleTypeId(0);
        let m = |name, offset| MemberDef {
            name,
            ty: u32t,
            offset,
        };
        let state = |members| TypeDef::Struct {
            name: envn,
            size: 40,
            members,
        };
        let variant = |ty| VariantDef {
            name: envn,
            discr_values: None,
            payload: MemberDef {
                name: envn,
                ty,
                offset: 0,
            },
            decl: None,
            await_site: None,
        };

        // The `futurelock` fixture's background block, as rustc lists it.
        let mut types = TypeTable {
            types: vec![
                TypeDef::Base {
                    name: s("u32"),
                    size: 4,
                    encoding: crate::Encoding::Unsigned,
                },
                // 1: Unresumed — the two captures.
                state(vec![m(lockn, 16), m(txn, 0)]),
                // 2: Suspend0 — the awaitee beside both captures, one of them
                // (in the source) not yet consumed.
                state(vec![m(awaiteen, 32), m(lockn, 16), m(txn, 0)]),
                // 3: Suspend1 — a body local beside the same captures.
                state(vec![m(guardn, 8), m(awaiteen, 32), m(lockn, 16), m(txn, 0)]),
                // 4, 5: the terminal states, listing captures the block has
                // dropped on its way out.
                state(vec![m(lockn, 16), m(txn, 0)]),
                state(vec![m(lockn, 16), m(txn, 0)]),
                TypeDef::Enum {
                    name: envn,
                    size: 40,
                    shape: VariantShape {
                        discr: None,
                        variants: (1..=5).map(|i| variant(BundleTypeId(i))).collect(),
                    },
                },
            ],
            debug_formats: BTreeMap::new(),
            name_index: vec![],
            ..Default::default()
        };
        let env = "app::start::{async_fn#0}::{async_block_env#0}";
        let names: Vec<Option<String>> = [
            "u32",
            "Unresumed",
            "Suspend0",
            "Suspend1",
            "Returned",
            "Panicked",
        ]
        .iter()
        .map(|state| Some(format!("{env}::{state}")))
        .chain([Some(env.to_owned())])
        .collect();

        assert_eq!(
            drop_members_of_other_states(&mut types, &names),
            StatePass {
                coroutines_seen: 1,
                coroutines_matched: 1,
                members_dropped: 4,
                members_deduplicated: 0,
                captures_kept: 4,
            }
        );

        let members = |i: usize| match &types.types[i] {
            TypeDef::Struct { members, .. } => members.clone(),
            other => panic!("{other:?} is not a struct"),
        };
        // The suspended states keep their captures, in rustc's order.
        assert_eq!(members(2), vec![m(awaiteen, 32), m(lockn, 16), m(txn, 0)]);
        assert_eq!(
            members(3),
            vec![m(guardn, 8), m(awaiteen, 32), m(lockn, 16), m(txn, 0)]
        );
        // The terminal states lose them.
        assert_eq!(members(4), vec![]);
        assert_eq!(members(5), vec![]);
    }
}

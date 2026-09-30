// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::tiny_bundle;
use crate::*;

use std::collections::BTreeMap;

const CHILD: BundleTypeId = BundleTypeId(1);
const PARENT: BundleTypeId = BundleTypeId(3);
const STATE: BundleTypeId = BundleTypeId(4);
const FIELD: StrRef = StrRef(1);
const VARIANT: StrRef = StrRef(2);
const POLL: StrRef = StrRef(5);

fn issue() -> SemanticIssue {
    SemanticIssue {
        kind: SemanticIssueKind::NoRule,
        detail: None,
    }
}

fn record(ty: BundleTypeId) -> TypeSemantics {
    TypeSemantics {
        ty,
        storage: StoragePolicy::DeclaredMembers,
        future: Some(FutureFacts {
            evidence: vec![FutureEvidence::PollSymbol(POLL)],
            continuation: Continuation::Unknown(issue()),
        }),
        coroutine: None,
        access: None,
        resource: None,
        container: None,
        select: None,
        http: None,
        request: None,
        table: None,
        pool: None,
        io_route: None,
        io: None,
        refcount: None,
        lock: None,
        acquires_for: None,
        coroutine_kind: None,
        issues: Vec::new(),
    }
}

fn base() -> Bundle {
    let mut b = tiny_bundle();
    let mut strings = StringInterner::new();
    for s in [
        "u64",
        "child",
        "3",
        "Parent",
        "State",
        "<Parent as core::future::future::Future>::poll",
        "rustc version 1.98.0 (synthetic)",
        "synthetic-convention",
        "tokio",
        "1.53.1",
        "v1_53",
        "source.rs",
        "tracing",
        "0.1.40",
        "data",
        "vtable",
        "dyn core::future::future::Future<Output=()>",
        "tracing-instrumented-0.1.40",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs",
        "vendor/tracing-0.1.40/src/instrument.rs",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.50/src/instrument.rs",
        "dyn hyper::rt::timer::Sleep<Output=()>",
        "futures-util",
        "0.3.33",
        "registry/src/index.crates.io-1949cf8c6b5b557f/futures-util-0.3.33/src/lib.rs",
        "hyper-util",
        "0.1.20",
        "registry/src/index.crates.io-1949cf8c6b5b557f/hyper-util-0.1.20/src/rt/tokio.rs",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.53.1/src/task/coop/mod.rs",
        "tokio-stream",
        "0.1.19",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-stream-0.1.19/src/wrappers/watch.rs",
        "tokio-util",
        "0.7.19",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-util-0.7.19/src/sync/reusable_box.rs",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-stream-0.1.19/src/stream_map.rs",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.53.1/src/time/interval.rs",
        "tokio-rustls",
        "0.26.4",
        "tokio-rustls-stream-0.26.0",
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-rustls-0.26.4/src/lib.rs",
        "sprockets-tls",
        "sprockets",
        "a233079",
        "sprockets-tls-stream-d2b68e4",
        "git/checkouts/sprockets-882d17aeeb0cb343/a233079/tls/src/lib.rs",
        "68a4b3b",
    ] {
        strings.intern(s);
    }
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    b.types = TypeTable {
        types: vec![
            TypeDef::Base {
                name: StrRef(0),
                size: 8,
                encoding: Encoding::Unsigned,
            },
            TypeDef::Struct {
                name: FIELD,
                size: 8,
                members: vec![member(FIELD, BundleTypeId(0), 0)],
            },
            TypeDef::Pointer {
                name: None,
                target: CHILD,
            },
            TypeDef::Struct {
                name: StrRef(3),
                size: 16,
                members: vec![member(FIELD, CHILD, 8)],
            },
            TypeDef::Enum {
                name: StrRef(4),
                size: 24,
                shape: VariantShape {
                    discr: None,
                    variants: vec![VariantDef {
                        name: VARIANT,
                        discr_values: None,
                        payload: member(VARIANT, PARENT, 8),
                        decl: None,
                        await_site: None,
                    }],
                },
            },
            TypeDef::Union {
                name: FIELD,
                size: 8,
                members: vec![member(FIELD, CHILD, 0)],
            },
            TypeDef::Opaque {
                name: StrRef(16),
                size: None,
            },
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(6),
            },
            TypeDef::Pointer {
                name: None,
                target: BundleTypeId(0),
            },
            TypeDef::Struct {
                name: FIELD,
                size: 16,
                members: vec![
                    member(StrRef(14), BundleTypeId(7), 0),
                    member(StrRef(15), BundleTypeId(8), 8),
                ],
            },
            TypeDef::Pointer {
                name: None,
                target: PARENT,
            },
        ],
        ..Default::default()
    };
    b.dyn_futures.by_symbol = BTreeMap::from([(
        b.strings.get(POLL).unwrap().into(),
        vec![CHILD, PARENT, STATE, BundleTypeId(9)],
    )]);
    b.semantics.origins = vec![SemanticOrigin::Rustc {
        producer: StrRef(6),
        family: StrRef(7),
    }];
    b.semantics.rules = vec![SemanticRule {
        kind: SemanticRuleKind::StdPinBoxPoll,
        revision: 1,
        origin: SemanticOriginId(0),
    }];
    b.validate().unwrap();
    b
}

fn path(steps: Vec<Step>, target: BundleTypeId) -> TypedPath {
    TypedPath { steps, target }
}

fn named(name: StrRef) -> Step {
    Step::Member(MemberRef::Named(name))
}

fn delegate(target: FutureTarget) -> Continuation {
    Continuation::Bound {
        rule: SemanticRuleId(0),
        program: PollProgram::Direct(PollAction::Delegate {
            target,
            exclusive: false,
        }),
    }
}

fn forwarding() -> Bundle {
    let mut b = base();
    let mut parent = record(PARENT);
    parent.future.as_mut().unwrap().continuation =
        delegate(FutureTarget::Value(path(vec![named(FIELD)], CHILD)));
    let mut child = record(CHILD);
    child.future.as_mut().unwrap().evidence = vec![FutureEvidence::DelegatedBy { parent: PARENT }];
    b.semantics.types = vec![child, parent];
    b.validate().unwrap();
    b
}

fn continuation(b: &mut Bundle) -> &mut Continuation {
    &mut b
        .semantics
        .types
        .last_mut()
        .unwrap()
        .future
        .as_mut()
        .unwrap()
        .continuation
}

fn target_path(b: &mut Bundle) -> &mut TypedPath {
    let Continuation::Bound {
        program:
            PollProgram::Direct(PollAction::Delegate {
                target: FutureTarget::Value(p),
                ..
            }),
        ..
    } = continuation(b)
    else {
        panic!("static delegate")
    };
    p
}

fn bad(b: &Bundle, expected: &str) {
    let err = b
        .validate()
        .expect_err("malformed semantics must fail validation")
        .to_string();
    assert!(err.contains(expected), "expected {expected:?}, got {err:?}");
}

#[test]
fn test_semantic_roundtrip_and_display_independence() {
    let mut b = forwarding();
    b.types.debug_formats.insert(
        PARENT,
        DisplayNode::Alias {
            at: Selector(vec![named(FIELD)]),
            follow_pointers: false,
        },
    );
    b.validate().unwrap();
    let semantics = b.semantics.clone();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
    b.types.debug_formats.clear();
    b.validate().unwrap();
    assert_eq!(b.semantics, semantics);
}

#[test]
fn test_semantic_ids_evidence_and_rule_validation() {
    type Mutation = (&'static str, fn(&mut Bundle));
    let cases: &[Mutation] = &[
        ("unsorted or duplicate type", |b| {
            b.semantics.types.reverse()
        }),
        ("unsorted or duplicate type", |b| {
            b.semantics.types.push(record(PARENT))
        }),
        ("invalid type", |b| {
            b.semantics.types.last_mut().unwrap().ty = BundleTypeId(99)
        }),
        ("empty future evidence", |b| {
            b.semantics.types[0]
                .future
                .as_mut()
                .unwrap()
                .evidence
                .clear()
        }),
        ("duplicate future evidence", |b| {
            b.semantics.types[0]
                .future
                .as_mut()
                .unwrap()
                .evidence
                .push(FutureEvidence::DelegatedBy { parent: PARENT })
        }),
        ("invalid or empty string", |b| {
            b.semantics.types[0].issues.push(SemanticIssue {
                kind: SemanticIssueKind::NoRule,
                detail: Some(StrRef(99)),
            })
        }),
        ("invalid rule", |b| {
            if let Continuation::Bound { rule, .. } = continuation(b) {
                *rule = SemanticRuleId(99);
            }
        }),
        ("unknown rule revision", |b| {
            b.semantics.rules[0].revision = 2
        }),
        ("unknown rule revision", |b| {
            b.semantics.rules[0].revision = 0
        }),
        ("invalid origin", |b| {
            b.semantics.rules[0].origin = SemanticOriginId(99)
        }),
        ("incompatible capability", |b| {
            b.semantics.rules[0].kind = SemanticRuleKind::StdBoxAccess
        }),
        ("duplicate semantic origin", |b| {
            b.semantics.origins.push(b.semantics.origins[0].clone())
        }),
        ("duplicate semantic rule", |b| {
            b.semantics.rules.push(b.semantics.rules[0].clone())
        }),
        ("invalid Rust producer", |b| {
            b.semantics.origins[0] = SemanticOrigin::Rustc {
                producer: StrRef(9),
                family: StrRef(7),
            }
        }),
        ("compiler origin", |b| {
            b.semantics.origins[0] = delegation_origin(StrRef(18));
        }),
        ("missing delegation parent", |b| {
            b.semantics.types[0].future.as_mut().unwrap().evidence =
                vec![FutureEvidence::DelegatedBy {
                    parent: BundleTypeId(99),
                }]
        }),
        ("no bound program", |b| {
            *continuation(b) = Continuation::Unknown(issue())
        }),
        ("wrong future", |b| {
            b.semantics.types[0].future.as_mut().unwrap().evidence =
                vec![FutureEvidence::TaskEntry(TaskEntryId(99))]
        }),
        ("lacks its layout", |b| {
            b.semantics.types[0].future.as_mut().unwrap().evidence =
                vec![FutureEvidence::Coroutine(SemanticRuleId(0))]
        }),
        ("exact symbol candidate", |b| {
            b.semantics.types[0].future.as_mut().unwrap().evidence =
                vec![FutureEvidence::PollSymbol(FIELD)]
        }),
    ];
    for (expected, mutate) in cases {
        let mut b = forwarding();
        mutate(&mut b);
        bad(&b, expected);
    }
}

#[test]
fn test_semantic_paths_reject_invalid_storage_and_endpoints() {
    type Mutation = (&'static str, fn(&mut Bundle));
    let cases: &[Mutation] = &[
        ("named members", |b| {
            target_path(b).steps = vec![Step::Member(MemberRef::Index(0))]
        }),
        ("explicit variants", |b| {
            target_path(b).steps = vec![Step::ActiveVariant]
        }),
        ("no unique member", |b| {
            target_path(b).steps = vec![named(VARIANT)]
        }),
        ("endpoint type", |b| target_path(b).target = BundleTypeId(0)),
        ("invalid type", |b| target_path(b).target = BundleTypeId(99)),
        ("empty self delegation", |b| {
            *target_path(b) = path(vec![], PARENT)
        }),
        ("non-pointer", |b| target_path(b).steps = vec![Step::Deref]),
        ("out of bounds", |b| {
            if let TypeDef::Struct { members, .. } = &mut b.types.types[3] {
                members[0].offset = 9;
            }
        }),
        ("out of bounds", |b| {
            if let TypeDef::Struct { members, .. } = &mut b.types.types[3] {
                members[0].offset = u64::MAX;
            }
        }),
        ("no unique member", |b| {
            if let TypeDef::Struct { members, .. } = &mut b.types.types[3] {
                members.push(members[0].clone());
            }
        }),
        ("union crossing", |b| {
            b.types.types[3] = TypeDef::Union {
                name: StrRef(3),
                size: 16,
                members: vec![MemberDef {
                    name: FIELD,
                    ty: CHILD,
                    offset: 8,
                }],
            }
        }),
        ("out of bounds", |b| {
            b.types.types[1] = TypeDef::Opaque {
                name: FIELD,
                size: Some(8),
            }
        }),
    ];
    for (expected, mutate) in cases {
        let mut b = forwarding();
        b.semantics.types.remove(0);
        mutate(&mut b);
        bad(&b, expected);
    }
}

#[test]
fn test_semantic_delegation_can_reach_another_value_of_the_same_type() {
    let mut b = base();
    let TypeDef::Struct { members, .. } = &mut b.types.types[PARENT.0 as usize] else {
        unreachable!()
    };
    members[0].ty = BundleTypeId(10); // A pointer back to Parent.
    let mut parent = record(PARENT);
    parent.future.as_mut().unwrap().continuation = delegate(FutureTarget::Value(path(
        vec![named(FIELD), Step::Deref],
        PARENT,
    )));
    b.semantics.types = vec![parent];
    // Repeated type ids do not prove an address cycle. The runtime checks
    // the reached value; only an empty static self route is invalid here.
    b.validate().unwrap();
    *target_path(&mut b) = path(vec![], PARENT);
    bad(&b, "empty self delegation");
}

fn set_exclusive(b: &mut Bundle) {
    let Continuation::Bound {
        program: PollProgram::Direct(PollAction::Delegate { exclusive, .. }),
        ..
    } = continuation(b)
    else {
        unreachable!()
    };
    *exclusive = true;
}

/// The bit is a property of the rule revision, not of the path: the
/// reviewed std adapters and compiler coroutines may carry it, a
/// callback-bearing wrapper under the same single-path program may not.
#[test]
fn test_semantic_exclusivity_is_reviewed_per_rule_kind() {
    for kind in [
        SemanticRuleKind::StdPinBoxPoll,
        SemanticRuleKind::StdBoxPoll,
        SemanticRuleKind::StdMutRefPoll,
        SemanticRuleKind::StdPinMutRefPoll,
    ] {
        let mut b = forwarding();
        b.semantics.rules[0].kind = kind;
        set_exclusive(&mut b);
        b.validate().unwrap_or_else(|e| panic!("{kind:?}: {e}"));
    }
    let mut b = forwarding();
    b.semantics.rules[0].kind = SemanticRuleKind::TracingInstrumented;
    b.semantics.origins[0] = delegation_origin(StrRef(18));
    b.validate().unwrap();
    set_exclusive(&mut b);
    bad(&b, "unreviewed delegation exclusivity");
}

#[test]
fn test_semantic_evidence_requires_an_independent_seed() {
    let mut b = forwarding();
    b.types.types[1] = TypeDef::Struct {
        name: FIELD,
        size: 8,
        members: vec![MemberDef {
            name: FIELD,
            ty: BundleTypeId(10),
            offset: 0,
        }],
    };
    let child = b.semantics.types[0].future.as_mut().unwrap();
    child.continuation = delegate(FutureTarget::Value(path(
        vec![named(FIELD), Step::Deref],
        PARENT,
    )));
    // The cycle is supported while the parent has independent poll evidence.
    b.validate().unwrap();
    b.semantics.types[1].future.as_mut().unwrap().evidence =
        vec![FutureEvidence::DelegatedBy { parent: CHILD }];
    bad(&b, "no independent seed");
    b.semantics.types[0]
        .future
        .as_mut()
        .unwrap()
        .evidence
        .insert(0, FutureEvidence::PollSymbol(POLL));
    b.validate().unwrap();
}

fn coroutine() -> Bundle {
    let mut b = base();
    b.semantics.rules[0].kind = SemanticRuleKind::RustcAsyncFn;
    let mut r = record(STATE);
    r.storage = StoragePolicy::CoroutineStates;
    r.coroutine = Some(CoroutineLayout {
        rule: SemanticRuleId(0),
        states: vec![CoroutineState {
            variant: VARIANT,
            stage: CoroutinePhase::Suspended,
            locals: vec![FIELD],
            uncertain_locals: vec![],
        }],
    });
    r.future.as_mut().unwrap().evidence = vec![FutureEvidence::Coroutine(SemanticRuleId(0))];
    r.future.as_mut().unwrap().continuation = Continuation::Bound {
        rule: SemanticRuleId(0),
        program: PollProgram::MatchVariant {
            state: path(vec![], STATE),
            cases: vec![PollCase {
                variant: VARIANT,
                action: PollAction::Delegate {
                    target: FutureTarget::Value(path(
                        vec![Step::Variant(VARIANT), named(FIELD)],
                        CHILD,
                    )),
                    exclusive: false,
                },
            }],
        },
    };
    b.semantics.types = vec![r];
    b.validate().unwrap();
    b
}

fn cases(b: &mut Bundle) -> &mut Vec<PollCase> {
    let Continuation::Bound {
        program: PollProgram::MatchVariant { cases, .. },
        ..
    } = continuation(b)
    else {
        unreachable!()
    };
    cases
}

#[test]
fn test_semantic_coroutine_cases_and_locals_use_final_payloads() {
    type Mutation = (&'static str, fn(&mut Bundle));
    let mutations: &[Mutation] = &[
        ("missing poll cases", |b| cases(b).clear()),
        ("duplicate poll case", |b| {
            let c = cases(b)[0].clone();
            cases(b).push(c);
        }),
        ("unknown variant", |b| cases(b)[0].variant = FIELD),
        ("selected variant guard", |b| {
            if let TypeDef::Enum { shape, .. } = &mut b.types.types[4] {
                let mut variant = shape.variants[0].clone();
                variant.name = FIELD;
                variant.discr_values = Some(DiscrValues(vec![DiscrValue::Value(1)]));
                shape.variants.push(variant);
                shape.discr = Some(DiscrDef {
                    offset: 0,
                    ty: BundleTypeId(0),
                });
            }
            let mut state = b.semantics.types[0].coroutine.as_ref().unwrap().states[0].clone();
            state.variant = FIELD;
            b.semantics.types[0]
                .coroutine
                .as_mut()
                .unwrap()
                .states
                .push(state);
            let mut case = cases(b)[0].clone();
            case.variant = FIELD;
            case.action = PollAction::Unknown(issue());
            cases(b).push(case);
            if let PollAction::Delegate {
                target: FutureTarget::Value(p),
                ..
            } = &mut cases(b)[0].action
            {
                p.steps[0] = Step::Variant(FIELD);
            }
        }),
        ("duplicate or overlapping", |b| {
            b.semantics.types[0].coroutine.as_mut().unwrap().states[0]
                .uncertain_locals
                .push(FIELD)
        }),
        ("missing coroutine local", |b| {
            b.semantics.types[0].coroutine.as_mut().unwrap().states[0].locals = vec![VARIANT]
        }),
        ("terminal coroutine state has locals", |b| {
            b.semantics.types[0].coroutine.as_mut().unwrap().states[0].stage =
                CoroutinePhase::Returned
        }),
        ("unknown coroutine state has initialized locals", |b| {
            b.semantics.types[0].coroutine.as_mut().unwrap().states[0].stage =
                CoroutinePhase::Unknown
        }),
        ("missing coroutine states", |b| {
            b.semantics.types[0]
                .coroutine
                .as_mut()
                .unwrap()
                .states
                .clear()
        }),
        ("requires state storage", |b| {
            b.semantics.types[0].storage = StoragePolicy::Unavailable(issue())
        }),
        ("coroutine cannot use declared", |b| {
            b.semantics.types[0].storage = StoragePolicy::DeclaredMembers
        }),
        ("disagrees with coroutine stage", |b| {
            cases(b)[0].action = PollAction::Returned
        }),
        ("different state or rule", |b| {
            b.semantics.rules.push(SemanticRule {
                kind: SemanticRuleKind::RustcAsyncBlock,
                revision: 1,
                origin: SemanticOriginId(0),
            });
            let Continuation::Bound { rule, .. } = continuation(b) else {
                unreachable!()
            };
            *rule = SemanticRuleId(1);
        }),
    ];
    for (expected, mutate) in mutations {
        let mut b = coroutine();
        mutate(&mut b);
        bad(&b, expected);
    }
    let mut b = coroutine();
    let state = &mut b.semantics.types[0].coroutine.as_mut().unwrap().states[0];
    state.stage = CoroutinePhase::Unknown;
    state.uncertain_locals = std::mem::take(&mut state.locals);
    cases(&mut b)[0].action = PollAction::Unknown(issue());
    b.validate().unwrap();
}

fn resource() -> Bundle {
    let mut b = base();
    b.semantics.origins[0] = SemanticOrigin::LibraryLayout {
        package: StrRef(8),
        version: Some(StrRef(9)),
        family: StrRef(10),
        selection: LayoutSelection::ReviewedRange,
    };
    b.semantics.rules[0].kind = SemanticRuleKind::TokioJoinHandle;
    let mut r = record(PARENT);
    r.resource = Some(ResourceBinding {
        rule: SemanticRuleId(0),
        kind: ResourceKind::JoinHandle,
        state_rule: None,
        exclusive_pending: false,
    });
    r.future.as_mut().unwrap().continuation = Continuation::Bound {
        rule: SemanticRuleId(0),
        program: PollProgram::Direct(PollAction::Primitive),
    };
    b.semantics.types = vec![r];
    b.walks.entries.insert(
        WalkRole::JoinHandleRaw,
        WalkBinding {
            roots: vec![PARENT],
            steps: vec![named(FIELD)],
            outcome: WalkOutcome::Bound {
                spelling: 0,
                spellings: 1,
                note: None,
            },
        },
    );
    b.validate().unwrap();
    b
}

#[test]
fn test_semantic_resource_layout_is_separate_from_state_and_exclusivity() {
    let mut b = resource();
    b.semantics.types[0].future = None;
    b.validate().unwrap();
    b.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&b, "unavailable storage carries a readable capability");
    let mut b = resource();
    b.semantics.types[0]
        .resource
        .as_mut()
        .unwrap()
        .exclusive_pending = true;
    bad(&b, "unreviewed exclusive-pending");
    let mut b = resource();
    b.walks.entries.clear();
    bad(&b, "essential walk role");
    let mut b = resource();
    b.walks
        .entries
        .get_mut(&WalkRole::JoinHandleRaw)
        .unwrap()
        .roots = vec![CHILD];
    bad(&b, "essential walk role");
    let mut b = resource();
    b.semantics.types[0].resource = None;
    bad(&b, "primitive has no compatible resource");
    // A state protocol binds only where the origin's version sits inside
    // the reviewed range; a guessed family observes and never assesses.
    // With the protocol bound, the exclusive-pending guarantee it
    // reviews is admitted too — and only then.
    for selection in [
        LayoutSelection::BelowFloor,
        LayoutSelection::AboveReviewedRange,
        LayoutSelection::ReviewedRange,
    ] {
        let mut b = resource();
        if let SemanticOrigin::LibraryLayout { selection: s, .. } = &mut b.semantics.origins[0] {
            *s = selection;
        }
        b.validate().unwrap();
        b.semantics.rules.push(SemanticRule {
            kind: SemanticRuleKind::TokioJoinHandleState,
            revision: 1,
            origin: SemanticOriginId(0),
        });
        b.semantics.types[0].resource.as_mut().unwrap().state_rule = Some(SemanticRuleId(1));
        if selection == LayoutSelection::ReviewedRange {
            b.validate().unwrap();
            b.semantics.types[0]
                .resource
                .as_mut()
                .unwrap()
                .exclusive_pending = true;
            b.validate().unwrap();
            // The protocol's kind must be the resource's own.
            b.semantics.rules[1].kind = SemanticRuleKind::TokioAcquireState;
            bad(&b, "incompatible capability");
        } else {
            bad(&b, "state rule requires a reviewed range");
        }
    }
}

/// A tracing delegation origin over the given source path: the crate,
/// version and family the fixture strings spell, with one checksum.
fn delegation_origin(source: StrRef) -> SemanticOrigin {
    SemanticOrigin::LibraryDelegation {
        package: StrRef(12),
        version: StrRef(13),
        family: StrRef(17),
        source,
        files: vec![SourceFileEvidence {
            file: StrRef(11),
            md5: [7; 16],
        }],
    }
}

/// The origin is the registry path: it has to parse under the cargo
/// convention, anchored at its `registry/src/` segment, and name the
/// crate and version the record claims. Checksums corroborate when a
/// file table carried them and are absent otherwise; a file listed
/// twice is still malformed.
#[test]
fn test_semantic_delegation_origin_is_its_registry_path() {
    let mut b = forwarding();
    b.semantics.rules[0].kind = SemanticRuleKind::TracingInstrumented;
    b.semantics.origins[0] = delegation_origin(StrRef(18));
    b.validate().unwrap();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
    if let SemanticOrigin::LibraryDelegation { files, .. } = &mut b.semantics.origins[0] {
        files.push(files[0].clone());
    }
    bad(&b, "duplicate source checksum file");
    if let SemanticOrigin::LibraryDelegation { files, .. } = &mut b.semantics.origins[0] {
        files.clear();
    }
    b.validate().unwrap();
    // A vendored tree is not an origin; a registry path that spells
    // another version is somebody else's review.
    b.semantics.origins[0] = delegation_origin(StrRef(19));
    bad(&b, "not a registry path");
    b.semantics.origins[0] = delegation_origin(StrRef(20));
    bad(&b, "another crate or version");
    // Each delegation kind names the crate whose implementation it
    // runs; another crate's origin, however well-formed, is not it.
    for (kind, package, version, source) in [
        (
            SemanticRuleKind::HyperUtilTokioSleep,
            StrRef(25),
            StrRef(26),
            StrRef(27),
        ),
        (
            SemanticRuleKind::FuturesUtilNext,
            StrRef(22),
            StrRef(23),
            StrRef(24),
        ),
        // tokio's own async fn, read like a third-party rule off the
        // closure's declaration file.
        (
            SemanticRuleKind::TokioIntervalTick,
            StrRef(8),
            StrRef(9),
            StrRef(36),
        ),
    ] {
        let mut b = forwarding();
        b.semantics.rules[0].kind = kind;
        b.semantics.origins[0] = SemanticOrigin::LibraryDelegation {
            package,
            version,
            family: StrRef(17),
            source,
            files: Vec::new(),
        };
        b.validate().unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        // tracing's origin is somebody else's review.
        b.semantics.origins[0] = delegation_origin(StrRef(18));
        bad(&b, "third-party delegation needs source evidence");
    }
    // A sole-member forwarder binds on its layout, under its crate's
    // layout origin, versioned or not: a declaration origin, even its
    // own crate's, is not that evidence, and another crate's layout is
    // another crate's.
    let layout = |package, version| SemanticOrigin::LibraryLayout {
        package,
        version,
        family: StrRef(10),
        selection: match version {
            Some(_) => LayoutSelection::ReviewedRange,
            None => LayoutSelection::VersionUnknown,
        },
    };
    // Each row: the kind, its crate, the version the layout origin
    // may or may not carry, another crate, and a well-formed
    // declaration origin of its own crate.
    for (kind, package, version, other, declared) in [
        (
            SemanticRuleKind::FuturesUtilMapErr,
            StrRef(22),
            None,
            StrRef(8),
            (StrRef(23), StrRef(24)),
        ),
        (
            SemanticRuleKind::FuturesUtilIntoFuture,
            StrRef(22),
            None,
            StrRef(8),
            (StrRef(23), StrRef(24)),
        ),
        (
            SemanticRuleKind::TokioCoop,
            StrRef(8),
            Some(StrRef(9)),
            StrRef(22),
            (StrRef(9), StrRef(28)),
        ),
        (
            SemanticRuleKind::TokioCoop,
            StrRef(8),
            None,
            StrRef(22),
            (StrRef(9), StrRef(28)),
        ),
    ] {
        let mut b = forwarding();
        b.semantics.rules[0].kind = kind;
        b.semantics.origins[0] = layout(package, version);
        b.validate().unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        b.semantics.origins[0] = layout(other, version);
        bad(&b, "layout rule has an incompatible library origin");
        b.semantics.origins[0] = SemanticOrigin::LibraryDelegation {
            package,
            version: declared.0,
            family: StrRef(17),
            source: declared.1,
            files: Vec::new(),
        };
        bad(&b, "layout rule has an incompatible library origin");
    }
    // The `map` kind is both: the newtype on its layout, the enum it
    // forwards into off its declaration — either of futures-util's
    // origins, and no other crate's of either sort.
    let mut b = forwarding();
    b.semantics.rules[0].kind = SemanticRuleKind::FuturesUtilMap;
    b.semantics.origins[0] = layout(StrRef(22), None);
    b.validate().unwrap();
    b.semantics.origins[0] = SemanticOrigin::LibraryDelegation {
        package: StrRef(22),
        version: StrRef(23),
        family: StrRef(17),
        source: StrRef(24),
        files: Vec::new(),
    };
    b.validate().unwrap();
    b.semantics.origins[0] = layout(StrRef(8), None);
    bad(&b, "futures-util map rule needs a futures-util origin");
    b.semantics.origins[0] = delegation_origin(StrRef(18));
    bad(&b, "futures-util map rule needs a futures-util origin");
}

fn dynamic() -> Bundle {
    let mut b = base();
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::DynFutureAbi,
        revision: 1,
        origin: SemanticOriginId(0),
    });
    let mut r = record(BundleTypeId(9));
    r.future.as_mut().unwrap().continuation = delegate(FutureTarget::Dynamic {
        pointer: path(vec![], BundleTypeId(9)),
        layout: DynFutureLayout {
            abi: SemanticRuleId(1),
            data: path(vec![named(StrRef(14))], BundleTypeId(7)),
            vtable: path(vec![named(StrRef(15))], BundleTypeId(8)),
            trait_ty: BundleTypeId(6),
            drop_slot: 0,
            size_slot: 1,
            align_slot: 2,
            poll_slot: Some(3),
        },
    });
    b.semantics.types = vec![r];
    b.validate().unwrap();
    b
}

fn dyn_layout(b: &mut Bundle) -> &mut DynFutureLayout {
    let Continuation::Bound {
        program:
            PollProgram::Direct(PollAction::Delegate {
                target: FutureTarget::Dynamic { layout, .. },
                ..
            }),
        ..
    } = continuation(b)
    else {
        unreachable!()
    };
    layout
}

#[test]
fn test_semantic_dynamic_targets_validate_bases_fields_trait_and_slots() {
    let mut b = dynamic();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
    // rustc spells the pointee as an empty zero-sized struct; a member
    // or a size makes it something else.
    b.types.types[6] = TypeDef::Struct {
        name: StrRef(16),
        size: 0,
        members: Vec::new(),
    };
    b.validate().unwrap();
    if let TypeDef::Struct { size, .. } = &mut b.types.types[6] {
        *size = 8;
    }
    bad(&b, "not a trait object");
    if let TypeDef::Struct { size, members, .. } = &mut b.types.types[6] {
        *size = 0;
        members.push(MemberDef {
            name: FIELD,
            ty: BundleTypeId(0),
            offset: 0,
        });
    }
    bad(&b, "not a trait object");
    let mut b = dynamic();
    dyn_layout(&mut b).poll_slot = Some(4);
    bad(&b, "dyn ABI slots");
    let mut b = dynamic();
    dyn_layout(&mut b).trait_ty = BundleTypeId(0);
    bad(&b, "wrong pointee");
    let mut b = dynamic();
    dyn_layout(&mut b).data.steps = vec![named(FIELD)];
    bad(&b, "no unique member");
    let mut b = dynamic();
    dyn_layout(&mut b).abi = SemanticRuleId(0);
    bad(&b, "incompatible capability");
    let mut b = dynamic();
    dyn_layout(&mut b).vtable = path(vec![], BundleTypeId(9));
    bad(&b, "distinct inline words");
    let mut b = dynamic();
    if let TypeDef::Struct { members, .. } = &mut b.types.types[9] {
        members[1].ty = BundleTypeId(0);
    }
    if let TypeDef::Base { size, .. } = &mut b.types.types[0] {
        *size = 4;
    }
    dyn_layout(&mut b).vtable.target = BundleTypeId(0);
    bad(&b, "pointer sized");
}

/// A trait object of a trait that merely has `Future` as a supertrait
/// is a legal dyn target — polling the adapter over it proves whatever
/// the pointer holds a future — but where that trait puts the poll is
/// its own declaration's business, so such a layout claims no poll slot
/// and is identified by its drop glue. Claiming one anyway is refused.
#[test]
fn test_a_dyn_target_of_another_trait_claims_no_poll_slot() {
    let mut b = dynamic();
    if let TypeDef::Opaque { name, .. } = &mut b.types.types[6] {
        *name = StrRef(21);
    }
    bad(&b, "a poll slot needs a Future trait object");
    dyn_layout(&mut b).poll_slot = None;
    b.validate().unwrap();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
    // Dropping the slot never excuses the rest of the ABI.
    dyn_layout(&mut b).align_slot = 3;
    bad(&b, "dyn ABI slots");
}

#[test]
fn test_semantic_storage_candidates_exclude_generic_arguments() {
    for (name, candidate) in [
        ("app::work::{async_fn_env#0}", true),
        ("app::work<T>::{async_block_env#0}<U>", true),
        ("app::{coroutine_env#0}", true),
        ("app::{async_closure_env#0}", true),
        ("app::{closure_env#0}", false),
        ("Wrapper<app::work::{async_fn_env#0}>", false),
        ("app::work::{async_fn_env#0}::Returned", false),
        ("&mut app::work::{async_fn_env#0}", false),
        ("&app::work::{async_block_env#0}", false),
        ("*const app::work::{async_fn_env#0}", false),
    ] {
        assert_eq!(names::is_coroutine_candidate(name), candidate, "{name}");
    }
    let mut b = base();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let name = strings.intern("app::work::{async_fn_env#0}");
    b.strings = strings.finish();
    if let TypeDef::Struct { name: n, .. } = &mut b.types.types[3] {
        *n = name;
    }
    b.semantics.types = vec![record(PARENT)];
    bad(&b, "unsupported compiler storage");
    b.semantics.types[0].storage = StoragePolicy::Unavailable(SemanticIssue {
        kind: SemanticIssueKind::UnsupportedOrigin,
        detail: None,
    });
    b.validate().unwrap();
    b.semantics.types[0].storage = StoragePolicy::CoroutineStates;
    bad(&b, "state storage lacks coroutine layout");
}

#[test]
fn test_semantic_access_does_not_supply_future_identity() {
    // The std kinds bind under the compiler origin the base bundle
    // carries; the two library routes are owned storage under their
    // crate's delegation origin, and nothing else may carry them.
    for (kind, rule, origin) in [
        (AccessKind::Owned, SemanticRuleKind::StdBoxAccess, None),
        (AccessKind::Owned, SemanticRuleKind::StdPinBoxAccess, None),
        (
            AccessKind::Borrowed,
            SemanticRuleKind::StdMutRefAccess,
            None,
        ),
        (
            AccessKind::Borrowed,
            SemanticRuleKind::StdPinMutRefAccess,
            None,
        ),
        (
            AccessKind::Owned,
            SemanticRuleKind::TokioStreamWatchStream,
            Some((StrRef(29), StrRef(30), StrRef(31))),
        ),
        (
            AccessKind::Owned,
            SemanticRuleKind::TokioUtilReusableBox,
            Some((StrRef(32), StrRef(33), StrRef(34))),
        ),
    ] {
        let mut b = base();
        b.semantics.rules[0].kind = rule;
        if let Some((package, version, source)) = origin {
            b.semantics.origins[0] = SemanticOrigin::LibraryDelegation {
                package,
                version,
                family: StrRef(17),
                source,
                files: Vec::new(),
            };
        }
        let mut r = record(PARENT);
        r.future = None;
        r.access = Some(AccessBinding {
            rule: SemanticRuleId(0),
            kind,
            target: FutureTarget::Value(path(vec![named(FIELD)], CHILD)),
        });
        b.semantics.types = vec![r];
        b.validate().unwrap();
        b.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
        bad(&b, "unavailable storage carries a readable capability");
        b.semantics.types[0].storage = StoragePolicy::DeclaredMembers;
        b.semantics.types[0].access.as_mut().unwrap().kind = match kind {
            AccessKind::Owned => AccessKind::Borrowed,
            AccessKind::Borrowed => AccessKind::Owned,
        };
        bad(&b, "incompatible capability");
        // A library route names its own crate's declaration: under a
        // compiler origin, or another crate's, it is not that route.
        if origin.is_some() {
            b.semantics.types[0].access.as_mut().unwrap().kind = kind;
            b.validate().unwrap();
            b.semantics.origins[0] = delegation_origin(StrRef(18));
            bad(&b, "third-party delegation needs source evidence");
        }
    }
}

#[test]
fn test_semantic_primitives_require_each_essential_role() {
    for (kind, rule, roles) in [
        (
            ResourceKind::Sleep,
            SemanticRuleKind::TokioSleep,
            vec![WalkRole::SleepDeadline],
        ),
        (
            ResourceKind::SemaphoreAcquire,
            SemanticRuleKind::TokioAcquire,
            vec![
                WalkRole::AcquireSemaphore,
                WalkRole::AcquireNode,
                WalkRole::AcquireNumPermits,
                WalkRole::AcquireNeeded,
                WalkRole::AcquireQueued,
            ],
        ),
    ] {
        let mut b = resource();
        b.semantics.rules[0].kind = rule;
        b.semantics.types[0].resource.as_mut().unwrap().kind = kind;
        let walk = b.walks.entries[&WalkRole::JoinHandleRaw].clone();
        b.walks.entries = roles.iter().map(|r| (*r, walk.clone())).collect();
        b.validate().unwrap();
        for role in roles {
            let mut missing = b.clone();
            missing.walks.entries.remove(&role);
            bad(&missing, "essential walk role");
        }
    }
    // A readiness await's essential routes are its own node and the
    // registration it names; an operation over a stream has none, its
    // stream reached by the record's own binding (tested with it).
    for (operation, roles, routes) in [(
        IoOperationKind::Readiness,
        vec![
            WalkRole::ReadinessScheduledIo,
            WalkRole::ReadinessState,
            WalkRole::ReadinessWaiter,
        ],
        vec![
            WalkRole::ReadinessWaiterWaker,
            WalkRole::ReadinessWaiterInterest,
            WalkRole::ReadinessWaiterReady,
        ],
    )] {
        let mut b = resource();
        b.semantics.rules[0].kind = SemanticRuleKind::TokioIoOperation;
        b.semantics.types[0].resource.as_mut().unwrap().kind = ResourceKind::IoOperation(operation);
        let walk = b.walks.entries[&WalkRole::JoinHandleRaw].clone();
        // A route roots where its parent landed, so it is bound at some
        // other type; only being bound is required of it.
        let route = WalkBinding {
            roots: vec![CHILD],
            ..walk.clone()
        };
        b.walks.entries = roles
            .iter()
            .map(|r| (*r, walk.clone()))
            .chain(routes.iter().map(|r| (*r, route.clone())))
            .collect();
        b.validate().unwrap();
        for role in &roles {
            let mut missing = b.clone();
            missing.walks.entries.remove(role);
            bad(&missing, "essential walk role");
            missing.walks.entries.insert(*role, route.clone());
            bad(&missing, "essential walk role");
        }
        for role in &routes {
            let mut missing = b.clone();
            missing.walks.entries.remove(role);
            bad(&missing, "essential walk route");
            missing.walks.entries.insert(
                *role,
                WalkBinding {
                    roots: Vec::new(),
                    steps: Vec::new(),
                    outcome: WalkOutcome::Absent {
                        reason: "none".into(),
                    },
                },
            );
            bad(&missing, "essential walk route");
        }
        let mut contained = b.clone();
        contained.walks.entries = [WalkRole::UnixStreamShared, WalkRole::TcpStreamShared]
            .into_iter()
            .map(|role| (role, walk.clone()))
            .collect();
        bad(&contained, "essential walk role");
    }
}

/// The stage route lands on the entry's recorded future, exactly: a
/// route bound at an entry's cell whose endpoint is any other type —
/// a payload one level short, a peeled member one level past — does
/// not load. A route bound at other cells says nothing about this one.
#[test]
fn test_the_stage_route_ends_at_the_entrys_future() {
    let mut b = resource();
    // The cell stands in for the enum: the route selects its one variant
    // and the payload's member, landing on `CHILD`.
    b.tasks.entries.push(TaskFutureEntry {
        future: CHILD,
        cell: STATE,
        stage: STATE,
        scheduler: CHILD,
        scheduler_binding: None,
        display_name: StrRef(3),
    });
    b.tasks
        .by_symbol
        .insert("_RINvNtNtNtC_5tokio_pollE".into(), vec![TaskEntryId(0)]);
    b.provenance.entries.push(Provenance {
        decl: None,
        kind: FutureKind::Manual,
    });
    b.semantics.types[0].ty = CHILD;
    let evidence = &mut b.semantics.types[0].future.as_mut().unwrap().evidence;
    evidence.insert(0, FutureEvidence::TaskEntry(TaskEntryId(0)));
    b.walks
        .entries
        .get_mut(&WalkRole::JoinHandleRaw)
        .unwrap()
        .roots = vec![CHILD];
    let route = |roots: Vec<BundleTypeId>, steps: Vec<Step>| WalkBinding {
        roots,
        steps,
        outcome: WalkOutcome::Bound {
            spelling: 0,
            spellings: 1,
            note: None,
        },
    };
    b.walks.entries.insert(
        WalkRole::CellStageRunning,
        route(vec![STATE], vec![Step::Variant(VARIANT), named(FIELD)]),
    );
    b.validate().unwrap();
    // One level short: the payload, not the future.
    b.walks.entries.insert(
        WalkRole::CellStageRunning,
        route(vec![STATE], vec![Step::Variant(VARIANT)]),
    );
    bad(
        &b,
        "stage route lands on type [3], not the entry's future 1",
    );
    // Bound at some other cell: nothing is said about this entry.
    b.walks.entries.insert(
        WalkRole::CellStageRunning,
        route(vec![PARENT], vec![named(FIELD)]),
    );
    b.validate().unwrap();
}

/// A task entry's scheduler class is a layout fact about its own `S`:
/// the class's route must have bound at exactly that type.
#[test]
fn test_semantic_scheduler_binding_requires_the_class_route_at_its_own_type() {
    let mut b = resource();
    b.tasks.entries.push(TaskFutureEntry {
        future: PARENT,
        cell: PARENT,
        stage: PARENT,
        scheduler: CHILD,
        scheduler_binding: None,
        display_name: StrRef(3),
    });
    b.tasks
        .by_symbol
        .insert("_RINvNtNtNtC_5tokio_pollE".into(), vec![TaskEntryId(0)]);
    b.provenance.entries.push(Provenance {
        decl: None,
        kind: FutureKind::Manual,
    });
    let evidence = &mut b.semantics.types[0].future.as_mut().unwrap().evidence;
    evidence.insert(0, FutureEvidence::TaskEntry(TaskEntryId(0)));
    b.validate().unwrap();

    let walk = b.walks.entries[&WalkRole::JoinHandleRaw].clone();
    let route = |root| WalkBinding {
        roots: vec![root],
        ..walk.clone()
    };
    for (class, rule, role) in [
        (
            SchedulerClass::MultiThread,
            SemanticRuleKind::TokioMultiThreadScheduler,
            WalkRole::MtSchedulerHandle,
        ),
        (
            SchedulerClass::CurrentThread,
            SemanticRuleKind::TokioCurrentThreadScheduler,
            WalkRole::CtSchedulerHandle,
        ),
        (
            SchedulerClass::LocalSet,
            SemanticRuleKind::TokioLocalScheduler,
            WalkRole::LocalSchedulerShared,
        ),
        (
            SchedulerClass::Blocking,
            SemanticRuleKind::TokioBlockingScheduler,
            WalkRole::BlockingScheduleHooks,
        ),
    ] {
        let mut b = b.clone();
        b.semantics.rules.push(SemanticRule {
            kind: rule,
            revision: 1,
            origin: SemanticOriginId(0),
        });
        b.tasks.entries[0].scheduler_binding = Some(SchedulerBinding {
            class,
            rule: SemanticRuleId(1),
        });
        bad(&b, "essential walk role");
        b.walks.entries.insert(role, route(CHILD));
        b.validate().unwrap();
        // Bound at some other type: the shared-state walks root elsewhere
        // and prove nothing about this entry's S.
        b.walks.entries.insert(role, route(PARENT));
        bad(&b, "essential walk role");
        b.walks.entries.insert(role, route(CHILD));
        // The rule kind must name the class.
        let other = match class {
            SchedulerClass::MultiThread => SemanticRuleKind::TokioCurrentThreadScheduler,
            _ => SemanticRuleKind::TokioMultiThreadScheduler,
        };
        b.semantics.rules[1].kind = other;
        bad(&b, "incompatible capability");
    }
}

#[test]
fn test_semantic_container_is_not_automatically_a_future() {
    let mut b = resource();
    b.semantics.rules[0].kind = SemanticRuleKind::TokioJoinSet;
    let r = &mut b.semantics.types[0];
    r.resource = None;
    r.future = None;
    r.container = Some(ContainerBinding {
        rule: SemanticRuleId(0),
        kind: ContainerKind::JoinSet,
        wakers: ContainerWakers::Own,
    });
    let walk = b.walks.entries[&WalkRole::JoinHandleRaw].clone();
    let route = WalkBinding {
        roots: vec![CHILD],
        ..walk.clone()
    };
    b.walks.entries = [
        (WalkRole::JoinSetLength, walk.clone()),
        (WalkRole::JoinSetLists, walk.clone()),
        (WalkRole::JoinSetNotifiedHead, route.clone()),
        (WalkRole::JoinSetIdleHead, route),
    ]
    .into_iter()
    .collect();
    b.validate().unwrap();
    let mut missing = b.clone();
    missing.walks.entries.remove(&WalkRole::JoinSetIdleHead);
    bad(&missing, "essential walk route");
    let mut missing = b.clone();
    missing.walks.entries.remove(&WalkRole::JoinSetLists);
    bad(&missing, "essential walk role");
    // The wakers flag is the kind's own fact, recorded beside it: a
    // set that claimed to forward the task's waker would be listed
    // as the task's branches.
    let mut forwarded = b.clone();
    forwarded.semantics.types[0]
        .container
        .as_mut()
        .unwrap()
        .wakers = ContainerWakers::Forwarded;
    bad(&forwarded, "container wakers disagree");
    b.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&b, "unavailable storage carries a readable capability");
    b.semantics.types[0].storage = StoragePolicy::DeclaredMembers;
    b.walks.entries.remove(&WalkRole::JoinSetIdleHead);
    bad(&b, "essential walk route");
}

/// A `StreamMap` container: its rule is the tokio-stream map kind
/// under that crate's delegation origin — the type's own declaration
/// file, like the watch stream's — its `entries` role bound at the
/// map and the entry route below it, and its children forwarded the
/// task's own waker.
#[test]
fn test_semantic_stream_map_container_forwards_the_task_waker() {
    let mut b = resource();
    b.semantics.rules[0].kind = SemanticRuleKind::TokioStreamStreamMap;
    b.semantics.origins[0] = SemanticOrigin::LibraryDelegation {
        package: StrRef(29),
        version: StrRef(30),
        family: StrRef(17),
        source: StrRef(35),
        files: Vec::new(),
    };
    let r = &mut b.semantics.types[0];
    r.resource = None;
    r.future = None;
    r.container = Some(ContainerBinding {
        rule: SemanticRuleId(0),
        kind: ContainerKind::StreamMap,
        wakers: ContainerWakers::Forwarded,
    });
    let walk = b.walks.entries[&WalkRole::JoinHandleRaw].clone();
    let route = WalkBinding {
        roots: vec![CHILD],
        ..walk.clone()
    };
    b.walks.entries = [
        (WalkRole::StreamMapEntries, walk),
        (WalkRole::StreamMapEntryStream, route),
    ]
    .into_iter()
    .collect();
    b.validate().unwrap();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
    let mut missing = b.clone();
    missing
        .walks
        .entries
        .remove(&WalkRole::StreamMapEntryStream);
    bad(&missing, "essential walk route");
    let mut missing = b.clone();
    missing.walks.entries.remove(&WalkRole::StreamMapEntries);
    bad(&missing, "essential walk role");
    // A map polls its entries with the task's context and nothing
    // else's; a set's kind under the map's rule is another review.
    let mut own = b.clone();
    own.semantics.types[0].container.as_mut().unwrap().wakers = ContainerWakers::Own;
    bad(&own, "container wakers disagree");
    let mut set = b.clone();
    set.semantics.types[0].container.as_mut().unwrap().kind = ContainerKind::FuturesUnordered;
    bad(&set, "incompatible capability");
    // The origin names the crate whose implementation was reviewed;
    // tokio-util's registry path, however well-formed, is not it.
    b.semantics.origins[0] = SemanticOrigin::LibraryDelegation {
        package: StrRef(32),
        version: StrRef(33),
        family: StrRef(17),
        source: StrRef(34),
        files: Vec::new(),
    };
    bad(&b, "third-party delegation needs source evidence");
}

#[test]
fn test_semantic_coroutine_cannot_delegate_through_uncertain_storage() {
    let mut b = coroutine();
    let state = &mut b.semantics.types[0].coroutine.as_mut().unwrap().states[0];
    state.uncertain_locals = std::mem::take(&mut state.locals);
    bad(&b, "delegate is not an initialized local");
    let mut b = coroutine();
    if let TypeDef::Enum { shape, .. } = &mut b.types.types[4] {
        shape.discr = Some(DiscrDef {
            ty: BundleTypeId(0),
            offset: 17,
        });
    }
    bad(&b, "discriminant is out of bounds");
    if let TypeDef::Enum { shape, .. } = &mut b.types.types[4] {
        shape.discr.as_mut().unwrap().offset = 16;
    }
    b.validate().unwrap();
}

/// A `select!` binding over a `PollFn`: `f` → `_ref__disabled` → `*`
/// lands on an unsigned word, `f` → `_ref__futures` → `*` on a tuple,
/// and every branch is one of the tuple's named members. The record's
/// storage is readable, the rule is the select kind under tokio's
/// registry origin, and each departure is refused by name.
#[test]
fn test_semantic_select_binding_reads_the_mask_and_the_tuple() {
    let mut b = base();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let name = |strings: &mut StringInterner, s: &str| strings.intern(s);
    let u8_name = name(&mut strings, "u8");
    let f = name(&mut strings, "f");
    let disabled = name(&mut strings, "_ref__disabled");
    let futures = name(&mut strings, "_ref__futures");
    let first = name(&mut strings, "__0");
    let tuple_name = name(&mut strings, "(child,)");
    let env_name = name(&mut strings, "app::run::{async_fn#0}::{closure_env#1}");
    let poll_fn_name = name(
        &mut strings,
        "core::future::poll_fn::PollFn<app::run::{async_fn#0}::{closure_env#1}>",
    );
    let tokio = name(&mut strings, "tokio");
    let version = name(&mut strings, "1.52.4");
    let family = name(&mut strings, "tokio-select-1.47");
    let source = name(
        &mut strings,
        "registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.52.4/src/macros/select.rs",
    );
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let next = b.types.types.len() as u32;
    let (u8_t, mask_ref, tuple, tuple_ref, env, poll_fn) = (
        BundleTypeId(next),
        BundleTypeId(next + 1),
        BundleTypeId(next + 2),
        BundleTypeId(next + 3),
        BundleTypeId(next + 4),
        BundleTypeId(next + 5),
    );
    b.types.types.extend([
        TypeDef::Base {
            name: u8_name,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Pointer {
            name: None,
            target: u8_t,
        },
        TypeDef::Struct {
            name: tuple_name,
            size: 8,
            members: vec![member(first, CHILD, 0)],
        },
        TypeDef::Pointer {
            name: None,
            target: tuple,
        },
        TypeDef::Struct {
            name: env_name,
            size: 16,
            members: vec![member(disabled, mask_ref, 0), member(futures, tuple_ref, 8)],
        },
        TypeDef::Struct {
            name: poll_fn_name,
            size: 16,
            members: vec![member(f, env, 0)],
        },
    ]);
    b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
        package: tokio,
        version,
        family,
        source,
        files: Vec::new(),
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::TokioSelect,
        revision: 1,
        origin: SemanticOriginId(1),
    });
    let capture = |member, target| TypedPath {
        steps: vec![named(f), named(member), Step::Deref],
        target,
    };
    // The binding is a layout fact beside whatever future evidence
    // the `PollFn` has; here it has none.
    let mut record = record(poll_fn);
    record.future = None;
    record.select = Some(SelectBinding {
        rule: SemanticRuleId(1),
        mask: capture(disabled, u8_t),
        futures: capture(futures, tuple),
        branches: vec![path(vec![named(first)], CHILD)],
        arms: vec![None],
    });
    b.semantics.types = vec![record];
    b.validate().unwrap();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    fn select(b: &mut Bundle) -> &mut SelectBinding {
        b.semantics.types[0].select.as_mut().unwrap()
    }
    // The rule has to be the select kind, under tokio's own origin.
    let mut wrong = b.clone();
    select(&mut wrong).rule = SemanticRuleId(0);
    bad(&wrong, "incompatible capability");
    let mut wrong = b.clone();
    wrong.semantics.origins[1] = SemanticOrigin::LibraryDelegation {
        package: StrRef(12),
        version: StrRef(13),
        family,
        source: StrRef(18),
        files: Vec::new(),
    };
    bad(&wrong, "third-party delegation needs source evidence");
    // Both routes end through the closure's reference.
    let mut wrong = b.clone();
    select(&mut wrong).mask = path(vec![named(f), named(disabled)], mask_ref);
    bad(&wrong, "mask is not reached through");
    let mut wrong = b.clone();
    select(&mut wrong).futures = path(vec![named(f), named(futures)], tuple_ref);
    bad(&wrong, "tuple is not reached through");
    // The mask is an unsigned word; a pointer to a `u64` struct is not.
    let mut wrong = b.clone();
    if let TypeDef::Pointer { target, .. } = &mut wrong.types.types[mask_ref.0 as usize] {
        *target = CHILD;
    }
    select(&mut wrong).mask = capture(disabled, CHILD);
    bad(&wrong, "mask is not an unsigned word");
    // Every branch is one named member of the tuple, once.
    let mut wrong = b.clone();
    select(&mut wrong).branches.clear();
    bad(&wrong, "select has no branches");
    let mut wrong = b.clone();
    let dup = select(&mut wrong).branches[0].clone();
    select(&mut wrong).branches.push(dup);
    bad(&wrong, "more branches than tuple members");
    // One arm per branch, and a written arm's file is a string the
    // bundle has.
    let mut wrong = b.clone();
    select(&mut wrong).arms.clear();
    bad(&wrong, "arms do not pair with its branches");
    let mut wrong = b.clone();
    select(&mut wrong).arms = vec![Some(SourceLoc {
        file: StrRef(u32::MAX),
        line: 286,
    })];
    bad(&wrong, "string");
    // The mask's bits bound the branches too: a nine-member tuple over
    // a `u8` mask is refused, eight members fill it exactly.
    let mut wide = b.clone();
    {
        let mut strings = StringInterner::new();
        for s in wide.strings.iter() {
            strings.intern(s);
        }
        let mut interned = Vec::new();
        for i in 0..9 {
            interned.push(strings.intern(&format!("__{i}")));
        }
        // `__0` was interned already and comes back as `first`; the
        // rest are new, in order.
        assert_eq!(interned[0], first);
        wide.strings = strings.finish();
        let TypeDef::Struct { members, size, .. } = &mut wide.types.types[tuple.0 as usize] else {
            panic!("the tuple is a struct");
        };
        *size = 72;
        *members = interned
            .iter()
            .enumerate()
            .map(|(i, &name)| member(name, CHILD, i as u64 * 8))
            .collect();
        select(&mut wide).branches = interned
            .iter()
            .map(|&name| path(vec![named(name)], CHILD))
            .collect();
        select(&mut wide).arms = vec![None; interned.len()];
    }
    bad(&wide, "more branches than tuple members or mask bits");
    select(&mut wide).branches.pop();
    select(&mut wide).arms.pop();
    wide.validate().unwrap();
    let mut wrong = b.clone();
    select(&mut wrong).branches[0] = path(vec![named(first), named(FIELD)], BundleTypeId(0));
    bad(&wrong, "not one named tuple member");
    let mut wrong = b.clone();
    select(&mut wrong).branches[0] = path(vec![named(FIELD)], CHILD);
    bad(&wrong, "semantic path");
    // A capability needs readable storage.
    let mut wrong = b.clone();
    wrong.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&wrong, "unavailable storage carries a readable capability");
}

/// A never-ready terminal: `core::future::pending::Pending<T>` bound as
/// a whole program under its compiler-origin rule, on a record with
/// nothing to read.
fn never_ready() -> Bundle {
    let mut b = base();
    b.semantics.rules[0].kind = SemanticRuleKind::CorePending;
    let mut r = record(CHILD);
    r.future.as_mut().unwrap().continuation = Continuation::Bound {
        rule: SemanticRuleId(0),
        program: PollProgram::Direct(PollAction::NeverReady),
    };
    b.semantics.types = vec![r];
    b.validate().unwrap();
    b
}

/// Never ready is a property of the type and legal only as a whole
/// program under its own rule: not as a state's case, not under any
/// other kind, not beside state the record says there is to read, and
/// not under a library origin.
#[test]
fn test_semantic_never_ready_is_a_whole_program_under_its_own_rule() {
    let b = never_ready();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    // A coroutine's case, under the coroutine's own rule.
    let mut b = coroutine();
    cases(&mut b)[0].action = PollAction::NeverReady;
    bad(&b, "incompatible capability");
    // A case of a plain enum's match under the pending rule itself:
    // the guard is the tell.
    b.semantics.rules[0].kind = SemanticRuleKind::CorePending;
    let r = &mut b.semantics.types[0];
    r.coroutine = None;
    r.storage = StoragePolicy::DeclaredMembers;
    r.future.as_mut().unwrap().evidence = vec![FutureEvidence::PollSymbol(POLL)];
    bad(&b, "never ready is not a state");

    // A whole program under a resource's rule, well-formed on its own.
    let mut b = never_ready();
    b.semantics.rules[0].kind = SemanticRuleKind::TokioSleep;
    b.semantics.origins[0] = SemanticOrigin::LibraryLayout {
        package: StrRef(8),
        version: Some(StrRef(9)),
        family: StrRef(10),
        selection: LayoutSelection::ReviewedRange,
    };
    bad(&b, "incompatible capability");

    // Beside a resource binding: the record has state to read.
    let mut b = resource();
    b.semantics.origins.push(SemanticOrigin::Rustc {
        producer: StrRef(6),
        family: StrRef(7),
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::CorePending,
        revision: 1,
        origin: SemanticOriginId(1),
    });
    b.semantics.types[0].future.as_mut().unwrap().continuation = Continuation::Bound {
        rule: SemanticRuleId(1),
        program: PollProgram::Direct(PollAction::NeverReady),
    };
    bad(&b, "never ready on a type with state to read");

    // Under a library origin: the source it reviews is the toolchain's.
    let mut b = never_ready();
    b.semantics.origins[0] = SemanticOrigin::LibraryLayout {
        package: StrRef(8),
        version: Some(StrRef(9)),
        family: StrRef(10),
        selection: LayoutSelection::ReviewedRange,
    };
    bad(&b, "compiler rule needs a compiler origin");

    // futures-util's terminal is the same program under the crate's
    // layout origin — and only under that: the compiler kind refuses
    // the library origin, and the library kind the compiler's.
    let mut b = never_ready();
    let (package, family) = {
        let mut strings = StringInterner::new();
        for s in b.strings.iter() {
            strings.intern(s);
        }
        let refs = (
            strings.intern("futures-util"),
            strings.intern("unversioned"),
        );
        b.strings = strings.finish();
        refs
    };
    b.semantics.origins[0] = SemanticOrigin::LibraryLayout {
        package,
        version: None,
        family,
        selection: LayoutSelection::VersionUnknown,
    };
    bad(&b, "compiler rule needs a compiler origin");
    b.semantics.rules[0].kind = SemanticRuleKind::FuturesUtilPending;
    b.validate().unwrap();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);
    b.semantics.origins[0] = SemanticOrigin::Rustc {
        producer: StrRef(6),
        family: StrRef(7),
    };
    bad(&b, "layout rule has an incompatible library origin");
}

/// hyper's dispatcher as the HTTP connection resource, laid out by
/// hand: the words the binding routes to, each of the shape the
/// verdict reads, under the hyper rule read off its registry path. The
/// second value is the client's dispatch routes, kept apart so a
/// server-shaped record can be built from the same table.
fn http_conn() -> (Bundle, HttpClientBinding, [TypedPath; 3]) {
    let mut b = base();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let mut name = |s: &str| strings.intern(s);
    let (
        hyper,
        version,
        family,
        source,
        u8_name,
        bool_name,
        unit,
        conn,
        state,
        keep_alive,
        reading,
        writing,
        method,
        is_closing,
        dispatch,
        callback,
        rx,
        inner,
        some,
        none,
        first,
        kind,
    ) = (
        name("hyper"),
        name("1.10.1"),
        name("hyper-h1-conn-1.6.0"),
        name("registry/src/index.crates.io-1949cf8c6b5b557f/hyper-1.10.1/src/proto/h1/dispatch.rs"),
        name("u8"),
        name("bool"),
        name("()"),
        name("conn"),
        name("state"),
        name("keep_alive"),
        name("reading"),
        name("writing"),
        name("method"),
        name("is_closing"),
        name("dispatch"),
        name("callback"),
        name("rx"),
        name("inner"),
        name("Some"),
        name("None"),
        name("__0"),
        name("kind"),
    );
    let (io, read_buf, len, cap, buffered_name, bytes_mut_name, dropshot, dropshot_version) = (
        name("io"),
        name("read_buf"),
        name("len"),
        name("cap"),
        name("hyper::proto::h1::io::Buffered<T, B>"),
        name("bytes::bytes_mut::BytesMut"),
        name("dropshot"),
        name("0.17.1"),
    );
    let (dropshot_family, dropshot_source) = (
        name("dropshot-server-0.17.0"),
        name("registry/src/index.crates.io-1949cf8c6b5b557f/dropshot-0.17.1/src/server.rs"),
    );
    let (timer, timeout, secs, nanos, u32_name, duration_name, nanoseconds_name) = (
        name("h1_header_read_timeout_fut"),
        name("h1_header_read_timeout"),
        name("secs"),
        name("nanos"),
        name("u32"),
        name("core::time::Duration"),
        name("core::num::niche_types::Nanoseconds"),
    );
    let (idle, busy, disabled, init, cont, body, length, chunked, get, post, retry, no_retry) = (
        name("Idle"),
        name("Busy"),
        name("Disabled"),
        name("Init"),
        name("Continue"),
        name("Body"),
        name("Length"),
        name("Chunked"),
        name("Get"),
        name("Post"),
        name("Retry"),
        name("NoRetry"),
    );
    let (
        ka_name,
        kind_name,
        decoder,
        encoder,
        reading_name,
        writing_name,
        inner_name,
        method_name,
        option,
        state_name,
        conn_name,
        sender,
        callback_name,
        unbounded,
        receiver,
        client,
        dispatcher,
    ) = (
        name("hyper::proto::h1::conn::KA"),
        name("Kind"),
        name("Decoder"),
        name("Encoder"),
        name("hyper::proto::h1::conn::Reading"),
        name("hyper::proto::h1::conn::Writing"),
        name("http::method::Inner"),
        name("http::method::Method"),
        name("Option"),
        name("hyper::proto::h1::conn::State"),
        name("hyper::proto::h1::conn::Conn<I, B, T>"),
        name("tokio::sync::oneshot::Sender<T>"),
        name("hyper::client::dispatch::Callback<T, U>"),
        name("tokio::sync::mpsc::unbounded::UnboundedReceiver<T>"),
        name("hyper::client::dispatch::Receiver<T, U>"),
        name("hyper::proto::h1::dispatch::Client<B>"),
        name("hyper::proto::h1::dispatch::Dispatcher<D, Bs, I, T>"),
    );
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let mut next = b.types.types.len() as u32;
    let mut id = || {
        next += 1;
        BundleTypeId(next - 1)
    };
    let (u8_t, bool_t, unit_t, ka, length_p, dkind, decoder_t, cont_p, body_p, reading_t) =
        (id(), id(), id(), id(), id(), id(), id(), id(), id(), id());
    let (encoder_t, wbody_p, writing_t, inner_t, method_t, some_m, opt_method, state_t, conn_t) =
        (id(), id(), id(), id(), id(), id(), id(), id(), id());
    let (sender_t, some_s, opt_sender, retry_p, no_retry_p, callback_t, some_c, opt_callback) =
        (id(), id(), id(), id(), id(), id(), id(), id());
    let (unbounded_t, receiver_t, client_t, dispatcher_t) = (id(), id(), id(), id());
    let (bytes_mut_t, buffered_t) = (id(), id());
    let (u32_t, nanos_t, duration_t, some_d, opt_timeout) = (id(), id(), id(), id(), id());
    let (some_t, opt_timer) = (id(), id());
    let variant = |name, discr: u128, payload: MemberDef| VariantDef {
        name,
        discr_values: Some(DiscrValues(vec![DiscrValue::Value(discr)])),
        payload,
        decl: None,
        await_site: None,
    };
    let enumeration = |name, size, variants| TypeDef::Enum {
        name,
        size,
        shape: VariantShape {
            discr: Some(DiscrDef {
                offset: 0,
                ty: u8_t,
            }),
            variants,
        },
    };
    let strukt = |name, size, members| TypeDef::Struct {
        name,
        size,
        members,
    };
    let word = BundleTypeId(0);
    let pointer = BundleTypeId(8);
    b.types.types.extend([
        TypeDef::Base {
            name: u8_name,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: bool_name,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        strukt(unit, 0, vec![]),
        TypeDef::CEnum {
            name: ka_name,
            size: 1,
            repr: u8_t,
            enumerators: vec![(idle, 0), (busy, 1), (disabled, 2)],
        },
        strukt(length, 8, vec![member(first, word, 0)]),
        enumeration(
            kind_name,
            16,
            vec![
                variant(length, 0, member(length, length_p, 8)),
                variant(chunked, 1, member(chunked, unit_t, 8)),
            ],
        ),
        strukt(decoder, 16, vec![member(kind, dkind, 0)]),
        strukt(cont, 16, vec![member(first, decoder_t, 0)]),
        strukt(body, 16, vec![member(first, decoder_t, 0)]),
        enumeration(
            reading_name,
            24,
            vec![
                variant(init, 0, member(init, unit_t, 8)),
                variant(cont, 1, member(cont, cont_p, 8)),
                variant(body, 2, member(body, body_p, 8)),
            ],
        ),
        strukt(encoder, 16, vec![member(kind, dkind, 0)]),
        strukt(body, 16, vec![member(first, encoder_t, 0)]),
        enumeration(
            writing_name,
            24,
            vec![
                variant(init, 0, member(init, unit_t, 8)),
                variant(body, 1, member(body, wbody_p, 8)),
            ],
        ),
        enumeration(
            inner_name,
            1,
            vec![
                variant(get, 0, member(get, unit_t, 1)),
                variant(post, 1, member(post, unit_t, 1)),
            ],
        ),
        strukt(method_name, 1, vec![member(first, inner_t, 0)]),
        strukt(some, 1, vec![member(first, method_t, 0)]),
        enumeration(
            option,
            2,
            vec![
                variant(none, 0, member(none, unit_t, 1)),
                variant(some, 1, member(some, some_m, 1)),
            ],
        ),
        strukt(
            state_name,
            96,
            vec![
                member(keep_alive, ka, 0),
                member(reading, reading_t, 8),
                member(writing, writing_t, 32),
                member(method, opt_method, 56),
                member(timeout, opt_timeout, 64),
                member(timer, opt_timer, 80),
            ],
        ),
        strukt(
            conn_name,
            112,
            vec![member(io, buffered_t, 0), member(state, state_t, 16)],
        ),
        strukt(sender, 8, vec![member(inner, pointer, 0)]),
        strukt(some, 8, vec![member(first, sender_t, 0)]),
        enumeration(
            option,
            16,
            vec![
                variant(none, 0, member(none, unit_t, 8)),
                variant(some, 1, member(some, some_s, 8)),
            ],
        ),
        strukt(retry, 16, vec![member(first, opt_sender, 0)]),
        strukt(no_retry, 16, vec![member(first, opt_sender, 0)]),
        enumeration(
            callback_name,
            24,
            vec![
                variant(retry, 0, member(retry, retry_p, 8)),
                variant(no_retry, 1, member(no_retry, no_retry_p, 8)),
            ],
        ),
        strukt(some, 24, vec![member(first, callback_t, 0)]),
        enumeration(
            option,
            32,
            vec![
                variant(none, 0, member(none, unit_t, 8)),
                variant(some, 1, member(some, some_c, 8)),
            ],
        ),
        strukt(unbounded, 8, vec![member(inner, pointer, 0)]),
        strukt(receiver, 8, vec![member(inner, unbounded_t, 0)]),
        strukt(
            client,
            48,
            vec![
                member(callback, opt_callback, 0),
                member(rx, receiver_t, 32),
            ],
        ),
        strukt(
            dispatcher,
            168,
            vec![
                member(conn, conn_t, 0),
                member(dispatch, client_t, 112),
                member(is_closing, bool_t, 160),
            ],
        ),
        strukt(
            bytes_mut_name,
            16,
            vec![member(len, word, 0), member(cap, word, 8)],
        ),
        strukt(buffered_name, 16, vec![member(read_buf, bytes_mut_t, 0)]),
        TypeDef::Base {
            name: u32_name,
            size: 4,
            encoding: Encoding::Unsigned,
        },
        strukt(nanoseconds_name, 4, vec![member(first, u32_t, 0)]),
        strukt(
            duration_name,
            16,
            vec![member(secs, word, 0), member(nanos, nanos_t, 8)],
        ),
        strukt(some, 16, vec![member(first, duration_t, 0)]),
        // `None` is the nanoseconds word's niche, as rustc lays it out.
        TypeDef::Enum {
            name: option,
            size: 16,
            shape: VariantShape {
                discr: Some(DiscrDef {
                    offset: 8,
                    ty: u32_t,
                }),
                variants: vec![
                    variant(none, 1_000_000_000, member(none, unit_t, 0)),
                    variant(some, 0, member(some, some_d, 0)),
                ],
            },
        },
        // The timer's option, standing in for the pinned box: its `Some`
        // holds the pointer the timer's address is.
        strukt(some, 8, vec![member(first, pointer, 0)]),
        enumeration(
            option,
            16,
            vec![
                variant(none, 0, member(none, unit_t, 8)),
                variant(some, 1, member(some, some_t, 8)),
            ],
        ),
    ]);
    b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
        package: hyper,
        version,
        family,
        source,
        files: Vec::new(),
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::HyperH1Conn,
        revision: 1,
        origin: SemanticOriginId(1),
    });
    let rule = SemanticRuleId(1);
    // dropshot's rule beside hyper's, for the server-shaped records the
    // tests build: its origin is dropshot's own server file.
    b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
        package: dropshot,
        version: dropshot_version,
        family: dropshot_family,
        source: dropshot_source,
        files: Vec::new(),
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::DropshotRequestHandler,
        revision: 1,
        origin: SemanticOriginId(2),
    });
    let route = |steps: Vec<Step>, target| TypedPath { steps, target };
    let state_word = |word, target| route(vec![named(conn), named(state), named(word)], target);
    let framing = |word, through, target| {
        route(
            vec![
                named(conn),
                named(state),
                named(word),
                Step::Variant(through),
                named(first),
                named(kind),
            ],
            target,
        )
    };
    let sender_route = |through| {
        route(
            vec![
                named(dispatch),
                named(callback),
                Step::Variant(some),
                named(first),
                Step::Variant(through),
                named(first),
                Step::Variant(some),
                named(first),
            ],
            sender_t,
        )
    };
    let client_binding = HttpClientBinding {
        callback: route(vec![named(dispatch), named(callback)], opt_callback),
        retry: sender_route(retry),
        no_retry: sender_route(no_retry),
        rx: route(vec![named(dispatch), named(rx), named(inner)], unbounded_t),
        // The fixture's receiver keeps no taker; the unbounded
        // receiver's own pointer stands in for the want handle's.
        want: route(
            vec![named(dispatch), named(rx), named(inner), named(inner)],
            pointer,
        ),
    };
    let mut r = record(dispatcher_t);
    r.future = None;
    r.resource = Some(ResourceBinding {
        rule,
        kind: ResourceKind::HttpConn,
        state_rule: Some(rule),
        exclusive_pending: true,
    });
    r.http = Some(HttpConnBinding {
        rule,
        role: HttpRole::Client,
        keep_alive: state_word(keep_alive, ka),
        reading: state_word(reading, reading_t),
        writing: state_word(writing, writing_t),
        method: state_word(method, opt_method),
        method_inner: route(
            vec![
                named(conn),
                named(state),
                named(method),
                Step::Variant(some),
                named(first),
                named(first),
            ],
            inner_t,
        ),
        read_continue_kind: framing(reading, cont, dkind),
        read_body_kind: framing(reading, body, dkind),
        write_body_kind: framing(writing, body, dkind),
        is_closing: route(vec![named(is_closing)], bool_t),
        read_buf_len: route(
            vec![named(conn), named(io), named(read_buf), named(len)],
            word,
        ),
        read_buf_cap: route(
            vec![named(conn), named(io), named(read_buf), named(cap)],
            word,
        ),
        client: Some(client_binding.clone()),
        server: None,
    });
    b.semantics.types = vec![r];
    b.validate().unwrap();
    // The header-read timeout's two words, for the server-shaped
    // records the tests build.
    let timeout_word = |steps: &[Step], target| {
        let mut path = vec![
            named(conn),
            named(state),
            named(timeout),
            Step::Variant(some),
            named(first),
        ];
        path.extend_from_slice(steps);
        route(path, target)
    };
    let timer_route = route(
        vec![
            named(conn),
            named(state),
            named(timer),
            Step::Variant(some),
            named(first),
        ],
        pointer,
    );
    let server_words = [
        timeout_word(&[named(secs)], word),
        timeout_word(&[named(nanos), named(first)], u32_t),
        timer_route,
    ];
    (b, client_binding, server_words)
}

/// The HTTP connection binding: the resource and the binding come
/// together under one hyper rule; every word is an enum of the shape
/// the verdict reads, the words inside a word are selected through the
/// variant that carries them, the closing flag is a byte, the client's
/// senders are reached through its callback, and the dispatch routes
/// present are the role's own.
#[test]
fn test_semantic_http_conn_binding_routes_every_word() {
    let (b, client, [secs, nanos, timer]) = http_conn();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    fn http(b: &mut Bundle) -> &mut HttpConnBinding {
        b.semantics.types[0].http.as_mut().unwrap()
    }
    // The resource and the binding stand together, under one rule.
    let mut wrong = b.clone();
    wrong.semantics.types[0].http = None;
    bad(&wrong, "resource and binding disagree");
    let mut wrong = b.clone();
    wrong.semantics.types[0].resource = None;
    bad(&wrong, "binding has no resource");
    let mut wrong = b.clone();
    http(&mut wrong).rule = SemanticRuleId(0);
    bad(&wrong, "resource and binding disagree");
    let mut wrong = b.clone();
    wrong.semantics.types[0]
        .resource
        .as_mut()
        .unwrap()
        .state_rule = Some(SemanticRuleId(0));
    bad(&wrong, "protocol is not the connection's own rule");
    let mut wrong = b.clone();
    wrong.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&wrong, "unavailable storage carries a readable capability");
    // Each word is the shape the verdict reads.
    let mut wrong = b.clone();
    http(&mut wrong).keep_alive = http(&mut wrong).reading.clone();
    bad(&wrong, "keep-alive is not a C-like enum");
    let mut wrong = b.clone();
    http(&mut wrong).reading = http(&mut wrong).keep_alive.clone();
    bad(&wrong, "reading is not an enum");
    let mut wrong = b.clone();
    http(&mut wrong).is_closing = http(&mut wrong).reading.clone();
    bad(&wrong, "closing flag is not one byte");
    // A word inside a word is selected from the word it sits in: a
    // route that is an enum but starts elsewhere is refused even when
    // a variant step sits where the selection would.
    let mut wrong = b.clone();
    http(&mut wrong).method_inner = http(&mut wrong).read_body_kind.clone();
    bad(&wrong, "method name is not selected from its word");
    let mut wrong = b.clone();
    http(&mut wrong).write_body_kind = http(&mut wrong).read_body_kind.clone();
    bad(&wrong, "write framing is not selected from its word");
    // A sender is reached through the callback, further than it.
    let mut wrong = b.clone();
    http(&mut wrong).client.as_mut().unwrap().retry = client.callback.clone();
    bad(&wrong, "sender is not reached through the callback");
    // The dispatch routes present are the role's own: both, or the
    // other role's, disagree.
    // The read buffer's words: unsigned words, under the connection.
    let mut wrong = b.clone();
    http(&mut wrong).read_buf_len = http(&mut wrong).reading.clone();
    bad(&wrong, "read buffer length is not an unsigned word");
    let mut wrong = b.clone();
    http(&mut wrong).read_buf_cap = http(&mut wrong).is_closing.clone();
    bad(&wrong, "read buffer capacity is not an unsigned word");
    // A word of the right width reached from the dispatch is not the
    // connection's read buffer: the receiver's route, retyped to a word.
    let mut wrong = b.clone();
    wrong.types.types[client.rx.target.0 as usize] = TypeDef::Base {
        name: StrRef(0),
        size: 8,
        encoding: Encoding::Unsigned,
    };
    http(&mut wrong).read_buf_len = client.rx.clone();
    bad(
        &wrong,
        "read buffer length is not reached through the connection",
    );
    // The server's handler option is reached through the dispatch —
    // here the client's callback stands in for it, an enum under
    // `dispatch` as the handler's option is.
    let server = HttpServerBinding {
        in_flight: client.callback.clone(),
        header_read_timeout_running: http(&mut b.clone()).is_closing.clone(),
        header_read_timeout_secs: secs.clone(),
        header_read_timeout_nanos: nanos.clone(),
        header_read_timer: timer.clone(),
        service: None,
    };
    let mut wrong = b.clone();
    http(&mut wrong).server = Some(server.clone());
    bad(&wrong, "dispatch paths disagree with the role");
    let mut wrong = b.clone();
    http(&mut wrong).role = HttpRole::Server;
    bad(&wrong, "dispatch paths disagree with the role");
    // A server-shaped record: the client's routes gone, the server's
    // two present, its flag a byte.
    let mut server_conn = b.clone();
    http(&mut server_conn).role = HttpRole::Server;
    http(&mut server_conn).client = None;
    http(&mut server_conn).server = Some(server);
    server_conn.validate().unwrap();
    let mut wrong = server_conn.clone();
    http(&mut wrong)
        .server
        .as_mut()
        .unwrap()
        .header_read_timeout_running = http(&mut wrong).reading.clone();
    bad(&wrong, "header-read timer flag is not one byte");
    let mut wrong = server_conn.clone();
    http(&mut wrong).server.as_mut().unwrap().in_flight = http(&mut wrong).is_closing.clone();
    bad(&wrong, "in-flight handler is not an enum");
    // The timeout's words: each an unsigned word of its own width, and
    // selected out of the state's `Option` — a word of the right width
    // reached elsewhere is not the timeout's.
    let mut wrong = server_conn.clone();
    http(&mut wrong)
        .server
        .as_mut()
        .unwrap()
        .header_read_timeout_secs = nanos.clone();
    bad(
        &wrong,
        "header-read timeout seconds is not an unsigned word",
    );
    let mut wrong = server_conn.clone();
    http(&mut wrong)
        .server
        .as_mut()
        .unwrap()
        .header_read_timeout_nanos = secs.clone();
    bad(
        &wrong,
        "header-read timeout nanoseconds is not an unsigned word",
    );
    let mut wrong = server_conn.clone();
    http(&mut wrong)
        .server
        .as_mut()
        .unwrap()
        .header_read_timeout_secs = http(&mut wrong).read_buf_len.clone();
    bad(
        &wrong,
        "header-read timeout seconds is not selected from the state",
    );
    // A word selected out of a variant elsewhere — the callback's
    // sender, retyped to a word — is not the timeout's either.
    let mut wrong = server_conn.clone();
    http(&mut wrong)
        .server
        .as_mut()
        .unwrap()
        .header_read_timeout_secs = client.retry.clone();
    wrong.types.types[client.retry.target.0 as usize] =
        wrong.types.types[secs.target.0 as usize].clone();
    bad(
        &wrong,
        "header-read timeout seconds is not selected from the state",
    );
    // The timer's address: a pointer, selected out of the state's
    // `Option` — a word there is not one, and neither is a pointer
    // reached through the dispatch.
    let mut wrong = server_conn.clone();
    http(&mut wrong).server.as_mut().unwrap().header_read_timer = secs.clone();
    bad(&wrong, "header-read timer is not a pointer");
    let mut wrong = server_conn.clone();
    http(&mut wrong).server.as_mut().unwrap().header_read_timer = client.retry.clone();
    wrong.types.types[client.retry.target.0 as usize] =
        wrong.types.types[timer.target.0 as usize].clone();
    bad(&wrong, "header-read timer is not selected from the state");
    // The service: the peer an address enum under the service crate's
    // rule, reached through the dispatch the handler is, and the
    // context a type the table carries.
    let peer = |rule, peer| {
        Some(HttpServiceBinding {
            rule,
            peer,
            context: secs.target,
        })
    };
    let with_peer = |service| {
        let mut conn = server_conn.clone();
        http(&mut conn).server.as_mut().unwrap().service = service;
        conn
    };
    let dropshot_rule = SemanticRuleId(2);
    // An enum three members under the dispatch: the callback's own
    // enum through the option, standing in for the service's address.
    let under_dispatch = client.callback.clone();
    let callback_enum = TypedPath {
        steps: client.retry.steps[..4].to_vec(),
        target: {
            // `dispatch.callback.Some.__0` lands on the `Callback` enum.
            let some = client.retry.steps[..4].to_vec();
            semantic_path_target(&b.types, b.semantics.types[0].ty, &Selector(some)).unwrap()
        },
    };
    with_peer(peer(dropshot_rule, callback_enum.clone()))
        .validate()
        .unwrap();
    bad(
        &with_peer(peer(SemanticRuleId(1), callback_enum.clone())),
        "rule has an incompatible capability",
    );
    bad(
        &with_peer(peer(dropshot_rule, http(&mut b.clone()).is_closing.clone())),
        "peer address is not an enum",
    );
    // An enum under the connection rather than the dispatch, and the
    // dispatch's own two-step member, are not a service's address.
    bad(
        &with_peer(peer(dropshot_rule, http(&mut b.clone()).method.clone())),
        "peer address is not reached through the dispatch",
    );
    bad(
        &with_peer(peer(dropshot_rule, under_dispatch)),
        "peer address is not reached through the dispatch",
    );
    let mut service = peer(dropshot_rule, callback_enum.clone());
    service.as_mut().unwrap().context = BundleTypeId(b.types.types.len() as u32);
    bad(&with_peer(service), "invalid type id");
    // The rule is hyper's, read off its own file.
    let mut wrong = b.clone();
    wrong.semantics.rules[1].kind = SemanticRuleKind::HyperUtilTokioSleep;
    bad(&wrong, "third-party delegation needs source evidence");
}

/// hyper-util's version-choosing wrapper as the connection resource:
/// while it reads a connection's first bytes it has no HTTP/1 words,
/// so the resource stands under the wrapper's own rule with no binding
/// beside it, and its program matches on the state — the reading state
/// a primitive, the HTTP/1 state an exclusive delegate to the
/// connection inside — while the dispatcher's resource keeps its
/// binding. Either resource with the other's shape is refused, and so
/// is a protocol that is not the connection's own rule.
#[test]
fn test_semantic_http_negotiating_wrapper_is_the_connection_resource() {
    let (mut b, _, _) = http_conn();
    let dispatcher_t = b.semantics.types[0].ty;
    let hyper_rule = b.semantics.types[0].resource.as_ref().unwrap().rule;
    let u8_t = BundleTypeId(
        b.types
            .types
            .iter()
            .position(
                |t| matches!(t, TypeDef::Base { name, .. } if b.strings.get(*name) == Some("u8")),
            )
            .unwrap() as u32,
    );
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let mut name = |s: &str| strings.intern(s);
    let (package, version, family, source) = (
        name("hyper-util"),
        name("0.1.20"),
        name("hyper-util-auto-conn-0.1.10"),
        name(
            "registry/src/index.crates.io-1949cf8c6b5b557f/hyper-util-0.1.20/src/server/conn/auto/mod.rs",
        ),
    );
    let (state, conn, read_version, h1, h2, wrapper_name, state_name) = (
        name("state"),
        name("conn"),
        name("ReadVersion"),
        name("H1"),
        name("H2"),
        name("hyper_util::server::conn::auto::UpgradeableConnection<I, S, E>"),
        name("hyper_util::server::conn::auto::UpgradeableConnState<I, S, E>"),
    );
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let variant = |name, discr: u128, payload: MemberDef| VariantDef {
        name,
        discr_values: Some(DiscrValues(vec![DiscrValue::Value(discr)])),
        payload,
        decl: None,
        await_site: None,
    };
    let strukt = |name, size, members| TypeDef::Struct {
        name,
        size,
        members,
    };
    let next = b.types.types.len() as u32;
    let (rv_p, h1_p, h2_p, state_t, wrapper_t) = (
        BundleTypeId(next),
        BundleTypeId(next + 1),
        BundleTypeId(next + 2),
        BundleTypeId(next + 3),
        BundleTypeId(next + 4),
    );
    b.types.types.extend([
        strukt(read_version, 0, vec![]),
        strukt(h1, 168, vec![member(conn, dispatcher_t, 0)]),
        strukt(h2, 0, vec![]),
        TypeDef::Enum {
            name: state_name,
            size: 176,
            shape: VariantShape {
                discr: Some(DiscrDef {
                    offset: 0,
                    ty: u8_t,
                }),
                variants: vec![
                    variant(read_version, 0, member(read_version, rv_p, 8)),
                    variant(h1, 1, member(h1, h1_p, 8)),
                    variant(h2, 2, member(h2, h2_p, 8)),
                ],
            },
        },
        strukt(wrapper_name, 176, vec![member(state, state_t, 0)]),
    ]);
    let origin = SemanticOriginId(b.semantics.origins.len() as u32);
    b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
        package,
        version,
        family,
        source,
        files: Vec::new(),
    });
    let rule = SemanticRuleId(b.semantics.rules.len() as u32);
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::HyperUtilAutoConn,
        revision: 1,
        origin,
    });
    let poll = b.strings.get(POLL).unwrap().to_owned();
    b.dyn_futures
        .by_symbol
        .get_mut(&poll)
        .unwrap()
        .push(wrapper_t);
    let mut wrapper = record(wrapper_t);
    wrapper.future.as_mut().unwrap().continuation = Continuation::Bound {
        rule,
        program: PollProgram::MatchVariant {
            state: path(vec![named(state)], state_t),
            cases: vec![
                PollCase {
                    variant: read_version,
                    action: PollAction::Primitive,
                },
                PollCase {
                    variant: h1,
                    action: PollAction::Delegate {
                        target: FutureTarget::Value(path(
                            vec![named(state), Step::Variant(h1), named(conn)],
                            dispatcher_t,
                        )),
                        exclusive: true,
                    },
                },
                PollCase {
                    variant: h2,
                    action: PollAction::Unknown(SemanticIssue {
                        kind: SemanticIssueKind::UnsupportedState,
                        detail: None,
                    }),
                },
            ],
        },
    };
    wrapper.resource = Some(ResourceBinding {
        rule,
        kind: ResourceKind::HttpConn,
        state_rule: Some(rule),
        exclusive_pending: true,
    });
    b.semantics.types.push(wrapper);
    b.validate().unwrap();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    fn auto(b: &mut Bundle) -> &mut TypeSemantics {
        &mut b.semantics.types[1]
    }
    // A connection resource under hyper's rule needs the words.
    let mut wrong = b.clone();
    auto(&mut wrong).resource.as_mut().unwrap().rule = hyper_rule;
    auto(&mut wrong).resource.as_mut().unwrap().state_rule = Some(hyper_rule);
    bad(&wrong, "resource and binding disagree");
    // The protocol is the connection's own rule, whichever it is.
    let mut wrong = b.clone();
    auto(&mut wrong).resource.as_mut().unwrap().state_rule = Some(hyper_rule);
    bad(&wrong, "protocol is not the connection's own rule");
    // Only the two connection rules carry the connection resource.
    let mut wrong = b.clone();
    wrong.semantics.rules[rule.0 as usize].kind = SemanticRuleKind::HyperUtilTokioSleep;
    bad(&wrong, "incompatible capability");
    // The reading state's primitive is the resource's; without the
    // resource it names nothing.
    let mut wrong = b.clone();
    auto(&mut wrong).resource = None;
    bad(&wrong, "primitive has no compatible resource binding");
}

/// A server's request as http lays it out — `Request { head: Parts {
/// method, uri }, body }` down to the path's `Bytes` — with the request
/// binding on the request under http's rule.
fn http_request() -> (Bundle, HttpRequestBinding) {
    let mut b = base();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let mut name = |s: &str| strings.intern(s);
    let (http, version, family, source, u8_name, unit, first, head, method, uri, body) = (
        name("http"),
        name("1.4.2"),
        name("http-request-1.0.0"),
        name("registry/src/index.crates.io-1949cf8c6b5b557f/http-1.4.2/src/request.rs"),
        name("u8"),
        name("()"),
        name("__0"),
        name("head"),
        name("method"),
        name("uri"),
        name("body"),
    );
    let (path_and_query, data, bytes, ptr, len, query, get, post, extra) = (
        name("path_and_query"),
        name("data"),
        name("bytes"),
        name("ptr"),
        name("len"),
        name("query"),
        name("Get"),
        name("Post"),
        name("extra"),
    );
    let (inner_name, method_name, bytes_name, byte_str, pq_name, uri_name, parts, request) = (
        name("http::method::Inner"),
        name("http::method::Method"),
        name("bytes::bytes::Bytes"),
        name("http::byte_str::ByteStr"),
        name("http::uri::path::PathAndQuery"),
        name("http::uri::Uri"),
        name("http::request::Parts"),
        name("http::request::Request<B>"),
    );
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let mut next = b.types.types.len() as u32;
    let mut id = || {
        next += 1;
        BundleTypeId(next - 1)
    };
    let (u8_t, unit_t, byte_ptr, inner_t, method_t, bytes_t, byte_str_t, pq_t, uri_t, parts_t) =
        (id(), id(), id(), id(), id(), id(), id(), id(), id(), id());
    let request_t = id();
    let word = BundleTypeId(0);
    let strukt = |name, size, members| TypeDef::Struct {
        name,
        size,
        members,
    };
    let variant = |name, discr: u128| VariantDef {
        name,
        discr_values: Some(DiscrValues(vec![DiscrValue::Value(discr)])),
        payload: member(name, unit_t, 1),
        decl: None,
        await_site: None,
    };
    b.types.types.extend([
        TypeDef::Base {
            name: u8_name,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        strukt(unit, 0, vec![]),
        TypeDef::Pointer {
            name: None,
            target: u8_t,
        },
        TypeDef::Enum {
            name: inner_name,
            size: 1,
            shape: VariantShape {
                discr: Some(DiscrDef {
                    offset: 0,
                    ty: u8_t,
                }),
                variants: vec![variant(get, 0), variant(post, 1)],
            },
        },
        strukt(method_name, 1, vec![member(first, inner_t, 0)]),
        strukt(
            bytes_name,
            32,
            vec![member(ptr, byte_ptr, 8), member(len, word, 16)],
        ),
        strukt(byte_str, 32, vec![member(bytes, bytes_t, 0)]),
        strukt(
            pq_name,
            40,
            vec![member(data, byte_str_t, 0), member(query, word, 32)],
        ),
        strukt(uri_name, 40, vec![member(path_and_query, pq_t, 0)]),
        strukt(
            parts,
            48,
            vec![member(method, method_t, 0), member(uri, uri_t, 8)],
        ),
        strukt(
            request,
            64,
            vec![
                member(head, parts_t, 0),
                member(body, unit_t, 48),
                member(extra, word, 56),
            ],
        ),
    ]);
    let origin = SemanticOriginId(b.semantics.origins.len() as u32);
    b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
        package: http,
        version,
        family,
        source,
        files: Vec::new(),
    });
    // Another crate's consistent origin beside it, for the test to
    // point the rule at.
    b.semantics.origins.push(delegation_origin(StrRef(18)));
    let rule = SemanticRuleId(b.semantics.rules.len() as u32);
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::HttpRequest,
        revision: 1,
        origin,
    });
    let route = |steps: Vec<Step>, target| TypedPath { steps, target };
    let text = |last, target| {
        route(
            vec![
                named(head),
                named(uri),
                named(path_and_query),
                named(data),
                named(bytes),
                named(last),
            ],
            target,
        )
    };
    let binding = HttpRequestBinding {
        rule,
        method: route(vec![named(head), named(method), named(first)], inner_t),
        target: HttpRequestTarget::PathAndQuery,
        target_ptr: text(ptr, byte_ptr),
        target_len: text(len, word),
    };
    let mut r = record(request_t);
    r.future = None;
    r.request = Some(binding.clone());
    b.semantics.types = vec![r];
    b.validate().unwrap();
    (b, binding)
}

/// The request binding: under a rule of one of the crates that keep a
/// request's words, the method is an enum, the target's text is a byte
/// pointer and a word out of one holder, and a record with no readable
/// storage carries none.
#[test]
fn test_semantic_request_binding_routes_the_method_and_the_target_text() {
    let (b, binding) = http_request();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    fn request(b: &mut Bundle) -> &mut HttpRequestBinding {
        b.semantics.types[0].request.as_mut().unwrap()
    }
    // The rule has to be one that keeps a request: hyper's connection
    // rule is not.
    let mut wrong = b.clone();
    request(&mut wrong).rule = SemanticRuleId(0);
    bad(&wrong, "rule has an incompatible capability");
    // The rule's origin is the crate whose type is bound.
    let mut wrong = b.clone();
    let origin = wrong.semantics.rules[binding.rule.0 as usize].origin;
    wrong.semantics.rules[binding.rule.0 as usize].origin = SemanticOriginId(origin.0 + 1);
    bad(&wrong, "third-party delegation needs source evidence");
    // The method lands on an enum: the newtype around it is not one.
    let mut wrong = b.clone();
    request(&mut wrong).method.steps.pop();
    request(&mut wrong).method.target = BundleTypeId(b.types.types.len() as u32 - 7);
    bad(&wrong, "method is not an enum");
    // The target's pointer is a pointer to bytes, and its length a word.
    let mut wrong = b.clone();
    request(&mut wrong).target_ptr = binding.target_len.clone();
    bad(&wrong, "target is not reached by a pointer");
    let mut wrong = b.clone();
    request(&mut wrong).target_len = binding.target_ptr.clone();
    bad(&wrong, "target length is not an unsigned word");
    // The two are read out of one value: a word elsewhere in the
    // record is no length of the text.
    let mut wrong = b.clone();
    let extra = StrRef(wrong.strings.iter().position(|s| s == "extra").unwrap() as u32);
    request(&mut wrong).target_len = TypedPath {
        steps: vec![named(extra)],
        target: BundleTypeId(0),
    };
    bad(&wrong, "not under one member");
    // However deep both routes run, they enter through one member: a
    // word under another holder of its own is no length of the text.
    let mut wrong = b.clone();
    let find = |s: &str| StrRef(wrong.strings.iter().position(|x| x == s).unwrap() as u32);
    let (query, pq_name) = (find("query"), find("http::uri::path::PathAndQuery"));
    let pq_t = wrong
        .types
        .types
        .iter()
        .position(|t| matches!(t, TypeDef::Struct { name, .. } if *name == pq_name))
        .unwrap();
    let request_t = wrong.semantics.types[0].ty;
    let TypeDef::Struct { size, members, .. } = &mut wrong.types.types[request_t.0 as usize] else {
        panic!("the request is a struct");
    };
    *size = 96;
    members.last_mut().unwrap().ty = BundleTypeId(pq_t as u32);
    request(&mut wrong).target_len = TypedPath {
        steps: vec![named(extra), named(query)],
        target: BundleTypeId(0),
    };
    bad(&wrong, "not under one member");
    // A record with no readable storage keeps no binding.
    let mut wrong = b.clone();
    wrong.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&wrong, "unavailable storage carries a readable capability");
}

/// A hashbrown map bound as a table — `{ table: RawTable { table:
/// RawTableInner { ctrl: NonNull<u8>, bucket_mask, growth_left, items } } }`
/// over `(u64, u64)` buckets — under a reviewed hashbrown layout origin,
/// with a tokio origin and an unreviewed hashbrown one beside it for the
/// test to point the rule at.
fn hash_table() -> (Bundle, HashTableBinding) {
    let mut b = base();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let mut name = |s: &str| strings.intern(s);
    let (hashbrown, version, newer, family, other_family) = (
        name("hashbrown"),
        name("0.17.1"),
        name("0.18.0"),
        name("hashbrown-table-0.12.3"),
        name("decoy-family"),
    );
    let (u8_name, non_null, inner_name, raw_name, map_name, bucket_name) = (
        name("u8"),
        name("core::ptr::non_null::NonNull<u8>"),
        name("hashbrown::raw::RawTableInner"),
        name("hashbrown::raw::RawTable<(u64, u64), alloc::alloc::Global>"),
        name("hashbrown::map::HashMap<u64, u64>"),
        name("(u64, u64)"),
    );
    let (table, ctrl, pointer, bucket_mask, growth_left, items, first, second) = (
        name("table"),
        name("ctrl"),
        name("pointer"),
        name("bucket_mask"),
        name("growth_left"),
        name("items"),
        name("__0"),
        name("__1"),
    );
    let tokio = name("tokio");
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let mut next = b.types.types.len() as u32;
    let mut id = || {
        next += 1;
        BundleTypeId(next - 1)
    };
    let (u8_t, byte_ptr, non_null_t, inner_t, raw_t, map_t, bucket_t) =
        (id(), id(), id(), id(), id(), id(), id());
    let word = BundleTypeId(0);
    let strukt = |name, size, members| TypeDef::Struct {
        name,
        size,
        members,
    };
    b.types.types.extend([
        TypeDef::Base {
            name: u8_name,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Pointer {
            name: None,
            target: u8_t,
        },
        strukt(non_null, 8, vec![member(pointer, byte_ptr, 0)]),
        strukt(
            inner_name,
            32,
            vec![
                member(ctrl, non_null_t, 0),
                member(bucket_mask, word, 8),
                member(growth_left, word, 16),
                member(items, word, 24),
            ],
        ),
        strukt(raw_name, 32, vec![member(table, inner_t, 0)]),
        strukt(map_name, 32, vec![member(table, raw_t, 0)]),
        strukt(
            bucket_name,
            16,
            vec![member(first, word, 0), member(second, word, 8)],
        ),
    ]);
    let origin = SemanticOriginId(b.semantics.origins.len() as u32);
    b.semantics.origins.extend([
        SemanticOrigin::LibraryLayout {
            package: hashbrown,
            version: Some(version),
            family,
            selection: LayoutSelection::ReviewedRange,
        },
        SemanticOrigin::LibraryLayout {
            package: tokio,
            version: None,
            family: other_family,
            selection: LayoutSelection::VersionUnknown,
        },
        SemanticOrigin::LibraryLayout {
            package: hashbrown,
            version: Some(newer),
            family,
            selection: LayoutSelection::AboveReviewedRange,
        },
    ]);
    let rule = SemanticRuleId(b.semantics.rules.len() as u32);
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::HashbrownTable,
        revision: 1,
        origin,
    });
    let words = |last: &[StrRef], target| TypedPath {
        steps: [table, table]
            .iter()
            .chain(last)
            .map(|&name| named(name))
            .collect(),
        target,
    };
    let binding = HashTableBinding {
        rule,
        bucket_mask: words(&[bucket_mask], word),
        ctrl: words(&[ctrl, pointer], byte_ptr),
        items: words(&[items], word),
        bucket: bucket_t,
    };
    let mut r = record(map_t);
    r.future = None;
    r.table = Some(binding.clone());
    b.semantics.types = vec![r];
    b.validate().unwrap();
    (b, binding)
}

/// The table binding: under hashbrown's layout rule at a reviewed
/// release, two unsigned words and a pointer to the control bytes, each
/// its own member, and a sized bucket; a record with no readable
/// storage carries none.
#[test]
fn test_semantic_table_binding_routes_the_words_of_a_reviewed_release() {
    let (b, binding) = hash_table();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    fn table(b: &mut Bundle) -> &mut HashTableBinding {
        b.semantics.types[0].table.as_mut().unwrap()
    }
    // The rule has to be the table rule: a pointer adapter's is not.
    let mut wrong = b.clone();
    table(&mut wrong).rule = SemanticRuleId(0);
    bad(&wrong, "rule has an incompatible capability");
    // The rule's origin is hashbrown's layout, at a release the review
    // read: tokio's origin is another crate's, and a newer release than
    // the range is unread.
    let rule = binding.rule.0 as usize;
    let origin = b.semantics.rules[rule].origin.0;
    let mut wrong = b.clone();
    wrong.semantics.rules[rule].origin = SemanticOriginId(origin + 1);
    bad(&wrong, "layout rule has an incompatible library origin");
    let mut wrong = b.clone();
    wrong.semantics.rules[rule].origin = SemanticOriginId(origin + 2);
    bad(&wrong, "hash table rule requires a reviewed range");
    // The mask and the count are words, the control bytes a pointer to
    // bytes: the `NonNull` holding that pointer is no pointer itself.
    let mut wrong = b.clone();
    table(&mut wrong).bucket_mask = binding.ctrl.clone();
    bad(&wrong, "bucket mask is not an unsigned word");
    let mut wrong = b.clone();
    table(&mut wrong).items = binding.ctrl.clone();
    bad(&wrong, "item count is not an unsigned word");
    let mut wrong = b.clone();
    table(&mut wrong).ctrl.steps.pop();
    table(&mut wrong).ctrl.target = BundleTypeId(binding.ctrl.target.0 + 1);
    bad(&wrong, "control bytes are not reached by a pointer");
    // Each word is its own member: a mask that is the count reads one
    // word as both.
    let mut wrong = b.clone();
    table(&mut wrong).items = binding.bucket_mask.clone();
    bad(&wrong, "reads one member as two of its words");
    // The bucket is a type the table has.
    let mut wrong = b.clone();
    table(&mut wrong).bucket = BundleTypeId(u32::MAX);
    bad(&wrong, "invalid type id");
    // A record with no readable storage keeps no binding.
    let mut wrong = b.clone();
    wrong.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&wrong, "unavailable storage carries a readable capability");
}

/// A pool's reaper and checkout over the table fixture's map: the
/// reaper `{ pool: *const ArcInner { strong, idle: map } }`, whose map's
/// bucket is re-pointed at `{ __0: Text { ptr, len }, __1: List { ptr,
/// len } }` and whose entry is `Idle { want: *const u8 }`; the checkout
/// `{ key: Text, want: *const u8 }`. Both bind under the pool rule at a
/// hyper-util delegation origin, with a reqwest one beside it for the
/// test to point the rule at.
fn pool() -> (Bundle, HttpPoolBinding, HttpPoolBinding) {
    let (mut b, _) = hash_table();
    let mut strings = StringInterner::new();
    for s in b.strings.iter() {
        strings.intern(s);
    }
    let mut name = |s: &str| strings.intern(s);
    let (hyper_util, version, family, source, reqwest, reqwest_source) = (
        name("hyper-util"),
        name("0.1.20"),
        name("hyper-util-pool-0.1.16"),
        name(
            "registry/src/index.crates.io-1949cf8c6b5b557f/hyper-util-0.1.20/src/client/legacy/pool.rs",
        ),
        name("reqwest"),
        name("registry/src/index.crates.io-1949cf8c6b5b557f/reqwest-0.1.20/src/lib.rs"),
    );
    let (text_name, list_name, bucket_name, entry_name, arc_name, reaper_name, checkout_name) = (
        name("Text"),
        name("List"),
        name("Bucket"),
        name("Idle"),
        name("ArcInner"),
        name("IdleTask"),
        name("Pooled"),
    );
    let (pools_name, unit_name) = (name("Pools"), name("Unit"));
    let (ptr, len, first, second, want, strong, idle, pool, other, key, pools) = (
        name("ptr"),
        name("len"),
        name("__0"),
        name("__1"),
        name("want"),
        name("strong"),
        name("idle"),
        name("pool"),
        name("other"),
        name("key"),
        name("pools"),
    );
    b.strings = strings.finish();
    let member = |name, ty, offset| MemberDef { name, ty, offset };
    let strukt = |name, size, members| TypeDef::Struct {
        name,
        size,
        members,
    };
    let word = BundleTypeId(0);
    let map_t = b.semantics.types[0].ty;
    let byte_ptr = b.semantics.types[0].table.as_ref().unwrap().ctrl.target;
    let mut next = b.types.types.len() as u32;
    let mut id = || {
        next += 1;
        BundleTypeId(next - 1)
    };
    let (text_t, list_t, bucket_t, entry_t, arc_t, arc_ptr, pools_t, reaper_t, checkout_t) =
        (id(), id(), id(), id(), id(), id(), id(), id(), id());
    b.types.types.extend([
        strukt(
            text_name,
            16,
            vec![member(ptr, byte_ptr, 0), member(len, word, 8)],
        ),
        strukt(
            list_name,
            16,
            vec![member(ptr, byte_ptr, 0), member(len, word, 8)],
        ),
        strukt(
            bucket_name,
            32,
            vec![member(first, text_t, 0), member(second, list_t, 16)],
        ),
        strukt(entry_name, 8, vec![member(want, byte_ptr, 0)]),
        strukt(
            arc_name,
            40,
            vec![member(strong, word, 0), member(idle, map_t, 8)],
        ),
        TypeDef::Pointer {
            name: None,
            target: arc_t,
        },
        // A holder of two pools, for a count and a map that enter
        // through one member and part below it.
        strukt(
            pools_name,
            16,
            vec![member(pool, arc_ptr, 0), member(other, arc_ptr, 8)],
        ),
        // A second pointer to a pool of the same type, for a count
        // read off another allocation than the map's.
        strukt(
            reaper_name,
            32,
            vec![
                member(pool, arc_ptr, 0),
                member(other, arc_ptr, 8),
                member(pools, pools_t, 16),
            ],
        ),
        strukt(
            checkout_name,
            24,
            vec![member(key, text_t, 0), member(want, byte_ptr, 16)],
        ),
        strukt(unit_name, 0, Vec::new()),
    ]);
    b.semantics.types[0].table.as_mut().unwrap().bucket = bucket_t;
    let origin = SemanticOriginId(b.semantics.origins.len() as u32);
    for (package, source) in [(hyper_util, source), (reqwest, reqwest_source)] {
        b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
            package,
            version,
            family,
            source,
            files: Vec::new(),
        });
    }
    let rule = SemanticRuleId(b.semantics.rules.len() as u32);
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::HyperUtilPool,
        revision: 1,
        origin,
    });
    let route = |steps: &[Step], target| TypedPath {
        steps: steps.to_vec(),
        target,
    };
    let reaper = HttpPoolBinding::Reaper {
        rule,
        strong: route(&[named(pool), Step::Deref, named(strong)], word),
        idle: route(&[named(pool), Step::Deref, named(idle)], map_t),
        key_ptr: route(&[named(first), named(ptr)], byte_ptr),
        key_len: route(&[named(first), named(len)], word),
        entries_ptr: route(&[named(second), named(ptr)], byte_ptr),
        entries_len: route(&[named(second), named(len)], word),
        entry: entry_t,
        want: route(&[named(want)], byte_ptr),
    };
    let checkout = HttpPoolBinding::Checkout {
        rule,
        key_ptr: route(&[named(key), named(ptr)], byte_ptr),
        key_len: route(&[named(key), named(len)], word),
        want: route(&[named(want)], byte_ptr),
    };
    for (ty, binding) in [(reaper_t, &reaper), (checkout_t, &checkout)] {
        let mut r = record(ty);
        r.future = None;
        r.pool = Some(binding.clone());
        b.semantics.types.push(r);
    }
    b.validate().unwrap();
    (b, reaper, checkout)
}

/// The pool binding: under hyper-util's pool rule at a hyper-util
/// origin, a reaper reaches a word-sized strong count and, through the
/// same pointer, a map carrying a table binding, whose bucket holds the
/// key's text and the idle list, and whose entry the want pointer; a
/// checkout reaches its key's text and its want pointer.
#[test]
fn test_semantic_pool_binding_names_each_connection_by_key_and_want() {
    let (b, reaper, _) = pool();
    let mut bytes = Vec::new();
    b.write_to(&mut bytes).unwrap();
    assert_eq!(Bundle::read_from(bytes.as_slice()).unwrap(), b);

    let (reaper_at, checkout_at) = (1, 2);
    fn binding(b: &mut Bundle, at: usize) -> &mut HttpPoolBinding {
        b.semantics.types[at].pool.as_mut().unwrap()
    }
    // The rule is the pool rule, at a hyper-util origin.
    let mut wrong = b.clone();
    match binding(&mut wrong, checkout_at) {
        HttpPoolBinding::Checkout { rule, .. } => *rule = SemanticRuleId(0),
        _ => unreachable!(),
    }
    bad(&wrong, "rule has an incompatible capability");
    let HttpPoolBinding::Reaper { rule, .. } = &reaper else {
        unreachable!()
    };
    let rule = rule.0 as usize;
    let mut wrong = b.clone();
    wrong.semantics.rules[rule].origin.0 += 1;
    bad(&wrong, "third-party delegation needs source evidence");
    // The key's text is a byte pointer and a word under one member.
    let mut wrong = b.clone();
    match binding(&mut wrong, checkout_at) {
        HttpPoolBinding::Checkout {
            key_ptr, key_len, ..
        } => *key_ptr = key_len.clone(),
        _ => unreachable!(),
    }
    bad(&wrong, "HTTP pool key is not reached by a pointer");
    let mut wrong = b.clone();
    match binding(&mut wrong, checkout_at) {
        HttpPoolBinding::Checkout {
            key_ptr, key_len, ..
        } => *key_len = key_ptr.clone(),
        _ => unreachable!(),
    }
    bad(&wrong, "HTTP pool key length is not an unsigned word");
    // The want handle is a pointer.
    let mut wrong = b.clone();
    match binding(&mut wrong, checkout_at) {
        HttpPoolBinding::Checkout { want, key_len, .. } => *want = key_len.clone(),
        _ => unreachable!(),
    }
    bad(&wrong, "checkout's want handle is not reached by a pointer");
    let mut wrong = b.clone();
    match binding(&mut wrong, reaper_at) {
        HttpPoolBinding::Reaper {
            want, entries_len, ..
        } => {
            *want = entries_len.clone();
        }
        _ => unreachable!(),
    }
    // An entry-relative route that is the bucket's names no member of
    // the entry.
    bad(&wrong, "no unique member");
    // The strong count is a word, and the map is reached through the
    // pointer the count is: a map reached from the count's own member
    // is some other allocation's.
    let mut wrong = b.clone();
    match binding(&mut wrong, reaper_at) {
        HttpPoolBinding::Reaper { strong, idle, .. } => *strong = idle.clone(),
        _ => unreachable!(),
    }
    bad(&wrong, "HTTP pool strong count is not a word");
    let [pool, other, pools] = match b.types.get(b.semantics.types[reaper_at].ty) {
        Some(TypeDef::Struct { members, .. }) => [0, 1, 2].map(|i| members[i].name),
        other => panic!("{other:?}"),
    };
    let mut wrong = b.clone();
    match binding(&mut wrong, reaper_at) {
        HttpPoolBinding::Reaper { strong, .. } => strong.steps[0] = named(other),
        _ => unreachable!(),
    }
    bad(&wrong, "is not reached through the pool its count is");
    // The whole route to the pointer is shared, not only its first
    // step: two pools one member holds are two allocations.
    let mut wrong = b.clone();
    match binding(&mut wrong, reaper_at) {
        HttpPoolBinding::Reaper { strong, idle, .. } => {
            strong.steps.splice(0..1, [named(pools), named(other)]);
            idle.steps.splice(0..1, [named(pools), named(pool)]);
        }
        _ => unreachable!(),
    }
    bad(&wrong, "is not reached through the pool its count is");
    // The map carries the table its buckets are read through.
    let mut wrong = b.clone();
    wrong.semantics.types[0].table = None;
    bad(&wrong, "HTTP pool map carries no table binding");
    // The entry is a sized type.
    let mut wrong = b.clone();
    match binding(&mut wrong, reaper_at) {
        HttpPoolBinding::Reaper { entry, .. } => *entry = BundleTypeId(u32::MAX),
        _ => unreachable!(),
    }
    bad(&wrong, "invalid type id");
    let unit = BundleTypeId(b.types.types.len() as u32 - 1);
    assert_eq!(b.types.size_of(unit), Some(0));
    let mut wrong = b.clone();
    match binding(&mut wrong, reaper_at) {
        HttpPoolBinding::Reaper { entry, .. } => *entry = unit,
        _ => unreachable!(),
    }
    bad(&wrong, "HTTP pool idle entry is unsized");
    // A record with no readable storage keeps no binding.
    let mut wrong = b.clone();
    wrong.semantics.types[checkout_at].storage = StoragePolicy::Unavailable(issue());
    bad(&wrong, "unavailable storage carries a readable capability");
}

/// A rule of `kind` under the base's compiler origin, appended.
fn compiler_rule(b: &mut Bundle, kind: SemanticRuleKind) -> SemanticRuleId {
    b.semantics.rules.push(SemanticRule {
        kind,
        revision: 1,
        origin: SemanticOriginId(0),
    });
    SemanticRuleId(b.semantics.rules.len() as u32 - 1)
}

/// A refcount header's value is one named member past the counts, under
/// the std rule and no other.
#[test]
fn test_semantic_refcount_value_is_a_named_member_past_the_counts() {
    let mut b = base();
    let rule = compiler_rule(&mut b, SemanticRuleKind::StdRefcountHeader);
    let mut header = record(PARENT);
    header.future = None;
    header.refcount = Some(RefcountBinding {
        rule,
        value: MemberRef::Named(FIELD),
    });
    b.semantics.types = vec![header];
    b.validate().unwrap();

    let mut wrong = b.clone();
    wrong.semantics.types[0].refcount.as_mut().unwrap().rule = SemanticRuleId(0);
    bad(&wrong, "incompatible capability");
    let mut positional = b.clone();
    positional.semantics.types[0]
        .refcount
        .as_mut()
        .unwrap()
        .value = MemberRef::Index(0);
    bad(&positional, "addressed by name");
    let mut missing = b.clone();
    missing.semantics.types[0].refcount.as_mut().unwrap().value = MemberRef::Named(VARIANT);
    bad(&missing, "no unique refcount value member");
    // CHILD's one member sits at its start, where the counts are.
    let mut at_start = b.clone();
    at_start.semantics.types[0].ty = CHILD;
    bad(&at_start, "past its counts");
}

/// A lock word is a whole integer inside the lock whose mask names a
/// bit of it, under a lock rule.
#[test]
fn test_semantic_lock_word_lies_in_the_lock() {
    let mut b = base();
    let rule = compiler_rule(&mut b, SemanticRuleKind::StdFutexMutex);
    let mut lock = record(CHILD);
    lock.future = None;
    lock.lock = Some(LockBinding {
        rule,
        word: LockWord {
            offset: 0,
            size: 4,
            locked_mask: 0xffff_ffff,
        },
    });
    b.semantics.types = vec![lock];
    b.validate().unwrap();

    fn word(b: &mut Bundle) -> &mut LockWord {
        &mut b.semantics.types[0].lock.as_mut().unwrap().word
    }
    let mut odd = b.clone();
    word(&mut odd).size = 3;
    bad(&odd, "1, 2, 4 or 8 bytes");
    let mut wide = b.clone();
    word(&mut wide).locked_mask = 1 << 32;
    bad(&wide, "names no bit");
    let mut empty = b.clone();
    word(&mut empty).locked_mask = 0;
    bad(&empty, "names no bit");
    let mut past = b.clone();
    word(&mut past).offset = 6;
    bad(&past, "past the lock");
    let mut wrong = b.clone();
    wrong.semantics.types[0].lock.as_mut().unwrap().rule = SemanticRuleId(0);
    bad(&wrong, "incompatible capability");
}

/// A lock word reads held exactly when a masked bit is set, and not at
/// all from bytes too short to hold it.
#[test]
fn test_lock_word_reads_its_masked_bits() {
    let byte = LockWord {
        offset: 0,
        size: 1,
        locked_mask: 0b01,
    };
    assert_eq!(byte.held(&[0b01]), Some(true));
    assert_eq!(byte.held(&[0b10]), Some(false));
    assert_eq!(byte.held(&[]), None);
    let word = LockWord {
        offset: 4,
        size: 4,
        locked_mask: 0xffff_ffff,
    };
    assert_eq!(word.held(&[0, 0, 0, 0, 0, 0, 0, 0]), Some(false));
    assert_eq!(word.held(&[0, 0, 0, 0, 0, 0, 0, 2]), Some(true));
    assert_eq!(word.held(&[0, 0, 0, 0, 1, 0, 0]), None);
}

/// An acquire's owner is a name on a future, under the tokio rule; a
/// coroutine's kind is a coroutine rule, the one its layout names.
#[test]
fn test_semantic_owner_and_coroutine_kind_rules() {
    let mut b = base();
    b.semantics.origins.push(SemanticOrigin::LibraryLayout {
        package: StrRef(8),
        version: Some(StrRef(9)),
        family: StrRef(10),
        selection: LayoutSelection::ReviewedRange,
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::TokioAcquireOwner,
        revision: 1,
        origin: SemanticOriginId(1),
    });
    let owner = SemanticRuleId(b.semantics.rules.len() as u32 - 1);
    let kind = compiler_rule(&mut b, SemanticRuleKind::RustcAsyncFn);
    let mut acquirer = record(PARENT);
    acquirer.acquires_for = Some(AcquiresForBinding {
        rule: owner,
        primitive: StrRef(3),
    });
    acquirer.coroutine_kind = Some(kind);
    b.semantics.types = vec![acquirer];
    b.validate().unwrap();

    let mut no_future = b.clone();
    no_future.semantics.types[0].future = None;
    bad(&no_future, "needs a future");
    let mut wrong_owner = b.clone();
    wrong_owner.semantics.types[0]
        .acquires_for
        .as_mut()
        .unwrap()
        .rule = kind;
    bad(&wrong_owner, "incompatible capability");
    let mut wrong_kind = b.clone();
    wrong_kind.semantics.types[0].coroutine_kind = Some(owner);
    bad(&wrong_kind, "incompatible capability");
}

/// A socket (the child, its registration and descriptor roles bound at
/// it), a stream forwarding to it (the parent, through its member), and
/// an operation over the stream (a new type holding a pointer to it),
/// each under tokio's rule for it.
fn io_routes() -> Bundle {
    let mut b = resource();
    const OP: BundleTypeId = BundleTypeId(11);
    let parent_ptr = BundleTypeId(10);
    b.types.types.push(TypeDef::Struct {
        name: FIELD,
        size: 8,
        members: vec![MemberDef {
            name: FIELD,
            ty: parent_ptr,
            offset: 0,
        }],
    });
    b.semantics.rules = vec![
        SemanticRule {
            kind: SemanticRuleKind::TokioIoRoute,
            revision: 1,
            origin: SemanticOriginId(0),
        },
        SemanticRule {
            kind: SemanticRuleKind::TokioIoOperation,
            revision: 1,
            origin: SemanticOriginId(0),
        },
    ];
    let mut socket = record(CHILD);
    socket.future = None;
    socket.io_route = Some(IoRouteBinding {
        rule: SemanticRuleId(0),
        step: IoRouteStep::Socket(IoSocket::TcpStream),
    });
    let mut stream = record(PARENT);
    stream.future = None;
    stream.io_route = Some(IoRouteBinding {
        rule: SemanticRuleId(0),
        step: IoRouteStep::Forward {
            inner: path(vec![named(FIELD)], CHILD),
        },
    });
    let mut op = record(OP);
    op.future = None;
    op.resource = Some(ResourceBinding {
        rule: SemanticRuleId(1),
        kind: ResourceKind::IoOperation(IoOperationKind::ReadExact),
        state_rule: None,
        exclusive_pending: false,
    });
    op.io = Some(IoOperationBinding {
        rule: SemanticRuleId(1),
        stream: path(vec![named(FIELD), Step::Deref], PARENT),
        remaining: None,
    });
    b.semantics.types = vec![socket, stream, op];
    let walk = b.walks.entries[&WalkRole::JoinHandleRaw].clone();
    let at_child = WalkBinding {
        roots: vec![CHILD],
        ..walk
    };
    b.walks.entries = socket_roles(IoSocket::TcpStream)
        .iter()
        .map(|role| (*role, at_child.clone()))
        .collect();
    b.validate().unwrap();
    b
}

/// A route forwards to a routed type and ends at a socket whose roles
/// are bound at it, under tokio's route rule; an operation reaches a
/// routed stream through its pointer, under its resource's rule, and
/// carries its binding exactly when its resource is an operation over
/// a stream.
#[test]
fn test_io_routes_end_at_sockets_and_operations_reach_them() {
    let b = io_routes();
    let [child, parent, op] = [0, 1, 2];

    let mut dangling = b.clone();
    dangling.semantics.types[child].io_route = None;
    bad(&dangling, "forwards to an unrouted type");

    let mut unbound = b.clone();
    unbound.walks.entries.remove(&WalkRole::TcpStreamFd);
    bad(&unbound, "essential walk role is not bound");

    let mut cycle = b.clone();
    cycle.semantics.types[child].io_route = Some(IoRouteBinding {
        rule: SemanticRuleId(0),
        step: IoRouteStep::Forward {
            inner: path(vec![named(FIELD)], BundleTypeId(0)),
        },
    });
    bad(&cycle, "forwards to an unrouted type");

    let mut to_itself = b.clone();
    to_itself.semantics.types[parent].io_route = Some(IoRouteBinding {
        rule: SemanticRuleId(0),
        step: IoRouteStep::Forward {
            inner: path(Vec::new(), PARENT),
        },
    });
    bad(&to_itself, "forwards to itself");

    let mut wrong_rule = b.clone();
    wrong_rule.semantics.types[parent]
        .io_route
        .as_mut()
        .unwrap()
        .rule = SemanticRuleId(1);
    bad(&wrong_rule, "incompatible capability");

    let mut unrouted = b.clone();
    unrouted.semantics.types[child].io_route = None;
    unrouted.semantics.types[parent].io_route = None;
    bad(&unrouted, "stream has no route");

    let mut no_pointer = b.clone();
    no_pointer.semantics.types[op].io.as_mut().unwrap().stream =
        path(vec![named(FIELD)], BundleTypeId(10));
    bad(&no_pointer, "not behind its pointer");

    let mut unbound_op = b.clone();
    unbound_op.semantics.types[op].io = None;
    bad(&unbound_op, "io operation resource and binding disagree");

    let mut readiness = b.clone();
    readiness.semantics.types[op]
        .resource
        .as_mut()
        .unwrap()
        .kind = ResourceKind::IoOperation(IoOperationKind::Readiness);
    bad(&readiness, "essential walk role is not bound");

    let mut not_a_word = b.clone();
    not_a_word.semantics.types[op]
        .io
        .as_mut()
        .unwrap()
        .remaining = Some(path(vec![named(FIELD)], BundleTypeId(10)));
    bad(&not_a_word, "not an unsigned word");
}

/// [`io_routes`] with a third-party stream on top: the state enum
/// matches its one variant onto the routed parent under tokio-rustls's
/// rule, and a struct holding the enum forwards to it under
/// sprockets-tls's, whose origin is a git checkout.
fn third_party_routes() -> Bundle {
    let mut b = io_routes();
    let holder = BundleTypeId(12);
    b.types.types.push(TypeDef::Struct {
        name: FIELD,
        size: 24,
        members: vec![MemberDef {
            name: FIELD,
            ty: STATE,
            offset: 0,
        }],
    });
    b.semantics.origins.push(SemanticOrigin::LibraryDelegation {
        package: StrRef(37),
        version: StrRef(38),
        family: StrRef(39),
        source: StrRef(40),
        files: Vec::new(),
    });
    b.semantics.origins.push(SemanticOrigin::GitDelegation {
        package: StrRef(41),
        repository: StrRef(42),
        revision: StrRef(43),
        family: StrRef(44),
        source: StrRef(45),
        files: Vec::new(),
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::TokioRustlsStream,
        revision: 1,
        origin: SemanticOriginId(1),
    });
    b.semantics.rules.push(SemanticRule {
        kind: SemanticRuleKind::SprocketsTlsStream,
        revision: 1,
        origin: SemanticOriginId(2),
    });
    let mut tls = record(STATE);
    tls.future = None;
    tls.io_route = Some(IoRouteBinding {
        rule: SemanticRuleId(2),
        step: IoRouteStep::Match {
            cases: vec![path(vec![Step::Variant(VARIANT)], PARENT)],
        },
    });
    let mut stream = record(holder);
    stream.future = None;
    stream.io_route = Some(IoRouteBinding {
        rule: SemanticRuleId(3),
        step: IoRouteStep::Forward {
            inner: path(vec![named(FIELD)], STATE),
        },
    });
    let op = b.semantics.types.pop().unwrap();
    b.semantics.types.extend([tls, op, stream]);
    b.validate().unwrap();
    b
}

/// A match's every case selects its own variant first and ends at a
/// socket, only under tokio-rustls's rule; a git delegation's origin
/// re-parses to the repository and revision it records, and only
/// sprockets-tls's rule stands on one.
#[test]
fn test_stream_matches_select_variants_and_git_origins_name_their_checkout() {
    let b = third_party_routes();
    let [child, tls] = [0, 2];
    fn cases(b: &mut Bundle) -> &mut Vec<TypedPath> {
        match &mut b.semantics.types[2].io_route.as_mut().unwrap().step {
            IoRouteStep::Match { cases } => cases,
            _ => unreachable!(),
        }
    }

    let mut empty = b.clone();
    cases(&mut empty).clear();
    bad(&empty, "a stream match has no case");

    let mut twice = b.clone();
    let case = cases(&mut twice)[0].clone();
    cases(&mut twice).push(case);
    bad(&twice, "selects one variant twice");

    let mut no_variant = b.clone();
    cases(&mut no_variant)[0] = path(Vec::new(), STATE);
    bad(&no_variant, "selects no variant first");

    let mut tokio_match = b.clone();
    tokio_match.semantics.types[tls]
        .io_route
        .as_mut()
        .unwrap()
        .rule = SemanticRuleId(0);
    bad(&tokio_match, "incompatible capability");

    let mut rustls_socket = b.clone();
    rustls_socket.semantics.types[child]
        .io_route
        .as_mut()
        .unwrap()
        .rule = SemanticRuleId(2);
    bad(&rustls_socket, "incompatible capability");

    let mut dangling = b.clone();
    dangling.semantics.types[tls].io_route = None;
    bad(&dangling, "forwards to an unrouted type");

    // Every case has to end at a socket, not just one.
    let mut dead_case = b.clone();
    let TypeDef::Enum { shape, .. } = &mut dead_case.types.types[STATE.0 as usize] else {
        unreachable!()
    };
    shape.variants.push(VariantDef {
        name: FIELD,
        discr_values: None,
        payload: MemberDef {
            name: FIELD,
            ty: BundleTypeId(0),
            offset: 8,
        },
        decl: None,
        await_site: None,
    });
    cases(&mut dead_case).push(path(vec![Step::Variant(FIELD)], BundleTypeId(0)));
    bad(&dead_case, "forwards to an unrouted type");

    let mut other_revision = b.clone();
    let SemanticOrigin::GitDelegation { revision, .. } = &mut other_revision.semantics.origins[2]
    else {
        unreachable!()
    };
    *revision = StrRef(46);
    bad(&other_revision, "names another repository or revision");

    let mut registry = b.clone();
    let SemanticOrigin::GitDelegation { source, .. } = &mut registry.semantics.origins[2] else {
        unreachable!()
    };
    *source = StrRef(40);
    bad(&registry, "not a git checkout path");

    let mut released = b.clone();
    released.semantics.rules[3].origin = SemanticOriginId(1);
    bad(&released, "git delegation needs checkout evidence");

    let mut checked_out = b.clone();
    checked_out.semantics.rules[2].origin = SemanticOriginId(2);
    bad(&checked_out, "third-party delegation needs source evidence");
}

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
            SemanticRuleKind::FuturesUtilMap,
            StrRef(22),
            StrRef(23),
            StrRef(24),
        ),
        (
            SemanticRuleKind::FuturesUtilMapErr,
            StrRef(22),
            StrRef(23),
            StrRef(24),
        ),
        (
            SemanticRuleKind::FuturesUtilIntoFuture,
            StrRef(22),
            StrRef(23),
            StrRef(24),
        ),
        (
            SemanticRuleKind::HyperUtilTokioSleep,
            StrRef(25),
            StrRef(26),
            StrRef(27),
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
    for (kind, rule) in [
        (AccessKind::Owned, SemanticRuleKind::StdBoxAccess),
        (AccessKind::Owned, SemanticRuleKind::StdPinBoxAccess),
        (AccessKind::Borrowed, SemanticRuleKind::StdMutRefAccess),
        (AccessKind::Borrowed, SemanticRuleKind::StdPinMutRefAccess),
    ] {
        let mut b = base();
        b.semantics.rules[0].kind = rule;
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
    // An I/O operation's essential routes are its own reader/writer or
    // node and the registration reached through it, never a contained
    // socket's own `shared` route.
    for (operation, roles, routes) in [
        (
            IoOperationKind::Read,
            vec![WalkRole::IoReadReader, WalkRole::IoReadBufLen],
            vec![WalkRole::IoReadShared],
        ),
        (
            IoOperationKind::WriteAll,
            vec![WalkRole::IoWriteAllWriter, WalkRole::IoWriteAllBufLen],
            vec![WalkRole::IoWriteAllShared],
        ),
        (
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
        ),
    ] {
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
    b.semantics.types[0].storage = StoragePolicy::Unavailable(issue());
    bad(&b, "unavailable storage carries a readable capability");
    b.semantics.types[0].storage = StoragePolicy::DeclaredMembers;
    b.walks.entries.remove(&WalkRole::JoinSetIdleHead);
    bad(&b, "essential walk route");
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

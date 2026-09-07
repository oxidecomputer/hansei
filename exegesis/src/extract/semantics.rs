// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sparse identity seeds and the library-layout bindings. Compiler
//! candidates retain an unavailable storage boundary until a reviewed
//! defining-origin convention can bind them; Tokio and futures-util
//! resource, container and scheduler facts bind from the walk contract's
//! own roots, so each is a layout fact about the exact type it names.

use super::emitter::Emitter;
use super::passes::{members_of, state_name};
use crate::TypeId;
use crate::bundle::names::coroutine_kind;
use crate::bundle::{
    BundleTypeId, ContainerBinding, ContainerKind, Continuation, CoroutineLayout, CoroutinePhase,
    CoroutineState, FutureEvidence, FutureFacts, IoOperationKind, LayoutSelection, PollAction,
    PollProgram, ResourceBinding, ResourceKind, SchedulerBinding, SchedulerClass, SemanticIssue,
    SemanticIssueKind, SemanticOrigin, SemanticOriginId, SemanticRule, SemanticRuleId,
    SemanticRuleKind, SemanticTable, StoragePolicy, StrRef, StringInterner, TaskEntryId,
    TaskFutureEntry, TypeDef, TypeSemantics, TypeTable, WalkOutcome, WalkRole, WalksTable,
    container_roles, container_routes, required_resource_roles, required_resource_routes,
    scheduler_role,
};
use crate::detect::Family;
use crate::detect::semantics::RustcConvention;

use std::collections::{BTreeMap, BTreeSet};

/// What the defining units of a compiler-storage candidate said about
/// the convention its layout follows, decided where the reader's origins
/// are at hand and carried to the binder by bundle id.
#[derive(Clone, Debug)]
pub(super) enum CompilerVerdict {
    /// Every defining unit's producer falls inside one reviewed range.
    Supported {
        /// The canonical definition's producer, as the origin records it.
        producer: String,
        convention: &'static RustcConvention,
    },
    /// Why no convention applies: the reader's decline, spelled out.
    Declined(String),
}

#[derive(Default)]
pub(super) struct Seed {
    polls: BTreeSet<String>,
    coroutine_candidate: bool,
    compiler: Option<CompilerVerdict>,
    resource: Option<ResourceKind>,
    container: Option<ContainerKind>,
}

pub(super) type SemanticSeeds = BTreeMap<BundleTypeId, Seed>;

/// What the library bindings dispatch on: the bound walk contract, and
/// the tokio version and family every versioned row answered from.
pub(super) struct Library<'a> {
    pub(super) walks: &'a WalksTable,
    pub(super) tokio_version: Option<&'a semver::Version>,
    pub(super) family: Family,
}

pub(super) fn collect_semantic_seeds(
    em: &Emitter<'_>,
    polls: &BTreeMap<TypeId, BTreeSet<String>>,
    coroutines: &BTreeSet<TypeId>,
    mut verdict: impl FnMut(TypeId) -> CompilerVerdict,
) -> SemanticSeeds {
    let mut seeds = SemanticSeeds::new();
    for (raw, _) in em.emitted_named() {
        let Some(ty) = em.bundle_id_of(raw) else {
            continue;
        };
        let name = em
            .reader
            .canonical_type(raw)
            .and_then(|t| t.name())
            .map(|n| em.reader.strings.get(n))
            .unwrap_or_default();
        let candidate =
            coroutines.contains(&raw) || crate::bundle::names::is_coroutine_candidate(name);
        if candidate {
            let seed = seeds.entry(ty).or_default();
            seed.coroutine_candidate = true;
            seed.compiler = Some(verdict(raw));
        }
    }
    for (raw, symbols) in polls {
        // Poll roots have already been emitted through the dynamic table.
        if let Some(ty) = em.bundle_id_of(*raw) {
            seeds
                .entry(ty)
                .or_default()
                .polls
                .extend(symbols.iter().cloned());
        }
    }
    seeds
}

/// The every-kind order the bindings are attempted in, which is also the
/// order their rules are numbered: a bundle's rule ids depend on which
/// kinds bound, never on the order types were met.
const RESOURCE_KINDS: [(ResourceKind, SemanticRuleKind); 6] = [
    (ResourceKind::Sleep, SemanticRuleKind::TokioSleep),
    (ResourceKind::JoinHandle, SemanticRuleKind::TokioJoinHandle),
    (
        ResourceKind::SemaphoreAcquire,
        SemanticRuleKind::TokioAcquire,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::Read),
        SemanticRuleKind::TokioIoOperation,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::WriteAll),
        SemanticRuleKind::TokioIoOperation,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::Readiness),
        SemanticRuleKind::TokioIoOperation,
    ),
];

const CONTAINER_KINDS: [(ContainerKind, SemanticRuleKind); 2] = [
    (ContainerKind::JoinSet, SemanticRuleKind::TokioJoinSet),
    (
        ContainerKind::FuturesUnordered,
        SemanticRuleKind::FuturesUnordered,
    ),
];

const SCHEDULER_CLASSES: [(SchedulerClass, SemanticRuleKind); 4] = [
    (
        SchedulerClass::MultiThread,
        SemanticRuleKind::TokioMultiThreadScheduler,
    ),
    (
        SchedulerClass::CurrentThread,
        SemanticRuleKind::TokioCurrentThreadScheduler,
    ),
    (
        SchedulerClass::LocalSet,
        SemanticRuleKind::TokioLocalScheduler,
    ),
    (
        SchedulerClass::Blocking,
        SemanticRuleKind::TokioBlockingScheduler,
    ),
];

/// The types every one of `roles` bound at, provided every chained
/// `route` below them bound too: a binding's roots are the set its
/// spelling resolved against, so a role broken for any root is broken
/// for all, and the intersection is the roots the whole route holds for.
fn bound_roots(
    walks: &WalksTable,
    roles: &[WalkRole],
    routes: &[WalkRole],
) -> BTreeSet<BundleTypeId> {
    let bound = |role: &WalkRole| {
        walks
            .entries
            .get(role)
            .is_some_and(|binding| matches!(binding.outcome, WalkOutcome::Bound { .. }))
    };
    if !routes.iter().all(bound) {
        return BTreeSet::new();
    }
    let mut roots: Option<BTreeSet<BundleTypeId>> = None;
    for role in roles {
        let bound: BTreeSet<BundleTypeId> = match walks.entries.get(role) {
            Some(binding) if matches!(binding.outcome, WalkOutcome::Bound { .. }) => {
                binding.roots.iter().copied().collect()
            }
            _ => BTreeSet::new(),
        };
        roots = Some(match roots {
            Some(roots) => &roots & &bound,
            None => bound,
        });
    }
    roots.unwrap_or_default()
}

/// The origins and rules a bundle applied, interned on first use in a
/// fixed kind order.
struct Rules {
    origins: Vec<SemanticOrigin>,
    rules: Vec<SemanticRule>,
    by_kind: Vec<(SemanticRuleKind, SemanticRuleId)>,
    tokio: Option<SemanticOriginId>,
    futures_util: Option<SemanticOriginId>,
    /// Compiler origins by producer string, and the rules under each:
    /// two producers inside one reviewed range are two origins.
    rustc: Vec<(String, SemanticOriginId)>,
    rustc_rules: Vec<(SemanticRuleKind, SemanticOriginId, SemanticRuleId)>,
}

impl Rules {
    fn origin(
        &mut self,
        kind: SemanticRuleKind,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> SemanticOriginId {
        let (slot, origin) = if kind == SemanticRuleKind::FuturesUnordered {
            // The set walker's layout has held across every futures-util
            // release the fixtures cover, and no version is recovered for
            // it: its rows are unversioned, and the origin says so.
            let origin = SemanticOrigin::LibraryLayout {
                package: strings.intern("futures-util"),
                version: None,
                family: strings.intern("unversioned"),
                selection: LayoutSelection::VersionUnknown,
            };
            (&mut self.futures_util, origin)
        } else {
            let origin = SemanticOrigin::LibraryLayout {
                package: strings.intern("tokio"),
                version: library
                    .tokio_version
                    .map(|version| strings.intern(&version.to_string())),
                family: strings.intern(library.family.name()),
                selection: Family::layout_selection(library.tokio_version),
            };
            (&mut self.tokio, origin)
        };
        if let Some(id) = *slot {
            return id;
        }
        let id = SemanticOriginId(u32::try_from(self.origins.len()).expect("origin overflow"));
        self.origins.push(origin);
        *slot = Some(id);
        id
    }

    /// The rule of a compiler kind under the origin of one producer,
    /// interned on first use.
    fn rustc_rule(
        &mut self,
        kind: SemanticRuleKind,
        producer: &str,
        convention: &RustcConvention,
        strings: &mut StringInterner,
    ) -> SemanticRuleId {
        let origin = match self.rustc.iter().find(|(p, _)| p == producer) {
            Some((_, id)) => *id,
            None => {
                let id =
                    SemanticOriginId(u32::try_from(self.origins.len()).expect("origin overflow"));
                self.origins.push(SemanticOrigin::Rustc {
                    producer: strings.intern(producer),
                    family: strings.intern(convention.family),
                });
                self.rustc.push((producer.to_owned(), id));
                id
            }
        };
        if let Some((_, _, id)) = self
            .rustc_rules
            .iter()
            .find(|(k, o, _)| *k == kind && *o == origin)
        {
            return *id;
        }
        let id = SemanticRuleId(u32::try_from(self.rules.len()).expect("rule overflow"));
        self.rules.push(SemanticRule {
            kind,
            revision: 1,
            origin,
        });
        self.rustc_rules.push((kind, origin, id));
        id
    }

    fn rule(
        &mut self,
        kind: SemanticRuleKind,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> SemanticRuleId {
        if let Some((_, id)) = self.by_kind.iter().find(|(k, _)| *k == kind) {
            return *id;
        }
        let origin = self.origin(kind, strings, library);
        let id = SemanticRuleId(u32::try_from(self.rules.len()).expect("rule overflow"));
        self.rules.push(SemanticRule {
            kind,
            revision: 1,
            origin,
        });
        self.by_kind.push((kind, id));
        id
    }
}

/// Run after type demotion and coroutine member pruning, while strings can
/// still be interned. Identity survives an opaque executable layout; the
/// library bindings attach to the exact types the walk contract bound
/// its routes at, and a task entry's scheduler class to the entry whose
/// `S` the class's route bound at.
pub(super) fn bind_semantics(
    mut seeds: SemanticSeeds,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
    tasks: &mut [TaskFutureEntry],
    library: &Library<'_>,
) -> SemanticTable {
    let mut rules = Rules {
        origins: Vec::new(),
        rules: Vec::new(),
        by_kind: Vec::new(),
        tokio: None,
        futures_util: None,
        rustc: Vec::new(),
        rustc_rules: Vec::new(),
    };
    let mut task_evidence: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (i, task) in tasks.iter().enumerate() {
        seeds.entry(task.future).or_default();
        task_evidence
            .entry(task.future)
            .or_default()
            .push(FutureEvidence::TaskEntry(TaskEntryId(
                u32::try_from(i).expect("task table overflow"),
            )));
    }
    for (kind, _) in RESOURCE_KINDS {
        for ty in bound_roots(
            library.walks,
            required_resource_roles(kind),
            required_resource_routes(kind),
        ) {
            seeds.entry(ty).or_default().resource = Some(kind);
        }
    }
    for (kind, _) in CONTAINER_KINDS {
        for ty in bound_roots(library.walks, container_roles(kind), container_routes(kind)) {
            seeds.entry(ty).or_default().container = Some(kind);
        }
    }
    let issue = |kind| SemanticIssue { kind, detail: None };
    let mut records = Vec::with_capacity(seeds.len());
    for (ty, seed) in seeds {
        let mut evidence = task_evidence.remove(&ty).unwrap_or_default();
        evidence.extend(
            seed.polls
                .iter()
                .map(|symbol| FutureEvidence::PollSymbol(strings.intern(symbol))),
        );
        let mut issues = Vec::new();
        let mut coroutine = None;
        let storage = if seed.coroutine_candidate {
            // A compiler candidate reads its states only under a reviewed
            // convention that its every defining unit supports and whose
            // shape this enum then actually has; anything less leaves the
            // storage unavailable, with the reason beside it.
            match bind_coroutine(ty, &seed, types, names, strings, &mut rules) {
                Ok((rule, layout)) => {
                    evidence.push(FutureEvidence::Coroutine(rule));
                    coroutine = Some(layout);
                    StoragePolicy::CoroutineStates
                }
                Err((kind, detail)) => {
                    let detail = strings.intern(&detail);
                    issues.push(SemanticIssue {
                        kind,
                        detail: Some(detail),
                    });
                    StoragePolicy::Unavailable(SemanticIssue {
                        kind,
                        detail: Some(detail),
                    })
                }
            }
        } else if matches!(types.get(ty), Some(TypeDef::Opaque { .. })) {
            StoragePolicy::Unavailable(issue(SemanticIssueKind::MissingLayout))
        } else {
            StoragePolicy::DeclaredMembers
        };
        evidence.sort();
        evidence.dedup();
        // A capability needs readable storage; a route cannot have bound
        // at a type without it, so this only guards the record's shape.
        let readable = matches!(storage, StoragePolicy::DeclaredMembers);
        let resource = seed.resource.filter(|_| readable).map(|kind| {
            let rule_kind = RESOURCE_KINDS
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, rule)| *rule)
                .expect("every resource kind has a rule");
            ResourceBinding {
                rule: rules.rule(rule_kind, strings, library),
                kind,
                state_rule: None,
                exclusive_pending: false,
            }
        });
        let container = seed.container.filter(|_| readable).map(|kind| {
            let rule_kind = CONTAINER_KINDS
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, rule)| *rule)
                .expect("every container kind has a rule");
            ContainerBinding {
                rule: rules.rule(rule_kind, strings, library),
                kind,
            }
        });
        // A resource that is positively a future polls its own state and
        // nothing else: its continuation is the primitive boundary. What
        // that state means — ready, pending, closed — is the state
        // rule's to say, and none is bound here.
        let continuation = match &resource {
            Some(resource) => Continuation::Bound {
                rule: resource.rule,
                program: PollProgram::Direct(PollAction::Primitive),
            },
            None => Continuation::Unknown(issue(SemanticIssueKind::NoRule)),
        };
        records.push(TypeSemantics {
            ty,
            storage,
            future: (!evidence.is_empty()).then_some(FutureFacts {
                evidence,
                continuation,
            }),
            coroutine,
            access: None,
            resource,
            container,
            issues,
        });
    }
    for task in tasks.iter_mut() {
        let mut classes = SCHEDULER_CLASSES.iter().filter(|(class, _)| {
            bound_roots(library.walks, &[scheduler_role(*class)], &[]).contains(&task.scheduler)
        });
        // Exactly one class may claim an entry's S; the roots are exact
        // types, so two claiming the same one is a table bug, and the
        // entry is left unknown rather than guessed.
        task.scheduler_binding = match (classes.next(), classes.next()) {
            (Some((class, rule_kind)), None) => Some(SchedulerBinding {
                class: *class,
                rule: rules.rule(*rule_kind, strings, library),
            }),
            _ => None,
        };
    }
    SemanticTable {
        origins: rules.origins,
        rules: rules.rules,
        types: records,
    }
}

/// The stage rustc's variant numbering assigns, and the payload name it
/// carries: the convention the reviewed range was checked for.
fn expected_state(index: usize) -> (CoroutinePhase, String) {
    match index {
        0 => (CoroutinePhase::Unresumed, "Unresumed".to_owned()),
        1 => (CoroutinePhase::Returned, "Returned".to_owned()),
        2 => (CoroutinePhase::Panicked, "Panicked".to_owned()),
        n => (CoroutinePhase::Suspended, format!("Suspend{}", n - 3)),
    }
}

type Decline = (SemanticIssueKind, String);

/// Bind a compiler candidate's states under its reviewed convention, or
/// say why not. The verdict on its defining units comes first; the enum
/// is then held to the convention's exact shape — numbered variants in
/// stage order, payload names to match, terminal states emptied — and
/// each state's members are classed: an `Unresumed`'s are its arguments,
/// a suspended state's are the locals live across its await, except
/// that an async block's captures, which the state kept whether or not
/// the body has moved them out, are uncertain.
fn bind_coroutine(
    ty: BundleTypeId,
    seed: &Seed,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
    rules: &mut Rules,
) -> Result<(SemanticRuleId, CoroutineLayout), Decline> {
    let (producer, convention) = match &seed.compiler {
        Some(CompilerVerdict::Supported {
            producer,
            convention,
        }) => (producer, *convention),
        Some(CompilerVerdict::Declined(detail)) => {
            return Err((SemanticIssueKind::UnsupportedOrigin, detail.clone()));
        }
        None => {
            return Err((
                SemanticIssueKind::UnsupportedOrigin,
                "no defining unit recorded".to_owned(),
            ));
        }
    };
    let name = names
        .get(ty.0 as usize)
        .and_then(|n| n.as_deref())
        .unwrap_or_default();
    let kind = match coroutine_kind(name) {
        Some("async fn") => SemanticRuleKind::RustcAsyncFn,
        Some("async block") => SemanticRuleKind::RustcAsyncBlock,
        _ => {
            return Err((
                SemanticIssueKind::NoRule,
                "only async fn and async block environments have a reviewed rule".to_owned(),
            ));
        }
    };
    let states = coroutine_states(
        ty,
        kind == SemanticRuleKind::RustcAsyncBlock,
        types,
        names,
        strings,
    )?;
    let rule = rules.rustc_rule(kind, producer, convention, strings);
    Ok((rule, CoroutineLayout { rule, states }))
}

/// Hold the final enum to the convention's shape and class each state's
/// members. `strings` is read only, for the variant keys.
fn coroutine_states(
    ty: BundleTypeId,
    is_block: bool,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<Vec<CoroutineState>, Decline> {
    let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the environment is not an enum".to_owned(),
        ));
    };
    if shape.variants.len() < 3 {
        return Err((
            SemanticIssueKind::UnsupportedState,
            format!(
                "{} variants, fewer than the three fixed stages",
                shape.variants.len()
            ),
        ));
    }
    let unresumed: BTreeSet<(StrRef, BundleTypeId, u64)> =
        members_of(types, shape.variants[0].payload.ty)
            .iter()
            .map(|m| (m.name, m.ty, m.offset))
            .collect();
    let mut states = Vec::with_capacity(shape.variants.len());
    for (index, variant) in shape.variants.iter().enumerate() {
        let key = strings.get(variant.name).unwrap_or_default();
        if key != index.to_string() {
            return Err((
                SemanticIssueKind::UnsupportedState,
                format!("variant {index} is keyed {key:?}, not by its position"),
            ));
        }
        let (stage, expected) = expected_state(index);
        let actual = state_name(names, variant.payload.ty).unwrap_or_default();
        if actual != expected {
            return Err((
                SemanticIssueKind::UnsupportedState,
                format!("variant {index} is {actual:?}, not {expected:?}"),
            ));
        }
        if !matches!(types.get(variant.payload.ty), Some(TypeDef::Struct { .. })) {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{expected} is not a struct"),
            ));
        }
        let members = members_of(types, variant.payload.ty);
        let mut seen = BTreeSet::new();
        for member in members {
            if !seen.insert(member.name) {
                return Err((
                    SemanticIssueKind::AmbiguousLayout,
                    format!(
                        "{expected} lists {:?} twice",
                        strings.get(member.name).unwrap_or_default()
                    ),
                ));
            }
        }
        let (locals, uncertain_locals): (Vec<StrRef>, Vec<StrRef>) = match stage {
            CoroutinePhase::Returned | CoroutinePhase::Panicked => {
                if !members.is_empty() {
                    return Err((
                        SemanticIssueKind::UnsupportedState,
                        format!("{expected} still lists {} members", members.len()),
                    ));
                }
                (Vec::new(), Vec::new())
            }
            CoroutinePhase::Unresumed => (members.iter().map(|m| m.name).collect(), Vec::new()),
            CoroutinePhase::Suspended => {
                let (captures, live): (Vec<_>, Vec<_>) = members
                    .iter()
                    .partition(|m| is_block && unresumed.contains(&(m.name, m.ty, m.offset)));
                (
                    live.into_iter().map(|m| m.name).collect(),
                    captures.into_iter().map(|m| m.name).collect(),
                )
            }
            CoroutinePhase::Unknown => unreachable!("expected_state never says unknown"),
        };
        states.push(CoroutineState {
            variant: variant.name,
            stage,
            locals,
            uncertain_locals,
        });
    }
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{MemberDef, VariantDef, VariantShape};

    /// A coroutine env spelled the way rustc does: numbered variants whose
    /// payload structs carry the state names, with the member sets the
    /// state pass leaves behind.
    struct Env {
        types: TypeTable,
        names: Vec<Option<String>>,
        strings: StringInterner,
        env: BundleTypeId,
    }

    fn env(kind: &str, states: &[(&str, &[&str])], keys: &[&str]) -> Env {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = vec![Some("u32".to_owned())];
        let mut types = vec![TypeDef::Base {
            name: strings.intern("u32"),
            size: 4,
            encoding: crate::Encoding::Unsigned,
        }];
        let env_name = format!("app::work::{{{kind}_env#0}}");
        let mut variants = Vec::new();
        for (index, (state, members)) in states.iter().enumerate() {
            let payload = BundleTypeId(types.len() as u32);
            let name = format!("{env_name}::{state}");
            types.push(TypeDef::Struct {
                name: strings.intern(&name),
                size: 32,
                members: members
                    .iter()
                    .enumerate()
                    .map(|(i, m)| MemberDef {
                        name: strings.intern(m),
                        ty: BundleTypeId(0),
                        // A repeated name at a distinct slot is the
                        // shadowed-local case; the same name at the same
                        // slot is what the capture check keys on.
                        offset: 4 * i as u64,
                    })
                    .collect(),
            });
            names.push(Some(name));
            let key = strings.intern(keys.get(index).copied().unwrap_or(&index.to_string()));
            variants.push(VariantDef {
                name: key,
                discr_values: None,
                payload: MemberDef {
                    name: key,
                    ty: payload,
                    offset: 0,
                },
                decl: None,
                await_site: None,
            });
        }
        let env = BundleTypeId(types.len() as u32);
        types.push(TypeDef::Enum {
            name: strings.intern(&env_name),
            size: 32,
            shape: VariantShape {
                discr: None,
                variants,
            },
        });
        names.push(Some(env_name));
        Env {
            types: TypeTable {
                types,
                ..Default::default()
            },
            names,
            strings,
            env,
        }
    }

    fn render(e: &Env, states: &[CoroutineState]) -> Vec<String> {
        let s = |r| e.strings.get(r).unwrap();
        states
            .iter()
            .map(|st| {
                format!(
                    "{}:{:?}[{}]({})",
                    s(st.variant),
                    st.stage,
                    st.locals
                        .iter()
                        .map(|&n| s(n))
                        .collect::<Vec<_>>()
                        .join(","),
                    st.uncertain_locals
                        .iter()
                        .map(|&n| s(n))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect()
    }

    const FN: &[(&str, &[&str])] = &[
        ("Unresumed", &["arg"]),
        ("Returned", &[]),
        ("Panicked", &[]),
        ("Suspend0", &["local", "__awaitee"]),
        ("Suspend1", &["__awaitee"]),
    ];

    #[test]
    fn test_async_fn_states_class_arguments_and_live_locals() {
        let e = env("async_fn", FN, &[]);
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(
            render(&e, &states),
            [
                "0:Unresumed[arg]()",
                "1:Returned[]()",
                "2:Panicked[]()",
                "3:Suspended[local,__awaitee]()",
                "4:Suspended[__awaitee]()",
            ]
        );
    }

    /// An async block's suspended states keep its captures at the slot
    /// `Unresumed` lists them at; those are uncertain, everything else is
    /// live. The same name at another slot is a distinct local.
    #[test]
    fn test_async_block_captures_are_uncertain_only_at_their_unresumed_slot() {
        let e = env(
            "async_block",
            &[
                ("Unresumed", &["cap", "other"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["cap", "__awaitee", "other"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, true, &e.types, &e.names, &e.strings).unwrap();
        // `cap` sits at slot 0 in both; `other` moved from slot 4 to 8.
        assert_eq!(render(&e, &states)[3], "3:Suspended[__awaitee,other](cap)");
        // The same shape as an async fn admits every member as live: its
        // arguments were already stripped from the suspended states.
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(render(&e, &states)[3], "3:Suspended[cap,__awaitee,other]()");
    }

    #[test]
    fn test_coroutine_shape_declines_name_each_departure_from_the_convention() {
        let decline = |e: &Env| {
            coroutine_states(e.env, false, &e.types, &e.names, &e.strings)
                .unwrap_err()
                .0
        };
        // Variants keyed by anything but their position.
        let e = env("async_fn", FN, &["0", "1", "2", "Suspend0", "4"]);
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // States out of the fixed order.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Panicked", &[]),
                ("Returned", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // Suspend numbering that skips.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend1", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // A terminal state still listing storage.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &["arg"]),
                ("Panicked", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // A shadowed local listed twice in one state: which is which is
        // not knowable by name, so the whole type declines.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["x", "__awaitee", "x"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::AmbiguousLayout);
        // Too few variants for the three fixed stages.
        let e = env("async_fn", &[("Unresumed", &[]), ("Returned", &[])], &[]);
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // Not an enum at all.
        let mut e = env("async_fn", FN, &[]);
        e.types.types[e.env.0 as usize] = TypeDef::Opaque {
            name: e.strings.intern("app::work::{async_fn_env#0}"),
            size: Some(32),
        };
        assert_eq!(decline(&e), SemanticIssueKind::MissingLayout);
    }
}

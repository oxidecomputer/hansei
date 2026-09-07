// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sparse identity seeds and the library-layout bindings. Compiler
//! candidates retain an unavailable storage boundary until a reviewed
//! defining-origin convention can bind them; Tokio and futures-util
//! resource, container and scheduler facts bind from the walk contract's
//! own roots, so each is a layout fact about the exact type it names.

use super::emitter::Emitter;
use crate::TypeId;
use crate::bundle::{
    BundleTypeId, ContainerBinding, ContainerKind, Continuation, FutureEvidence, FutureFacts,
    IoOperationKind, LayoutSelection, PollAction, PollProgram, ResourceBinding, ResourceKind,
    SchedulerBinding, SchedulerClass, SemanticIssue, SemanticIssueKind, SemanticOrigin,
    SemanticOriginId, SemanticRule, SemanticRuleId, SemanticRuleKind, SemanticTable, StoragePolicy,
    StringInterner, TaskEntryId, TaskFutureEntry, TypeDef, TypeSemantics, TypeTable, WalkOutcome,
    WalkRole, WalksTable, container_roles, container_routes, required_resource_roles,
    required_resource_routes, scheduler_role,
};
use crate::detect::Family;

use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Seed {
    polls: BTreeSet<String>,
    coroutine_candidate: bool,
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
            seeds.entry(ty).or_default().coroutine_candidate = true;
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
        evidence.sort();
        evidence.dedup();
        let storage = if seed.coroutine_candidate {
            StoragePolicy::Unavailable(issue(SemanticIssueKind::UnsupportedOrigin))
        } else if matches!(types.get(ty), Some(TypeDef::Opaque { .. })) {
            StoragePolicy::Unavailable(issue(SemanticIssueKind::MissingLayout))
        } else {
            StoragePolicy::DeclaredMembers
        };
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
            coroutine: None,
            access: None,
            resource,
            container,
            issues: Vec::new(),
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

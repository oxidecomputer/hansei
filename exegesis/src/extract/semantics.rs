// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sparse identity seeds. Compiler candidates retain an unavailable storage
//! boundary until a reviewed defining-origin convention can bind them.

use super::emitter::Emitter;
use crate::TypeId;
use crate::bundle::{
    BundleTypeId, Continuation, FutureEvidence, FutureFacts, SemanticIssue, SemanticIssueKind,
    SemanticTable, StoragePolicy, StringInterner, TaskEntryId, TaskFutureEntry, TypeDef,
    TypeSemantics, TypeTable,
};

use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Seed {
    polls: BTreeSet<String>,
    coroutine_candidate: bool,
}

pub(super) type SemanticSeeds = BTreeMap<BundleTypeId, Seed>;

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

/// Run after type demotion and coroutine member pruning, while strings can
/// still be interned. Identity survives an opaque executable layout.
pub(super) fn bind_semantics(
    mut seeds: SemanticSeeds,
    types: &TypeTable,
    strings: &mut StringInterner,
    tasks: &[TaskFutureEntry],
) -> SemanticTable {
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
    let issue = |kind| SemanticIssue { kind, detail: None };
    let records = seeds
        .into_iter()
        .map(|(ty, seed)| {
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
            TypeSemantics {
                ty,
                storage,
                future: (!evidence.is_empty()).then(|| FutureFacts {
                    evidence,
                    continuation: Continuation::Unknown(issue(SemanticIssueKind::NoRule)),
                }),
                coroutine: None,
                access: None,
                resource: None,
                container: None,
                issues: Vec::new(),
            }
        })
        .collect();
    SemanticTable {
        types: records,
        ..Default::default()
    }
}

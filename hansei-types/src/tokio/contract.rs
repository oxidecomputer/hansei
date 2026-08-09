// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The runtime walk over the bundle's recorded bindings.
//!
//! Everything the walk navigates *by declaration* — the member chains
//! below the bundle's infra roots, and the leaf readers rooted at
//! name-keyed types (`Sleep`, `JoinHandle`, `Acquire`, the census's
//! `FuturesUnordered` and `JoinSet`) — travels in the bundle as a
//! [`WalkBinding`] per [`WalkRole`]: a navigation exegesis resolved
//! against the target's own DWARF at extraction, where the layout is
//! ground truth. This module executes those recorded steps over target
//! memory ([`Context::walk`]) and applies policy to the recorded
//! outcomes ([`verify_walk_contract`]): which spelling bound, what is
//! absent and why, what broke — decided at extraction, read here.
//!
//! The runtime layer holds **zero version logic**. A tokio release that
//! moves a walked layout is a family-keyed entry in exegesis's binder
//! (`detect/walk.rs`); nothing here changes.
//!
//! Recorded steps are literal: every wrapper level is a step, so the
//! walker descends exactly what is written — no implicit peeling. The
//! two runtime outcomes that are states rather than failures survive
//! unchanged: a [`Step::Deref`] over a null word is [`Walked::Null`],
//! and a [`Step::Variant`] whose variant is not the live one is
//! [`Walked::Inactive`].
//!
//! What is *not* here is the await-chain recursion: it walks arbitrary
//! coroutine types whose conventions (`__awaitee` naming, variant
//! encoding, what survives inlining) cannot be a recorded path. Its
//! cross-version coverage is behavioral, not declarative.

use super::bundle::Context;

use anyhow::{Context as _, Result, anyhow, bail};
use exegesis::bundle::{
    BundleMember, BundleType, BundleView, MemberRef, StaticRole, Step, WalkOutcome, WalkRole,
};
use proc::Target;
use reify::{ParseWithDbgInfo, TypeInfo, TypeInfoRef};

use std::fmt;

// ---------------------------------------------------------------------------
// Name keys shared by the walk and the leaf readers
// ---------------------------------------------------------------------------

/// `tokio::time::Sleep`'s leaf future.
pub const SLEEP: &str = "tokio::time::sleep::Sleep";
/// A join edge to another task.
pub const JOIN_HANDLE: &str = "tokio::runtime::task::join::JoinHandle<";
/// The future queued on the semaphore backing Mutex/RwLock/Semaphore.
pub const ACQUIRE: &str = "tokio::sync::batch_semaphore::Acquire";
/// The by-value type every `FuturesUnordered` is recognized as.
pub const FUTURES_UNORDERED: &str = "futures_util::stream::futures_unordered::FuturesUnordered<";
/// The by-value type every join set is recognized as.
pub const JOIN_SET: &str = "tokio::task::join_set::JoinSet<";

/// Whether `name` is a type a leaf key names. A key ending in `<` is a
/// generic: the prefix of every monomorphization's name. Any other key
/// is an exact fully-qualified name — a bare prefix match would take
/// lookalike siblings with it (`batch_semaphore::Acquire` is one
/// character away from `AcquireError`).
pub fn leaf_matches(key: &str, name: &str) -> bool {
    if key.ends_with('<') {
        name.starts_with(key)
    } else {
        name == key
    }
}

/// `Stage<T>`'s variant names, as the stage decode matches them.
pub const STAGE_RUNNING: &str = "Running";
pub const STAGE_FINISHED: &str = "Finished";
pub const STAGE_CONSUMED: &str = "Consumed";

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// What a role failing to bind means for the walk. This is the
/// consumer's question — "can this walker function without the datum" —
/// so it lives here, not in the bundle: extraction records facts, the
/// consumer states needs.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Class {
    /// The walk cannot function without it: runtime discovery, task
    /// enumeration, the stage decode. Broken always refuses to attach.
    Required,
    /// Supporting output the walk can degrade without — park states,
    /// leaf readers, the census walks. Broken refuses to attach under
    /// [`WalkPolicy::Strict`] and degrades under
    /// [`WalkPolicy::BestEffort`].
    Optional,
}

/// The class of every role. The match is exhaustive on purpose: a role
/// added to the schema does not compile here until it is classed.
pub fn classify(role: WalkRole) -> Class {
    use WalkRole::*;
    match role {
        // Runtime discovery and task enumeration.
        CurrentTaskId | WorkerHandle | HandleShared | OwnedLists | ShardHead | HeaderState
        | HeaderOwnerId | HeaderVtable | TrailerNext => Class::Required,
        // The target-recorded vtable offsets and the poll join key.
        VtablePoll | VtableTrailerOffset | VtableIdOffset => Class::Required,
        // Spawn locations' Location layout.
        LocationFile | LocationLine | LocationCol => Class::Required,
        // The stage decode and the offset cross-check.
        CellStage | CellStageRunning | CellStageFinished | CellStageConsumed | CellTrailer
        | CellTaskId => Class::Required,
        // Scheduler introspection beyond the listing.
        WorkerContext | WorkerIndex | SharedRemotes | RemoteUnpark | ParkerState
        | ParkerDriverLock | BlockingMetrics | BlockingThreads | BlockingIdle
        | BlockingQueueDepth => Class::Optional,
        // The sibling vtable fns the future join falls through.
        VtableDealloc
        | VtableTryReadOutput
        | VtableDropJoinHandleSlow
        | VtableDropAbortHandle
        | VtableShutdown
        | VtableSpawnLocationOffset => Class::Optional,
        // Leaf readers and the census walks.
        SleepDeadline | DeadlineTvSec | DeadlineTvNsec | JoinHandleRaw | AcquireSemaphore
        | AcquireNumPermits | AcquireNode | AcquireNeeded | AcquireQueued | SemaphorePermits
        | SemaphoreQueueHead | WaiterNeeded | WaiterNext | WaiterWaker | WakerData
        | WakerVtable | SetHeadAll | SetNodeFuture | SetNodeNext | JoinSetLength | JoinSetLists
        | JoinSetNotifiedHead | JoinSetIdleHead | JoinSetEntryValue | JoinSetEntryNext => {
            Class::Optional
        }
    }
}

// ---------------------------------------------------------------------------
// The runtime executor
// ---------------------------------------------------------------------------

/// Where a walk ended: at the terminal, or at one of the two outcomes
/// that are runtime states rather than failures.
pub enum Walked<'b> {
    At(TypeInfo<'b>),
    /// A [`Step::Variant`] step found some other variant active; the
    /// name is the variant the step asked for.
    Inactive(&'b str),
    /// A [`Step::Deref`] step found a null pointer.
    Null,
}

impl<'b> Walked<'b> {
    /// The terminal, for callers to whom an inactive variant (a `None`
    /// head, an unarmed waker) and a null pointer both mean "nothing
    /// here".
    pub fn optional(self) -> Option<TypeInfo<'b>> {
        match self {
            Walked::At(info) => Some(info),
            Walked::Inactive(_) | Walked::Null => None,
        }
    }

    /// The terminal, treating the runtime outcomes as errors — for
    /// paths whose steps admit neither.
    fn at(self, name: &str) -> Result<TypeInfo<'b>> {
        match self {
            Walked::At(info) => Ok(info),
            Walked::Inactive(v) => bail!("{name}: variant {v} is not active"),
            Walked::Null => bail!("{name}: null pointer"),
        }
    }
}

impl<'b, T: Target> Context<'b, T> {
    /// The recorded binding for a role, as a handle the walk executes
    /// through. Looking one up is free; whether the role actually bound
    /// is answered when the handle is walked or read.
    pub fn walk(&self, role: WalkRole) -> Bound<'_, 'b, T> {
        Bound { ctx: self, role }
    }
}

/// A role's recorded binding, resolved against a [`Context`] — the read
/// API the walk's accessors go through. `walk`/`read` treat an unbound
/// role as an error; the `try_` forms treat it as `None`, for the roles
/// whose absence is an expected shape of the target (an unused leaf, a
/// plain build's missing instrumentation).
pub struct Bound<'a, 'b, T> {
    ctx: &'a Context<'b, T>,
    role: WalkRole,
}

impl<'b, T: Target> Bound<'_, 'b, T> {
    fn name(&self) -> &'static str {
        self.role.name()
    }

    /// The recorded steps when the role bound, or the recorded reason it
    /// did not.
    fn steps(&self) -> std::result::Result<&'b [Step], String> {
        match self.ctx.view.bundle().walks.entries.get(&self.role) {
            None => Err("the bundle records no walk binding for this role".to_owned()),
            Some(binding) => match &binding.outcome {
                WalkOutcome::Bound { .. } => Ok(&binding.steps),
                WalkOutcome::Absent { reason } => Err(reason.clone()),
                WalkOutcome::Broken { errors } => Err(errors.join("; ")),
            },
        }
    }

    /// Execute the recorded steps from `root`.
    pub fn walk(&self, root: TypeInfoRef<'_, 'b>) -> Result<Walked<'b>> {
        match self.steps() {
            Ok(steps) => walk_steps(self.ctx, root, steps)
                .with_context(|| format!("walk path {}", self.name())),
            Err(reason) => bail!("walk path {}: {reason}", self.name()),
        }
    }

    /// Like [`Bound::walk`], but an unbound role is `None` — for
    /// [`Class::Optional`] members whose absence is an expected shape.
    pub fn try_walk(&self, root: TypeInfoRef<'_, 'b>) -> Result<Option<Walked<'b>>> {
        match self.steps() {
            Ok(steps) => walk_steps(self.ctx, root, steps)
                .map(Some)
                .with_context(|| format!("walk path {}", self.name())),
            Err(_) => Ok(None),
        }
    }

    /// Walk to the terminal, where the steps admit no variant or null
    /// outcome (or where either would be a hard error anyway).
    pub fn walk_at(&self, root: TypeInfoRef<'_, 'b>) -> Result<TypeInfo<'b>> {
        self.walk(root)?.at(self.name())
    }

    /// Walk to the terminal and parse a value out of it.
    pub fn read<V>(&self, root: TypeInfoRef<'_, 'b>) -> Result<V>
    where
        V: ParseWithDbgInfo<'b, Context<'b, T>>,
    {
        let info = self.walk_at(root)?;
        info.parse(self.ctx)
            .with_context(|| format!("walk path {}", self.name()))
    }

    /// [`Bound::read`] for a member whose absence is expected.
    pub fn try_read<V>(&self, root: TypeInfoRef<'_, 'b>) -> Result<Option<V>>
    where
        V: ParseWithDbgInfo<'b, Context<'b, T>>,
    {
        match self.try_walk(root)? {
            Some(w) => {
                let info = w.at(self.name())?;
                let v = info
                    .parse(self.ctx)
                    .with_context(|| format!("walk path {}", self.name()))?;
                Ok(Some(v))
            }
            None => Ok(None),
        }
    }

    /// The byte offset the recorded steps reach within `root` — for
    /// cross-checking a bundle layout against offsets the target itself
    /// records. Only member steps carry an offset; `None` where the role
    /// is unbound or the navigation does not apply to this type.
    pub(crate) fn member_offset(&self, root: BundleType<'_>) -> Option<u64> {
        let steps = self.steps().ok()?;
        let mut ty = root;
        let mut offset = 0;
        for step in steps {
            let Step::Member(at) = step else { return None };
            let member = member_at(&self.ctx.view, ty, at)?;
            offset += member.offset();
            ty = member.ty();
        }
        Some(offset)
    }
}

/// The unique member a recorded step addresses, resolved by the shared
/// [`MemberRef`] rule — so the runtime walker means exactly what bundle
/// validation checked.
fn member_at<'b>(
    view: &BundleView<'b>,
    ty: BundleType<'b>,
    at: &MemberRef,
) -> Option<BundleMember<'b>> {
    let members: Vec<BundleMember<'b>> = ty.members().collect();
    let index = at.resolve(members.len(), |i, name| {
        view.str(name) == Some(members[i].name())
    })?;
    Some(members[index])
}

/// Execute recorded steps over target memory, literally: a member or
/// variant step descends exactly the level it names, with no wrapper
/// peeling — recorded bindings spell every level explicitly.
fn walk_steps<'b, T: Target>(
    ctx: &Context<'b, T>,
    cur: TypeInfoRef<'_, 'b>,
    steps: &[Step],
) -> Result<Walked<'b>> {
    let [step, rest @ ..] = steps else {
        return Ok(Walked::At(cur.to_owned()));
    };
    let slice = |offset: u64, size: u64| -> Result<&[u8]> {
        cur.bytes
            .get(offset as usize..(offset + size) as usize)
            .ok_or_else(|| {
                anyhow!(
                    "bytes {offset}..{} do not fit {} bytes of {}",
                    offset + size,
                    cur.bytes.len(),
                    cur.ty.name()
                )
            })
    };
    match step {
        Step::Member(at) => {
            let member = member_at(&ctx.view, cur.ty, at).ok_or_else(|| match at {
                MemberRef::Named(name) => {
                    anyhow!(no_member(
                        cur.ty,
                        ctx.view.str(*name).unwrap_or("<bad strref>")
                    ))
                }
                MemberRef::Index(index) => {
                    anyhow!("no member at index {index} in {}", cur.ty.name())
                }
            })?;
            let bytes = slice(member.offset(), member.ty().size())?;
            let next = TypeInfoRef::new(member.ty(), cur.addr + member.offset(), bytes);
            walk_steps(ctx, next, rest)
        }
        Step::Variant(name) => {
            let name = ctx
                .view
                .str(*name)
                .ok_or_else(|| anyhow!("unresolvable variant name in {}", cur.ty.name()))?;
            match cur.ty.check_variant(cur.bytes, name) {
                None => bail!("{} is not an enum", cur.ty.name()),
                Some(Err(e)) => {
                    Err(anyhow!("{e}").context(format!("variant {name} of {}", cur.ty.name())))
                }
                Some(Ok(None)) => Ok(Walked::Inactive(name)),
                Some(Ok(Some((payload, offset)))) => {
                    let bytes = slice(offset, payload.size())?;
                    let next = TypeInfoRef::new(payload, cur.addr + offset, bytes);
                    walk_steps(ctx, next, rest)
                }
            }
        }
        Step::ActiveVariant => match cur.ty.active_variant(cur.bytes) {
            None => bail!("{} is not an enum", cur.ty.name()),
            Some(Err(e)) => {
                Err(anyhow!("{e}").context(format!("decoding the variant of {}", cur.ty.name())))
            }
            Some(Ok(active)) => {
                let bytes = slice(active.offset, active.ty.size())?;
                let next = TypeInfoRef::new(active.ty, cur.addr + active.offset, bytes);
                walk_steps(ctx, next, rest)
            }
        },
        Step::Deref => {
            let Some(target) = cur.ty.pointer_target() else {
                bail!("{} is not a pointer", cur.ty.name());
            };
            let Some(&bytes) = cur.bytes.first_chunk::<8>() else {
                bail!(
                    "{} is {} bytes, not a pointer",
                    cur.ty.name(),
                    cur.bytes.len()
                );
            };
            let addr = u64::from_le_bytes(bytes);
            if addr == 0 {
                return Ok(Walked::Null);
            }
            let pointee = TypeInfo::from_addr(ctx, target, addr)
                .map_err(|e| anyhow!(e).context(format!("dereferencing {}", cur.ty.name())))?;
            walk_steps(ctx, pointee.as_ref(), rest)
        }
    }
}

fn no_member(ty: BundleType<'_>, name: &str) -> String {
    let members: Vec<&str> = ty.members().map(|m| m.name()).collect();
    if members.is_empty() {
        format!("no member {name} in {} (which has no members)", ty.name())
    } else {
        format!(
            "no member {name} in {} (has: {})",
            ty.name(),
            members.join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// How [`ContractReport::check`] treats breakage below
/// [`Class::Required`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WalkPolicy {
    /// Any broken path refuses to attach. The default: a silently
    /// degraded walk is how drift goes unnoticed.
    Strict,
    /// Only [`Class::Required`] breakage refuses; everything else
    /// degrades at the site that walks it, for looking at a target
    /// whose inessential layouts have moved.
    BestEffort,
}

/// One row of the report: a role's recorded outcome (or a static's
/// presence), classed by what its breakage would mean.
#[derive(Clone, Debug)]
pub struct ContractEntry {
    pub name: &'static str,
    pub class: Class,
    pub outcome: WalkOutcome,
}

impl ContractEntry {
    pub fn is_broken(&self) -> bool {
        matches!(self.outcome, WalkOutcome::Broken { .. })
    }

    fn line(&self) -> String {
        match &self.outcome {
            WalkOutcome::Bound {
                spelling,
                spellings,
                note,
            } => {
                let mut extras = Vec::new();
                if *spellings > 1 {
                    extras.push(format!("spelling {} of {spellings}", spelling + 1));
                }
                if let Some(note) = note {
                    extras.push(note.clone());
                }
                if extras.is_empty() {
                    format!("ok      {}", self.name)
                } else {
                    format!("ok      {} ({})", self.name, extras.join("; "))
                }
            }
            WalkOutcome::Absent { reason } => format!("absent  {} — {reason}", self.name),
            WalkOutcome::Broken { errors } => {
                format!("BROKEN  {} — {}", self.name, errors.join("; "))
            }
        }
    }
}

/// The bundle's recorded walk outcomes, rendered as one report — same
/// shape the attach-time verifier used to produce, but now a *reading*
/// of what the binder concluded at extraction rather than a second
/// resolution. Produced without a target and without memory reads.
pub fn verify_walk_contract(view: &BundleView<'_>) -> ContractReport {
    use Class::{Optional, Required};

    let meta = &view.bundle().meta;
    let target = format!(
        "tokio {}, rustc {}",
        meta.tokio_version
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned()),
        meta.rustc_version,
    );

    let mut entries = Vec::new();
    for (name, role, class) in [
        (
            "statics.tls_context_key",
            StaticRole::TlsContextKey,
            Required,
        ),
        (
            "statics.task_waker_vtable",
            StaticRole::TaskWakerVtable,
            Optional,
        ),
    ] {
        let outcome = if view.bundle().statics.entries.contains_key(&role) {
            WalkOutcome::Bound {
                spelling: 0,
                spellings: 1,
                note: None,
            }
        } else {
            WalkOutcome::Broken {
                errors: vec![format!(
                    "the bundle records no {role:?} static \
                     (was it extracted with --allow-missing-infra?)"
                )],
            }
        };
        entries.push(ContractEntry {
            name,
            class,
            outcome,
        });
    }

    for &role in WalkRole::ALL {
        let outcome = match view.bundle().walks.entries.get(&role) {
            Some(binding) => binding.outcome.clone(),
            None => WalkOutcome::Broken {
                errors: vec![
                    "the bundle records no walk binding for this role \
                     (extracted before the walk binder?)"
                        .to_owned(),
                ],
            },
        };
        entries.push(ContractEntry {
            name: role.name(),
            class: classify(role),
            outcome,
        });
    }
    ContractReport { target, entries }
}

/// The recorded outcomes of the whole table against one bundle.
#[derive(Clone, Debug)]
pub struct ContractReport {
    /// "tokio 1.50.0, rustc …" — the versions the bundle records, for
    /// diagnostics only. Nothing here branches on them; the binder's
    /// family selection already happened at extraction.
    pub target: String,
    pub entries: Vec<ContractEntry>,
}

impl ContractReport {
    pub fn is_clean(&self) -> bool {
        !self.entries.iter().any(ContractEntry::is_broken)
    }

    /// The broken entries the given policy walks past — what a caller
    /// in best-effort mode should warn about.
    pub fn degraded(&self, policy: WalkPolicy) -> Vec<String> {
        match policy {
            WalkPolicy::Strict => Vec::new(),
            WalkPolicy::BestEffort => self
                .entries
                .iter()
                .filter(|e| e.is_broken() && e.class != Class::Required)
                .map(ContractEntry::line)
                .collect(),
        }
    }

    /// Enforce the policy: an error naming every path that refuses the
    /// attach, or `Ok` — possibly with degraded paths left for
    /// [`ContractReport::degraded`] to report.
    pub fn check(&self, policy: WalkPolicy) -> Result<()> {
        let fatal: Vec<&ContractEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.is_broken() && (e.class == Class::Required || policy == WalkPolicy::Strict)
            })
            .collect();
        if fatal.is_empty() {
            return Ok(());
        }
        let lines: Vec<String> = fatal.iter().map(|e| format!("  {}", e.line())).collect();
        bail!(
            "the bundle's walk contract does not hold against this tokio ({}):\n{}",
            self.target,
            lines.join("\n")
        );
    }

    /// The entry for a path, by its report name.
    pub fn entry(&self, name: &str) -> Option<&ContractEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

impl fmt::Display for ContractReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let broken = self.entries.iter().filter(|e| e.is_broken()).count();
        let absent = self
            .entries
            .iter()
            .filter(|e| matches!(e.outcome, WalkOutcome::Absent { .. }))
            .count();
        writeln!(
            f,
            "walk contract ({}): {} entries, {} broken, {} absent",
            self.target,
            self.entries.len(),
            broken,
            absent
        )?;
        for entry in &self.entries {
            writeln!(f, "  {}", entry.line())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &'static str, class: Class, outcome: WalkOutcome) -> ContractEntry {
        ContractEntry {
            name,
            class,
            outcome,
        }
    }

    fn ok() -> WalkOutcome {
        WalkOutcome::Bound {
            spelling: 0,
            spellings: 1,
            note: None,
        }
    }

    fn broken(msg: &str) -> WalkOutcome {
        WalkOutcome::Broken {
            errors: vec![msg.to_owned()],
        }
    }

    fn report(entries: Vec<ContractEntry>) -> ContractReport {
        ContractReport {
            target: "tokio 1.50.0, rustc test".to_owned(),
            entries,
        }
    }

    /// Required breakage refuses the attach under either policy.
    #[test]
    fn test_required_breakage_always_refuses() {
        let r = report(vec![entry(
            "Header.state",
            Class::Required,
            broken("no member state"),
        )]);
        for policy in [WalkPolicy::Strict, WalkPolicy::BestEffort] {
            let err = r.check(policy).expect_err("required breakage refuses");
            let text = format!("{err:#}");
            assert!(text.contains("Header.state"), "{text}");
            assert!(text.contains("tokio 1.50.0"), "{text}");
        }
    }

    /// Optional breakage refuses under Strict and degrades under
    /// BestEffort — where it is reported, not swallowed.
    #[test]
    fn test_optional_breakage_degrades_under_best_effort() {
        let r = report(vec![
            entry("Header.state", Class::Required, ok()),
            entry("Sleep.deadline", Class::Optional, broken("no member entry")),
        ]);
        assert!(r.check(WalkPolicy::Strict).is_err());
        r.check(WalkPolicy::BestEffort)
            .expect("optional breakage degrades");
        let degraded = r.degraded(WalkPolicy::BestEffort);
        assert_eq!(degraded.len(), 1);
        assert!(degraded[0].contains("Sleep.deadline"), "{degraded:?}");
        assert!(r.degraded(WalkPolicy::Strict).is_empty());
        assert!(!r.is_clean());
    }

    /// Expected absences — an unused leaf, a plain build's missing
    /// instrumentation member — are not breakage under any policy.
    #[test]
    fn test_absence_is_not_breakage() {
        let r = report(vec![
            entry("Header.state", Class::Required, ok()),
            entry(
                "Sleep.deadline",
                Class::Optional,
                WalkOutcome::Absent {
                    reason: "no tokio::time::sleep::Sleep… type in the bundle".to_owned(),
                },
            ),
        ]);
        r.check(WalkPolicy::Strict).expect("absence is expected");
        assert!(r.is_clean());
        let shown = r.to_string();
        assert!(shown.contains("absent  Sleep.deadline"), "{shown}");
    }

    /// The report names which spelling bound (and, via the recorded
    /// note, under which family), so "1.55 silently started taking the
    /// fallback" is a reviewable diff.
    #[test]
    fn test_report_names_the_bound_spelling() {
        let r = report(vec![entry(
            "Location.file",
            Class::Required,
            WalkOutcome::Bound {
                spelling: 1,
                spellings: 2,
                note: Some("family v1_49".to_owned()),
            },
        )]);
        let shown = r.to_string();
        assert!(shown.contains("spelling 2 of 2"), "{shown}");
        assert!(shown.contains("family v1_49"), "{shown}");
    }

    /// An exact leaf key must not take lookalike siblings with it —
    /// `AcquireError` shares `Acquire`'s prefix in a real sled-agent
    /// bundle — while a `<`-terminated key spans its monomorphizations.
    #[test]
    fn test_leaf_matching_is_exact_unless_generic() {
        assert!(leaf_matches(
            ACQUIRE,
            "tokio::sync::batch_semaphore::Acquire"
        ));
        assert!(!leaf_matches(
            ACQUIRE,
            "tokio::sync::batch_semaphore::AcquireError"
        ));
        assert!(leaf_matches(SLEEP, "tokio::time::sleep::Sleep"));
        assert!(!leaf_matches(SLEEP, "tokio::time::sleep::Sleeper"));
        assert!(leaf_matches(
            JOIN_HANDLE,
            "tokio::runtime::task::join::JoinHandle<()>"
        ));
        assert!(!leaf_matches(
            JOIN_HANDLE,
            "tokio::runtime::task::join::JoinHandleFoo"
        ));
    }
}

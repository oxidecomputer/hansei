// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use crate::{
    Bundle, Error, MemberRef, Result, Selector, TypeDef, VariantDef, WalkOutcome, WalkRole,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Corrupt(format!("semantics: {message}")))
    }
}

struct Check<'a>(&'a Bundle);

impl<'a> Check<'a> {
    fn string(&self, id: StrRef) -> Result<&'a str> {
        self.0
            .strings
            .get(id)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Corrupt("semantics: invalid or empty string".into()))
    }

    fn ty(&self, id: BundleTypeId) -> Result<&'a TypeDef> {
        self.0
            .types
            .get(id)
            .ok_or_else(|| Error::Corrupt("semantics: invalid type id".into()))
    }

    fn issue(&self, issue: &SemanticIssue) -> Result<()> {
        if let Some(detail) = issue.detail {
            self.string(detail)?;
        }
        Ok(())
    }

    fn rule(&self, id: SemanticRuleId, kinds: &[SemanticRuleKind]) -> Result<&'a SemanticRule> {
        let rule = self
            .0
            .semantics
            .rules
            .get(id.0 as usize)
            .ok_or_else(|| Error::Corrupt("semantics: invalid rule id".into()))?;
        require(
            kinds.contains(&rule.kind),
            "rule has an incompatible capability",
        )?;
        Ok(rule)
    }

    fn origin(&self, origin: &SemanticOrigin) -> Result<()> {
        let version = |id| -> Result<()> {
            require(
                semver::Version::parse(self.string(id)?).is_ok(),
                "invalid library version",
            )
        };
        match origin {
            SemanticOrigin::Rustc { producer, family } => {
                // rustc's LLVM backend spells its producer
                // `clang LLVM (rustc version X (hash date))`; the bare form
                // is accepted too. Both anchored at the front.
                let producer = self.string(*producer)?;
                let token = producer
                    .strip_prefix("clang LLVM (rustc version ")
                    .or_else(|| producer.strip_prefix("rustc version "))
                    .and_then(|s| s.split_ascii_whitespace().next())
                    .map(|s| s.strip_suffix(')').unwrap_or(s));
                require(
                    token.is_some_and(|s| semver::Version::parse(s).is_ok()),
                    "invalid Rust producer",
                )?;
                self.string(*family)?;
            }
            SemanticOrigin::LibraryLayout {
                package,
                version: v,
                family,
                selection,
            } => {
                self.string(*package)?;
                self.string(*family)?;
                require(
                    v.is_none() == (*selection == LayoutSelection::VersionUnknown),
                    "layout selection disagrees with version availability",
                )?;
                if let Some(v) = v {
                    version(*v)?;
                }
            }
            SemanticOrigin::LibraryDelegation {
                package,
                version: v,
                family,
                source,
                files,
            } => {
                let package = self.string(*package)?;
                let v = self.string(*v)?;
                self.string(*family)?;
                // The recorded path is the anchored tail, so a reader
                // re-parses exactly what the producer parsed, and it has
                // to say what the origin says.
                let origin =
                    crate::origin::registry_origin(self.string(*source)?).ok_or_else(|| {
                        Error::Corrupt("semantics: delegation source is not a registry path".into())
                    })?;
                require(
                    origin.path == self.string(*source)?,
                    "delegation source is not anchored at its registry segment",
                )?;
                require(
                    origin.package == package && origin.version.to_string() == v,
                    "delegation source names another crate or version",
                )?;
                let mut names = BTreeSet::new();
                for file in files {
                    require(
                        names.insert(self.string(file.file)?),
                        "duplicate source checksum file",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn rule_origin(&self, rule: &SemanticRule) -> Result<()> {
        use SemanticRuleKind::*;
        require(rule.revision == 1, "unknown rule revision")?;
        let origin = self
            .0
            .semantics
            .origins
            .get(rule.origin.0 as usize)
            .ok_or_else(|| Error::Corrupt("semantics: invalid origin id".into()))?;
        let package = match rule.kind {
            RustcAsyncFn | RustcAsyncBlock | DynFutureAbi | StdBoxAccess | StdMutRefAccess
            | StdPinBoxAccess | StdPinMutRefAccess | StdBoxPoll | StdMutRefPoll | StdPinBoxPoll
            | StdPinMutRefPoll => {
                return require(
                    matches!(origin, SemanticOrigin::Rustc { .. }),
                    "compiler rule needs a compiler origin",
                );
            }
            TracingInstrumented
            | FuturesUtilMap
            | FuturesUtilMapErr
            | FuturesUtilIntoFuture
            | HyperUtilTokioSleep
            | TokioSelect
            | TokioCoop
            | FuturesUtilNext
            | TokioStreamWatchStream
            | TokioUtilReusableBox
            | TokioStreamStreamMap => {
                let crate_name = match rule.kind {
                    TracingInstrumented => "tracing",
                    HyperUtilTokioSleep => "hyper-util",
                    // tokio's own macro and wrapper, but read like a
                    // third-party rule: the declaration file is the
                    // evidence, and tokio's version comes off its
                    // registry path rather than the layout family.
                    TokioSelect | TokioCoop => "tokio",
                    // The map is a container, but one whose layout the
                    // walk contract binds by name alone: its origin is
                    // the type's own method declarations, read like the
                    // stream route's.
                    TokioStreamWatchStream | TokioStreamStreamMap => "tokio-stream",
                    TokioUtilReusableBox => "tokio-util",
                    _ => "futures-util",
                };
                return require(
                    matches!(origin, SemanticOrigin::LibraryDelegation { package, .. }
                    if self.0.strings.get(*package) == Some(crate_name)),
                    "third-party delegation needs source evidence",
                );
            }
            FuturesUnordered => "futures-util",
            TokioSleep
            | TokioJoinHandle
            | TokioAcquire
            | TokioJoinSet
            | TokioSleepState
            | TokioJoinHandleState
            | TokioAcquireState
            | TokioIoOperation
            | TokioIoState
            | TokioMultiThreadScheduler
            | TokioCurrentThreadScheduler
            | TokioLocalScheduler
            | TokioBlockingScheduler
            | TokioMpscRecv
            | TokioMpscRecvState
            | TokioNotified
            | TokioNotifiedState
            | TokioOneshotRecv
            | TokioOneshotRecvState => "tokio",
        };
        require(
            matches!(origin, SemanticOrigin::LibraryLayout { package: p, .. }
            if self.0.strings.get(*p) == Some(package)),
            "layout rule has an incompatible library origin",
        )?;
        if matches!(
            rule.kind,
            TokioSleepState
                | TokioJoinHandleState
                | TokioAcquireState
                | TokioIoState
                | TokioMpscRecvState
                | TokioNotifiedState
                | TokioOneshotRecvState
        ) {
            // Layout validation alone cannot authorize a state protocol:
            // revision 1 of each is the reading the runtime's assessor
            // was reviewed against, and it binds only where the origin
            // records a version inside the reviewed range — a guessed
            // family observes and never assesses.
            require(
                matches!(
                    origin,
                    SemanticOrigin::LibraryLayout {
                        selection: LayoutSelection::ReviewedRange,
                        ..
                    }
                ),
                "state rule requires a reviewed range",
            )?;
        }
        Ok(())
    }

    fn path(&self, root: BundleTypeId, path: &TypedPath) -> Result<()> {
        self.ty(root)?;
        self.ty(path.target)?;
        for step in &path.steps {
            match step {
                Step::Member(MemberRef::Named(name)) | Step::Variant(name) => {
                    self.string(*name)?;
                }
                Step::Deref => {}
                Step::Member(MemberRef::Index(_)) | Step::ActiveVariant => {
                    return require(
                        false,
                        "semantic paths require named members and explicit variants",
                    );
                }
            }
        }
        let target =
            crate::io::semantic_path_target(&self.0.types, root, &Selector(path.steps.clone()))?;
        require(
            target == path.target,
            "path endpoint type differs from recorded target",
        )
    }

    fn target(&self, root: BundleTypeId, target: &FutureTarget) -> Result<()> {
        match target {
            FutureTarget::Value(path) => {
                self.path(root, path)?;
                require(
                    !path.steps.is_empty() || path.target != root,
                    "empty self delegation",
                )
            }
            FutureTarget::Dynamic { pointer, layout } => {
                self.path(root, pointer)?;
                self.rule(layout.abi, &[SemanticRuleKind::DynFutureAbi])?;
                self.ty(layout.trait_ty)?;
                self.path(pointer.target, &layout.data)?;
                self.path(pointer.target, &layout.vtable)?;
                let field_offset = |path: &TypedPath| {
                    crate::io::selector_offset(
                        self.0,
                        pointer.target,
                        &Selector(path.steps.clone()),
                    )
                };
                require(
                    field_offset(&layout.data)
                        .zip(field_offset(&layout.vtable))
                        .is_some_and(|(data, vtable)| data.abs_diff(vtable) >= crate::POINTER_SIZE),
                    "dyn fields must be distinct inline words",
                )?;
                require(
                    self.0.types.size_of(layout.data.target) == Some(crate::POINTER_SIZE)
                        && self.0.types.size_of(layout.vtable.target) == Some(crate::POINTER_SIZE),
                    "dyn fields must be pointer sized",
                )?;
                require(
                    matches!(self.ty(layout.data.target)?, TypeDef::Pointer { target, .. } if *target == layout.trait_ty),
                    "dyn data pointer has the wrong pointee",
                )?;
                // rustc spells a trait object as an empty zero-sized
                // struct; a hand-built table may leave it opaque. Either
                // way it has no members of its own to read.
                let name = match self.ty(layout.trait_ty)? {
                    TypeDef::Opaque { name, .. } => name,
                    TypeDef::Struct {
                        name,
                        size: 0,
                        members,
                    } if members.is_empty() => name,
                    _ => return require(false, "dyn pointee is not a trait object"),
                };
                // A poll slot is a claim about where the trait puts
                // `Future::poll`, which the reviewed ABI settles only
                // for `dyn Future` itself. Another trait's object is
                // legal here — polling the adapter over it proves its
                // concrete pointee a future, and the vtable's drop glue
                // names which one — but it claims no slot.
                require(
                    layout.poll_slot.is_none()
                        || crate::names::is_future_trait_object(self.string(*name)?),
                    "a poll slot needs a Future trait object",
                )?;
                require(
                    (layout.drop_slot, layout.size_slot, layout.align_slot) == (0, 1, 2)
                        && matches!(layout.poll_slot, None | Some(3)),
                    "dyn ABI slots disagree with rule",
                )?;
                require(
                    layout.data.steps != layout.vtable.steps,
                    "dyn data and vtable alias",
                )
            }
        }
    }

    fn variants(&self, ty: BundleTypeId) -> Result<&'a [VariantDef]> {
        let TypeDef::Enum { shape, size, .. } = self.ty(ty)? else {
            return Err(Error::Corrupt("semantics: state is not an enum".into()));
        };
        require(!shape.variants.is_empty(), "state enum has no variants")?;
        if let Some(discr) = &shape.discr {
            require(
                matches!(
                    self.ty(discr.ty)?,
                    TypeDef::Base {
                        encoding: crate::Encoding::Signed | crate::Encoding::Unsigned,
                        size: 1 | 2 | 4 | 8 | 16,
                        ..
                    }
                ),
                "state discriminant is not a supported integer",
            )?;
            require(
                self.0
                    .types
                    .size_of(discr.ty)
                    .and_then(|n| discr.offset.checked_add(n))
                    .is_some_and(|end| end <= *size),
                "state discriminant is out of bounds",
            )?;
        } else {
            require(
                shape.variants.len() == 1,
                "multiple states require a discriminant",
            )?;
        }
        let mut names = BTreeSet::new();
        for variant in &shape.variants {
            require(
                names.insert(self.string(variant.name)?),
                "ambiguous variant name",
            )?;
        }
        Ok(&shape.variants)
    }

    fn roles(&self, root: BundleTypeId, roles: &[WalkRole]) -> Result<()> {
        for role in roles {
            let binding = self.0.walks.entries.get(role);
            require(
                binding.is_some_and(|b| {
                    matches!(b.outcome, WalkOutcome::Bound { .. }) && b.roots.contains(&root)
                }),
                "essential walk role is not bound for this root",
            )?;
        }
        Ok(())
    }

    fn routes(&self, routes: &[WalkRole]) -> Result<()> {
        for role in routes {
            let binding = self.0.walks.entries.get(role);
            require(
                binding.is_some_and(|b| matches!(b.outcome, WalkOutcome::Bound { .. })),
                "essential walk route is not bound",
            )?;
        }
        Ok(())
    }

    fn resource(&self, ty: BundleTypeId, binding: &ResourceBinding) -> Result<()> {
        use SemanticRuleKind::*;
        let kind = match binding.kind {
            ResourceKind::Sleep => TokioSleep,
            ResourceKind::JoinHandle => TokioJoinHandle,
            ResourceKind::SemaphoreAcquire => TokioAcquire,
            ResourceKind::IoOperation(_) => TokioIoOperation,
            ResourceKind::MpscRecv => TokioMpscRecv,
            ResourceKind::Notified => TokioNotified,
            ResourceKind::OneshotRecv => TokioOneshotRecv,
        };
        self.rule(binding.rule, &[kind])?;
        self.roles(ty, required_resource_roles(binding.kind))?;
        self.routes(required_resource_routes(binding.kind))?;
        if let Some(rule) = binding.state_rule {
            let kind = match binding.kind {
                ResourceKind::Sleep => TokioSleepState,
                ResourceKind::JoinHandle => TokioJoinHandleState,
                ResourceKind::SemaphoreAcquire => TokioAcquireState,
                ResourceKind::IoOperation(_) => TokioIoState,
                ResourceKind::MpscRecv => TokioMpscRecvState,
                ResourceKind::Notified => TokioNotifiedState,
                ResourceKind::OneshotRecv => TokioOneshotRecvState,
            };
            self.rule(rule, &[kind])?;
        }
        // Whether a pending primitive polls nothing else is a fact about
        // its reviewed implementation, and the state protocol is the
        // review: a layout binding alone carries no such guarantee.
        require(
            !binding.exclusive_pending || binding.state_rule.is_some(),
            "unreviewed exclusive-pending guarantee",
        )
    }

    /// A `select!` binding: both routes walk from the record's type
    /// through the closure's references, the mask lands on an unsigned
    /// word of a width tokio-macros emits, the tuple is an aggregate,
    /// and every branch is one of its members — no more of them than
    /// the mask has bits.
    fn select(&self, record: &TypeSemantics, binding: &SelectBinding) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::TokioSelect])?;
        self.path(record.ty, &binding.mask)?;
        require(
            matches!(binding.mask.steps.last(), Some(Step::Deref)),
            "select mask is not reached through the closure's reference",
        )?;
        let width = match self.ty(binding.mask.target)? {
            TypeDef::Base {
                encoding: crate::Encoding::Unsigned,
                size: size @ (1 | 2 | 4 | 8),
                ..
            } => *size,
            _ => return require(false, "select mask is not an unsigned word"),
        };
        self.path(record.ty, &binding.futures)?;
        require(
            matches!(binding.futures.steps.last(), Some(Step::Deref)),
            "select tuple is not reached through the closure's reference",
        )?;
        let TypeDef::Struct { members, .. } = self.ty(binding.futures.target)? else {
            return require(false, "select tuple is not an aggregate");
        };
        require(!binding.branches.is_empty(), "select has no branches")?;
        require(
            binding.branches.len() <= members.len() && binding.branches.len() as u64 <= width * 8,
            "select has more branches than tuple members or mask bits",
        )?;
        let mut seen = BTreeSet::new();
        for branch in &binding.branches {
            let [Step::Member(MemberRef::Named(name))] = branch.steps.as_slice() else {
                return require(false, "select branch is not one named tuple member");
            };
            require(seen.insert(*name), "duplicate select branch")?;
            self.path(binding.futures.target, branch)?;
        }
        Ok(())
    }

    fn coroutine(&self, record: &TypeSemantics, layout: &CoroutineLayout) -> Result<()> {
        self.rule(
            layout.rule,
            &[
                SemanticRuleKind::RustcAsyncFn,
                SemanticRuleKind::RustcAsyncBlock,
            ],
        )?;
        require(
            record.storage == StoragePolicy::CoroutineStates,
            "coroutine layout requires state storage",
        )?;
        let variants = self.variants(record.ty)?;
        let mut seen = BTreeSet::new();
        for state in &layout.states {
            require(seen.insert(state.variant), "duplicate coroutine state")?;
            let variant = variants
                .iter()
                .find(|v| v.name == state.variant)
                .ok_or_else(|| Error::Corrupt("semantics: unknown coroutine variant".into()))?;
            self.path(
                record.ty,
                &TypedPath {
                    steps: vec![Step::Variant(state.variant)],
                    target: variant.payload.ty,
                },
            )?;
            let TypeDef::Struct { members, .. } = self.ty(variant.payload.ty)? else {
                return require(false, "coroutine payload is not a struct");
            };
            let mut names = BTreeSet::new();
            for &name in state.locals.iter().chain(&state.uncertain_locals) {
                self.string(name)?;
                require(
                    names.insert(name),
                    "duplicate or overlapping coroutine locals",
                )?;
                let mut found = members.iter().filter(|m| m.name == name);
                let member = found
                    .next()
                    .ok_or_else(|| Error::Corrupt("semantics: missing coroutine local".into()))?;
                require(found.next().is_none(), "ambiguous coroutine local")?;
                self.path(
                    record.ty,
                    &TypedPath {
                        steps: vec![
                            Step::Variant(state.variant),
                            Step::Member(MemberRef::Named(name)),
                        ],
                        target: member.ty,
                    },
                )?;
            }
            if matches!(
                state.stage,
                CoroutinePhase::Returned | CoroutinePhase::Panicked
            ) {
                require(names.is_empty(), "terminal coroutine state has locals")?;
            }
            if state.stage == CoroutinePhase::Unknown {
                require(
                    state.locals.is_empty(),
                    "unknown coroutine state has initialized locals",
                )?;
            }
        }
        require(seen.len() == variants.len(), "missing coroutine states")
    }

    fn action(
        &self,
        record: &TypeSemantics,
        rule: SemanticRuleId,
        action: &PollAction,
        guard: Option<(&TypedPath, StrRef)>,
    ) -> Result<()> {
        use SemanticRuleKind::*;
        match action {
            PollAction::Delegate { target, exclusive } => {
                let binding = self.rule(
                    rule,
                    &[
                        RustcAsyncFn,
                        RustcAsyncBlock,
                        StdBoxPoll,
                        StdMutRefPoll,
                        StdPinBoxPoll,
                        StdPinMutRefPoll,
                        TracingInstrumented,
                        FuturesUtilMap,
                        FuturesUtilMapErr,
                        FuturesUtilIntoFuture,
                        HyperUtilTokioSleep,
                        TokioCoop,
                        FuturesUtilNext,
                    ],
                )?;
                self.target(record.ty, target)?;
                // The wire bit cannot promote a structurally valid path into
                // reviewed control flow: only a rule revision whose reviewed
                // implementation polls nothing but its delegate may carry
                // it. A coroutine resumes into its awaitee alone; the std
                // adapters forward one poll and nothing else, as do the
                // reviewed futures-util combinators, hyper-util's sleep
                // newtype, tokio's cooperative wrapper, whose budget
                // check polls nothing, and futures-util's `Next`, whose
                // poll is its stream's `poll_next` alone. `Instrumented`
                // enters a span around its poll, running subscriber
                // callbacks the review does not bound, so it stays false.
                let reviewed = matches!(
                    binding.kind,
                    RustcAsyncFn
                        | RustcAsyncBlock
                        | StdBoxPoll
                        | StdMutRefPoll
                        | StdPinBoxPoll
                        | StdPinMutRefPoll
                        | FuturesUtilMap
                        | FuturesUtilMapErr
                        | FuturesUtilIntoFuture
                        | HyperUtilTokioSleep
                        | TokioCoop
                        | FuturesUtilNext
                );
                require(!exclusive || reviewed, "unreviewed delegation exclusivity")?;
                let path = match target {
                    FutureTarget::Value(p) => p,
                    FutureTarget::Dynamic { pointer, .. } => pointer,
                };
                if let Some((state, variant)) = guard {
                    require(
                        path.steps.starts_with(&state.steps)
                            && path.steps.get(state.steps.len()) == Some(&Step::Variant(variant)),
                        "delegate does not carry its selected variant guard",
                    )?;
                } else {
                    require(
                        !path.steps.iter().any(|s| matches!(s, Step::Variant(_))),
                        "variant delegation requires a match guard",
                    )?;
                }
            }
            PollAction::Primitive => {
                self.rule(
                    rule,
                    &[
                        TokioSleep,
                        TokioJoinHandle,
                        TokioAcquire,
                        TokioIoOperation,
                        TokioMpscRecv,
                        TokioNotified,
                        TokioOneshotRecv,
                    ],
                )?;
                require(
                    record
                        .resource
                        .as_ref()
                        .is_some_and(|resource| resource.rule == rule),
                    "primitive has no compatible resource binding",
                )?;
            }
            // A terminal state is a state, so it needs the match that
            // selected it. Only a compiler coroutine is ever unresumed
            // or panicked; a reviewed combinator whose enum records
            // that it already produced its output is returned.
            PollAction::Unresumed | PollAction::Panicked => {
                self.rule(rule, &[RustcAsyncFn, RustcAsyncBlock])?;
                require(guard.is_some(), "a terminal state requires a variant guard")?;
            }
            PollAction::Returned => {
                self.rule(rule, &[RustcAsyncFn, RustcAsyncBlock, FuturesUtilMap])?;
                require(guard.is_some(), "a terminal state requires a variant guard")?;
            }
            PollAction::Unknown(issue) => self.issue(issue)?,
        }
        Ok(())
    }

    fn program(
        &self,
        record: &TypeSemantics,
        rule: SemanticRuleId,
        program: &PollProgram,
    ) -> Result<()> {
        use SemanticRuleKind::*;
        let binding = self.rule(
            rule,
            &[
                RustcAsyncFn,
                RustcAsyncBlock,
                StdBoxPoll,
                StdMutRefPoll,
                StdPinBoxPoll,
                StdPinMutRefPoll,
                TracingInstrumented,
                FuturesUtilMap,
                FuturesUtilMapErr,
                FuturesUtilIntoFuture,
                HyperUtilTokioSleep,
                TokioCoop,
                FuturesUtilNext,
                TokioSleep,
                TokioJoinHandle,
                TokioAcquire,
                TokioIoOperation,
                TokioMpscRecv,
                TokioNotified,
                TokioOneshotRecv,
            ],
        )?;
        require(
            !matches!(record.storage, StoragePolicy::Unavailable(_)),
            "bound program has unavailable storage",
        )?;
        if matches!(binding.kind, RustcAsyncFn | RustcAsyncBlock) {
            require(
                record.coroutine.is_some(),
                "compiler polling rule lacks a coroutine layout",
            )?;
        }
        match program {
            PollProgram::Direct(action) => {
                require(
                    record.coroutine.is_none(),
                    "coroutine requires a state match",
                )?;
                self.action(record, rule, action, None)
            }
            PollProgram::MatchVariant { state, cases } => {
                // Which rule kinds read a state is exegesis' business,
                // asserted over its real extractions: a bundle built by
                // hand to exercise the stateful executor names whatever
                // forwarding kind it has, and the structure below —
                // every variant covered, every delegate carrying its
                // own guard — is what makes such a program legible.
                self.path(record.ty, state)?;
                let variants = self.variants(state.target)?;
                let mut seen = BTreeSet::new();
                for case in cases {
                    require(seen.insert(case.variant), "duplicate poll case")?;
                    require(
                        variants.iter().any(|v| v.name == case.variant),
                        "poll case names an unknown variant",
                    )?;
                    self.action(record, rule, &case.action, Some((state, case.variant)))?;
                    if let Some(layout) = &record.coroutine {
                        require(
                            layout.rule == rule && state.steps.is_empty(),
                            "coroutine program uses a different state or rule",
                        )?;
                        let stage = layout
                            .states
                            .iter()
                            .find(|s| s.variant == case.variant)
                            .ok_or_else(|| {
                                Error::Corrupt("semantics: poll case lacks coroutine state".into())
                            })?;
                        require(
                            matches!(
                                (&stage.stage, &case.action),
                                (CoroutinePhase::Unresumed, PollAction::Unresumed)
                                    | (CoroutinePhase::Returned, PollAction::Returned)
                                    | (CoroutinePhase::Panicked, PollAction::Panicked)
                                    | (CoroutinePhase::Unknown, PollAction::Unknown(_))
                                    | (
                                        CoroutinePhase::Suspended,
                                        PollAction::Delegate { .. } | PollAction::Unknown(_)
                                    )
                            ),
                            "poll action disagrees with coroutine stage",
                        )?;
                        if let PollAction::Delegate { target, .. } = &case.action {
                            let path = match target {
                                FutureTarget::Value(path) => path,
                                FutureTarget::Dynamic { pointer, .. } => pointer,
                            };
                            require(
                                matches!(path.steps.get(1), Some(Step::Member(MemberRef::Named(name))) if stage.locals.contains(name)),
                                "coroutine delegate is not an initialized local",
                            )?;
                        }
                    }
                }
                require(seen.len() == variants.len(), "missing poll cases")
            }
        }
    }
}

/// Essential roles rooted at the resource type itself: a binding needs
/// every one of them bound at exactly that type. An I/O operation's
/// roots are the reviewed operation-over-socket monomorphizations only;
/// a contained socket is not an operation identity.
pub fn required_resource_roles(kind: ResourceKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ResourceKind::Sleep => &[SleepDeadline],
        ResourceKind::JoinHandle => &[JoinHandleRaw],
        ResourceKind::SemaphoreAcquire => &[
            AcquireSemaphore,
            AcquireNode,
            AcquireNumPermits,
            AcquireNeeded,
            AcquireQueued,
        ],
        ResourceKind::IoOperation(IoOperationKind::Read) => &[IoReadReader, IoReadBufLen],
        ResourceKind::IoOperation(IoOperationKind::WriteAll) => {
            &[IoWriteAllWriter, IoWriteAllBufLen]
        }
        ResourceKind::IoOperation(IoOperationKind::Readiness) => {
            &[ReadinessScheduledIo, ReadinessState, ReadinessWaiter]
        }
        ResourceKind::MpscRecv => &[MpscRecvRx],
        ResourceKind::Notified => &[NotifiedNotify, NotifiedState, NotifiedCalls, NotifiedWaiter],
        ResourceKind::OneshotRecv => &[OneshotInner],
    }
}

/// Essential routes chained below those roles — rooted where a role
/// landed, so at other types — that must also have bound for the
/// binding to identify its resource: the registration an operation
/// reaches through its own reader or writer, and the waker, interest
/// and ready flag inside a readiness await's node.
pub fn required_resource_routes(kind: ResourceKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ResourceKind::Sleep | ResourceKind::JoinHandle | ResourceKind::SemaphoreAcquire => &[],
        ResourceKind::IoOperation(IoOperationKind::Read) => &[IoReadShared],
        ResourceKind::IoOperation(IoOperationKind::WriteAll) => &[IoWriteAllShared],
        ResourceKind::IoOperation(IoOperationKind::Readiness) => &[
            ReadinessWaiterWaker,
            ReadinessWaiterInterest,
            ReadinessWaiterReady,
        ],
        // The channel behind the receiver's `Rx`, and every word the
        // recv protocol reads from it: the sender count, the two list
        // positions, the block chain the head names, the receiver's
        // close flag and its registered waker. The bounded semaphore's
        // permit word and bound serve one branch (a receiver closed
        // from its own side) and are enrichment, not identity.
        ResourceKind::MpscRecv => &[
            MpscRecvChan,
            ChanTxCount,
            ChanTailPosition,
            ChanRxIndex,
            ChanRxHead,
            ChanRxClosed,
            ChanRxWakerState,
            ChanRxWaker,
            BlockStartIndex,
            BlockNext,
            BlockReadySlots,
        ],
        // The `Notify` the future borrowed and its wait list, whose
        // nodes carry the waker, the successor and the notification
        // word the protocol reads on the embedded node too.
        ResourceKind::Notified => &[
            NotifyState,
            NotifyQueueHead,
            NotifyWaiterNext,
            NotifyWaiterWaker,
            NotifyWaiterNotification,
        ],
        // The shared `Inner` behind the receiver's `Arc`: the state
        // word the recv protocol reads, the value whose presence says
        // whether a completion carried one, and the receiver's own
        // waker slot.
        ResourceKind::OneshotRecv => &[OneshotState, OneshotValue, OneshotRxTask],
    }
}

/// The route that identifies a task cell's scheduler `S` as one class:
/// the data behind the flavor handle's `Arc`, the `LocalSet`'s shared
/// state, or the blocking schedule's hooks. Each roots at the exact `S`
/// type, so a binding is a layout fact about that type, not a name.
pub fn scheduler_role(class: SchedulerClass) -> WalkRole {
    match class {
        SchedulerClass::MultiThread => WalkRole::MtSchedulerHandle,
        SchedulerClass::CurrentThread => WalkRole::CtSchedulerHandle,
        SchedulerClass::LocalSet => WalkRole::LocalSchedulerShared,
        SchedulerClass::Blocking => WalkRole::BlockingScheduleHooks,
    }
}

/// The roles a container binding needs bound at the container type.
pub fn container_roles(kind: ContainerKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ContainerKind::JoinSet => &[JoinSetLength, JoinSetLists],
        ContainerKind::FuturesUnordered => &[SetHeadAll],
        ContainerKind::StreamMap => &[StreamMapEntries],
    }
}

/// The routes chained below them that the set walkers execute.
pub fn container_routes(kind: ContainerKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ContainerKind::JoinSet => &[JoinSetNotifiedHead, JoinSetIdleHead],
        ContainerKind::FuturesUnordered => &[],
        ContainerKind::StreamMap => &[StreamMapEntryStream],
    }
}

fn actions(program: &PollProgram) -> impl Iterator<Item = &PollAction> {
    let (direct, cases): (_, &[PollCase]) = match program {
        PollProgram::Direct(action) => (Some(action), &[]),
        PollProgram::MatchVariant { cases, .. } => (None, cases),
    };
    direct.into_iter().chain(cases.iter().map(|c| &c.action))
}

pub(crate) fn check_semantics(bundle: &Bundle) -> Result<()> {
    let check = Check(bundle);
    let table = &bundle.semantics;
    require(
        u32::try_from(bundle.types.types.len()).is_ok() && u32::try_from(table.types.len()).is_ok(),
        "type table exceeds semantic index capacity",
    )?;
    for (i, origin) in table.origins.iter().enumerate() {
        check.origin(origin)?;
        require(
            !table.origins[..i].contains(origin),
            "duplicate semantic origin",
        )?;
    }
    for (i, rule) in table.rules.iter().enumerate() {
        check.rule_origin(rule)?;
        require(!table.rules[..i].contains(rule), "duplicate semantic rule")?;
    }
    require(
        table.types.windows(2).all(|w| w[0].ty < w[1].ty),
        "unsorted or duplicate type semantics",
    )?;
    for record in &table.types {
        check.ty(record.ty)?;
    }
    let positions: BTreeMap<_, _> = table
        .types
        .iter()
        .enumerate()
        .map(|(i, t)| (t.ty, i))
        .collect();
    let mut seeded = vec![false; table.types.len()];
    let mut children = vec![Vec::new(); table.types.len()];
    for (i, record) in table.types.iter().enumerate() {
        check.ty(record.ty)?;
        for issue in &record.issues {
            check.issue(issue)?;
        }
        match &record.storage {
            StoragePolicy::CoroutineStates => require(
                record.coroutine.is_some(),
                "state storage lacks coroutine layout",
            )?,
            StoragePolicy::Unavailable(issue) => {
                check.issue(issue)?;
                require(
                    record.access.is_none()
                        && record.resource.is_none()
                        && record.container.is_none()
                        && record.select.is_none(),
                    "unavailable storage carries a readable capability",
                )?;
            }
            StoragePolicy::DeclaredMembers => {
                require(
                    record.coroutine.is_none(),
                    "coroutine cannot use declared-member storage",
                )?;
                if let TypeDef::Enum { name, .. }
                | TypeDef::Opaque { name, .. }
                | TypeDef::Struct { name, .. } = check.ty(record.ty)?
                {
                    require(
                        !crate::names::is_coroutine_candidate(check.string(*name)?),
                        "unsupported compiler storage cannot use declared members",
                    )?;
                }
            }
        }
        if let Some(layout) = &record.coroutine {
            check.coroutine(record, layout)?;
        }
        if let Some(access) = &record.access {
            use SemanticRuleKind::*;
            check.rule(
                access.rule,
                // The two library routes are owned: each type holds
                // the storage it polls through, and neither is a
                // future in its own right.
                match access.kind {
                    AccessKind::Owned => &[
                        StdBoxAccess,
                        StdPinBoxAccess,
                        TokioStreamWatchStream,
                        TokioUtilReusableBox,
                    ],
                    AccessKind::Borrowed => &[StdMutRefAccess, StdPinMutRefAccess],
                },
            )?;
            check.target(record.ty, &access.target)?;
        }
        if let Some(resource) = &record.resource {
            check.resource(record.ty, resource)?;
        }
        if let Some(container) = &record.container {
            let kind = match container.kind {
                ContainerKind::JoinSet => SemanticRuleKind::TokioJoinSet,
                ContainerKind::FuturesUnordered => SemanticRuleKind::FuturesUnordered,
                ContainerKind::StreamMap => SemanticRuleKind::TokioStreamStreamMap,
            };
            check.rule(container.rule, &[kind])?;
            // Whose waker the children get is the reviewed
            // implementation's, so the recorded flag must be the
            // kind's own: a set claiming forwarded wakers would have
            // the wait set list its children as the task's branches.
            require(
                container.wakers == container.kind.wakers(),
                "container wakers disagree with its kind",
            )?;
            check.roles(record.ty, container_roles(container.kind))?;
            check.routes(container_routes(container.kind))?;
        }
        if let Some(select) = &record.select {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "select binding needs declared-member storage",
            )?;
            check.select(record, select)?;
        }
        let Some(future) = &record.future else {
            continue;
        };
        require(!future.evidence.is_empty(), "empty future evidence")?;
        require(
            future.evidence.windows(2).all(|w| w[0] < w[1]),
            "unsorted or duplicate future evidence",
        )?;
        match &future.continuation {
            Continuation::Unknown(issue) => check.issue(issue)?,
            Continuation::Bound { rule, program } => check.program(record, *rule, program)?,
        }
        for evidence in &future.evidence {
            match evidence {
                FutureEvidence::TaskEntry(id) => {
                    require(
                        bundle
                            .tasks
                            .entries
                            .get(id.0 as usize)
                            .is_some_and(|entry| entry.future == record.ty),
                        "task evidence has the wrong future",
                    )?;
                    seeded[i] = true;
                }
                FutureEvidence::PollSymbol(symbol) => {
                    let symbol = check.string(*symbol)?;
                    require(
                        crate::strip_llvm_suffix(symbol) == symbol
                            && bundle
                                .dyn_futures
                                .by_symbol
                                .get(symbol)
                                .is_some_and(|ids| ids.contains(&record.ty)),
                        "poll evidence is not an exact symbol candidate",
                    )?;
                    let demangled = format!("{:#}", rustc_demangle::demangle(symbol));
                    require(
                        demangled.ends_with(" as core::future::future::Future>::poll"),
                        "poll evidence is not a Future trait implementation",
                    )?;
                    seeded[i] = true;
                }
                FutureEvidence::Coroutine(rule) => {
                    require(
                        record.coroutine.as_ref().is_some_and(|c| c.rule == *rule),
                        "coroutine evidence lacks its layout",
                    )?;
                    seeded[i] = true;
                }
                FutureEvidence::DelegatedBy { parent } => {
                    let parent = positions.get(parent).copied().ok_or_else(|| {
                        Error::Corrupt("semantics: missing delegation parent".into())
                    })?;
                    let continuation = table.types[parent].future.as_ref().map(|f| &f.continuation);
                    let Some(Continuation::Bound { program, .. }) = continuation else {
                        return require(false, "delegation parent has no bound program");
                    };
                    require(actions(program).any(|a| matches!(a, PollAction::Delegate { target: FutureTarget::Value(p), .. } if p.target == record.ty)), "parent does not delegate to this static type")?;
                    children[parent].push(i);
                }
            }
        }
    }
    let mut queue: VecDeque<_> = seeded
        .iter()
        .enumerate()
        .filter_map(|(i, &s)| s.then_some(i))
        .collect();
    while let Some(parent) = queue.pop_front() {
        for &child in &children[parent] {
            if !seeded[child] {
                seeded[child] = true;
                queue.push_back(child);
            }
        }
    }
    require(
        table
            .types
            .iter()
            .zip(seeded)
            .all(|(record, seed)| record.future.is_none() || seed),
        "future evidence cycle has no independent seed",
    )?;
    for entry in &bundle.tasks.entries {
        if let Some(binding) = &entry.scheduler_binding {
            use SemanticRuleKind::*;
            let kind = match binding.class {
                SchedulerClass::MultiThread => TokioMultiThreadScheduler,
                SchedulerClass::CurrentThread => TokioCurrentThreadScheduler,
                SchedulerClass::LocalSet => TokioLocalScheduler,
                SchedulerClass::Blocking => TokioBlockingScheduler,
            };
            check.rule(binding.rule, &[kind])?;
            require(
                bundle.types.size_of(entry.scheduler).is_some(),
                "scheduler binding has opaque storage",
            )?;
            // The class's route must have bound at this entry's own S; the
            // shared-state walks root elsewhere and prove nothing about it.
            check.roles(entry.scheduler, &[scheduler_role(binding.class)])?;
        }
    }
    Ok(())
}

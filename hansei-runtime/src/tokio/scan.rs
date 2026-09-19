// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The bounded scan of initialized storage for task references.
//!
//! Discovery needs the tasks a value refers to — the header a held
//! `JoinHandle` names, the wakers queued on a semaphore an `Acquire`
//! sits in, the wakers parked on the registration an io operation
//! reaches — without first deciding what the holder is waiting on. The
//! scan here walks a value's *initialized* storage by the bundle's
//! facts alone, dispatches every resource it meets to the raw
//! observers, and hands each reference to a sink as it is found. It
//! never diagnoses a wait, never consults a task list, and never
//! follows a pointer it has no contract for.
//!
//! At each nominal value, in order: its complete inline byte range is
//! required; a bound resource is observed and its references emitted,
//! and its interior is the observer's business, not the scan's; a
//! recognized container is walked by its own contract, each initialized
//! child a new root; a compiler coroutine is decoded through its
//! recorded layout, with only the active state's locals scanned and
//! its uncertain captures reported rather than read; storage the
//! bundle declares unreadable stops with a diagnostic; any other
//! struct descends its sized members and any other Rust enum its
//! active payload; and raw pointers, unions, scalars, opaque values
//! and arrays of aggregates stop where they are. A future the bundle
//! recognizes is an event — a new origin whose contents are scanned
//! like any other — not a stop.
//!
//! What the scan does *not* follow is as deliberate as what it does.
//! A pointer is followed only by a contract: a container's node list,
//! or the access binding of a supported adapter — a `Box<F>`, a
//! `Pin<Box<F>>`, a `&mut F`, a `Pin<Box<dyn Future>>` — whose
//! recorded route reaches the referent as its nominal type, through
//! the dyn-future join where the route is dynamic. A pointer with no
//! such binding is a stop, whatever it looks like.
//!
//! Hidden-task discovery ([`Context::discover_hidden_tasks`]) runs
//! this scan over every enumerated task's storage as its candidate
//! input, under the session's allocator evidence.

use super::TaskAddr;
use super::bundle::{ChainEnd, Context};
use super::census::{
    NodeStop, join_set_entry_task, walk_fanout_entries, walk_join_set_entries, walk_set_nodes,
};
use super::chain::NextFuture;
use super::contract::{self, Walked};
use super::observe::{
    ReadContext, ReferenceSink, ReferenceSource, ResourceObservation, ScanBudget, ScanCompletion,
    ValueKey, WalkIssue, WalkIssueKind, issue_of,
};

use anyhow::anyhow;
use foldhash::HashSet;
use hansei_bundle::{
    ContainerKind, CoroutineLayout, CoroutinePhase, FutureTarget, MemberRef, SemanticIssueKind,
    Step, StoragePolicy, TypeClass, WalkRole,
};
use proc::Target;
use reify::Value;

impl<'b, T: Target> Context<'b, T> {
    /// Scan `value`'s initialized storage for task references, as the
    /// storage of `root_task`. Every reference and every issue goes to
    /// `sink` as it arises; the returned completion says whether the
    /// scan saw everything it set out to and what it cost `budget`.
    pub fn scan_references(
        &self,
        value: Value<'b>,
        root_task: TaskAddr,
        read: &ReadContext<'_>,
        budget: &mut ScanBudget,
        sink: &mut impl ReferenceSink,
    ) -> ScanCompletion {
        let (visits, referents) = (budget.inline_visits, budget.referent_expansions);
        let mut scanner = Scanner {
            ctx: self,
            read: *read,
            budget,
            sink,
            root_task: Some(root_task),
            path: Vec::new(),
            seen: HashSet::default(),
            queues: HashSet::default(),
            complete: true,
            visits_spent: false,
        };
        scanner.root(value, Frame::default());
        ScanCompletion {
            complete: scanner.complete,
            inline_visits: budget.inline_visits - visits,
            referent_expansions: budget.referent_expansions - referents,
        }
    }
}

/// How far from the root the scan is, in the two dimensions the limits
/// bound separately: futures nested inside other futures' storage, and
/// the run of awaitees a coroutine chain descends through.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
struct Frame {
    nesting: u16,
    chain: u16,
}

impl Frame {
    /// One future further inside another's storage.
    fn nested(self) -> Frame {
        Frame {
            nesting: self.nesting + 1,
            ..self
        }
    }

    /// One awaitee further down a coroutine chain.
    fn linked(self) -> Frame {
        Frame {
            chain: self.chain + 1,
            ..self
        }
    }
}

struct Scanner<'a, 'b, T> {
    ctx: &'a Context<'b, T>,
    read: ReadContext<'a>,
    budget: &'a mut ScanBudget,
    sink: &'a mut dyn ReferenceSink,
    root_task: Option<TaskAddr>,
    /// The literal steps from the scan's root to the value in hand,
    /// kept on the stack and copied only by a sink that wants it. A
    /// container's node is one dereference in it, whatever its
    /// position in the list.
    path: Vec<Step>,
    /// Every origin started, by `(addr, type)`: an aliased or
    /// re-reached future or container is scanned once.
    seen: HashSet<ValueKey>,
    /// The semaphores whose queues this scan has already read: one
    /// observation per semaphore per scan.
    queues: HashSet<ValueKey>,
    complete: bool,
    /// Whether the spent visit budget has been reported yet.
    visits_spent: bool,
}

impl<'b, T: Target> Scanner<'_, 'b, T> {
    fn report(&mut self, issue: WalkIssue) {
        self.complete = false;
        self.sink.issue(issue);
    }

    fn reference(&mut self, target: TaskAddr, source: ReferenceSource, from: ValueKey) {
        self.sink
            .reference(target, source, Some(from), self.root_task, &self.path);
    }

    /// A new origin: the scan's root, a container's child, a future
    /// found inside another value. Scanned once per identity.
    fn root(&mut self, value: Value<'b>, frame: Frame) {
        if !self.seen.insert(ValueKey::of(value)) {
            return;
        }
        self.scan(value, 0, frame);
    }

    /// One value, `depth` aggregate levels below its origin.
    fn scan(&mut self, value: Value<'b>, depth: u16, frame: Frame) {
        let key = ValueKey::of(value);
        if !self.budget.charge_visit() {
            // Said once per scan: every value after the first refused
            // one would only repeat it.
            if !self.visits_spent {
                self.visits_spent = true;
                self.report(WalkIssue::new(
                    key,
                    WalkIssueKind::VisitLimit,
                    format!(
                        "the inline visit budget ({}) is spent",
                        self.budget.limits.max_inline_visits
                    ),
                ));
            }
            self.complete = false;
            return;
        }
        if value.bytes.len() as u64 != value.ty.size() {
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::InvalidLayout,
                format!(
                    "{} bytes in hand for the {}-byte {}",
                    value.bytes.len(),
                    value.ty.size(),
                    value.ty.name()
                ),
            ));
            return;
        }
        if depth > self.budget.limits.max_depth {
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::DepthLimit,
                format!(
                    "the scan depth limit ({}) was reached",
                    self.budget.limits.max_depth
                ),
            ));
            return;
        }
        let record = self.ctx.type_semantics(value.ty.id());

        // A resource or container met inside a value is an origin of
        // its own for identity's sake: one held by value in a frame
        // and reached again through a borrowed adapter further down
        // the chain is observed and walked once. An origin (`depth`
        // zero) was already entered by `root`.
        let once = |scanner: &mut Self| depth == 0 || scanner.seen.insert(key);

        // 1. A bound resource: observed whole, its interior the
        // observer's. The registrations and queues it names are read
        // for the tasks they hold.
        if record.is_some_and(|r| r.resource.is_some()) {
            if once(self) {
                self.resource(value, key);
            }
            return;
        }

        // 2. A recognized container: walked by its own contract.
        match self.ctx.container_kind(value.ty.id()) {
            Some(ContainerKind::FuturesUnordered) => {
                if once(self) {
                    self.set(value, key, frame);
                }
                return;
            }
            Some(ContainerKind::JoinSet) => {
                if once(self) {
                    self.join_set(value, key);
                }
                return;
            }
            Some(ContainerKind::StreamMap) => {
                if once(self) {
                    self.fanout(value, key, frame);
                }
                return;
            }
            None => {}
        }

        // 3. A supported pointer adapter: its referent by the route its
        // access binding records, one referent expansion and one link
        // further down the chain. The pointer word itself the members
        // descent below would stop at.
        if record.is_some_and(|r| r.access.is_some()) {
            self.adapter(value, key, frame);
            return;
        }

        // 4. Storage the bundle cannot vouch for stops here: a
        // coroutine no reviewed convention bound has no variant this
        // scan may believe, and the enum it is shaped as must not be
        // read as one.
        if let Some(StoragePolicy::Unavailable(issue)) = record.map(|r| &r.storage) {
            let detail = match issue.kind {
                SemanticIssueKind::PossiblyUninitialized => {
                    "storage the tokio info cannot read: which members are initialized is unknown"
                }
                SemanticIssueKind::UnsupportedOrigin => {
                    "storage laid out by a compiler no reviewed convention covers"
                }
                _ => "storage the tokio info declares unreadable",
            };
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::UnknownInitialization,
                format!("{detail} ({})", value.ty.name()),
            ));
            return;
        }

        // A future the bundle recognizes, met inside another value, is
        // a new origin — scanned once by identity, nested one deeper —
        // and a coroutine's awaitee is one more link of its chain
        // rather than a future it holds beside the chain.
        let is_future = record.is_some_and(|r| r.future.is_some());
        let (depth, frame) = if is_future && depth > 0 {
            if !self.seen.insert(key) {
                return;
            }
            let awaitee = matches!(self.path.last(), Some(Step::Member(MemberRef::Named(name)))
                if self.ctx.view.str(*name) == Some("__awaitee"));
            if awaitee {
                if frame.chain >= self.budget.limits.max_chain_depth {
                    self.report(WalkIssue::new(
                        key,
                        WalkIssueKind::DepthLimit,
                        format!(
                            "the chain depth limit ({}) was reached",
                            self.budget.limits.max_chain_depth
                        ),
                    ));
                    return;
                }
                (0, frame.linked())
            } else {
                if frame.nesting >= self.budget.limits.max_future_nesting {
                    self.report(WalkIssue::new(
                        key,
                        WalkIssueKind::HopLimit,
                        format!(
                            "the future nesting limit ({}) was reached",
                            self.budget.limits.max_future_nesting
                        ),
                    ));
                    return;
                }
                (0, frame.nested())
            }
        } else {
            (depth, frame)
        };

        // 4. A compiler coroutine: its active state's locals, by the
        // recorded layout.
        if let Some(layout) = record.and_then(|r| r.coroutine.as_ref()) {
            self.coroutine(value, key, layout, depth, frame);
            return;
        }

        // 5 and 6. Declared members; an enum's active payload; a stop
        // at everything that is not initialized aggregate storage.
        match value.ty.classify() {
            TypeClass::Struct => self.members(value, depth, frame),
            TypeClass::RustEnum => match value.active_variant_raw() {
                Ok((_, payload)) => {
                    // The variant struct is the enum's own storage, not
                    // another aggregate layer, so its members cost the
                    // level rather than the payload.
                    self.path.push(Step::ActiveVariant);
                    self.members(payload, depth, frame);
                    self.path.pop();
                }
                Err(e) => self.report(WalkIssue::new(
                    key,
                    WalkIssueKind::InvalidLayout,
                    format!("decoding the variant of {}: {e}", value.ty.name()),
                )),
            },
            // An array of aggregates could hold a future or a handle
            // per element; nothing here scans them, and saying so is
            // what keeps the completion honest. An array of scalars
            // holds neither.
            TypeClass::Array { element, .. } if holds_aggregates(element) => {
                self.report(WalkIssue::new(
                    key,
                    WalkIssueKind::UnsupportedArray,
                    format!("{} is not scanned element by element", value.ty.name()),
                ));
            }
            // A union's members are one storage read as several types,
            // at most one of them live and nothing here to say which.
            // A raw pointer's referent is nobody's without a binding.
            TypeClass::Union
            | TypeClass::Pointer { .. }
            | TypeClass::Array { .. }
            | TypeClass::Integer { .. }
            | TypeClass::Float { .. }
            | TypeClass::CEnum
            | TypeClass::Opaque => {}
        }
    }

    /// Descend `value`'s declared sized members, one level down.
    fn members(&mut self, value: Value<'b>, depth: u16, frame: Frame) {
        for member in value.ty.members() {
            if member.ty().size() == 0 {
                continue;
            }
            let step = Step::Member(MemberRef::Named(member.name_ref()));
            match contract::execute_steps(self.ctx, &self.read, value, &[step]) {
                Ok(Walked::At(child)) => {
                    self.path.push(step);
                    self.scan(child, depth + 1, frame);
                    self.path.pop();
                }
                Ok(_) => {}
                Err(e) => self.report(issue_of(ValueKey::of(value), &e)),
            }
        }
    }

    /// A coroutine's active state: its locals, each by name through
    /// the recorded layout; its uncertain captures reported, not read.
    fn coroutine(
        &mut self,
        value: Value<'b>,
        key: ValueKey,
        layout: &CoroutineLayout,
        depth: u16,
        frame: Frame,
    ) {
        let active = match value.ty.active_variant(value.bytes) {
            Some(Ok(active)) => active,
            Some(Err(e)) => {
                self.report(WalkIssue::new(
                    key,
                    WalkIssueKind::InvalidLayout,
                    format!("decoding the state of {}: {e}", value.ty.name()),
                ));
                return;
            }
            None => {
                self.report(WalkIssue::new(
                    key,
                    WalkIssueKind::InvalidLayout,
                    format!("{} has a coroutine layout but is no enum", value.ty.name()),
                ));
                return;
            }
        };
        let Some(state) = layout
            .states
            .iter()
            .find(|s| self.ctx.view.str(s.variant) == Some(active.name))
        else {
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::UnknownInitialization,
                format!(
                    "state {} of {} is not in its recorded layout",
                    active.name,
                    value.ty.name()
                ),
            ));
            return;
        };
        match state.stage {
            // Nothing of the body is live once it has finished.
            CoroutinePhase::Returned | CoroutinePhase::Panicked => return,
            CoroutinePhase::Unknown => {
                self.report(WalkIssue::new(
                    key,
                    WalkIssueKind::UnknownInitialization,
                    format!(
                        "state {} of {} exposes no locals the layout vouches for",
                        active.name,
                        value.ty.name()
                    ),
                ));
                return;
            }
            CoroutinePhase::Unresumed | CoroutinePhase::Suspended => {}
        }
        let payload = match contract::execute_steps(
            self.ctx,
            &self.read,
            value,
            &[Step::Variant(state.variant)],
        ) {
            Ok(Walked::At(payload)) => payload,
            Ok(_) => return,
            Err(e) => {
                self.report(issue_of(key, &e));
                return;
            }
        };
        self.path.push(Step::Variant(state.variant));
        for &name in &state.uncertain_locals {
            let local = self.ctx.view.str(name).unwrap_or("<bad strref>");
            self.report(WalkIssue::new(
                ValueKey::of(payload),
                WalkIssueKind::UnknownInitialization,
                format!(
                    "`{local}` may not be initialized in state {} of {}",
                    active.name,
                    value.ty.name()
                ),
            ));
        }
        for &name in &state.locals {
            let step = Step::Member(MemberRef::Named(name));
            match contract::execute_steps(self.ctx, &self.read, payload, &[step]) {
                Ok(Walked::At(local)) => {
                    self.path.push(step);
                    self.scan(local, depth + 1, frame);
                    self.path.pop();
                }
                Ok(_) => {}
                Err(e) => self.report(issue_of(ValueKey::of(payload), &e)),
            }
        }
        self.path.pop();
    }

    /// A supported pointer adapter: the referent its access binding's
    /// route reaches, scanned as a new origin. A route that lands
    /// nowhere — a trait object the join cannot resolve, a read the
    /// allocator refuses — is reported and stops.
    fn adapter(&mut self, value: Value<'b>, key: ValueKey, frame: Frame) {
        if frame.chain >= self.budget.limits.max_chain_depth {
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::DepthLimit,
                format!(
                    "the chain depth limit ({}) was reached",
                    self.budget.limits.max_chain_depth
                ),
            ));
            return;
        }
        if !self.budget.charge_referent() {
            let stop = Self::spent(self.budget);
            self.node_stop(key, stop);
            return;
        }
        let Some(next) = self.ctx.access_referent(value, &self.read) else {
            return;
        };
        match next {
            NextFuture::Next {
                future, selected, ..
            } => {
                let steps: Vec<Step> = match selected {
                    FutureTarget::Value(path) => path.steps.clone(),
                    FutureTarget::Dynamic { pointer, .. } => {
                        let mut steps = pointer.steps.clone();
                        steps.push(Step::Deref);
                        steps
                    }
                };
                let depth = self.path.len();
                self.path.extend(steps);
                self.root(future, frame.linked());
                self.path.truncate(depth);
            }
            NextFuture::End(ChainEnd::Error(e)) => self.report(issue_of(key, &e)),
            NextFuture::End(ChainEnd::UnknownDyn { pointee, .. }) => self.report(WalkIssue::new(
                key,
                WalkIssueKind::UnknownDynamicType,
                format!("the concrete type behind the {pointee} is not in the tokio info"),
            )),
            NextFuture::End(ChainEnd::AmbiguousDyn { pointee, .. }) => self.report(WalkIssue::new(
                key,
                WalkIssueKind::AmbiguousDynamicType,
                format!("the concrete type behind the {pointee} is ambiguous"),
            )),
            NextFuture::End(_) => {}
        }
    }

    /// A bound resource: observed, and the tasks its observation names
    /// — directly, or through the queue or registration it identifies
    /// — emitted as references.
    fn resource(&mut self, value: Value<'b>, key: ValueKey) {
        let observed = self.ctx.observe_resource(value, &self.read);
        for issue in observed.issues {
            self.report(issue);
        }
        match observed.value {
            Some(ResourceObservation::Join(join)) => {
                self.reference(join.header, ReferenceSource::JoinHandle, key);
            }
            Some(ResourceObservation::Acquire(acquire)) => {
                if !self.queues.insert(acquire.semaphore) {
                    return;
                }
                let queue =
                    self.ctx
                        .observe_semaphore_queue(acquire.semaphore, &self.read, self.budget);
                for issue in queue.issues {
                    self.report(issue);
                }
                for waiter in &queue.waiters {
                    if let Some(task) = waiter.waker.task() {
                        self.reference(TaskAddr(task), ReferenceSource::SemaphoreWaker, key);
                    }
                }
            }
            Some(ResourceObservation::Io(io)) => {
                if !self.queues.insert(io.scheduled_io) {
                    return;
                }
                let registration =
                    self.ctx
                        .observe_io_registration(io.scheduled_io, &self.read, self.budget);
                for issue in registration.issues {
                    self.report(issue);
                }
                if let Some(resource) = registration.value {
                    for waiter in &resource.waiters {
                        if let Some(task) = waiter.task {
                            self.reference(TaskAddr(task), ReferenceSource::IoWaker, key);
                        }
                    }
                }
            }
            Some(ResourceObservation::Recv(recv)) => {
                if !self.queues.insert(recv.chan) {
                    return;
                }
                let channel = self.ctx.observe_channel(recv.chan, &self.read, self.budget);
                for issue in channel.issues {
                    self.report(issue);
                }
                if let Some(task) = channel.waker.as_ref().and_then(|w| w.task()) {
                    self.reference(TaskAddr(task), ReferenceSource::ChannelWaker, key);
                }
            }
            Some(ResourceObservation::Notified(notified)) => {
                if !self.queues.insert(notified.notify) {
                    return;
                }
                let mut issues = Vec::new();
                let tasks = self.ctx.notify_waiter_tasks(
                    notified.notify,
                    &self.read,
                    self.budget,
                    &mut issues,
                );
                for issue in issues {
                    self.report(issue);
                }
                for task in tasks {
                    self.reference(TaskAddr(task), ReferenceSource::NotifyWaker, key);
                }
            }
            Some(ResourceObservation::Oneshot(oneshot)) => {
                if let Some(task) = oneshot.rx_waker.as_ref().and_then(|w| w.task()) {
                    self.reference(TaskAddr(task), ReferenceSource::OneshotWaker, key);
                }
            }
            // A connection's dispatch primitives: the waker parked in
            // its request channel, and the one its response callback's
            // sender cell holds — each names the connection task itself.
            Some(ResourceObservation::HttpConn(http)) => {
                let Some(client) = http.client else {
                    return;
                };
                if let Some(chan) = client.rx
                    && self.queues.insert(chan)
                {
                    let channel = self.ctx.observe_channel(chan, &self.read, self.budget);
                    for issue in channel.issues {
                        self.report(issue);
                    }
                    if let Some(task) = channel.waker.as_ref().and_then(|w| w.task()) {
                        self.reference(TaskAddr(task), ReferenceSource::ChannelWaker, key);
                    }
                }
                if let Some(task) = client
                    .callback
                    .as_ref()
                    .and_then(|callback| callback.tx_waker.as_ref())
                    .and_then(|w| w.task())
                {
                    self.reference(TaskAddr(task), ReferenceSource::OneshotWaker, key);
                }
            }
            // A timer entry's waker is the wheel's to hand over: the
            // sleep names no task itself.
            Some(ResourceObservation::Timer(_)) | None => {}
        }
    }

    /// Why a container walk stopped short, as the issue it is.
    fn node_stop(&mut self, at: ValueKey, stop: NodeStop) {
        let issue = match stop {
            NodeStop::Unmapped { addr, .. } => WalkIssue::new(
                ValueKey { addr, ..at },
                WalkIssueKind::ReadFailed,
                stop.to_string(),
            ),
            NodeStop::Refused {
                addr, ref refusal, ..
            } => WalkIssue::new(ValueKey { addr, ..at }, refusal.kind(), stop.to_string()),
            NodeStop::Cycle { addr, .. } => WalkIssue::new(
                ValueKey { addr, ..at },
                WalkIssueKind::Cycle,
                stop.to_string(),
            ),
            NodeStop::Capped { .. } => {
                WalkIssue::new(at, WalkIssueKind::VisitLimit, stop.to_string())
            }
            NodeStop::Failed(ref e) => issue_of(at, e),
        };
        self.report(issue);
    }

    /// The stop a container walk takes when the referent budget is
    /// spent before its next node.
    fn spent(budget: &ScanBudget) -> NodeStop {
        NodeStop::Capped {
            unit: "referent expansions",
            max: budget.limits.max_referent_expansions as usize,
        }
    }

    /// A `FuturesUnordered`: each node's initialized child is a new
    /// origin, one dereference and one nesting hop from here.
    fn set(&mut self, set: Value<'b>, key: ValueKey, frame: Frame) {
        let max = self.budget.limits.max_children as usize;
        let mut children: Vec<Value<'b>> = Vec::new();
        let ctx = self.ctx;
        let read = self.read;
        let budget = &mut *self.budget;
        let visit = &mut |cur: u64, node: Value<'b>| -> std::result::Result<(), NodeStop> {
            if !budget.charge_referent() {
                return Err(Self::spent(budget));
            }
            // Task.future: UnsafeCell<Option<Fut>>; `None` is a
            // completed child the set has not reaped. The child is
            // the `Some` payload's one member, entered by name.
            let slot = ctx
                .walk(WalkRole::SetNodeFuture)
                .walk_at_with(&read, node)?;
            let some = slot
                .ty
                .variant_name_ref("Some")
                .ok_or_else(|| anyhow!("the child slot at {cur:#x} is not an Option"))?;
            match contract::execute_steps(ctx, &read, slot, &[Step::Variant(some)])? {
                Walked::At(payload) => {
                    let member = payload
                        .ty
                        .members()
                        .find(|m| m.name() == "__0")
                        .ok_or_else(|| anyhow!("the child slot at {cur:#x} holds nothing"))?;
                    let step = Step::Member(MemberRef::Named(member.name_ref()));
                    if let Walked::At(child) =
                        contract::execute_steps(ctx, &read, payload, &[step])?
                    {
                        children.push(child);
                    }
                }
                Walked::Inactive(_) | Walked::Null => {}
            }
            Ok(())
        };
        let result = walk_set_nodes(ctx, &read, set, max, visit);
        if let Err(stop) = result {
            self.node_stop(key, stop);
        }
        let child_frame = frame.nested();
        if frame.nesting >= self.budget.limits.max_future_nesting && !children.is_empty() {
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::HopLimit,
                format!(
                    "the future nesting limit ({}) was reached",
                    self.budget.limits.max_future_nesting
                ),
            ));
            return;
        }
        self.path.push(Step::Deref);
        for child in children {
            self.root(child, child_frame);
        }
        self.path.pop();
    }

    /// A `StreamMap`: each entry's stream is a new origin, one
    /// dereference — the entries buffer — and one nesting hop from
    /// here, scanned as the value it is: an owned stream over a box,
    /// a future outright.
    fn fanout(&mut self, map: Value<'b>, key: ValueKey, frame: Frame) {
        let max = self.budget.limits.max_children as usize;
        let mut children: Vec<Value<'b>> = Vec::new();
        let ctx = self.ctx;
        let read = self.read;
        let budget = &mut *self.budget;
        let visit = &mut |_index: usize,
                          _entry: Value<'b>,
                          stream: Value<'b>|
         -> std::result::Result<(), NodeStop> {
            if !budget.charge_referent() {
                return Err(Self::spent(budget));
            }
            children.push(stream);
            Ok(())
        };
        if let Err(stop) = walk_fanout_entries(ctx, &read, map, max, visit) {
            self.node_stop(key, stop);
        }
        let child_frame = frame.nested();
        if frame.nesting >= self.budget.limits.max_future_nesting && !children.is_empty() {
            self.report(WalkIssue::new(
                key,
                WalkIssueKind::HopLimit,
                format!(
                    "the future nesting limit ({}) was reached",
                    self.budget.limits.max_future_nesting
                ),
            ));
            return;
        }
        self.path.push(Step::Deref);
        for child in children {
            self.root(child, child_frame);
        }
        self.path.pop();
    }

    /// A `JoinSet`: each entry's handle names a task.
    fn join_set(&mut self, set: Value<'b>, key: ValueKey) {
        let max = self.budget.limits.max_children as usize;
        let mut tasks: Vec<(u64, u64)> = Vec::new();
        let mut length = 0;
        let ctx = self.ctx;
        let read = self.read;
        let budget = &mut *self.budget;
        let visit = &mut |addr: u64, entry: Value<'b>| -> std::result::Result<(), NodeStop> {
            if !budget.charge_referent() {
                return Err(Self::spent(budget));
            }
            tasks.push((addr, join_set_entry_task(ctx, entry)?));
            Ok(())
        };
        let result = walk_join_set_entries(ctx, &read, set, max, &mut length, visit);
        let walked = tasks.len() as u64;
        match result {
            Ok(()) if walked != length => self.report(WalkIssue::new(
                key,
                WalkIssueKind::CountMismatch,
                format!("the JoinSet lists {walked} tasks against its own count of {length}"),
            )),
            Ok(()) => {}
            Err(stop) => self.node_stop(key, stop),
        }
        self.path.push(Step::Deref);
        for (entry, task) in tasks {
            let from = ValueKey {
                addr: entry,
                ty: key.ty,
            };
            self.reference(TaskAddr(task), ReferenceSource::JoinSetEntry, from);
        }
        self.path.pop();
    }
}

/// Whether an array of `element`s could hold a future or a handle:
/// an aggregate element might, a scalar cannot.
fn holds_aggregates(element: hansei_bundle::BundleType<'_>) -> bool {
    matches!(
        element.classify(),
        TypeClass::Struct | TypeClass::RustEnum | TypeClass::Union | TypeClass::Array { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testkit;
    use crate::testkit::corrupt::Corrupt;
    use crate::testkit::heap::FakeHeap;
    use crate::tokio::bundle::{FutureInfo, Task, TaskList, TaskStage, WaitKind};
    use crate::tokio::observe::{CollectedReferences, ScanLimits, TaskReference};

    use hansei_bundle::{BundleView, SemanticIssue, StoragePolicy};

    /// An address nothing in a small test program's address space
    /// reaches.
    const NOWHERE: u64 = 0xdead_beef_0000;

    /// The listed task whose future's display name contains `name`.
    fn task_named<'a>(list: &'a TaskList, name: &str) -> &'a Task {
        list.tasks
            .iter()
            .find(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
            .unwrap_or_else(|| panic!("the fixture lists a task named {name}"))
    }

    /// The resident future a task's stage holds, as its nominal root.
    fn root_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> Value<'a> {
        match ctx.task_root(task, &ReadContext::none()).unwrap() {
            TaskStage::Running(root) => root,
            other => panic!("the task's future is resident: {other:?}"),
        }
    }

    /// Scan a task's own storage under the default limits and no
    /// allocator evidence.
    fn scan_task<'a, T: Target>(
        ctx: &Context<'a, T>,
        task: &Task,
    ) -> (ScanCompletion, CollectedReferences) {
        scan_task_with(ctx, task, &ReadContext::none(), ScanLimits::default())
    }

    fn scan_task_with<'a, T: Target>(
        ctx: &Context<'a, T>,
        task: &Task,
        read: &ReadContext<'_>,
        limits: ScanLimits,
    ) -> (ScanCompletion, CollectedReferences) {
        let mut sink = CollectedReferences::default();
        let mut budget = ScanBudget::new(limits);
        let completion =
            ctx.scan_references(root_of(ctx, task), task.addr, read, &mut budget, &mut sink);
        assert_eq!(completion.inline_visits, budget.inline_visits);
        assert_eq!(completion.referent_expansions, budget.referent_expansions);
        (completion, sink)
    }

    /// A path's steps spelled with their names, for assertions.
    fn spell<T: Target>(ctx: &Context<'_, T>, path: &[Step]) -> Vec<String> {
        path.iter()
            .map(|step| match step {
                Step::Member(MemberRef::Named(name)) => {
                    format!(".{}", ctx.view.str(*name).unwrap())
                }
                Step::Member(MemberRef::Index(i)) => format!(".[{i}]"),
                Step::Variant(name) => format!("<{}>", ctx.view.str(*name).unwrap()),
                Step::ActiveVariant => "<active>".to_owned(),
                Step::Deref => "*".to_owned(),
            })
            .collect()
    }

    fn kinds(issues: &[WalkIssue]) -> Vec<WalkIssueKind> {
        issues.iter().map(|i| i.kind).collect()
    }

    /// A held `JoinHandle` is a reference to the task it names, found
    /// with no task list and no wait diagnosed: the joiner's storage
    /// yields exactly the sleeper, by the literal path through the
    /// suspended state's awaitee, and the scan is complete.
    #[test]
    fn test_a_held_join_handle_references_its_task() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let joiner = task_named(&list, "joiner");
        let sleeper = task_named(&list, "sleeper");
        let (completion, sink) = scan_task(&ctx, joiner);
        assert!(completion.complete, "{:?}", sink.issues);
        assert!(sink.issues.is_empty(), "{:?}", sink.issues);
        assert_eq!(completion.referent_expansions, 0);
        assert!(completion.inline_visits > 1);
        let [reference] = &sink.references[..] else {
            panic!("one reference: {:?}", sink.references);
        };
        assert_eq!(reference.target, sleeper.addr);
        assert_eq!(reference.source, ReferenceSource::JoinHandle);
        assert_eq!(reference.root_task, Some(joiner.addr));
        let handle = reference.source_value.expect("the handle is the source");
        assert!(
            ctx.view
                .ty(handle.ty)
                .unwrap()
                .name()
                .starts_with("tokio::runtime::task::join::JoinHandle<")
        );
        let path = spell(&ctx, &reference.path);
        assert_eq!(path.len(), 2, "{path:?}");
        assert!(path[0].starts_with('<'), "{path:?}");
        assert_eq!(path[1], ".__awaitee");
        // The handle sits at a nonzero offset inside the state: the
        // path's endpoint is the source value's own address.
        let root = root_of(&ctx, joiner);
        assert!(handle.addr > root.addr && handle.addr < root.addr + root.ty.size());
    }

    /// A resource the scan reaches only through an adapter — another
    /// task's `JoinHandle` behind a pinned box of `dyn Future`, held by
    /// a hand-written future no rule looks past — is an origin of its
    /// own, observed once: the holder references the task the handle
    /// names, and nothing else.
    #[test]
    fn test_a_resource_behind_an_adapter_is_observed_as_an_origin() {
        let (bundle, snapshot) = testkit::load_any("delegation-cases");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let handle = task_named(&list, "delegation_cases::Handle");
        let holder = task_named(&list, "delegation_cases::Holder<");
        let (completion, sink) = scan_task(&ctx, handle);
        assert!(completion.complete, "{:?}", sink.issues);
        assert!(sink.issues.is_empty(), "{:?}", sink.issues);
        let [reference] = sink.references.as_slice() else {
            panic!("one reference: {:?}", sink.references);
        };
        assert_eq!(reference.target, holder.addr);
        assert!(matches!(reference.source, ReferenceSource::JoinHandle));
        // Two expansions: the pin over the box, to the hand-written
        // future, and the pin over the boxed dyn, to the handle.
        assert_eq!(completion.referent_expansions, 2);
    }

    /// The scan is independent of the wait: the same handle references
    /// the same task after the sleeper has completed and left its list,
    /// and the reference is found whether or not anything awaits it.
    #[test]
    fn test_a_reference_survives_the_referenced_tasks_completion() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let joiner = task_named(&list, "joiner");
        let sleeper = task_named(&list, "sleeper");
        let header_ty = ctx.view.ty(bundle.infra.header).unwrap();
        let state_at = ctx
            .walk(WalkRole::HeaderState)
            .member_offset(header_ty)
            .unwrap();
        let done = Corrupt::new(&snapshot).patch(sleeper.addr.0 + state_at, (1 << 6) | 0b10);
        let ctx = Context::new(&done, BundleView::new(&bundle)).unwrap();
        let (completion, sink) = scan_task(&ctx, joiner);
        assert!(completion.complete, "{:?}", sink.issues);
        assert_eq!(sink.references.len(), 1);
        assert_eq!(sink.references[0].target, sleeper.addr);
        assert!(
            ctx.read_task_header(sleeper.addr, &ReadContext::none())
                .unwrap()
                .state
                .is_complete()
        );
    }

    /// A sleep names no task: the sleeper's storage yields no
    /// reference and nothing to report — the wheel is the registry
    /// that hands its waker over.
    #[test]
    fn test_a_sleep_references_nothing() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let sleeper = task_named(&list, "sleeper");
        let (completion, sink) = scan_task(&ctx, sleeper);
        assert!(completion.complete, "{:?}", sink.issues);
        assert!(sink.references.is_empty(), "{:?}", sink.references);
        assert_eq!(completion.referent_expansions, 0);
    }

    /// A receiver parked in `recv` and a `Notified` parked on its
    /// `Notify` each reference the task whose waker they registered —
    /// their own — through the channel's waker cell and the `Notify`'s
    /// wait list, read once per scan; the list's tasks are kept per
    /// target, so a second walk with no budget left still names them.
    #[test]
    fn test_a_receiver_and_a_notified_reference_their_registered_wakers() {
        let (bundle, snapshot) = testkit::load_any("channels");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        for (name, source) in [
            ("recv_waiter", ReferenceSource::ChannelWaker),
            ("notify_waiter", ReferenceSource::NotifyWaker),
        ] {
            let task = task_named(&list, name);
            let (completion, sink) = scan_task(&ctx, task);
            assert!(completion.complete, "{name}: {:?}", sink.issues);
            let named: Vec<_> = sink
                .references
                .iter()
                .filter(|r| r.source == source)
                .map(|r| r.target)
                .collect();
            assert_eq!(named, [task.addr], "{name}: {:?}", sink.references);
        }
        let waiter = task_named(&list, "notify_waiter");
        let read = ReadContext::none();
        let Some(ResourceObservation::Notified(notified)) = ctx
            .inspect_task(waiter, &read)
            .unwrap()
            .expect("resident")
            .primitive
            .value
        else {
            panic!("the waiter parks on a Notified");
        };
        let mut issues = Vec::new();
        let first = ctx.notify_waiter_tasks(
            notified.notify,
            &read,
            &mut ScanBudget::default(),
            &mut issues,
        );
        assert_eq!(first, [waiter.addr.0]);
        assert!(issues.is_empty(), "{issues:?}");
        let mut spent = ScanBudget::new(ScanLimits {
            max_referent_expansions: 0,
            ..ScanLimits::default()
        });
        let again = ctx.notify_waiter_tasks(notified.notify, &read, &mut spent, &mut issues);
        assert_eq!(again, first);
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// An acquire reached through an unsupported wrapper — the tokio
    /// lock's own async block, whose captured `self` reference the
    /// layout cannot vouch for — still yields the queue's task wakers,
    /// with the uncertain capture reported rather than read. The held
    /// `future1` is followed through its box by the pin's access
    /// binding, and its own lock's async block reports the same
    /// capture; the `Arc` on the way is a silent stop.
    #[test]
    fn test_an_acquire_references_the_queued_wakers() {
        let (bundle, snapshot) = testkit::load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "futurelock::main");
        let (completion, sink) = scan_task(&ctx, task);
        assert!(!completion.complete);
        assert_eq!(
            kinds(&sink.issues),
            [
                WalkIssueKind::UnknownInitialization,
                WalkIssueKind::UnknownInitialization
            ]
        );
        assert!(
            sink.issues.iter().all(|i| i
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("_ref__self"))),
            "{:?}",
            sink.issues
        );
        let [reference] = &sink.references[..] else {
            panic!("one queued waker: {:?}", sink.references);
        };
        assert_eq!(reference.source, ReferenceSource::SemaphoreWaker);
        assert_eq!(reference.target, task.addr);
        let acquire = reference.source_value.unwrap();
        assert_eq!(
            ctx.view.ty(acquire.ty).unwrap().name(),
            "tokio::sync::batch_semaphore::Acquire"
        );
        let path = spell(&ctx, &reference.path);
        assert_eq!(path.last().map(String::as_str), Some(".__awaitee"));
        assert!(
            path.iter().filter(|s| *s == ".__awaitee").count() >= 5,
            "{path:?}"
        );
        // The semaphore and its one queue node, one dereference each,
        // and `future1`'s box.
        assert_eq!(completion.referent_expansions, 3);
    }

    /// The tasks a `JoinSet` holds are references through its entries,
    /// each keyed by the entry it was found in — the same pairs the
    /// census lists as the set's members — and an entry's handle is a
    /// reference of its own when the entry is scanned as a plain
    /// value, through the cell and `ManuallyDrop` around it.
    #[test]
    fn test_a_join_set_references_its_members_through_its_entries() {
        let (bundle, snapshot) = testkit::load_any("joinset");
        let run = testkit::run(&bundle, &snapshot);
        let driver = task_named(&run.list, "driver");
        let (completion, sink) = scan_task(&run.ctx, driver);
        assert!(completion.complete, "{:?}", sink.issues);
        let mut found: Vec<(u64, u64)> = sink
            .references
            .iter()
            .map(|r| {
                assert_eq!(r.source, ReferenceSource::JoinSetEntry);
                assert_eq!(r.root_task, Some(driver.addr));
                assert_eq!(r.path.last(), Some(&Step::Deref));
                (r.source_value.unwrap().addr, r.target.0)
            })
            .collect();
        found.sort_unstable();
        let mut listed: Vec<(u64, u64)> = run
            .census
            .join_sets
            .iter()
            .flat_map(|s| s.children.iter().map(|c| (c.entry, c.task)))
            .collect();
        listed.sort_unstable();
        assert!(!listed.is_empty());
        assert_eq!(found, listed);
        // One expansion per entry, and one for the `&mut JoinSet` the
        // `join_next` frame borrows — which lands on the set the driver
        // holds by value, walked once.
        assert_eq!(completion.referent_expansions, listed.len() as u64 + 1);

        // A set whose own count disagrees with its lists says so.
        {
            let set = &run.census.join_sets[0];
            let set_ty = run.ctx.view.find_by_name(&set.ty).next().unwrap();
            let set_value = Value::read(&snapshot, set_ty, set.addr).unwrap();
            let length = run
                .ctx
                .walk(WalkRole::JoinSetLength)
                .walk_at(set_value)
                .unwrap();
            let lying = Corrupt::new(&snapshot).patch(length.addr, set.length + 1);
            let ctx = Context::new(&lying, BundleView::new(&bundle)).unwrap();
            let (completion, sink) = scan_task(&ctx, driver);
            assert!(!completion.complete);
            assert_eq!(sink.references.len(), listed.len());
            let mismatch: Vec<&WalkIssue> = sink
                .issues
                .iter()
                .filter(|i| i.kind == WalkIssueKind::CountMismatch)
                .collect();
            assert_eq!(mismatch.len(), 1, "{:?}", sink.issues);
            assert_eq!(mismatch[0].at.addr, set.addr);
            assert!(
                mismatch[0]
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.contains(&format!(
                        "{} tasks against its own count of {}",
                        set.length,
                        set.length + 1
                    ))),
                "{:?}",
                mismatch[0]
            );
        }

        // One entry as a root of its own: the handle inside it is a
        // struct member two wrappers down, found by descent.
        let (entry, task) = listed[0];
        let set = run.census.join_sets[0].addr;
        let set_ty = run
            .census
            .join_sets
            .iter()
            .find(|s| s.addr == set)
            .map(|s| s.ty.as_str())
            .unwrap();
        let set_ty = run.ctx.view.find_by_name(set_ty).next().unwrap();
        let set_value = Value::read(&snapshot, set_ty, set).unwrap();
        let lists = run
            .ctx
            .walk(WalkRole::JoinSetLists)
            .walk_at(set_value)
            .unwrap();
        let head = run
            .ctx
            .walk(WalkRole::JoinSetIdleHead)
            .walk(lists)
            .unwrap()
            .optional()
            .or_else(|| {
                run.ctx
                    .walk(WalkRole::JoinSetNotifiedHead)
                    .walk(lists)
                    .unwrap()
                    .optional()
            })
            .unwrap();
        let entry_value = Value::read(&snapshot, head.ty.pointer_target().unwrap(), entry).unwrap();
        let mut sink = CollectedReferences::default();
        let mut budget = ScanBudget::default();
        let completion = run.ctx.scan_references(
            entry_value,
            driver.addr,
            &ReadContext::none(),
            &mut budget,
            &mut sink,
        );
        assert!(completion.complete, "{:?}", sink.issues);
        assert_eq!(completion.referent_expansions, 0);
        let [reference] = &sink.references[..] else {
            panic!("the entry's handle: {:?}", sink.references);
        };
        assert_eq!(reference.source, ReferenceSource::JoinHandle);
        assert_eq!(reference.target.0, task);
        let path = spell(&run.ctx, &reference.path);
        assert!(
            path.len() >= 2 && path.iter().all(|s| s.starts_with('.')),
            "{path:?}"
        );

        // A freed entry ends the walk before it is read: the entries
        // before it are references, nothing after it is.
        let entry_ty = head.ty.pointer_target().unwrap();
        let victim = listed[listed.len() / 2].0;
        let freed = FakeHeap::new().freed(victim..victim + entry_ty.size());
        let (completion, sink) = scan_task_with(
            &run.ctx,
            driver,
            &ReadContext::with_heap(&freed),
            ScanLimits::default(),
        );
        assert!(!completion.complete);
        assert!(sink.references.len() < listed.len());
        assert!(
            sink.references
                .iter()
                .all(|r| r.source_value.unwrap().addr != victim)
        );
        assert!(
            sink.issues
                .iter()
                .any(|i| i.kind == WalkIssueKind::Freed && i.at.addr == victim),
            "{:?}",
            sink.issues
        );
        assert_eq!(freed.counts(), (0, 0, 0));
    }

    /// A `FuturesUnordered`'s children are new origins, each one
    /// dereference and one nesting hop away: the walk charges a
    /// referent per node, a freed node stops it before the node is
    /// read, a looped node is a cycle, and a spent nesting allowance
    /// keeps the children unscanned and says so.
    #[test]
    fn test_a_set_walks_its_children_as_new_origins() {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let run = testkit::run(&bundle, &snapshot);
        let driver = task_named(&run.list, "driver");
        let nodes: Vec<Vec<u64>> = run
            .census
            .sets
            .iter()
            .map(|s| s.children.iter().map(|c| c.node).collect())
            .collect();
        let total: usize = nodes.iter().map(Vec::len).sum();
        assert!(total > 2);

        let (completion, sink) = scan_task(&run.ctx, driver);
        // The children park in one `Notify`, whose wait list holds the
        // set's own waker on every node, not a task's: nothing here
        // names a task.
        assert!(sink.references.is_empty(), "{:?}", sink.references);
        assert!(completion.complete, "{:?}", sink.issues);
        // One expansion per child, plus the two adapters the driver's
        // frames hold: the `boxed` local's pin, and the `&mut
        // FuturesUnordered` the `Next` awaitee borrows — which lands on
        // the set held by value, walked once. The `Notify` the
        // children park in costs nothing here: the sweep that built
        // `run` walked its list, and the tasks it names are kept per
        // target.
        assert!(
            run.census
                .sets
                .iter()
                .flat_map(|s| s.children.iter())
                .any(|c| matches!(c.wait, Some(WaitKind::Notify { .. })))
        );
        assert_eq!(completion.referent_expansions, total as u64 + 2);
        let (expansions, visits) = (completion.referent_expansions, completion.inline_visits);

        // Every child scanned once: a second scan of the same root
        // costs the same visits.
        let (again, _) = scan_task(&run.ctx, driver);
        assert_eq!(again.inline_visits, visits);

        // The outermost set's second node freed: the first child is
        // still scanned, the rest are not.
        let outer = nodes.iter().max_by_key(|n| n.len()).unwrap();
        let victim = outer[1];
        let node_ty = {
            let set_ty = run
                .ctx
                .view
                .find_by_name(&run.census.sets[0].ty)
                .next()
                .unwrap();
            let set = Value::read(&snapshot, set_ty, run.census.sets[0].addr).unwrap();
            run.ctx
                .walk(WalkRole::SetHeadAll)
                .walk_at(set)
                .unwrap()
                .ty
                .pointer_target()
                .unwrap()
        };
        let freed = FakeHeap::new().freed(victim..victim + node_ty.size());
        let (completion, sink) = scan_task_with(
            &run.ctx,
            driver,
            &ReadContext::with_heap(&freed),
            ScanLimits::default(),
        );
        assert!(!completion.complete);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.kind == WalkIssueKind::Freed && i.at.addr == victim),
            "{:?}",
            sink.issues
        );
        assert!(completion.referent_expansions < expansions);
        assert!(completion.inline_visits < visits);

        // Looped: the first node's link back to itself.
        let first = outer[0];
        let node = Value::read(&snapshot, node_ty, first).unwrap();
        let next = run.ctx.walk(WalkRole::SetNodeNext).walk_at(node).unwrap();
        let looped = Corrupt::new(&snapshot).patch(next.addr, first);
        let ctx = Context::new(&looped, BundleView::new(&bundle)).unwrap();
        let (completion, sink) = scan_task(&ctx, driver);
        assert!(!completion.complete);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.kind == WalkIssueKind::Cycle && i.at.addr == first),
            "{:?}",
            sink.issues
        );

        // Cut: the link runs off the map.
        let cut = Corrupt::new(&snapshot).patch(next.addr, NOWHERE);
        let ctx = Context::new(&cut, BundleView::new(&bundle)).unwrap();
        let (completion, sink) = scan_task(&ctx, driver);
        assert!(!completion.complete);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.kind == WalkIssueKind::ReadFailed && i.at.addr == NOWHERE),
            "{:?}",
            sink.issues
        );

        // No nesting allowed: the sets' nodes are walked, their
        // children are not scanned, and the hop limit says so.
        let (completion, sink) = scan_task_with(
            &run.ctx,
            driver,
            &ReadContext::none(),
            ScanLimits {
                max_future_nesting: 0,
                ..ScanLimits::default()
            },
        );
        assert!(!completion.complete);
        assert!(kinds(&sink.issues).contains(&WalkIssueKind::HopLimit));
        assert!(completion.inline_visits < visits);
        // The nested set sits inside a child, so it is never walked:
        // its nodes are the expansions the unbounded scan made and
        // this one did not.
        assert!(completion.referent_expansions < total as u64 + 2);

        // One hop allowed: the children are scanned, the set nested in
        // one of them is walked, and its own children are the limit —
        // every node expanded, the `Notify` and its list read once
        // through the children that were scanned.
        let (completion, sink) = scan_task_with(
            &run.ctx,
            driver,
            &ReadContext::none(),
            ScanLimits {
                max_future_nesting: 1,
                ..ScanLimits::default()
            },
        );
        assert!(!completion.complete);
        assert!(kinds(&sink.issues).contains(&WalkIssueKind::HopLimit));
        assert_eq!(completion.referent_expansions, expansions);
        assert!(completion.inline_visits < visits);

        // A future held beside a chain is one hop of its own: the
        // `holder` the driver keeps carries a `leaf` as its argument,
        // reached by descent rather than through a set.
        let holder = run
            .census
            .held
            .iter()
            .find(|h| h.local == "nested_hold")
            .expect("the fixture holds `nested_hold`");
        let holder_ty = run.ctx.view.ty(holder.ty).unwrap();
        let holder_value = Value::read(&snapshot, holder_ty, holder.addr).unwrap();
        let scan_holder = |limit: u16| {
            let mut sink = CollectedReferences::default();
            let mut budget = ScanBudget::new(ScanLimits {
                max_future_nesting: limit,
                ..ScanLimits::default()
            });
            let completion = run.ctx.scan_references(
                holder_value,
                driver.addr,
                &ReadContext::none(),
                &mut budget,
                &mut sink,
            );
            (completion, sink)
        };
        let (completion, sink) = scan_holder(0);
        assert_eq!(kinds(&sink.issues), [WalkIssueKind::HopLimit]);
        assert!(!completion.complete);
        let (completion, sink) = scan_holder(1);
        assert!(completion.complete, "{:?}", sink.issues);

        // A child cap of one: one node is listed per set, the rest are
        // a visit limit.
        let (completion, sink) = scan_task_with(
            &run.ctx,
            driver,
            &ReadContext::none(),
            ScanLimits {
                max_children: 1,
                ..ScanLimits::default()
            },
        );
        assert!(!completion.complete);
        assert!(kinds(&sink.issues).contains(&WalkIssueKind::VisitLimit));

        // A referent budget of one: one node read, then the stop.
        let (completion, sink) = scan_task_with(
            &run.ctx,
            driver,
            &ReadContext::none(),
            ScanLimits {
                max_referent_expansions: 1,
                ..ScanLimits::default()
            },
        );
        assert_eq!(completion.referent_expansions, 1);
        assert!(kinds(&sink.issues).contains(&WalkIssueKind::VisitLimit));
    }

    /// The inline limits: a depth of zero stops at the root's own
    /// locals, and a visit budget of one stops after the root.
    #[test]
    fn test_the_inline_limits_stop_where_they_say() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let joiner = task_named(&list, "joiner");

        let (completion, sink) = scan_task_with(
            &ctx,
            joiner,
            &ReadContext::none(),
            ScanLimits {
                max_depth: 0,
                ..ScanLimits::default()
            },
        );
        assert!(!completion.complete);
        assert!(sink.references.is_empty());
        assert!(!sink.issues.is_empty());
        assert!(
            kinds(&sink.issues)
                .iter()
                .all(|k| *k == WalkIssueKind::DepthLimit)
        );

        let (completion, sink) = scan_task_with(
            &ctx,
            joiner,
            &ReadContext::none(),
            ScanLimits {
                max_inline_visits: 1,
                ..ScanLimits::default()
            },
        );
        assert!(!completion.complete);
        assert_eq!(completion.inline_visits, 1);
        assert!(sink.references.is_empty());
        assert_eq!(kinds(&sink.issues), [WalkIssueKind::VisitLimit]);
    }

    /// Storage the bundle declares unreadable is stopped at with the
    /// reason, never scanned as the enum it is shaped as: the same
    /// joiner, with its coroutine record downgraded, yields no
    /// reference at all.
    #[test]
    fn test_unavailable_storage_stops_with_a_diagnostic() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let joiner = task_named(&list, "joiner");
        let root = root_of(&ctx, joiner);
        let mut unbound = bundle.clone();
        let record = unbound
            .semantics
            .types
            .iter_mut()
            .find(|r| r.ty == root.ty.id())
            .expect("the joiner's coroutine has a record");
        record.storage = StoragePolicy::Unavailable(SemanticIssue {
            kind: SemanticIssueKind::PossiblyUninitialized,
            detail: None,
        });
        record.coroutine = None;
        let ctx = testkit::context(&unbound, &snapshot);
        let (completion, sink) = scan_task(&ctx, joiner);
        assert!(!completion.complete);
        assert!(sink.references.is_empty(), "{:?}", sink.references);
        assert_eq!(kinds(&sink.issues), [WalkIssueKind::UnknownInitialization]);
        assert_eq!(sink.issues[0].at, ValueKey::of(root));
        assert_eq!(completion.inline_visits, 1);
        let detail = sink.issues[0].detail.as_deref().unwrap_or("");
        assert!(
            detail.contains("which members are initialized is unknown"),
            "{detail}"
        );

        // The reason is spelled per issue: a compiler no convention
        // covers says so.
        let mut foreign = bundle.clone();
        let record = foreign
            .semantics
            .types
            .iter_mut()
            .find(|r| r.ty == root.ty.id())
            .unwrap();
        record.storage = StoragePolicy::Unavailable(SemanticIssue {
            kind: SemanticIssueKind::UnsupportedOrigin,
            detail: None,
        });
        record.coroutine = None;
        let ctx = testkit::context(&foreign, &snapshot);
        let (_, sink) = scan_task(&ctx, joiner);
        assert_eq!(kinds(&sink.issues), [WalkIssueKind::UnknownInitialization]);
        let detail = sink.issues[0].detail.as_deref().unwrap_or("");
        assert!(detail.contains("no reviewed convention"), "{detail}");
    }

    /// The completion reports what this call cost, not the budget's
    /// running totals: two scans against one budget report the same
    /// deltas, and the budget holds their sum.
    #[test]
    fn test_the_completion_reports_deltas_against_a_charged_budget() {
        let (bundle, snapshot) = testkit::load_any("joinset");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let driver = task_named(&list, "driver");
        let mut budget = ScanBudget::default();
        let mut sink = CollectedReferences::default();
        let first = ctx.scan_references(
            root_of(&ctx, driver),
            driver.addr,
            &ReadContext::none(),
            &mut budget,
            &mut sink,
        );
        let second = ctx.scan_references(
            root_of(&ctx, driver),
            driver.addr,
            &ReadContext::none(),
            &mut budget,
            &mut sink,
        );
        assert!(first.inline_visits > 0 && first.referent_expansions > 0);
        assert_eq!(first, second);
        assert_eq!(budget.inline_visits, 2 * first.inline_visits);
        assert_eq!(budget.referent_expansions, 2 * first.referent_expansions);
    }

    /// A coroutine chain is bounded by its own limit, not the nesting
    /// one: the futurelock's acquire sits five awaitees down, and a
    /// chain limit of two stops short of it with the reason — on the
    /// task's own chain, and again on the chain of the `future1` it
    /// holds, followed through its box.
    #[test]
    fn test_the_chain_depth_limit_bounds_a_deep_await_chain() {
        let (bundle, snapshot) = testkit::load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let task = task_named(&list, "futurelock::main");
        let (completion, sink) = scan_task_with(
            &ctx,
            task,
            &ReadContext::none(),
            ScanLimits {
                max_chain_depth: 2,
                ..ScanLimits::default()
            },
        );
        assert!(!completion.complete);
        assert!(sink.references.is_empty(), "{:?}", sink.references);
        let limits: Vec<&WalkIssue> = sink
            .issues
            .iter()
            .filter(|i| i.kind == WalkIssueKind::DepthLimit)
            .collect();
        assert_eq!(limits.len(), 2, "{:?}", sink.issues);
        assert!(
            limits.iter().all(|l| l
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("chain depth limit (2)"))),
            "{limits:?}"
        );
        // The nesting limit, at the same value, does not bind the
        // chain at all.
        let (completion, sink) = scan_task_with(
            &ctx,
            task,
            &ReadContext::none(),
            ScanLimits {
                max_future_nesting: 2,
                ..ScanLimits::default()
            },
        );
        assert_eq!(sink.references.len(), 1);
        assert!(!kinds(&sink.issues).contains(&WalkIssueKind::HopLimit));
        // The semaphore, its queue node, and `future1`'s box.
        assert_eq!(completion.referent_expansions, 3);
    }

    /// An array of aggregates is reported as unscanned rather than
    /// silently skipped, and a depth limit stops at the members before
    /// any of them is looked at: a timer wheel level, laid down as
    /// zeros, is a struct of scalars beside a 64-slot array.
    #[test]
    fn test_arrays_of_aggregates_are_reported_and_depth_stops_first() {
        let (bundle, snapshot) = testkit::load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let level = ctx
            .view
            .find_by_name("tokio::runtime::time::wheel::level::Level")
            .next()
            .expect("the wheel level type is in the bundle");
        let slots = level.member("slot").expect("Level.slot");
        let TypeClass::Array { element, .. } = slots.ty().classify() else {
            panic!("Level.slot is an array");
        };
        assert!(holds_aggregates(element));
        let byte = ctx.view.find_by_name("u8").next().unwrap();
        assert!(!holds_aggregates(byte));

        let zeros = vec![0u8; level.size() as usize];
        let value = Value::new(level, 0x1000, &zeros);
        let scan = |limits: ScanLimits| {
            let mut sink = CollectedReferences::default();
            let mut budget = ScanBudget::new(limits);
            let completion = ctx.scan_references(
                value,
                TaskAddr(0),
                &ReadContext::none(),
                &mut budget,
                &mut sink,
            );
            (completion, sink)
        };
        let (completion, sink) = scan(ScanLimits::default());
        assert!(!completion.complete);
        assert_eq!(kinds(&sink.issues), [WalkIssueKind::UnsupportedArray]);
        assert_eq!(sink.issues[0].at.addr, 0x1000 + slots.offset());
        // Every member visited: the array and the two words.
        assert_eq!(completion.inline_visits, 1 + level.members().count() as u64);

        let (completion, sink) = scan(ScanLimits {
            max_depth: 0,
            ..ScanLimits::default()
        });
        assert!(!completion.complete);
        assert!(!sink.issues.is_empty());
        assert!(
            kinds(&sink.issues)
                .iter()
                .all(|k| *k == WalkIssueKind::DepthLimit)
        );
    }

    /// The two frame counters move independently.
    #[test]
    fn test_frame_counters_move_one_at_a_time() {
        let frame = Frame::default();
        assert_eq!(
            frame.nested(),
            Frame {
                nesting: 1,
                chain: 0
            }
        );
        assert_eq!(
            frame.linked(),
            Frame {
                nesting: 0,
                chain: 1
            }
        );
        assert_eq!(
            frame.nested().nested().linked(),
            Frame {
                nesting: 2,
                chain: 1
            }
        );
    }

    /// Every io operation's task is a reference through the
    /// registration it reaches: the local set's members each name
    /// themselves through their own resource's waiters, and the
    /// gated reader, which reaches no registration, names nobody.
    #[test]
    fn test_io_operations_reference_the_parked_wakers() {
        let (bundle, snapshot) = testkit::load_any("local-set-io");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        // The registration is one dereference; a readiness await's
        // listed node is one more, while the direction slots are in
        // no list at all.
        for (name, expansions) in [
            ("local_reader", 1),
            ("local_writer", 1),
            ("local_watcher", 2),
            ("::reader", 1),
        ] {
            let task = task_named(&list, name);
            let (completion, sink) = scan_task(&ctx, task);
            assert!(completion.complete, "{name}: {:?}", sink.issues);
            let targets: Vec<TaskAddr> = sink.references.iter().map(|r| r.target).collect();
            assert_eq!(targets, [task.addr], "{name}: {:?}", sink.references);
            assert_eq!(sink.references[0].source, ReferenceSource::IoWaker);
            assert_eq!(completion.referent_expansions, expansions, "{name}");
        }
        let gated = task_named(&list, "local_gated_reader");
        let (completion, sink) = scan_task(&ctx, gated);
        assert!(completion.complete, "{:?}", sink.issues);
        assert!(sink.references.is_empty(), "{:?}", sink.references);
        assert_eq!(completion.referent_expansions, 0);
    }

    /// A `StreamMap` is walked by its own contract: each entry is an
    /// origin one dereference and one nesting hop from the map, so a
    /// scan of the mapper completes with the map's three entries
    /// visited; with no nesting allowed the map reports the hop limit
    /// and roots none of them; with no referent budget the map's walk
    /// stops on its first entry and says so.
    #[test]
    fn test_a_stream_map_roots_each_entry_under_the_limits() {
        let (bundle, snapshot) = testkit::load_any("watch-stream");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let mapper = task_named(&list, "mapper");
        let map = testkit::frame_local(&ctx, mapper, "mapper", "map");
        let map_key = ValueKey::of(map);
        let (completion, sink) = scan_task(&ctx, mapper);
        assert!(completion.complete, "{:?}", sink.issues);
        assert!(sink.issues.is_empty(), "{:?}", sink.issues);
        let visits = completion.inline_visits;
        let expansions = completion.referent_expansions;

        let (limited, sink) = scan_task_with(
            &ctx,
            mapper,
            &ReadContext::none(),
            ScanLimits {
                max_future_nesting: 0,
                ..ScanLimits::default()
            },
        );
        assert!(!limited.complete);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.kind == WalkIssueKind::HopLimit && i.at == map_key),
            "{:?}",
            sink.issues
        );
        // The entries were walked and charged, then not rooted.
        assert!(limited.inline_visits < visits, "{limited:?}");
        assert!(limited.referent_expansions < expansions, "{limited:?}");

        let (spent, sink) = scan_task_with(
            &ctx,
            mapper,
            &ReadContext::none(),
            ScanLimits {
                max_referent_expansions: 0,
                ..ScanLimits::default()
            },
        );
        assert!(!spent.complete);
        assert!(
            sink.issues
                .iter()
                .any(|i| i.kind == WalkIssueKind::VisitLimit && i.at == map_key),
            "{:?}",
            sink.issues
        );
        assert_eq!(spent.referent_expansions, 0);
    }

    /// A counting sink sees the same references as the collecting
    /// one, and copies no path.
    #[test]
    fn test_a_counting_sink_sees_every_reference() {
        struct Count(usize, usize);
        impl ReferenceSink for Count {
            fn reference(
                &mut self,
                _: TaskAddr,
                _: ReferenceSource,
                _: Option<ValueKey>,
                _: Option<TaskAddr>,
                path: &[Step],
            ) {
                assert!(!path.is_empty());
                self.0 += 1;
            }
            fn issue(&mut self, _: WalkIssue) {
                self.1 += 1;
            }
        }
        let (bundle, snapshot) = testkit::load_any("joinset");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let driver = task_named(&list, "driver");
        let (_, collected) = scan_task(&ctx, driver);
        let mut count = Count(0, 0);
        let mut budget = ScanBudget::default();
        ctx.scan_references(
            root_of(&ctx, driver),
            driver.addr,
            &ReadContext::none(),
            &mut budget,
            &mut count,
        );
        assert_eq!(count.0, collected.references.len());
        assert_eq!(count.1, collected.issues.len());
        let _: &Vec<TaskReference> = &collected.references;
    }
}

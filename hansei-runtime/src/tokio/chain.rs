// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The explicit continuation engine: a future's await chain walked by
//! the poll programs the bundle carries, and by nothing else.
//!
//! A frame's continuation is whatever its type's semantic record says
//! it is. A coroutine's program matches its own state enum and runs the
//! selected case; an adapter's runs its one recorded route; a
//! primitive's ends the chain at the resource its poll reads; a type
//! with no record, no rule, or a state its rule declined ends the chain
//! with the continuation unknown. No member is counted, no wrapper
//! peeled, no candidate preferred: a route that lands somewhere other
//! than its recorded target, an inactive guard on a selected route, or
//! a read that fails is an error, never a reason to try another child.
//!
//! Dynamic dispatch is an explicit operation over the wide pointer the
//! program names and the vtable slots its ABI rule records: the poll
//! and drop-glue symbols are joined against the bundle's dyn-future
//! table (the poll also against the task table, a spawned future's
//! identity), and a concrete type is accepted only when every slot
//! that said anything agrees on it. Disagreement is reported as
//! ambiguity, not resolved by preference.
//!
//! Lifecycle is passed beside the value, not read out of it: a task
//! mid-poll has saved discriminants that may be mid-mutation, so its
//! inspection keeps the root and stops. A held value walks under no
//! lifecycle at all, and nothing here says its holder polls it.

use super::Lifecycle;
use super::bundle::{
    AwaitChain, AwaitFrame, ChainEdge, ChainEnd, Context, FrameState, FutureInfo, MAX_AWAIT_DEPTH,
    Task, TaskStage, TypeCandidate,
};
use super::contract::{self, Walked};
use super::observe::{Observed, ReadContext, ResourceObservation, ValueKey};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use hansei_bundle::{
    BundleTypeId, Continuation, DynFutureLayout, FutureTarget, PollAction, PollProgram,
    SemanticIssueKind, Step, SymbolLookup, TypedPath, WalkRole,
};
use proc::Target;
use reify::Value;

use foldhash::HashSet;

/// Where one continuation step led.
#[derive(Debug)]
pub enum NextFuture<'b> {
    /// The program delegated: the future it polls next, read as its
    /// recorded nominal type, and the route it ran.
    Next {
        future: Value<'b>,
        /// The recorded route, borrowed from the bundle.
        selected: &'b FutureTarget,
        /// The reviewed control-flow guarantee of the hop.
        exclusive: bool,
        /// The vtable symbol that identified `future`, when the route
        /// was dynamic.
        dynamic_symbol: Option<String>,
    },
    /// The chain ends here, for the reason given.
    End(ChainEnd),
}

/// What the root of an inspection is, which decides how far it walks.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InspectionMode {
    /// A task's resident root future, under the task's lifecycle: a
    /// running task keeps its root and stops, since the saved state
    /// below it may be mid-mutation.
    Task { lifecycle: Lifecycle },
    /// A future held somewhere — a local, a container's child, an
    /// address the user named. Its saved state is interpreted like a
    /// parked task's, and nothing about the walk says its holder
    /// polls it.
    Held,
}

/// One future's chain and, when the chain ends in a primitive, the
/// raw observation read from it. Any other end observes nothing; the
/// chain's end says why.
#[derive(Debug)]
pub struct FutureInspection<'b> {
    pub chain: AwaitChain<'b>,
    pub primitive: Observed<ResourceObservation>,
}

/// The outcome of resolving one `dyn Future` wide pointer.
enum Dyn<'b> {
    Resolved {
        future: Value<'b>,
        symbol: String,
    },
    Unknown {
        poll_symbol: Option<String>,
    },
    Ambiguous {
        symbol: String,
        candidates: Vec<TypeCandidate>,
    },
}

const EMPTY: &[u8] = &[];

impl<'b, T: Target> Context<'b, T> {
    /// A task's resident root future as its recorded nominal type: the
    /// `Cell`'s stage decoded through the recorded stage route, which
    /// lands on the entry's own future type or is refused. No peeling
    /// stands between the stage and the root, so a root that is itself
    /// an adapter — a spawned `Pin<Box<dyn Future>>` — is read as that
    /// adapter, and its program takes the first step.
    ///
    /// A finished stage holds the task's output and a consumed one
    /// nothing; neither exposes resident future bytes.
    pub fn task_root(&self, task: &Task, read: &ReadContext<'_>) -> Result<TaskStage<'b>> {
        let known = match &task.future {
            FutureInfo::Known(known) => known,
            FutureInfo::Unknown { poll_symbol } => {
                let sym = poll_symbol
                    .as_ref()
                    .map(|s| format!(" (poll symbol {s})"))
                    .unwrap_or_default();
                bail!(
                    "the task's future type is not in the tokio info{sym}; nothing can be traced"
                );
            }
            FutureInfo::Ambiguous { symbol, candidates } => bail!(
                "the task's future symbol {symbol} is ambiguous: {}; nothing can be traced",
                candidates
                    .iter()
                    .map(|c| format!("{} (type {})", c.name, c.ty.0))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        let entry = self.task_entry(known.entry);
        let cell_ty = self.infra_ty(entry.cell, &format!("the Cell of {}", known.display_name))?;
        let cell = Value::read(self.proc, cell_ty, task.addr.0)
            .with_context(|| format!("failed to read the task Cell at {:?}", task.addr))?;
        let stage = self.walk(WalkRole::CellStage).walk_at_with(read, cell)?;
        let active = match stage.ty.active_variant(stage.bytes) {
            None => bail!("the Stage of {} is not an enum", known.display_name),
            Some(Err(e)) => return Err(anyhow!(e).context("failed to decode the task's Stage")),
            Some(Ok(active)) => active,
        };
        match active.name {
            contract::STAGE_RUNNING => {
                let future = self
                    .walk(WalkRole::CellStageRunning)
                    .walk_at_with(read, cell)?;
                ensure!(
                    future.ty.id() == entry.future,
                    "the stage route landed on {} rather than the entry's future {}",
                    future.ty.name(),
                    known.display_name
                );
                Ok(TaskStage::Running(future))
            }
            contract::STAGE_FINISHED => Ok(TaskStage::Finished(
                self.walk(WalkRole::CellStageFinished)
                    .walk_at_with(read, cell)?,
            )),
            contract::STAGE_CONSUMED => Ok(TaskStage::Consumed),
            other => bail!("unexpected Stage variant {other:?}"),
        }
    }

    /// The one continuation entry point: where polling `value` goes
    /// next, by its type's program. A direct program runs its action;
    /// a variant program resolves its state path, decodes the active
    /// variant once and runs exactly that case's action. Unknown
    /// recognition or continuation, a state no case names, and a case
    /// bound to no action all end the chain unknown; an invalid
    /// discriminant, a route landing off its recorded target, an
    /// inactive guard or a failed read end it with an error.
    pub fn next_future(&self, value: Value<'b>, read: &ReadContext<'_>) -> NextFuture<'b> {
        self.continuation(value, read).1
    }

    /// The referent a supported pointer adapter reaches — a `Box<F>`,
    /// a `Pin<Box<F>>`, a `&mut F`, a `Pin<Box<dyn Future>>` — by the
    /// route its access binding records, whether or not the adapter is
    /// itself a future. `None` for a value with no such binding: the
    /// pointer word is then nobody's to follow.
    pub(crate) fn access_referent(
        &self,
        value: Value<'b>,
        read: &ReadContext<'_>,
    ) -> Option<NextFuture<'b>> {
        let access = self.type_semantics(value.ty.id())?.access.as_ref()?;
        Some(self.delegate(value, &access.target, false, read))
    }

    /// [`Context::next_future`], keeping the decoded state of a
    /// variant-matched frame for the chain's display.
    fn continuation(
        &self,
        value: Value<'b>,
        read: &ReadContext<'_>,
    ) -> (Option<FrameState<'b>>, NextFuture<'b>) {
        let at = ValueKey::of(value);
        let unknown = |reason| NextFuture::End(ChainEnd::UnknownContinuation { at, reason });
        let Some(facts) = self
            .type_semantics(value.ty.id())
            .and_then(|record| record.future.as_ref())
        else {
            return (None, unknown(SemanticIssueKind::NoRule));
        };
        let program = match &facts.continuation {
            Continuation::Unknown(issue) => return (None, unknown(issue.kind)),
            Continuation::Bound { program, .. } => program,
        };
        let (state, action) = match program {
            PollProgram::Direct(action) => (None, action),
            PollProgram::MatchVariant { state, cases } => {
                let error = |e: anyhow::Error| (None, NextFuture::End(ChainEnd::Error(e)));
                let state_value = match self.route(value, &state.steps, read) {
                    Ok(state_value) => state_value,
                    Err(e) => return error(e.context("the state path")),
                };
                if state_value.ty.id() != state.target {
                    return error(anyhow!(
                        "the state path of {} landed on {} rather than its recorded state type",
                        value.ty.name(),
                        state_value.ty.name()
                    ));
                }
                let active = match state_value.ty.active_variant(state_value.bytes) {
                    None => {
                        return error(anyhow!(
                            "the state of {} is not an enum",
                            state_value.ty.name()
                        ));
                    }
                    Some(Err(e)) => {
                        return error(anyhow!(e).context(format!(
                            "failed to decode the state of {} at {:#x}",
                            state_value.ty.name(),
                            state_value.addr
                        )));
                    }
                    Some(Ok(active)) => active,
                };
                // The variant's payload, sliced without peeling: the
                // state's live locals, as the layout records them.
                let (start, size) = (active.offset, active.ty.size());
                let bytes = start
                    .checked_add(size)
                    .and_then(|end| state_value.bytes.get(start as usize..end as usize));
                let Some(bytes) = bytes else {
                    return error(anyhow!(
                        "variant payload {start}..{} does not fit {} bytes of {}",
                        start.saturating_add(size),
                        state_value.bytes.len(),
                        state_value.ty.name()
                    ));
                };
                let frame_state = FrameState {
                    name: active.state_name(),
                    await_loc: active.await_loc(),
                    payload: Value::new(active.ty, state_value.addr + start, bytes),
                };
                let Some(case) = cases
                    .iter()
                    .find(|case| self.view.str(case.variant) == Some(active.name))
                else {
                    return (
                        Some(frame_state),
                        unknown(SemanticIssueKind::UnsupportedState),
                    );
                };
                (Some(frame_state), &case.action)
            }
        };
        let next = match action {
            PollAction::Delegate { target, exclusive } => {
                self.delegate(value, target, *exclusive, read)
            }
            PollAction::Primitive => NextFuture::End(ChainEnd::Primitive),
            PollAction::Unresumed => NextFuture::End(ChainEnd::Unresumed),
            PollAction::Returned => NextFuture::End(ChainEnd::Returned),
            PollAction::Panicked => NextFuture::End(ChainEnd::Panicked),
            PollAction::Unknown(issue) => unknown(issue.kind),
        };
        (state, next)
    }

    /// Run a recorded route to its terminal. A route a program selected
    /// admits no inactive guard and no null pointer: either is an
    /// error, not a reason to look elsewhere.
    fn route(&self, from: Value<'b>, steps: &[Step], read: &ReadContext<'_>) -> Result<Value<'b>> {
        match contract::execute_steps(self, read, from, steps)? {
            Walked::At(value) => Ok(value),
            Walked::Inactive(name) => bail!(
                "variant {name} is not active on the route from {}",
                from.ty.name()
            ),
            Walked::Null => bail!("a null pointer on the route from {}", from.ty.name()),
        }
    }

    /// Run one delegation: the static route to its recorded target, or
    /// the wide pointer's dynamic join.
    fn delegate(
        &self,
        value: Value<'b>,
        target: &'b FutureTarget,
        exclusive: bool,
        read: &ReadContext<'_>,
    ) -> NextFuture<'b> {
        let landed = match target {
            FutureTarget::Value(path) => match self.route(value, &path.steps, read) {
                Ok(landed) if landed.ty.id() == path.target => Ok((landed, None)),
                Ok(landed) => Err(anyhow!(
                    "the delegation route from {} landed on {} rather than its recorded target",
                    value.ty.name(),
                    landed.ty.name()
                )),
                Err(e) => Err(e.context(format!("delegating from {}", value.ty.name()))),
            },
            FutureTarget::Dynamic { pointer, layout } => {
                let pointee = || {
                    self.view
                        .ty(layout.trait_ty)
                        .map(|ty| ty.name().to_owned())
                        .unwrap_or_default()
                };
                match self.dynamic(value, pointer, layout, read) {
                    Ok(Dyn::Resolved { future, symbol }) => Ok((future, Some(symbol))),
                    Ok(Dyn::Unknown { poll_symbol }) => {
                        return NextFuture::End(ChainEnd::UnknownDyn {
                            pointee: pointee(),
                            poll_symbol,
                        });
                    }
                    Ok(Dyn::Ambiguous { symbol, candidates }) => {
                        return NextFuture::End(ChainEnd::AmbiguousDyn {
                            pointee: pointee(),
                            symbol,
                            candidates,
                        });
                    }
                    Err(e) => Err(e.context(format!(
                        "delegating from {} through its trait object",
                        value.ty.name()
                    ))),
                }
            }
        };
        match landed {
            Ok((future, dynamic_symbol)) => NextFuture::Next {
                future,
                selected: target,
                exclusive,
                dynamic_symbol,
            },
            Err(e) => NextFuture::End(ChainEnd::Error(e)),
        }
    }

    /// The wide pointer a dynamic route names, its two words read by
    /// the recorded ABI paths, resolved to the concrete future.
    fn dynamic(
        &self,
        value: Value<'b>,
        pointer: &TypedPath,
        layout: &DynFutureLayout,
        read: &ReadContext<'_>,
    ) -> Result<Dyn<'b>> {
        let wide = self.route(value, &pointer.steps, read)?;
        ensure!(
            wide.ty.id() == pointer.target,
            "the wide-pointer route landed on {} rather than its recorded type",
            wide.ty.name()
        );
        let word = |path: &TypedPath, what: &str| -> Result<u64> {
            let field = self
                .route(wide, &path.steps, read)
                .with_context(|| format!("the {what} word"))?;
            let bytes: [u8; 8] = field
                .bytes
                .try_into()
                .map_err(|_| anyhow!("the {what} word is {} bytes, not 8", field.bytes.len()))?;
            Ok(u64::from_le_bytes(bytes))
        };
        let data = word(&layout.data, "data")?;
        let vtable = word(&layout.vtable, "vtable")?;
        self.resolve_dynamic(data, vtable, layout, read)
    }

    /// Resolve a `dyn Future` by its vtable: the identity every slot
    /// that says anything agrees on, then the size and alignment the
    /// vtable records checked against the pointer and the layout, then
    /// the referent read whole under `read`. A zero-sized future has a
    /// dangling, aligned data pointer and no bytes to read.
    fn resolve_dynamic(
        &self,
        data: u64,
        vtable: u64,
        layout: &DynFutureLayout,
        read: &ReadContext<'_>,
    ) -> Result<Dyn<'b>> {
        ensure!(
            vtable != 0 && self.mappings.contains_addr(vtable),
            "dyn future vtable pointer {vtable:#x} is unmapped"
        );
        ensure!(data != 0, "dyn future data pointer is null");
        let slot = |slot: u32| -> Result<u64> {
            let addr = vtable
                .checked_add(u64::from(slot) * 8)
                .ok_or_else(|| anyhow!("vtable slot {slot} of {vtable:#x} overflows"))?;
            self.proc.read_u64(addr).map_err(|e| {
                anyhow!(e).context(format!("failed to read slot {slot} of vtable {vtable:#x}"))
            })
        };
        let size = slot(layout.size_slot)?;
        let align = slot(layout.align_slot)?;
        ensure!(
            align != 0 && align.is_power_of_two(),
            "vtable {vtable:#x} records an alignment of {align}, not a power of two"
        );
        ensure!(
            data.is_multiple_of(align),
            "dyn future data pointer {data:#x} is not aligned to {align}"
        );

        // Identity: what each slot's symbol joins. The poll slot also
        // joins the task table, since a spawned future's identity is a
        // task entry's; the drop slot may be null by the ABI, and a
        // symbol that resolves nothing constrains nothing.
        let mut candidates: Vec<(String, SymbolLookup<BundleTypeId>)> = Vec::new();
        let mut poll_symbol = None;
        for (which, index) in [("poll", layout.poll_slot), ("drop", layout.drop_slot)] {
            let fn_addr = slot(index)?;
            if fn_addr == 0 {
                ensure!(which == "drop", "vtable {vtable:#x} has a null poll slot");
                continue;
            }
            let Some(symbol) = self.symbol_at(fn_addr) else {
                continue;
            };
            let mut lookup = self.dyn_future_ids_memoized(&symbol);
            if which == "poll" {
                poll_symbol = Some(symbol.clone());
                if matches!(lookup, SymbolLookup::Missing) {
                    lookup = match self.task_ids_memoized(&symbol) {
                        SymbolLookup::Unique(id) => {
                            SymbolLookup::Unique(self.task_entry(id).future)
                        }
                        SymbolLookup::Ambiguous(ids) => {
                            let mut futures: Vec<BundleTypeId> =
                                ids.iter().map(|id| self.task_entry(*id).future).collect();
                            futures.sort();
                            futures.dedup();
                            match futures.as_slice() {
                                [one] => SymbolLookup::Unique(*one),
                                _ => SymbolLookup::Ambiguous(futures),
                            }
                        }
                        SymbolLookup::Missing => SymbolLookup::Missing,
                    };
                }
            }
            if !matches!(lookup, SymbolLookup::Missing) {
                candidates.push((symbol, lookup));
            }
        }
        // One conflict policy: a unique identity is accepted only if
        // every other set that said anything contains it and no other
        // unique result disagrees; anything else is reported whole.
        let unique = candidates.iter().find_map(|(_, lookup)| match lookup {
            SymbolLookup::Unique(id) => Some(*id),
            _ => None,
        });
        let agreed = |id: BundleTypeId| {
            candidates.iter().all(|(_, lookup)| match lookup {
                SymbolLookup::Unique(other) => *other == id,
                SymbolLookup::Ambiguous(ids) => ids.contains(&id),
                SymbolLookup::Missing => true,
            })
        };
        let id = match unique {
            Some(id) if agreed(id) => id,
            _ if candidates.is_empty() => return Ok(Dyn::Unknown { poll_symbol }),
            _ => {
                let mut ids: Vec<BundleTypeId> = candidates
                    .iter()
                    .flat_map(|(_, lookup)| match lookup {
                        SymbolLookup::Unique(id) => vec![*id],
                        SymbolLookup::Ambiguous(ids) => ids.clone(),
                        SymbolLookup::Missing => Vec::new(),
                    })
                    .collect();
                ids.sort();
                ids.dedup();
                return Ok(Dyn::Ambiguous {
                    symbol: poll_symbol.unwrap_or_else(|| candidates[0].0.clone()),
                    candidates: ids
                        .into_iter()
                        .filter_map(|id| self.view.ty(id))
                        .map(|ty| TypeCandidate {
                            name: ty.name().to_owned(),
                            ty: ty.id(),
                        })
                        .collect(),
                });
            }
        };
        let symbol = candidates
            .iter()
            .find(|(_, lookup)| matches!(lookup, SymbolLookup::Unique(other) if *other == id))
            .map(|(symbol, _)| symbol.clone())
            .expect("a unique candidate named the identity");
        let ty = self
            .view
            .ty(id)
            .ok_or_else(|| anyhow!("dyn future type {} is not in the tokio info", id.0))?;
        ensure!(
            ty.size() == size,
            "vtable {vtable:#x} records a size of {size} for {}, whose layout is {} bytes",
            ty.name(),
            ty.size()
        );
        if size == 0 {
            return Ok(Dyn::Resolved {
                future: Value::new(ty, data, EMPTY),
                symbol,
            });
        }
        let end = data
            .checked_add(size)
            .ok_or_else(|| anyhow!("dyn future data {data:#x} + {size} overflows"))?;
        ensure!(
            self.mappings.contains_addr(data) && self.mappings.contains_addr(end - 1),
            "dyn future data {data:#x}..{end:#x} is unmapped"
        );
        if let Some(refusal) = read.refusal(data, size) {
            return Err(anyhow::Error::new(refusal).context(format!("reading {}", ty.name())));
        }
        let future = Value::read(self.proc, ty, data)
            .with_context(|| format!("failed to read {} at {data:#x}", ty.name()))?;
        Ok(Dyn::Resolved { future, symbol })
    }

    /// Walk `root`'s chain by its programs, outermost future first,
    /// and observe the primitive it ends in, if it ends in one.
    ///
    /// The walk never fails outright: every frame that decoded is in
    /// the chain, every hop followed is an edge, and the end says why
    /// it stopped. Depth is bounded, every hop — an adapter's included
    /// — costs one frame of it, and an `(address, nominal type)` pair
    /// seen twice is a cycle. A hop whose target the bound or the
    /// cycle guard refuses records no edge.
    pub fn inspect_future(
        &self,
        root: Value<'b>,
        mode: InspectionMode,
        read: &ReadContext<'_>,
    ) -> FutureInspection<'b> {
        let mut frames: Vec<AwaitFrame<'b>> = Vec::new();
        let mut edges: Vec<ChainEdge<'b>> = Vec::new();
        let mut visited: HashSet<(u64, BundleTypeId)> = HashSet::default();
        let mut cur = root;
        let mut dyn_symbol: Option<String> = None;
        let mut pending: Option<ChainEdge<'b>> = None;
        let end = loop {
            if frames.len() >= MAX_AWAIT_DEPTH {
                break ChainEnd::DepthLimit;
            }
            if !visited.insert((cur.addr, cur.ty.id())) {
                break ChainEnd::Cycle { addr: cur.addr };
            }
            edges.extend(pending.take());
            let index = frames.len() as u32;
            if matches!(
                mode,
                InspectionMode::Task {
                    lifecycle: Lifecycle::Running
                }
            ) {
                frames.push(AwaitFrame {
                    future: cur,
                    state: None,
                    dyn_symbol: dyn_symbol.take(),
                });
                break ChainEnd::ActivePoll;
            }
            let (state, next) = self.continuation(cur, read);
            frames.push(AwaitFrame {
                future: cur,
                state,
                dyn_symbol: dyn_symbol.take(),
            });
            match next {
                NextFuture::Next {
                    future,
                    selected,
                    exclusive,
                    dynamic_symbol,
                } => {
                    pending = Some(ChainEdge {
                        from: index,
                        to: index + 1,
                        selected,
                        exclusive,
                        source: ValueKey::of(cur),
                        target: ValueKey::of(future),
                    });
                    dyn_symbol = dynamic_symbol;
                    cur = future;
                }
                NextFuture::End(end) => break end,
            }
        };
        let chain = AwaitChain { frames, edges, end };
        let primitive = match chain.primitive_leaf() {
            Some(leaf) => self.observe_resource(leaf, read),
            None => Observed::none(),
        };
        FutureInspection { chain, primitive }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, FIXTURE_SETS, load, load_any};
    use crate::tokio::bundle::TaskList;
    use crate::tokio::observe::ResourceObservation;

    use hansei_bundle::{Bundle, BundleView};
    use proc::snapshot::Snapshot;

    const NOWHERE: u64 = 0xdead_beef_0000;

    fn task_named<'a>(list: &'a TaskList, name: &str) -> &'a Task {
        let hits: Vec<&Task> = list
            .tasks
            .iter()
            .filter(|t| matches!(&t.future, FutureInfo::Known(k) if k.display_name.contains(name)))
            .collect();
        assert_eq!(hits.len(), 1, "one task named {name}: {hits:?}");
        hits[0]
    }

    fn root_of<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> Value<'a> {
        match ctx.task_root(task, &ReadContext::none()).unwrap() {
            TaskStage::Running(root) => root,
            other => panic!("the task's future is resident: {other:?}"),
        }
    }

    fn inspect<'a, T: Target>(ctx: &Context<'a, T>, task: &Task) -> FutureInspection<'a> {
        let root = root_of(ctx, task);
        ctx.inspect_future(
            root,
            InspectionMode::Task {
                lifecycle: task.state.lifecycle(),
            },
            &ReadContext::none(),
        )
    }

    fn names(chain: &AwaitChain<'_>) -> Vec<String> {
        chain
            .frames
            .iter()
            .map(|f| f.future.ty.name().to_owned())
            .collect()
    }

    /// The root is the entry's own type at the stage's address, and
    /// the route is held to that endpoint. A plain spawn stores its
    /// coroutine inline and the legacy decode lands on the same type;
    /// a spawn of a `Pin<Box<F>>` is read as that pin, which the legacy
    /// decode peels away to `F`.
    #[test]
    fn test_task_roots_are_the_entrys_nominal_type() {
        for (program, boxed) in [("sleep-join", false), ("delegation-cases", true)] {
            let (bundle, snapshot) = load_any(program);
            let ctx = testkit::context(&bundle, &snapshot);
            let list = testkit::tasks(&ctx, &snapshot);
            for task in &list.tasks {
                let FutureInfo::Known(known) = &task.future else {
                    panic!("every fixture task's future is known");
                };
                let entry = &bundle.tasks.entries[known.entry.0 as usize];
                let root = root_of(&ctx, task);
                assert_eq!(root.ty.id(), entry.future, "{}", known.display_name);
                assert_eq!(
                    root.ty
                        .name()
                        .starts_with("core::pin::Pin<alloc::boxed::Box<"),
                    boxed,
                    "{}",
                    root.ty.name()
                );
                let TaskStage::Running(again) = ctx.task_root(task, &ReadContext::none()).unwrap()
                else {
                    unreachable!()
                };
                assert_eq!(again.addr, root.addr);
            }
        }
    }

    /// Every delegation case, walked by its emitted programs from the
    /// nominal root: the pin over the box forwards exclusively to the
    /// registered root, and the case's own rule — or none — decides
    /// whether the registered child is the next frame. The registry
    /// the fixture wrote is the oracle for every address.
    #[test]
    fn test_the_engine_walks_the_delegation_cases_by_their_programs() {
        use crate::testkit::delegation::read_from;
        for set in FIXTURE_SETS {
            let (bundle, snapshot) = load(set, "delegation-cases");
            let ctx = testkit::context(&bundle, &snapshot);
            let list = testkit::tasks(&ctx, &snapshot);
            let cases = read_from(&snapshot).unwrap().unwrap();
            let mut reached = std::collections::BTreeSet::new();
            for task in &list.tasks {
                let inspection = inspect(&ctx, task);
                let chain = &inspection.chain;
                assert!(chain.frames.len() >= 2, "{set}: {:?}", names(chain));
                assert!(chain.edges[0].exclusive, "{set}: the pin over the box");
                assert_eq!((chain.edges[0].from, chain.edges[0].to), (0, 1));
                assert_eq!(chain.edges[0].source, ValueKey::of(chain.frames[0].future));
                assert_eq!(chain.edges[0].target, ValueKey::of(chain.frames[1].future));
                let inner = chain.frames[1].future;
                let case = cases
                    .iter()
                    .find(|c| c.root == inner.addr)
                    .unwrap_or_else(|| panic!("{set}: no case at {:#x}", inner.addr));
                assert_eq!(inner.ty.size(), case.root_size, "{set}: {}", case.name);
                assert_eq!(chain.edges.len(), chain.frames.len() - 1);
                match case.name {
                    "gated" | "previously-polled" | "enum-retained" | "raw-pointer" => {
                        assert_eq!(chain.frames.len(), 2, "{set}: {:?}", names(chain));
                        let ChainEnd::UnknownContinuation { at, reason } = &chain.end else {
                            panic!("{set}: {} ends unknown: {:?}", case.name, chain.end);
                        };
                        assert_eq!(*at, ValueKey::of(inner));
                        assert_eq!(*reason, SemanticIssueKind::NoRule);
                    }
                    "reference" | "boxed" | "instrumented" => {
                        assert_eq!(chain.frames.len(), 3, "{set}: {:?}", names(chain));
                        let child = chain.frames[2].future;
                        assert_eq!((child.addr, child.ty.size()), (case.child, case.child_size));
                        assert_eq!(chain.edges[1].exclusive, case.name != "instrumented");
                        assert_eq!(chain.all_exclusive(), case.name != "instrumented");
                        assert!(chain.frames[2].dyn_symbol.is_none());
                        assert!(matches!(
                            chain.end,
                            ChainEnd::UnknownContinuation {
                                reason: SemanticIssueKind::NoRule,
                                ..
                            }
                        ));
                    }
                    "dynamic" => {
                        assert_eq!(chain.frames.len(), 3, "{set}: {:?}", names(chain));
                        let child = chain.frames[2].future;
                        assert_eq!((child.addr, child.ty.size()), (case.child, case.child_size));
                        assert!(chain.edges[1].exclusive);
                        assert!(
                            chain.frames[2].dyn_symbol.is_some(),
                            "{set}: the vtable named the child"
                        );
                        assert!(matches!(
                            chain.frames[1].future.ty.debug_format(),
                            Some(_) | None
                        ));
                    }
                    other => panic!("{set}: unexpected case {other}"),
                }
                assert!(inspection.primitive.value.is_none());
                reached.insert(case.name);
            }
            assert_eq!(reached.len(), 8, "{set}");
        }
    }

    /// A chain ends where the programs say: at the primitive whose
    /// poll reads a resource — observed on the spot — with every hop a
    /// coroutine's exclusive resumption; at a `select!`'s `PollFn`,
    /// which no rule covers; at the fixture's own reader over a socket,
    /// however much of a socket it holds.
    #[test]
    fn test_chains_end_at_primitives_and_at_the_first_unknown_rule() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let sleeper = inspect(&ctx, task_named(&list, "sleeper"));
        assert!(
            matches!(sleeper.chain.end, ChainEnd::Primitive),
            "{:?}",
            sleeper.chain.end
        );
        assert!(sleeper.chain.all_exclusive());
        assert_eq!(
            sleeper.chain.primitive_leaf().map(|v| v.ty.name()),
            Some("tokio::time::sleep::Sleep")
        );
        assert!(matches!(
            sleeper.primitive.value,
            Some(ResourceObservation::Timer(_))
        ));
        let joiner = inspect(&ctx, task_named(&list, "joiner"));
        assert!(matches!(joiner.chain.end, ChainEnd::Primitive));
        assert!(matches!(
            joiner.primitive.value,
            Some(ResourceObservation::Join(_))
        ));
        // The coroutine and the primitive: two frames, one exclusive
        // edge, and the state decoded on the frame that is a coroutine.
        assert_eq!(joiner.chain.frames.len(), 2, "{:?}", names(&joiner.chain));
        assert_eq!(joiner.chain.edges.len(), 1);
        let state = joiner.chain.frames[0]
            .state
            .as_ref()
            .expect("a coroutine's state");
        assert!(joiner.chain.frames[1].state.is_none());
        // rustc lays a coroutine's variant payload at the enum's own
        // address; the payload is sliced there, without peeling.
        assert_eq!(state.payload.addr, joiner.chain.frames[0].future.addr);
        assert!(state.name.starts_with("Suspend"), "{}", state.name);
        assert!(state.await_loc.is_some());

        let (bundle, snapshot) = load_any("futurelock");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let parked = list
            .tasks
            .iter()
            .map(|task| inspect(&ctx, task))
            .find(|i| matches!(i.primitive.value, Some(ResourceObservation::Acquire(_))))
            .expect("a task parked on an acquire");
        assert!(parked.chain.all_exclusive());
        assert!(
            names(&parked.chain)
                .iter()
                .any(|n| n.contains("do_async_thing"))
        );
        assert!(names(&parked.chain).iter().any(|n| n.contains("mutex")));

        let (bundle, snapshot) = load_any("local-set-io");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let gated = inspect(&ctx, task_named(&list, "local_gated_reader"));
        let ChainEnd::UnknownContinuation { at, reason } = &gated.chain.end else {
            panic!("the gated reader ends unknown: {:?}", gated.chain.end);
        };
        assert_eq!(*reason, SemanticIssueKind::NoRule);
        assert_eq!(*at, ValueKey::of(gated.chain.frames.last().unwrap().future));
        assert!(gated.primitive.value.is_none());
        assert!(
            gated
                .chain
                .frames
                .last()
                .unwrap()
                .future
                .ty
                .name()
                .starts_with("tokio::io::util::read::Read<local_set_io::Gated>")
        );
        let reader = inspect(&ctx, task_named(&list, "local_reader"));
        assert!(matches!(reader.chain.end, ChainEnd::Primitive));
        assert!(matches!(
            reader.primitive.value,
            Some(ResourceObservation::Io(_))
        ));
    }

    /// A running task keeps its root and stops: nothing below a
    /// mid-poll root is read as a chain, whatever the saved
    /// discriminants say. A held value walks the same storage whole.
    #[test]
    fn test_a_running_root_stops_at_itself() {
        let (bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let root = root_of(&ctx, task_named(&list, "sleeper"));
        let running = ctx.inspect_future(
            root,
            InspectionMode::Task {
                lifecycle: Lifecycle::Running,
            },
            &ReadContext::none(),
        );
        assert_eq!(running.chain.frames.len(), 1);
        assert!(running.chain.edges.is_empty());
        assert!(matches!(running.chain.end, ChainEnd::ActivePoll));
        assert!(running.primitive.value.is_none());
        let held = ctx.inspect_future(root, InspectionMode::Held, &ReadContext::none());
        assert!(matches!(held.chain.end, ChainEnd::Primitive));
        assert_eq!(held.chain.frames.len(), 2);
    }

    /// The wide pointer of the dyn-future fixture's driver, and the
    /// vtable it names: what the dynamic resolver checks, one word at
    /// a time.
    fn wide_pointer(ctx: &Context<'_, Snapshot>, list: &TaskList) -> (u64, u64, u64) {
        let driver = task_named(list, "driver");
        let inspection = inspect(ctx, driver);
        let dynamic = inspection
            .chain
            .edges
            .iter()
            .find(|e| matches!(e.selected, FutureTarget::Dynamic { .. }))
            .expect("the driver awaits through a trait object");
        let FutureTarget::Dynamic { pointer, layout } = dynamic.selected else {
            unreachable!()
        };
        let from = inspection.chain.frames[dynamic.from as usize].future;
        let wide = ctx
            .route(from, &pointer.steps, &ReadContext::none())
            .unwrap();
        let data = ctx
            .route(wide, &layout.data.steps, &ReadContext::none())
            .unwrap();
        let vtable = ctx
            .route(wide, &layout.vtable.steps, &ReadContext::none())
            .unwrap();
        let word = |v: Value<'_>| u64::from_le_bytes(v.bytes.try_into().unwrap());
        (data.addr, vtable.addr, word(vtable))
    }

    fn corrupted<'a>(
        bundle: &'a Bundle,
        snapshot: &'a Snapshot,
        patch: impl FnOnce(crate::testkit::corrupt::Corrupt<'a>) -> crate::testkit::corrupt::Corrupt<'a>,
    ) -> (crate::testkit::corrupt::Corrupt<'a>, TaskList) {
        let corrupt = patch(crate::testkit::corrupt::Corrupt::new(snapshot));
        let ctx = Context::new(&corrupt, BundleView::new(bundle)).unwrap();
        let list = testkit::tasks(&ctx, &corrupt);
        drop(ctx);
        (corrupt, list)
    }

    /// The dynamic join reads the recorded ABI slots and believes none
    /// of them blindly: the concrete type is named by the poll and
    /// drop-glue symbols agreeing, the alignment word must be a power
    /// of two the data pointer honors, the size word must be the
    /// layout's, and the referent must be mapped whole. Each check
    /// failing ends the chain with an error naming it; a vtable whose
    /// symbols resolve nothing ends it unknown, with nothing guessed.
    #[test]
    fn test_the_dynamic_join_checks_every_vtable_word() {
        let (bundle, snapshot) = load_any("dyn-future");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        // The driver, the boxed trait object, the leaf it names, and
        // the oneshot receiver the leaf awaits — which no rule covers.
        let healthy = inspect(&ctx, task_named(&list, "driver"));
        assert!(
            matches!(
                healthy.chain.end,
                ChainEnd::UnknownContinuation {
                    reason: SemanticIssueKind::NoRule,
                    ..
                }
            ),
            "{:?}",
            healthy.chain.end
        );
        assert_eq!(healthy.chain.frames.len(), 4, "{:?}", names(&healthy.chain));
        let resolved = &healthy.chain.frames[2];
        assert!(resolved.dyn_symbol.is_some(), "the vtable named the leaf");
        assert!(resolved.future.ty.name().contains("boxed_leaf"));
        assert!(healthy.chain.frames[3].future.ty.name().contains("oneshot"));
        assert!(healthy.chain.all_exclusive());
        let (data_at, vtable_at, vtable) = wide_pointer(&ctx, &list);
        let slot = |n: u64| vtable + n * 8;
        let end_of = |corrupt: &crate::testkit::corrupt::Corrupt<'_>, list: &TaskList| {
            let ctx = Context::new(corrupt, BundleView::new(&bundle)).unwrap();
            let inspection = inspect(&ctx, task_named(list, "driver"));
            match inspection.chain.end {
                ChainEnd::Error(e) => format!("error: {e:#}"),
                other => format!("{other:?}"),
            }
        };
        // Alignment: three is no power of two; a real one the data
        // pointer does not honor is caught the same way.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| c.patch(slot(2), 3));
        assert!(end_of(&corrupt, &list).contains("not a power of two"));
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| c.patch(slot(2), 1 << 20));
        assert!(end_of(&corrupt, &list).contains("is not aligned to"));
        // Size: the vtable's word must be the layout's.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| c.patch(slot(1), 7));
        assert!(end_of(&corrupt, &list).contains("records a size of 7"));
        // The referent: unmapped data is refused before it is read.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| c.patch(data_at, NOWHERE));
        assert!(end_of(&corrupt, &list).contains("unmapped"));
        // The vtable pointer itself.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| c.patch(vtable_at, NOWHERE));
        assert!(end_of(&corrupt, &list).contains("vtable pointer"));
        // Symbols that resolve nothing: the poll slot pointing at no
        // symbol and the drop slot null leave the type unknown.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| {
            c.patch(slot(3), NOWHERE).patch(slot(0), 0)
        });
        let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
        let inspection = inspect(&ctx, task_named(&list, "driver"));
        let ChainEnd::UnknownDyn {
            pointee,
            poll_symbol,
        } = &inspection.chain.end
        else {
            panic!("unknown, not guessed: {:?}", inspection.chain.end);
        };
        assert!(pointee.contains("Future"), "{pointee}");
        assert!(poll_symbol.is_none());
        // A null poll slot is no vtable.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| c.patch(slot(3), 0));
        assert!(end_of(&corrupt, &list).contains("null poll slot"));
    }

    /// Two slots that name different concrete types are conflicting
    /// identity evidence, reported whole; neither is preferred. The
    /// set member's task poll fn stands in for the leaf's poll here:
    /// it joins the task table alone, naming the member's future, while
    /// the drop glue still names the leaf.
    #[test]
    fn test_conflicting_vtable_slots_are_reported_not_resolved() {
        let (bundle, snapshot) = load_any("dyn-future");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let (_, _, vtable) = wide_pointer(&ctx, &list);
        let member = task_named(&list, "set_member");
        let header_ty = ctx
            .infra_ty(ctx.view.bundle().infra.header, "task Header")
            .unwrap();
        let header = Value::read(&snapshot, header_ty, member.addr.0).unwrap();
        let member_vtable: u64 = ctx.walk(WalkRole::HeaderVtable).read(header).unwrap();
        let member_poll: u64 = ctx
            .walk(WalkRole::VtablePoll)
            .read(
                Value::read(
                    &snapshot,
                    ctx.infra_ty(ctx.view.bundle().infra.vtable, "task Vtable")
                        .unwrap(),
                    member_vtable,
                )
                .unwrap(),
            )
            .unwrap();
        let symbol = ctx
            .symbol_at(member_poll)
            .expect("the task poll is a symbol");
        assert!(matches!(
            ctx.dyn_future_ids_memoized(&symbol),
            SymbolLookup::Missing
        ));
        assert!(matches!(
            ctx.task_ids_memoized(&symbol),
            SymbolLookup::Unique(_)
        ));
        let (corrupt, list) =
            corrupted(&bundle, &snapshot, |c| c.patch(vtable + 3 * 8, member_poll));
        let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
        let inspection = inspect(&ctx, task_named(&list, "driver"));
        match &inspection.chain.end {
            ChainEnd::AmbiguousDyn { candidates, .. } => {
                let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
                assert!(names.iter().any(|n| n.contains("boxed_leaf")), "{names:?}");
                assert!(names.iter().any(|n| n.contains("set_member")), "{names:?}");
            }
            other => panic!("conflicting slots are reported: {other:?}"),
        }
        // With the drop glue's constraint gone, the task table alone
        // names the member's future: the sibling fallback resolves it.
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| {
            c.patch(vtable + 3 * 8, member_poll).patch(vtable, 0)
        });
        let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
        let inspection = inspect(&ctx, task_named(&list, "driver"));
        let resolved = &inspection.chain.frames[2];
        assert!(
            resolved.future.ty.name().contains("set_member"),
            "{:?} {:?}",
            names(&inspection.chain),
            inspection.chain.end
        );
    }

    /// A route is held to its recorded target: a program whose path
    /// claims another endpoint than the one the route lands on ends
    /// the chain with an error, whatever the landed value looks like.
    #[test]
    fn test_a_route_landing_off_its_recorded_target_is_an_error() {
        let (mut bundle, snapshot) = load_any("sleep-join");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let root_ty = root_of(&ctx, task_named(&list, "sleeper")).ty.id();
        let join_ty = root_of(&ctx, task_named(&list, "joiner")).ty.id();
        drop(ctx);
        // The sleeper's delegating case now claims to land on the
        // joiner's coroutine.
        let record = bundle
            .semantics
            .types
            .iter_mut()
            .find(|r| r.ty == root_ty)
            .unwrap();
        let Continuation::Bound {
            program: PollProgram::MatchVariant { cases, .. },
            ..
        } = &mut record.future.as_mut().unwrap().continuation
        else {
            panic!("a coroutine matches its states");
        };
        let mut retargeted = 0;
        for case in cases.iter_mut() {
            if let PollAction::Delegate {
                target: FutureTarget::Value(path),
                ..
            } = &mut case.action
            {
                path.target = join_ty;
                retargeted += 1;
            }
        }
        assert!(retargeted > 0);
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let inspection = inspect(&ctx, task_named(&list, "sleeper"));
        assert_eq!(inspection.chain.frames.len(), 1);
        assert!(inspection.chain.edges.is_empty());
        let ChainEnd::Error(e) = &inspection.chain.end else {
            panic!("an error end: {:?}", inspection.chain.end);
        };
        assert!(
            format!("{e:#}").contains("rather than its recorded target"),
            "{e:#}"
        );
    }

    /// A poll symbol ambiguous in the task table between entries of one
    /// future is that future's identity, not an ambiguity: the entries
    /// name one type.
    #[test]
    fn test_task_entries_of_one_future_are_one_identity() {
        let (mut bundle, snapshot) = load_any("dyn-future");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let (_, _, vtable) = wide_pointer(&ctx, &list);
        let member = task_named(&list, "set_member");
        let FutureInfo::Known(known) = &member.future else {
            unreachable!()
        };
        let entry_id = known.entry;
        let header_ty = ctx
            .infra_ty(ctx.view.bundle().infra.header, "task Header")
            .unwrap();
        let header = Value::read(&snapshot, header_ty, member.addr.0).unwrap();
        let member_vtable: u64 = ctx.walk(WalkRole::HeaderVtable).read(header).unwrap();
        let member_poll: u64 = ctx
            .walk(WalkRole::VtablePoll)
            .read(
                Value::read(
                    &snapshot,
                    ctx.infra_ty(ctx.view.bundle().infra.vtable, "task Vtable")
                        .unwrap(),
                    member_vtable,
                )
                .unwrap(),
            )
            .unwrap();
        drop(ctx);
        // A second entry of the same future under the same symbol.
        let twin = bundle.tasks.entries[entry_id.0 as usize].clone();
        bundle.tasks.entries.push(twin);
        let twin_id = hansei_bundle::TaskEntryId(bundle.tasks.entries.len() as u32 - 1);
        // Under every symbol that names the entry: the vtable's poll
        // is one of them, whichever spelling the target's symtab uses.
        let mut keyed = 0;
        for ids in bundle.tasks.by_symbol.values_mut() {
            if ids.contains(&entry_id) {
                ids.push(twin_id);
                keyed += 1;
            }
        }
        assert!(keyed > 0, "the member's symbols are in the task table");
        bundle.tasks.by_normalized_symbol =
            hansei_bundle::symbols::normalized_candidate_index(&bundle.tasks.by_symbol);
        let (corrupt, list) = corrupted(&bundle, &snapshot, |c| {
            c.patch(vtable + 3 * 8, member_poll).patch(vtable, 0)
        });
        let ctx = Context::new(&corrupt, BundleView::new(&bundle)).unwrap();
        assert!(matches!(
            ctx.task_ids_memoized(&ctx.symbol_at(member_poll).unwrap()),
            SymbolLookup::Ambiguous(_)
        ));
        let inspection = inspect(&ctx, task_named(&list, "driver"));
        assert!(
            inspection.chain.frames[2]
                .future
                .ty
                .name()
                .contains("set_member"),
            "{:?} {:?}",
            names(&inspection.chain),
            inspection.chain.end
        );
    }
}

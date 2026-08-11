// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A census of the futures no task listing shows.
//!
//! `tasks` names every *task*; a `trace` shows one task's active
//! `__awaitee` spine. Everything else a program has in flight is
//! invisible to both: the children a `FuturesUnordered` polls, and the
//! futures a frame merely *holds* — `select!`/`join!` arms mid-flight,
//! a future stored across an await, the abandoned lock future of a
//! futurelock. The census walks every enumerated task's chain and
//! scans each frame's locals, by value through nested aggregates and
//! active enum variants, for anything recognizably a future:
//!
//! - a coroutine environment (an `async fn`/`async block` instance),
//! - a future trait object's wide pointer, resolved through the
//!   dyn-future vtable join,
//! - a known leaf future (`Sleep`, `JoinHandle`, `Acquire`),
//! - a `FuturesUnordered`, whose intrusive child list is then walked.
//!
//! Each find is chained (`await_chain`) for its concrete identity,
//! suspend state, and recognized wait target — and its own frames are
//! scanned in turn, so a set inside a held future inside a set is
//! reached. What DWARF cannot say is whether an arbitrary struct
//! implements `Future`, so a hand-written combinator is not itself
//! listed — but the scan descends through it by value, and any
//! coroutine inside it is.
//!
//! Discovery never follows ordinary pointers: a future reachable only
//! behind an unrecognized `Box`/`Arc` is not found (the dyn wide
//! pointer and a set's node list are the deliberate exceptions).

use super::TaskState;
use super::bundle::{AwaitChain, ChainEnd, Context, TaskList, TaskStage, WaitKind, leaf_kind};
// The by-value types sets and join sets are recognized as; the trailing
// `<` keeps each match on the real generic, not a lookalike suffix. A
// `JoinSet` holds *tasks* rather than futures, so it is walked and
// reported apart from a set of futures; anything built on one
// (omicron's `ParallelTaskSet`, which pairs it with a semaphore) is
// reached by the same scan, since it holds its `JoinSet` by value.
use super::contract::{FUTURES_UNORDERED, JOIN_SET};

use anyhow::{Context as _, Result, anyhow, ensure};
use exegesis::bundle::{BundleTypeId, TypeClass, WalkRole};
use foldhash::{HashMap, HashSet};
use proc::Target;
use reify::TypeInfo;
use std::rc::Rc;

/// The spelling of a future trait object's pointee, which is what makes
/// a wide pointer worth chaining even before the vtable join names the
/// concrete type behind it.
const DYN_FUTURE: &str = "dyn core::future::future::Future<";

/// Hard bound on one set's child walk. Real sets run to thousands of
/// children (a `buffer_unordered` over a large stream), so the bound is
/// generous; it exists so corrupt memory ends in a report, not a spin,
/// and a walk that hits it keeps the children found up to there.
const MAX_CHILDREN: usize = 65_536;

/// How deep the locals scan descends through nested aggregates.
const MAX_SCAN_DEPTH: usize = 12;

/// How many held-future/set-child hops the census follows away from a
/// task's own frames before it stops recursing.
const MAX_NESTING: usize = 8;

/// Every future the census found outside the task listings.
#[derive(Debug)]
pub struct FutureCensus {
    pub sets: Vec<FutureSet>,
    pub join_sets: Vec<JoinSet>,
    pub held: Vec<HeldFuture>,
    /// `(start, end, set, child)` per child node, sorted by start, so a
    /// raw pointer into a node resolves to the set that owns it.
    spans: Vec<(u64, u64, usize, usize)>,
    /// Per-find walk failures; the finds that produced entries are
    /// unaffected by these.
    pub errors: Vec<anyhow::Error>,
    /// How many times a hard limit — [`MAX_NESTING`] hops away from a
    /// task's own frames, or [`MAX_SCAN_DEPTH`] levels into one value —
    /// stopped the scan short of where it would otherwise have gone.
    ///
    /// Nonzero means the listing is incomplete in a way no error
    /// reports, which is the only kind of incompleteness a reader cannot
    /// otherwise see.
    pub capped: usize,
}

/// How the census reached a chain that is not an enumerated task's own:
/// the find whose frames were scanned to get there.
///
/// It refers to that find by *position* rather than by address, so it
/// names one recorded entry exactly — an address would be ambiguous
/// where the same memory was reached as two types. A listing can
/// therefore print the census as the tree it is: a future held inside a
/// set child belongs under that child, not beside the ones the task
/// holds itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// A held future's own chain, by its index in [`FutureCensus::held`].
    Held(usize),
    /// A resident set child's chain, by its set's index in
    /// [`FutureCensus::sets`] and its own index among that set's
    /// children.
    SetChild { set: usize, child: usize },
}

/// One `FuturesUnordered`, in place: who polls it and what it holds.
#[derive(Debug)]
pub struct FutureSet {
    /// Index into the [`TaskList`] the census was built from.
    pub owner: usize,
    /// The await-chain frame the set was found in, and the local (the
    /// frame member the scan entered through) that holds it.
    pub frame: usize,
    pub local: String,
    /// How the census reached the frame when it is not one of the
    /// owning task's own; see [`HeldFuture::via`].
    pub via: Option<Via>,
    /// The set's address and full type name.
    pub addr: u64,
    pub ty: String,
    pub children: Vec<SetChild>,
}

/// One `JoinSet`, in place: who drives it and which tasks it holds.
///
/// Its members are spawned tasks, so — unlike a set of futures — every
/// one of them is already a row in the task listing, polled by whatever
/// worker picks it up rather than by the task holding the set. What the
/// census adds is the edge: which listed tasks this one is waiting to
/// join. Their own frames are therefore *not* scanned from here; each is
/// scanned as the task it is.
#[derive(Debug)]
pub struct JoinSet {
    /// Index into the [`TaskList`] the census was built from.
    pub owner: usize,
    /// The await-chain frame the set was found in, and the local (the
    /// frame member the scan entered through) that holds it.
    pub frame: usize,
    pub local: String,
    /// How the census reached the frame when it is not one of the
    /// owning task's own; see [`HeldFuture::via`].
    pub via: Option<Via>,
    /// The set's address and full type name.
    pub addr: u64,
    pub ty: String,
    /// The count the set keeps for itself, which the walk is checked
    /// against: they disagree only if the walk stopped early, and the
    /// error that says so is on the census.
    pub length: u64,
    pub children: Vec<JoinedTask>,
}

/// One task a [`JoinSet`] holds, as the set's own list entry names it.
#[derive(Debug)]
pub struct JoinedTask {
    /// The set's `ListEntry` for this task — the allocation whose waker
    /// the task notifies on completion, not the task itself.
    pub entry: u64,
    /// The joined task's `Header`, which is the address a task listing
    /// identifies it by.
    pub task: u64,
    /// Its id, when the header carries one.
    pub id: Option<u64>,
    /// Its state word. A complete task has left the runtime's owned
    /// list — no listing shows it, and the set's entry is what keeps it
    /// alive until it is joined.
    pub state: TaskState,
    /// Whether the enumerated task list contains it.
    pub listed: bool,
}

/// Where a census future can be re-rooted for tracing: the address its
/// await chain decodes from and the bundle type it decodes with.
#[derive(Debug, Clone, Copy)]
pub struct FutureRoot {
    pub addr: u64,
    pub ty: BundleTypeId,
}

/// One child slot of a set: a heap `Task` node holding the future.
#[derive(Debug)]
pub struct SetChild {
    /// The node's address — what the child's registered wakers carry as
    /// their data word.
    pub node: u64,
    /// How many frames the child's own chain ran to. A census counts
    /// this child as one future in flight however deep it runs, so this
    /// is what a reader needs to tell the two apart.
    pub depth: usize,
    /// The child's concrete future type (dyn-resolved when it had to
    /// be), or `None` for an empty slot: a completed child the set has
    /// not reaped yet.
    pub future: Option<String>,
    /// Where the resident future's chain roots, so the child can be
    /// traced on its own; `None` exactly when `future` is.
    pub root: Option<FutureRoot>,
    /// The child's own suspend state, `Suspend1 — file:line` style.
    pub state: Option<String>,
    /// What the child's chain bottoms out in, when it is a recognized
    /// wait primitive.
    pub waiting_on: Option<String>,
    /// The same wait as a tally counts it, so a summary over thousands
    /// of children need not read the line back.
    pub wait: Option<WaitKind>,
    /// The type the child's chain bottoms out in, whether or not it is
    /// a primitive `wait` names; see [`AwaitChain::leaf`].
    pub leaf: Option<String>,
}

/// A future a frame holds off its task's active `__awaitee` spine: a
/// `select!`/`join!` arm in flight, a future stored across an await, an
/// abandoned one. Whether it will ever be polled again is not knowable
/// here — a select arm is polled every wakeup, a futurelock's never;
/// the futurelock analysis is what proves abandonment.
#[derive(Debug)]
pub struct HeldFuture {
    /// Index into the [`TaskList`] the census was built from.
    pub owner: usize,
    /// The await-chain frame it was found in, and the local (the frame
    /// member the scan entered through) that holds it.
    pub frame: usize,
    pub local: String,
    /// How the census reached the frame when it is not one of the
    /// owning task's own: through a held future's chain, or a set
    /// child's.
    pub via: Option<Via>,
    pub addr: u64,
    /// The bundle type `addr` decodes with — the chain root's when the
    /// chain decoded, the holding local's otherwise — so the future can
    /// be traced on its own.
    pub ty: BundleTypeId,
    /// How many frames its own chain ran to; see [`SetChild::depth`].
    pub depth: usize,
    /// The concrete future type, dyn-resolved when it had to be.
    pub future: String,
    /// Its suspend state, `Suspend1 — file:line` style.
    pub state: Option<String>,
    /// What its chain bottoms out in, when recognized.
    pub waiting_on: Option<String>,
    /// The same wait as a tally counts it; see [`SetChild::wait`].
    pub wait: Option<WaitKind>,
    /// The type its chain bottoms out in; see [`SetChild::leaf`].
    pub leaf: Option<String>,
}

impl FutureCensus {
    /// How a find was reached, spelled for a reader: what the parent is
    /// and the address whose row prints it.
    pub fn describe(&self, via: Via) -> String {
        match via {
            Via::Held(i) => format!("held future at {:#x}", self.held[i].addr),
            Via::SetChild { set, child } => {
                format!("set child at {:#x}", self.sets[set].children[child].node)
            }
        }
    }

    /// The set child whose node allocation contains `addr`: the set and
    /// child indices, and the offset inside the node.
    pub fn locate(&self, addr: u64) -> Option<(usize, usize, u64)> {
        let at = self.spans.partition_point(|&(start, ..)| start <= addr);
        let &(start, end, set, child) = self.spans.get(at.checked_sub(1)?)?;
        (addr < end).then(|| (set, child, addr - start))
    }
}

/// What one scan hit is; [`Walker::record`] decides what to do with it.
enum Find<'b> {
    Set(TypeInfo<'b>),
    JoinSet(TypeInfo<'b>),
    Future(TypeInfo<'b>),
}

/// The census walker's running state.
struct Walker {
    sets: Vec<FutureSet>,
    join_sets: Vec<JoinSet>,
    held: Vec<HeldFuture>,
    spans: Vec<(u64, u64, usize, usize)>,
    errors: Vec<anyhow::Error>,
    capped: usize,
    /// Every find, by (address, type), so an aliased or re-reached
    /// future is recorded once.
    visited: HashSet<(u64, BundleTypeId)>,
    /// [`ScanPlan`] per type: the scan visits millions of values but
    /// only thousands of distinct types, and everything it asks short
    /// of an enum's active variant is a fact of the type.
    plans: HashMap<BundleTypeId, ScanPlan>,
}

/// Walk every enumerated task's await chain and take the census.
///
/// A task whose stage or chain does not decode contributes nothing —
/// those failures already surface wherever the task itself is asked
/// about — while a *found* set or future whose walk fails is reported.
pub fn census<T: Target + Sync>(ctx: &Context<'_, T>, list: &TaskList) -> FutureCensus {
    let mut walker = Walker {
        sets: Vec::new(),
        join_sets: Vec::new(),
        held: Vec::new(),
        spans: Vec::new(),
        errors: Vec::new(),
        capped: 0,
        visited: HashSet::default(),
        plans: HashMap::default(),
    };

    for (owner, task) in list.tasks.iter().enumerate() {
        let Ok(TaskStage::Running(root)) = ctx.task_stage(task) else {
            continue;
        };
        let chain = ctx.await_chain(root);
        walker.scan_chain(ctx, list, owner, None, &chain, 0);
    }

    walker.spans.sort_unstable();
    FutureCensus {
        sets: walker.sets,
        join_sets: walker.join_sets,
        held: walker.held,
        spans: walker.spans,
        errors: walker.errors,
        capped: walker.capped,
    }
}

impl Walker {
    /// Scan every frame of `chain` for sets and held futures, recursing
    /// through what it finds. `via` says how the census reached this
    /// chain when it is not a task's own.
    #[allow(clippy::too_many_arguments)]
    fn scan_chain<'b, T: Target + Sync>(
        &mut self,
        ctx: &Context<'b, T>,
        list: &TaskList,
        owner: usize,
        via: Option<Via>,
        chain: &AwaitChain<'b>,
        nesting: usize,
    ) {
        for (frame_index, frame) in chain.frames.iter().enumerate() {
            let payload = match &frame.state {
                Some(state) => &state.payload,
                None => &frame.future,
            };
            // A frame's own locals only: the `__…` slots are the
            // compiler's (the `__awaitee` is the next frame, scanned as
            // itself), and zero-sized members hold nothing. A wrapper's
            // inner future is the next frame for the same reason, and is
            // skipped for the same reason — counting it here would put
            // it in two of the three populations the census calls
            // disjoint.
            for m in payload.ty.members() {
                if m.name().starts_with("__") || m.ty().size() == 0 || frame.inner == Some(m.name())
                {
                    continue;
                }
                let start = m.offset() as usize;
                let end = start + m.ty().size() as usize;
                let Some(bytes) = payload.bytes.get(start..end) else {
                    continue;
                };
                let local = TypeInfo::new(m.ty(), payload.addr + m.offset(), bytes);
                let mut found = Vec::new();
                scan_value(local, 0, &mut found, &mut self.capped, &mut self.plans);
                for find in found {
                    self.record(ctx, list, owner, frame_index, m.name(), via, find, nesting);
                }
            }
        }
    }

    /// Record one find and recurse into it.
    #[allow(clippy::too_many_arguments)]
    fn record<'b, T: Target + Sync>(
        &mut self,
        ctx: &Context<'b, T>,
        list: &TaskList,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        find: Find<'b>,
        nesting: usize,
    ) {
        let value = match &find {
            Find::Set(value) | Find::JoinSet(value) | Find::Future(value) => value,
        };
        if !self.visited.insert((value.addr, value.ty.id())) {
            return;
        }
        match find {
            Find::Set(value) => {
                self.record_set(ctx, list, owner, frame, local, via, value, nesting)
            }
            Find::JoinSet(value) => {
                self.record_join_set(ctx, list, owner, frame, local, via, value)
            }
            Find::Future(value) => {
                let place = (value.addr, value.ty.id());
                let chain = ctx.await_chain(value);
                let summary = summarize(ctx, list, &chain);
                // The future itself when the chain decoded (behind a
                // box, that is the heap allocation rather than the
                // local's pointer slot); the slot when it did not.
                let (addr, ty) = chain
                    .frames
                    .first()
                    .map(|f| (f.future.addr, f.future.ty.id()))
                    .unwrap_or(place);
                let index = self.held.len();
                self.held.push(HeldFuture {
                    owner,
                    frame,
                    local: local.to_string(),
                    via,
                    addr,
                    ty,
                    depth: summary.depth,
                    future: summary.future,
                    state: summary.state,
                    waiting_on: summary.waiting_on,
                    wait: summary.wait,
                    leaf: summary.leaf,
                });
                if nesting < MAX_NESTING {
                    self.scan_chain(
                        ctx,
                        list,
                        owner,
                        Some(Via::Held(index)),
                        &chain,
                        nesting + 1,
                    );
                } else {
                    self.capped += 1;
                }
            }
        }
    }

    /// Record one set: walk its child nodes, then scan each resident
    /// child's own chain.
    #[allow(clippy::too_many_arguments)]
    fn record_set<'b, T: Target + Sync>(
        &mut self,
        ctx: &Context<'b, T>,
        list: &TaskList,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        value: TypeInfo<'b>,
        nesting: usize,
    ) {
        let index = self.sets.len();
        let mut set = FutureSet {
            owner,
            frame,
            local: local.to_string(),
            via,
            addr: value.addr,
            ty: value.ty.name().to_string(),
            children: Vec::new(),
        };
        // A walk that fails part-way (an unmapped node, the bound)
        // keeps what it found: the children up to the failure are real,
        // and the error says the list is incomplete.
        let mut children = Vec::new();
        if let Err(e) = walk_set(ctx, list, value, &mut children) {
            self.errors.push(e.context(format!(
                "the FuturesUnordered at {:#x} lists only {} of its children",
                value.addr,
                children.len()
            )));
        }
        let mut scan = Vec::new();
        for (child_index, (child, chain, extent)) in children.into_iter().enumerate() {
            self.spans.push((extent.0, extent.1, index, child_index));
            set.children.push(child);
            if chain.is_some() && nesting >= MAX_NESTING {
                self.capped += 1;
            }
            if let Some(chain) = chain
                && nesting < MAX_NESTING
            {
                scan.push((child_index, chain));
            }
        }
        // Record the set before descending into its children, so the
        // index reserved above is the one it keeps: a nested set the
        // scan finds would otherwise take that slot first, and every
        // `Via` naming this one would point at it instead.
        self.sets.push(set);
        for (child, chain) in scan {
            let via = Via::SetChild { set: index, child };
            self.scan_chain(ctx, list, owner, Some(via), &chain, nesting + 1);
        }
    }

    /// Record one join set: walk its two entry lists for the tasks it
    /// holds.
    ///
    /// Nothing recurses out of here. A member is a task the runtime owns
    /// and the listing already carries, so its frames are scanned as its
    /// own — a second scan from here would report every future it holds
    /// twice, under a task that does not poll it.
    #[allow(clippy::too_many_arguments)]
    fn record_join_set<'b, T: Target + Sync>(
        &mut self,
        ctx: &Context<'b, T>,
        list: &TaskList,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        value: TypeInfo<'b>,
    ) {
        // As for a set of futures: a walk that fails part-way keeps the
        // members it reached, and the error says the list is short. The
        // length is read before the walk and kept either way, so a short
        // list is visible in the listing and not only on stderr.
        let mut children = Vec::new();
        let mut length = 0;
        if let Err(e) = walk_join_set(ctx, list, value, &mut children, &mut length) {
            self.errors.push(e.context(format!(
                "the JoinSet at {:#x} lists only {} of its tasks",
                value.addr,
                children.len()
            )));
        }
        self.join_sets.push(JoinSet {
            owner,
            frame,
            local: local.to_string(),
            via,
            addr: value.addr,
            ty: value.ty.name().to_string(),
            length,
            children,
        });
    }
}

/// What [`scan_value`] does at a value of one type — every type-level
/// test it makes, decided once per type and remembered. Everything the
/// scan asks short of an enum's active variant is a fact of the type,
/// and the scan visits millions of values but only thousands of
/// distinct types.
#[derive(Clone)]
enum ScanPlan {
    Set,
    JoinSet,
    /// A future outright: a coroutine env, a known leaf, or a wide
    /// pointer to a future trait object — chained rather than descended
    /// into, so its insides are attributed to it rather than to the
    /// frame holding it.
    Future,
    /// A struct or union: recurse into each sized member, as
    /// `(member type, offset, size)`.
    Descend(Rc<Vec<(BundleTypeId, u64, u64)>>),
    /// A Rust enum: recurse into the active variant's payload. Only the
    /// active variant's payload holds live values; the other variants
    /// are the same storage misread.
    Enum,
    Stop,
}

/// Decide [`ScanPlan`] for one value: the type-level tests of the scan,
/// in order.
fn scan_plan(value: TypeInfo<'_>) -> ScanPlan {
    let name = value.ty.name();
    if name.starts_with(FUTURES_UNORDERED) {
        return ScanPlan::Set;
    }
    if name.starts_with(JOIN_SET) {
        return ScanPlan::JoinSet;
    }
    if value.ty.is_coroutine() || leaf_kind(name).is_some() {
        return ScanPlan::Future;
    }
    // The pointee must *be* a future trait object — anchored at the
    // front (past the parenthesized spelling), since any dyn whose
    // generics merely mention a future (a `dyn FnOnce(..) -> BoxFuture`)
    // would otherwise match.
    if let Some(dp) = value.peel().ty.dyn_pointer() {
        let pointee = dp.pointee.name();
        if pointee
            .strip_prefix('(')
            .unwrap_or(pointee)
            .starts_with(DYN_FUTURE)
        {
            return ScanPlan::Future;
        }
    }
    match value.ty.classify() {
        TypeClass::Struct | TypeClass::Union => ScanPlan::Descend(Rc::new(
            value
                .ty
                .members()
                .filter(|m| m.ty().size() > 0)
                .map(|m| (m.ty().id(), m.offset(), m.ty().size()))
                .collect(),
        )),
        TypeClass::RustEnum => ScanPlan::Enum,
        _ => ScanPlan::Stop,
    }
}

/// Find every by-value future inside `value`: the value itself, or one
/// nested in its structs, unions, and active enum variants. Ordinary
/// pointers are never followed, so the scan stays inside the frame's
/// own bytes and terminates.
fn scan_value<'b>(
    value: TypeInfo<'b>,
    depth: usize,
    found: &mut Vec<Find<'b>>,
    capped: &mut usize,
    plans: &mut HashMap<BundleTypeId, ScanPlan>,
) {
    if depth > MAX_SCAN_DEPTH {
        *capped += 1;
        return;
    }
    // A remembered plan is only valid for a buffer that covers the type
    // exactly: `peel` stops early on a short buffer, so a truncated
    // value's plan is its own. Every value the scan builds covers
    // exactly; this guard keeps the memo honest rather than fast.
    let plan = if value.bytes.len() as u64 == value.ty.size() {
        match plans.get(&value.ty.id()) {
            Some(plan) => plan.clone(),
            None => {
                let plan = scan_plan(value);
                plans.insert(value.ty.id(), plan.clone());
                plan
            }
        }
    } else {
        scan_plan(value)
    };
    match plan {
        ScanPlan::Set => found.push(Find::Set(value)),
        ScanPlan::JoinSet => found.push(Find::JoinSet(value)),
        ScanPlan::Future => found.push(Find::Future(value)),
        ScanPlan::Descend(members) => {
            for &(ty, offset, size) in members.iter() {
                let start = offset as usize;
                let Some(bytes) = value.bytes.get(start..start + size as usize) else {
                    continue;
                };
                let child = TypeInfo::new(value.ty.related_type(ty), value.addr + offset, bytes);
                scan_value(child, depth + 1, found, capped, plans);
            }
        }
        ScanPlan::Enum => {
            if let Ok((_, payload)) = value.active_variant() {
                scan_value(payload, depth + 1, found, capped, plans);
            }
        }
        ScanPlan::Stop => {}
    }
}

/// One find's listing row, reduced from its await chain.
struct Summary {
    /// How many frames the chain ran to, which is what lets a count of
    /// futures be told apart from a count of the frames they stand on.
    depth: usize,
    future: String,
    state: Option<String>,
    waiting_on: Option<String>,
    wait: Option<WaitKind>,
    leaf: Option<String>,
}

/// Reduce a future's await chain to one listing row. An empty chain is
/// a trait object the join could not resolve; the pointee is the most
/// that can be said of it.
fn summarize<'b, T: Target + Sync>(
    ctx: &Context<'b, T>,
    list: &TaskList,
    chain: &AwaitChain<'b>,
) -> Summary {
    let Some(first) = chain.frames.first() else {
        let future = match &chain.end {
            ChainEnd::UnknownDyn { pointee, .. } | ChainEnd::AmbiguousDyn { pointee, .. } => {
                format!("<unresolved: {pointee}>")
            }
            _ => "<undecoded>".to_string(),
        };
        return Summary {
            depth: 0,
            future,
            state: None,
            waiting_on: None,
            wait: None,
            leaf: None,
        };
    };
    let state = first.state.as_ref().map(|state| {
        let loc = state
            .await_loc
            .map(|(file, line)| format!(" — {file}:{line}"))
            .unwrap_or_default();
        format!("{}{loc}", state.name)
    });
    let target = match ctx.wait_target(chain, list) {
        Some(Ok(target)) => Some(target),
        _ => None,
    };
    Summary {
        depth: chain.frames.len(),
        future: first.future.ty.name().to_string(),
        state,
        waiting_on: target.as_ref().map(|t| t.to_string()),
        wait: target.as_ref().map(|t| t.kind()),
        leaf: chain.leaf().map(str::to_string),
    }
}

/// One walked child slot: the listing entry, the resident future's own
/// chain (`None` for an empty slot), and the node's extent.
type WalkedChild<'b> = (SetChild, Option<AwaitChain<'b>>, (u64, u64));

/// Walk one set's intrusive `head_all` → `next_all` node list, pushing
/// each child slot as it goes, so a caller keeps the prefix a failing
/// walk found.
fn walk_set<'b, T: Target + Sync>(
    ctx: &Context<'b, T>,
    list: &TaskList,
    set: TypeInfo<'b>,
    children: &mut Vec<WalkedChild<'b>>,
) -> Result<()> {
    let head_member = ctx.walk(WalkRole::SetHeadAll).walk_at(set)?;
    let head: u64 = head_member.parse(ctx)?;
    // The node layout is the pointer's target, reached by peeling the
    // atomic shims off the `head_all` word.
    let node_ty = head_member
        .ty
        .pointer_target()
        .ok_or_else(|| anyhow!("head_all does not peel to a pointer"))?;

    let mut visited = HashSet::default();
    let mut cur = head;
    while cur != 0 {
        ensure!(
            ctx.mappings.contains_addr(cur),
            "set node pointer {cur:#x} is unmapped"
        );
        ensure!(visited.insert(cur), "set node cycle at {cur:#x}");
        ensure!(
            children.len() < MAX_CHILDREN,
            "the walk stopped at {MAX_CHILDREN} nodes"
        );

        let node = TypeInfo::from_addr(ctx, node_ty, cur)
            .with_context(|| format!("failed to read the set node at {cur:#x}"))?;
        // Task.future: UnsafeCell<Option<Fut>>; `None` is a completed
        // child the set has not reaped.
        let slot = ctx.walk(WalkRole::SetNodeFuture).walk_at(node)?;
        let (variant, payload) = slot
            .active_variant()
            .with_context(|| format!("failed to decode the child slot at {cur:#x}"))?;
        let (child, chain) = if variant == "Some" {
            // The payload peels to the future itself, whose own await
            // chain gives the concrete (dyn-resolved) identity, the
            // suspend state, and the recognized wait target.
            let fut = payload.peel();
            let slot_root = FutureRoot {
                addr: fut.addr,
                ty: fut.ty.id(),
            };
            let chain = ctx.await_chain(fut);
            let summary = summarize(ctx, list, &chain);
            // As for a held future: the chain root itself when the
            // chain decoded (past a dyn wide pointer, that is the heap
            // future), the slot when it did not.
            let root = chain
                .frames
                .first()
                .map(|f| FutureRoot {
                    addr: f.future.addr,
                    ty: f.future.ty.id(),
                })
                .unwrap_or(slot_root);
            (
                SetChild {
                    node: cur,
                    depth: summary.depth,
                    future: Some(summary.future),
                    root: Some(root),
                    state: summary.state,
                    waiting_on: summary.waiting_on,
                    wait: summary.wait,
                    leaf: summary.leaf,
                },
                Some(chain),
            )
        } else {
            (
                SetChild {
                    node: cur,
                    // A reaped slot holds no future, so it stands on no
                    // frames either.
                    depth: 0,
                    future: None,
                    root: None,
                    state: None,
                    waiting_on: None,
                    wait: None,
                    leaf: None,
                },
                None,
            )
        };
        children.push((child, chain, (cur, cur + node_ty.size())));

        cur = ctx.walk(WalkRole::SetNodeNext).read(node)?;
    }
    Ok(())
}

/// Walk one join set's two entry lists for the tasks it holds, returning
/// the length the set keeps for itself.
///
/// A `JoinSet<T>` is an `IdleNotifiedSet<JoinHandle<T>>`: a `length` in
/// the frame beside an `Arc` to a mutex over *two* intrusive lists, one
/// of entries whose task has woken and one of the rest. Which list an
/// entry is in says nothing about the task — a completed task waits in
/// `notified` for its output to be taken — so both are walked and the
/// tasks reported together, in the order the lists hold them.
///
/// Every entry's `value` is live by construction: an entry leaves the
/// two lists before its `JoinHandle` is consumed.
fn walk_join_set<'b, T: Target + Sync>(
    ctx: &Context<'b, T>,
    list: &TaskList,
    set: TypeInfo<'b>,
    tasks: &mut Vec<JoinedTask>,
    length: &mut u64,
) -> Result<()> {
    *length = ctx.walk(WalkRole::JoinSetLength).read(set)?;
    // The lists live behind an Arc, whose target is the `ArcInner`
    // header the payload follows; `data` is the mutex, and its own
    // `data` the guarded value, however the loom shim spells the lock.
    let lists = ctx
        .walk(WalkRole::JoinSetLists)
        .walk_at(set)
        .context("failed to read the join set's shared lists")?;

    let mut visited = HashSet::default();
    for queue in [WalkRole::JoinSetNotifiedHead, WalkRole::JoinSetIdleHead] {
        let Some(head) = ctx.walk(queue).walk(lists)?.optional() else {
            continue;
        };
        // The recorded steps land on the raw entry pointer inside the
        // NonNull: its target is the layout each entry decodes with.
        let entry_ty = head
            .ty
            .pointer_target()
            .ok_or_else(|| anyhow!("the {} list head is not pointer-shaped", queue.name()))?;
        let mut cur = Some(head.parse::<u64, _>(ctx)?);
        while let Some(addr) = cur {
            ensure!(
                ctx.mappings.contains_addr(addr),
                "join set entry pointer {addr:#x} is unmapped"
            );
            ensure!(visited.insert(addr), "join set entry cycle at {addr:#x}");
            ensure!(
                tasks.len() < MAX_CHILDREN,
                "the walk stopped at {MAX_CHILDREN} entries"
            );

            let entry = TypeInfo::from_addr(ctx, entry_ty, addr)
                .with_context(|| format!("failed to read the join set entry at {addr:#x}"))?;
            // ListEntry.value is the joined task's `JoinHandle`, behind
            // a cell and a `ManuallyDrop`. Every wrapper from the cell
            // down to the `Header` pointer holds one value, the handle
            // included, so peeling lands on that pointer — the same word
            // a `JoinHandle` leaf is read through. Asking for a member
            // by name in there would peel first and look afterwards,
            // which is to say look past what it asked for.
            let handle = ctx.walk(WalkRole::JoinSetEntryValue).walk_at(entry)?;
            ensure!(
                handle.ty.pointer_target().is_some(),
                "the join set entry at {addr:#x} does not peel to a task pointer, \
                 but to {}",
                handle.ty.name()
            );
            let task: u64 = handle.parse(ctx)?;
            let (id, state) = ctx
                .header_task_ref(task)
                .with_context(|| format!("failed to identify the task joined at {addr:#x}"))?;
            tasks.push(JoinedTask {
                entry: addr,
                task,
                id,
                state,
                listed: list.contains(task),
            });

            cur = ctx
                .walk(WalkRole::JoinSetEntryNext)
                .walk(entry)?
                .optional()
                .map(|ptr| ptr.parse(ctx).map_err(anyhow::Error::from))
                .transpose()?;
        }
    }
    Ok(())
}

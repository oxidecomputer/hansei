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
use super::contract::{FUTURES_UNORDERED, JOIN_SET, is_dyn_future_pointee};

use anyhow::{Context as _, Result, anyhow, ensure};
use foldhash::{HashMap, HashSet};
use hansei_bundle::{BundleTypeId, TypeClass, WalkRole};
use proc::Target;
use reify::Value;
use std::rc::Rc;

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
    /// Where a hard limit stopped the walk short of where it would
    /// otherwise have gone.
    pub capped: Capped,
}

/// How often each of the census's two hard limits stopped it, kept
/// apart because they say different things about the target: a value
/// nested past [`MAX_SCAN_DEPTH`] is a deep structure (or garbage bytes
/// read as one), while a chain [`MAX_NESTING`] hops out is a real
/// fan-out the census refused to follow any further.
///
/// Either being nonzero means the listing is incomplete in a way no
/// error reports, which is the only kind of incompleteness a reader
/// cannot otherwise see.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Capped {
    /// Values abandoned [`MAX_SCAN_DEPTH`] aggregates into one local.
    pub deep: usize,
    /// Chains not scanned because they lay [`MAX_NESTING`] hops away
    /// from the task's own frames.
    pub distant: usize,
}

impl Capped {
    /// Whether anything was capped at all.
    pub fn any(&self) -> bool {
        self.deep > 0 || self.distant > 0
    }

    /// Every place a limit stopped the walk, of either kind.
    pub fn total(&self) -> usize {
        self.deep + self.distant
    }
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
    Set(Value<'b>),
    JoinSet(Value<'b>),
    Future(Value<'b>),
}

/// The census walker: the context and task listing it scans over, and
/// its running state.
struct Walker<'a, 'b, T> {
    ctx: &'a Context<'b, T>,
    list: &'a TaskList,
    sets: Vec<FutureSet>,
    join_sets: Vec<JoinSet>,
    held: Vec<HeldFuture>,
    spans: Vec<(u64, u64, usize, usize)>,
    errors: Vec<anyhow::Error>,
    capped: Capped,
    /// Where this walk's hard limits sit; [`Bounds::default`] outside
    /// the tests.
    bounds: Bounds,
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
pub fn census<T: Target>(ctx: &Context<'_, T>, list: &TaskList) -> FutureCensus {
    census_bounded(ctx, list, Bounds::default())
}

/// Where the walk's two hard limits sit, as arguments rather than as
/// the constants themselves.
///
/// Every fixture holds its futures a hop or two out and nests its
/// locals a few deep, so a bound is reachable in a test only by moving
/// it — the alternative being a fixture nine hops out and thirteen
/// aggregates deep, built in every matrix cell, to exercise two
/// comparisons.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    /// How many hops away from a task's own frames the scan recurses.
    nesting: usize,
    /// The depth a local's scan starts at. The cap is a fact of
    /// [`MAX_SCAN_DEPTH`], so starting part-way down is how a test
    /// reaches it — the same handle `scan_value`'s own tests take.
    scan_from: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            nesting: MAX_NESTING,
            scan_from: 0,
        }
    }
}

/// [`census`], with the bounds as an argument.
fn census_bounded<T: Target>(
    ctx: &Context<'_, T>,
    list: &TaskList,
    bounds: Bounds,
) -> FutureCensus {
    let mut walker = Walker {
        ctx,
        list,
        sets: Vec::new(),
        join_sets: Vec::new(),
        held: Vec::new(),
        spans: Vec::new(),
        errors: Vec::new(),
        capped: Capped::default(),
        bounds,
        visited: HashSet::default(),
        plans: HashMap::default(),
    };

    for (owner, task) in list.tasks.iter().enumerate() {
        let Ok(TaskStage::Running(root)) = ctx.task_stage(task) else {
            continue;
        };
        let chain = ctx.await_chain(root);
        walker.scan_chain(owner, None, &chain, 0);
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

impl<'b, T: Target> Walker<'_, 'b, T> {
    /// Scan every frame of `chain` for sets and held futures, recursing
    /// through what it finds. `via` says how the census reached this
    /// chain when it is not a task's own.
    fn scan_chain(
        &mut self,
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
                let local = Value::new(m.ty(), payload.addr + m.offset(), bytes);
                let mut found = Vec::new();
                scan_value(
                    local,
                    self.ctx.known_futures(),
                    self.bounds.scan_from,
                    &mut found,
                    &mut self.capped.deep,
                    &mut self.plans,
                );
                for find in found {
                    self.record(owner, frame_index, m.name(), via, find, nesting);
                }
            }
        }
    }

    /// Record one find and recurse into it.
    fn record(
        &mut self,
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
            Find::Set(value) => self.record_set(owner, frame, local, via, value, nesting),
            Find::JoinSet(value) => self.record_join_set(owner, frame, local, via, value),
            Find::Future(value) => {
                let place = (value.addr, value.ty.id());
                let chain = self.ctx.await_chain(value);
                let summary = self.summarize(&chain);
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
                if nesting < self.bounds.nesting {
                    self.scan_chain(owner, Some(Via::Held(index)), &chain, nesting + 1);
                } else {
                    self.capped.distant += 1;
                }
            }
        }
    }

    /// Record one set: walk its child nodes, then scan each resident
    /// child's own chain.
    fn record_set(
        &mut self,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        value: Value<'b>,
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
        if let Err(e) = self.walk_set(value, &mut children) {
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
            if chain.is_some() && nesting >= self.bounds.nesting {
                self.capped.distant += 1;
            }
            if let Some(chain) = chain
                && nesting < self.bounds.nesting
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
            self.scan_chain(owner, Some(via), &chain, nesting + 1);
        }
    }

    /// Record one join set: walk its two entry lists for the tasks it
    /// holds.
    ///
    /// Nothing recurses out of here. A member is a task the runtime owns
    /// and the listing already carries, so its frames are scanned as its
    /// own — a second scan from here would report every future it holds
    /// twice, under a task that does not poll it.
    fn record_join_set(
        &mut self,
        owner: usize,
        frame: usize,
        local: &str,
        via: Option<Via>,
        value: Value<'b>,
    ) {
        // As for a set of futures: a walk that fails part-way keeps the
        // members it reached, and the error says the list is short. The
        // length is read before the walk and kept either way, so a short
        // list is visible in the listing and not only on stderr.
        let mut children = Vec::new();
        let mut length = 0;
        if let Err(e) = self.walk_join_set(value, &mut children, &mut length) {
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
    /// A struct: recurse into each sized member, as
    /// `(member type, offset, size)`.
    Descend(Rc<Vec<(BundleTypeId, u64, u64)>>),
    /// A Rust enum: recurse into the active variant's payload. Only the
    /// active variant's payload holds live values; the other variants
    /// are the same storage misread.
    Enum,
    Stop,
}

/// Decide [`ScanPlan`] for one value: the type-level tests of the scan,
/// in order. `futures` is the bundle's poll table — the types whose
/// `<T as Future>::poll` extraction recorded — so a future the chain
/// walk would follow is one the census counts, even where rustc left
/// no coroutine shape or leaf name to recognize it by.
fn scan_plan(value: Value<'_>, futures: &HashSet<BundleTypeId>) -> ScanPlan {
    let name = value.ty.name();
    if name.starts_with(FUTURES_UNORDERED) {
        return ScanPlan::Set;
    }
    if name.starts_with(JOIN_SET) {
        return ScanPlan::JoinSet;
    }
    if value.ty.is_coroutine() || leaf_kind(name).is_some() || futures.contains(&value.ty.id()) {
        return ScanPlan::Future;
    }
    // The pointee must *be* a future trait object itself, not a dyn
    // whose generics merely mention one.
    if let Some(dp) = value.peel().ty.dyn_pointer()
        && is_dyn_future_pointee(dp.pointee.name())
    {
        return ScanPlan::Future;
    }
    match value.ty.classify() {
        TypeClass::Struct => ScanPlan::Descend(Rc::new(
            value
                .ty
                .members()
                .filter(|m| m.ty().size() > 0)
                .map(|m| (m.ty().id(), m.offset(), m.ty().size()))
                .collect(),
        )),
        TypeClass::RustEnum => ScanPlan::Enum,
        // A union is stopped at rather than descended into, for the
        // reason an enum's inactive variants are: its members are the
        // same storage read as different types, and at most one of them
        // is live. An enum says which one; a union does not, so a scan
        // that descended would take dead — often uninitialized — bytes
        // for a value. `MaybeUninit<F>` is spelled as a union, and a
        // future decoded from uninitialized memory would be chained,
        // summarized, and listed like any other.
        //
        // Which member of a union is initialized is the containing
        // container's own business — an inline-capacity `SmallVec`
        // knows its length, the type does not — so recovering the live
        // ones would take container-specific knowledge the scan has no
        // way to ask for.
        TypeClass::Union => ScanPlan::Stop,
        _ => ScanPlan::Stop,
    }
}

/// Find every by-value future inside `value`: the value itself, or one
/// nested in its structs and active enum variants. Ordinary pointers
/// are never followed, so the scan stays inside the frame's own bytes
/// and terminates.
fn scan_value<'b>(
    value: Value<'b>,
    futures: &HashSet<BundleTypeId>,
    depth: usize,
    found: &mut Vec<Find<'b>>,
    deep: &mut usize,
    plans: &mut HashMap<BundleTypeId, ScanPlan>,
) {
    if depth > MAX_SCAN_DEPTH {
        *deep += 1;
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
                let plan = scan_plan(value, futures);
                plans.insert(value.ty.id(), plan.clone());
                plan
            }
        }
    } else {
        scan_plan(value, futures)
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
                let child = Value::new(value.ty.related_type(ty), value.addr + offset, bytes);
                scan_value(child, futures, depth + 1, found, deep, plans);
            }
        }
        ScanPlan::Enum => {
            if let Ok((_, payload)) = value.active_variant() {
                scan_value(payload, futures, depth + 1, found, deep, plans);
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

impl<'b, T: Target> Walker<'_, 'b, T> {
    /// Reduce a future's await chain to one listing row. An empty chain
    /// is a trait object the join could not resolve; the pointee is the
    /// most that can be said of it.
    fn summarize(&self, chain: &AwaitChain<'b>) -> Summary {
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
        let target = match self.ctx.wait_target(chain, self.list) {
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
}

/// One walked child slot: the listing entry, the resident future's own
/// chain (`None` for an empty slot), and the node's extent.
type WalkedChild<'b> = (SetChild, Option<AwaitChain<'b>>, (u64, u64));

impl<'b, T: Target> Walker<'_, 'b, T> {
    /// Walk one set's intrusive `head_all` → `next_all` node list,
    /// pushing each child slot as it goes, so a caller keeps the prefix
    /// a failing walk found.
    fn walk_set(&self, set: Value<'b>, children: &mut Vec<WalkedChild<'b>>) -> Result<()> {
        let ctx = self.ctx;
        let head_member = ctx.walk(WalkRole::SetHeadAll).walk_at(set)?;
        let head: u64 = head_member.parse(ctx.proc)?;
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

            let node = Value::read(ctx.proc, node_ty, cur)
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
                let summary = self.summarize(&chain);
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
                        // A reaped slot holds no future, so it stands on
                        // no frames either.
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

    /// Walk one join set's two entry lists for the tasks it holds,
    /// returning the length the set keeps for itself.
    ///
    /// A `JoinSet<T>` is an `IdleNotifiedSet<JoinHandle<T>>`: a `length`
    /// in the frame beside an `Arc` to a mutex over *two* intrusive
    /// lists, one of entries whose task has woken and one of the rest.
    /// Which list an entry is in says nothing about the task — a
    /// completed task waits in `notified` for its output to be taken —
    /// so both are walked and the tasks reported together, in the order
    /// the lists hold them.
    ///
    /// Every entry's `value` is live by construction: an entry leaves
    /// the two lists before its `JoinHandle` is consumed.
    fn walk_join_set(
        &self,
        set: Value<'b>,
        tasks: &mut Vec<JoinedTask>,
        length: &mut u64,
    ) -> Result<()> {
        let ctx = self.ctx;
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
            let mut cur = Some(head.parse::<u64>(ctx.proc)?);
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

                let entry = Value::read(ctx.proc, entry_ty, addr)
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
                let task: u64 = handle.parse(ctx.proc)?;
                let (id, state) = ctx
                    .header_task_ref(task)
                    .with_context(|| format!("failed to identify the task joined at {addr:#x}"))?;
                tasks.push(JoinedTask {
                    entry: addr,
                    task,
                    id,
                    state,
                    listed: self.list.contains(task),
                });

                cur = ctx
                    .walk(WalkRole::JoinSetEntryNext)
                    .walk(entry)?
                    .optional()
                    .map(|ptr| ptr.parse(ctx.proc).map_err(anyhow::Error::from))
                    .transpose()?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The locals scan
// ---------------------------------------------------------------------------
//
// `scan_value` decides what the census counts as a future in flight and
// where it says one lies, and every fixture the offline suites capture
// holds its futures as bare frame-top locals — so the descent, the
// active-variant rule, the caps and the plan memo all run against real
// captures without ever reaching a find. These tests drive the two
// scan functions directly over real bundle types and hand-laid bytes,
// the way `contract.rs` drives the step interpreter.
//
// A type is made to look like a future in one of two ways: it *is* one
// (a coroutine, a trait object's wide pointer), or the poll table names
// it. The table is an argument, so a test that only needs "the scan
// reached this member" names an ordinary scalar in it and reads the
// find's address back.
#[cfg(test)]
mod tests {
    use super::*;

    use crate::testkit;

    use hansei_bundle::{Bundle, BundleMember, BundleType, BundleView, DiscrValue, TypeDef};

    use std::sync::OnceLock;

    /// Where every hand-laid value is placed.
    const AT: u64 = 0x1000;

    /// The `unordered` fixture's bundle: a `FuturesUnordered` of
    /// coroutines, an `Option<coroutine>`, a `Pin<Box<dyn Future>>`, and
    /// the std/tokio plumbing the structural finders below pick from.
    fn unordered() -> &'static Bundle {
        static BUNDLE: OnceLock<Bundle> = OnceLock::new();
        BUNDLE.get_or_init(|| testkit::load_any("unordered").0)
    }

    /// The `joinset` fixture's bundle, for the one screen `unordered`
    /// has no type to exercise.
    fn joinset() -> &'static Bundle {
        static BUNDLE: OnceLock<Bundle> = OnceLock::new();
        BUNDLE.get_or_init(|| testkit::load_any("joinset").0)
    }

    /// The first bundle type satisfying `pred`, scanned in id order so
    /// one frozen fixture always yields the same type.
    fn find_ty<'b>(
        bundle: &'b Bundle,
        mut pred: impl FnMut(BundleType<'b>) -> bool,
    ) -> BundleType<'b> {
        let view = BundleView::new(bundle);
        (0..bundle.types.types.len() as u32)
            .filter_map(|i| view.ty(BundleTypeId(i)))
            .find(|ty| pred(*ty))
            .expect("the fixture bundle has such a type")
    }

    /// A poll table naming exactly `ids`: the extraction's record of
    /// which types have a `poll`, which the scan takes as proof of a
    /// future however the type is spelled.
    fn poll_table(ids: impl IntoIterator<Item = BundleTypeId>) -> HashSet<BundleTypeId> {
        ids.into_iter().collect()
    }

    /// A poll table naming every type there is — so a value screened as
    /// anything other than a future was screened by the order of the
    /// tests in [`scan_plan`], not by what the table knows.
    fn every_type(bundle: &Bundle) -> HashSet<BundleTypeId> {
        poll_table((0..bundle.types.types.len() as u32).map(BundleTypeId))
    }

    /// The sized member lying furthest into a type.
    fn last_member(ty: BundleType<'_>) -> BundleMember<'_> {
        ty.members()
            .filter(|m| m.ty().size() > 0)
            .max_by_key(|m| m.offset())
            .expect("the type has a sized member")
    }

    /// What one scan did: what it found, how often a cap stopped it,
    /// and what it remembered.
    struct Scanned<'b> {
        finds: Vec<Find<'b>>,
        capped: usize,
        plans: HashMap<BundleTypeId, ScanPlan>,
    }

    impl Scanned<'_> {
        /// The finds as `kind at address`, for assertion messages.
        fn summary(&self) -> Vec<String> {
            self.finds
                .iter()
                .map(|f| format!("{} at {:#x}", f.kind(), f.value().addr))
                .collect()
        }
    }

    impl<'b> Find<'b> {
        fn kind(&self) -> &'static str {
            match self {
                Find::Set(_) => "set",
                Find::JoinSet(_) => "join set",
                Find::Future(_) => "future",
            }
        }

        fn value(&self) -> Value<'b> {
            match *self {
                Find::Set(v) | Find::JoinSet(v) | Find::Future(v) => v,
            }
        }
    }

    fn scan<'b>(value: Value<'b>, futures: &HashSet<BundleTypeId>) -> Scanned<'b> {
        scan_from(value, futures, 0, HashMap::default())
    }

    /// A scan started part-way down, and over a memo a previous scan
    /// left behind.
    fn scan_from<'b>(
        value: Value<'b>,
        futures: &HashSet<BundleTypeId>,
        depth: usize,
        mut plans: HashMap<BundleTypeId, ScanPlan>,
    ) -> Scanned<'b> {
        let mut finds = Vec::new();
        let mut capped = 0;
        scan_value(value, futures, depth, &mut finds, &mut capped, &mut plans);
        Scanned {
            finds,
            capped,
            plans,
        }
    }

    /// An `Option`-shaped enum over a coroutine: two variants, each
    /// naming its own tag value, one of them carrying a future.
    struct OptionOfFuture<'b> {
        ty: BundleType<'b>,
        discr_offset: u64,
        discr_size: u64,
        some: u128,
        none: u128,
    }

    impl OptionOfFuture<'_> {
        /// The enum's bytes with its tag set to `value`.
        fn bytes(&self, value: u128) -> Vec<u8> {
            let mut out = vec![0u8; self.ty.size() as usize];
            let at = self.discr_offset as usize;
            let size = self.discr_size as usize;
            out[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
            out
        }
    }

    fn option_of_future(bundle: &Bundle) -> OptionOfFuture<'_> {
        let mut found = None;
        find_ty(bundle, |ty| {
            let Some(shape) = ty.variant_shape() else {
                return false;
            };
            let Some(discr) = &shape.discr else {
                return false;
            };
            let discr_size = ty.related_type(discr.ty).size();
            if discr_size == 0 || discr_size > 8 || shape.variants.len() != 2 {
                return false;
            }
            // Both variants must name their own tag value, so bytes
            // selecting either can be laid down deliberately.
            let mut values = Vec::new();
            for v in &shape.variants {
                let Some(vals) = &v.discr_values else {
                    return false;
                };
                let [DiscrValue::Value(x)] = vals.0.as_slice() else {
                    return false;
                };
                values.push(*x);
            }
            // …and one of them must carry a coroutine outright, so the
            // find needs nothing from the poll table to be recognized.
            let carries = |i: usize| {
                let payload = ty.related_type(shape.variants[i].payload.ty);
                let mut sized = payload.members().filter(|m| m.ty().size() > 0);
                matches!((sized.next(), sized.next()), (Some(m), None) if m.ty().is_coroutine())
            };
            let Some(some) = (0..2).find(|&i| carries(i)) else {
                return false;
            };
            found = Some(OptionOfFuture {
                ty,
                discr_offset: discr.offset,
                discr_size,
                some: values[some],
                none: values[1 - some],
            });
            true
        });
        found.expect("the fixture bundle has an Option over a coroutine")
    }

    /// A struct of plain scalars: two or more sized members, all base
    /// types, no two of the same type, and one of them past the start.
    /// Naming a single member's type in the poll table then pins both
    /// that the descent reached it and where it put it.
    fn scalar_struct(bundle: &Bundle) -> BundleType<'_> {
        find_ty(bundle, |ty| {
            if !matches!(ty.def(), TypeDef::Struct { .. }) {
                return false;
            }
            let members: Vec<_> = ty.members().filter(|m| m.ty().size() > 0).collect();
            let ids: HashSet<_> = members.iter().map(|m| m.ty().id()).collect();
            members.len() >= 2
                && ids.len() == members.len()
                && members
                    .iter()
                    .all(|m| matches!(m.ty().def(), TypeDef::Base { .. }))
                && members.iter().any(|m| m.offset() > 0)
        })
    }

    /// A struct that peels to a future trait object's wide pointer
    /// without being one itself — the shape whose plan depends on the
    /// bytes in hand, since `peel` stops short of a member the buffer
    /// does not cover.
    fn dyn_wrapper(bundle: &Bundle) -> BundleType<'_> {
        find_ty(bundle, |ty| {
            if ty.size() <= 8 || ty.dyn_pointer().is_some() {
                return false;
            }
            let bytes = vec![0u8; ty.size() as usize];
            Value::new(ty, AT, &bytes)
                .peel()
                .ty
                .dyn_pointer()
                .is_some_and(|dp| is_dyn_future_pointee(dp.pointee.name()))
        })
    }

    /// A pointer to a set: something the scan would certainly have
    /// recorded had it been reached by value.
    fn pointer_to_set(bundle: &Bundle) -> BundleType<'_> {
        find_ty(bundle, |ty| {
            matches!(ty.def(), TypeDef::Pointer { .. })
                && ty
                    .pointer_target()
                    .is_some_and(|t| t.name().starts_with(FUTURES_UNORDERED))
        })
    }

    fn union_with_members(bundle: &Bundle) -> BundleType<'_> {
        find_ty(bundle, |ty| {
            matches!(ty.classify(), TypeClass::Union) && ty.members().any(|m| m.ty().size() > 0)
        })
    }

    /// Only the active variant's payload is live storage; the other
    /// variant is those same bytes read as something they are not, and
    /// a future decoded from them would be reported as one in flight.
    #[test]
    fn test_an_enum_scans_only_its_active_variant() {
        let e = option_of_future(unordered());
        let empty = poll_table([]);

        let bytes = e.bytes(e.some);
        let value = Value::new(e.ty, AT, &bytes);
        let (name, payload) = value
            .active_variant()
            .expect("the laid-down variant decodes");
        // The payload lies past the tag, so an address taken from the
        // enum rather than from the variant would be visibly wrong.
        assert!(payload.addr > value.addr, "{:#x}", payload.addr);

        let scanned = scan(value, &empty);
        let [Find::Future(found)] = scanned.finds.as_slice() else {
            panic!(
                "the {name} payload's future is found: {:?}",
                scanned.summary()
            );
        };
        assert!(found.ty.is_coroutine(), "{}", found.ty.name());
        assert_eq!(found.addr, payload.addr);
        assert_eq!(found.ty.id(), payload.ty.id());

        // The same storage with the other variant selected holds the
        // same bytes and yields nothing.
        let bytes = e.bytes(e.none);
        let scanned = scan(Value::new(e.ty, AT, &bytes), &empty);
        assert!(
            scanned.finds.is_empty(),
            "an inactive variant was scanned: {:?}",
            scanned.summary()
        );
    }

    /// A future nested in an aggregate is found, at the address the
    /// descent computed for it rather than at its holder's.
    #[test]
    fn test_a_nested_future_is_found_where_it_lies() {
        let bundle = unordered();
        let ty = scalar_struct(bundle);
        let member = last_member(ty);
        let bytes = vec![0u8; ty.size() as usize];
        let value = Value::new(ty, AT, &bytes);

        // Nothing in it is a future until the poll table says one is.
        let quiet = scan(value, &poll_table([]));
        assert!(quiet.finds.is_empty(), "{:?}", quiet.summary());

        let scanned = scan(value, &poll_table([member.ty().id()]));
        let [Find::Future(found)] = scanned.finds.as_slice() else {
            panic!("the nested future is found: {:?}", scanned.summary());
        };
        assert_eq!(found.addr, AT + member.offset());
        assert_eq!(found.ty.id(), member.ty().id());
        assert_eq!(found.bytes.len() as u64, member.ty().size());
    }

    /// The depth cap stops the descent, and says it did: a listing
    /// short by a cap is incomplete in a way no error reports.
    #[test]
    fn test_the_scan_depth_cap_stops_the_descent() {
        let bundle = unordered();
        let ty = scalar_struct(bundle);
        let member = last_member(ty);
        let futures = poll_table([member.ty().id()]);
        let bytes = vec![0u8; ty.size() as usize];
        let value = Value::new(ty, AT, &bytes);
        let members = ty.members().filter(|m| m.ty().size() > 0).count();

        // One level shy of the cap, the descent still runs.
        let scanned = scan_from(value, &futures, MAX_SCAN_DEPTH - 1, HashMap::default());
        assert_eq!(scanned.finds.len(), 1, "{:?}", scanned.summary());
        assert_eq!(scanned.capped, 0);

        // At it, the value is planned but its members are out of reach,
        // and each one they stopped at is counted.
        let scanned = scan_from(value, &futures, MAX_SCAN_DEPTH, HashMap::default());
        assert!(scanned.finds.is_empty(), "{:?}", scanned.summary());
        assert_eq!(scanned.capped, members);

        // Past it, the value itself is never even planned.
        let scanned = scan_from(value, &futures, MAX_SCAN_DEPTH + 1, HashMap::default());
        assert!(scanned.finds.is_empty(), "{:?}", scanned.summary());
        assert_eq!(scanned.capped, 1);
        assert!(scanned.plans.is_empty());
    }

    /// A plan is a fact of the type only for a buffer that covers the
    /// type: `peel` stops early on a short one, so the plan a truncated
    /// value computes is its own and must not be the one every later
    /// value of that type inherits.
    #[test]
    fn test_a_truncated_value_does_not_poison_the_memo() {
        let bundle = unordered();
        let ty = dyn_wrapper(bundle);
        let empty = poll_table([]);
        let full = vec![0u8; ty.size() as usize];
        let whole = Value::new(ty, AT, &full);
        let short = Value::new(ty, AT, &full[..8]);

        // Whole, the wrapper peels to the trait object's wide pointer.
        let scanned = scan(whole, &empty);
        assert!(
            matches!(scanned.finds.as_slice(), [Find::Future(_)]),
            "{:?}",
            scanned.summary()
        );
        assert!(scanned.plans.contains_key(&ty.id()));

        // Truncated, the peel stops short of that pointer and there is
        // nothing to find — and nothing is remembered either.
        let scanned = scan(short, &empty);
        assert!(scanned.finds.is_empty(), "{:?}", scanned.summary());
        assert!(scanned.plans.is_empty(), "a short buffer wrote a plan");

        // So a whole value read after a truncated one is still planned
        // for what it is.
        let first = scan_from(short, &empty, 0, HashMap::default());
        let second = scan_from(whole, &empty, 0, first.plans);
        assert!(
            matches!(second.finds.as_slice(), [Find::Future(_)]),
            "{:?}",
            second.summary()
        );
    }

    /// Discovery follows a dyn wide pointer and a set's node list, and
    /// no other pointer: a future reachable only through one is not
    /// found, however plainly its type says what it points at.
    #[test]
    fn test_ordinary_pointers_are_not_followed() {
        let bundle = unordered();
        let ty = pointer_to_set(bundle);
        let target = ty.pointer_target().expect("a pointer has a target");
        let bytes = vec![0u8; ty.size() as usize];
        // The target named in the poll table as well, so nothing about
        // it could make following the pointer look justified.
        let scanned = scan(Value::new(ty, AT, &bytes), &poll_table([target.id()]));
        assert!(scanned.finds.is_empty(), "{:?}", scanned.summary());
        // A pointer is stopped at outright, rather than counted as the
        // future it points at: the word is not the future, and reading
        // what it addresses is what discovery declines to do.
        assert!(matches!(scanned.plans.get(&ty.id()), Some(ScanPlan::Stop)));
        assert_eq!(scanned.capped, 0);
    }

    /// A set is recognized as one before the struct fallback would
    /// descend into it: its children belong to it, not to the frame.
    #[test]
    fn test_a_set_screens_before_the_descent() {
        let bundle = unordered();
        let ty = find_ty(bundle, |t| t.name().starts_with(FUTURES_UNORDERED));
        let bytes = vec![0u8; ty.size() as usize];
        let scanned = scan(Value::new(ty, AT, &bytes), &every_type(bundle));
        let [Find::Set(found)] = scanned.finds.as_slice() else {
            panic!("the set is screened as one: {:?}", scanned.summary());
        };
        assert_eq!(found.addr, AT);
        assert_eq!(found.ty.id(), ty.id());
    }

    /// And a join set as a join set, which is walked and reported
    /// apart: it holds tasks the listing already carries.
    #[test]
    fn test_a_join_set_screens_before_the_descent() {
        let bundle = joinset();
        let ty = find_ty(bundle, |t| t.name().starts_with(JOIN_SET));
        let bytes = vec![0u8; ty.size() as usize];
        let scanned = scan(Value::new(ty, AT, &bytes), &every_type(bundle));
        let [Find::JoinSet(found)] = scanned.finds.as_slice() else {
            panic!("the join set is screened as one: {:?}", scanned.summary());
        };
        assert_eq!(found.addr, AT);
        assert_eq!(found.ty.id(), ty.id());
    }

    /// A coroutine is a future outright, screened before the enum it is
    /// spelled as would have been descended into — its locals belong to
    /// it, and are scanned as its own frame rather than its holder's.
    #[test]
    fn test_a_coroutine_screens_before_its_variants() {
        let bundle = unordered();
        let ty = find_ty(bundle, |t| t.is_coroutine());
        let bytes = vec![0u8; ty.size() as usize];
        let scanned = scan(Value::new(ty, AT, &bytes), &poll_table([]));
        let [Find::Future(found)] = scanned.finds.as_slice() else {
            panic!("the coroutine is a future: {:?}", scanned.summary());
        };
        assert_eq!(found.addr, AT);
        assert_eq!(found.ty.id(), ty.id());
    }

    /// A union is stopped at: its members are one storage read several
    /// ways, with nothing saying which reading is live, so descending
    /// would report a future built from bytes that hold none.
    #[test]
    fn test_a_union_is_not_descended_into() {
        let bundle = unordered();
        let ty = union_with_members(bundle);
        let members = ty
            .members()
            .filter(|m| m.ty().size() > 0)
            .map(|m| m.ty().id());
        let bytes = vec![0u8; ty.size() as usize];
        let scanned = scan(Value::new(ty, AT, &bytes), &poll_table(members));
        assert!(
            scanned.finds.is_empty(),
            "a union was descended into: {:?}",
            scanned.summary()
        );
        // Stopped, not cut short: there is nothing here the scan could
        // have read, so the caps that say a listing is incomplete are
        // untouched.
        assert!(matches!(scanned.plans.get(&ty.id()), Some(ScanPlan::Stop)));
        assert_eq!(scanned.capped, 0);
    }

    /// The whole census of the `unordered` pair, walked with the given
    /// bounds.
    ///
    /// That fixture is the one with nesting to stop: its driver holds a
    /// `FuturesUnordered` whose three children each hold a future of
    /// their own, one of them a whole set of its own, beside the four
    /// futures the driver holds itself.
    fn unordered_census(bounds: Bounds) -> FutureCensus {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census_bounded(&ctx, &list, bounds);
        assert!(census.errors.is_empty(), "{:?}", census.errors);
        census
    }

    /// The nesting bound at `hops`, the depth bound where it lies.
    fn nesting(hops: usize) -> Bounds {
        Bounds {
            nesting: hops,
            ..Bounds::default()
        }
    }

    /// A find at the bound is still recorded — it was found in frames
    /// the census was allowed to scan — but its own frames are not
    /// scanned, and every chain left unscanned that way is counted.
    /// The count is the whole of what says so: no error is raised, and
    /// a listing shortened by a bound reads exactly like a complete
    /// one.
    #[test]
    fn test_the_nesting_bound_keeps_the_find_it_stops_at() {
        // With no hops allowed, a task's own frames are all that is
        // scanned: the four futures the driver holds and the set it
        // drives, whose children are walked (a set's own child list is
        // not a hop) but never scanned.
        let census = unordered_census(nesting(0));
        assert_eq!(census.sets.len(), 1, "{:#?}", census.sets);
        assert_eq!(census.sets[0].children.len(), 3, "{:#?}", census.sets[0]);
        let own: Vec<&str> = census.held.iter().map(|h| h.local.as_str()).collect();
        assert_eq!(
            own,
            ["held", "boxed", "pair", "maybe"],
            "{:#?}",
            census.held
        );
        assert!(
            census.held.iter().all(|h| h.via.is_none()),
            "{:#?}",
            census.held
        );

        // Four held futures and three resident set children: seven
        // chains the census reached and declined to scan.
        assert_eq!(
            census.capped,
            Capped {
                deep: 0,
                distant: 7
            }
        );
        assert!(census.capped.any());
        assert_eq!(census.capped.total(), 7);
    }

    /// The bound counts where the walk stopped, not what it found: one
    /// hop out reaches every find the fixture has, and still reports
    /// the five chains it would have gone on to scan. The unbounded
    /// walk finds the same and reports nothing, which is what makes a
    /// nonzero count mean something.
    #[test]
    fn test_the_nesting_bound_counts_the_chains_it_declined() {
        let bounded = unordered_census(nesting(1));
        let full = unordered_census(Bounds::default());

        assert_eq!(bounded.sets.len(), full.sets.len(), "{:#?}", bounded.sets);
        assert_eq!(bounded.held.len(), full.held.len(), "{:#?}", bounded.held);
        assert_eq!(full.capped, Capped::default());
        assert!(!full.capped.any());

        // The three futures the set's children hold, plus the two
        // children of the set one of them holds.
        assert_eq!(
            bounded.capped,
            Capped {
                deep: 0,
                distant: 5
            }
        );
    }

    /// The two bounds are counted apart, because they say different
    /// things: a scan that starts past the depth cap plans nothing, so
    /// every local is abandoned where it lies and no chain is ever
    /// reached to decline.
    #[test]
    fn test_a_capped_descent_is_not_counted_as_a_capped_hop() {
        let census = unordered_census(Bounds {
            scan_from: MAX_SCAN_DEPTH + 1,
            ..Bounds::default()
        });
        assert!(census.sets.is_empty(), "{:#?}", census.sets);
        assert!(census.held.is_empty(), "{:#?}", census.held);
        assert!(census.capped.deep > 0, "{:?}", census.capped);
        assert_eq!(census.capped.distant, 0, "{:?}", census.capped);
    }
}

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
    /// Which of the scan's paths produced the finds; see [`Stats`].
    pub stats: Stats,
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

/// Which of the scan's paths the walk's finds came through. Nothing in
/// the listing says how a find was reached — a future found through a
/// struct descent reads exactly like one lying at the frame top — so
/// these counters are what lets a test assert a path is still
/// exercised at all, against the quiet decay where a fixture edit
/// leaves a path running but never finding. Counted unconditionally:
/// an integration test links the library built without `cfg(test)`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Finds the scan reached through at least one struct descent.
    pub descend_finds: usize,
    /// Finds the scan reached through at least one active enum
    /// variant.
    pub enum_finds: usize,
    /// Finds dropped because their (address, type) was already
    /// recorded.
    pub dedup_hits: usize,
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
    /// Where the scan found it: the found value's own address inside
    /// the frame — the future itself when held by value, the wide
    /// pointer's slot when boxed. Equal to `addr` except for a boxed
    /// find, whose `addr` is re-pointed at the heap referent below.
    /// This is the address a fixture can name for the thing it built,
    /// which is what the ground-truth registry keys held finds by.
    pub slot: u64,
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

    /// Check the census against its own construction rules: the
    /// invariants that hold over *any* input, corrupt memory included,
    /// because the walk builds these properties itself rather than
    /// reading them from the target. A violation is therefore a census
    /// bug, never a fact about the target — which is what lets a fault
    /// campaign assert this over output produced from damaged memory,
    /// where nothing about the *content* of the listing can be
    /// asserted at all.
    ///
    /// `list` must be the [`TaskList`] the census was built from. One
    /// line per violation; empty is clean. [`FutureCensus::audit`]
    /// adds the invariants only a healthy capture guarantees.
    pub fn audit_total(&self, list: &TaskList) -> Vec<String> {
        let mut v = Vec::new();

        // Every find belongs to an enumerated task, and every find
        // reached through another names one that exists — recorded
        // *earlier* where the two live in the same table, which is the
        // index-reservation rule made checkable.
        for (i, held) in self.held.iter().enumerate() {
            self.check_owner("held find", i, held.owner, list, &mut v);
            self.check_via("held find", i, held.via, i, self.sets.len(), &mut v);
            check_summary(
                &format!("held find {i}"),
                held.depth,
                held.state.is_some(),
                held.waiting_on.is_some(),
                held.wait.is_some(),
                held.leaf.is_some(),
                &mut v,
            );
        }
        for (i, set) in self.sets.iter().enumerate() {
            self.check_owner("set", i, set.owner, list, &mut v);
            self.check_via("set", i, set.via, self.held.len(), i, &mut v);
            for (c, child) in set.children.iter().enumerate() {
                let what = format!("set {i} child {c}");
                // An empty slot holds no future, so it roots nowhere
                // and stands on no frames; a resident child roots
                // exactly where its future is.
                if child.future.is_none() != child.root.is_none() {
                    v.push(format!(
                        "{what} has a future without a root, or a root without a future"
                    ));
                }
                if child.future.is_none() && child.depth != 0 {
                    v.push(format!(
                        "{what} is an empty slot standing on {} frames",
                        child.depth
                    ));
                }
                check_summary(
                    &what,
                    child.depth,
                    child.state.is_some(),
                    child.waiting_on.is_some(),
                    child.wait.is_some(),
                    child.leaf.is_some(),
                    &mut v,
                );
            }
        }
        for (i, set) in self.join_sets.iter().enumerate() {
            self.check_owner("join set", i, set.owner, list, &mut v);
            self.check_via(
                "join set",
                i,
                set.via,
                self.held.len(),
                self.sets.len(),
                &mut v,
            );
            let mut entries = HashSet::default();
            for child in &set.children {
                if !entries.insert(child.entry) {
                    v.push(format!(
                        "the join set at {:#x} lists the entry at {:#x} twice",
                        set.addr, child.entry
                    ));
                }
                if child.listed != list.contains(child.task) {
                    v.push(format!(
                        "the join set member at {:#x} is marked listed={} against the task list",
                        child.task, child.listed
                    ));
                }
            }
            // A walk may disagree with the set's own length — a failed
            // walk runs short, a bent link grafts entries in — but
            // never silently: the escape hatch is part of the
            // invariant, which is what keeps it total over corrupt
            // input.
            if set.children.len() as u64 != set.length && !self.some_error_names(set.addr) {
                v.push(format!(
                    "the join set at {:#x} lists {} tasks against a length of {}, and no error says so",
                    set.addr,
                    set.children.len(),
                    set.length
                ));
            }
        }

        // No two rows of one population claim one future: what
        // `Walker::visited` promises regardless of input.
        let mut seen = HashSet::default();
        for held in &self.held {
            if !seen.insert((held.addr, held.ty)) {
                v.push(format!("two held finds at {:#x} share a type", held.addr));
            }
        }
        let mut seen = HashSet::default();
        for set in &self.sets {
            if !seen.insert((set.addr, set.ty.as_str())) {
                v.push(format!("the set at {:#x} is recorded twice", set.addr));
            }
        }
        let mut seen = HashSet::default();
        for set in &self.join_sets {
            if !seen.insert((set.addr, set.ty.as_str())) {
                v.push(format!("the join set at {:#x} is recorded twice", set.addr));
            }
        }

        // The spans are the walk's record of where every child node
        // lies: sorted, disjoint, one per child, each naming the child
        // whose node it covers. `locate` resolves raw pointers through
        // them by binary search, so any breach here is a `whatis` that
        // names the wrong child.
        let mut claimed = HashSet::default();
        for (i, &(start, end, set, child)) in self.spans.iter().enumerate() {
            if let Some(&(prev_start, prev_end, ..)) = i.checked_sub(1).map(|p| &self.spans[p]) {
                if prev_start > start {
                    v.push(format!(
                        "the span at {start:#x} sorts before its predecessor"
                    ));
                } else if prev_end > start && !self.some_error_names(start) {
                    // The same escape hatch as a join set's length: a
                    // bent list can make two correct walks claim one
                    // allocation, so what is total is that an overlap
                    // is never silent.
                    v.push(format!(
                        "the span {start:#x}..{end:#x} overlaps its predecessor ending at {prev_end:#x}, and no error says so"
                    ));
                }
            }
            match self.sets.get(set).and_then(|s| s.children.get(child)) {
                None => v.push(format!(
                    "the span {start:#x}..{end:#x} names set {set} child {child}, which does not exist"
                )),
                Some(c) if c.node != start => v.push(format!(
                    "the span at {start:#x} claims the child whose node is at {:#x}",
                    c.node
                )),
                Some(_) => {}
            }
            if !claimed.insert((set, child)) {
                v.push(format!("set {set} child {child} has two spans"));
            }
        }
        let children: usize = self.sets.iter().map(|s| s.children.len()).sum();
        if self.spans.len() != children {
            v.push(format!(
                "{} spans for {} set children",
                self.spans.len(),
                children
            ));
        }

        // An error is a report, and a report that names no address
        // gives a reader nothing to look at.
        for (i, e) in self.errors.iter().enumerate() {
            if !format!("{e:#}").contains("0x") {
                v.push(format!("error {i} names no address: {e:#}"));
            }
        }

        v
    }

    /// [`FutureCensus::audit_total`] plus the invariants a healthy
    /// capture guarantees but corruption may legitimately break, for
    /// input known to be good.
    ///
    /// The one cross-population overlap deliberately *not* asserted:
    /// a future can appear as both a set child and a held find, since
    /// set children are recorded by the set walk and never keyed into
    /// the dedup — an accepted risk, reachable only through unsafe
    /// code.
    pub fn audit(&self, list: &TaskList) -> Vec<String> {
        let mut v = self.audit_total(list);

        // A live future is one set's child, once.
        let mut roots = HashSet::default();
        for set in &self.sets {
            for child in &set.children {
                if let Some(root) = child.root
                    && !roots.insert((root.addr, root.ty))
                {
                    v.push(format!(
                        "the future at {:#x} is more than one set's child",
                        root.addr
                    ));
                }
            }
        }

        // A task joins one set through one entry. Within one set the
        // entry check is total (the walk's own cycle guard); across
        // sets, and for the task behind the entry, only healthy memory
        // promises it.
        let mut entries: HashMap<u64, usize> = HashMap::default();
        let mut members = HashSet::default();
        for (i, set) in self.join_sets.iter().enumerate() {
            for child in &set.children {
                if let Some(prev) = entries.insert(child.entry, i)
                    && prev != i
                {
                    v.push(format!(
                        "the entry at {:#x} is in two join sets",
                        child.entry
                    ));
                }
                if !members.insert(child.task) {
                    v.push(format!(
                        "the task at {:#x} is joined more than once",
                        child.task
                    ));
                }
            }
        }

        v
    }

    /// Whether some recorded error's report names `addr`.
    fn some_error_names(&self, addr: u64) -> bool {
        let spelled = format!("{addr:#x}");
        self.errors
            .iter()
            .any(|e| format!("{e:#}").contains(&spelled))
    }

    fn check_owner(
        &self,
        kind: &str,
        index: usize,
        owner: usize,
        list: &TaskList,
        v: &mut Vec<String>,
    ) {
        if owner >= list.tasks.len() {
            v.push(format!(
                "{kind} {index} names owner {owner} of {} tasks",
                list.tasks.len()
            ));
        }
    }

    /// One `via`'s validity: it names a find that exists — recorded
    /// earlier, where both live in the same table — and a set child it
    /// arrives through actually holds a future, since the walk only
    /// descends into resident children.
    fn check_via(
        &self,
        kind: &str,
        index: usize,
        via: Option<Via>,
        held_limit: usize,
        set_limit: usize,
        v: &mut Vec<String>,
    ) {
        match via {
            None => {}
            Some(Via::Held(h)) => {
                if h >= held_limit {
                    v.push(format!(
                        "{kind} {index} was reached via held find {h}, which is not earlier-recorded"
                    ));
                }
            }
            Some(Via::SetChild { set, child }) => {
                if set >= set_limit {
                    v.push(format!(
                        "{kind} {index} was reached via set {set}, which is not earlier-recorded"
                    ));
                } else if self.sets[set].children.get(child).is_none() {
                    v.push(format!(
                        "{kind} {index} was reached via set {set} child {child}, which does not exist"
                    ));
                } else if self.sets[set].children[child].future.is_none() {
                    v.push(format!(
                        "{kind} {index} was reached via set {set} child {child}, an empty slot"
                    ));
                }
            }
        }
    }
}

/// The conventions every reduced chain summary obeys, held future and
/// set child alike: a find standing on no frames has nothing to
/// summarize, and a wait is counted exactly when it is named — both
/// halves come from one recognized target.
fn check_summary(
    what: &str,
    depth: usize,
    state: bool,
    waiting_on: bool,
    wait: bool,
    leaf: bool,
    v: &mut Vec<String>,
) {
    if depth == 0 && (state || waiting_on || wait || leaf) {
        v.push(format!("{what} stands on no frames but carries a summary"));
    }
    if wait != waiting_on {
        v.push(format!(
            "{what} counts a wait it does not name, or names one it does not count"
        ));
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
    stats: Stats,
    /// Where this walk's hard limits sit; [`Bounds::default`] outside
    /// the tests.
    bounds: Bounds,
    /// Every find, by (address, type), so an aliased or re-reached
    /// future is recorded once.
    ///
    /// A find is keyed both by the slot it was found in and — once its
    /// chain has decoded — by the future that chain roots at, which
    /// are the same place for a future held by value and different
    /// ones behind a wide pointer. Keying only the slot would let two
    /// references to one future be two rows in a listing whose
    /// populations are meant not to overlap.
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

/// Where the walk's two hard limits sit, as values rather than as the
/// constants themselves: a caller who was told the walk stopped can
/// move the limit that stopped it and ask again.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    /// How deep the scan descends through one local's nested
    /// aggregates and active variants.
    pub scan_depth: usize,
    /// How many hops away from a task's own frames the scan recurses:
    /// a future held by a future held by a set child. Not reachable
    /// from the command line, since no target has yet come near it.
    pub nesting: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds {
            scan_depth: MAX_SCAN_DEPTH,
            nesting: MAX_NESTING,
        }
    }
}

/// [`census`], with the bounds as an argument.
pub fn census_bounded<T: Target>(
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
        stats: Stats::default(),
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
    walker.errors.extend(span_overlap_errors(&walker.spans));
    FutureCensus {
        sets: walker.sets,
        join_sets: walker.join_sets,
        held: walker.held,
        spans: walker.spans,
        errors: walker.errors,
        capped: walker.capped,
        stats: walker.stats,
    }
}

/// The reports for any two sorted spans claiming one byte. No healthy
/// walk produces one — each node is one allocation — but a bent list
/// can graft one set's node into another set's chain, and each walk,
/// correct in isolation, then claims that allocation for its own
/// child. Which claim is real is unknowable here, so both stand in the
/// listing and these say they conflict. Touching spans are adjacent
/// allocations, not a conflict.
fn span_overlap_errors(spans: &[(u64, u64, usize, usize)]) -> Vec<anyhow::Error> {
    spans
        .windows(2)
        .filter_map(|pair| {
            let &[(a_start, a_end, ..), (b_start, ..)] = pair else {
                return None;
            };
            (a_end > b_start).then(|| {
                anyhow!(
                    "the set nodes at {a_start:#x} and {b_start:#x} overlap: \
                     two sets claim one allocation"
                )
            })
        })
        .collect()
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
            for m in payload.ty.members() {
                if !is_own_local(m.name(), m.ty().size(), frame.inner) {
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
                    0,
                    self.bounds.scan_depth,
                    Path::default(),
                    &mut found,
                    &mut self.capped.deep,
                    &mut self.plans,
                    &mut self.stats,
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
            self.stats.dedup_hits += 1;
            return;
        }
        match find {
            Find::Set(value) => self.record_set(owner, frame, local, via, value, nesting),
            Find::JoinSet(value) => self.record_join_set(owner, frame, local, via, value),
            Find::Future(value) => {
                let place = (value.addr, value.ty.id());
                let chain = self.ctx.await_chain(value);
                // The future itself when the chain decoded (behind a
                // box, that is the heap allocation rather than the
                // local's pointer slot); the slot when it did not.
                let (addr, ty) = chain
                    .frames
                    .first()
                    .map(|f| (f.future.addr, f.future.ty.id()))
                    .unwrap_or(place);
                // What was recorded is that future, so that is what a
                // later reference to it has to be deduped against —
                // the slot key above is the pointer's, and two
                // pointers to one future have two of those. A find
                // held by value keys the same place twice, which is
                // why only a differing root is looked up.
                if (addr, ty) != place && !self.visited.insert((addr, ty)) {
                    self.stats.dedup_hits += 1;
                    return;
                }
                let summary = self.summarize(&chain);
                let index = self.held.len();
                self.held.push(HeldFuture {
                    owner,
                    frame,
                    local: local.to_string(),
                    via,
                    slot: place.0,
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
        } else if children.len() as u64 != length {
            // Both lists ran to their ends and still disagree with the
            // count the set keeps for itself: the length word or a
            // list link lies — a bent link can graft entries in as
            // well as cut them off — and nothing can say which. The
            // listing carries both numbers; this says they conflict.
            self.errors.push(anyhow!(
                "the JoinSet at {:#x} lists {} tasks against its own count of {}",
                value.addr,
                children.len(),
                length
            ));
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

/// Whether a frame member is one of the frame's own locals, which are
/// all the scan looks at.
///
/// The rest is the machinery around them, and each piece of it is
/// somewhere else in the listing already: the `__…` slots are the
/// compiler's, and its `__awaitee` is the next frame, scanned as
/// itself; a zero-sized member holds nothing; and a wrapper future's
/// sole inner future (`inner`) is that wrapper's next frame, for the
/// same reason. Counting any of them here would put one future in two
/// of the three populations the census calls disjoint.
fn is_own_local(name: &str, size: u64, inner: Option<&str>) -> bool {
    !name.starts_with("__") && size > 0 && inner != Some(name)
}

/// The steps between the scanned local and the value in hand: whether
/// a struct descent or an active-variant step lies on the way, which
/// is what the per-path find counters in [`Stats`] record.
#[derive(Debug, Default, Clone, Copy)]
struct Path {
    descended: bool,
    variant: bool,
}

/// Find every by-value future inside `value`: the value itself, or one
/// nested in its structs and active enum variants. Ordinary pointers
/// are never followed, so the scan stays inside the frame's own bytes
/// and terminates.
#[expect(clippy::too_many_arguments, reason = "internal recursion")]
fn scan_value<'b>(
    value: Value<'b>,
    futures: &HashSet<BundleTypeId>,
    depth: usize,
    max_depth: usize,
    path: Path,
    found: &mut Vec<Find<'b>>,
    deep: &mut usize,
    plans: &mut HashMap<BundleTypeId, ScanPlan>,
    stats: &mut Stats,
) {
    if depth > max_depth {
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
    if matches!(plan, ScanPlan::Set | ScanPlan::JoinSet | ScanPlan::Future) {
        if path.descended {
            stats.descend_finds += 1;
        }
        if path.variant {
            stats.enum_finds += 1;
        }
    }
    match plan {
        ScanPlan::Set => found.push(Find::Set(value)),
        ScanPlan::JoinSet => found.push(Find::JoinSet(value)),
        ScanPlan::Future => found.push(Find::Future(value)),
        ScanPlan::Descend(members) => {
            let path = Path {
                descended: true,
                ..path
            };
            for &(ty, offset, size) in members.iter() {
                let start = offset as usize;
                let Some(bytes) = value.bytes.get(start..start + size as usize) else {
                    continue;
                };
                let child = Value::new(value.ty.related_type(ty), value.addr + offset, bytes);
                scan_value(
                    child,
                    futures,
                    depth + 1,
                    max_depth,
                    path,
                    found,
                    deep,
                    plans,
                    stats,
                );
            }
        }
        ScanPlan::Enum => {
            if let Ok((_, payload)) = value.active_variant() {
                let path = Path {
                    variant: true,
                    ..path
                };
                scan_value(
                    payload,
                    futures,
                    depth + 1,
                    max_depth,
                    path,
                    found,
                    deep,
                    plans,
                    stats,
                );
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
        stats: Stats,
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
        let mut stats = Stats::default();
        scan_value(
            value,
            futures,
            depth,
            MAX_SCAN_DEPTH,
            Path::default(),
            &mut finds,
            &mut capped,
            &mut plans,
            &mut stats,
        );
        Scanned {
            finds,
            capped,
            plans,
            stats,
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
        // The find came through the variant step and nothing else: the
        // payload is the coroutine itself, not a struct around one.
        assert_eq!(scanned.stats.enum_finds, 1, "{:?}", scanned.stats);
        assert_eq!(scanned.stats.descend_finds, 0, "{:?}", scanned.stats);

        // The same storage with the other variant selected holds the
        // same bytes and yields nothing.
        let bytes = e.bytes(e.none);
        let scanned = scan(Value::new(e.ty, AT, &bytes), &empty);
        assert!(
            scanned.finds.is_empty(),
            "an inactive variant was scanned: {:?}",
            scanned.summary()
        );
        assert_eq!(scanned.stats, Stats::default());
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
        assert_eq!(quiet.stats, Stats::default());

        let scanned = scan(value, &poll_table([member.ty().id()]));
        let [Find::Future(found)] = scanned.finds.as_slice() else {
            panic!("the nested future is found: {:?}", scanned.summary());
        };
        assert_eq!(found.addr, AT + member.offset());
        assert_eq!(found.ty.id(), member.ty().id());
        assert_eq!(found.bytes.len() as u64, member.ty().size());
        // Reached through the descent and through nothing else.
        assert_eq!(scanned.stats.descend_finds, 1, "{:?}", scanned.stats);
        assert_eq!(scanned.stats.enum_finds, 0, "{:?}", scanned.stats);
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
        // A frame-top find came through no step the counters record.
        assert_eq!(scanned.stats, Stats::default());
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

    /// Which frame members the scan looks at. Every fixture's chains
    /// are coroutines, whose next frame is an `__awaitee` — none has a
    /// wrapper future, whose sole inner future is its next frame under
    /// a name of its own, so that arm of the rule is stated here or
    /// nowhere.
    #[test]
    fn test_only_a_frame_s_own_locals_are_scanned() {
        // A local of the frame, and nothing about it to skip.
        assert!(is_own_local("held", 8, None));
        assert!(is_own_local("held", 8, Some("value")));

        // The compiler's slots, whatever else is true of them.
        assert!(!is_own_local("__awaitee", 8, None));
        assert!(!is_own_local("__0", 8, Some("__0")));

        // Nothing to find in nothing.
        assert!(!is_own_local("marker", 0, None));

        // The wrapper's inner future is the wrapper's next frame, and
        // is listed there.
        assert!(!is_own_local("value", 8, Some("value")));
    }

    /// The whole census of the `unordered` pair, walked with the given
    /// bounds.
    ///
    /// That fixture is the one with nesting to stop: its driver holds a
    /// `FuturesUnordered` whose three children each hold a future of
    /// their own, one of them a whole set of its own, beside the five
    /// futures the driver holds itself — the last of which carries a
    /// future of its own, the fixture's only nesting that arrives
    /// through a held future rather than through a set.
    fn unordered_census(bounds: Bounds) -> FutureCensus {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census_bounded(&ctx, &list, bounds);
        assert!(census.errors.is_empty(), "{:?}", census.errors);
        // A healthy capture passes both audit classes, bounded or not.
        let violations = census.audit(&list);
        assert!(violations.is_empty(), "{violations:#?}");
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
        // scanned: the five futures the driver holds and the set it
        // drives, whose children are walked (a set's own child list is
        // not a hop) but never scanned.
        let census = unordered_census(nesting(0));
        assert_eq!(census.sets.len(), 1, "{:#?}", census.sets);
        assert_eq!(census.sets[0].children.len(), 3, "{:#?}", census.sets[0]);
        let own: Vec<&str> = census.held.iter().map(|h| h.local.as_str()).collect();
        assert_eq!(
            own,
            ["held", "boxed", "pair", "maybe", "nested_hold"],
            "{:#?}",
            census.held
        );
        assert!(
            census.held.iter().all(|h| h.via.is_none()),
            "{:#?}",
            census.held
        );

        // Five held futures and three resident set children: eight
        // chains the census reached and declined to scan.
        assert_eq!(
            census.capped,
            Capped {
                deep: 0,
                distant: 8
            }
        );
        assert!(census.capped.any());
        assert_eq!(census.capped.total(), 8);
    }

    /// The bound counts where the walk stopped, not what it found: one
    /// hop out reaches every find the fixture has, and still reports
    /// the six chains it would have gone on to scan. The unbounded
    /// walk finds the same and reports nothing, which is what makes a
    /// nonzero count mean something.
    ///
    /// This is also where the hop out of a *held* future is pinned. A
    /// find reached that way is recorded at one hop, not none, so its
    /// own chain is the sixth chain declined here; were the hop not
    /// counted it would be scanned instead, and the count would stop
    /// at the five a set's children account for.
    #[test]
    fn test_the_nesting_bound_counts_the_chains_it_declined() {
        let bounded = unordered_census(nesting(1));
        let full = unordered_census(Bounds::default());

        assert_eq!(bounded.sets.len(), full.sets.len(), "{:#?}", bounded.sets);
        assert_eq!(bounded.held.len(), full.held.len(), "{:#?}", bounded.held);
        assert_eq!(full.capped, Capped::default());
        assert!(!full.capped.any());

        // The one find a held future led to, which is what the hop out
        // of a held future buys: the future the driver's `nested_hold`
        // carries.
        let nested: Vec<&HeldFuture> = bounded
            .held
            .iter()
            .filter(|h| matches!(h.via, Some(Via::Held(_))))
            .collect();
        assert_eq!(nested.len(), 1, "{nested:#?}");
        assert_eq!(nested[0].local, "inner", "{nested:#?}");

        // The three futures the set's children hold, the two children
        // of the set one of them holds, and the chain of the future
        // found inside a held one.
        assert_eq!(
            bounded.capped,
            Capped {
                deep: 0,
                distant: 6
            }
        );
    }

    /// The depth bound stops the descent through one local, and is
    /// counted apart from the nesting bound because it is a different
    /// thing to be told: with no descent at all a local that *is* a
    /// future is still found (a boxed one too — peeling a transparent
    /// wrapper to a pointer is not a descent), while the two the
    /// fixture hides inside a tuple and an enum are not, and every
    /// chain the census does reach is still followed.
    #[test]
    fn test_the_depth_bound_stops_inside_a_local() {
        let census = unordered_census(Bounds {
            scan_depth: 0,
            ..Bounds::default()
        });
        let own: Vec<&str> = census
            .held
            .iter()
            .filter(|h| h.via.is_none())
            .map(|h| h.local.as_str())
            .collect();
        assert_eq!(own, ["held", "boxed", "nested_hold"], "{:#?}", census.held);
        assert!(census.capped.deep > 0, "{:?}", census.capped);
        assert_eq!(census.capped.distant, 0, "{:?}", census.capped);
        // A depth cap on its own is still a short listing, which is all
        // a caller asks before deciding whether to say so.
        assert!(census.capped.any(), "{:?}", census.capped);
        assert_eq!(census.capped.total(), census.capped.deep);
    }

    /// A walker over `ctx` and `list` that has recorded nothing yet,
    /// with nesting 0 so recording stops at the row itself: whatever
    /// the dedup tests below count is their own call's, not something
    /// a recursive scan of the find's chain happened to meet.
    fn shallow_walker<'a, 'b>(
        ctx: &'a Context<'b, proc::snapshot::Snapshot>,
        list: &'a TaskList,
    ) -> Walker<'a, 'b, proc::snapshot::Snapshot> {
        Walker {
            ctx,
            list,
            sets: Vec::new(),
            join_sets: Vec::new(),
            held: Vec::new(),
            spans: Vec::new(),
            errors: Vec::new(),
            capped: Capped::default(),
            stats: Stats::default(),
            bounds: nesting(0),
            visited: HashSet::default(),
            plans: HashMap::default(),
        }
    }

    /// A re-reached find is dropped, and the drop is counted. The drop
    /// itself the audit already forces (a duplicate row is a
    /// violation); the counter is the only trace a *successful* dedup
    /// leaves, so it is pinned here where a hit can be provoked — no
    /// healthy fixture reaches one future through two slots.
    #[test]
    fn test_a_re_reached_find_is_dropped_and_counted() {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census(&ctx, &list);
        let held = census.held.first().expect("the fixture holds a future");
        let ty = ctx
            .view
            .ty(held.ty)
            .expect("the held type is in the bundle");
        let value = Value::read(ctx.proc, ty, held.addr).expect("the held future reads back");

        let mut walker = shallow_walker(&ctx, &list);
        walker.record(0, 0, "held", None, Find::Future(value), 0);
        assert_eq!(walker.held.len(), 1, "{:#?}", walker.held);
        assert_eq!(walker.stats.dedup_hits, 0);

        walker.record(0, 0, "held_again", None, Find::Future(value), 0);
        assert_eq!(walker.held.len(), 1, "{:#?}", walker.held);
        assert_eq!(walker.stats.dedup_hits, 1);
    }

    /// Two slots holding one future are one row. The second slot's own
    /// key is fresh, so the dedup that drops it is the *chain root's* —
    /// the re-keying `record` does for a find whose root differs from
    /// its slot — and that drop is counted like the other.
    #[test]
    fn test_a_second_slot_to_one_future_is_deduped_by_its_root() {
        let (bundle, snapshot) = testkit::load_any("unordered");
        let ctx = testkit::context(&bundle, &snapshot);
        let list = testkit::tasks(&ctx, &snapshot);
        let census = census(&ctx, &list);
        let held = census
            .held
            .iter()
            .find(|h| h.slot != h.addr)
            .expect("the fixture holds a boxed dyn future");

        // The slot value as the scan built it: the owner's frame
        // payload, entered through the holding local's member.
        let task = &list.tasks[held.owner];
        let Ok(TaskStage::Running(root)) = ctx.task_stage(task) else {
            panic!("the owner task is running");
        };
        let chain = ctx.await_chain(root);
        let frame = &chain.frames[held.frame];
        let payload = match &frame.state {
            Some(state) => &state.payload,
            None => &frame.future,
        };
        let m = payload
            .ty
            .members()
            .find(|m| m.name() == held.local)
            .expect("the frame still names the slot");
        let start = m.offset() as usize;
        let bytes = &payload.bytes[start..start + m.ty().size() as usize];
        let slot = Value::new(m.ty(), payload.addr + m.offset(), bytes);
        assert_eq!(slot.addr, held.slot);

        let mut walker = shallow_walker(&ctx, &list);
        walker.record(0, 0, "boxed", None, Find::Future(slot), 0);
        assert_eq!(walker.held.len(), 1, "{:#?}", walker.held);
        assert_eq!(walker.stats.dedup_hits, 0);

        // The same wide pointer read out of a different slot: a fresh
        // slot key over the same future behind it.
        let alias = Value::new(m.ty(), AT, bytes);
        walker.record(0, 0, "alias", None, Find::Future(alias), 0);
        assert_eq!(walker.held.len(), 1, "{:#?}", walker.held);
        assert_eq!(walker.stats.dedup_hits, 1);
    }

    // -----------------------------------------------------------------
    // The audit
    // -----------------------------------------------------------------
    //
    // Each invariant is broken one at a time in a census built by hand,
    // because no walk over any memory is supposed to be able to break
    // one: the real captures (healthy and corrupted both) only ever
    // show the audit passing, so the flagging side is pinned here or
    // nowhere.

    use super::super::TaskAddr;
    use super::super::bundle::{FutureInfo, Task};

    use anyhow::anyhow;

    /// A list of `n` tasks at distinct addresses, for owners to name.
    fn task_list(n: usize) -> TaskList {
        TaskList {
            tasks: (0..n)
                .map(|i| Task {
                    addr: TaskAddr(0x100 + i as u64 * 0x40),
                    state: TaskState(0),
                    owner_id: None,
                    task_id: None,
                    spawn_location: None,
                    future: FutureInfo::Unknown { poll_symbol: None },
                    group: 0,
                })
                .collect(),
            errors: Vec::new(),
        }
    }

    fn blank() -> FutureCensus {
        FutureCensus {
            sets: Vec::new(),
            join_sets: Vec::new(),
            held: Vec::new(),
            spans: Vec::new(),
            errors: Vec::new(),
            capped: Capped::default(),
            stats: Stats::default(),
        }
    }

    fn a_held(owner: usize, addr: u64) -> HeldFuture {
        HeldFuture {
            owner,
            frame: 0,
            local: "held".to_string(),
            via: None,
            slot: addr,
            addr,
            ty: BundleTypeId(0),
            depth: 1,
            future: "f".to_string(),
            state: None,
            waiting_on: None,
            wait: None,
            leaf: None,
        }
    }

    fn a_child(node: u64, root: u64) -> SetChild {
        SetChild {
            node,
            depth: 1,
            future: Some("f".to_string()),
            root: Some(FutureRoot {
                addr: root,
                ty: BundleTypeId(0),
            }),
            state: None,
            waiting_on: None,
            wait: None,
            leaf: None,
        }
    }

    fn a_set(addr: u64, ty: &str, children: Vec<SetChild>) -> FutureSet {
        FutureSet {
            owner: 0,
            frame: 0,
            local: "set".to_string(),
            via: None,
            addr,
            ty: ty.to_string(),
            children,
        }
    }

    fn a_join_set(addr: u64, length: u64, children: Vec<JoinedTask>) -> JoinSet {
        JoinSet {
            owner: 0,
            frame: 0,
            local: "set".to_string(),
            via: None,
            addr,
            ty: "J".to_string(),
            length,
            children,
        }
    }

    fn a_member(entry: u64, task: u64, listed: bool) -> JoinedTask {
        JoinedTask {
            entry,
            task,
            id: None,
            state: TaskState(0),
            listed,
        }
    }

    /// Spans as the walk records them: one per child, sorted, `size`
    /// bytes each.
    fn spans_of(sets: &[FutureSet], size: u64) -> Vec<(u64, u64, usize, usize)> {
        let mut spans: Vec<_> = sets
            .iter()
            .enumerate()
            .flat_map(|(s, set)| {
                set.children
                    .iter()
                    .enumerate()
                    .map(move |(c, child)| (child.node, child.node + size, s, c))
            })
            .collect();
        spans.sort_unstable();
        spans
    }

    #[track_caller]
    fn assert_flags(violations: &[String], needle: &str) {
        assert!(
            violations.iter().any(|v| v.contains(needle)),
            "no violation containing {needle:?}: {violations:#?}"
        );
    }

    /// The audit passes a census whose every rule holds — the baseline
    /// each breakage below stands against, over the same constructors.
    #[test]
    fn test_the_audit_passes_a_sound_census() {
        let list = task_list(2);
        let mut census = blank();
        census.held.push(a_held(0, 0x2000));
        census.held.push({
            let mut nested = a_held(1, 0x3000);
            nested.via = Some(Via::Held(0));
            nested
        });
        // Two children whose nodes touch: adjacent allocations, which
        // no invariant may mistake for an overlap.
        census.sets.push(a_set(
            0x4000,
            "S",
            vec![a_child(0x5000, 0x5008), a_child(0x5020, 0x5028)],
        ));
        census.spans = spans_of(&census.sets, 0x20);
        census
            .join_sets
            .push(a_join_set(0x6000, 1, vec![a_member(0x7000, 0x140, true)]));
        assert_eq!(census.audit(&list), Vec::<String>::new());
    }

    #[test]
    fn test_the_audit_flags_an_owner_off_the_list() {
        let mut census = blank();
        census.held.push(a_held(0, 0x2000));
        assert_flags(
            &census.audit_total(&task_list(0)),
            "names owner 0 of 0 tasks",
        );
    }

    /// A `Via` may only point at an earlier-recorded find, which is the
    /// index-reservation rule: a self- or forward-reference means an
    /// index was taken by something other than what reserved it.
    #[test]
    fn test_the_audit_flags_a_via_that_is_not_earlier_recorded() {
        let list = task_list(1);
        let mut census = blank();
        census.held.push({
            let mut held = a_held(0, 0x2000);
            held.via = Some(Via::Held(0));
            held
        });
        assert_flags(&census.audit_total(&list), "not earlier-recorded");

        let mut census = blank();
        census.sets.push({
            let mut set = a_set(0x4000, "S", Vec::new());
            set.via = Some(Via::SetChild { set: 0, child: 0 });
            set
        });
        assert_flags(&census.audit_total(&list), "not earlier-recorded");
    }

    /// Nothing is reachable through an empty slot: the walk descends
    /// only into resident children.
    #[test]
    fn test_the_audit_flags_a_via_through_an_empty_slot() {
        let list = task_list(1);
        let mut census = blank();
        let mut reaped = a_child(0x5000, 0);
        reaped.future = None;
        reaped.root = None;
        reaped.depth = 0;
        census.sets.push(a_set(0x4000, "S", vec![reaped]));
        census.spans = spans_of(&census.sets, 0x20);
        census.held.push({
            let mut held = a_held(0, 0x2000);
            held.via = Some(Via::SetChild { set: 0, child: 0 });
            held
        });
        assert_flags(&census.audit_total(&list), "an empty slot");

        census.held[0].via = Some(Via::SetChild { set: 0, child: 9 });
        assert_flags(&census.audit_total(&list), "does not exist");
    }

    /// Overlapping spans are two children claiming one allocation —
    /// which a bent list can genuinely produce, so the total invariant
    /// is that the overlap is never *silent*: an error naming it is
    /// the escape hatch.
    #[test]
    fn test_the_audit_flags_a_silent_span_overlap() {
        let list = task_list(1);
        let mut census = blank();
        census.sets.push(a_set(
            0x4000,
            "S",
            vec![a_child(0x5000, 0x5010), a_child(0x5010, 0x5020)],
        ));
        census.spans = spans_of(&census.sets, 0x20);
        assert_flags(&census.audit_total(&list), "overlaps its predecessor");

        census
            .errors
            .push(anyhow!("the set nodes at 0x5000 and 0x5010 overlap"));
        let violations = census.audit_total(&list);
        assert!(
            !violations.iter().any(|v| v.contains("overlaps")),
            "{violations:#?}"
        );
    }

    /// The spans are searched by binary search, so their order is load-
    /// bearing on its own, sorted being what the walk promises.
    #[test]
    fn test_the_audit_flags_spans_out_of_order() {
        let list = task_list(1);
        let mut census = blank();
        census.sets.push(a_set(
            0x4000,
            "S",
            vec![a_child(0x5100, 0x5110), a_child(0x5000, 0x5010)],
        ));
        census.spans = vec![(0x5100, 0x5120, 0, 0), (0x5000, 0x5020, 0, 1)];
        assert_flags(&census.audit_total(&list), "sorts before its predecessor");
    }

    /// Two claims on one node sort as equals, which is a (reported)
    /// overlap and not a sort violation.
    #[test]
    fn test_two_claims_on_one_node_sort_as_equals() {
        let list = task_list(1);
        let mut census = blank();
        census.sets.push(a_set(
            0x4000,
            "S",
            vec![a_child(0x5000, 0x5010), a_child(0x5000, 0x5030)],
        ));
        census.spans = spans_of(&census.sets, 0x20);
        census
            .errors
            .push(anyhow!("the set nodes at 0x5000 and 0x5000 overlap"));
        assert_eq!(census.audit_total(&list), Vec::<String>::new());
    }

    /// A span must cover the node of the very child it names.
    #[test]
    fn test_the_audit_flags_a_span_claiming_the_wrong_child() {
        let list = task_list(1);
        let mut census = blank();
        census
            .sets
            .push(a_set(0x4000, "S", vec![a_child(0x5000, 0x5010)]));
        census.spans = vec![(0x5008, 0x5028, 0, 0)];
        assert_flags(&census.audit_total(&list), "claims the child");
    }

    /// The walk's own overlap report: any two sorted spans sharing a
    /// byte produce one, touching spans produce none.
    #[test]
    fn test_span_overlaps_are_reported_and_adjacency_is_not() {
        let overlapping = [(0x5000, 0x5020, 0, 0), (0x5010, 0x5030, 1, 0)];
        let errors = span_overlap_errors(&overlapping);
        assert_eq!(errors.len(), 1, "{errors:?}");
        let report = format!("{:#}", errors[0]);
        assert!(
            report.contains("0x5000") && report.contains("0x5010"),
            "{report}"
        );

        let touching = [(0x5000, 0x5010, 0, 0), (0x5010, 0x5020, 1, 0)];
        assert!(span_overlap_errors(&touching).is_empty());
        assert!(span_overlap_errors(&[]).is_empty());
    }

    #[test]
    fn test_the_audit_flags_a_span_count_mismatch() {
        let list = task_list(1);
        let mut census = blank();
        census
            .sets
            .push(a_set(0x4000, "S", vec![a_child(0x5000, 0x5010)]));
        assert_flags(&census.audit_total(&list), "0 spans for 1 set children");
    }

    /// A find standing on no frames has nothing to summarize, and a
    /// wait is counted exactly when it is named.
    #[test]
    fn test_the_audit_flags_a_summary_that_disagrees_with_its_depth() {
        let list = task_list(1);
        let mut census = blank();
        census.held.push({
            let mut held = a_held(0, 0x2000);
            held.depth = 0;
            held.state = Some("Suspend0".to_string());
            held
        });
        assert_flags(
            &census.audit_total(&list),
            "no frames but carries a summary",
        );

        // Each summary field alone betrays the missing frames.
        for leftovers in [
            (|held: &mut HeldFuture| held.waiting_on = Some("a Notify".to_string()))
                as fn(&mut HeldFuture),
            |held| held.leaf = Some("tokio::sync::notify::Notified".to_string()),
        ] {
            let mut census = blank();
            census.held.push({
                let mut held = a_held(0, 0x2000);
                held.depth = 0;
                leftovers(&mut held);
                held
            });
            assert_flags(
                &census.audit_total(&list),
                "no frames but carries a summary",
            );
        }

        let mut census = blank();
        census.held.push({
            let mut held = a_held(0, 0x2000);
            held.waiting_on = Some("a Notify".to_string());
            held
        });
        assert_flags(&census.audit_total(&list), "counts a wait");
    }

    /// An empty slot roots nowhere and stands on no frames.
    #[test]
    fn test_the_audit_flags_an_empty_slot_with_leftovers() {
        let list = task_list(1);
        let mut census = blank();
        let mut child = a_child(0x5000, 0x5010);
        child.future = None;
        census.sets.push(a_set(0x4000, "S", vec![child]));
        census.spans = spans_of(&census.sets, 0x20);
        let violations = census.audit_total(&list);
        assert_flags(&violations, "root without a future");

        let mut census = blank();
        let mut child = a_child(0x5000, 0x5010);
        child.future = None;
        child.root = None;
        census.sets.push(a_set(0x4000, "S", vec![child]));
        census.spans = spans_of(&census.sets, 0x20);
        assert_flags(
            &census.audit_total(&list),
            "empty slot standing on 1 frames",
        );
    }

    #[test]
    fn test_the_audit_flags_a_duplicate_row() {
        let list = task_list(1);
        let mut census = blank();
        census.held.push(a_held(0, 0x2000));
        census.held.push(a_held(0, 0x2000));
        assert_flags(&census.audit_total(&list), "share a type");

        let mut census = blank();
        census.sets.push(a_set(0x4000, "S", Vec::new()));
        census.sets.push(a_set(0x4000, "S", Vec::new()));
        assert_flags(&census.audit_total(&list), "recorded twice");
    }

    /// A join set listing other than its own length is silent
    /// fabrication (a grafted entry) or silent omission (a cut list) —
    /// unless an error already says the walk went wrong, which is the
    /// escape hatch that keeps the invariant total.
    #[test]
    fn test_the_audit_flags_a_long_join_set_without_an_error() {
        let list = task_list(1);
        let mut census = blank();
        census
            .join_sets
            .push(a_join_set(0x6000, 0, vec![a_member(0x7000, 0x9000, false)]));
        assert_flags(&census.audit_total(&list), "no error says so");

        census.join_sets[0].length = 2;
        assert_flags(&census.audit_total(&list), "no error says so");

        census
            .errors
            .push(anyhow!("the JoinSet at 0x6000 lists only 1 of its tasks"));
        let violations = census.audit_total(&list);
        assert!(
            !violations.iter().any(|v| v.contains("no error says so")),
            "{violations:#?}"
        );
    }

    #[test]
    fn test_the_audit_flags_a_duplicate_entry_and_a_wrong_listed_flag() {
        let list = task_list(1);
        let mut census = blank();
        census.join_sets.push(a_join_set(
            0x6000,
            2,
            vec![
                a_member(0x7000, 0x9000, false),
                a_member(0x7000, 0x9100, false),
            ],
        ));
        assert_flags(
            &census.audit_total(&list),
            "lists the entry at 0x7000 twice",
        );

        let mut census = blank();
        census
            .join_sets
            .push(a_join_set(0x6000, 1, vec![a_member(0x7000, 0x9000, true)]));
        assert_flags(&census.audit_total(&list), "marked listed=true");
    }

    #[test]
    fn test_the_audit_flags_an_addressless_error() {
        let mut census = blank();
        census.errors.push(anyhow!("something went wrong"));
        assert_flags(&census.audit_total(&task_list(0)), "names no address");
    }

    /// The healthy-only class: shapes corruption may legitimately
    /// produce — so the total audit accepts them — that a sound
    /// capture cannot.
    #[test]
    fn test_the_healthy_audit_flags_cross_population_duplicates() {
        let list = task_list(1);
        let mut census = blank();
        census
            .sets
            .push(a_set(0x4000, "S", vec![a_child(0x5000, 0x8000)]));
        census
            .sets
            .push(a_set(0x4100, "T", vec![a_child(0x5100, 0x8000)]));
        census.spans = spans_of(&census.sets, 0x20);
        census
            .join_sets
            .push(a_join_set(0x6000, 1, vec![a_member(0x7000, 0x9000, false)]));
        census
            .join_sets
            .push(a_join_set(0x6100, 1, vec![a_member(0x7000, 0x9000, false)]));
        assert_eq!(census.audit_total(&list), Vec::<String>::new());

        let violations = census.audit(&list);
        assert_flags(&violations, "more than one set's child");
        assert_flags(&violations, "in two join sets");
        assert_flags(&violations, "joined more than once");
    }
    // The registry diff (`testkit::expect::diff`) is pinned here rather
    // than in `testkit` because only this module can build a
    // `FutureCensus` by hand; the offline registry test only ever shows
    // it passing, so the flagging side is pinned here or nowhere.

    use crate::testkit::expect::{Expectation, diff};

    /// A task whose future resolved, for the task-name expectations to
    /// match against.
    fn known_task(name: &str) -> Task {
        Task {
            addr: TaskAddr(0x2000),
            state: TaskState(0),
            owner_id: None,
            task_id: None,
            spawn_location: None,
            future: FutureInfo::Known(super::super::bundle::KnownFuture {
                entry: hansei_bundle::TaskEntryId(0),
                display_name: name.to_string(),
                kind: hansei_bundle::FutureKind::AsyncFn,
                decl: None,
                symbol: String::new(),
            }),
            group: 0,
        }
    }

    #[test]
    fn test_the_registry_diff_is_clean_on_an_exact_match() {
        let mut list = task_list(1);
        list.tasks
            .push(known_task("demo::driver::{async_fn_env#0}"));
        let mut census = blank();
        census.held.push(a_held(0, 0x1000));
        census
            .sets
            .push(a_set(0x4000, "S", vec![a_child(0x5000, 0x8000)]));
        census.join_sets.push(a_join_set(
            0x6000,
            2,
            vec![
                a_member(0x7000, 0x9000, true),
                a_member(0x7040, 0x9040, false),
            ],
        ));
        let expected = [
            Expectation::Held {
                slot: 0x1000,
                name: "f".to_string(),
            },
            Expectation::Set {
                addr: 0x4000,
                children: 1,
            },
            Expectation::JoinSet {
                addr: 0x6000,
                members: 2,
            },
            Expectation::Task {
                name: "demo::driver".to_string(),
            },
        ];
        assert_eq!(diff(&expected, &census, &list), Vec::<String>::new());
    }

    /// A registered item with no row is an omission — unless an error
    /// names its address, which is the accounted-for escape.
    #[test]
    fn test_the_registry_diff_flags_an_omission_unless_an_error_names_it() {
        let list = task_list(1);
        let mut census = blank();
        let expected = [Expectation::Held {
            slot: 0x1000,
            name: "f".to_string(),
        }];
        let flagged = diff(&expected, &census, &list);
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(flagged[0].contains("no census row"), "{flagged:#?}");

        census.errors.push(anyhow!("something failed at 0x1000"));
        assert_eq!(diff(&expected, &census, &list), Vec::<String>::new());
    }

    /// The reverse direction: a row nothing registered is a
    /// fabrication, whichever population it is in.
    #[test]
    fn test_the_registry_diff_flags_unregistered_rows() {
        let list = task_list(1);
        let mut census = blank();
        census.held.push(a_held(0, 0x1000));
        census.sets.push(a_set(0x4000, "S", Vec::new()));
        census.join_sets.push(a_join_set(0x6000, 0, Vec::new()));
        let flagged = diff(&[], &census, &list);
        assert_eq!(flagged.len(), 3, "{flagged:#?}");
        assert!(
            flagged[0].contains("unregistered held find"),
            "{flagged:#?}"
        );
        assert!(flagged[1].contains("unregistered set"), "{flagged:#?}");
        assert!(flagged[2].contains("unregistered join set"), "{flagged:#?}");
    }

    /// A matched row must also agree: the held find's name and a set's
    /// child count are part of the registration.
    #[test]
    fn test_the_registry_diff_flags_a_disagreeing_match() {
        let list = task_list(1);
        let mut census = blank();
        census.held.push(a_held(0, 0x1000));
        census
            .sets
            .push(a_set(0x4000, "S", vec![a_child(0x5000, 0x8000)]));
        let expected = [
            Expectation::Held {
                slot: 0x1000,
                name: "something_else".to_string(),
            },
            Expectation::Set {
                addr: 0x4000,
                children: 3,
            },
        ];
        let flagged = diff(&expected, &census, &list);
        assert_eq!(flagged.len(), 2, "{flagged:#?}");
        assert!(
            flagged[0].contains("not the registered `something_else`"),
            "{flagged:#?}"
        );
        assert!(
            flagged[1].contains("1 children against the registered 3"),
            "{flagged:#?}"
        );
    }

    /// A boxed find is keyed by the slot the walk entered through, not
    /// by the referent its `addr` was re-pointed at — the slot/referent
    /// split the registry must not re-blur.
    #[test]
    fn test_the_registry_diff_keys_a_boxed_find_by_its_slot() {
        let list = task_list(1);
        let mut census = blank();
        let mut boxed = a_held(0, 0x9000);
        boxed.slot = 0x1000;
        census.held.push(boxed);
        let expected = [Expectation::Held {
            slot: 0x1000,
            name: "f".to_string(),
        }];
        assert_eq!(diff(&expected, &census, &list), Vec::<String>::new());
        let by_referent = [Expectation::Held {
            slot: 0x9000,
            name: "f".to_string(),
        }];
        assert_eq!(diff(&by_referent, &census, &list).len(), 2);
    }

    /// A future carried inside a registered held future is matched
    /// through its carrier's slot and the `Via` the census recorded.
    #[test]
    fn test_the_registry_diff_matches_a_carried_future_through_its_carrier() {
        let list = task_list(1);
        let mut census = blank();
        census.held.push(a_held(0, 0x1000));
        let mut carried = a_held(0, 0x1010);
        carried.via = Some(Via::Held(0));
        census.held.push(carried);
        let expected = [
            Expectation::Held {
                slot: 0x1000,
                name: "f".to_string(),
            },
            Expectation::HeldIn {
                parent: 0x1000,
                name: "f".to_string(),
            },
        ];
        assert_eq!(diff(&expected, &census, &list), Vec::<String>::new());

        // The same registration against a census that attributed the
        // carried future to the wrong parent — or to no parent — fails.
        census.held[1].via = None;
        let flagged = diff(&expected, &census, &list);
        assert!(
            flagged
                .iter()
                .any(|f| f.contains("was not found via the held find")),
            "{flagged:#?}"
        );
    }

    /// The omission escapes, kind by kind: a registered set or join
    /// set with no row is excused exactly when an error names its
    /// address, and a carried future whose carrier is missing is
    /// excused the same way — never silently, never on someone
    /// else's error.
    #[test]
    fn test_the_registry_diff_excuses_only_the_omissions_an_error_names() {
        let list = task_list(1);
        let mut census = blank();
        let expected = [
            Expectation::Set {
                addr: 0x4000,
                children: 1,
            },
            Expectation::JoinSet {
                addr: 0x6000,
                members: 1,
            },
            Expectation::HeldIn {
                parent: 0x1000,
                name: "f".to_string(),
            },
        ];
        let flagged = diff(&expected, &census, &list);
        assert_eq!(flagged.len(), 3, "{flagged:#?}");
        assert!(
            flagged[0].contains("registered set at 0x4000"),
            "{flagged:#?}"
        );
        assert!(
            flagged[1].contains("registered join set at 0x6000"),
            "{flagged:#?}"
        );
        assert!(
            flagged[2].contains("no held find at its carrier's slot 0x1000"),
            "{flagged:#?}"
        );

        // An error naming some other address excuses nothing...
        census.errors.push(anyhow!("something failed at 0x9999"));
        assert_eq!(diff(&expected, &census, &list).len(), 3);

        // ...and one error per named address excuses each in turn.
        census.errors.push(anyhow!("the set at 0x4000 broke"));
        census.errors.push(anyhow!("the join set at 0x6000 broke"));
        census.errors.push(anyhow!("the frame at 0x1000 broke"));
        assert_eq!(diff(&expected, &census, &list), Vec::<String>::new());
    }

    /// A join set's member count is part of the registration, with the
    /// same error escape as a set's.
    #[test]
    fn test_the_registry_diff_flags_a_join_set_count_mismatch() {
        let list = task_list(1);
        let mut census = blank();
        census
            .join_sets
            .push(a_join_set(0x6000, 1, vec![a_member(0x7000, 0x9000, true)]));
        let expected = [Expectation::JoinSet {
            addr: 0x6000,
            members: 3,
        }];
        let flagged = diff(&expected, &census, &list);
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(
            flagged[0].contains("1 members against the registered 3"),
            "{flagged:#?}"
        );

        // An error naming the set stands in for the missing members.
        census.errors.push(anyhow!("the walk stopped at 0x6000"));
        assert_eq!(diff(&expected, &census, &list), Vec::<String>::new());
    }

    /// A registration claims a row by address, never by position: a
    /// set (or join set) at some other address satisfies nothing, and
    /// both directions report.
    #[test]
    fn test_the_registry_diff_matches_by_address_not_position() {
        let list = task_list(1);
        let mut census = blank();
        census.sets.push(a_set(0x5000, "S", Vec::new()));
        census.join_sets.push(a_join_set(0x7000, 0, Vec::new()));
        let expected = [
            Expectation::Set {
                addr: 0x4000,
                children: 0,
            },
            Expectation::JoinSet {
                addr: 0x6000,
                members: 0,
            },
        ];
        let flagged = diff(&expected, &census, &list);
        assert_eq!(flagged.len(), 4, "{flagged:#?}");
        assert!(
            flagged[0].contains("registered set at 0x4000"),
            "{flagged:#?}"
        );
        assert!(
            flagged[1].contains("registered join set at 0x6000"),
            "{flagged:#?}"
        );
        assert!(flagged[2].contains("unregistered set"), "{flagged:#?}");
        assert!(flagged[3].contains("unregistered join set"), "{flagged:#?}");
    }

    /// Task expectations are one-directional: every registered name
    /// must be listed (as many times as it was registered), and tasks
    /// nothing registered are no one's business.
    #[test]
    fn test_the_registry_diff_counts_registered_tasks() {
        let mut list = task_list(1);
        list.tasks
            .push(known_task("demo::worker::{async_fn_env#0}"));
        let census = blank();
        let one = Expectation::Task {
            name: "demo::worker".to_string(),
        };
        assert_eq!(
            diff(std::slice::from_ref(&one), &census, &list),
            Vec::<String>::new()
        );
        let two = [one.clone(), one];
        let flagged = diff(&two, &census, &list);
        assert_eq!(flagged.len(), 1, "{flagged:#?}");
        assert!(
            flagged[0].contains("2 task(s) registered as `demo::worker`, but the listing shows 1"),
            "{flagged:#?}"
        );
    }
}
